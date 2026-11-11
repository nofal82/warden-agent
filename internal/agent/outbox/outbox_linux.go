package outbox

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

const (
	dirFlags  = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	readFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NOCTTY |
		unix.O_NONBLOCK // a planted FIFO must not block the open
	tmpFlags    = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC
	tmpPrefix   = ".tmp-"
	seqDigits   = 20 // math.MaxUint64 has 20 decimal digits
	watermarkSz = 8
)

var suffixes = map[Part]string{PartGeneral: ".g", PartReserve: ".r", PartTrust: ".t"}

// randReader names temporary files.
var randReader = rand.Reader

// openat is unix.Openat; tests replace it to inject transient errors.
var openat = unix.Openat

// errBadFile marks a definite verdict on a message file: it is not a
// regular file, has the wrong owner, mode or link count, is a symlink, is
// too large, is gone, fails the strict check, or changed since it was
// queued. Only such a file is removed. Any other error (EMFILE, EIO,
// EINTR, ENOMEM …) is transient: the file is kept and the error returned,
// because removing a valid signed reply would open a result_sequence gap
// (R28).
var errBadFile = errors.New("bad message file")

// maxMessageBytes reads MAX_INBOX_MESSAGE from the contract (R52c: no
// second copy of a limit) and subtracts the AgentMessage field-3 tag and
// length prefix, so the AgentMessage carrying the stored bytes stays within
// the limit.
var maxMessageBytes = sync.OnceValues(func() (n int, err error) {
	// A broken descriptor must become an error, never a panic.
	defer func() {
		if recover() != nil {
			n, err = 0, errors.New("outbox: reading MAX_INBOX_MESSAGE panicked")
		}
	}()
	opts := (&agentapiv1.OutboxMessage{}).ProtoReflect().Descriptor().Options()
	if opts == nil || !proto.HasExtension(opts, wardenv1.E_MaxMessageBytes) {
		return 0, errors.New("outbox: OutboxMessage max_message_bytes missing")
	}
	limit, ok := proto.GetExtension(opts, wardenv1.E_MaxMessageBytes).(uint32)
	if !ok || limit < 16 {
		return 0, errors.New("outbox: OutboxMessage max_message_bytes invalid")
	}
	l := int(limit)
	return l - protowire.SizeTag(3) - protowire.SizeVarint(uint64(limit)), nil
})

// MaxMessageBytes is the largest OutboxMessage the outbox stores: the
// MAX_INBOX_MESSAGE limit of the whole AgentMessage carrying it (R11),
// minus that message's tag and length prefix.
func MaxMessageBytes() (int, error) { return maxMessageBytes() }

type entry struct {
	seq    uint64
	size   uint64
	part   Part
	kind   string
	digest [sha256.Size]byte
}

// Outbox is an open outbox directory. It is safe for concurrent use.
type Outbox struct {
	mu       sync.Mutex
	dir      string
	uid      int
	maxMsg   int
	log      *slog.Logger
	statfs   func(int) (FSStat, error)
	next     uint64  // next message_seq to assign
	entries  []entry // ascending seq
	parts    map[Part]*PartStats
	rejected uint64
	full     bool
	inflight map[uint64]bool
	sendFrom uint64 // Next returns the first entry with seq >= sendFrom
}

// Open checks dir, confirms the storage limit, reloads every message and
// the watermark, and removes (logs, counts) every file that fails.
func Open(dir string, opt Options) (*Outbox, error) {
	uid := os.Geteuid()
	if uid == 0 {
		return nil, fmt.Errorf("%w: refusing to run as root", ErrUnsafeDir)
	}
	if !path.IsAbs(dir) || path.Clean(dir) != dir {
		return nil, fmt.Errorf("%w: %q is not an absolute clean path", ErrUnsafeDir, dir)
	}
	maxMsg, err := maxMessageBytes()
	if err != nil {
		return nil, err
	}
	o := &Outbox{
		dir: dir, uid: uid, maxMsg: maxMsg, log: opt.Logger, statfs: opt.Statfs,
		parts:    map[Part]*PartStats{PartGeneral: {}, PartReserve: {}, PartTrust: {}},
		inflight: map[uint64]bool{},
	}
	if o.log == nil {
		o.log = slog.New(slog.DiscardHandler)
	}
	if o.statfs == nil {
		o.statfs = fstatfs
	}
	confirm := opt.ConfirmStorage
	if confirm == nil {
		confirm = confirmDedicated
	}
	d, err := o.openDir()
	if err != nil {
		return nil, err
	}
	defer closeDir(d)
	st, err := o.statfs(dirFD(d))
	if err != nil {
		return nil, fmt.Errorf("%w: statfs %s: %w", ErrStorageUnconfirmed, dir, err)
	}
	if err := confirm(st); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStorageUnconfirmed, err)
	}
	if err := o.load(d); err != nil {
		return nil, err
	}
	return o, nil
}

func confirmDedicated(st FSStat) error {
	if st.TotalBytes == 0 || st.TotalBytes > StorageBudget {
		return fmt.Errorf("filesystem of %d bytes is not a dedicated outbox filesystem of at most %d bytes", st.TotalBytes, StorageBudget)
	}
	return nil
}

func fstatfs(fd int) (FSStat, error) {
	var s unix.Statfs_t
	if err := unix.Fstatfs(fd, &s); err != nil {
		return FSStat{}, err
	}
	bs := s.Frsize
	if bs <= 0 {
		bs = s.Bsize
	}
	if bs <= 0 {
		return FSStat{}, errors.New("statfs reports no block size")
	}
	ubs := uint64(bs)
	return FSStat{TotalBytes: s.Blocks * ubs, AvailBytes: s.Bavail * ubs, BlockSize: ubs}, nil
}

// openDir opens the outbox directory without following a symlink and
// checks it is a directory owned by the agent user with no group or other
// permission bits.
func (o *Outbox) openDir() (*os.File, error) {
	fd, err := unix.Open(o.dir, dirFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", ErrUnsafeDir, o.dir, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: stat %s: %w", ErrUnsafeDir, o.dir, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int64(st.Uid) != int64(o.uid) || st.Mode&0o077 != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %s must be a directory owned by uid %d with mode 0700", ErrUnsafeDir, o.dir, o.uid)
	}
	return os.NewFile(uintptr(fd), o.dir), nil // #nosec G115 -- fd is a valid non-negative descriptor
}

func dirFD(d *os.File) int { return int(d.Fd()) } // #nosec G115 -- descriptor from unix.Open

func closeDir(d *os.File) { _ = d.Close() } // read-only directory: nothing to lose

// load reads every file of the directory (Open).
func (o *Outbox) load(d *os.File) error {
	names, err := d.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("outbox: list %s: %w", o.dir, err)
	}
	fd := dirFD(d)
	changed := false
	seen := map[uint64]bool{}
	for _, name := range names {
		if name == WatermarkFile {
			continue
		}
		if strings.HasPrefix(name, tmpPrefix) {
			if err := unlinkNotDir(fd, name); err != nil {
				return fmt.Errorf("%w: %s/%s: %w", ErrUnsafeDir, o.dir, name, err)
			}
			changed = true
			continue
		}
		seq, part, ok := parseName(name)
		if !ok || seen[seq] {
			if err := unlinkNotDir(fd, name); err != nil {
				return fmt.Errorf("%w: %s/%s: %w", ErrUnsafeDir, o.dir, name, err)
			}
			o.reject(seq, name, "", nil, "unrecognised or duplicate file name")
			changed = true
			continue
		}
		e, why, err := o.readEntry(fd, seq, part)
		if err != nil {
			return fmt.Errorf("outbox: read %s/%s: %w", o.dir, name, err)
		}
		if why != "" {
			if err := unlinkNotDir(fd, name); err != nil {
				return fmt.Errorf("%w: %s/%s: %w", ErrUnsafeDir, o.dir, name, err)
			}
			o.reject(seq, name, "", nil, why)
			changed = true
			continue
		}
		seen[seq] = true
		o.entries = append(o.entries, e)
		o.account(e, 1)
	}
	sort.Slice(o.entries, func(i, j int) bool { return o.entries[i].seq < o.entries[j].seq })
	if changed {
		if err := unix.Fsync(fd); err != nil {
			return fmt.Errorf("outbox: fsync %s: %w", o.dir, err)
		}
	}
	wm, err := o.readWatermark(fd)
	if err != nil {
		return err
	}
	o.next = wm
	if n := len(o.entries); n > 0 && o.entries[n-1].seq >= o.next {
		o.next = o.entries[n-1].seq + 1 // never reuse a stored sequence
	}
	g := o.parts[PartGeneral]
	o.full = g.Files >= MaxGeneralFiles || g.Bytes >= MaxGeneralBytes
	return nil
}

// unlinkNotDir removes a non-directory entry without following it. A
// directory is refused: nothing in the outbox creates one.
func unlinkNotDir(fd int, name string) error {
	if err := unix.Unlinkat(fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

// parseName parses "<20 digits>.<g|r|t>"; the zero padding makes the name
// of a sequence unique.
func parseName(name string) (uint64, Part, bool) {
	if len(name) != seqDigits+2 || name[seqDigits] != '.' {
		return 0, 0, false
	}
	var part Part
	for p, s := range suffixes {
		if name[seqDigits:] == s {
			part = p
		}
	}
	if part == 0 {
		return 0, 0, false
	}
	digits := name[:seqDigits]
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, 0, false
		}
	}
	seq, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || seq == 0 {
		return 0, 0, false
	}
	return seq, part, true
}

func fileName(seq uint64, part Part) string {
	return fmt.Sprintf("%0*d%s", seqDigits, seq, suffixes[part])
}

// readEntry reads and checks one message file. A non-empty reason means
// the file fails and must be removed; an error means it could not be read
// and must be kept.
func (o *Outbox) readEntry(fd int, seq uint64, part Part) (entry, string, error) {
	b, err := o.readAt(fd, fileName(seq, part), o.maxMsg)
	if why, err := verdict(err); why != "" || err != nil {
		return entry{}, why, err
	}
	if err := o.check(seq, b); err != nil {
		return entry{}, err.Error(), nil
	}
	return entry{seq: seq, size: uint64(len(b)), part: part, kind: kindOf(b), digest: sha256.Sum256(b)}, "", nil
}

// verdict splits a readAt error into a removal reason (errBadFile) or a
// transient error to return.
func verdict(err error) (string, error) {
	switch {
	case err == nil:
		return "", nil
	case errors.Is(err, errBadFile):
		return err.Error(), nil
	default:
		return "", err
	}
}

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errBadFile}, args...)...)
}

// readAt reads one file of the directory without following a symlink: it
// must be a regular file owned by the agent user, with no group or other
// permission bit, one hard link, and at most limit bytes.
func (o *Outbox) readAt(dfd int, name string, limit int) ([]byte, error) {
	fd, err := openat(dfd, name, readFlags, 0)
	switch {
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOENT):
		// ELOOP: a symlink under O_NOFOLLOW. ENOENT: gone.
		return nil, fmt.Errorf("%w: open: %w", errBadFile, err)
	case err != nil:
		return nil, fmt.Errorf("open: %w", err)
	}
	f := os.NewFile(uintptr(fd), name) // #nosec G115 -- fd is a valid non-negative descriptor
	defer func() { _ = f.Close() }()   // read-only: nothing to lose
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, bad("not a regular file")
	case int64(st.Uid) != int64(o.uid) || st.Mode&0o077 != 0:
		return nil, bad("wrong owner or mode")
	case st.Nlink != 1:
		return nil, bad("more than one hard link")
	case st.Size < 0 || st.Size > int64(limit):
		return nil, bad("too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(b) > limit {
		return nil, bad("too large")
	}
	return b, nil
}

func (o *Outbox) check(seq uint64, b []byte) error {
	if len(b) == 0 || len(b) > o.maxMsg {
		return errors.New("size out of range")
	}
	return checkFile(seq, b)
}

// checkFile is the strict check of one stored message: b decodes with the
// strict decoder, its message_seq equals seq (the file name's), exactly
// one payload member is set, and len(b) is within MaxMessageBytes.
func checkFile(seq uint64, b []byte) error {
	limit, err := maxMessageBytes()
	if err != nil {
		return err
	}
	if seq == 0 {
		return errors.New("message_seq zero")
	}
	if len(b) == 0 || len(b) > limit {
		return errors.New("size out of range")
	}
	var m agentapiv1.OutboxMessage
	if err := agentapiv1.StrictUnmarshal(b, &m); err != nil {
		return errors.New("fails the strict decoder")
	}
	if m.GetMessageSeq() != seq {
		return errors.New("message_seq does not match the file name")
	}
	if m.GetPayload().GetPayload() == nil {
		return errors.New("no payload")
	}
	return nil
}

// kindOf names the payload member for local logs; b has passed checkFile.
func kindOf(b []byte) string {
	var m agentapiv1.OutboxMessage
	if agentapiv1.StrictUnmarshal(b, &m) != nil {
		return "unknown"
	}
	return payloadKind(m.GetPayload())
}

func payloadKind(p *agentapiv1.OutboxPayload) string {
	switch {
	case p.GetSignedReply() != nil:
		return "signed_reply"
	case p.GetEnvelopeAdvisory() != nil:
		return "envelope_advisory"
	case p.GetTrustDocumentOversize() != nil:
		return "trust_document_oversize"
	case p.GetRecoveryReport() != nil:
		return "recovery_report"
	case p.GetAdminToolRecord() != nil:
		return "admin_tool_record"
	default:
		return "unknown"
	}
}

// parseWatermark decodes the watermark file: exactly 8 bytes, big-endian,
// a value of at least 1.
func parseWatermark(b []byte) (uint64, error) {
	if len(b) != watermarkSz {
		return 0, fmt.Errorf("%w: %d bytes", ErrCorruptWatermark, len(b))
	}
	v := binary.BigEndian.Uint64(b)
	if v == 0 {
		return 0, fmt.Errorf("%w: zero", ErrCorruptWatermark)
	}
	return v, nil
}

// readWatermark returns the stored next sequence, or 1 when the file does
// not exist yet (first start).
func (o *Outbox) readWatermark(fd int) (uint64, error) {
	b, err := o.readAt(fd, WatermarkFile, watermarkSz+1)
	if errors.Is(err, unix.ENOENT) {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%w: %s/%s: %w", ErrCorruptWatermark, o.dir, WatermarkFile, err)
	}
	return parseWatermark(b)
}

// writeAt writes data under name atomically with mode 0600: a random
// temporary file created with O_EXCL and O_NOFOLLOW, written and fsync'ed,
// renamed into place, then the directory fsync'ed.
func writeAt(dfd int, name string, data []byte) error {
	var rnd [12]byte
	if _, err := io.ReadFull(randReader, rnd[:]); err != nil {
		return fmt.Errorf("temporary name: %w", err)
	}
	tmp := tmpPrefix + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(dfd, tmp, tmpFlags, 0o600)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmp) // #nosec G115 -- fd is a valid non-negative descriptor
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = unix.Unlinkat(dfd, tmp, 0) // best effort; the name is random and unused
		return fmt.Errorf("write: %w", werr)
	}
	if err := unix.Renameat(dfd, tmp, dfd, name); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("rename: %w", err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return fmt.Errorf("fsync directory: %w", err)
	}
	return nil
}

// Enqueue assigns the next message_seq, writes the message durably and
// returns its sequence. The watermark is advanced and fsync'ed before the
// message file, so a crash in between skips a sequence but never reuses
// one. A refused message changes nothing on disk.
func (o *Outbox) Enqueue(p *agentapiv1.OutboxPayload) (uint64, error) {
	if p.GetPayload() == nil {
		return 0, ErrInvalidMessage
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	seq := o.next
	if seq == math.MaxUint64 {
		return 0, ErrSequenceExhausted
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentapiv1.OutboxMessage{MessageSeq: seq, Payload: p})
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	if len(b) > o.maxMsg {
		return 0, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(b))
	}
	if err := checkFile(seq, b); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidMessage, err)
	}
	d, err := o.openDir()
	if err != nil {
		return 0, err
	}
	defer closeDir(d)
	fd := dirFD(d)
	part, err := o.choosePart(fd, uint64(len(b)), PartFor(p))
	if err != nil {
		return 0, err
	}
	var wm [watermarkSz]byte
	binary.BigEndian.PutUint64(wm[:], seq+1)
	if err := writeAt(fd, WatermarkFile, wm[:]); err != nil {
		return 0, fmt.Errorf("outbox: watermark: %w", err)
	}
	o.next = seq + 1
	if err := writeAt(fd, fileName(seq, part), b); err != nil {
		return 0, fmt.Errorf("outbox: message %d: %w", seq, err)
	}
	e := entry{seq: seq, size: uint64(len(b)), part: part, kind: payloadKind(p), digest: sha256.Sum256(b)}
	o.entries = append(o.entries, e) // seq is above every stored one
	o.account(e, 1)
	g := o.parts[PartGeneral]
	if g.Files >= MaxGeneralFiles || g.Bytes >= MaxGeneralBytes {
		o.full = true
	}
	return seq, nil
}

// choosePart picks the part for a message of size bytes: the general part
// when both caps and the free-space floor allow it, otherwise the reserve
// the payload may use (never the floor there: R33).
func (o *Outbox) choosePart(fd int, size uint64, overflow Part) (Part, error) {
	g := o.parts[PartGeneral]
	if g.Files+1 <= MaxGeneralFiles && g.Bytes+size <= MaxGeneralBytes && o.floorOK(fd, size) {
		return PartGeneral, nil
	}
	o.full = true
	if overflow == PartGeneral {
		return 0, ErrFull
	}
	maxFiles, maxBytes := uint64(ReserveFiles), uint64(ReserveBytes)
	if overflow == PartTrust {
		maxFiles, maxBytes = TrustReserveFiles, TrustReserveBytes
	}
	r := o.parts[overflow]
	if r.Files+1 > maxFiles || r.Bytes+size > maxBytes {
		return 0, ErrReserveFull
	}
	return overflow, nil
}

// floorOK reports whether writing size bytes leaves at least
// FreeSpaceFloor of free space after the file's block-rounded allocation.
// A statfs failure counts as no space: fail safe.
func (o *Outbox) floorOK(fd int, size uint64) bool {
	st, err := o.statfs(fd)
	if err != nil {
		o.log.Warn("outbox: statfs failed; general part treated as full", "error", err)
		return false
	}
	bs := st.BlockSize
	if bs == 0 {
		bs = 1
	}
	alloc := (size + bs - 1) / bs * bs
	if alloc < size || st.AvailBytes < alloc {
		return false
	}
	return st.AvailBytes-alloc >= FreeSpaceFloor
}

func (o *Outbox) account(e entry, sign int) {
	p := o.parts[e.part]
	if sign > 0 {
		p.Files++
		p.Bytes += e.size
		return
	}
	p.Files--
	p.Bytes -= e.size
}

func (o *Outbox) find(seq uint64) int {
	i := sort.Search(len(o.entries), func(i int) bool { return o.entries[i].seq >= seq })
	if i < len(o.entries) && o.entries[i].seq == seq {
		return i
	}
	return -1
}

// remove unlinks the file of entries[i] and drops the entry. On an unlink
// error the entry stays, so the message is sent again (DUPLICATE) rather
// than lost.
func (o *Outbox) remove(fd, i int) error {
	e := o.entries[i]
	if err := unix.Unlinkat(fd, fileName(e.seq, e.part), 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("outbox: remove %d: %w", e.seq, err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("outbox: fsync %s: %w", o.dir, err)
	}
	o.entries = append(o.entries[:i], o.entries[i+1:]...)
	o.account(e, -1)
	delete(o.inflight, e.seq)
	g := o.parts[PartGeneral]
	if o.full && g.Files*10 < MaxGeneralFiles*9 && g.Bytes*10 < MaxGeneralBytes*9 {
		o.full = false
	}
	return nil
}

// reject logs a removed message (seq, kind, length, SHA-256, reason;
// never its content) and counts it.
func (o *Outbox) reject(seq uint64, name, kind string, b []byte, reason string) {
	o.rejected++
	sum := sha256.Sum256(b)
	o.log.Warn("outbox: message removed", "message_seq", seq, "file", name, "kind", kind,
		"length", len(b), "sha256", hex.EncodeToString(sum[:]), "reason", reason)
}

// Next returns the next message to send in message_seq order, or false
// when Window messages are in flight, the next one is still in flight
// (waiting for its RETRY_LATER), or none is left. A file that no longer
// passes the strict check, or no longer holds the bytes queued, is
// removed and counted, and Next goes on with the following one (R32a).
func (o *Outbox) Next() (Message, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.inflight) >= Window {
		return Message{}, false, nil
	}
	d, err := o.openDir()
	if err != nil {
		return Message{}, false, err
	}
	defer closeDir(d)
	fd := dirFD(d)
	for {
		i := sort.Search(len(o.entries), func(i int) bool { return o.entries[i].seq >= o.sendFrom })
		if i == len(o.entries) || o.inflight[o.entries[i].seq] {
			return Message{}, false, nil
		}
		e := o.entries[i]
		b, why, err := o.reread(fd, e)
		if err != nil {
			return Message{}, false, fmt.Errorf("outbox: read message %d: %w", e.seq, err)
		}
		if why != "" {
			if err := o.remove(fd, i); err != nil {
				return Message{}, false, err
			}
			o.reject(e.seq, fileName(e.seq, e.part), e.kind, b, why)
			continue
		}
		o.inflight[e.seq] = true
		o.sendFrom = e.seq + 1
		return Message{Seq: e.seq, Bytes: b}, true, nil
	}
}

// reread reads a queued message again: a non-empty reason means remove
// it, an error means keep it and report.
func (o *Outbox) reread(fd int, e entry) ([]byte, string, error) {
	b, err := o.readAt(fd, fileName(e.seq, e.part), o.maxMsg)
	if why, err := verdict(err); why != "" || err != nil {
		return nil, why, err
	}
	if err := o.check(e.seq, b); err != nil {
		return b, err.Error(), nil
	}
	if sum := sha256.Sum256(b); !bytes.Equal(sum[:], e.digest[:]) || uint64(len(b)) != e.size {
		return b, "content changed since it was queued", nil
	}
	return b, "", nil
}

// Ack applies one MessageAck (R32). ACCEPTED and DUPLICATE remove the
// message; REJECTED removes, logs and counts it; RETRY_LATER keeps it and
// makes it the next one Next returns, so later messages follow in order.
func (o *Outbox) Ack(seq uint64, outcome agentapiv1.AckOutcome, reason agentapiv1.AckReason) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	switch outcome {
	case agentapiv1.AckOutcome_ACK_OUTCOME_ACCEPTED, agentapiv1.AckOutcome_ACK_OUTCOME_DUPLICATE,
		agentapiv1.AckOutcome_ACK_OUTCOME_RETRY_LATER, agentapiv1.AckOutcome_ACK_OUTCOME_REJECTED:
	default:
		return fmt.Errorf("%w: outcome %d", ErrUnexpectedAck, outcome)
	}
	i := o.find(seq)
	if !o.inflight[seq] || i < 0 {
		return fmt.Errorf("%w: message_seq %d is not in flight", ErrUnexpectedAck, seq)
	}
	if outcome == agentapiv1.AckOutcome_ACK_OUTCOME_RETRY_LATER {
		delete(o.inflight, seq)
		if seq < o.sendFrom {
			o.sendFrom = seq
		}
		return nil
	}
	d, err := o.openDir()
	if err != nil {
		return err
	}
	defer closeDir(d)
	e := o.entries[i]
	if err := o.remove(dirFD(d), i); err != nil {
		return err
	}
	if outcome == agentapiv1.AckOutcome_ACK_OUTCOME_REJECTED {
		o.rejected++
		o.log.Warn("outbox: message rejected by the control plane", "message_seq", e.seq, "kind", e.kind,
			"length", e.size, "sha256", hex.EncodeToString(e.digest[:]), "reason", reason.String())
	}
	return nil
}

// Rewind forgets every message in flight: the next Next starts again from
// the oldest unacknowledged message (a new stream, R32).
func (o *Outbox) Rewind() {
	o.mu.Lock()
	defer o.mu.Unlock()
	clear(o.inflight)
	o.sendFrom = 0
}

// Recheck re-checks every file with the strict decoder and removes the
// ones that fail (R32a); it returns how many it removed.
func (o *Outbox) Recheck() (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	d, err := o.openDir()
	if err != nil {
		return 0, err
	}
	defer closeDir(d)
	fd := dirFD(d)
	removed := 0
	for i := 0; i < len(o.entries); {
		e := o.entries[i]
		b, why, err := o.reread(fd, e)
		if err != nil {
			return removed, fmt.Errorf("outbox: read message %d: %w", e.seq, err)
		}
		if why == "" {
			i++
			continue
		}
		if err := o.remove(fd, i); err != nil {
			return removed, err
		}
		o.reject(e.seq, fileName(e.seq, e.part), e.kind, b, why)
		removed++
	}
	return removed, nil
}

// Seqs returns the message_seq of every queued message, ascending.
func (o *Outbox) Seqs() []uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := make([]uint64, len(o.entries))
	for i, e := range o.entries {
		s[i] = e.seq
	}
	return s
}

// Stats returns the current figures.
func (o *Outbox) Stats() Stats {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := Stats{
		Rejected: o.rejected,
		General:  *o.parts[PartGeneral],
		Reserve:  *o.parts[PartReserve],
		Trust:    *o.parts[PartTrust],
	}
	for _, p := range []PartStats{s.General, s.Reserve, s.Trust} {
		s.Messages += p.Files
		s.Bytes += p.Bytes
	}
	g := s.General
	switch {
	case o.full:
		s.Condition = ConditionFull
	case g.Files*5 >= MaxGeneralFiles*4 || g.Bytes*5 >= MaxGeneralBytes*4:
		s.Condition = ConditionHighWater
	}
	return s
}
