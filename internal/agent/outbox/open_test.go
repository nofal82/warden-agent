package outbox_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

func maxBytes(t testing.TB) int {
	t.Helper()
	n, err := outbox.MaxMessageBytes()
	if err != nil {
		t.Fatalf("MaxMessageBytes: %v", err)
	}
	return n
}

func TestMaxMessageBytes(t *testing.T) {
	// 65,536 (OutboxMessage max_message_bytes, applied to the whole
	// AgentMessage) minus the AgentMessage tag (1 byte) and a 3-byte length.
	if got := maxBytes(t); got != 65532 {
		t.Fatalf("MaxMessageBytes = %d, want 65532", got)
	}
}

func TestOpenFreshDirectory(t *testing.T) {
	o, dir, _ := fresh(t)
	if s := o.Seqs(); len(s) != 0 {
		t.Fatalf("Seqs = %v, want none", s)
	}
	st := o.Stats()
	if st.Messages != 0 || st.Bytes != 0 || st.Rejected != 0 || st.Condition != outbox.ConditionNone {
		t.Fatalf("Stats = %+v, want zero", st)
	}
	if _, ok := next(t, o); ok {
		t.Fatal("Next on an empty outbox returned a message")
	}
	if fs := messageFiles(t, dir); len(fs) != 0 {
		t.Fatalf("message files in a fresh outbox: %v", fs)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("Open changed the directory mode to %v", fi.Mode().Perm())
	}
}

// TestOpenRejectsUnsafeDirectory: R29 (owner the agent user, 0700,
// O_NOFOLLOW). Open must refuse, never "repair" the mode.
func TestOpenRejectsUnsafeDirectory(t *testing.T) {
	modes := []os.FileMode{0o750, 0o705, 0o770, 0o777, 0o701, 0o710, 0o702, 0o720}
	for _, m := range modes {
		t.Run("mode "+m.String(), func(t *testing.T) {
			dir := newDir(t)
			if err := os.Chmod(dir, m); err != nil {
				t.Fatal(err)
			}
			_, err := openTimed(t, dir, opts(newFakeFS()))
			if !errors.Is(err, outbox.ErrUnsafeDir) {
				t.Fatalf("Open with mode %v: err = %v, want ErrUnsafeDir", m, err)
			}
			fi, _ := os.Stat(dir)
			if fi.Mode().Perm() != m {
				t.Fatalf("Open changed mode %v to %v", m, fi.Mode().Perm())
			}
		})
	}

	cases := []struct {
		name  string
		setup func(t *testing.T) string
		want  error // nil: any error
	}{
		{"symlink to a safe directory", func(t *testing.T) string {
			real := newDir(t)
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, outbox.ErrUnsafeDir},
		{"regular file", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}, outbox.ErrUnsafeDir},
		{"subdirectory inside", func(t *testing.T) string {
			d := newDir(t)
			if err := os.Mkdir(filepath.Join(d, "00000000000000000001.g"), 0o700); err != nil {
				t.Fatal(err)
			}
			return d
		}, outbox.ErrUnsafeDir},
		{"plain subdirectory inside", func(t *testing.T) string {
			d := newDir(t)
			if err := os.Mkdir(filepath.Join(d, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			return d
		}, outbox.ErrUnsafeDir},
		{"missing", func(t *testing.T) string { return filepath.Join(t.TempDir(), "nope") }, nil},
		{"empty path", func(t *testing.T) string { return "" }, nil},
		{"NUL in path", func(t *testing.T) string { return newDir(t) + "\x00x" }, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, err := openTimed(t, c.setup(t), opts(newFakeFS()))
			if err == nil || o != nil {
				t.Fatalf("Open succeeded, want an error")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}

	t.Run("root", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("not root: the refusal of root can only be tested as root")
		}
		_, err := openTimed(t, newDir(t), opts(newFakeFS()))
		if !errors.Is(err, outbox.ErrUnsafeDir) {
			t.Fatalf("Open as root: err = %v, want ErrUnsafeDir", err)
		}
	})
}

// TestOpenStorageConfirmation: R33 "Storage", AC26 (refuses to start when
// the limit cannot be confirmed).
func TestOpenStorageConfirmation(t *testing.T) {
	t.Run("ConfirmStorage error", func(t *testing.T) {
		fs := newFakeFS()
		opt := opts(fs)
		opt.ConfirmStorage = func(outbox.FSStat) error { return errors.New("no quota") }
		o, err := openTimed(t, newDir(t), opt)
		if !errors.Is(err, outbox.ErrStorageUnconfirmed) || o != nil {
			t.Fatalf("err = %v, want ErrStorageUnconfirmed", err)
		}
	})
	t.Run("ConfirmStorage sees the Statfs result", func(t *testing.T) {
		fs := newFakeFS()
		fs.st = outbox.FSStat{TotalBytes: 12345678, AvailBytes: 1 << 30, BlockSize: 4096}
		var got outbox.FSStat
		opt := opts(fs)
		opt.ConfirmStorage = func(s outbox.FSStat) error { got = s; return nil }
		if _, err := openTimed(t, newDir(t), opt); err != nil {
			t.Fatal(err)
		}
		if got != fs.st {
			t.Fatalf("ConfirmStorage got %+v, want %+v", got, fs.st)
		}
	})
	defaults := []struct {
		name  string
		total uint64
		err   error
		ok    bool
	}{
		{"default: total == budget", outbox.StorageBudget, nil, true},
		{"default: total < budget", outbox.StorageBudget - 1, nil, true},
		{"default: total == budget+1", outbox.StorageBudget + 1, nil, false},
		{"default: total huge", 1 << 62, nil, false},
		{"default: total max", ^uint64(0), nil, false},
		{"default: statfs error", outbox.StorageBudget, errors.New("EIO"), false},
	}
	for _, c := range defaults {
		t.Run(c.name, func(t *testing.T) {
			fs := newFakeFS()
			fs.st.TotalBytes = c.total
			fs.err = c.err
			o, err := openTimed(t, newDir(t), outbox.Options{Statfs: fs.statfs})
			if c.ok {
				if err != nil || o == nil {
					t.Fatalf("Open: %v, want success", err)
				}
				return
			}
			if !errors.Is(err, outbox.ErrStorageUnconfirmed) || o != nil {
				t.Fatalf("err = %v, want ErrStorageUnconfirmed", err)
			}
		})
	}
	t.Run("real statfs on a large tmp filesystem", func(t *testing.T) {
		dir := newDir(t)
		var st syscall.Statfs_t
		if err := syscall.Statfs(dir, &st); err != nil {
			t.Fatal(err)
		}
		if uint64(st.Blocks)*uint64(st.Bsize) <= outbox.StorageBudget { // #nosec G115 -- block counts and sizes are non-negative
			t.Skip("tmp filesystem is within the storage budget")
		}
		_, err := openTimed(t, dir, outbox.Options{})
		if !errors.Is(err, outbox.ErrStorageUnconfirmed) {
			t.Fatalf("Open on a %d-byte filesystem: err = %v, want ErrStorageUnconfirmed",
				uint64(st.Blocks)*uint64(st.Bsize), err) // #nosec G115 -- block counts and sizes are non-negative
		}
	})
}

// tamper damages the file of seq 2 in dir; outside is a scratch directory
// on the same filesystem for link targets.
type tamper func(t *testing.T, path, outside string, valid []byte)

func writeOver(b []byte) tamper {
	return func(t *testing.T, p, _ string, _ []byte) {
		if err := os.WriteFile(p, b, 0o600); err != nil { // #nosec G304 G703 -- test file under t.TempDir()
			t.Fatal(err)
		}
	}
}

func badFileCases(t *testing.T) []struct {
	name string
	do   tamper
} {
	t.Helper()
	valid2 := encode(t, 2, envResult(1))
	seq2 := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 2)
	// encode(0, p) is field 2 only (a zero seq is omitted); strip its tag
	// and length to get the OutboxPayload body.
	payloadBody := func(b []byte) []byte {
		v, n := protowire.ConsumeBytes(b[1:])
		if n < 0 {
			t.Fatal("cannot strip payload field")
		}
		return v
	}
	srPayload := payloadBody(encode(t, 0, envResult(1)))
	advPayload := payloadBody(encode(t, 0, advisory(1)))
	twoMembers := append(append([]byte{}, seq2...),
		protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType),
			append(append([]byte{}, srPayload...), advPayload...))...)

	dupSeq := append(append(append([]byte{}, seq2...), seq2...), valid2[len(seq2):]...)
	outOfOrder := append(append([]byte{}, valid2[len(seq2):]...), seq2...)
	noPayload := append([]byte{}, seq2...)
	emptyPayload := protowire.AppendBytes(protowire.AppendTag(append([]byte{}, seq2...), 2, protowire.BytesType), nil)
	unknown := protowire.AppendVarint(protowire.AppendTag(append([]byte{}, valid2...), 9, protowire.VarintType), 1)
	mx := maxBytes(t)

	return []struct {
		name string
		do   tamper
	}{
		{"group readable", func(t *testing.T, p, _ string, _ []byte) { chmod(t, p, 0o640) }},
		{"group writable", func(t *testing.T, p, _ string, _ []byte) { chmod(t, p, 0o620) }},
		{"other readable", func(t *testing.T, p, _ string, _ []byte) { chmod(t, p, 0o604) }},
		{"world writable", func(t *testing.T, p, _ string, _ []byte) { chmod(t, p, 0o666) }},
		{"symlink to a valid copy outside", func(t *testing.T, p, out string, v []byte) {
			target := filepath.Join(out, "copy")
			if err := os.WriteFile(target, v, 0o600); err != nil { // #nosec G304 G703 -- test file under t.TempDir()
				t.Fatal(err)
			}
			replaceWithSymlink(t, p, target)
		}},
		{"dangling symlink", func(t *testing.T, p, out string, _ []byte) {
			replaceWithSymlink(t, p, filepath.Join(out, "missing"))
		}},
		{"symlink to a directory", func(t *testing.T, p, out string, _ []byte) {
			replaceWithSymlink(t, p, out)
		}},
		{"hard link (nlink 2)", func(t *testing.T, p, out string, _ []byte) {
			if err := os.Link(p, filepath.Join(out, "hardlink")); err != nil {
				t.Skipf("hard link not possible here: %v", err)
			}
		}},
		{"fifo", func(t *testing.T, p, _ string, _ []byte) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"over MaxMessageBytes (wire-valid)", writeOver(encode(t, 2, sized(t, 2, mx+1)))},
		{"over MaxMessageBytes (garbage)", writeOver(fill(mx+1, 3))},
		{"garbage", writeOver(fill(100, 9))},
		{"empty file", writeOver(nil)},
		{"truncated", writeOver(valid2[:len(valid2)-1])},
		{"one byte", writeOver(valid2[:1])},
		{"duplicate field 1", writeOver(dupSeq)},
		{"fields out of order", writeOver(outOfOrder)},
		{"message_seq does not match the name", writeOver(encode(t, 7, envResult(1)))},
		{"message_seq absent (0)", writeOver(encode(t, 0, envResult(1)))},
		{"no payload", writeOver(noPayload)},
		{"payload with no member", writeOver(emptyPayload)},
		{"payload with two members", writeOver(twoMembers)},
		{"unknown field", writeOver(unknown)},
		{"trailing byte", writeOver(append(append([]byte{}, valid2...), 0xff))},
	}
}

func chmod(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

func replaceWithSymlink(t *testing.T, p, target string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

// TestOpenRemovesBadMessageFiles: R29 (strict check at start), AC23 (a
// file that fails is removed and counted). Nothing is followed; the other
// messages still load.
func TestOpenRemovesBadMessageFiles(t *testing.T) {
	for _, c := range badFileCases(t) {
		t.Run(c.name, func(t *testing.T) {
			o, dir, fs := fresh(t)
			enqueue(t, o, envResult(0))
			enqueue(t, o, envResult(1))
			enqueue(t, o, envResult(2))
			p := mustMsgPath(t, dir, 2)
			valid, err := os.ReadFile(p) // #nosec G304 -- test file under t.TempDir()
			if err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			c.do(t, p, outside, valid)
			before := snapshot(t, outside)

			o2 := openOrFail(t, dir, fs)
			equalSeqs(t, "Seqs after Open", o2.Seqs(), []uint64{1, 3})
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Fatalf("bad file still present (err %v)", err)
			}
			if r := o2.Stats().Rejected; r != 1 {
				t.Fatalf("Rejected = %d, want 1", r)
			}
			sameSnapshot(t, "outside directory", before, snapshot(t, outside))
			mustNext(t, o2, 1)
			mustNext(t, o2, 3)
			if s := enqueue(t, o2, envResult(4)); s != 4 {
				t.Fatalf("next seq = %d, want 4 (never reuse 2 or 3)", s)
			}
		})
	}
}

// TestOpenRemovesUnrecognisedNames: names outside the %020d.{g,r,t}
// pattern are removed and counted, never parsed loosely.
func TestOpenRemovesUnrecognisedNames(t *testing.T) {
	names := []string{
		"foo",
		"00000000000000000002",
		"00000000000000000002.x",
		"00000000000000000002.G",
		"00000000000000000002.gg",
		"00000000000000000002.g.bak",
		"2.g",
		"0000000000000000002.g",   // 19 digits
		"000000000000000000002.g", // 21 digits
		"00000000000000000000.g",  // seq 0
		"99999999999999999999.g",  // above 2^64-1
		"+0000000000000000002.g",
		"-0000000000000000002.g",
		" 0000000000000000002.g",
		"0x000000000000000002.g",
		"next-seq.bak",
		"tmp-1",
		"00000000000000000002.g\n",
		"0000000000000000000２.g", // fullwidth digit
	}
	for _, name := range names {
		for _, link := range []bool{false, true} {
			kind := "file"
			if link {
				kind = "symlink"
			}
			t.Run(kind+" "+name, func(t *testing.T) {
				o, dir, fs := fresh(t)
				enqueueN(t, o, 3)
				outside := t.TempDir()
				target := filepath.Join(outside, "target")
				if err := os.WriteFile(target, encode(t, 2, envResult(9)), 0o600); err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(dir, name)
				if link {
					if err := os.Symlink(target, p); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(p, encode(t, 2, envResult(9)), 0o600); err != nil {
					t.Fatal(err)
				}
				before := snapshot(t, outside)
				o2 := openOrFail(t, dir, fs)
				equalSeqs(t, "Seqs", o2.Seqs(), []uint64{1, 2, 3})
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Fatalf("%q still present", name)
				}
				if r := o2.Stats().Rejected; r != 1 {
					t.Fatalf("Rejected = %d, want 1", r)
				}
				sameSnapshot(t, "outside", before, snapshot(t, outside))
				if s := enqueue(t, o2, envResult(4)); s != 4 {
					t.Fatalf("next seq = %d, want 4", s)
				}
			})
		}
	}
}

func TestOpenRemovesTempFilesSilently(t *testing.T) {
	o, dir, fs := fresh(t)
	enqueueN(t, o, 2)
	for _, n := range []string{".tmp-", ".tmp-1", ".tmp-00000000000000000003.g", ".tmp-abc"} {
		if err := os.WriteFile(filepath.Join(dir, n), fill(50, 1), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	o2 := openOrFail(t, dir, fs)
	equalSeqs(t, "Seqs", o2.Seqs(), []uint64{1, 2})
	if r := o2.Stats().Rejected; r != 0 {
		t.Fatalf("Rejected = %d, want 0 (temp files are not counted)", r)
	}
	got := messageFiles(t, dir)
	want := []string{fileName(1, "g"), fileName(2, "g")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("files = %v, want %v", got, want)
	}
}

// TestReloadPreservesOrderAndBytes: R29, AC23 (same message_seq and bytes
// after restart; removed only after ACCEPTED/DUPLICATE/REJECTED).
func TestReloadPreservesOrderAndBytes(t *testing.T) {
	o, dir, fs := fresh(t)
	ps := []struct {
		seq uint64
		raw []byte
	}{}
	for _, p := range mixed() {
		seq := enqueue(t, o, p)
		ps = append(ps, struct {
			seq uint64
			raw []byte
		}{seq, encode(t, seq, p)})
	}
	first := map[uint64][]byte{}
	for i := 1; i <= 3; i++ {
		m := mustNext(t, o, uint64(i))
		first[m.Seq] = append([]byte{}, m.Bytes...)
	}
	ack(t, o, 1, accepted)
	ack(t, o, 2, retryLater)

	o2 := openOrFail(t, dir, fs)
	equalSeqs(t, "Seqs after reopen", o2.Seqs(), []uint64{2, 3, 4, 5, 6})
	if msgPath(dir, 1) != "" {
		t.Fatal("acknowledged message 1 is still on disk")
	}
	for _, want := range ps[1:] {
		m := mustNext(t, o2, want.seq)
		mustBytesEqual(t, "reloaded message", m.Bytes, want.raw)
		if b, ok := first[m.Seq]; ok {
			mustBytesEqual(t, "re-sent message", m.Bytes, b)
		}
	}
	if s := enqueue(t, o2, recovery(9)); s != 7 {
		t.Fatalf("seq after reopen = %d, want 7", s)
	}
}

func TestStatsMatchDiskAfterReload(t *testing.T) {
	o, dir, fs := fresh(t)
	enqueue(t, o, recovery(1))
	enqueue(t, o, statusReply(2))
	enqueue(t, o, bigReply(agentapiv1.ReplyKind_REPLY_KIND_STATUS, 3))
	fs.setAvail(0) // general part full: replies go to the reserves
	enqueue(t, o, envResult(4))
	enqueue(t, o, statusReply(5))
	enqueue(t, o, trustResult(6))
	enqueue(t, o, oversize())
	enqueue(t, o, trustResult(8))

	check := func(what string, st outbox.Stats) {
		t.Helper()
		var parts = map[string]*outbox.PartStats{"g": {}, "r": {}, "t": {}}
		for _, n := range messageFiles(t, dir) {
			fi, err := os.Lstat(filepath.Join(dir, n))
			if err != nil {
				t.Fatal(err)
			}
			ps := parts[filepath.Ext(n)[1:]]
			ps.Files++
			ps.Bytes += uint64(fi.Size()) // #nosec G115 -- block counts and sizes are non-negative
		}
		if st.General != *parts["g"] || st.Reserve != *parts["r"] || st.Trust != *parts["t"] {
			t.Fatalf("%s: parts %+v/%+v/%+v, disk %+v/%+v/%+v", what,
				st.General, st.Reserve, st.Trust, *parts["g"], *parts["r"], *parts["t"])
		}
		if st.Messages != 8 || st.Messages != parts["g"].Files+parts["r"].Files+parts["t"].Files {
			t.Fatalf("%s: Messages = %d, want 8", what, st.Messages)
		}
		if st.Bytes != parts["g"].Bytes+parts["r"].Bytes+parts["t"].Bytes {
			t.Fatalf("%s: Bytes = %d", what, st.Bytes)
		}
		if parts["g"].Files != 3 || parts["r"].Files != 2 || parts["t"].Files != 3 {
			t.Fatalf("%s: disk parts g=%d r=%d t=%d, want 3/2/3", what,
				parts["g"].Files, parts["r"].Files, parts["t"].Files)
		}
	}
	check("before reopen", o.Stats())
	fs.setAvail(1 << 40)
	o2 := openOrFail(t, dir, fs)
	check("after reopen", o2.Stats())
	if o2.Stats().Rejected != 0 {
		t.Fatalf("Rejected = %d after a clean reopen", o2.Stats().Rejected)
	}
}
