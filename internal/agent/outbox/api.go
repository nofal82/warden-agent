package outbox

import (
	"errors"
	"log/slog"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
)

// Limits of agent-api §7 and R31, R33. Byte limits are logical: the sum of
// the outbox files' sizes.
const (
	Window = 8 // OUTBOX_WINDOW: unacknowledged messages at a time (R31)

	MaxGeneralFiles = 20_000   // OUTBOX_MAX_MESSAGES
	MaxGeneralBytes = 64 << 20 // OUTBOX_MAX_BYTES

	ReserveBytes = 1 << 20 // OUTBOX_RESERVE_BYTES (in-flight replies)
	ReserveFiles = 64

	TrustReserveBytes = 1 << 20 // OUTBOX_TRUST_RESERVE_BYTES
	TrustReserveFiles = 1_024

	MaxFiles = MaxGeneralFiles + ReserveFiles + TrustReserveFiles // OUTBOX_MAX_FILES, 21,088

	StorageBudget  = 96 << 20 // OUTBOX_STORAGE_BUDGET
	FreeSpaceFloor = 8 << 20  // statfs floor for general-part writes
)

// WatermarkFile is the next-sequence watermark in the outbox directory.
const WatermarkFile = "next-seq"

// Part is the slice of the outbox a message file is counted against.
type Part int

// The three parts of R33.
const (
	PartGeneral Part = iota + 1
	PartReserve      // in-flight replies (R33 item 3)
	PartTrust        // trust-document results and oversize reports (item 2a)
)

// Condition is the outbox's health condition (R33 items 1, 2).
type Condition int

// Conditions, least severe first.
const (
	ConditionNone      Condition = iota
	ConditionHighWater           // OUTBOX_HIGH_WATER: 80 % of a general limit
	ConditionFull                // OUTBOX_FULL: at a general limit, until under 90 % of both
)

// Errors. Callers test them with errors.Is.
var (
	// ErrFull: the general part cannot take the message (a cap or the
	// free-space floor) and the message may not use a reserve.
	ErrFull = errors.New("outbox: full")
	// ErrReserveFull: the general part is full and so is the reserve the
	// message may use.
	ErrReserveFull = errors.New("outbox: reserve full")
	// ErrInvalidMessage: the payload is nil, empty, or does not pass the
	// strict decoder after encoding.
	ErrInvalidMessage = errors.New("outbox: invalid message")
	// ErrTooLarge: the encoded message would exceed MaxMessageBytes.
	ErrTooLarge = errors.New("outbox: message too large")
	// ErrUnexpectedAck: an acknowledgement for a message_seq not in
	// flight, or with an outcome outside ACCEPTED, DUPLICATE, RETRY_LATER,
	// REJECTED. The caller ends the stream.
	ErrUnexpectedAck = errors.New("outbox: unexpected acknowledgement")
	// ErrUnsafeDir: the directory or a file in it fails the ownership,
	// mode or type checks, or the process is root.
	ErrUnsafeDir = errors.New("outbox: unsafe directory")
	// ErrStorageUnconfirmed: the outbox's storage limit cannot be
	// confirmed (R33 "Storage"); the agent must not start.
	ErrStorageUnconfirmed = errors.New("outbox: storage limit not confirmed")
	// ErrCorruptWatermark: the watermark file exists but is not valid.
	ErrCorruptWatermark = errors.New("outbox: corrupt watermark")
	// ErrSequenceExhausted: no message_seq is left.
	ErrSequenceExhausted = errors.New("outbox: message_seq exhausted")
)

// FSStat is what the outbox needs from statfs(2) for its storage.
type FSStat struct {
	TotalBytes uint64 // size of the filesystem
	AvailBytes uint64 // free space available to the agent user
	BlockSize  uint64 // allocation unit; a file takes a multiple of it
}

// Options configure Open. The zero value is the production setting.
type Options struct {
	// Logger receives removals and rejections; nil discards.
	Logger *slog.Logger
	// Statfs reports the storage of the open outbox directory; nil uses
	// fstatfs(2) on the directory descriptor.
	Statfs func(dirFD int) (FSStat, error)
	// ConfirmStorage checks the storage limit at Open; nil requires a
	// dedicated filesystem no larger than StorageBudget.
	ConfirmStorage func(FSStat) error
}

// Message is one queued message: its sequence and the exact bytes sent.
type Message struct {
	Seq   uint64
	Bytes []byte
}

// Stats are the outbox figures for the health report (§4.4).
type Stats struct {
	Messages  uint64 // files in all parts
	Bytes     uint64 // logical bytes in all parts
	Rejected  uint64 // REJECTED, or removed by a strict check, since Open
	Condition Condition
	General   PartStats
	Reserve   PartStats
	Trust     PartStats
}

// PartStats are the figures of one part.
type PartStats struct {
	Files uint64
	Bytes uint64
}

// PartFor returns the part a payload may overflow into when the general
// part is full: PartTrust for a TRUST_RESULT reply and a
// TrustDocumentOversize report, PartReserve for any other signed reply,
// PartGeneral (no overflow) for every other report.
func PartFor(p *agentapiv1.OutboxPayload) Part {
	switch {
	case p.GetTrustDocumentOversize() != nil:
		return PartTrust
	case p.GetSignedReply() != nil:
		if p.GetSignedReply().GetKind() == agentapiv1.ReplyKind_REPLY_KIND_TRUST_RESULT {
			return PartTrust
		}
		return PartReserve
	default:
		return PartGeneral
	}
}
