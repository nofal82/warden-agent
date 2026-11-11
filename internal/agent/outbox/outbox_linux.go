package outbox

import (
	"errors"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
)

var errNotImplemented = errors.New("outbox: not implemented")

// MaxMessageBytes is the largest OutboxMessage the outbox stores: the
// MAX_INBOX_MESSAGE limit of the whole AgentMessage carrying it (R11),
// minus that message's tag and length prefix.
func MaxMessageBytes() (int, error) { return 0, errNotImplemented }

// Outbox is an open outbox directory. It is safe for concurrent use.
type Outbox struct{}

// Open checks dir, confirms the storage limit, reloads every message and
// the watermark, and removes (logs, counts) every file that fails.
func Open(dir string, opt Options) (*Outbox, error) { return nil, errNotImplemented }

// Enqueue assigns the next message_seq, writes the message durably and
// returns its sequence.
func (o *Outbox) Enqueue(p *agentapiv1.OutboxPayload) (uint64, error) {
	return 0, errNotImplemented
}

// Next returns the next message to send in message_seq order, or false
// when Window messages are in flight or none is left.
func (o *Outbox) Next() (Message, bool, error) { return Message{}, false, errNotImplemented }

// Ack applies one MessageAck (R32).
func (o *Outbox) Ack(seq uint64, outcome agentapiv1.AckOutcome, reason agentapiv1.AckReason) error {
	return errNotImplemented
}

// Rewind forgets every message in flight: the next Next starts again from
// the oldest unacknowledged message (a new stream, R32).
func (o *Outbox) Rewind() {}

// Recheck re-checks every file with the strict decoder and removes the
// ones that fail (R32a); it returns how many it removed.
func (o *Outbox) Recheck() (int, error) { return 0, errNotImplemented }

// Seqs returns the message_seq of every queued message, ascending.
func (o *Outbox) Seqs() []uint64 { return nil }

// Stats returns the current figures.
func (o *Outbox) Stats() Stats { return Stats{} }

// checkFile is the strict check of one stored message: b decodes with the
// strict decoder, its message_seq equals seq (the file name's), exactly
// one payload member is set, and len(b) is within MaxMessageBytes.
func checkFile(seq uint64, b []byte) error { return errNotImplemented }

// parseWatermark decodes the watermark file: exactly 8 bytes, big-endian,
// a value of at least 1.
func parseWatermark(b []byte) (uint64, error) { return 0, errNotImplemented }
