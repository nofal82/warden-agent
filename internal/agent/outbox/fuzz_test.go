package outbox_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

// FuzzCheckFile: never panics; whenever it accepts, the bytes strict-decode
// to a message with the given seq, exactly one payload member, and a size
// within MaxMessageBytes.
func FuzzCheckFile(f *testing.F) {
	valid := encode(f, 2, envResult(1))
	seq2 := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 2)
	f.Add(uint64(2), valid)
	f.Add(uint64(3), valid)
	f.Add(uint64(0), valid)
	f.Add(uint64(5), encode(f, 5, advisory(1)))
	f.Add(uint64(7), encode(f, 7, oversize()))
	f.Add(uint64(1), encode(f, 1, recovery(1)))
	f.Add(uint64(2), append(append([]byte{}, seq2...), valid...))
	f.Add(uint64(2), append(append([]byte{}, valid[len(seq2):]...), seq2...))
	f.Add(uint64(2), seq2)
	f.Add(uint64(2), valid[:len(valid)-1])
	f.Add(uint64(2), []byte{})
	f.Add(uint64(2), []byte{0x08, 0x82, 0x00})
	f.Add(^uint64(0), encode(f, ^uint64(0), recovery(1)))
	f.Fuzz(func(t *testing.T, seq uint64, b []byte) {
		err := outbox.CheckFile(seq, b)
		if err != nil {
			return
		}
		mx, merr := outbox.MaxMessageBytes()
		if merr != nil {
			t.Fatalf("MaxMessageBytes: %v", merr)
		}
		if len(b) > mx {
			t.Fatalf("accepted %d bytes > %d", len(b), mx)
		}
		var m agentapiv1.OutboxMessage
		if err := agentapiv1.StrictUnmarshal(b, &m); err != nil {
			t.Fatalf("accepted bytes the strict decoder refuses: %v", err)
		}
		if seq == 0 || m.GetMessageSeq() != seq {
			t.Fatalf("accepted message_seq %d for name seq %d", m.GetMessageSeq(), seq)
		}
		if m.GetPayload().GetPayload() == nil {
			t.Fatal("accepted a message without a payload member")
		}
	})
}

// FuzzParseWatermark: nil error iff exactly 8 bytes with a value of at
// least 1, and then the big-endian value.
func FuzzParseWatermark(f *testing.F) {
	for _, s := range [][]byte{be(1), be(0), be(^uint64(0)), nil, {1}, make([]byte, 9), be(1)[1:]} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := outbox.ParseWatermark(b)
		valid := len(b) == 8 && binary.BigEndian.Uint64(b) >= 1
		if valid {
			if err != nil || v != binary.BigEndian.Uint64(b) {
				t.Fatalf("ParseWatermark(%x) = %d, %v", b, v, err)
			}
			return
		}
		if err == nil {
			t.Fatalf("ParseWatermark(%x) accepted %d", b, v)
		}
		if !errors.Is(err, outbox.ErrCorruptWatermark) {
			t.Fatalf("err = %v, want ErrCorruptWatermark", err)
		}
	})
}
