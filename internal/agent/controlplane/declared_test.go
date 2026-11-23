package controlplane_test

// Issue #59: DecodeControl refuses undeclared enum values (PR #61 LOW
// finding) and carries envelope bytes opaque (AC37 agent leg).

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
)

// TestDecodeControlUndeclaredTrustKind: agent-api R12, §4.5. Every enum in
// ControlMessage is hand-checked by checkControl (outcome 99 is covered in
// TestDecodeControl); this pins the TrustDocument kind.
func TestDecodeControlUndeclaredTrustKind(t *testing.T) {
	t.Parallel()
	b := ctl(t, &agentapiv1.ControlMessage{Body: &agentapiv1.ControlMessage_Delivery{Delivery: &agentapiv1.Delivery{
		DeliveryId: 1,
		Content: &agentapiv1.DeliveryContent{Content: &agentapiv1.DeliveryContent_TrustDocument{
			TrustDocument: &agentapiv1.TrustDocument{Kind: wardenv1.TrustKind(99), Document: []byte("FAKE-DOC")},
		}},
	}}})
	if m, err := controlplane.DecodeControl(b); !errors.Is(err, controlplane.ErrControlRefused) || m != nil {
		t.Fatalf("DecodeControl = %v, %v; want ErrControlRefused", m, err)
	}
}

// TestDecodeControlEnvelopeOpaque: agent-api AC37, R22, R52a. A
// SignedEnvelope whose bytes are not canonical (fields in reverse order)
// and whose body carries envelope_counter (field 13) comes out of
// DecodeControl byte-identical: the agent never re-encodes it.
func TestDecodeControlEnvelopeOpaque(t *testing.T) {
	t.Parallel()
	body := protowire.AppendVarint(protowire.AppendTag(nil, 13, protowire.VarintType), 1<<62)
	body = protowire.AppendVarint(protowire.AppendTag(body, 1, protowire.VarintType), 1)
	var env []byte
	env = protowire.AppendBytes(protowire.AppendTag(env, 3, protowire.BytesType), bytes.Repeat([]byte{2}, 64))
	env = protowire.AppendBytes(protowire.AppendTag(env, 2, protowire.BytesType), body)
	env = protowire.AppendBytes(protowire.AppendTag(env, 1, protowire.BytesType), bytes.Repeat([]byte{1}, 32))
	want := append([]byte(nil), env...)
	b := ctl(t, &agentapiv1.ControlMessage{Body: &agentapiv1.ControlMessage_Delivery{Delivery: &agentapiv1.Delivery{
		DeliveryId: 1,
		Content: &agentapiv1.DeliveryContent{Content: &agentapiv1.DeliveryContent_Envelope{
			Envelope: &agentapiv1.EnvelopeDelivery{SignedEnvelope: env},
		}},
	}}})
	m, err := controlplane.DecodeControl(b)
	if err != nil {
		t.Fatalf("DecodeControl: %v", err)
	}
	got := m.GetDelivery().GetContent().GetEnvelope().GetSignedEnvelope()
	if !bytes.Equal(got, want) {
		t.Fatal("signed_envelope bytes changed")
	}
}
