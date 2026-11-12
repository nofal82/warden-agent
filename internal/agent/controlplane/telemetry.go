package controlplane

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/telemetry"
)

// UploadTelemetry constants (agent-api R46, R47, §4.9).
const (
	TelemetryDeadline   = 30 * time.Second
	TelemetryRetryFirst = 5 * time.Second
	TelemetryRetryCap   = 300 * time.Second
	// telemetryIdle is how often an empty buffer is looked at again.
	telemetryIdle = time.Second
	// maxTelemetryAck: field 1 tag and a 10-byte varint.
	maxTelemetryAck = 11
)

// ErrAckRefused: a TelemetryAck failed the size limit, the strict decoder,
// canonical encoding or batch_seq ≥ 1.
var ErrAckRefused = errors.New("controlplane: telemetry ack refused")

// TelemetrySource is the telemetry buffer as the uploader sees it
// (package telemetry). Accepted and Rejected with an unknown seq do
// nothing.
type TelemetrySource interface {
	Next() (seq uint64, body []byte, ok bool)
	Accepted(seq uint64)
	Rejected(seq uint64)
}

// DecodeTelemetryAck checks a TelemetryAck: at most 11 bytes, strictly
// decoded, canonical (one field, minimal varint) and batch_seq ≥ 1.
func DecodeTelemetryAck(b []byte) (*agentapiv1.TelemetryAck, error) {
	if len(b) > maxTelemetryAck {
		return nil, ErrAckRefused
	}
	var a agentapiv1.TelemetryAck
	if err := agentapiv1.StrictUnmarshal(b, &a); err != nil || a.GetBatchSeq() < 1 {
		return nil, ErrAckRefused
	}
	again, err := proto.MarshalOptions{Deterministic: true}.Marshal(&a)
	if err != nil || !bytes.Equal(again, b) {
		return nil, ErrAckRefused
	}
	return &a, nil
}

// uploadTelemetry sends the buffered batches one at a time on conn, the
// stream's own connection (R5), until ctx is done. It starts only after
// Welcome, so the control plane has seen Hello. A failed batch is retried
// with the R46 backoff while it is still buffered; INVALID_ARGUMENT drops
// it (§4.8: "drop the batch"). Telemetry never touches the outbox or the
// stream (R44).
func (s *session) uploadTelemetry(ctx context.Context, conn *grpc.ClientConn) {
	src := s.c.cfg.Telemetry
	failures := 0
	for ctx.Err() == nil {
		seq, body, ok := src.Next()
		if !ok {
			idle := time.NewTimer(telemetryIdle)
			select {
			case <-ctx.Done():
			case <-idle.C:
			}
			idle.Stop()
			continue
		}
		err := s.sendBatch(ctx, conn, seq, body)
		switch {
		case err == nil:
			src.Accepted(seq)
			failures = 0
			continue
		case status.Code(err) == codes.InvalidArgument:
			src.Rejected(seq)
			failures = 0
			continue
		case ctx.Err() != nil:
			return
		}
		failures++
		wait := min(s.c.clock.Jitter(doubling(TelemetryRetryFirst, TelemetryRetryCap, failures)), TelemetryRetryCap)
		if s.c.clock.Sleep(ctx, wait) != nil {
			return
		}
	}
}

func (s *session) sendBatch(ctx context.Context, conn *grpc.ClientConn, seq uint64, body []byte) error {
	cctx, cancel := context.WithTimeout(ctx, TelemetryDeadline)
	defer cancel()
	var frame rawFrame
	err := conn.Invoke(cctx, agentapiv1.AgentControl_UploadTelemetry_FullMethodName, &rawFrame{b: body}, &frame,
		grpc.MaxCallSendMsgSize(telemetry.MaxBatchBytes), grpc.MaxCallRecvMsgSize(maxTelemetryAck))
	if err != nil {
		return err
	}
	a, err := DecodeTelemetryAck(frame.b)
	if err != nil {
		return err
	}
	if a.GetBatchSeq() != seq {
		return ErrAckRefused // never counted as an acknowledgement of this batch
	}
	return nil
}

// healthDrops copies the redact_drops of §4.6a: classes with drops only,
// sorted and distinct by class, each capped at 2^40.
func healthDrops(in []*agentapiv1.RedactDropCount) []*agentapiv1.RedactDropCount {
	out := make([]*agentapiv1.RedactDropCount, 0, len(in))
	for _, d := range in {
		if d.GetDropped() == 0 || d.GetClass() < agentapiv1.RedactClass_REDACT_CLASS_T_NAME ||
			d.GetClass() > agentapiv1.RedactClass_REDACT_CLASS_UNSIGNED_BODY {
			continue
		}
		out = append(out, &agentapiv1.RedactDropCount{Class: d.GetClass(), Dropped: min(d.GetDropped(), maxCounter)})
	}
	slices.SortFunc(out, func(a, b *agentapiv1.RedactDropCount) int { return int(a.GetClass()) - int(b.GetClass()) })
	return slices.CompactFunc(out, func(a, b *agentapiv1.RedactDropCount) bool { return a.GetClass() == b.GetClass() })
}
