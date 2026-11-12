package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/mem"
)

func TestRealClockSleep(t *testing.T) {
	t.Parallel()
	c := realClock{}
	if err := c.Sleep(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("Sleep: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := c.Now()
	if err := c.Sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sleep on a cancelled context = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Sleep did not return on cancel")
	}
}

func TestRawCodecRefusesOtherTypes(t *testing.T) {
	t.Parallel()
	if _, err := (rawCodec{}).Marshal("not a message"); err == nil {
		t.Fatal("Marshal accepted a non-message")
	}
	if err := (rawCodec{}).Unmarshal(mem.BufferSlice{}, new(int)); err == nil {
		t.Fatal("Unmarshal accepted a non-frame")
	}
}

// blockedStream is a ClientStream whose SendMsg blocks until its context
// ends, as when the peer never opens its flow-control window.
type blockedStream struct {
	grpc.ClientStream
	ctx context.Context
}

func (b blockedStream) SendMsg(any) error { <-b.ctx.Done(); return b.ctx.Err() }

// A send blocked by flow control must not wedge the stream: the watchdog
// ends it after MESSAGE_ACK_TIMEOUT (R32, R47).
func TestWatchdogEndsBlockedSend(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &ConnectClient{t: timings{AckTimeout: 50 * time.Millisecond}}
	s := newSession(c, blockedStream{ctx: ctx}, streamLimits{send: 1 << 20}, cancel)
	go s.watchdog(ctx)
	done := make(chan error, 1)
	go func() { done <- s.sendRaw([]byte{1}) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrAckTimeout) {
			t.Fatalf("sendRaw = %v, want ErrAckTimeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked send was never ended")
	}
}
