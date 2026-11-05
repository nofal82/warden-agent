package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

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
