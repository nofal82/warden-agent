package outbox_test

import (
	"errors"
	"testing"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

// TestFullGeneralRoutesByPart: R33 items 2, 2a, 3 (signed replies overflow
// into the in-flight reserve, trust results and oversize reports into the
// trust reserve, everything else is refused).
func TestFullGeneralRoutesByPart(t *testing.T) {
	cases := []struct {
		name   string
		p      *agentapiv1.OutboxPayload
		part   outbox.Part
		suffix string // "" means ErrFull
	}{
		{"envelope result", envResult(1), outbox.PartReserve, "r"},
		{"status", statusReply(1), outbox.PartReserve, "r"},
		{"trust result", trustResult(1), outbox.PartTrust, "t"},
		{"trust document oversize", oversize(), outbox.PartTrust, "t"},
		{"envelope advisory", advisory(1), outbox.PartGeneral, ""},
		{"recovery report", recovery(1), outbox.PartGeneral, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := outbox.PartFor(c.p); got != c.part {
				t.Fatalf("PartFor = %v, want %v", got, c.part)
			}
			o, dir, fs := fresh(t)
			enqueue(t, o, recovery(0))
			fs.setAvail(0)
			before := snapshot(t, dir)
			seq, err := o.Enqueue(c.p)
			if c.suffix == "" {
				if !errors.Is(err, outbox.ErrFull) {
					t.Fatalf("err = %v, want ErrFull", err)
				}
				sameSnapshot(t, "dir after ErrFull", before, snapshot(t, dir))
				return
			}
			if err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			if got := suffixOf(t, dir, seq); got != c.suffix {
				t.Fatalf("stored in .%s, want .%s", got, c.suffix)
			}
			mustBytesEqual(t, "reserve file via Next", mustNext(t, o, 1).Bytes, encode(t, 1, recovery(0)))
			mustBytesEqual(t, "reserve file via Next", mustNext(t, o, 2).Bytes, encode(t, 2, c.p))
		})
	}
}

// TestFreeSpaceFloorBoundary: R33 Storage (free space minus the new file's
// block-rounded allocation must stay at or above FreeSpaceFloor; reserve
// writes are never refused by it).
func TestFreeSpaceFloorBoundary(t *testing.T) {
	const floor = outbox.FreeSpaceFloor
	small := recovery(1) // one block
	cases := []struct {
		name  string
		avail uint64
		block uint64
		p     func(t *testing.T) *agentapiv1.OutboxPayload
		want  string // "g", "r", "t" or "full"
	}{
		{"exactly at floor after write", floor + blockSize, blockSize, nil, "g"},
		{"one byte under", floor + blockSize - 1, blockSize, nil, "full"},
		{"one block under", floor, blockSize, nil, "full"},
		{"avail below allocation (no underflow)", 100, blockSize, nil, "full"},
		{"avail zero", 0, blockSize, nil, "full"},
		{"plenty", 1 << 40, blockSize, nil, "g"},
		{"avail max", ^uint64(0), blockSize, nil, "g"},
		{"two blocks: at floor", floor + 2*blockSize, blockSize,
			func(t *testing.T) *agentapiv1.OutboxPayload { return sized(t, 1, blockSize+1) }, "g"},
		{"two blocks: one byte under", floor + 2*blockSize - 1, blockSize,
			func(t *testing.T) *agentapiv1.OutboxPayload { return sized(t, 1, blockSize+1) }, "r"},
		{"exact block: at floor", floor + blockSize, blockSize,
			func(t *testing.T) *agentapiv1.OutboxPayload { return sized(t, 1, blockSize) }, "g"},
		{"reserve ignores floor (avail 0)", 0, blockSize,
			func(*testing.T) *agentapiv1.OutboxPayload { return envResult(1) }, "r"},
		{"trust reserve ignores floor (avail 0)", 0, blockSize,
			func(*testing.T) *agentapiv1.OutboxPayload { return trustResult(1) }, "t"},
		{"large block size", floor + 65536, 65536, nil, "g"},
		{"large block size one under", floor + 65535, 65536, nil, "full"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, dir, fs := fresh(t)
			fs.st.BlockSize = c.block
			fs.setAvail(c.avail)
			p := small
			if c.p != nil {
				p = c.p(t)
			}
			seq, err := o.Enqueue(p)
			if c.want == "full" {
				if !errors.Is(err, outbox.ErrFull) {
					t.Fatalf("err = %v, want ErrFull", err)
				}
				if o.Stats().Condition != outbox.ConditionFull {
					t.Fatalf("Condition = %v, want Full", o.Stats().Condition)
				}
				return
			}
			if err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			if got := suffixOf(t, dir, seq); got != c.want {
				t.Fatalf("stored in .%s, want .%s", got, c.want)
			}
		})
	}
	t.Run("block size zero does not panic", func(t *testing.T) {
		o, _, fs := fresh(t)
		fs.st.BlockSize = 0
		if _, err := o.Enqueue(small); err != nil && !errors.Is(err, outbox.ErrFull) {
			t.Fatalf("err = %v, want nil or ErrFull", err)
		}
	})
}

// TestStatfsErrorTreatsGeneralAsFull: fail safe, never a panic.
func TestStatfsErrorTreatsGeneralAsFull(t *testing.T) {
	o, dir, fs := fresh(t)
	fs.setErr(errors.New("EIO"))
	if _, err := o.Enqueue(recovery(1)); !errors.Is(err, outbox.ErrFull) {
		t.Fatalf("advisory: err = %v, want ErrFull", err)
	}
	if s := enqueue(t, o, envResult(1)); suffixOf(t, dir, s) != "r" {
		t.Fatal("signed reply not in the in-flight reserve")
	}
	if s := enqueue(t, o, trustResult(1)); suffixOf(t, dir, s) != "t" {
		t.Fatal("trust result not in the trust reserve")
	}
	if c := o.Stats().Condition; c != outbox.ConditionFull {
		t.Fatalf("Condition = %v, want Full", c)
	}
}

// fillReserve fills a reserve with copies of p until the next one would
// exceed maxBytes; it returns how many it wrote.
func fillReserve(t *testing.T, o *outbox.Outbox, dir string, p *agentapiv1.OutboxPayload, maxBytes int, suffix string) int {
	t.Helper()
	size := len(encode(t, 1, p))
	n := maxBytes / size
	for i := 0; i < n; i++ {
		if s := enqueue(t, o, p); suffixOf(t, dir, s) != suffix {
			t.Fatalf("message %d not in .%s", i, suffix)
		}
	}
	return n
}

// TestInFlightReserveCaps: R33 (OUTBOX_RESERVE_BYTES, at most 64 files);
// nothing queued is dropped or overwritten.
func TestInFlightReserveCaps(t *testing.T) {
	t.Run("files", func(t *testing.T) {
		o, dir, fs := fresh(t)
		fs.setAvail(0)
		for i := 0; i < outbox.ReserveFiles; i++ {
			if s := enqueue(t, o, envResult(byte(i))); suffixOf(t, dir, s) != "r" {
				t.Fatalf("reply %d not in the reserve", i)
			}
		}
		before := snapshot(t, dir)
		for _, p := range []*agentapiv1.OutboxPayload{envResult(99), statusReply(99)} {
			if _, err := o.Enqueue(p); !errors.Is(err, outbox.ErrReserveFull) {
				t.Fatalf("err = %v, want ErrReserveFull", err)
			}
		}
		sameSnapshot(t, "dir after ErrReserveFull", before, snapshot(t, dir))
		if st := o.Stats().Reserve; st.Files != outbox.ReserveFiles {
			t.Fatalf("Reserve.Files = %d", st.Files)
		}
		// An acknowledgement frees room.
		mustNext(t, o, 1)
		ack(t, o, 1, accepted)
		if s := enqueue(t, o, envResult(100)); s != outbox.ReserveFiles+1 || suffixOf(t, dir, s) != "r" {
			t.Fatalf("after an ack: seq %d", s)
		}
	})
	t.Run("bytes", func(t *testing.T) {
		o, dir, fs := fresh(t)
		fs.setAvail(0)
		p := bigReply(agentapiv1.ReplyKind_REPLY_KIND_STATUS, 1)
		n := fillReserve(t, o, dir, p, outbox.ReserveBytes, "r")
		before := snapshot(t, dir)
		if _, err := o.Enqueue(p); !errors.Is(err, outbox.ErrReserveFull) {
			t.Fatalf("message %d: err = %v, want ErrReserveFull", n+1, err)
		}
		sameSnapshot(t, "dir", before, snapshot(t, dir))
		if b := o.Stats().Reserve.Bytes; b > outbox.ReserveBytes {
			t.Fatalf("Reserve.Bytes = %d > %d", b, outbox.ReserveBytes)
		}
		// A small reply still fits in the bytes left.
		if s := enqueue(t, o, envResult(1)); suffixOf(t, dir, s) != "r" {
			t.Fatal("small reply not in the reserve")
		}
	})
}

// TestTrustReserveCaps: R33 item 2a (OUTBOX_TRUST_RESERVE_BYTES, at most
// 1,024 files; still written when the disk is nearly full).
func TestTrustReserveCaps(t *testing.T) {
	t.Run("files", func(t *testing.T) {
		o, dir, fs := fresh(t)
		fs.setAvail(0)
		for i := 0; i < outbox.TrustReserveFiles; i++ {
			p := trustResult(byte(i))
			if i%2 == 1 {
				p = oversize()
			}
			if _, err := o.Enqueue(p); err != nil {
				t.Fatalf("trust message %d: %v", i, err)
			}
		}
		if st := o.Stats().Trust; st.Files != outbox.TrustReserveFiles {
			t.Fatalf("Trust.Files = %d", st.Files)
		}
		before := snapshot(t, dir)
		for _, p := range []*agentapiv1.OutboxPayload{trustResult(1), oversize()} {
			if _, err := o.Enqueue(p); !errors.Is(err, outbox.ErrReserveFull) {
				t.Fatalf("err = %v, want ErrReserveFull", err)
			}
		}
		sameSnapshot(t, "dir", before, snapshot(t, dir))
	})
	t.Run("bytes", func(t *testing.T) {
		o, dir, fs := fresh(t)
		fs.setAvail(0)
		p := bigReply(agentapiv1.ReplyKind_REPLY_KIND_TRUST_RESULT, 1)
		fillReserve(t, o, dir, p, outbox.TrustReserveBytes, "t")
		before := snapshot(t, dir)
		if _, err := o.Enqueue(p); !errors.Is(err, outbox.ErrReserveFull) {
			t.Fatalf("err = %v, want ErrReserveFull", err)
		}
		sameSnapshot(t, "dir", before, snapshot(t, dir))
		if b := o.Stats().Trust.Bytes; b > outbox.TrustReserveBytes {
			t.Fatalf("Trust.Bytes = %d", b)
		}
	})
}

// TestReservesAreSeparate: the trust reserve is a slice nothing else may
// use (R33 item 2a), and trust results never take the in-flight reserve.
func TestReservesAreSeparate(t *testing.T) {
	t.Run("trust full, in-flight empty", func(t *testing.T) {
		o, dir, fs := fresh(t)
		fs.setAvail(0)
		fillReserve(t, o, dir, bigReply(agentapiv1.ReplyKind_REPLY_KIND_TRUST_RESULT, 1), outbox.TrustReserveBytes, "t")
		before := snapshot(t, dir)
		if _, err := o.Enqueue(bigReply(agentapiv1.ReplyKind_REPLY_KIND_TRUST_RESULT, 2)); !errors.Is(err, outbox.ErrReserveFull) {
			t.Fatalf("trust result: err = %v, want ErrReserveFull (must not use the in-flight reserve)", err)
		}
		sameSnapshot(t, "dir", before, snapshot(t, dir))
		if s := enqueue(t, o, bigReply(agentapiv1.ReplyKind_REPLY_KIND_STATUS, 3)); suffixOf(t, dir, s) != "r" {
			t.Fatal("status reply not in the in-flight reserve")
		}
	})
	t.Run("in-flight full, trust empty", func(t *testing.T) {
		o, dir, fs := fresh(t)
		fs.setAvail(0)
		fillReserve(t, o, dir, bigReply(agentapiv1.ReplyKind_REPLY_KIND_STATUS, 1), outbox.ReserveBytes, "r")
		before := snapshot(t, dir)
		for _, p := range []*agentapiv1.OutboxPayload{
			bigReply(agentapiv1.ReplyKind_REPLY_KIND_STATUS, 2),
			bigReply(agentapiv1.ReplyKind_REPLY_KIND_ENVELOPE_RESULT, 2),
		} {
			if _, err := o.Enqueue(p); !errors.Is(err, outbox.ErrReserveFull) {
				t.Fatalf("err = %v, want ErrReserveFull (must not use the trust reserve)", err)
			}
		}
		sameSnapshot(t, "dir", before, snapshot(t, dir))
		if s := enqueue(t, o, bigReply(agentapiv1.ReplyKind_REPLY_KIND_TRUST_RESULT, 3)); suffixOf(t, dir, s) != "t" {
			t.Fatal("trust result not in the trust reserve")
		}
		if _, err := o.Enqueue(advisory(1)); !errors.Is(err, outbox.ErrFull) {
			t.Fatalf("advisory: err = %v, want ErrFull", err)
		}
	})
}

// TestConditionFullUntilAcked: R33 item 2 (OUTBOX_FULL from a general
// refusal until the general part is under 90 % of both limits).
func TestConditionFullUntilAcked(t *testing.T) {
	o, dir, fs := fresh(t)
	enqueue(t, o, recovery(1))
	enqueue(t, o, recovery(2))
	if c := o.Stats().Condition; c != outbox.ConditionNone {
		t.Fatalf("Condition = %v, want None", c)
	}
	fs.setAvail(0)
	if _, err := o.Enqueue(advisory(1)); !errors.Is(err, outbox.ErrFull) {
		t.Fatalf("err = %v, want ErrFull", err)
	}
	if c := o.Stats().Condition; c != outbox.ConditionFull {
		t.Fatalf("Condition = %v, want Full", c)
	}
	enqueue(t, o, envResult(1)) // into the reserve
	if c := o.Stats().Condition; c != outbox.ConditionFull {
		t.Fatalf("Condition after a reserve write = %v, want Full", c)
	}
	fs.setAvail(1 << 40)
	if c := o.Stats().Condition; c != outbox.ConditionFull {
		t.Fatalf("Condition before the next write = %v, want Full", c)
	}
	// The floor is re-checked on the next write: space is back, so the
	// write goes into the general part and OUTBOX_FULL clears.
	if s := enqueue(t, o, advisory(2)); suffixOf(t, dir, s) != "g" {
		t.Fatal("advisory not in the general part")
	}
	if c := o.Stats().Condition; c != outbox.ConditionNone {
		t.Fatalf("Condition after a general write with space = %v, want None", c)
	}
}

// TestTransientStatfsErrorDoesNotStickFull: one statfs failure makes the
// general part full for that write only; the next write re-checks, so
// OUTBOX_FULL cannot stay set and keep the control plane from signing for
// this server (R33 item 4; security review MEDIUM).
func TestTransientStatfsErrorDoesNotStickFull(t *testing.T) {
	o, dir, fs := fresh(t)
	fs.setErr(errors.New("statfs: transient"))
	if _, err := o.Enqueue(advisory(1)); !errors.Is(err, outbox.ErrFull) {
		t.Fatalf("err = %v, want ErrFull", err)
	}
	if c := o.Stats().Condition; c != outbox.ConditionFull {
		t.Fatalf("Condition = %v, want Full", c)
	}
	fs.setErr(nil)
	if s := enqueue(t, o, advisory(2)); suffixOf(t, dir, s) != "g" {
		t.Fatal("advisory not in the general part")
	}
	if c := o.Stats().Condition; c != outbox.ConditionNone {
		t.Fatalf("Condition = %v, want None", c)
	}
}

// TestGeneralFileCapAndHighWater: R33 OUTBOX_MAX_MESSAGES, item 1, AC26.
func TestGeneralFileCapAndHighWater(t *testing.T) {
	if testing.Short() {
		t.Skip("loads 20,000 files")
	}
	rec := func(i uint64) *agentapiv1.OutboxPayload { return recovery(byte(i)) } // #nosec G115 -- test seed, wraps by design
	high := outbox.MaxGeneralFiles * 8 / 10
	{
		dir := newDir(t)
		seedGeneral(t, dir, uint64(high-2), rec)
		o := openOrFail(t, dir, newFakeFS())
		for i := high - 1; i <= high; i++ {
			enqueue(t, o, recovery(byte(i))) // #nosec G115 -- test seed, wraps by design
			c := o.Stats().Condition
			switch {
			case i == high-1 && c != outbox.ConditionNone:
				t.Fatalf("%d files: Condition %v, want None", i, c)
			case i == high && c != outbox.ConditionHighWater:
				t.Fatalf("%d files: Condition %v, want HighWater", i, c)
			}
		}
	}
	dir := newDir(t)
	seedGeneral(t, dir, outbox.MaxGeneralFiles-2, rec)
	o := openOrFail(t, dir, newFakeFS())
	for i := outbox.MaxGeneralFiles - 1; i <= outbox.MaxGeneralFiles; i++ {
		enqueue(t, o, recovery(byte(i))) // #nosec G115 -- test seed, wraps by design
	}
	before := snapshot(t, dir)
	if _, err := o.Enqueue(recovery(0)); !errors.Is(err, outbox.ErrFull) {
		t.Fatalf("file %d: err = %v, want ErrFull", outbox.MaxGeneralFiles+1, err)
	}
	sameSnapshot(t, "dir", before, snapshot(t, dir))
	if c := o.Stats().Condition; c != outbox.ConditionFull {
		t.Fatalf("Condition = %v, want Full", c)
	}
	if s := enqueue(t, o, envResult(1)); suffixOf(t, dir, s) != "r" {
		t.Fatal("reply not in the reserve")
	}
	if g := o.Stats().General.Files; g != outbox.MaxGeneralFiles {
		t.Fatalf("General.Files = %d", g)
	}
	resume := uint64(outbox.MaxGeneralFiles * 9 / 10) // Full until strictly under
	for o.Stats().General.Files >= resume {
		if c := o.Stats().Condition; c != outbox.ConditionFull {
			t.Fatalf("Condition %v with %d general files, want Full", c, o.Stats().General.Files)
		}
		m, ok := next(t, o)
		if !ok {
			t.Fatal("Next ran dry")
		}
		ack(t, o, m.Seq, accepted)
	}
	if c := o.Stats().Condition; c != outbox.ConditionHighWater {
		t.Fatalf("Condition at %d general files = %v, want HighWater", o.Stats().General.Files, c)
	}
}

// TestGeneralByteCapAndHighWater: R33 OUTBOX_MAX_BYTES, item 1.
func TestGeneralByteCapAndHighWater(t *testing.T) {
	if testing.Short() {
		t.Skip("loads about 64 MiB")
	}
	p := bigReply(agentapiv1.ReplyKind_REPLY_KIND_STATUS, 1)
	dir := newDir(t)
	// Start just under high water: about 920 of the ~1,170 messages that fit.
	seedGeneral(t, dir, 920, func(uint64) *agentapiv1.OutboxPayload { return p })
	o := openOrFail(t, dir, newFakeFS())
	if c := o.Stats().Condition; c != outbox.ConditionNone {
		t.Fatalf("seeded Condition = %v, want None", c)
	}
	size := uint64(len(encode(t, 1, p)))
	for i := 0; ; i++ {
		before := o.Stats().General.Bytes
		s := enqueue(t, o, p)
		st := o.Stats()
		if suffixOf(t, dir, s) == "r" {
			if before > outbox.MaxGeneralBytes || before+size+2 <= outbox.MaxGeneralBytes {
				t.Fatalf("general refused at %d bytes (message %d bytes)", before, size)
			}
			if st.Condition != outbox.ConditionFull {
				t.Fatalf("Condition = %v, want Full", st.Condition)
			}
			break
		}
		want := outbox.ConditionNone
		if st.General.Bytes*10 >= outbox.MaxGeneralBytes*8 {
			want = outbox.ConditionHighWater
		}
		if st.Condition != want {
			t.Fatalf("%d general bytes: Condition %v, want %v", st.General.Bytes, st.Condition, want)
		}
		if i > 2000 {
			t.Fatal("general byte cap never reached")
		}
	}
	// A small advisory may still fit under the byte cap; it must never
	// go into a reserve, and the cap must hold either way.
	if s, err := o.Enqueue(advisory(1)); err == nil {
		if suffixOf(t, dir, s) != "g" {
			t.Fatal("advisory written outside the general part")
		}
	} else if !errors.Is(err, outbox.ErrFull) {
		t.Fatalf("advisory: err = %v, want nil or ErrFull", err)
	}
	if b := o.Stats().General.Bytes; b > outbox.MaxGeneralBytes {
		t.Fatalf("General.Bytes = %d > cap", b)
	}
}
