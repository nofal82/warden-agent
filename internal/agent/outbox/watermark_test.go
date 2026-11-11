package outbox_test

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/nofal82/warden-agent/internal/agent/outbox"
)

// TestWatermarkFileFormat: R29 (watermark written before the message file
// that uses the value; never behind any assigned seq).
func TestWatermarkFileFormat(t *testing.T) {
	o, dir, _ := fresh(t)
	for i := uint64(1); i <= 5; i++ {
		seq := enqueue(t, o, envResult(byte(i)))
		if seq != i {
			t.Fatalf("seq = %d, want %d", seq, i)
		}
		if wm := readWatermark(t, dir); wm != seq+1 {
			t.Fatalf("watermark = %d after seq %d, want %d", wm, seq, seq+1)
		}
		for _, n := range []string{outbox.WatermarkFile, fileName(seq, "g")} {
			fi, err := os.Lstat(filepath.Join(dir, n))
			if err != nil {
				t.Fatal(err)
			}
			if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
				t.Fatalf("%s mode = %v, want regular 0600", n, fi.Mode())
			}
		}
	}
}

// TestSeqNeverReusedAfterDrain: AC23 (after the outbox drains to empty the
// next message_seq is above every one used before).
func TestSeqNeverReusedAfterDrain(t *testing.T) {
	o, dir, fs := fresh(t)
	for _, s := range enqueueN(t, o, 3) {
		mustNext(t, o, s)
		ack(t, o, s, accepted)
	}
	if f := messageFiles(t, dir); len(f) != 0 {
		t.Fatalf("files after drain: %v", f)
	}
	if s := enqueue(t, o, recovery(1)); s != 4 {
		t.Fatalf("seq after drain = %d, want 4", s)
	}
	mustNext(t, o, 4)
	ack(t, o, 4, duplicate)

	o2 := openOrFail(t, dir, fs)
	if s := enqueue(t, o2, recovery(2)); s != 5 {
		t.Fatalf("seq after drain and reopen = %d, want 5", s)
	}
}

// TestSeqNeverReusedAfterLastFileDeleted: AC23 (a crash that removed the
// last message file).
func TestSeqNeverReusedAfterLastFileDeleted(t *testing.T) {
	o, dir, fs := fresh(t)
	enqueueN(t, o, 3)
	for _, s := range []uint64{3, 2} {
		if err := os.Remove(mustMsgPath(t, dir, s)); err != nil {
			t.Fatal(err)
		}
	}
	o2 := openOrFail(t, dir, fs)
	equalSeqs(t, "Seqs", o2.Seqs(), []uint64{1})
	if s := enqueue(t, o2, recovery(1)); s != 4 {
		t.Fatalf("seq = %d, want 4 (2 and 3 were used)", s)
	}
}

// TestCorruptWatermarkRefused: a watermark that exists but is invalid
// stops Open; nothing on disk is changed (the agent cannot know which seqs
// were used).
func TestCorruptWatermarkRefused(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"7 bytes", make([]byte, 7)},
		{"9 bytes", append(be(5), 0)},
		{"16 bytes", append(be(5), be(5)...)},
		{"zero", be(0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, dir, fs := fresh(t)
			enqueueN(t, o, 2)
			if err := os.WriteFile(filepath.Join(dir, outbox.WatermarkFile), c.b, 0o600); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, dir)
			_, err := openTimed(t, dir, opts(fs))
			if !errors.Is(err, outbox.ErrCorruptWatermark) {
				t.Fatalf("err = %v, want ErrCorruptWatermark", err)
			}
			sameSnapshot(t, "outbox dir", before, snapshot(t, dir))
		})
	}
	others := []struct {
		name  string
		setup func(t *testing.T, wm, outside string)
	}{
		{"symlink to a valid watermark", func(t *testing.T, wm, out string) {
			target := filepath.Join(out, "wm")
			if err := os.WriteFile(target, be(1000), 0o600); err != nil {
				t.Fatal(err)
			}
			replaceWithSymlink(t, wm, target)
		}},
		{"directory", func(t *testing.T, wm, _ string) {
			if err := os.Remove(wm); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(wm, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range others {
		t.Run(c.name, func(t *testing.T) {
			o, dir, fs := fresh(t)
			enqueueN(t, o, 2)
			outside := t.TempDir()
			c.setup(t, filepath.Join(dir, outbox.WatermarkFile), outside)
			before := snapshot(t, outside)
			if _, err := openTimed(t, dir, opts(fs)); err == nil {
				t.Fatal("Open succeeded with an unsafe watermark")
			}
			sameSnapshot(t, "outside", before, snapshot(t, outside))
		})
	}
}

func be(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// TestWatermarkRecoveredFromFiles: the next seq is above every file and
// never below the watermark.
func TestWatermarkRecoveredFromFiles(t *testing.T) {
	cases := []struct {
		name string
		wm   uint64 // 0: remove the watermark
		want uint64
	}{
		{"lower than a file", 2, 4},
		{"equal to the last file", 3, 4},
		{"exact", 4, 4},
		{"higher", 100, 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, dir, fs := fresh(t)
			enqueueN(t, o, 3)
			if c.wm == 0 {
				if err := os.Remove(filepath.Join(dir, outbox.WatermarkFile)); err != nil {
					t.Fatal(err)
				}
			} else {
				writeWatermark(t, dir, c.wm)
			}
			o2 := openOrFail(t, dir, fs)
			equalSeqs(t, "Seqs", o2.Seqs(), []uint64{1, 2, 3})
			if s := enqueue(t, o2, recovery(1)); s != c.want {
				t.Fatalf("seq = %d, want %d", s, c.want)
			}
			if wm := readWatermark(t, dir); wm != c.want+1 {
				t.Fatalf("watermark = %d, want %d", wm, c.want+1)
			}
		})
	}
}

func TestSequenceExhausted(t *testing.T) {
	t.Run("watermark at max", func(t *testing.T) {
		dir := newDir(t)
		writeWatermark(t, dir, math.MaxUint64)
		o := openOrFail(t, dir, newFakeFS())
		before := snapshot(t, dir)
		if _, err := o.Enqueue(recovery(1)); !errors.Is(err, outbox.ErrSequenceExhausted) {
			t.Fatalf("err = %v, want ErrSequenceExhausted", err)
		}
		sameSnapshot(t, "dir", before, snapshot(t, dir))
	})
	t.Run("last usable seq", func(t *testing.T) {
		dir := newDir(t)
		writeWatermark(t, dir, math.MaxUint64-1)
		o := openOrFail(t, dir, newFakeFS())
		s := enqueue(t, o, recovery(1))
		if s != math.MaxUint64-1 {
			t.Fatalf("seq = %d, want %d", s, uint64(math.MaxUint64-1))
		}
		if _, err := os.Lstat(filepath.Join(dir, "18446744073709551614.g")); err != nil {
			t.Fatalf("file for the highest seq: %v", err)
		}
		if _, err := o.Enqueue(recovery(2)); !errors.Is(err, outbox.ErrSequenceExhausted) {
			t.Fatalf("err = %v, want ErrSequenceExhausted", err)
		}
		o2 := openOrFail(t, dir, newFakeFS())
		equalSeqs(t, "Seqs", o2.Seqs(), []uint64{math.MaxUint64 - 1})
	})
}

func TestParseWatermark(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want uint64
		ok   bool
	}{
		{"one", be(1), 1, true},
		{"large", be(1 << 40), 1 << 40, true},
		{"max", be(math.MaxUint64), math.MaxUint64, true},
		{"zero", be(0), 0, false},
		{"nil", nil, 0, false},
		{"empty", []byte{}, 0, false},
		{"7 bytes", be(1)[1:], 0, false},
		{"9 bytes", append(be(1), 1), 0, false},
		{"little endian 1", []byte{1, 0, 0, 0, 0, 0, 0, 0}, 1 << 56, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := outbox.ParseWatermark(c.b)
			if c.ok {
				if err != nil || v != c.want {
					t.Fatalf("= %d, %v; want %d", v, err, c.want)
				}
				return
			}
			if !errors.Is(err, outbox.ErrCorruptWatermark) {
				t.Fatalf("err = %v, want ErrCorruptWatermark", err)
			}
		})
	}
}

// TestMissingWatermarkFailsClosed: the watermark survives the outbox
// emptying, and Open never recreates a lost one, so message_seq never
// restarts (R29, must-apply 7).
func TestMissingWatermarkFailsClosed(t *testing.T) {
	for _, drained := range []bool{true, false} {
		name := "with messages"
		if drained {
			name = "drained"
		}
		t.Run(name, func(t *testing.T) {
			o, dir, fs := fresh(t)
			seqs := enqueueN(t, o, 3)
			if drained {
				for _, s := range seqs {
					mustNext(t, o, s)
					ack(t, o, s, accepted)
				}
				if wm := readWatermark(t, dir); wm != 4 {
					t.Fatalf("watermark after drain = %d, want 4", wm)
				}
			}
			if err := os.Remove(filepath.Join(dir, outbox.WatermarkFile)); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, dir)
			if _, err := openTimed(t, dir, opts(fs)); !errors.Is(err, outbox.ErrNoWatermark) {
				t.Fatalf("err = %v, want ErrNoWatermark", err)
			}
			sameSnapshot(t, "outbox dir", before, snapshot(t, dir))
			if !drained {
				if err := outbox.Create(dir); !errors.Is(err, outbox.ErrNotEmpty) {
					t.Fatalf("Create on a used dir: err = %v, want ErrNotEmpty", err)
				}
			}
		})
	}
}

// TestCreate: Create writes the first watermark into an empty directory
// only.
func TestCreate(t *testing.T) {
	dir := newDir(t) // newDir calls Create
	if wm := readWatermark(t, dir); wm != 1 {
		t.Fatalf("watermark = %d, want 1", wm)
	}
	if err := outbox.Create(dir); !errors.Is(err, outbox.ErrNotEmpty) {
		t.Fatalf("second Create: err = %v, want ErrNotEmpty", err)
	}
	if err := outbox.Create("relative/dir"); !errors.Is(err, outbox.ErrUnsafeDir) {
		t.Fatalf("relative: err = %v, want ErrUnsafeDir", err)
	}
	o := openOrFail(t, dir, newFakeFS())
	if s := enqueue(t, o, recovery(1)); s != 1 {
		t.Fatalf("first seq = %d, want 1", s)
	}
}
