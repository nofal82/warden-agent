package identity_test

// Tests for the executor binding file format (decision 0013, issue #35):
// exactly 64 raw bytes, the 32-byte Ed25519 result public key followed by
// the 32-byte binding MAC. The agent cannot check the MAC; only the format
// is checked here. LoadExecutorBinding reads a root-owned file under R10e
// and is not unit-testable without root.

import (
	"bytes"
	"errors"
	"testing"

	"github.com/nofal82/warden-agent/internal/identity"
)

func patterned(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 1)
	}
	return b
}

func TestParseExecutorBinding(t *testing.T) {
	t.Parallel()
	if identity.FileExecutorBinding != "executor-binding" || identity.ExecutorBindingFileSize != 64 {
		t.Fatalf("constants = %q, %d", identity.FileExecutorBinding, identity.ExecutorBindingFileSize)
	}
	tests := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"empty", nil, false},
		{"63 bytes", patterned(63), false},
		{"64 bytes", patterned(64), true},
		{"65 bytes", patterned(65), false},
		// Format only: the control plane checks the MAC, not the agent.
		{"64 zero bytes", make([]byte, 64), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := bytes.Clone(tc.in)
			b, err := identity.ParseExecutorBinding(in)
			if !tc.ok {
				if !errors.Is(err, identity.ErrInvalidBinding) {
					t.Fatalf("ParseExecutorBinding(%d bytes) = %v, want ErrInvalidBinding", len(tc.in), err)
				}
				if b != (identity.ExecutorBinding{}) {
					t.Errorf("rejected input returned a non-zero binding")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseExecutorBinding: %v", err)
			}
			if !bytes.Equal(b.PublicKey[:], tc.in[:32]) || !bytes.Equal(b.MAC[:], tc.in[32:]) {
				t.Fatalf("binding fields do not match the input halves")
			}
			// The result must be a copy: mutating the input changes nothing.
			for i := range in {
				in[i] ^= 0xff
			}
			if !bytes.Equal(b.PublicKey[:], tc.in[:32]) || !bytes.Equal(b.MAC[:], tc.in[32:]) {
				t.Errorf("binding aliases the input slice")
			}
		})
	}
}

func FuzzParseExecutorBinding(f *testing.F) {
	for _, n := range []int{0, 1, 31, 32, 33, 63, 64, 65, 128, 4096} {
		f.Add(patterned(n))
	}
	f.Add(make([]byte, 64))
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		want := bytes.Clone(data)
		b, err := identity.ParseExecutorBinding(data)
		if (err == nil) != (len(want) == identity.ExecutorBindingFileSize) {
			t.Fatalf("ParseExecutorBinding(%d bytes) err = %v", len(want), err)
		}
		if err != nil {
			if !errors.Is(err, identity.ErrInvalidBinding) {
				t.Fatalf("error %v does not wrap ErrInvalidBinding", err)
			}
			return
		}
		got := append(append([]byte(nil), b.PublicKey[:]...), b.MAC[:]...)
		if !bytes.Equal(got, want) {
			t.Fatalf("round trip mismatch")
		}
		if !bytes.Equal(data, want) {
			t.Fatalf("ParseExecutorBinding modified its input")
		}
	})
}
