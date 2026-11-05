package controlplane_test

import (
	"bytes"
	"errors"
	"testing"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
)

func FuzzDecodeEnrollResponse(f *testing.F) {
	for _, tc := range responseAttacks(f) {
		f.Add(tc.b)
	}
	f.Add(marshalDet(f, &agentapiv1.EnrollResponse{Certificate: []byte{1}}))
	f.Add(marshalDet(f, &agentapiv1.EnrollResponse{Certificate: make([]byte, 4096)}))
	f.Fuzz(func(t *testing.T, in []byte) {
		orig := append([]byte(nil), in...)
		cert, err := controlplane.DecodeEnrollResponse(in)
		if !bytes.Equal(in, orig) {
			t.Fatal("decoder modified its input")
		}
		if err != nil {
			if !errors.Is(err, controlplane.ErrResponseRefused) {
				t.Fatalf("error %v is not ErrResponseRefused", err)
			}
			if cert != nil {
				t.Fatal("certificate returned with an error")
			}
			return
		}
		if len(in) > 4608 {
			t.Fatalf("accepted a %d-byte response", len(in))
		}
		if len(cert) < 1 || len(cert) > 4096 {
			t.Fatalf("accepted a %d-byte certificate", len(cert))
		}
		if !bytes.Equal(marshalDet(t, &agentapiv1.EnrollResponse{Certificate: cert}), in) {
			t.Fatalf("accepted a non-canonical encoding %x", in)
		}
		if len(in) > 0 {
			in[len(in)-1] ^= 0xff
			if !bytes.Equal(cert, orig[len(orig)-len(cert):]) {
				t.Fatal("certificate aliases the input buffer")
			}
		}
	})
}
