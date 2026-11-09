package labtrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/nofal82/warden-agent/internal/agent"
	"github.com/nofal82/warden-agent/internal/identity"
)

// The marker of decision 0013, written only by the lab install.
const (
	MarkerPath    = "/etc/warden-agent/lab-trust"
	MarkerContent = "warden-lab-trust-m1\n"
)

// WarnLine is logged at every start of the lab binary while the marker is
// on (decision 0013, "Loud locally").
const WarnLine = "LAB MODE: control-plane CA trusted from controlplane-ca.pem without a verified keyset (lab only, decision 0013)"

// ReadFunc reads a root-owned file under the R10e rules; production passes
// identity.ReadRootFile.
type ReadFunc func(path string, maxBytes int64) ([]byte, error)

// MarkerOK reports whether the marker is present, passes R10e and holds
// exactly MarkerContent. Any error or any other content means off.
func MarkerOK(read ReadFunc) bool {
	data, err := read(MarkerPath, int64(len(MarkerContent)))
	return err == nil && bytes.Equal(data, []byte(MarkerContent))
}

// Entries derives the CA entries from controlplane-ca.pem itself: one per
// certificate, its DER SHA-256 and its own validity. A nil certificate is
// skipped; TrustedControlPlaneCAs refuses it in fileCAs.
func Entries(fileCAs []*x509.Certificate) []identity.CAEntry {
	out := make([]identity.CAEntry, 0, len(fileCAs))
	for _, c := range fileCAs {
		if c == nil {
			continue
		}
		out = append(out, identity.CAEntry{
			Fingerprint: sha256.Sum256(c.Raw),
			NotBefore:   c.NotBefore.Unix(),
			NotAfter:    c.NotAfter.Unix(),
		})
	}
	return out
}

// Trust wraps the keyset check. The keyset result stands unless it is
// agent.ErrTrustCheckImpossible (no verified keyset); only then, and only
// with a good marker, the lab entries are used. The marker is read at
// every check; the agent checks at start and before every new connection
// (R37), so removing the marker stops new connections without a restart.
func Trust(keyset agent.TrustFunc, read ReadFunc) agent.TrustFunc {
	return func(fileCAs []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
		set, err := keyset(fileCAs, now)
		if !errors.Is(err, agent.ErrTrustCheckImpossible) {
			return set, err
		}
		if !MarkerOK(read) {
			return nil, fmt.Errorf("%w (lab trust marker absent or invalid)", agent.ErrTrustCheckImpossible)
		}
		return identity.TrustedControlPlaneCAs(fileCAs, Entries(fileCAs), now)
	}
}
