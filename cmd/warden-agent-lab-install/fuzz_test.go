package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/nofal82/warden-agent/internal/identity"
)

// FuzzDecodeBundle: decodeBundle never panics, and whatever it accepts
// satisfies every §4.1, §4.2 and §4.3 limit.
func FuzzDecodeBundle(f *testing.F) {
	fx := newFixture(f, true)
	valid := fx.encode(f)
	f.Add(valid)
	f.Add(newFixture(f, false).encode(f))
	end := valid[: len(valid)-1 : len(valid)-1]
	f.Add(append(append(end, fmt.Sprintf(`,"token":%q`, fx.token)...), '}'))
	f.Add(append(append(end, `,"kind":"enroll"`...), '}'))
	f.Add(append([]byte("\xef\xbb\xbf"), valid...))
	f.Add(append(valid, "{}"...))
	f.Add(bytes.Replace(valid, []byte(`"format_version":1`), []byte(`"format_version":1e0`), 1))
	f.Add([]byte(`{"format_version":1,"kind":"enroll","expires_at":-1}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := decodeBundle(data, testNow)
		if err != nil {
			if b != nil {
				t.Fatalf("non-nil bundle with error %v", err)
			}
			return
		}
		if len(data) > maxBundleBytes {
			t.Fatalf("accepted %d bytes", len(data))
		}
		if identity.ValidateServerID(b.ServerID) != nil || identity.ValidateToken(b.Token) != nil {
			t.Fatalf("accepted invalid server_id or token")
		}
		if b.ExpiresAt <= testNow.Unix() {
			t.Fatalf("accepted expired bundle")
		}
		if identity.ValidateEndpoint(b.Endpoints.Enroll) != nil || identity.ValidateEndpoint(b.Endpoints.Agent) != nil ||
			identity.ValidateServerName(b.Endpoints.ServerName) != nil {
			t.Fatalf("accepted invalid endpoints %+v", b.Endpoints)
		}
		if _, err := identity.ParseAgentCA(b.AgentCA); err != nil || len(b.AgentCA) > 8<<10 {
			t.Fatalf("agent CA: %v", err)
		}
		if cas, err := identity.ParseControlPlaneCAs(b.ControlPlaneCA); err != nil || len(cas) != 1 {
			t.Fatalf("control-plane CA: %v", err)
		}
		if m, err := decodeObject(data); err == nil {
			if _, ok := m["manifest"]; ok {
				t.Fatal("accepted a bundle with a manifest (M1 has no manifest key)")
			}
		}
		if len(b.secret) != 32 {
			t.Fatalf("secret of %d bytes", len(b.secret))
		}
		secret := b.secret
		b.wipe()
		if !bytes.Equal(secret, make([]byte, 32)) {
			t.Fatalf("wipe left the secret")
		}
	})
}
