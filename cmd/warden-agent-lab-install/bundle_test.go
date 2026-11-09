package main

// Attack and failure tests for the lab enrollment bundle decoder
// (agent-identity §4.1, §4.2, §4.3; executor-ipc R52). Realistic-looking
// values (token, binding secret, CA certificates) are built at runtime,
// never written as literals.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testNow is the fixed clock of every decode test.
var testNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// fixture is one valid enroll bundle plus the secret values the tests
// look for in errors and written files.
type fixture struct {
	fields    map[string]any
	serverID  string
	token     string
	secret    []byte
	secretB64 string
	agentCA   []byte
	cpCA      []byte
	manifest  []byte
	expiresAt int64
}

func randBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// newUUIDv4 returns a lowercase canonical UUID v4 (§4.1).
func newUUIDv4(t testing.TB) string {
	t.Helper()
	b := randBytes(t, 16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// newToken returns a §4.2 token: the prefix and 43 base64url characters.
func newToken(t testing.TB) string {
	t.Helper()
	return "wdn1_" + base64.RawURLEncoding.EncodeToString(randBytes(t, 32))
}

// newCertPEM returns a canonical CERTIFICATE PEM; isCA selects CA:true.
func newCertPEM(t testing.TB, cn string, isCA bool) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// newFixture builds a valid enroll bundle, with a manifest when withManifest.
func newFixture(t testing.TB, withManifest bool) *fixture {
	t.Helper()
	fx := &fixture{
		serverID:  newUUIDv4(t),
		token:     newToken(t),
		secret:    randBytes(t, 32),
		agentCA:   newCertPEM(t, "Fake Agent CA", true),
		cpCA:      newCertPEM(t, "Fake Control Plane CA", true),
		expiresAt: testNow.Add(24 * time.Hour).Unix(),
	}
	fx.secretB64 = base64.StdEncoding.EncodeToString(fx.secret)
	fx.fields = map[string]any{
		"format_version":          1,
		"kind":                    "enroll",
		"server_id":               fx.serverID,
		"token":                   fx.token,
		"expires_at":              fx.expiresAt,
		"agent_ca":                string(fx.agentCA),
		"controlplane_ca":         string(fx.cpCA),
		"enroll_endpoint":         "enroll.lab.example.test:8443",
		"agent_endpoint":          "[2001:db8::1]:9443",
		"server_name":             "cp.lab.example.test",
		"executor_binding_secret": fx.secretB64,
	}
	if withManifest {
		fx.manifest = []byte("FAKE-SIGNED-MANIFEST-123")
		fx.fields["manifest"] = base64.StdEncoding.EncodeToString(fx.manifest)
	}
	return fx
}

func (fx *fixture) encode(t testing.TB) []byte {
	t.Helper()
	b, err := json.Marshal(fx.fields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// assertNoSecretInError checks that a refusal never echoes the token or
// the binding secret (§4.3 "never prints the token"; R52).
func assertNoSecretInError(t *testing.T, fx *fixture, err error) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	for _, s := range []string{fx.token, fx.token[5:], fx.secretB64, string(fx.secret)} {
		if strings.Contains(msg, s) {
			t.Errorf("error %q leaks a secret value", msg)
		}
	}
}

func TestDecodeBundleValid(t *testing.T) {
	t.Parallel()
	fx := newFixture(t, true)
	b, err := decodeBundle(fx.encode(t), testNow)
	if err != nil {
		t.Fatalf("decodeBundle(valid) = %v", err)
	}
	if b.ServerID != fx.serverID || b.Token != fx.token || b.ExpiresAt != fx.expiresAt {
		t.Errorf("identity fields not decoded as given")
	}
	if b.Endpoints.Enroll != "enroll.lab.example.test:8443" || b.Endpoints.Agent != "[2001:db8::1]:9443" ||
		b.Endpoints.ServerName != "cp.lab.example.test" {
		t.Errorf("endpoints = %+v", b.Endpoints)
	}
	if !bytes.Equal(b.AgentCA, fx.agentCA) || !bytes.Equal(b.ControlPlaneCA, fx.cpCA) {
		t.Errorf("CA PEM is not the canonical re-encoding")
	}
	if !bytes.Equal(b.Manifest, fx.manifest) {
		t.Errorf("manifest = %q, want %q", b.Manifest, fx.manifest)
	}
	if !bytes.Equal(b.secret, fx.secret) {
		t.Errorf("secret not decoded")
	}
}

// TestDecodeBundleRefusesFields mutates one member of a valid bundle.
func TestDecodeBundleRefusesFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(t *testing.T, fx *fixture)
	}{
		{"format_version 2", func(_ *testing.T, fx *fixture) { fx.fields["format_version"] = 2 }},
		{"format_version float 1.0", func(_ *testing.T, fx *fixture) { fx.fields["format_version"] = json.Number("1.0") }},
		{"kind reenroll refused by lab installer", func(_ *testing.T, fx *fixture) { fx.fields["kind"] = "reenroll" }},
		{"server_id uppercase", func(_ *testing.T, fx *fixture) { fx.fields["server_id"] = strings.ToUpper(fx.serverID) }},
		{"token 47 bytes", func(_ *testing.T, fx *fixture) { fx.fields["token"] = fx.token[:47] }},
		{"expires_at equals now", func(_ *testing.T, fx *fixture) { fx.fields["expires_at"] = testNow.Unix() }},
		{"expires_at as string", func(_ *testing.T, fx *fixture) {
			fx.fields["expires_at"] = strconv.FormatInt(fx.expiresAt, 10)
		}},
		{"agent_ca is not a CA", func(t *testing.T, fx *fixture) {
			fx.fields["agent_ca"] = string(newCertPEM(t, "Fake Leaf", false))
		}},
		{"controlplane_ca two certificates", func(t *testing.T, fx *fixture) {
			fx.fields["controlplane_ca"] = string(fx.cpCA) + string(newCertPEM(t, "Fake CA 2", true))
		}},
		{"enroll_endpoint port with leading zero", func(_ *testing.T, fx *fixture) {
			fx.fields["enroll_endpoint"] = "enroll.lab.example.test:08443"
		}},
		{"secret 31 bytes", func(t *testing.T, fx *fixture) {
			fx.fields["executor_binding_secret"] = base64.StdEncoding.EncodeToString(randBytes(t, 31))
		}},
		{"secret without padding", func(_ *testing.T, fx *fixture) {
			fx.fields["executor_binding_secret"] = base64.RawStdEncoding.EncodeToString(fx.secret)
		}},
		{"secret non-canonical trailing bits", func(_ *testing.T, fx *fixture) {
			const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			s := []byte(fx.secretB64)
			s[42] = alphabet[strings.IndexByte(alphabet, s[42])|1]
			fx.fields["executor_binding_secret"] = string(s)
		}},
		{"manifest over 32 KiB", func(_ *testing.T, fx *fixture) {
			fx.fields["manifest"] = base64.StdEncoding.EncodeToString(make([]byte, 32<<10+1))
		}},
		{"unknown field", func(_ *testing.T, fx *fixture) { fx.fields["root_key_fingerprint"] = strings.Repeat("0", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t, false)
			tc.mutate(t, fx)
			b, err := decodeBundle(fx.encode(t), testNow)
			if !errors.Is(err, errBundle) {
				t.Fatalf("decodeBundle = (%v, %v), want errBundle", b, err)
			}
			assertNoSecretInError(t, fx, err)
		})
	}
}

// TestDecodeBundleRefusesRawBytes covers encodings json.Marshal cannot
// produce: duplicate keys, BOM, trailing data, non-canonical numbers.
func TestDecodeBundleRefusesRawBytes(t *testing.T) {
	t.Parallel()
	insertBeforeEnd := func(data []byte, s string) []byte {
		return append(append(data[:len(data)-1:len(data)-1], s...), '}')
	}
	cases := []struct {
		name   string
		mangle func(fx *fixture, data []byte) []byte
	}{
		{"duplicate token key same value", func(fx *fixture, d []byte) []byte {
			return insertBeforeEnd(d, fmt.Sprintf(`,"token":%q`, fx.token))
		}},
		{"duplicate key spelled with escape", func(_ *fixture, d []byte) []byte {
			return insertBeforeEnd(d, `,"kind":"enroll"`)
		}},
		{"byte order mark", func(_ *fixture, d []byte) []byte { return append([]byte("\xef\xbb\xbf"), d...) }},
		{"trailing object", func(_ *fixture, d []byte) []byte { return append(d, "{}"...) }},
		{"invalid UTF-8 in a string", func(_ *fixture, d []byte) []byte {
			return bytes.Replace(d, []byte(`"enroll"`), []byte("\"enroll\xff\""), 1)
		}},
		{"format_version leading zero", func(_ *fixture, d []byte) []byte {
			return bytes.Replace(d, []byte(`"format_version":1`), []byte(`"format_version":01`), 1)
		}},
		{"over 64 KiB with trailing white space", func(_ *fixture, d []byte) []byte {
			return append(d, bytes.Repeat([]byte(" "), maxBundleBytes+1-len(d))...)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fx := newFixture(t, false)
			data := tc.mangle(fx, fx.encode(t))
			b, err := decodeBundle(data, testNow)
			if !errors.Is(err, errBundle) {
				t.Fatalf("decodeBundle = (%v, %v), want errBundle", b, err)
			}
			assertNoSecretInError(t, fx, err)
		})
	}
}

// TestBindingMACKnownAnswer pins R52's MAC input layout with fixed inputs,
// and cross-checks it against an independent crypto/hmac computation.
func TestBindingMACKnownAnswer(t *testing.T) {
	t.Parallel()
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	const serverID = "123e4567-e89b-42d3-a456-426614174000"
	pub := bytes.Repeat([]byte{0xa5}, 32)
	const want = "80b9616765e754e80cf81d672d03728c797c04bebbe049e7e31ffc3716ac009b"

	got := bindingMAC(secret, serverID, pub)
	if hex.EncodeToString(got[:]) != want {
		t.Errorf("bindingMAC = %x, want %s", got, want)
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("warden/v1/executor-key-binding\x00" + serverID))
	m.Write(pub)
	if !hmac.Equal(got[:], m.Sum(nil)) {
		t.Errorf("bindingMAC differs from HMAC-SHA-256 over the R52 layout")
	}
}

// TestBundleWipe: R52 says the installer does not keep the secret after
// the MAC is computed.
func TestBundleWipe(t *testing.T) {
	t.Parallel()
	fx := newFixture(t, true)
	b, err := decodeBundle(fx.encode(t), testNow)
	if err != nil {
		t.Fatalf("decodeBundle: %v", err)
	}
	secret := b.secret
	b.wipe()
	if len(secret) != 32 || !bytes.Equal(secret, make([]byte, 32)) {
		t.Errorf("secret backing array not zeroed after wipe: %x", secret)
	}
}
