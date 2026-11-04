//go:build linux

package identity

// Tests for the R18a start-up states, one enrollment attempt (R12, R12a,
// R15) and the clean-up after the first handshake. Every state file is
// written by the test as the agent user, mode 0600; the control plane is a
// fake EnrollFunc that issues from a test agent CA.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
)

func put(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	p := filepath.Join(dir, name)
	_ = os.Remove(p)
	writeMode(t, p, data, 0o600)
}

func present(t *testing.T, dir, name string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(dir, name))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

func unixText(sec int64) []byte { return []byte(strconv.FormatInt(sec, 10)) }

// issuedPair returns a key and its identity.pem for id, issued by ca from
// agentLeafTemplate(id, at) after mut.
func issuedPair(t *testing.T, ca *testCA, id string, at time.Time, mut func(*x509.Certificate)) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key := newP256(t)
	tmpl := agentLeafTemplate(t, id, at)
	if mut != nil {
		mut(tmpl)
	}
	der := ca.issue(t, tmpl, &key.PublicKey)
	return key, identityPEM(t, key, der), der
}

// renewalKeyPEM is identity.pending-key.pem: one canonical PKCS #8 block.
func renewalKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	return pemBlock(privateKeyBlockType(), pkcs8(t, key), nil)
}

func TestHealthMessages(t *testing.T) {
	t.Parallel()
	// The exact operator texts of R18a cases 3 and 4.
	if HealthTokenExpired != "enrollment token expired, ask an admin for a new enrollment bundle" {
		t.Errorf("HealthTokenExpired = %q", HealthTokenExpired)
	}
	if HealthNoIdentity != "identity expired or missing, ask an admin for a re-enrollment bundle" {
		t.Errorf("HealthNoIdentity = %q", HealthNoIdentity)
	}
	if !strings.Contains(ErrTokenExpired.Error(), HealthTokenExpired) {
		t.Errorf("ErrTokenExpired = %q", ErrTokenExpired)
	}
}

func TestDecideCase1UsesIdentity(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "agent CA", testNow)
	key, idPEM, der := issuedPair(t, ca, testServerID, testNow, nil)
	_, prevPEM, _ := issuedPair(t, ca, testServerID, testNow, nil)

	t.Run("plain", func(t *testing.T) {
		t.Parallel()
		d, p := stateDir(t)
		put(t, p, FileIdentity, idPEM)
		st, err := Decide(d, testServerID, testNow)
		if err != nil || st.State != StartUseIdentity || st.TokenPresent {
			t.Fatalf("Decide = %+v, %v; want StartUseIdentity, no token", st, err)
		}
		if c := st.Identity.Certificate(); c == nil || !bytes.Equal(c.Raw, der) {
			t.Fatal("Identity is not identity.pem's certificate")
		}
		tc := st.Identity.TLSCertificate()
		if k, ok := tc.PrivateKey.(*ecdsa.PrivateKey); !ok || !k.Equal(key) || len(tc.Certificate) != 1 {
			t.Fatal("TLSCertificate is not identity.pem's pair")
		}
	})
	// A leftover token and every other leftover file stay; Decide never
	// removes them (they go in AfterHandshake).
	t.Run("leftovers kept", func(t *testing.T) {
		t.Parallel()
		d, p := stateDir(t)
		put(t, p, FileIdentity, idPEM)
		put(t, p, FileIdentityPrev, prevPEM)
		put(t, p, FileToken, []byte(canaryToken()))
		put(t, p, FileTokenExpires, unixText(testNow.Unix()-1))
		h := TokenHash(canaryToken())
		put(t, p, FileEnrollPendingKey, pendingPEM(t, key, h[:]))
		st, err := Decide(d, testServerID, testNow)
		if err != nil || st.State != StartUseIdentity || !st.TokenPresent {
			t.Fatalf("Decide = %+v, %v; want StartUseIdentity with TokenPresent", st, err)
		}
		for _, n := range []string{FileIdentity, FileIdentityPrev, FileToken, FileTokenExpires, FileEnrollPendingKey} {
			if !present(t, p, n) {
				t.Errorf("Decide removed %s", n)
			}
		}
	})
	// Not yet valid is not a reason to skip it (clock behind); now ==
	// NotAfter is still valid.
	for name, mut := range map[string]func(*x509.Certificate){
		"NotBefore in the future": func(c *x509.Certificate) { c.NotBefore = testNow.Add(time.Hour) },
		"now equals NotAfter":     func(c *x509.Certificate) { c.NotAfter = testNow },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d, p := stateDir(t)
			_, pem, _ := issuedPair(t, ca, testServerID, testNow, mut)
			put(t, p, FileIdentity, pem)
			if st, err := Decide(d, testServerID, testNow); err != nil || st.State != StartUseIdentity {
				t.Fatalf("Decide = %+v, %v; want StartUseIdentity", st, err)
			}
		})
	}
}

// R18a case 1: a renewal pending key equal to identity.pem's key is done
// with and removed; any other content is kept for the renewal retry.
func TestDecideCase1RenewalPendingKey(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "agent CA", testNow)
	key, idPEM, _ := issuedPair(t, ca, testServerID, testNow, nil)
	cases := []struct {
		name    string
		data    []byte
		removed bool
	}{
		{"same key", renewalKeyPEM(t, key), true},
		{"other key", renewalKeyPEM(t, newP256(t)), false},
		{"malformed", []byte("not a key"), false},
		{"same key with trailing data", cat(renewalKeyPEM(t, key), []byte("x")), false},
		{"same key in SEC 1", pemBlock(ecPrivateKeyBlockType(), sec1(t, key), nil), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, p := stateDir(t)
			put(t, p, FileIdentity, idPEM)
			put(t, p, FileIdentityPendingKey, tc.data)
			st, err := Decide(d, testServerID, testNow)
			if err != nil || st.State != StartUseIdentity {
				t.Fatalf("Decide = %+v, %v", st, err)
			}
			if got := !present(t, p, FileIdentityPendingKey); got != tc.removed {
				t.Fatalf("identity.pending-key.pem removed = %v, want %v", got, tc.removed)
			}
		})
	}
}

// R18a case 2: identity.pem not valid for any reason, identity.prev.pem
// valid. Each invalid identity.pem falls back to the previous pair.
func TestDecideCase2UsesPrevious(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "agent CA", testNow)
	_, prevPEM, prevDER := issuedPair(t, ca, testServerID, testNow, nil)
	other := newCA(t, "other agent CA", testNow)
	cases := []struct {
		name  string
		setup func(t *testing.T, p string)
	}{
		{"missing", func(t *testing.T, p string) {}},
		{"expired", func(t *testing.T, p string) {
			_, pem, _ := issuedPair(t, ca, testServerID, testNow, func(c *x509.Certificate) { c.NotAfter = testNow.Add(-time.Second) })
			put(t, p, FileIdentity, pem)
		}},
		{"names another UUID", func(t *testing.T, p string) {
			_, pem, _ := issuedPair(t, ca, otherServerID, testNow, nil)
			put(t, p, FileIdentity, pem)
		}},
		{"extra DNS SAN", func(t *testing.T, p string) {
			_, pem, _ := issuedPair(t, ca, testServerID, testNow, func(c *x509.Certificate) { c.DNSNames = []string{"agent.example.test"} })
			put(t, p, FileIdentity, pem)
		}},
		{"CN only, no SAN", func(t *testing.T, p string) {
			_, pem, _ := issuedPair(t, ca, testServerID, testNow, func(c *x509.Certificate) { c.URIs = nil })
			put(t, p, FileIdentity, pem)
		}},
		{"malformed", func(t *testing.T, p string) { put(t, p, FileIdentity, []byte("garbage")) }},
		{"key does not match certificate", func(t *testing.T, p string) {
			_, _, der := issuedPair(t, ca, testServerID, testNow, nil)
			put(t, p, FileIdentity, identityPEM(t, newP256(t), der))
		}},
		{"group-readable", func(t *testing.T, p string) {
			_, pem, _ := issuedPair(t, ca, testServerID, testNow, nil)
			put(t, p, FileIdentity, pem)
			mustChmod(t, filepath.Join(p, FileIdentity), 0o640)
		}},
		{"symlink to a valid pair", func(t *testing.T, p string) {
			_, pem, _ := issuedPair(t, ca, testServerID, testNow, nil)
			outside := filepath.Join(t.TempDir(), "identity.pem")
			writeMode(t, outside, pem, 0o600)
			if err := os.Symlink(outside, filepath.Join(p, FileIdentity)); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T, p string) {
			if err := os.Mkdir(filepath.Join(p, FileIdentity), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		// No chain check at start (R15a): a pair from another agent CA that
		// names this server is still valid, so it is case 1, not case 2.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, p := stateDir(t)
			tc.setup(t, p)
			put(t, p, FileIdentityPrev, prevPEM)
			put(t, p, FileIdentityPendingKey, renewalKeyPEM(t, newP256(t)))
			st, err := Decide(d, testServerID, testNow)
			if err != nil || st.State != StartUsePrevious {
				t.Fatalf("Decide = %+v, %v; want StartUsePrevious", st, err)
			}
			if c := st.Identity.Certificate(); c == nil || !bytes.Equal(c.Raw, prevDER) {
				t.Fatal("Identity is not identity.prev.pem's certificate")
			}
			// The renewal retry still needs its pending key.
			if !present(t, p, FileIdentityPendingKey) || !present(t, p, FileIdentityPrev) {
				t.Fatal("Decide removed a renewal file in case 2")
			}
		})
	}
	t.Run("pair from another agent CA", func(t *testing.T) {
		t.Parallel()
		d, p := stateDir(t)
		_, pem, _ := issuedPair(t, other, testServerID, testNow, nil)
		put(t, p, FileIdentity, pem)
		if st, err := Decide(d, testServerID, testNow); err != nil || st.State != StartUseIdentity {
			t.Fatalf("Decide = %+v, %v; want StartUseIdentity (no chain check, R15a)", st, err)
		}
	})
}

// R18a cases 3 and 4: no valid pair.
func TestDecideNoValidPair(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "agent CA", testNow)
	_, expiredPEM, _ := issuedPair(t, ca, testServerID, testNow, func(c *x509.Certificate) { c.NotAfter = testNow.Add(-time.Second) })
	_, otherPEM, _ := issuedPair(t, ca, otherServerID, testNow, nil)
	now := testNow.Unix()
	noFile := []byte(nil)
	cases := []struct {
		name    string
		token   bool
		expires []byte // nil: no token-expires file
		want    StartState
	}{
		{"token, no token-expires", true, noFile, StartEnroll},
		{"token-expires in the future", true, unixText(now + 3600), StartEnroll},
		{"token-expires equal to now", true, unixText(now), StartEnroll},
		{"token-expires one second past", true, unixText(now - 1), StartTokenExpired},
		{"token-expires long past", true, []byte("1"), StartTokenExpired},
		{"token-expires with newline", true, []byte("1\n"), StartEnroll},
		{"token-expires leading zero", true, []byte("01"), StartEnroll},
		{"token-expires zero", true, []byte("0"), StartEnroll},
		{"token-expires negative", true, []byte("-1"), StartEnroll},
		{"token-expires plus sign", true, []byte("+1"), StartEnroll},
		{"token-expires leading space", true, []byte(" 1"), StartEnroll},
		{"token-expires 13 digits", true, []byte("1000000000000"), StartEnroll},
		{"token-expires empty", true, []byte{}, StartEnroll},
		{"token-expires not a number", true, []byte("yesterday"), StartEnroll},
		{"token-expires fraction", true, []byte("1.5"), StartEnroll},
		{"token-expires 12 digits", true, []byte("999999999999"), StartEnroll},
		{"no token", false, noFile, StartNoIdentity},
		{"no token, token-expires past", false, unixText(now - 1), StartNoIdentity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, p := stateDir(t)
			put(t, p, FileIdentity, expiredPEM)
			put(t, p, FileIdentityPrev, otherPEM)
			put(t, p, FileIdentityPendingKey, renewalKeyPEM(t, newP256(t)))
			h := TokenHash(canaryToken())
			pending := pendingPEM(t, newP256(t), h[:])
			put(t, p, FileEnrollPendingKey, pending)
			if tc.token {
				// Content is Enroll's business; Decide only needs the file.
				put(t, p, FileToken, []byte("not even a token"))
			}
			if tc.expires != nil {
				put(t, p, FileTokenExpires, tc.expires)
			}
			st, err := Decide(d, testServerID, testNow)
			if err != nil || st.State != tc.want {
				t.Fatalf("Decide = %+v, %v; want state %d", st, err, tc.want)
			}
			if st.Identity.Certificate() != nil || len(st.Identity.TLSCertificate().Certificate) != 0 {
				t.Error("an identity is returned without a valid pair")
			}
			if tc.want == StartEnroll || tc.want == StartTokenExpired {
				// A renewal key is never used for enrollment.
				if present(t, p, FileIdentityPendingKey) {
					t.Error("identity.pending-key.pem kept in case 3")
				}
			}
			for _, n := range []string{FileIdentity, FileIdentityPrev, FileEnrollPendingKey} {
				if !present(t, p, n) {
					t.Errorf("Decide removed %s", n)
				}
			}
			if got, _ := readTestFile(filepath.Join(p, FileEnrollPendingKey)); !bytes.Equal(got, pending) {
				t.Error("Decide changed enroll.pending-key.pem")
			}
			if tc.token && !present(t, p, FileToken) {
				t.Error("Decide removed the token")
			}
			if tc.expires != nil && !present(t, p, FileTokenExpires) {
				t.Error("Decide removed token-expires")
			}
		})
	}
}

func TestDecideEmptyAndUnsafeDir(t *testing.T) {
	t.Parallel()
	d, p := stateDir(t)
	if st, err := Decide(d, testServerID, testNow); err != nil || st.State != StartNoIdentity {
		t.Fatalf("empty dir: %+v, %v; want StartNoIdentity", st, err)
	}
	mustChmod(t, p, 0o755)
	if _, err := Decide(d, testServerID, testNow); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("0755 state dir: %v, want ErrUnsafeFile", err)
	}
}

func TestParseTokenFile(t *testing.T) {
	t.Parallel()
	tok := canaryToken()
	if got, err := parseTokenFile([]byte(tok)); err != nil || got != tok {
		t.Fatalf("parseTokenFile(valid) = %v", err)
	}
	for name, data := range map[string]string{
		"empty": "", "newline": tok + "\n", "CRLF": tok + "\r\n", "47 bytes": tok[:47],
		"49 bytes": tok + "Q", "plus": tok[:47] + "+", "padding": tok[:47] + "=", "space": " " + tok,
		"BOM": "\ufeff" + tok, "NUL": tok[:47] + "\x00", "two tokens": tok + "\n" + otherToken(),
	} {
		got, err := parseTokenFile([]byte(data))
		if !errors.Is(err, ErrInvalidToken) || got != "" {
			t.Errorf("%s: parseTokenFile = %v; want ErrInvalidToken", name, err)
		}
		if err != nil {
			assertNoLeak(t, err.Error(), nil, tok, tok[5:21])
		}
	}
}

func TestParseTokenExpires(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]int64{"1": 1, "1700000000": 1700000000, "999999999999": 999999999999} {
		if got, ok := parseTokenExpires([]byte(s)); !ok || got != want {
			t.Errorf("parseTokenExpires(%q) = %d, %v", s, got, ok)
		}
	}
	for _, s := range []string{"", "0", "01", "-1", "+1", " 1", "1 ", "1\n", "1000000000000", "1e9", "0x10", "\uff11", "9223372036854775808"} {
		if got, ok := parseTokenExpires([]byte(s)); ok {
			t.Errorf("parseTokenExpires(%q) accepted as %d", s, got)
		}
	}
}

// fakeCP is the enrollment endpoint: it records each request and, unless
// err is set, issues a leaf for the CSR's key from ca after mut.
type fakeCP struct {
	t       *testing.T
	ca      *testCA
	id      string
	mut     func(*x509.Certificate)
	respond func(pub any) []byte // overrides issuing
	err     error
	hook    func(req *agentapiv1.EnrollRequest)
	calls   []*agentapiv1.EnrollRequest
}

func (c *fakeCP) send(_ context.Context, req *agentapiv1.EnrollRequest) ([]byte, error) {
	c.calls = append(c.calls, req)
	if c.hook != nil {
		c.hook(req)
	}
	if c.err != nil {
		return nil, c.err
	}
	csr, err := x509.ParseCertificateRequest(req.GetCsr())
	if err != nil {
		c.t.Fatalf("fake control plane: CSR does not parse: %v", err)
	}
	if c.respond != nil {
		return c.respond(csr.PublicKey), nil
	}
	tmpl := agentLeafTemplate(c.t, c.id, testNow)
	if c.mut != nil {
		c.mut(tmpl)
	}
	return c.ca.issue(c.t, tmpl, csr.PublicKey), nil
}

func spki(t *testing.T, req *agentapiv1.EnrollRequest) [sha256.Size]byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(req.GetCsr())
	if err != nil {
		t.Fatalf("CSR does not parse: %v", err)
	}
	return sha256.Sum256(csr.RawSubjectPublicKeyInfo)
}

// enrollFixture is a state directory with a token and a future
// token-expires, and a fake control plane for testServerID.
type enrollFixture struct {
	d  *StateDir
	p  string
	cp *fakeCP
	in EnrollInput
}

func newEnrollFixture(t *testing.T) *enrollFixture {
	t.Helper()
	d, p := stateDir(t)
	ca := newCA(t, "agent CA", testNow)
	put(t, p, FileToken, []byte(canaryToken()))
	put(t, p, FileTokenExpires, unixText(testNow.Unix()+3600))
	return &enrollFixture{
		d: d, p: p,
		cp: &fakeCP{t: t, ca: ca, id: testServerID},
		in: EnrollInput{ServerID: testServerID, AgentCA: ca.cert, Binding: testBinding(t)},
	}
}

func (f *enrollFixture) enroll(ctx context.Context) (Identity, error) {
	return Enroll(ctx, f.d, f.in, f.cp.send, testNow)
}

func (f *enrollFixture) pendingKey(t *testing.T) (*ecdsa.PrivateKey, [sha256.Size]byte) {
	t.Helper()
	data, err := readTestFile(filepath.Join(f.p, FileEnrollPendingKey))
	if err != nil {
		t.Fatalf("enroll.pending-key.pem: %v", err)
	}
	k, h, err := DecodePendingEnrollKey(data)
	if err != nil {
		t.Fatalf("enroll.pending-key.pem does not decode: %v", err)
	}
	return k, h
}

func TestEnrollSuccess(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)
	var sentKey *ecdsa.PrivateKey
	// R12a: the key is on disk, bound to this token, before the request
	// leaves, and the CSR is for that key.
	f.cp.hook = func(req *agentapiv1.EnrollRequest) {
		k, h := f.pendingKey(t)
		if h != TokenHash(canaryToken()) {
			t.Error("pending key is not bound to the token being sent")
		}
		if spki(t, req) != sha256.Sum256(mustSPKI(t, &k.PublicKey)) {
			t.Error("CSR is not for the durable pending key")
		}
		fi, err := os.Lstat(filepath.Join(f.p, FileEnrollPendingKey))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("pending key mode %v, %v; want 0600", fi.Mode(), err)
		}
		sentKey = k
	}
	id, err := f.enroll(context.Background())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(f.cp.calls) != 1 {
		t.Fatalf("send called %d times, want 1", len(f.cp.calls))
	}
	req := f.cp.calls[0]
	b := testBinding(t)
	if req.GetToken() != canaryToken() || req.GetServerId() != testServerID || req.GetFormatVersion() != 1 ||
		!bytes.Equal(req.GetExecutorPublicKey(), b.PublicKey[:]) || !bytes.Equal(req.GetExecutorBindingMac(), b.MAC[:]) {
		t.Error("request fields are not the token, server ID and binding")
	}
	data, err := readTestFile(filepath.Join(f.p, FileIdentity))
	if err != nil {
		t.Fatalf("identity.pem not written: %v", err)
	}
	k, c, err := DecodeIdentity(data)
	if err != nil || sentKey == nil || !k.Equal(sentKey) {
		t.Fatalf("identity.pem does not hold the pending key: %v", err)
	}
	if got := id.Certificate(); got == nil || !bytes.Equal(got.Raw, c.Raw) {
		t.Error("returned Identity is not identity.pem")
	}
	if pk, ok := id.TLSCertificate().PrivateKey.(*ecdsa.PrivateKey); !ok || !pk.Equal(sentKey) {
		t.Error("returned TLS certificate does not hold the pending key")
	}
	for _, n := range []string{FileToken, FileTokenExpires, FileEnrollPendingKey} {
		if present(t, f.p, n) {
			t.Errorf("%s left after a successful enrollment", n)
		}
	}
	// A second attempt has no token: nothing is sent.
	if _, err := f.enroll(context.Background()); !errors.Is(err, fs.ErrNotExist) || len(f.cp.calls) != 1 {
		t.Fatalf("second Enroll = %v after %d sends; want fs.ErrNotExist and no send", err, len(f.cp.calls))
	}
}

func mustSPKI(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// R12a, §5.4: the response is lost (or the agent crashes after sending);
// the next attempt, through a fresh handle as after a restart, sends the
// same key.
func TestEnrollRetryReusesPendingKey(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)
	lost := errors.New("fake transport: response lost")
	f.cp.err = lost
	if _, err := f.enroll(context.Background()); !errors.Is(err, lost) {
		t.Fatalf("Enroll = %v, want the send error wrapped", err)
	}
	for _, n := range []string{FileToken, FileTokenExpires, FileEnrollPendingKey} {
		if !present(t, f.p, n) {
			t.Fatalf("%s removed after a failed send", n)
		}
	}
	if present(t, f.p, FileIdentity) {
		t.Fatal("identity.pem written after a failed send")
	}
	// A rejected certificate is not a reason to change keys either.
	f.cp.err = nil
	f.cp.id = otherServerID
	if _, err := f.enroll(context.Background()); !errors.Is(err, ErrCertificateRejected) {
		t.Fatalf("Enroll with a wrong UUID = %v", err)
	}
	restarted, err := OpenStateDir(f.p)
	if err != nil {
		t.Fatal(err)
	}
	f.d = restarted
	f.cp.id = testServerID
	if _, err := f.enroll(context.Background()); err != nil {
		t.Fatalf("Enroll after restart: %v", err)
	}
	if len(f.cp.calls) != 3 {
		t.Fatalf("send called %d times, want 3", len(f.cp.calls))
	}
	first := spki(t, f.cp.calls[0])
	for i, req := range f.cp.calls[1:] {
		if spki(t, req) != first {
			t.Fatalf("send %d used a different key than send 0", i+1)
		}
	}
}

// A pending key that is not this token's is discarded and replaced by a
// new one bound to this token (R12a, I4 plants a pending key).
func TestEnrollReplacesForeignPendingKey(t *testing.T) {
	t.Parallel()
	planted := newP256(t)
	otherHash := TokenHash(otherToken())
	thisHash := TokenHash(canaryToken())
	cases := map[string][]byte{
		"bound to another token": pendingPEM(t, planted, otherHash[:]),
		"malformed":              []byte("garbage"),
		"P-384 key":              pendingPEM(t, newP384(t), thisHash[:]),
		"short hash":             pendingPEM(t, planted, thisHash[:31]),
		"key block only":         renewalKeyPEM(t, planted),
		"right hash, extra data": cat(pendingPEM(t, planted, thisHash[:]), []byte("\n")),
		"empty":                  {},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newEnrollFixture(t)
			put(t, f.p, FileEnrollPendingKey, data)
			f.cp.err = errors.New("fake transport: down") // keep the key on disk to inspect it
			_, _ = f.enroll(context.Background())
			if len(f.cp.calls) != 1 {
				t.Fatalf("send called %d times, want 1", len(f.cp.calls))
			}
			k, h := f.pendingKey(t)
			if h != thisHash {
				t.Fatal("new pending key is not bound to this token")
			}
			if k.Equal(planted) || spki(t, f.cp.calls[0]) == sha256.Sum256(mustSPKI(t, &planted.PublicKey)) {
				t.Fatal("a planted key was used")
			}
			if spki(t, f.cp.calls[0]) != sha256.Sum256(mustSPKI(t, &k.PublicKey)) {
				t.Fatal("CSR is not for the new pending key")
			}
		})
	}
}

// A symlink planted at enroll.pending-key.pem is never followed: its target
// is neither used as the key nor written.
func TestEnrollPendingKeySymlink(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)
	planted := newP256(t)
	h := TokenHash(canaryToken())
	target := filepath.Join(t.TempDir(), "planted.pem")
	content := pendingPEM(t, planted, h[:])
	writeMode(t, target, content, 0o600)
	if err := os.Symlink(target, filepath.Join(f.p, FileEnrollPendingKey)); err != nil {
		t.Fatal(err)
	}
	f.cp.err = errors.New("fake transport: down")
	_, _ = f.enroll(context.Background())
	for _, req := range f.cp.calls {
		if spki(t, req) == sha256.Sum256(mustSPKI(t, &planted.PublicKey)) {
			t.Fatal("the key behind a symlink was sent")
		}
	}
	if got, _ := readTestFile(target); !bytes.Equal(got, content) {
		t.Fatal("the symlink target was written")
	}
}

// R15 failures: nothing is written, the token and the pending key stay
// (the same key is retried), and an existing identity.pem is untouched.
func TestEnrollRejectsIssuedCertificate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		set  func(t *testing.T, cp *fakeCP)
		skew bool
	}{
		{"another UUID", func(t *testing.T, cp *fakeCP) { cp.id = otherServerID }, false},
		{"another key", func(t *testing.T, cp *fakeCP) {
			other := newP256(t)
			cp.respond = func(any) []byte {
				return cp.ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &other.PublicKey)
			}
		}, false},
		{"another CA", func(t *testing.T, cp *fakeCP) {
			other := newCA(t, "agent CA", testNow)
			cp.respond = func(pub any) []byte { return other.issue(t, agentLeafTemplate(t, testServerID, testNow), pub) }
		}, false},
		{"serverAuth EKU", func(t *testing.T, cp *fakeCP) {
			cp.mut = func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }
		}, false},
		{"not yet valid beyond skew", func(t *testing.T, cp *fakeCP) {
			cp.mut = func(c *x509.Certificate) { c.NotBefore = testNow.Add(MaxSkew + time.Hour) }
		}, true},
		{"expired beyond skew", func(t *testing.T, cp *fakeCP) {
			cp.mut = func(c *x509.Certificate) {
				c.NotBefore = testNow.Add(-48 * time.Hour)
				c.NotAfter = testNow.Add(-MaxSkew - time.Hour)
			}
		}, true},
		{"garbage", func(t *testing.T, cp *fakeCP) { cp.respond = func(any) []byte { return []byte("garbage") } }, false},
		{"empty", func(t *testing.T, cp *fakeCP) { cp.respond = func(any) []byte { return nil } }, false},
		{"oversized", func(t *testing.T, cp *fakeCP) {
			cp.respond = func(any) []byte { return bytesOf(MaxCertificateBytes+1, 0x30) }
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newEnrollFixture(t)
			// An expired pair from before re-enrollment.
			_, oldPEM, _ := issuedPair(t, f.cp.ca, testServerID, testNow, func(c *x509.Certificate) { c.NotAfter = testNow.Add(-time.Hour) })
			put(t, f.p, FileIdentity, oldPEM)
			tc.set(t, f.cp)
			var resp []byte
			send := func(ctx context.Context, req *agentapiv1.EnrollRequest) ([]byte, error) {
				b, err := f.cp.send(ctx, req)
				resp = b
				return b, err
			}
			_, err := Enroll(context.Background(), f.d, f.in, send, testNow)
			if !errors.Is(err, ErrCertificateRejected) {
				t.Fatalf("Enroll = %v, want ErrCertificateRejected", err)
			}
			if tc.skew != errors.Is(err, ErrClockSkew) {
				t.Fatalf("ErrClockSkew = %v, want %v", errors.Is(err, ErrClockSkew), tc.skew)
			}
			if got, _ := readTestFile(filepath.Join(f.p, FileIdentity)); !bytes.Equal(got, oldPEM) {
				t.Fatal("identity.pem changed after an R15 failure")
			}
			for _, n := range []string{FileToken, FileTokenExpires, FileEnrollPendingKey} {
				if !present(t, f.p, n) {
					t.Fatalf("%s removed after an R15 failure", n)
				}
			}
			k, _ := f.pendingKey(t)
			noSecretIn(t, err, append(keySecrets(t, k), canaryToken(), canaryToken()[5:21], string(resp))...)
		})
	}
}

// Order of the success clean-up (R12a): identity.pem, then token, then
// token-expires, then enroll.pending-key.pem. A removal that fails stops
// the sequence, so a token is never left without its pending key. The
// failure is injected during send by replacing a file with a non-empty
// directory, which unlink cannot remove.
func TestEnrollCleanupOrder(t *testing.T) {
	t.Parallel()
	block := func(t *testing.T, p, name string) {
		t.Helper()
		_ = os.Remove(filepath.Join(p, name))
		if err := os.Mkdir(filepath.Join(p, name), 0o700); err != nil {
			t.Fatal(err)
		}
		writeMode(t, filepath.Join(p, name, "x"), nil, 0o600)
	}
	t.Run("token removal fails", func(t *testing.T) {
		t.Parallel()
		f := newEnrollFixture(t)
		f.cp.hook = func(*agentapiv1.EnrollRequest) { block(t, f.p, FileToken) }
		_, _ = f.enroll(context.Background())
		if !present(t, f.p, FileIdentity) {
			t.Fatal("identity.pem not written before the token removal")
		}
		if !present(t, f.p, FileEnrollPendingKey) || !present(t, f.p, FileTokenExpires) {
			t.Fatal("files after the token were removed although the token removal failed")
		}
	})
	t.Run("token-expires removal fails", func(t *testing.T) {
		t.Parallel()
		f := newEnrollFixture(t)
		f.cp.hook = func(*agentapiv1.EnrollRequest) { block(t, f.p, FileTokenExpires) }
		_, _ = f.enroll(context.Background())
		if present(t, f.p, FileToken) {
			t.Fatal("token not removed before token-expires")
		}
		if !present(t, f.p, FileEnrollPendingKey) {
			t.Fatal("pending key removed although token-expires removal failed")
		}
	})
}

// Token and token-expires are checked before anything is generated, written
// or sent.
func TestEnrollRefusesBeforeSending(t *testing.T) {
	t.Parallel()
	tok := canaryToken()
	now := testNow.Unix()
	cases := []struct {
		name    string
		token   []byte // nil: no token file
		expires []byte // nil: no token-expires file
		want    error
	}{
		{"token-expires past", []byte(tok), unixText(now - 1), ErrTokenExpired},
		{"token-expires past wins over a bad token", []byte("bad"), unixText(now - 1), ErrTokenExpired},
		{"token trailing newline", []byte(tok + "\n"), nil, ErrInvalidToken},
		{"token CRLF", []byte(tok + "\r\n"), nil, ErrInvalidToken},
		{"token 47 bytes", []byte(tok[:47]), nil, ErrInvalidToken},
		{"token 49 bytes", []byte(tok + "Q"), nil, ErrInvalidToken},
		{"token invalid character", []byte(tok[:47] + "+"), nil, ErrInvalidToken},
		{"token empty", []byte{}, nil, ErrInvalidToken},
		{"token with leading space", []byte(" " + tok[1:]), nil, ErrInvalidToken},
		{"token missing", nil, nil, fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newEnrollFixture(t)
			_ = os.Remove(filepath.Join(f.p, FileToken))
			_ = os.Remove(filepath.Join(f.p, FileTokenExpires))
			if tc.token != nil {
				put(t, f.p, FileToken, tc.token)
			}
			if tc.expires != nil {
				put(t, f.p, FileTokenExpires, tc.expires)
			}
			_, err := f.enroll(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("Enroll = %v, want %v", err, tc.want)
			}
			if len(f.cp.calls) != 0 {
				t.Fatal("send was called")
			}
			if present(t, f.p, FileEnrollPendingKey) || present(t, f.p, FileIdentity) {
				t.Fatal("a file was written")
			}
			if tc.token != nil && !present(t, f.p, FileToken) {
				t.Fatal("the token was removed")
			}
			noSecretIn(t, err, tok, tok[5:21])
		})
	}
}

// noSecretIn is assertNoLeak without the long-run heuristics, which would
// flag the temporary state-directory path that file errors carry.
func noSecretIn(t *testing.T, err error, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if len(s) >= 8 && strings.Contains(err.Error(), s) {
			t.Errorf("error text leaks a secret fragment %q: %q", short(s), err)
		}
	}
}

func TestEnrollCancelledContext(t *testing.T) {
	t.Parallel()
	f := newEnrollFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.enroll(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Enroll = %v, want context.Canceled", err)
	}
	if len(f.cp.calls) != 0 {
		t.Fatal("send was called with a cancelled context")
	}
	if present(t, f.p, FileIdentity) || !present(t, f.p, FileToken) {
		t.Fatal("state changed")
	}
}

func TestEnrollBadInput(t *testing.T) {
	t.Parallel()
	t.Run("invalid server ID", func(t *testing.T) {
		t.Parallel()
		f := newEnrollFixture(t)
		f.in.ServerID = strings.ToUpper(testServerID)
		if _, err := f.enroll(context.Background()); err == nil || len(f.cp.calls) != 0 {
			t.Fatalf("Enroll = %v after %d sends; want an error and no send", err, len(f.cp.calls))
		}
	})
	t.Run("nil agent CA", func(t *testing.T) {
		t.Parallel()
		f := newEnrollFixture(t)
		f.in.AgentCA = nil
		if _, err := f.enroll(context.Background()); !errors.Is(err, ErrInvalidTrust) || len(f.cp.calls) != 0 {
			t.Fatalf("Enroll = %v after %d sends; want ErrInvalidTrust and no send", err, len(f.cp.calls))
		}
		if present(t, f.p, FileIdentity) || present(t, f.p, FileEnrollPendingKey) || !present(t, f.p, FileToken) {
			t.Fatal("state changed")
		}
	})
	t.Run("unsafe state dir", func(t *testing.T) {
		t.Parallel()
		f := newEnrollFixture(t)
		mustChmod(t, f.p, 0o755)
		if _, err := f.enroll(context.Background()); !errors.Is(err, ErrUnsafeFile) || len(f.cp.calls) != 0 {
			t.Fatalf("Enroll = %v after %d sends; want ErrUnsafeFile and no send", err, len(f.cp.calls))
		}
	})
}

// Agent CA checked first (R15, R12a): an agent CA that is not a CA
// certificate is refused before the token is read, before
// enroll.pending-key.pem is written or replaced and before anything is
// sent. Otherwise a broken agent-ca.pem would make every attempt burn a
// round trip with the token and replace a pending key the next good
// attempt could have reused.
func TestEnrollChecksAgentCAFirst(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "agent CA", testNow)
	leaf := mustParse(t, ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &newP256(t).PublicKey))
	// Go never emits CA:TRUE without basic constraints, so these two are
	// built in memory from a parsed CA certificate.
	noBC := *ca.cert
	noBC.BasicConstraintsValid = false
	bcNotCA := *ca.cert
	bcNotCA.IsCA = false
	cas := map[string]*x509.Certificate{
		"nil":                                nil,
		"leaf certificate":                   leaf,
		"IsCA without basic constraints":     &noBC,
		"basic constraints with CA false":    &bcNotCA,
		"zero certificate":                   {},
		"self-signed leaf (no CA extension)": selfSignedLeaf(t),
	}
	otherHash := TokenHash(otherToken())
	tok := canaryToken()
	tokens := []struct {
		name  string
		token []byte // nil: no token file
		dir   bool   // token is a directory
	}{
		{"valid token", []byte(tok), false},
		{"invalid token", []byte("bad"), false},
		{"token trailing newline", []byte(tok + "\n"), false},
		{"token missing", nil, false},
		{"token is a directory", nil, true},
	}
	for caName, agentCA := range cas {
		for _, tk := range tokens {
			for _, withPending := range []bool{false, true} {
				name := caName + "/" + tk.name
				if withPending {
					name += "/foreign pending key"
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					f := newEnrollFixture(t)
					f.in.AgentCA = agentCA
					_ = os.Remove(filepath.Join(f.p, FileToken))
					switch {
					case tk.dir:
						if err := os.Mkdir(filepath.Join(f.p, FileToken), 0o700); err != nil {
							t.Fatal(err)
						}
					case tk.token != nil:
						put(t, f.p, FileToken, tk.token)
					}
					if withPending {
						put(t, f.p, FileEnrollPendingKey, pendingPEM(t, newP256(t), otherHash[:]))
					}
					before := snapshot(t, f.p, FileToken, FileTokenExpires, FileEnrollPendingKey)
					_, err := f.enroll(context.Background())
					if !errors.Is(err, ErrInvalidTrust) {
						t.Fatalf("Enroll = %v, want ErrInvalidTrust", err)
					}
					if len(f.cp.calls) != 0 {
						t.Fatalf("send called %d times, want 0", len(f.cp.calls))
					}
					sameFiles(t, f.p, before)
					if !withPending && present(t, f.p, FileEnrollPendingKey) {
						t.Fatal("enroll.pending-key.pem written before the agent CA check")
					}
					if present(t, f.p, FileIdentity) {
						t.Fatal("identity.pem written")
					}
					noSecretIn(t, err, tok, tok[5:21])
				})
			}
		}
	}
	// The same fixture with a real CA is accepted: the refusals above are
	// the CA check, not the fixture.
	t.Run("real CA control", func(t *testing.T) {
		t.Parallel()
		f := newEnrollFixture(t)
		if _, err := f.enroll(context.Background()); err != nil || len(f.cp.calls) != 1 {
			t.Fatalf("Enroll = %v after %d sends; want success after 1", err, len(f.cp.calls))
		}
	})
}

// selfSignedLeaf is a self-signed certificate with CA:FALSE: it signs
// itself but is not a CA.
func selfSignedLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	tmpl := caTemplate(t, "not a CA", testNow)
	tmpl.IsCA = false
	tmpl.BasicConstraintsValid = false
	c := newCAFrom(t, tmpl, nil).cert
	if c.IsCA || c.BasicConstraintsValid {
		t.Fatal("selfSignedLeaf: Go emitted basic constraints")
	}
	return c
}

// snapshot records the bytes of each named file; a missing file maps to
// nil and a directory to an empty non-nil slice.
func snapshot(t *testing.T, dir string, names ...string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte, len(names))
	for _, n := range names {
		p := filepath.Join(dir, n)
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			out[n] = nil
		case err != nil:
			t.Fatal(err)
		case fi.IsDir():
			out[n] = []byte{}
		default:
			data, err := readTestFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if data == nil {
				data = []byte{}
			}
			out[n] = data
		}
	}
	return out
}

// sameFiles fails unless every file in before is still there (or still
// absent) with the same bytes.
func sameFiles(t *testing.T, dir string, before map[string][]byte) {
	t.Helper()
	after := snapshot(t, dir, keys(before)...)
	for n, b := range before {
		a := after[n]
		switch {
		case b == nil && a != nil:
			t.Errorf("%s created", n)
		case b != nil && a == nil:
			t.Errorf("%s removed", n)
		case !bytes.Equal(a, b):
			t.Errorf("%s changed", n)
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// handshakeFixture is a state directory whose identity.pem is a real pair
// for testServerID, plus every leftover AfterHandshake may remove.
type handshakeFixture struct {
	d    *StateDir
	p    string
	ca   *testCA
	cur  Identity // identity.pem
	prev Identity // identity.prev.pem
}

// leftovers is the removal order of AfterHandshake.
var leftovers = []string{FileToken, FileTokenExpires, FileEnrollPendingKey, FileIdentityPrev}

func newHandshakeFixture(t *testing.T) *handshakeFixture {
	t.Helper()
	d, p := stateDir(t)
	ca := newCA(t, "agent CA", testNow)
	_, curPEM, _ := issuedPair(t, ca, testServerID, testNow, nil)
	_, prevPEM, _ := issuedPair(t, ca, testServerID, testNow, nil)
	put(t, p, FileIdentity, curPEM)
	put(t, p, FileIdentityPrev, prevPEM)
	cur, ok := loadValid(d, FileIdentity, testServerID, testNow)
	if !ok {
		t.Fatal("fixture identity.pem does not load")
	}
	prev, ok := loadValid(d, FileIdentityPrev, testServerID, testNow)
	if !ok {
		t.Fatal("fixture identity.prev.pem does not load")
	}
	return &handshakeFixture{d: d, p: p, ca: ca, cur: cur, prev: prev}
}

// putLeftovers writes a token, token-expires and an enroll pending key.
func (f *handshakeFixture) putLeftovers(t *testing.T) {
	t.Helper()
	h := TokenHash(canaryToken())
	put(t, f.p, FileToken, []byte(canaryToken()))
	put(t, f.p, FileTokenExpires, unixText(testNow.Unix()+3600))
	put(t, f.p, FileEnrollPendingKey, pendingPEM(t, newP256(t), h[:]))
}

// R18a case 1, R12a, R22: after a handshake with identity.pem, the leftovers
// go in order and identity.pem and the renewal pending key stay.
func TestAfterHandshake(t *testing.T) {
	t.Parallel()
	t.Run("all present", func(t *testing.T) {
		t.Parallel()
		f := newHandshakeFixture(t)
		f.putLeftovers(t)
		put(t, f.p, FileIdentityPendingKey, renewalKeyPEM(t, newP256(t)))
		kept := snapshot(t, f.p, FileIdentity, FileIdentityPendingKey)
		got, err := f.d.AfterHandshake(f.cur)
		if err != nil || strings.Join(got, ",") != strings.Join(leftovers, ",") {
			t.Fatalf("AfterHandshake = %q, %v; want %q", got, err, leftovers)
		}
		for _, n := range leftovers {
			if present(t, f.p, n) {
				t.Errorf("%s not removed", n)
			}
		}
		sameFiles(t, f.p, kept)
	})
	t.Run("identity from Decide", func(t *testing.T) {
		t.Parallel()
		f := newHandshakeFixture(t)
		f.putLeftovers(t)
		st, err := Decide(f.d, testServerID, testNow)
		if err != nil || st.State != StartUseIdentity {
			t.Fatalf("Decide = %+v, %v; want StartUseIdentity", st, err)
		}
		if got, err := f.d.AfterHandshake(st.Identity); err != nil || len(got) != len(leftovers) {
			t.Fatalf("AfterHandshake = %q, %v; want %q", got, err, leftovers)
		}
	})
	t.Run("none present", func(t *testing.T) {
		t.Parallel()
		f := newHandshakeFixture(t)
		_ = os.Remove(filepath.Join(f.p, FileIdentityPrev))
		if got, err := f.d.AfterHandshake(f.cur); err != nil || len(got) != 0 {
			t.Fatalf("AfterHandshake = %q, %v; want nothing", got, err)
		}
		if !present(t, f.p, FileIdentity) {
			t.Fatal("identity.pem removed")
		}
	})
	t.Run("some present", func(t *testing.T) {
		t.Parallel()
		f := newHandshakeFixture(t)
		put(t, f.p, FileTokenExpires, []byte("x"))
		got, err := f.d.AfterHandshake(f.cur)
		if err != nil || strings.Join(got, ",") != FileTokenExpires+","+FileIdentityPrev {
			t.Fatalf("AfterHandshake = %q, %v", got, err)
		}
	})
	// Validity is not rechecked: the handshake already succeeded, and
	// identity.pem may expire between the handshake and the clean-up.
	t.Run("expired identity.pem that was used", func(t *testing.T) {
		t.Parallel()
		f := newHandshakeFixture(t)
		key, pem, der := issuedPair(t, f.ca, testServerID, testNow, func(c *x509.Certificate) { c.NotAfter = testNow.Add(-time.Second) })
		put(t, f.p, FileIdentity, pem)
		f.putLeftovers(t)
		used := Identity{key: key, cert: mustParse(t, der)}
		if got, err := f.d.AfterHandshake(used); err != nil || len(got) != len(leftovers) {
			t.Fatalf("AfterHandshake = %q, %v; want %q", got, err, leftovers)
		}
	})
	t.Run("token removal fails keeps the pending key", func(t *testing.T) {
		t.Parallel()
		f := newHandshakeFixture(t)
		put(t, f.p, FileEnrollPendingKey, []byte("x"))
		if err := os.Mkdir(filepath.Join(f.p, FileToken), 0o700); err != nil {
			t.Fatal(err)
		}
		writeMode(t, filepath.Join(f.p, FileToken, "x"), nil, 0o600)
		_, err := f.d.AfterHandshake(f.cur)
		if err == nil {
			t.Fatal("AfterHandshake hid a failed removal")
		}
		if errors.Is(err, ErrNotCurrentIdentity) {
			t.Fatalf("AfterHandshake = %v; the identity matched, the removal failed", err)
		}
		if !present(t, f.p, FileEnrollPendingKey) || !present(t, f.p, FileIdentityPrev) {
			t.Fatal("pending key or identity.prev.pem removed while the token is still there")
		}
	})
	t.Run("unsafe dir", func(t *testing.T) {
		t.Parallel()
		f := newHandshakeFixture(t)
		f.putLeftovers(t)
		before := snapshot(t, f.p, append([]string{FileIdentity}, leftovers...)...)
		mustChmod(t, f.p, 0o755)
		got, err := f.d.AfterHandshake(f.cur)
		mustChmod(t, f.p, 0o700)
		// identity.pem cannot be read through an unsafe directory, so the
		// refusal may name either class; nothing may be removed.
		if !errors.Is(err, ErrUnsafeFile) && !errors.Is(err, ErrNotCurrentIdentity) {
			t.Fatalf("AfterHandshake = %v, want ErrUnsafeFile or ErrNotCurrentIdentity", err)
		}
		if len(got) != 0 {
			t.Fatalf("AfterHandshake reported %q removed", got)
		}
		sameFiles(t, f.p, before)
	})
}

// AfterHandshake removes nothing unless the pair that connected is exactly
// identity.pem. In particular a handshake with identity.prev.pem (R18a case
// 2) keeps identity.prev.pem, the token, token-expires and the enroll
// pending key: they are what the agent falls back on (R22, R12a).
func TestAfterHandshakeRefusesOtherIdentity(t *testing.T) {
	t.Parallel()
	all := append([]string{FileIdentity, FileIdentityPendingKey}, leftovers...)
	check := func(t *testing.T, f *handshakeFixture, used Identity) {
		t.Helper()
		before := snapshot(t, f.p, all...)
		got, err := f.d.AfterHandshake(used)
		if !errors.Is(err, ErrNotCurrentIdentity) {
			t.Fatalf("AfterHandshake = %q, %v; want ErrNotCurrentIdentity", got, err)
		}
		if got != nil {
			t.Fatalf("AfterHandshake reported %q removed, want nil", got)
		}
		sameFiles(t, f.p, before)
		noSecretIn(t, err, canaryToken(), canaryToken()[5:21])
	}
	// R18a case 2: identity.pem not valid, identity.prev.pem valid; Decide
	// picks the previous pair and the handshake uses it.
	invalidCurrent := map[string]func(t *testing.T, f *handshakeFixture){
		"identity.pem garbage": func(t *testing.T, f *handshakeFixture) { put(t, f.p, FileIdentity, []byte("garbage")) },
		"identity.pem expired": func(t *testing.T, f *handshakeFixture) {
			_, pem, _ := issuedPair(t, f.ca, testServerID, testNow, func(c *x509.Certificate) { c.NotAfter = testNow.Add(-time.Second) })
			put(t, f.p, FileIdentity, pem)
		},
		"identity.pem names another UUID": func(t *testing.T, f *handshakeFixture) {
			_, pem, _ := issuedPair(t, f.ca, otherServerID, testNow, nil)
			put(t, f.p, FileIdentity, pem)
		},
		"identity.pem missing": func(t *testing.T, f *handshakeFixture) { _ = os.Remove(filepath.Join(f.p, FileIdentity)) },
		"identity.pem empty":   func(t *testing.T, f *handshakeFixture) { put(t, f.p, FileIdentity, []byte{}) },
		"identity.pem key does not match certificate": func(t *testing.T, f *handshakeFixture) {
			put(t, f.p, FileIdentity, identityPEM(t, newP256(t), f.cur.cert.Raw))
		},
	}
	for name, setup := range invalidCurrent {
		t.Run("case 2/"+name, func(t *testing.T) {
			t.Parallel()
			f := newHandshakeFixture(t)
			setup(t, f)
			f.putLeftovers(t)
			put(t, f.p, FileIdentityPendingKey, renewalKeyPEM(t, newP256(t)))
			st, err := Decide(f.d, testServerID, testNow)
			if err != nil || st.State != StartUsePrevious {
				t.Fatalf("Decide = %+v, %v; want StartUsePrevious", st, err)
			}
			check(t, f, st.Identity)
		})
	}
	// identity.pem valid, but the pair that connected is another one.
	others := map[string]func(t *testing.T, f *handshakeFixture) Identity{
		"previous pair while identity.pem is valid": func(t *testing.T, f *handshakeFixture) Identity { return f.prev },
		"unrelated pair": func(t *testing.T, f *handshakeFixture) Identity {
			key, _, der := issuedPair(t, f.ca, testServerID, testNow, nil)
			return Identity{key: key, cert: mustParse(t, der)}
		},
		"identity.pem certificate with another key": func(t *testing.T, f *handshakeFixture) Identity {
			return Identity{key: newP256(t), cert: f.cur.cert}
		},
		"identity.pem key with another certificate": func(t *testing.T, f *handshakeFixture) Identity {
			der := f.ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &f.cur.key.PublicKey)
			return Identity{key: f.cur.key, cert: mustParse(t, der)}
		},
		"identity.pem key, no certificate": func(t *testing.T, f *handshakeFixture) Identity {
			return Identity{key: f.cur.key}
		},
		"identity.pem certificate, no key": func(t *testing.T, f *handshakeFixture) Identity {
			return Identity{cert: f.cur.cert}
		},
		"zero Identity": func(t *testing.T, f *handshakeFixture) Identity { return Identity{} },
	}
	for name, used := range others {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newHandshakeFixture(t)
			f.putLeftovers(t)
			put(t, f.p, FileIdentityPendingKey, renewalKeyPEM(t, newP256(t)))
			check(t, f, used(t, f))
		})
	}
	// Each check fails closed whatever identity.pem holds.
	t.Run("zero Identity, identity.pem missing", func(t *testing.T) {
		t.Parallel()
		f := newHandshakeFixture(t)
		_ = os.Remove(filepath.Join(f.p, FileIdentity))
		f.putLeftovers(t)
		check(t, f, Identity{})
	})
	t.Run("identity.pem symlink to the used pair", func(t *testing.T) {
		t.Parallel()
		f := newHandshakeFixture(t)
		data, err := readTestFile(filepath.Join(f.p, FileIdentity))
		if err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "identity.pem")
		writeMode(t, outside, data, 0o600)
		_ = os.Remove(filepath.Join(f.p, FileIdentity))
		if err := os.Symlink(outside, filepath.Join(f.p, FileIdentity)); err != nil {
			t.Fatal(err)
		}
		f.putLeftovers(t)
		check(t, f, f.cur)
	})
	// A renewal replaced identity.pem after the old pair connected: the
	// old pair is no longer identity.pem, so its connection proves nothing
	// about the new one.
	t.Run("identity.pem replaced after the handshake", func(t *testing.T) {
		t.Parallel()
		f := newHandshakeFixture(t)
		used := f.cur
		_, pem, _ := issuedPair(t, f.ca, testServerID, testNow, nil)
		put(t, f.p, FileIdentity, pem)
		f.putLeftovers(t)
		check(t, f, used)
	})
}
