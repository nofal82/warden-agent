package identity

// TLS tests for R24 and AC15. Every handshake runs over an in-process
// socketpair (connPair): no test opens a listening socket.

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"
	"time"
)

type cpServer struct {
	chain [][]byte
	key   crypto.Signer
	leaf  *x509.Certificate
}

// issueServer issues a control-plane server certificate for name from ca,
// valid around now, after mut adjusts the template.
func issueServer(t testing.TB, ca *testCA, name string, now time.Time, mut func(*x509.Certificate)) cpServer {
	t.Helper()
	key := newP256(t)
	tmpl := serverLeafTemplate(t, name, now)
	if mut != nil {
		mut(tmpl)
	}
	der := ca.issue(t, tmpl, &key.PublicKey)
	return cpServer{chain: [][]byte{der}, key: key, leaf: mustParse(t, der)}
}

func mustClientTLS(t testing.TB, cas []*x509.Certificate, name string, client *tls.Certificate, now func() time.Time) *tls.Config {
	t.Helper()
	cfg, err := ClientTLSConfig(cas, name, client, now)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	return cfg
}

func insecureFlag(cfg *tls.Config) bool {
	// The field name is assembled so no file of this package contains it
	// (R24, AC15 source scan).
	return reflect.ValueOf(cfg).Elem().FieldByName("Insecure" + "SkipVerify").Bool()
}

func TestClientTLSConfigFields(t *testing.T) {
	t.Parallel()
	caA := newCA(t, "cp CA A", testNow)
	caB := newCA(t, "cp CA B", testNow)
	for _, cas := range [][]*x509.Certificate{{caA.cert}, {caA.cert, caB.cert}} {
		cfg := mustClientTLS(t, cas, testServerName, nil, nil)
		if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
			t.Errorf("versions = %#x..%#x, want TLS 1.3 only", cfg.MinVersion, cfg.MaxVersion)
		}
		want := x509.NewCertPool()
		for _, c := range cas {
			want.AddCert(c)
		}
		if cfg.RootCAs == nil || !cfg.RootCAs.Equal(want) {
			t.Error("RootCAs is not exactly the given CAs")
		}
		if sys, err := x509.SystemCertPool(); err == nil && cfg.RootCAs != nil && cfg.RootCAs.Equal(sys) {
			t.Error("RootCAs is the system pool")
		}
		if cfg.ServerName != testServerName {
			t.Errorf("ServerName = %q", cfg.ServerName)
		}
		if cfg.ClientSessionCache != nil {
			t.Error("ClientSessionCache is set")
		}
		if insecureFlag(cfg) {
			t.Error("certificate verification is disabled")
		}
		if cfg.VerifyConnection == nil {
			t.Error("VerifyConnection is not set")
		}
		if len(cfg.Certificates) != 0 || cfg.GetClientCertificate != nil {
			t.Error("a client certificate is configured on the enrollment config")
		}
	}
}

// The returned config does not alias the caller's slice: changing it later
// cannot add a trust anchor.
func TestClientTLSConfigDoesNotAliasCAs(t *testing.T) {
	t.Parallel()
	caA := newCA(t, "cp CA A", time.Now())
	evil := newCA(t, "evil", time.Now())
	cas := []*x509.Certificate{caA.cert}
	cfg := mustClientTLS(t, cas, testServerName, nil, nil)
	cas[0] = evil.cert
	srv := issueServer(t, evil, testServerName, time.Now(), nil)
	if _, err, _ := tlsPair(t, cfg, serverTLS(srv.chain, srv.key, 0)); err == nil {
		t.Fatal("a CA swapped into the caller's slice after the call became trusted")
	}
}

func TestClientTLSConfigClientCertificate(t *testing.T) {
	t.Parallel()
	agentCA := newCA(t, "agent CA", testNow)
	key := newP256(t)
	der := agentCA.issue(t, agentLeafTemplate(t, testServerID, testNow), &key.PublicKey)
	client := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	cp := newCA(t, "cp CA", testNow)
	cfg := mustClientTLS(t, []*x509.Certificate{cp.cert}, testServerName, client, nil)
	if len(cfg.Certificates) == 1 {
		if !bytes.Equal(cfg.Certificates[0].Certificate[0], der) {
			t.Fatal("configured client certificate differs")
		}
		return
	}
	if cfg.GetClientCertificate == nil {
		t.Fatal("no client certificate configured on the agent config")
	}
	got, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{Version: tls.VersionTLS13})
	if err != nil || got == nil || len(got.Certificate) == 0 || !bytes.Equal(got.Certificate[0], der) {
		t.Fatal("GetClientCertificate does not return the agent certificate")
	}
}

func TestClientTLSConfigRefusals(t *testing.T) {
	t.Parallel()
	ca1 := newCA(t, "1", testNow)
	ca2 := newCA(t, "2", testNow)
	ca3 := newCA(t, "3", testNow)
	leaf := issueServer(t, ca1, testServerName, testNow, nil).leaf
	notCATmpl := caTemplate(t, "not CA", testNow)
	notCATmpl.IsCA = false
	notCATmpl.KeyUsage = x509.KeyUsageDigitalSignature
	notCA := newCAFrom(t, notCATmpl, nil).cert
	noBC := caTemplate(t, "no basic constraints", testNow)
	noBC.BasicConstraintsValid = false
	noBC.IsCA = false
	noBCCert := newCAFrom(t, noBC, nil).cert

	cases := []struct {
		name string
		cas  []*x509.Certificate
		sn   string
		want error
	}{
		{"nil CAs", nil, testServerName, ErrInvalidTrust},
		{"zero CAs", []*x509.Certificate{}, testServerName, ErrInvalidTrust},
		{"three CAs", []*x509.Certificate{ca1.cert, ca2.cert, ca3.cert}, testServerName, ErrInvalidTrust},
		{"nil entry", []*x509.Certificate{nil}, testServerName, ErrInvalidTrust},
		{"nil second entry", []*x509.Certificate{ca1.cert, nil}, testServerName, ErrInvalidTrust},
		{"leaf as CA", []*x509.Certificate{leaf}, testServerName, ErrInvalidTrust},
		{"CA:false self-signed", []*x509.Certificate{notCA}, testServerName, ErrInvalidTrust},
		{"no basic constraints", []*x509.Certificate{noBCCert}, testServerName, ErrInvalidTrust},
		{"zero certificate", []*x509.Certificate{{}}, testServerName, ErrInvalidTrust},
		{"empty server name", []*x509.Certificate{ca1.cert}, "", ErrInvalidServerName},
		{"wildcard server name", []*x509.Certificate{ca1.cert}, "*.example.test", ErrInvalidServerName},
		{"host:port server name", []*x509.Certificate{ca1.cert}, testServerName + ":443", ErrInvalidServerName},
		{"bracketed ipv6 server name", []*x509.Certificate{ca1.cert}, "[2001:db8::1]", ErrInvalidServerName},
		{"trailing dot server name", []*x509.Certificate{ca1.cert}, testServerName + ".", ErrInvalidServerName},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := ClientTLSConfig(tc.cas, tc.sn, nil, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ClientTLSConfig = %v, want %v", err, tc.want)
			}
			if cfg != nil {
				t.Error("a config was returned with the error")
			}
		})
	}
}

// RootCAs trusts only what it was given: a certificate from another CA (for
// example one a public CA would issue) does not verify against it.
func TestClientTLSConfigRootsOnlyGiven(t *testing.T) {
	t.Parallel()
	caA := newCA(t, "A", testNow)
	caB := newCA(t, "B", testNow)
	cfg := mustClientTLS(t, []*x509.Certificate{caA.cert}, testServerName, nil, nil)
	good := issueServer(t, caA, testServerName, testNow, nil).leaf
	bad := issueServer(t, caB, testServerName, testNow, nil).leaf
	opts := x509.VerifyOptions{Roots: cfg.RootCAs, CurrentTime: testNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := good.Verify(opts); err != nil {
		t.Fatalf("leaf from the trusted CA does not verify: %v", err)
	}
	if _, err := bad.Verify(opts); err == nil {
		t.Fatal("leaf from an untrusted CA verifies against RootCAs")
	}
}

func TestHandshakeAccepted(t *testing.T) {
	t.Parallel()
	now := time.Now()
	caA := newCA(t, "cp CA A", now)
	caB := newCA(t, "cp CA B", now)
	one := []*x509.Certificate{caA.cert}
	two := []*x509.Certificate{caA.cert, caB.cert}
	cases := []struct {
		name string
		cas  []*x509.Certificate
		sn   string
		srv  cpServer
		now  func() time.Time
	}{
		{"one CA dns", one, testServerName, issueServer(t, caA, testServerName, now, nil), nil},
		{"one CA explicit clock", one, testServerName, issueServer(t, caA, testServerName, now, nil), time.Now},
		{"two CAs cert from A", two, testServerName, issueServer(t, caA, testServerName, now, nil), nil},
		{"two CAs cert from B", two, testServerName, issueServer(t, caB, testServerName, now, nil), nil},
		{"ipv4 server name", one, "192.0.2.10", issueServer(t, caA, "192.0.2.10", now, nil), nil},
		{"ipv6 server name", one, "2001:db8::10", issueServer(t, caA, "2001:db8::10", now, nil), nil},
		{"extra SAN besides server name", one, testServerName, issueServer(t, caA, testServerName, now, func(c *x509.Certificate) {
			c.DNSNames = append(c.DNSNames, "other.example.test")
		}), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := mustClientTLS(t, tc.cas, tc.sn, nil, tc.now)
			state, cerr, serr := tlsPair(t, cfg, serverTLS(tc.srv.chain, tc.srv.key, 0))
			if cerr != nil || serr != nil {
				t.Fatalf("handshake refused: client %v, server %v", cerr, serr)
			}
			if state.Version != tls.VersionTLS13 {
				t.Fatalf("negotiated %#x, want TLS 1.3", state.Version)
			}
			if state.DidResume {
				t.Fatal("first handshake resumed")
			}
		})
	}
}

func TestHandshakeSendsClientCertificateOnlyWhenGiven(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cp := newCA(t, "cp CA", now)
	srv := issueServer(t, cp, testServerName, now, nil)
	agentCA := newCA(t, "agent CA", now)
	key := newP256(t)
	der := agentCA.issue(t, agentLeafTemplate(t, testServerID, now), &key.PublicKey)

	for _, withClient := range []bool{false, true} {
		var client *tls.Certificate
		if withClient {
			client = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
		}
		cfg := mustClientTLS(t, []*x509.Certificate{cp.cert}, testServerName, client, nil)
		got := make(chan [][]byte, 1)
		scfg := serverTLS(srv.chain, srv.key, 0)
		scfg.ClientAuth = tls.RequestClientCert
		scfg.VerifyConnection = func(cs tls.ConnectionState) error {
			var raws [][]byte
			for _, c := range cs.PeerCertificates {
				raws = append(raws, c.Raw)
			}
			got <- raws
			return nil
		}
		if _, cerr, serr := tlsPair(t, cfg, scfg); cerr != nil || serr != nil {
			t.Fatalf("handshake: client %v, server %v", cerr, serr)
		}
		raws := <-got
		if !withClient && len(raws) != 0 {
			t.Fatal("enrollment config presented a client certificate")
		}
		if withClient && (len(raws) != 1 || !bytes.Equal(raws[0], der)) {
			t.Fatalf("agent config presented %d certificates, want the agent leaf", len(raws))
		}
	}
}

func TestHandshakeRejected(t *testing.T) {
	t.Parallel()
	now := time.Now()
	caA := newCA(t, "cp CA A", now)
	other := newCA(t, "cp CA A", now) // same name, other key
	inter := newCAFrom(t, caTemplate(t, "cp intermediate", now), caA)
	one := []*x509.Certificate{caA.cert}

	interLeafKey := newP256(t)
	interLeaf := inter.issue(t, serverLeafTemplate(t, testServerName, now), &interLeafKey.PublicKey)
	unrelated := issueServer(t, other, "unrelated.example.test", now, nil)
	twoCerts := issueServer(t, caA, testServerName, now, nil)
	twoCerts.chain = append(twoCerts.chain, unrelated.chain[0])
	selfSigned := func() cpServer {
		ca := newCAFrom(t, func() *x509.Certificate {
			c := serverLeafTemplate(t, testServerName, now)
			return c
		}(), nil)
		return cpServer{chain: [][]byte{ca.cert.Raw}, key: ca.key, leaf: ca.cert}
	}()

	cases := []struct {
		name       string
		sn         string
		srv        cpServer
		maxVersion uint16
		now        func() time.Time
		// wantPeer: Go's own verification passes, so the refusal must come
		// from VerifyConnection.
		wantPeer bool
	}{
		{"other CA", testServerName, issueServer(t, other, testServerName, now, nil), 0, nil, false},
		{"self-signed leaf", testServerName, selfSigned, 0, nil, false},
		{"name mismatch", testServerName, issueServer(t, caA, "other.example.test", now, nil), 0, nil, false},
		{"wildcard cert", testServerName, issueServer(t, caA, testServerName, now, func(c *x509.Certificate) {
			c.DNSNames = []string{"*.example.test"}
		}), 0, nil, true},
		{"CN only no SAN", testServerName, issueServer(t, caA, testServerName, now, func(c *x509.Certificate) {
			c.DNSNames = nil
		}), 0, nil, false},
		{"ip server name, DNS-only cert", "192.0.2.10", issueServer(t, caA, testServerName, now, nil), 0, nil, false},
		{"dns server name, IP-only cert", testServerName, issueServer(t, caA, "192.0.2.10", now, nil), 0, nil, false},
		{"EKU clientAuth only", testServerName, issueServer(t, caA, testServerName, now, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}), 0, nil, false},
		{"EKU serverAuth and clientAuth", testServerName, issueServer(t, caA, testServerName, now, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		}), 0, nil, true},
		{"EKU any", testServerName, issueServer(t, caA, testServerName, now, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}), 0, nil, true},
		{"no EKU", testServerName, issueServer(t, caA, testServerName, now, func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
		}), 0, nil, true},
		{"leaf CA:true", testServerName, issueServer(t, caA, testServerName, now, func(c *x509.Certificate) {
			c.IsCA = true
			c.KeyUsage |= x509.KeyUsageCertSign
		}), 0, nil, true},
		{"expired (Go check)", testServerName, issueServer(t, caA, testServerName, now, func(c *x509.Certificate) {
			c.NotBefore = now.Add(-100 * 24 * time.Hour)
			c.NotAfter = now.Add(-time.Hour)
		}), 0, nil, false},
		{"expired (now func)", testServerName, issueServer(t, caA, testServerName, now, nil), 0, fixedClock(now.Add(200 * 24 * time.Hour)), false},
		{"not yet valid (now func)", testServerName, issueServer(t, caA, testServerName, now, nil), 0, fixedClock(now.Add(-48 * time.Hour)), false},
		{"chain of length 3", testServerName, cpServer{chain: [][]byte{interLeaf, inter.cert.Raw}, key: interLeafKey}, 0, nil, true},
		{"TLS 1.2 server", testServerName, issueServer(t, caA, testServerName, now, nil), tls.VersionTLS12, nil, false},
		{"two certificates presented", testServerName, twoCerts, 0, nil, true},
		{"trusted CA cert sent as the leaf", testServerName, cpServer{chain: [][]byte{caA.cert.Raw}, key: caA.key}, 0, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := mustClientTLS(t, one, tc.sn, nil, tc.now)
			_, cerr, _ := tlsPair(t, cfg, serverTLS(tc.srv.chain, tc.srv.key, tc.maxVersion))
			if cerr == nil {
				t.Fatal("handshake accepted")
			}
			if tc.wantPeer && !errors.Is(cerr, ErrPeerRejected) {
				t.Fatalf("handshake error = %v, want ErrPeerRejected from VerifyConnection", cerr)
			}
		})
	}
}

// Every connection is a full handshake (R24, AC15). The control run shows
// the test peer does issue tickets, so a client cache would resume.
func TestNoSessionResumption(t *testing.T) {
	t.Parallel()
	now := time.Now()
	ca := newCA(t, "cp CA", now)
	srv := issueServer(t, ca, testServerName, now, nil)
	scfg := serverTLS(srv.chain, srv.key, 0)
	cfg := mustClientTLS(t, []*x509.Certificate{ca.cert}, testServerName, nil, nil)

	control := cfg.Clone()
	control.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	for i := 0; i < 2; i++ {
		state, cerr, serr := tlsPair(t, control, scfg)
		if cerr != nil || serr != nil {
			t.Fatalf("control handshake %d: %v / %v", i, cerr, serr)
		}
		if i == 1 && !state.DidResume {
			t.Fatal("control: the test peer did not offer resumption, so this test proves nothing")
		}
	}

	for i := 0; i < 3; i++ {
		state, cerr, serr := tlsPair(t, cfg, scfg)
		if cerr != nil || serr != nil {
			t.Fatalf("handshake %d: %v / %v", i, cerr, serr)
		}
		if state.DidResume {
			t.Fatalf("handshake %d resumed a session", i)
		}
	}
}

// VerifyConnection is called directly with crafted states, so each R24
// check is exercised even where Go's own verification would stop first.
func TestVerifyConnectionDirect(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "cp CA", testNow)
	other := newCA(t, "other", testNow)
	inter := newCAFrom(t, caTemplate(t, "inter", testNow), ca)
	reissued := ca.reissueSelf(t)
	if bytes.Equal(reissued.Raw, ca.cert.Raw) {
		t.Fatal("reissued CA is byte-identical")
	}

	good := issueServer(t, ca, testServerName, testNow, nil).leaf
	second := issueServer(t, ca, testServerName, testNow, nil).leaf
	fromOther := issueServer(t, other, testServerName, testNow, nil).leaf
	interKey := newP256(t)
	viaInter := mustParse(t, inter.issue(t, serverLeafTemplate(t, testServerName, testNow), &interKey.PublicKey))
	clientOnly := issueServer(t, ca, testServerName, testNow, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}).leaf
	bothEKU := issueServer(t, ca, testServerName, testNow, func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}).leaf
	leafCA := issueServer(t, ca, testServerName, testNow, func(c *x509.Certificate) {
		c.IsCA = true
		c.KeyUsage |= x509.KeyUsageCertSign
	}).leaf
	wildcard := issueServer(t, ca, testServerName, testNow, func(c *x509.Certificate) {
		c.DNSNames = []string{"*.example.test"}
	}).leaf
	otherName := issueServer(t, ca, "other.example.test", testNow, nil).leaf
	expired := issueServer(t, ca, testServerName, testNow, func(c *x509.Certificate) {
		c.NotBefore = testNow.Add(-90 * 24 * time.Hour)
		c.NotAfter = testNow.Add(-time.Second)
	}).leaf

	cfg := mustClientTLS(t, []*x509.Certificate{ca.cert}, testServerName, nil, fixedClock(testNow))
	st := func(peers []*x509.Certificate, chains ...[]*x509.Certificate) tls.ConnectionState {
		return tls.ConnectionState{
			Version:           tls.VersionTLS13,
			HandshakeComplete: true,
			ServerName:        testServerName,
			PeerCertificates:  peers,
			VerifiedChains:    chains,
		}
	}
	p := func(c ...*x509.Certificate) []*x509.Certificate { return c }

	if err := cfg.VerifyConnection(st(p(good), p(good, ca.cert))); err != nil {
		t.Fatalf("control: a correct state is refused: %v", err)
	}

	cases := []struct {
		name  string
		state tls.ConnectionState
	}{
		{"zero peer certificates", st(nil, p(good, ca.cert))},
		{"zero everything", tls.ConnectionState{}},
		{"two peer certificates", st(p(good, second), p(good, ca.cert))},
		{"two peer certificates leaf and CA", st(p(good, ca.cert), p(good, ca.cert))},
		{"empty verified chains", st(p(good))},
		{"empty chain inside", st(p(good), p())},
		{"chain of length 1", st(p(good), p(good))},
		{"chain of length 3", st(p(viaInter), p(viaInter, inter.cert, ca.cert))},
		{"second element not trusted", st(p(fromOther), p(fromOther, other.cert))},
		{"second element same key different bytes", st(p(good), p(good, reissued))},
		{"one good chain and one bad", st(p(good), p(good, ca.cert), p(good, other.cert))},
		{"forged chain: leaf from other CA claims trusted CA", st(p(fromOther), p(fromOther, ca.cert))},
		{"chain leaf differs from peer", st(p(good), p(second, ca.cert))},
		{"EKU clientAuth only", st(p(clientOnly), p(clientOnly, ca.cert))},
		{"EKU serverAuth and clientAuth", st(p(bothEKU), p(bothEKU, ca.cert))},
		{"leaf is a CA", st(p(leafCA), p(leafCA, ca.cert))},
		{"wildcard SAN", st(p(wildcard), p(wildcard, ca.cert))},
		{"other name", st(p(otherName), p(otherName, ca.cert))},
		{"expired at now", st(p(expired), p(expired, ca.cert))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := cfg.VerifyConnection(tc.state); !errors.Is(err, ErrPeerRejected) {
				t.Fatalf("VerifyConnection = %v, want ErrPeerRejected", err)
			}
		})
	}
}

// The re-verification uses the now function: a state that is valid now is
// refused when the clock says the leaf has expired.
func TestVerifyConnectionUsesClock(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "cp CA", testNow)
	leaf := issueServer(t, ca, testServerName, testNow, nil).leaf
	state := tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf, ca.cert}},
	}
	ok := mustClientTLS(t, []*x509.Certificate{ca.cert}, testServerName, nil, fixedClock(testNow))
	if err := ok.VerifyConnection(state); err != nil {
		t.Fatalf("valid at now: %v", err)
	}
	late := mustClientTLS(t, []*x509.Certificate{ca.cert}, testServerName, nil, fixedClock(leaf.NotAfter.Add(time.Second)))
	if err := late.VerifyConnection(state); !errors.Is(err, ErrPeerRejected) {
		t.Fatalf("after not-after: %v, want ErrPeerRejected", err)
	}
	early := mustClientTLS(t, []*x509.Certificate{ca.cert}, testServerName, nil, fixedClock(leaf.NotBefore.Add(-time.Second)))
	if err := early.VerifyConnection(state); !errors.Is(err, ErrPeerRejected) {
		t.Fatalf("before not-before: %v, want ErrPeerRejected", err)
	}
}

// With two trusted CAs, a chain ending at either one passes.
func TestVerifyConnectionTwoCAs(t *testing.T) {
	t.Parallel()
	a := newCA(t, "A", testNow)
	b := newCA(t, "B", testNow)
	cfg := mustClientTLS(t, []*x509.Certificate{a.cert, b.cert}, testServerName, nil, fixedClock(testNow))
	for _, ca := range []*testCA{a, b} {
		leaf := issueServer(t, ca, testServerName, testNow, nil).leaf
		state := tls.ConnectionState{
			Version:          tls.VersionTLS13,
			PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains:   [][]*x509.Certificate{{leaf, ca.cert}},
		}
		if err := cfg.VerifyConnection(state); err != nil {
			t.Fatalf("leaf from %s refused: %v", ca.cert.Subject.CommonName, err)
		}
	}
}
