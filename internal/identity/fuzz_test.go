package identity

// Native fuzz tests for every parser and validator of the package. Seeds
// are the attack cases of the unit tests; key material is generated at
// runtime, so no seed is a real secret.
//
// Note for whoever runs `make fuzz-short`: a failing input is saved under
// testdata/fuzz/. Inputs of FuzzDecodePendingEnrollKey and
// FuzzDecodeIdentity may contain a PEM private-key header; such a corpus file
// must be reduced (or its block type changed) before it is committed, as the
// rule checker refuses that header.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var (
	serverIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenRe    = regexp.MustCompile(`^wdn1_[A-Za-z0-9_-]{43}$`)
)

func FuzzValidateServerID(f *testing.F) {
	for _, s := range []string{
		testServerID, otherServerID, strings.ToUpper(testServerID), "", testServerID + "\n",
		"\ufeff" + testServerID, "{" + testServerID + "}", testServerID[:35], testServerID + "0",
		"01920f3e-7c4a-7b2d-8e5f-0a1b2c3d4e5f", "6f1c2d3e-4a5b-4c6d-ce7f-90a1b2c3d4e5",
		"00000000-0000-0000-0000-000000000000", "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e\x00",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateServerID(s)
		// The spec regex is the exact oracle (§4.1).
		if want := serverIDRe.MatchString(s); want != (err == nil) {
			t.Fatalf("ValidateServerID(%q) = %v, regex says valid=%v", s, err, want)
		}
		if err != nil && !errors.Is(err, ErrInvalidServerID) {
			t.Fatalf("wrong error class: %v", err)
		}
		if err == nil && len(s) != 36 {
			t.Fatalf("accepted %d bytes", len(s))
		}
	})
}

func FuzzValidateToken(f *testing.F) {
	body := strings.Repeat("Q", 43)
	for _, s := range []string{
		canaryToken(), otherToken(), "", "wdn1" + "_", "wdn1" + "_" + body[:42],
		"wdn1" + "_" + body + "Q", "wdn1" + "_" + body[:42] + "=", "wdn1" + "_" + body[:42] + "+",
		"wdn1" + "_" + body[:42] + "/", "wdn2" + "_" + body, "WDN1" + "_" + body,
		"wdn1" + "_" + body[:41] + "\u00e9", "wdn1" + "_" + body[:42] + "\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateToken(s)
		if want := tokenRe.MatchString(s); want != (err == nil) {
			t.Fatalf("ValidateToken(len %d) = %v, regex says valid=%v", len(s), err, want)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("wrong error class: %v", err)
			}
			if len(s) >= 8 && strings.Contains(err.Error(), s) {
				t.Fatal("error echoes the input")
			}
		}
	})
}

// ldhName reports whether s is a DNS name under the §4.3 rules.
func ldhName(s string) bool {
	for _, l := range strings.Split(s, ".") {
		if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			if !isLDH(l[i]) {
				return false
			}
		}
	}
	return true
}

func isLDH(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

func FuzzValidateServerName(f *testing.F) {
	for _, s := range []string{
		testServerName, "localhost", "192.0.2.10", "2001:db8::10", "::1", "", "*.example.test",
		"cp.example.test.", "-cp.example.test", "cp-.example.test", "cp..example.test",
		"cp_1.example.test", "cp example.test", testServerName + ":443", "[2001:db8::10]",
		"https://" + testServerName, "c\u00e9.example.test", "fe80::1%eth0", strings.Repeat("a", 64),
		strings.Repeat("a.", 127),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateServerName(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidServerName) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		if len(s) < 1 || len(s) > 253 {
			t.Fatalf("accepted a name of %d bytes", len(s))
		}
		if strings.ContainsAny(s, "*[]/@% \t\r\n\x00_") {
			t.Fatalf("accepted %q", s)
		}
		addr, ipErr := netip.ParseAddr(s)
		isIP := ipErr == nil && addr.Zone() == ""
		if !isIP && !ldhName(s) {
			t.Fatalf("accepted %q, which is neither an IP literal nor an LDH DNS name", s)
		}
	})
}

func FuzzNewExecutorBinding(f *testing.F) {
	for _, n := range [][2]int{{32, 32}, {0, 0}, {31, 32}, {33, 32}, {32, 31}, {32, 33}, {64, 64}} {
		f.Add(bytesOf(n[0], 0xa5), bytesOf(n[1], 0x5a))
	}
	f.Fuzz(func(t *testing.T, pub, mac []byte) {
		b, err := NewExecutorBinding(pub, mac)
		want := len(pub) == 32 && len(mac) == 32
		if want != (err == nil) {
			t.Fatalf("NewExecutorBinding(%d, %d) = %v", len(pub), len(mac), err)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidBinding) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		if !bytes.Equal(b.PublicKey[:], pub) || !bytes.Equal(b.MAC[:], mac) {
			t.Fatal("binding differs from input")
		}
	})
}

func FuzzDecodePendingEnrollKey(f *testing.F) {
	key := newP256(f)
	h := TokenHash(canaryToken())
	keyBlock := pemBlock(privateKeyBlockType(), pkcs8(f, key), nil)
	hashBlock := pemBlock(tokenHashBlockType, h[:], nil)
	for _, s := range [][]byte{
		pendingPEM(f, key, h[:]),
		cat(hashBlock, keyBlock),
		cat(keyBlock, hashBlock, hashBlock),
		cat([]byte("x"), keyBlock, hashBlock),
		cat(keyBlock, hashBlock, []byte("x")),
		pendingPEM(f, key, h[:31]),
		pendingPEM(f, key, append(h[:], 0)),
		pendingPEM(f, newP384(f), h[:]),
		cat(pemBlock(ecPrivateKeyBlockType(), sec1(f, key), nil), hashBlock),
		cat(pemBlock(privateKeyBlockType(), pkcs8(f, key), map[string]string{"A": "b"}), hashBlock),
		{},
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		k, hash, err := DecodePendingEnrollKey(data)
		if err != nil {
			if !errors.Is(err, ErrMalformedFile) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		if k == nil || k.Curve != elliptic.P256() {
			t.Fatal("accepted a key that is not P-256")
		}
		again, err := EncodePendingEnrollKey(k, hash)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		k2, h2, err := DecodePendingEnrollKey(again)
		if err != nil || !k2.Equal(k) || h2 != hash {
			t.Fatalf("re-encoded file does not round-trip: %v", err)
		}
	})
}

func FuzzDecodeIdentity(f *testing.F) {
	ca := newCA(f, "agent CA", testNow)
	key := newP256(f)
	der := ca.issue(f, agentLeafTemplate(f, testServerID, testNow), &key.PublicKey)
	keyBlock := pemBlock(privateKeyBlockType(), pkcs8(f, key), nil)
	certBlock := pemBlock(certBlockType, der, nil)
	other := newP256(f)
	for _, s := range [][]byte{
		identityPEM(f, key, der),
		cat(certBlock, keyBlock),
		cat(keyBlock, certBlock, certBlock),
		cat(keyBlock, keyBlock, certBlock),
		cat([]byte("x"), keyBlock, certBlock),
		cat(keyBlock, certBlock, []byte("x")),
		identityPEM(f, other, der),
		cat(keyBlock, pemBlock(certBlockType, append(bytes.Clone(der), 0), nil)),
		cat(pemBlock(ecPrivateKeyBlockType(), sec1(f, key), nil), certBlock),
		{},
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		k, c, err := DecodeIdentity(data)
		if err != nil {
			if !errors.Is(err, ErrMalformedFile) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		if k == nil || c == nil || k.Curve != elliptic.P256() {
			t.Fatal("accepted a non-P-256 key or nil values")
		}
		pub, ok := c.PublicKey.(*ecdsa.PublicKey)
		if !ok || !pub.Equal(&k.PublicKey) {
			t.Fatal("accepted a certificate whose key is not the private key's")
		}
		k2, c2, err := DecodeIdentity(identityPEM(t, k, c.Raw))
		if err != nil || !k2.Equal(k) || !bytes.Equal(c2.Raw, c.Raw) {
			t.Fatalf("re-encoded identity does not round-trip: %v", err)
		}
	})
}

func FuzzVerifyIssued(f *testing.F) {
	fx := newVerifyFixture(f)
	valid := mustParse(f, fx.leaf)
	pub := &fx.key.PublicKey
	other := newCA(f, "warden agent CA", testNow)
	f.Add(fx.leaf)
	f.Add(append(bytes.Clone(fx.leaf), 0))
	f.Add(fx.leaf[:len(fx.leaf)-1])
	f.Add([]byte{})
	f.Add([]byte("garbage"))
	f.Add(fx.ca.cert.Raw)
	f.Add(fx.ca.issue(f, agentLeafTemplate(f, otherServerID, testNow), pub))
	f.Add(other.issue(f, agentLeafTemplate(f, testServerID, testNow), pub))
	srv := agentLeafTemplate(f, testServerID, testNow)
	srv.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	f.Add(fx.ca.issue(f, srv, pub))
	f.Fuzz(func(t *testing.T, der []byte) {
		v, err := VerifyIssued(der, testServerID, fx.key, fx.ca.cert, testNow)
		if err != nil {
			if !errors.Is(err, ErrCertificateRejected) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		// Only the one valid leaf (up to ECDSA signature re-encoding) can be
		// accepted: anything else would need a forged agent-CA signature.
		c := v.Certificate()
		if c == nil || !bytes.Equal(c.RawTBSCertificate, valid.RawTBSCertificate) {
			t.Fatal("accepted a certificate other than the valid leaf")
		}
		if len(der) > MaxCertificateBytes {
			t.Fatalf("accepted %d bytes", len(der))
		}
	})
}

// FuzzBuildEnrollRequest: a request is built only when token, server ID
// and CSR all validate, and it carries exactly the inputs (design §A.5).
func FuzzBuildEnrollRequest(f *testing.F) {
	key := newP256(f)
	csr := mustCSR(f, key)
	body := strings.Repeat("Q", 43)
	f.Add(canaryToken(), testServerID, csr)
	f.Add(canaryToken()+"\n", testServerID, csr)
	f.Add("wdn1"+"_"+body[:42], testServerID, csr)
	f.Add(canaryToken(), strings.ToUpper(testServerID), csr)
	f.Add(canaryToken(), testServerID+"\n", csr)
	f.Add(canaryToken(), testServerID, append(bytes.Clone(csr), 0))
	f.Add(canaryToken(), testServerID, csr[:len(csr)-1])
	f.Add(canaryToken(), testServerID, mustCSR(f, newP384(f)))
	f.Add(canaryToken(), testServerID, []byte{})
	f.Add("", "", []byte(nil))
	binding := testBinding(f)
	f.Fuzz(func(t *testing.T, token, serverID string, csrDER []byte) {
		req, err := BuildEnrollRequest(token, serverID, csrDER, binding)
		_, csrErr := checkCSR(csrDER)
		want := ValidateToken(token) == nil && ValidateServerID(serverID) == nil && csrErr == nil
		if want != (err == nil) {
			t.Fatalf("BuildEnrollRequest = %v, validators say valid=%v", err, want)
		}
		if err != nil {
			if req != nil {
				t.Fatal("request returned with the error")
			}
			if len(token) >= 8 && strings.Contains(err.Error(), token) {
				t.Fatal("error echoes the token")
			}
			return
		}
		if req.GetFormatVersion() != 1 || req.GetToken() != token || req.GetServerId() != serverID ||
			!bytes.Equal(req.GetCsr(), csrDER) || !bytes.Equal(req.GetExecutorPublicKey(), binding.PublicKey[:]) ||
			!bytes.Equal(req.GetExecutorBindingMac(), binding.MAC[:]) {
			t.Fatal("request fields differ from the input")
		}
		if len(csrDER) > 0 {
			csrDER[0] ^= 0xff
			if bytes.Equal(req.GetCsr(), csrDER) {
				t.Fatal("request aliases the caller's CSR slice")
			}
			csrDER[0] ^= 0xff
		}
	})
}

func FuzzParseServerIDFile(f *testing.F) {
	for _, s := range []string{
		testServerID, "", testServerID + "\n", testServerID + "\r\n", " " + testServerID,
		"\ufeff" + testServerID, strings.ToUpper(testServerID), testServerID[:35], testServerID + "0",
		testServerID[:35] + "\x00",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseServerIDFile(data)
		want := len(data) == 36 && serverIDRe.Match(data)
		if want != (err == nil) {
			t.Fatalf("ParseServerIDFile(%q) = %v, want valid=%v", data, err, want)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidServerID) || got != "" {
				t.Fatalf("wrong error or value: %q, %v", got, err)
			}
			return
		}
		if got != string(data) {
			t.Fatalf("returned %q for %q", got, data)
		}
	})
}

// topLevelKeys returns the member names of a JSON object in order, with
// duplicates, or ok=false if data is not one object followed only by
// whitespace.
func topLevelKeys(data []byte) (keys []string, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		k, isStr := tok.(string)
		if !isStr {
			return nil, false
		}
		keys = append(keys, k)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, false
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return keys, true
}

func FuzzParseEndpoints(f *testing.F) {
	e, a, s := `"enroll_endpoint":"enroll.example.test:443"`, `"agent_endpoint":"agent.example.test:8443"`, `"server_name":"cp.example.test"`
	for _, seed := range []string{
		endpointsJSON, "{" + s + "," + a + "," + e + "}", "\n" + endpointsJSON + "\n", "", "null", "{}",
		"{" + e + "," + a + "}", "{" + e + "," + a + "," + s + "," + s + "}",
		"{" + e + "," + a + "," + s + `,"server_nam\u0065":"evil.example.test"}`,
		"{" + e + "," + a + `,"server_name":443}`, "{" + e + "," + a + `,"server_name":null}`,
		endpointsJSON + "x", endpointsJSON + endpointsJSON, "{" + e + "," + a + ",\"server_name\":\"cp\xff\"}",
		"\ufeff" + endpointsJSON, `{"enroll_endpoint":"[2001:db8::10]:443","agent_endpoint":"192.0.2.10:8443","server_name":"2001:db8::10"}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseEndpoints(data)
		if err != nil {
			if !errors.Is(err, ErrInvalidEndpoints) && !errors.Is(err, ErrInvalidServerName) {
				t.Fatalf("wrong error class: %v", err)
			}
			if got != (Endpoints{}) {
				t.Fatal("values returned with the error")
			}
			return
		}
		if !utf8.Valid(data) || !json.Valid(data) {
			t.Fatal("accepted invalid UTF-8 or invalid JSON")
		}
		keys, ok := topLevelKeys(data)
		if !ok || len(keys) != 3 {
			t.Fatalf("accepted something other than one object of three members: %q", keys)
		}
		seen := map[string]bool{}
		for _, k := range keys {
			seen[k] = true
		}
		if !seen["enroll_endpoint"] || !seen["agent_endpoint"] || !seen["server_name"] {
			t.Fatalf("accepted members %q", keys)
		}
		if ValidateEndpoint(got.Enroll) != nil || ValidateEndpoint(got.Agent) != nil || ValidateServerName(got.ServerName) != nil {
			t.Fatalf("accepted invalid values %+v", got)
		}
		again, err := json.Marshal(map[string]string{"enroll_endpoint": got.Enroll, "agent_endpoint": got.Agent, "server_name": got.ServerName})
		if err != nil {
			t.Fatal(err)
		}
		if got2, err := ParseEndpoints(again); err != nil || got2 != got {
			t.Fatalf("re-encoded endpoints do not round-trip: %v", err)
		}
	})
}

var endpointPortRe = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)

func FuzzValidateEndpoint(f *testing.F) {
	for _, s := range []string{
		"cp.example.test:443", "192.0.2.10:8443", "[2001:db8::10]:443", "cp:65535", "cp:65536", "cp:0",
		"cp:0443", "cp:+443", "", ":443", "cp:", "[::1]", "cp:443:1", "2001:db8::10:443",
		"[fe80::1%eth0]:443", "*.example.test:443", "cp.example.test.:443", "cp:443\n", "$(id):443",
		strings.Repeat("a", 250) + ":443",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateEndpoint(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidEndpoints) {
				t.Fatalf("wrong error class: %v", err)
			}
			return
		}
		if len(s) > 253 {
			t.Fatalf("accepted %d bytes", len(s))
		}
		host, port, perr := net.SplitHostPort(s)
		if perr != nil {
			t.Fatalf("accepted %q, which does not split: %v", s, perr)
		}
		if ValidateServerName(host) != nil {
			t.Fatalf("accepted host %q", host)
		}
		if strings.Contains(host, ":") && !strings.HasPrefix(s, "[") {
			t.Fatalf("accepted an unbracketed IPv6 literal %q", s)
		}
		n, cerr := strconv.Atoi(port)
		if !endpointPortRe.MatchString(port) || cerr != nil || n < 1 || n > 65535 {
			t.Fatalf("accepted port %q", port)
		}
	})
}

func FuzzParseAgentCA(f *testing.F) {
	ca := newCA(f, "agent CA", testNow)
	good := certPEM(ca.cert)
	leaf := ca.issue(f, agentLeafTemplate(f, testServerID, testNow), &newP256(f).PublicKey)
	for _, s := range [][]byte{
		good, {}, ca.cert.Raw, pemBlock(certBlockType, leaf, nil), cat(good, good), cat(good, []byte("\n")),
		good[:len(good)-1], bytes.ReplaceAll(good, []byte("\n"), []byte("\r\n")), cat([]byte("x\n"), good),
		pemBlock(certBlockType, ca.cert.Raw, map[string]string{"A": "b"}),
		pemBlock(certBlockType, append(bytes.Clone(ca.cert.Raw), 0), nil),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseAgentCA(data)
		if err != nil {
			if !errors.Is(err, ErrInvalidTrust) || c != nil {
				t.Fatalf("wrong error or value: %v", err)
			}
			return
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			t.Fatal("accepted a certificate that is not a CA")
		}
		if !bytes.Equal(data, certPEM(c)) {
			t.Fatal("accepted a file that is not the canonical encoding of its certificate")
		}
	})
}

func FuzzParseControlPlaneCAs(f *testing.F) {
	cas := sortedCAs(newCA(f, "cp CA A", testNow).cert, newCA(f, "cp CA B", testNow).cert, newCA(f, "cp CA C", testNow).cert)
	for _, s := range [][]byte{
		casPEM(cas[0]), casPEM(cas[0], cas[1]), casPEM(cas[1], cas[0]), casPEM(cas[0], cas[0]),
		casPEM(cas...), {}, cat(casPEM(cas[0]), []byte("\n"), casPEM(cas[1])),
		bytes.ReplaceAll(casPEM(cas[0], cas[1]), []byte("\n"), []byte("\r\n")),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseControlPlaneCAs(data)
		if err != nil {
			if !errors.Is(err, ErrInvalidTrust) || got != nil {
				t.Fatalf("wrong error or value: %v", err)
			}
			return
		}
		if len(got) < 1 || len(got) > 2 {
			t.Fatalf("accepted %d certificates", len(got))
		}
		var prev [32]byte
		for i, c := range got {
			if c == nil || !c.BasicConstraintsValid || !c.IsCA {
				t.Fatal("accepted a certificate that is not a CA")
			}
			h := sha256.Sum256(c.Raw)
			if i > 0 && bytes.Compare(prev[:], h[:]) >= 0 {
				t.Fatal("accepted certificates not strictly sorted by SHA-256")
			}
			prev = h
		}
		if !bytes.Equal(data, casPEM(got...)) {
			t.Fatal("accepted a file that is not the canonical encoding of its certificates")
		}
	})
}

// FuzzTrustedControlPlaneCAs checks the R10d filter against a direct
// restatement of design §C.
func FuzzTrustedControlPlaneCAs(f *testing.F) {
	pool := sortedCAs(newCA(f, "cp CA A", testNow).cert, newCA(f, "cp CA B", testNow).cert, newCA(f, "cp CA C", testNow).cert)
	now := testNow.Unix()
	// fileSel and entrySel pick certificates from pool: low two bits the
	// count, then two bits per index.
	f.Add(uint8(0b0001), uint8(0b0001), now-1, now+1, int64(0), int64(0), now)
	f.Add(uint8(0b010010), uint8(0b000110), now, now, now+1, now+2, now)
	f.Add(uint8(0b0001), uint8(0b0001), now+1, now+2, int64(0), int64(0), now)
	f.Add(uint8(0b0001), uint8(0b0010), now-1, now+1, now-1, now+1, now)
	f.Add(uint8(0b0001), uint8(0b0001), int64(0), now, int64(0), int64(0), now)
	f.Add(uint8(0b0001), uint8(0b0001), now, now-1, int64(0), int64(0), now)
	f.Add(uint8(0b0011), uint8(0b0011), int64(1), int64(math.MaxInt64), int64(1), int64(math.MaxInt64), int64(math.MinInt64))
	f.Fuzz(func(t *testing.T, fileSel, entrySel uint8, nb1, na1, nb2, na2, at int64) {
		pick := func(sel uint8) []*x509.Certificate {
			n := int(sel & 3)
			out := make([]*x509.Certificate, 0, n)
			for i := 0; i < n; i++ {
				out = append(out, pool[int(sel>>(2+2*i)&3)%len(pool)])
			}
			return out
		}
		file := pick(fileSel)
		var entries []CAEntry
		bounds := [][2]int64{{nb1, na1}, {nb2, na2}, {nb1, na2}}
		for i, c := range pick(entrySel) {
			entries = append(entries, CAEntry{Fingerprint: sha256.Sum256(c.Raw), NotBefore: bounds[i][0], NotAfter: bounds[i][1]})
		}
		got, err := TrustedControlPlaneCAs(file, entries, time.Unix(at, 0))

		validInput := len(file) >= 1 && len(file) <= 2 && len(entries) >= 1 && len(entries) <= 2
		seen := map[[32]byte]bool{}
		for _, e := range entries {
			if seen[e.Fingerprint] || e.NotBefore < 1 || e.NotBefore > e.NotAfter {
				validInput = false
			}
			seen[e.Fingerprint] = true
		}
		if !validInput {
			if !errors.Is(err, ErrInvalidTrust) || got != nil {
				t.Fatalf("invalid input accepted or wrong error: %d, %v", len(got), err)
			}
			return
		}
		var want []*x509.Certificate
		for _, c := range file {
			fp := sha256.Sum256(c.Raw)
			for _, e := range entries {
				if e.Fingerprint == fp && e.NotBefore <= at && at <= e.NotAfter {
					want = append(want, c)
					break
				}
			}
		}
		if len(want) == 0 {
			if !errors.Is(err, ErrNoTrustedControlPlaneCA) || got != nil {
				t.Fatalf("empty set: %d, %v; want ErrNoTrustedControlPlaneCA", len(got), err)
			}
			return
		}
		if err != nil || len(got) != len(want) {
			t.Fatalf("got %d, %v; want %d", len(got), err, len(want))
		}
		for i := range want {
			if got[i] != want[i] && !bytes.Equal(got[i].Raw, want[i].Raw) {
				t.Fatalf("certificate %d differs", i)
			}
		}
	})
}
