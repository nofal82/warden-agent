package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
)

func testBinding(t testing.TB) ExecutorBinding {
	t.Helper()
	b, err := NewExecutorBinding(bytesOf(ExecutorPublicKeySize, 0xa1), bytesOf(BindingMACSize, 0xb2))
	if err != nil {
		t.Fatalf("NewExecutorBinding: %v", err)
	}
	return b
}

func TestNewExecutorBinding(t *testing.T) {
	t.Parallel()
	good := bytesOf(32, 0x11)
	cases := []struct {
		name     string
		pub, mac []byte
		ok       bool
	}{
		{"32 and 32", good, bytesOf(32, 0x22), true},
		{"all zero 32 and 32", make([]byte, 32), make([]byte, 32), true},
		{"pub nil", nil, good, false},
		{"pub empty", []byte{}, good, false},
		{"pub 31", bytesOf(31, 1), good, false},
		{"pub 33", bytesOf(33, 1), good, false},
		{"pub 64", bytesOf(64, 1), good, false},
		{"mac nil", good, nil, false},
		{"mac empty", good, []byte{}, false},
		{"mac 31", good, bytesOf(31, 1), false},
		{"mac 33", good, bytesOf(33, 1), false},
		{"mac 64", good, bytesOf(64, 1), false},
		{"both nil", nil, nil, false},
		{"swapped sizes 31 33", bytesOf(31, 1), bytesOf(33, 1), false},
		{"1 MiB", bytesOf(1<<20, 1), good, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, err := NewExecutorBinding(tc.pub, tc.mac)
			if !tc.ok {
				if !errors.Is(err, ErrInvalidBinding) {
					t.Fatalf("NewExecutorBinding = %v, want ErrInvalidBinding", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewExecutorBinding: %v", err)
			}
			if !bytes.Equal(b.PublicKey[:], tc.pub) || !bytes.Equal(b.MAC[:], tc.mac) {
				t.Fatal("binding does not hold the given values")
			}
		})
	}
}

func TestNewExecutorBindingCopiesInput(t *testing.T) {
	t.Parallel()
	pub, mac := bytesOf(32, 0x33), bytesOf(32, 0x44)
	b, err := NewExecutorBinding(pub, mac)
	if err != nil {
		t.Fatalf("NewExecutorBinding: %v", err)
	}
	pub[0], mac[31] = 0, 0
	if b.PublicKey[0] != 0x33 || b.MAC[31] != 0x44 {
		t.Fatal("binding aliases the caller's slices")
	}
}

func TestBuildEnrollRequestFields(t *testing.T) {
	t.Parallel()
	key := newP256(t)
	csr := mustCSR(t, key)
	b := testBinding(t)
	req, err := BuildEnrollRequest(canaryToken(), testServerID, csr, b)
	if err != nil {
		t.Fatalf("BuildEnrollRequest: %v", err)
	}
	if req.GetFormatVersion() != 1 {
		t.Errorf("format_version = %d, want 1", req.GetFormatVersion())
	}
	if req.GetToken() != canaryToken() {
		t.Error("token not exactly as given")
	}
	if req.GetServerId() != testServerID {
		t.Errorf("server_id = %q", req.GetServerId())
	}
	if !bytes.Equal(req.GetCsr(), csr) {
		t.Error("csr not exactly as given")
	}
	if !bytes.Equal(req.GetExecutorPublicKey(), b.PublicKey[:]) {
		t.Error("executor_public_key not exactly as given")
	}
	if !bytes.Equal(req.GetExecutorBindingMac(), b.MAC[:]) {
		t.Error("executor_binding_mac not exactly as given")
	}
	// The private key never appears in the request (R12, AC35).
	wire, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, raw) || bytes.Contains(wire, pkcs8(t, key)[:40]) {
		t.Fatal("request bytes contain the private key")
	}
	var back agentapiv1.EnrollRequest
	if err := agentapiv1.StrictUnmarshal(wire, &back); err != nil {
		t.Fatalf("strict decode of the built request: %v", err)
	}
	if !proto.Equal(req, &back) {
		t.Fatal("strict round trip changed the request")
	}
}

func TestBuildEnrollRequestMaxSizes(t *testing.T) {
	t.Parallel()
	key := newP256(t)
	csr := csrOfSize(t, key, MaxCSRBytes)
	req, err := BuildEnrollRequest(canaryToken(), testServerID, csr, testBinding(t))
	if err != nil {
		t.Fatalf("BuildEnrollRequest with a %d-byte CSR: %v", len(csr), err)
	}
	if n := proto.Size(req); n > 8192 {
		t.Fatalf("request is %d bytes, over the 8 KiB limit", n)
	}
	wire, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(wire) > 8192 {
		t.Fatalf("marshalled request is %d bytes", len(wire))
	}
}

func TestBuildEnrollRequestRefusals(t *testing.T) {
	t.Parallel()
	key := newP256(t)
	csr := mustCSR(t, key)

	flipped := bytes.Clone(csr)
	flipped[len(flipped)-1] ^= 0x01 // last byte of the ECDSA signature

	tbsFlipped := csrWithAlteredInfo(t, csr)

	rsaCSR := mustCSR(t, rsaKey(t))
	p384CSR := mustCSR(t, newP384(t))
	edCSR := mustCSR(t, newEd25519(t))
	over := csrOfSize(t, key, MaxCSRBytes+1)

	cases := []struct {
		name     string
		token    string
		serverID string
		csr      []byte
		want     error
	}{
		{"bad token empty", "", testServerID, csr, ErrInvalidToken},
		{"bad token 49", canaryToken() + "Q", testServerID, csr, ErrInvalidToken},
		{"bad token padding", canaryToken()[:47] + "=", testServerID, csr, ErrInvalidToken},
		{"bad token wdn2", "wdn2" + canaryToken()[4:], testServerID, csr, ErrInvalidToken},
		{"server ID as token", testServerID, testServerID, csr, ErrInvalidToken},
		{"bad server ID empty", canaryToken(), "", csr, ErrInvalidServerID},
		{"bad server ID upper", canaryToken(), strings.ToUpper(testServerID), csr, ErrInvalidServerID},
		{"bad server ID v7", canaryToken(), "01920f3e-7c4a-7b2d-8e5f-0a1b2c3d4e5f", csr, ErrInvalidServerID},
		{"bad server ID newline", canaryToken(), testServerID + "\n", csr, ErrInvalidServerID},
		{"token as server ID", canaryToken(), canaryToken(), csr, ErrInvalidServerID},
		{"csr nil", canaryToken(), testServerID, nil, ErrInvalidCSR},
		{"csr empty", canaryToken(), testServerID, []byte{}, ErrInvalidCSR},
		{"csr garbage", canaryToken(), testServerID, []byte("not a certificate request"), ErrInvalidCSR},
		{"csr 4097 bytes zero", canaryToken(), testServerID, make([]byte, MaxCSRBytes+1), ErrInvalidCSR},
		{"csr valid but 4097 bytes", canaryToken(), testServerID, over, ErrInvalidCSR},
		{"csr trailing byte", canaryToken(), testServerID, append(bytes.Clone(csr), 0), ErrInvalidCSR},
		{"csr truncated", canaryToken(), testServerID, csr[:len(csr)-1], ErrInvalidCSR},
		{"csr bad signature", canaryToken(), testServerID, flipped, ErrInvalidCSR},
		{"csr altered info", canaryToken(), testServerID, tbsFlipped, ErrInvalidCSR},
		{"csr RSA", canaryToken(), testServerID, rsaCSR, ErrInvalidCSR},
		{"csr P-384", canaryToken(), testServerID, p384CSR, ErrInvalidCSR},
		{"csr Ed25519", canaryToken(), testServerID, edCSR, ErrInvalidCSR},
		{"csr is a certificate", canaryToken(), testServerID, newCA(t, "x", testNow).cert.Raw, ErrInvalidCSR},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := BuildEnrollRequest(tc.token, tc.serverID, tc.csr, testBinding(t))
			if req != nil {
				t.Error("a request was returned with the error")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("BuildEnrollRequest = %v, want %v", err, tc.want)
			}
			// R20: the token text never appears in an error.
			assertNoLeak(t, err.Error(), nil, canaryToken(), canaryToken()[5:], strings.Repeat("Q", 16))
		})
	}
}

func TestBuildEnrollRequestAcceptsCSRAt4096(t *testing.T) {
	t.Parallel()
	csr := csrOfSize(t, newP256(t), MaxCSRBytes)
	if _, err := BuildEnrollRequest(canaryToken(), testServerID, csr, testBinding(t)); err != nil {
		t.Fatalf("a valid %d-byte CSR was refused: %v", len(csr), err)
	}
}

// csrWithAlteredInfo flips one byte inside the signed CertificationRequestInfo
// of a CSR carrying a DNS name, so the DER still parses but the signature no
// longer covers what is there.
func csrWithAlteredInfo(t testing.TB, _ []byte) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"aaaaaaaaaaaaaaaa.example"},
	}, newP256(t))
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(der, []byte("aaaaaaaaaaaaaaaa"))
	if i < 0 {
		t.Fatal("marker not found")
	}
	der = bytes.Clone(der)
	der[i] = 'b'
	if _, err := x509.ParseCertificateRequest(der); err != nil {
		t.Fatalf("altered CSR no longer parses: %v", err)
	}
	return der
}
