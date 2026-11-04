//go:build linux

package identity

// Tests for the /etc/warden-agent trust files (R5, R10e, §4.1, §4.3, §4.7)
// and the trusted control-plane CA set (R10d; signing-and-updates R37,
// §4.4, §5.4). loadTrustFiles is exercised on a temporary tree owned by the
// test user, like readOwnedFile in files_test.go.

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseServerIDFile(t *testing.T) {
	t.Parallel()
	got, err := ParseServerIDFile([]byte(testServerID))
	if err != nil || got != testServerID {
		t.Fatalf("ParseServerIDFile(valid) = %q, %v", got, err)
	}
	for name, data := range map[string]string{
		"empty":            "",
		"trailing newline": testServerID + "\n",
		"CRLF":             testServerID + "\r\n",
		"leading space":    " " + testServerID,
		"BOM":              "\ufeff" + testServerID,
		"uppercase":        strings.ToUpper(testServerID),
		"35 bytes":         testServerID[:35],
		"37 bytes":         testServerID + "0",
		"NUL":              testServerID[:35] + "\x00",
		"braces":           "{" + testServerID + "}",
		"UUID v7":          "01920f3e-7c4a-7b2d-8e5f-0a1b2c3d4e5f",
		"two IDs":          testServerID + otherServerID,
	} {
		if got, err := ParseServerIDFile([]byte(data)); !errors.Is(err, ErrInvalidServerID) || got != "" {
			t.Errorf("%s: ParseServerIDFile = %q, %v; want ErrInvalidServerID", name, got, err)
		}
	}
}

func TestParseEndpoints(t *testing.T) {
	t.Parallel()
	want := Endpoints{Enroll: "enroll.example.test:443", Agent: "agent.example.test:8443", ServerName: "cp.example.test"}
	for name, data := range map[string]string{
		"compact":            endpointsJSON,
		"other member order": `{"server_name":"cp.example.test","agent_endpoint":"agent.example.test:8443","enroll_endpoint":"enroll.example.test:443"}`,
		"whitespace around":  "\n  " + endpointsJSON + "\n",
	} {
		got, err := ParseEndpoints([]byte(data))
		if err != nil || got != want {
			t.Errorf("%s: ParseEndpoints = %+v, %v", name, got, err)
		}
	}
	ip := `{"enroll_endpoint":"[2001:db8::10]:443","agent_endpoint":"192.0.2.10:8443","server_name":"2001:db8::10"}`
	if got, err := ParseEndpoints([]byte(ip)); err != nil || got.Enroll != "[2001:db8::10]:443" || got.ServerName != "2001:db8::10" {
		t.Errorf("IP literals: %+v, %v", got, err)
	}

	e, a, s := `"enroll_endpoint":"enroll.example.test:443"`, `"agent_endpoint":"agent.example.test:8443"`, `"server_name":"cp.example.test"`
	obj := func(members ...string) string { return "{" + strings.Join(members, ",") + "}" }
	for name, data := range map[string]string{
		"empty":                      "",
		"whitespace only":            " \n",
		"null":                       "null",
		"array":                      "[" + endpointsJSON + "]",
		"string":                     `"` + endpointsJSON + `"`,
		"empty object":               "{}",
		"missing enroll_endpoint":    obj(a, s),
		"missing agent_endpoint":     obj(e, s),
		"missing server_name":        obj(e, a),
		"unknown member":             obj(e, a, s, `"extra":"x"`),
		"case-changed member":        obj(`"Enroll_endpoint":"enroll.example.test:443"`, a, s),
		"duplicate member":           obj(e, a, s, s),
		"duplicate with other value": obj(e, a, s, `"server_name":"evil.example.test"`),
		"duplicate via escape":       obj(e, a, s, `"server_nam\u0065":"evil.example.test"`),
		"number value":               obj(e, a, `"server_name":443`),
		"null value":                 obj(e, a, `"server_name":null`),
		"bool value":                 obj(e, a, `"server_name":true`),
		"nested object":              obj(e, a, `"server_name":{"x":"cp.example.test"}`),
		"array value":                obj(e, a, `"server_name":["cp.example.test"]`),
		"trailing data":              endpointsJSON + "x",
		"trailing comma":             strings.TrimSuffix(endpointsJSON, "}") + ",}",
		"second JSON value":          endpointsJSON + endpointsJSON,
		"second value after space":   endpointsJSON + " {}",
		"truncated":                  endpointsJSON[:len(endpointsJSON)-1],
		"invalid UTF-8 in value":     obj(e, a, "\"server_name\":\"cp.example.test\xff\""),
		"invalid UTF-8 in key":       obj(e, a, s, "\"\xff\":\"x\""),
		"BOM":                        "\ufeff" + endpointsJSON,
		"NUL escape in value":        obj(e, a, `"server_name":"cp.example.test\u0000"`),
		"wildcard server_name":       obj(e, a, `"server_name":"*.example.test"`),
		"server_name with port":      obj(e, a, `"server_name":"cp.example.test:443"`),
		"empty server_name":          obj(e, a, `"server_name":""`),
		"enroll without port":        obj(`"enroll_endpoint":"enroll.example.test"`, a, s),
		"agent URL":                  obj(e, `"agent_endpoint":"https://agent.example.test:8443"`, s),
		"comment":                    "/* x */" + endpointsJSON,
	} {
		got, err := ParseEndpoints([]byte(data))
		if !errors.Is(err, ErrInvalidEndpoints) && !errors.Is(err, ErrInvalidServerName) {
			t.Errorf("%s: ParseEndpoints = %+v, %v; want ErrInvalidEndpoints", name, got, err)
		}
		if got != (Endpoints{}) {
			t.Errorf("%s: values returned with the error: %+v", name, got)
		}
	}
}

func TestValidateEndpoint(t *testing.T) {
	t.Parallel()
	maxHost := dnsNameOfLen(253 - len(":443"))
	for _, s := range []string{
		"cp.example.test:443", "localhost:1", "cp:65535", "192.0.2.10:8443",
		"[2001:db8::10]:443", "[::1]:443", maxHost + ":443",
	} {
		if err := ValidateEndpoint(s); err != nil {
			t.Errorf("ValidateEndpoint(%q) = %v", short(s), err)
		}
	}
	for _, s := range []string{
		"", ":", "cp.example.test", "cp.example.test:", ":443", "[::1]", "[]:443",
		"cp.example.test:443:1", "2001:db8::10:443", "[fe80::1%eth0]:443",
		"cp:0", "cp:00", "cp:0443", "cp:+443", "cp:-1", "cp:65536", "cp:99999", "cp:123456",
		"cp:0x1bb", "cp:44 3", "cp: 443", " cp:443", "cp:443 ", "cp:443\n", "cp\x00:443",
		"cp:\uff14\uff14\uff13", "*.example.test:443", "cp.example.test.:443", "-cp:443",
		"cp_1:443", "https://cp.example.test:443", "cp.example.test:443/path",
		"user@cp.example.test:443", "cp;id:443", "$(id):443", "`id`:443", "--config=/tmp/x:443",
		maxHost + "a:443", dnsNameOfLen(254) + ":443", strings.Repeat("a", 10<<10) + ":443",
	} {
		if err := ValidateEndpoint(s); !errors.Is(err, ErrInvalidEndpoints) {
			t.Errorf("ValidateEndpoint(%q) = %v, want ErrInvalidEndpoints", short(s), err)
		}
	}
}

func TestParseAgentCA(t *testing.T) {
	t.Parallel()
	ca := newCA(t, "agent CA", testNow)
	got, err := ParseAgentCA(certPEM(ca.cert))
	if err != nil || got == nil || !bytes.Equal(got.Raw, ca.cert.Raw) {
		t.Fatalf("ParseAgentCA(valid) = %v", err)
	}
	for name, data := range caFileAttacks(t, ca) {
		if got, err := ParseAgentCA(data); !errors.Is(err, ErrInvalidTrust) || got != nil {
			t.Errorf("%s: ParseAgentCA = %v; want ErrInvalidTrust", name, err)
		}
	}
	other := newCA(t, "other", testNow)
	if _, err := ParseAgentCA(casPEM(sortedCAs(ca.cert, other.cert)...)); !errors.Is(err, ErrInvalidTrust) {
		t.Errorf("two blocks in agent-ca.pem: %v, want ErrInvalidTrust", err)
	}
}

// caFileAttacks returns non-canonical or non-CA encodings of ca that both
// CA parsers refuse.
func caFileAttacks(t *testing.T, ca *testCA) map[string][]byte {
	t.Helper()
	good := certPEM(ca.cert)
	leaf := mustParse(t, ca.issue(t, agentLeafTemplate(t, testServerID, testNow), &newP256(t).PublicKey))
	notCATmpl := caTemplate(t, "not CA", testNow)
	notCATmpl.IsCA = false
	notCA := newCAFrom(t, notCATmpl, nil).cert
	noBC := caTemplate(t, "no basic constraints", testNow)
	noBC.BasicConstraintsValid, noBC.IsCA = false, false
	noBCCert := newCAFrom(t, noBC, nil).cert
	// Base64 lines re-wrapped at 76 instead of 64 characters.
	lines := strings.Split(strings.TrimSpace(string(good)), "\n")
	body := strings.Join(lines[1:len(lines)-1], "")
	var wrapped strings.Builder
	wrapped.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(body) > 76 {
		wrapped.WriteString(body[:76] + "\n")
		body = body[76:]
	}
	wrapped.WriteString(body + "\n-----END CERTIFICATE-----\n")
	return map[string][]byte{
		"empty":                 {},
		"DER not PEM":           ca.cert.Raw,
		"leaf certificate":      certPEM(leaf),
		"CA:false":              certPEM(notCA),
		"no basic constraints":  certPEM(noBCCert),
		"PEM header":            pemBlock(certBlockType, ca.cert.Raw, map[string]string{"Proc-Type": "4,ENCRYPTED"}),
		"text before":           cat([]byte("agent CA\n"), good),
		"extra final newline":   cat(good, []byte("\n")),
		"missing final newline": good[:len(good)-1],
		"trailing space":        cat(good, []byte(" ")),
		"CRLF":                  bytes.ReplaceAll(good, []byte("\n"), []byte("\r\n")),
		"wrong block type":      pemBlock("TRUSTED CERTIFICATE", ca.cert.Raw, nil),
		"X509 CRL block":        pemBlock("X509 CRL", ca.cert.Raw, nil),
		"garbage DER":           pemBlock(certBlockType, []byte("not a certificate"), nil),
		"DER trailing byte":     pemBlock(certBlockType, append(bytes.Clone(ca.cert.Raw), 0), nil),
		"truncated DER":         pemBlock(certBlockType, ca.cert.Raw[:len(ca.cert.Raw)-1], nil),
		"76-column base64":      []byte(wrapped.String()),
		"truncated PEM":         good[:len(good)/2],
	}
}

func TestParseControlPlaneCAs(t *testing.T) {
	t.Parallel()
	a := newCA(t, "cp CA A", testNow)
	b := newCA(t, "cp CA B", testNow)
	c := newCA(t, "cp CA C", testNow)
	two := sortedCAs(a.cert, b.cert)

	for name, in := range map[string][]*x509.Certificate{"one": {a.cert}, "two sorted": two} {
		got, err := ParseControlPlaneCAs(casPEM(in...))
		if err != nil || len(got) != len(in) {
			t.Fatalf("%s: ParseControlPlaneCAs = %d, %v", name, len(got), err)
		}
		for i := range in {
			if !bytes.Equal(got[i].Raw, in[i].Raw) {
				t.Errorf("%s: certificate %d is not the file's, in file order", name, i)
			}
		}
	}

	refused := caFileAttacks(t, a)
	refused["unsorted"] = casPEM(two[1], two[0])
	refused["duplicate"] = casPEM(a.cert, a.cert)
	refused["three"] = casPEM(sortedCAs(a.cert, b.cert, c.cert)...)
	refused["blank line between"] = cat(certPEM(two[0]), []byte("\n"), certPEM(two[1]))
	refused["text between"] = cat(certPEM(two[0]), []byte("x\n"), certPEM(two[1]))
	refused["second is a leaf"] = cat(certPEM(a.cert), certPEM(mustParse(t, a.issue(t, agentLeafTemplate(t, testServerID, testNow), &newP256(t).PublicKey))))
	refused["second has a header"] = cat(certPEM(two[0]), pemBlock(certBlockType, two[1].Raw, map[string]string{"A": "b"}))
	// The same CA key reissued: different DER, so distinct and allowed only
	// in hash order; reversed it is refused.
	re := sortedCAs(a.cert, a.reissueSelf(t))
	if _, err := ParseControlPlaneCAs(casPEM(re...)); err != nil {
		t.Errorf("same key, two certificates, sorted: %v", err)
	}
	refused["reissued CA unsorted"] = casPEM(re[1], re[0])
	for name, data := range refused {
		got, err := ParseControlPlaneCAs(data)
		if !errors.Is(err, ErrInvalidTrust) || got != nil {
			t.Errorf("%s: ParseControlPlaneCAs = %d certs, %v; want ErrInvalidTrust", name, len(got), err)
		}
		assertNoLeak(t, errText(err), data)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// trustFixture is a valid /etc/warden-agent tree at start/etc/warden-agent.
type trustFixture struct {
	start, rel, dir string
	agentCA         *testCA
	cpCAs           []*x509.Certificate
}

func newTrustFixture(t *testing.T) *trustFixture {
	t.Helper()
	start := t.TempDir()
	mustChmod(t, start, 0o755)
	dir := filepath.Join(start, "etc", "warden-agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, filepath.Join(start, "etc"), 0o755)
	mustChmod(t, dir, 0o755)
	f := &trustFixture{
		start: start, rel: "etc/warden-agent", dir: dir,
		agentCA: newCA(t, "agent CA", testNow),
		cpCAs:   sortedCAs(newCA(t, "cp CA A", testNow).cert, newCA(t, "cp CA B", testNow).cert),
	}
	f.put(t, FileServerID, []byte(testServerID))
	f.put(t, FileEndpoints, []byte(endpointsJSON))
	f.put(t, FileAgentCA, certPEM(f.agentCA.cert))
	f.put(t, FileControlPlaneCA, casPEM(f.cpCAs...))
	return f
}

func (f *trustFixture) put(t *testing.T, name string, data []byte) {
	t.Helper()
	p := filepath.Join(f.dir, name)
	_ = os.Remove(p)
	writeMode(t, p, data, rootFileMode)
}

func (f *trustFixture) load() (TrustFiles, error) {
	return loadTrustFiles(f.start, f.rel, os.Getuid())
}

func TestLoadTrustFilesAccepts(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t)
	got, err := f.load()
	if err != nil {
		t.Fatalf("loadTrustFiles: %v", err)
	}
	if got.ServerID != testServerID {
		t.Errorf("ServerID = %q", got.ServerID)
	}
	if got.Endpoints != (Endpoints{Enroll: "enroll.example.test:443", Agent: "agent.example.test:8443", ServerName: "cp.example.test"}) {
		t.Errorf("Endpoints = %+v", got.Endpoints)
	}
	if got.AgentCA == nil || !bytes.Equal(got.AgentCA.Raw, f.agentCA.cert.Raw) {
		t.Error("AgentCA is not agent-ca.pem")
	}
	// Not filtered by the keyset here (R10d is TrustedControlPlaneCAs).
	if len(got.ControlPlaneCAs) != 2 || !bytes.Equal(got.ControlPlaneCAs[0].Raw, f.cpCAs[0].Raw) || !bytes.Equal(got.ControlPlaneCAs[1].Raw, f.cpCAs[1].Raw) {
		t.Error("ControlPlaneCAs is not the file's certificates in file order")
	}
	// endpoints.json padded with whitespace to exactly its 4096-byte limit.
	f.put(t, FileEndpoints, []byte(endpointsJSON+strings.Repeat(" ", 4096-len(endpointsJSON))))
	if _, err := f.load(); err != nil {
		t.Fatalf("endpoints.json of exactly 4096 bytes: %v", err)
	}
}

// Every R10e and content failure gives an error and nothing else.
func TestLoadTrustFilesRefuses(t *testing.T) {
	t.Parallel()
	uid := os.Getuid()
	marker := "leakmarker" + "zq"
	cases := []struct {
		name  string
		setup func(t *testing.T, f *trustFixture) int // returns the owner to require
		want  error
	}{
		{"server-id missing", func(t *testing.T, f *trustFixture) int {
			_ = os.Remove(filepath.Join(f.dir, FileServerID))
			return uid
		}, fs.ErrNotExist},
		{"endpoints.json missing", func(t *testing.T, f *trustFixture) int {
			_ = os.Remove(filepath.Join(f.dir, FileEndpoints))
			return uid
		}, fs.ErrNotExist},
		{"agent-ca.pem missing", func(t *testing.T, f *trustFixture) int {
			_ = os.Remove(filepath.Join(f.dir, FileAgentCA))
			return uid
		}, fs.ErrNotExist},
		{"controlplane-ca.pem missing", func(t *testing.T, f *trustFixture) int {
			_ = os.Remove(filepath.Join(f.dir, FileControlPlaneCA))
			return uid
		}, fs.ErrNotExist},
		{"server-id is a symlink", func(t *testing.T, f *trustFixture) int {
			real := filepath.Join(f.start, "real-server-id")
			writeMode(t, real, []byte(testServerID), rootFileMode)
			_ = os.Remove(filepath.Join(f.dir, FileServerID))
			if err := os.Symlink(real, filepath.Join(f.dir, FileServerID)); err != nil {
				t.Fatal(err)
			}
			return uid
		}, ErrUnsafeFile},
		{"controlplane-ca.pem symlink to an attacker CA", func(t *testing.T, f *trustFixture) int {
			evil := filepath.Join(t.TempDir(), "evil.pem")
			writeMode(t, evil, certPEM(newCA(t, "evil", testNow).cert), rootFileMode)
			_ = os.Remove(filepath.Join(f.dir, FileControlPlaneCA))
			if err := os.Symlink(evil, filepath.Join(f.dir, FileControlPlaneCA)); err != nil {
				t.Fatal(err)
			}
			return uid
		}, ErrUnsafeFile},
		{"warden-agent dir is a symlink", func(t *testing.T, f *trustFixture) int {
			moved := filepath.Join(f.start, "etc", "real")
			if err := os.Rename(f.dir, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, f.dir); err != nil {
				t.Fatal(err)
			}
			return uid
		}, ErrUnsafeFile},
		{"agent-ca.pem group-writable", func(t *testing.T, f *trustFixture) int {
			mustChmod(t, filepath.Join(f.dir, FileAgentCA), 0o664)
			return uid
		}, ErrUnsafeFile},
		{"endpoints.json other-writable", func(t *testing.T, f *trustFixture) int {
			mustChmod(t, filepath.Join(f.dir, FileEndpoints), 0o646)
			return uid
		}, ErrUnsafeFile},
		{"warden-agent dir group-writable", func(t *testing.T, f *trustFixture) int {
			mustChmod(t, f.dir, 0o775)
			return uid
		}, ErrUnsafeFile},
		{"parent dir other-writable", func(t *testing.T, f *trustFixture) int {
			mustChmod(t, filepath.Join(f.start, "etc"), 0o757)
			return uid
		}, ErrUnsafeFile},
		{"agent-ca.pem hard-linked", func(t *testing.T, f *trustFixture) int {
			if err := os.Link(filepath.Join(f.dir, FileAgentCA), filepath.Join(f.start, "agent-ca-link")); err != nil {
				t.Skipf("cannot create a hard link here: %v", err)
			}
			return uid
		}, ErrUnsafeFile},
		{"server-id is a FIFO", func(t *testing.T, f *trustFixture) int {
			p := filepath.Join(f.dir, FileServerID)
			_ = os.Remove(p)
			mkfifo(t, p)
			mustChmod(t, p, rootFileMode)
			return uid
		}, ErrUnsafeFile},
		{"not owned by the required owner", func(t *testing.T, f *trustFixture) int { return uid + 1 }, ErrUnsafeFile},
		{"required owner root, files ours", func(t *testing.T, f *trustFixture) int {
			if os.Geteuid() == 0 {
				t.Skip("running as root: our files are root's")
			}
			return 0
		}, ErrUnsafeFile},
		{"endpoints.json over 4096 bytes", func(t *testing.T, f *trustFixture) int {
			f.put(t, FileEndpoints, []byte(endpointsJSON+strings.Repeat(" ", 4097-len(endpointsJSON))))
			return uid
		}, ErrFileTooLarge},
		{"agent-ca.pem over 8192 bytes", func(t *testing.T, f *trustFixture) int {
			f.put(t, FileAgentCA, bytes.Repeat([]byte("A"), 8193))
			return uid
		}, ErrFileTooLarge},
		{"controlplane-ca.pem over 16384 bytes", func(t *testing.T, f *trustFixture) int {
			f.put(t, FileControlPlaneCA, bytes.Repeat([]byte("A"), 16385))
			return uid
		}, ErrFileTooLarge},
		{"server-id with newline", func(t *testing.T, f *trustFixture) int {
			f.put(t, FileServerID, []byte(testServerID+"\n"))
			return uid
		}, nil}, // over its 36-byte limit or invalid: either class is fine
		{"server-id uppercase", func(t *testing.T, f *trustFixture) int {
			f.put(t, FileServerID, []byte(strings.ToUpper(testServerID)))
			return uid
		}, ErrInvalidServerID},
		{"endpoints.json with an unknown member", func(t *testing.T, f *trustFixture) int {
			f.put(t, FileEndpoints, []byte(strings.TrimSuffix(endpointsJSON, "}")+`,"`+marker+`":"x"}`))
			return uid
		}, ErrInvalidEndpoints},
		{"endpoints.json with a bad server_name", func(t *testing.T, f *trustFixture) int {
			f.put(t, FileEndpoints, []byte(strings.Replace(endpointsJSON, "cp.example.test", marker+"_x.test", 1)))
			return uid
		}, nil},
		{"agent-ca.pem is a leaf", func(t *testing.T, f *trustFixture) int {
			leaf := f.agentCA.issue(t, agentLeafTemplate(t, testServerID, testNow), &newP256(t).PublicKey)
			f.put(t, FileAgentCA, pemBlock(certBlockType, leaf, nil))
			return uid
		}, ErrInvalidTrust},
		{"controlplane-ca.pem unsorted", func(t *testing.T, f *trustFixture) int {
			f.put(t, FileControlPlaneCA, casPEM(f.cpCAs[1], f.cpCAs[0]))
			return uid
		}, ErrInvalidTrust},
		{"controlplane-ca.pem empty", func(t *testing.T, f *trustFixture) int {
			f.put(t, FileControlPlaneCA, nil)
			return uid
		}, ErrInvalidTrust},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newTrustFixture(t)
			owner := tc.setup(t, f)
			var got TrustFiles
			err := noBlock(t, filepath.Join(f.dir, FileServerID), func() error {
				var err error
				got, err = loadTrustFiles(f.start, f.rel, owner)
				return err
			})
			if err == nil {
				t.Fatal("loadTrustFiles accepted")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("loadTrustFiles = %v, want %v", err, tc.want)
			}
			if got.ServerID != "" || got.Endpoints != (Endpoints{}) || got.AgentCA != nil || got.ControlPlaneCAs != nil {
				t.Error("values returned with the error")
			}
			// Paths are fine in the error; file contents are not.
			if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), testServerID) {
				t.Errorf("error carries file contents: %q", err)
			}
		})
	}
}

// LoadTrustFiles reads the real /etc/warden-agent. On a development
// machine it is absent (or not root-owned), so it must fail closed.
func TestLoadTrustFilesRealPath(t *testing.T) {
	t.Parallel()
	if _, err := os.Lstat(ConfigDir); err == nil {
		t.Skip("this machine has a real " + ConfigDir)
	}
	if got, err := LoadTrustFiles(); err == nil || got.AgentCA != nil {
		t.Fatalf("LoadTrustFiles without %s = %v", ConfigDir, err)
	}
}

func TestTrustedControlPlaneCAs(t *testing.T) {
	t.Parallel()
	cas := sortedCAs(newCA(t, "cp CA A", testNow).cert, newCA(t, "cp CA B", testNow).cert)
	a, b := cas[0], cas[1]
	notInKeyset := newCA(t, "cp CA C", testNow).cert
	now := testNow.Unix()
	entry := func(c *x509.Certificate, nb, na int64) CAEntry {
		return CAEntry{Fingerprint: fingerprint(c), NotBefore: nb, NotAfter: na}
	}
	nb, na := now-3600, now+3600
	cases := []struct {
		name    string
		file    []*x509.Certificate
		entries []CAEntry
		at      time.Time
		want    []*x509.Certificate // nil with wantErr
		wantErr error
	}{
		{"one CA, one entry", []*x509.Certificate{a}, []CAEntry{entry(a, nb, na)}, testNow, []*x509.Certificate{a}, nil},
		{"exactly at NotBefore", []*x509.Certificate{a}, []CAEntry{entry(a, now, na)}, testNow, []*x509.Certificate{a}, nil},
		{"one second before NotBefore", []*x509.Certificate{a}, []CAEntry{entry(a, now+1, na)}, testNow, nil, ErrNoTrustedControlPlaneCA},
		{"exactly at NotAfter", []*x509.Certificate{a}, []CAEntry{entry(a, nb, now)}, testNow, []*x509.Certificate{a}, nil},
		{"inside the NotAfter second", []*x509.Certificate{a}, []CAEntry{entry(a, nb, now)}, testNow.Add(999 * time.Millisecond), []*x509.Certificate{a}, nil},
		{"one second after NotAfter", []*x509.Certificate{a}, []CAEntry{entry(a, nb, now-1)}, testNow, nil, ErrNoTrustedControlPlaneCA},
		{"NotBefore equals NotAfter", []*x509.Certificate{a}, []CAEntry{entry(a, now, now)}, testNow, []*x509.Certificate{a}, nil},
		{"NotAfter max int64", []*x509.Certificate{a}, []CAEntry{entry(a, 1, math.MaxInt64)}, testNow, []*x509.Certificate{a}, nil},
		{"rotation: both trusted", []*x509.Certificate{a, b}, []CAEntry{entry(b, nb, na), entry(a, nb, na)}, testNow, []*x509.Certificate{a, b}, nil},
		{"old CA removed from keyset", []*x509.Certificate{a, b}, []CAEntry{entry(b, nb, na)}, testNow, []*x509.Certificate{b}, nil},
		{"old CA entry expired", []*x509.Certificate{a, b}, []CAEntry{entry(a, nb, now-1), entry(b, nb, na)}, testNow, []*x509.Certificate{b}, nil},
		{"new CA entry not yet valid", []*x509.Certificate{a, b}, []CAEntry{entry(a, nb, na), entry(b, now+1, na)}, testNow, []*x509.Certificate{a}, nil},
		{"file CA not in keyset", []*x509.Certificate{notInKeyset}, []CAEntry{entry(a, nb, na)}, testNow, nil, ErrNoTrustedControlPlaneCA},
		{"one of two file CAs not in keyset", sortedCAs(a, notInKeyset), []CAEntry{entry(a, nb, na), entry(b, nb, na)}, testNow, []*x509.Certificate{a}, nil},
		{"all entries expired", []*x509.Certificate{a, b}, []CAEntry{entry(a, nb, now-1), entry(b, nb, now-1)}, testNow, nil, ErrNoTrustedControlPlaneCA},
		{"no entries", []*x509.Certificate{a}, nil, testNow, nil, ErrInvalidTrust},
		{"three entries", []*x509.Certificate{a}, []CAEntry{entry(a, nb, na), entry(b, nb, na), entry(notInKeyset, nb, na)}, testNow, nil, ErrInvalidTrust},
		{"duplicate entries", []*x509.Certificate{a}, []CAEntry{entry(a, nb, na), entry(a, nb, na)}, testNow, nil, ErrInvalidTrust},
		{"duplicate fingerprint, other bounds", []*x509.Certificate{a}, []CAEntry{entry(a, nb, now-1), entry(a, nb, na)}, testNow, nil, ErrInvalidTrust},
		{"inverted validity", []*x509.Certificate{a}, []CAEntry{entry(a, na, nb)}, testNow, nil, ErrInvalidTrust},
		{"NotBefore 0", []*x509.Certificate{a}, []CAEntry{entry(a, 0, na)}, testNow, nil, ErrInvalidTrust},
		{"NotBefore negative", []*x509.Certificate{a}, []CAEntry{entry(a, -1, na)}, testNow, nil, ErrInvalidTrust},
		{"zero entry", []*x509.Certificate{a}, []CAEntry{{}}, testNow, nil, ErrInvalidTrust},
		{"no file CAs", nil, []CAEntry{entry(a, nb, na)}, testNow, nil, ErrInvalidTrust},
		{"three file CAs", sortedCAs(a, b, notInKeyset), []CAEntry{entry(a, nb, na)}, testNow, nil, ErrInvalidTrust},
		{"nil file CA", []*x509.Certificate{nil}, []CAEntry{entry(a, nb, na)}, testNow, nil, ErrInvalidTrust},
		{"nil second file CA", []*x509.Certificate{a, nil}, []CAEntry{entry(a, nb, na)}, testNow, nil, ErrInvalidTrust},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := TrustedControlPlaneCAs(tc.file, tc.entries, tc.at)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || got != nil {
					t.Fatalf("TrustedControlPlaneCAs = %d certs, %v; want %v", len(got), err, tc.wantErr)
				}
				return
			}
			if err != nil || len(got) != len(tc.want) {
				t.Fatalf("TrustedControlPlaneCAs = %d certs, %v; want %d", len(got), err, len(tc.want))
			}
			for i := range tc.want {
				if !bytes.Equal(got[i].Raw, tc.want[i].Raw) {
					t.Errorf("certificate %d is not the expected one in file order", i)
				}
			}
		})
	}
}

// The empty-set error carries the R10d / §5.4 operator message, and the
// result plugs straight into ClientTLSConfig.
func TestTrustedControlPlaneCAsMessageAndUse(t *testing.T) {
	t.Parallel()
	if !strings.Contains(ErrNoTrustedControlPlaneCA.Error(), "control-plane trust outdated, run the installer trust update") {
		t.Fatalf("ErrNoTrustedControlPlaneCA = %q", ErrNoTrustedControlPlaneCA)
	}
	ca := newCA(t, "cp CA", testNow)
	got, err := TrustedControlPlaneCAs([]*x509.Certificate{ca.cert},
		[]CAEntry{{Fingerprint: fingerprint(ca.cert), NotBefore: 1, NotAfter: testNow.Unix() + 1}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientTLSConfig(got, testServerName, nil, fixedClock(testNow)); err != nil {
		t.Fatalf("ClientTLSConfig with the trusted set: %v", err)
	}
}
