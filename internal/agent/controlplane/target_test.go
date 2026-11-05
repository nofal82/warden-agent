package controlplane_test

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/identity"
)

func TestTargetValid(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"127.0.0.1:443":           "passthrough:///127.0.0.1:443",
		"10.0.0.1:1":              "passthrough:///10.0.0.1:1",
		"192.0.2.10:65535":        "passthrough:///192.0.2.10:65535",
		"[::1]:443":               "passthrough:///[::1]:443",
		"[2001:db8::1]:8443":      "passthrough:///[2001:db8::1]:8443",
		"enroll.warden.test:443":  "dns:///enroll.warden.test:443",
		"localhost:8443":          "dns:///localhost:8443",
		"a:1":                     "dns:///a:1",
		"Enroll.Warden.Test:443":  "dns:///Enroll.Warden.Test:443",
		"xn--bcher-kva.test:443":  "dns:///xn--bcher-kva.test:443",
		"a-b.c-d.example.com:443": "dns:///a-b.c-d.example.com:443",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			got, err := controlplane.Target(in)
			if err != nil || got != want {
				t.Fatalf("Target(%q) = %q, %v; want %q", in, got, err, want)
			}
		})
	}
}

func TestTargetInvalid(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"host",
		"host:",
		":443",
		"[]:443",
		"[::1]",
		"127.0.0.1",
		"::1:443",
		"1.2.3.4:443:1",
		"host:0",
		"host:00",
		"host:0443",
		"host:00443",
		"host:65536",
		"host:99999999999999999999",
		"host:-1",
		"host:+443",
		"host:44a",
		"host:0x1bb",
		"host: 443",
		"host:443 ",
		" host:443",
		"ho st:443",
		"host\t:443",
		"host:443\n",
		"host\r\n:443",
		"\x00host:443",
		"host\x00:443",
		"host\x7f:443",
		"unix:///tmp/x",
		"unix:/tmp/x",
		"unix-abstract:x",
		"xds:///a",
		"xds:///a:443",
		"dns:///a:443",
		"dns://8.8.8.8/a:443",
		"passthrough:///1.2.3.4:443",
		"user@host:443",
		"user:pass@host:443",
		"host/path:443",
		"host/:443",
		"/host:443",
		"../host:443",
		"host?x=1:443",
		"host#frag:443",
		"host%2f:443",
		"host%00:443",
		"[fe80::1%eth0]:443",
		"[fe80::1%25eth0]:443",
		"-host:443",
		"host-:443",
		"ho_st:443",
		"host..test:443",
		".host:443",
		"*.warden.test:443",
		"c\u0440.warden.test:443", // Cyrillic er
		"enroll.warden.test\u200b:443",
		strings.Repeat("a", 64) + ".test:443",
		strings.Repeat("a.", 130) + "test:443",
		strings.Repeat("a", 10<<10) + ":443",
		"host:" + strings.Repeat("4", 10<<10),
		"[::1]:443/",
		"[::1]:0443",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			got, err := controlplane.Target(in)
			if !errors.Is(err, controlplane.ErrInvalidEndpoint) {
				t.Fatalf("Target(%q) = %q, %v; want ErrInvalidEndpoint", in, got, err)
			}
			if got != "" {
				t.Errorf("returned %q with an error", got)
			}
			// The error must not echo a 10 KB input back.
			if len(err.Error()) > 512 {
				t.Errorf("error is %d bytes", len(err.Error()))
			}
		})
	}
}

// checkTarget is the invariant of every accepted target.
func checkTarget(t *testing.T, in, got string) {
	t.Helper()
	var rest string
	switch {
	case strings.HasPrefix(got, "dns:///"):
		rest = strings.TrimPrefix(got, "dns:///")
	case strings.HasPrefix(got, "passthrough:///"):
		rest = strings.TrimPrefix(got, "passthrough:///")
	default:
		t.Fatalf("Target(%q) = %q: bad scheme", in, got)
	}
	if strings.ContainsAny(rest, "/@%?# \t\r\n\x00") {
		t.Fatalf("Target(%q) = %q: forbidden byte after the scheme", in, got)
	}
	host, port, err := net.SplitHostPort(rest)
	if err != nil {
		t.Fatalf("Target(%q) = %q: %v", in, got, err)
	}
	if port == "" || port[0] == '0' || len(port) > 5 {
		t.Fatalf("Target(%q) = %q: bad port", in, got)
	}
	if err := identity.ValidateServerName(host); err != nil {
		t.Fatalf("Target(%q) = %q: host fails ValidateServerName: %v", in, got, err)
	}
	if strings.HasPrefix(got, "dns:///") && net.ParseIP(host) != nil {
		t.Fatalf("Target(%q) = %q: IP literal under dns:///", in, got)
	}
	if strings.HasPrefix(got, "passthrough:///") && net.ParseIP(host) == nil {
		t.Fatalf("Target(%q) = %q: name under passthrough:///", in, got)
	}
}

func FuzzTarget(f *testing.F) {
	for _, s := range []string{
		"127.0.0.1:443", "[::1]:443", "enroll.warden.test:443",
		"unix:///tmp/x", "xds:///a", "dns:///a:443", "[fe80::1%eth0]:443",
		"host:0443", "host:65536", "user@host:443", "host/x:443", "host%2f:443",
		"host:443\n", "", ":443", "a:1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := controlplane.Target(in)
		if err != nil {
			if !errors.Is(err, controlplane.ErrInvalidEndpoint) || got != "" {
				t.Fatalf("Target(%q) = %q, %v", in, got, err)
			}
			return
		}
		checkTarget(t, in, got)
	})
}
