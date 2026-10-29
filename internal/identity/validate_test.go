package identity

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestValidateServerID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid v4", testServerID, true},
		{"valid v4 other", otherServerID, true},
		{"valid variant 8", "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5", true},
		{"valid variant 9", "6f1c2d3e-4a5b-4c6d-9e7f-90a1b2c3d4e5", true},
		{"valid variant a", "6f1c2d3e-4a5b-4c6d-ae7f-90a1b2c3d4e5", true},
		{"valid variant b", "6f1c2d3e-4a5b-4c6d-be7f-90a1b2c3d4e5", true},
		{"all hex digits", "01234567-89ab-4cde-8f01-23456789abcd", true},

		{"empty", "", false},
		{"uppercase", strings.ToUpper(testServerID), false},
		{"mixed case", "6F1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5", false},
		{"version 1", "6f1c2d3e-4a5b-1c6d-8e7f-90a1b2c3d4e5", false},
		{"version 7", "01920f3e-7c4a-7b2d-8e5f-0a1b2c3d4e5f", false},
		{"version 0 nil UUID", "00000000-0000-0000-0000-000000000000", false},
		{"version 5", "6f1c2d3e-4a5b-5c6d-8e7f-90a1b2c3d4e5", false},
		{"variant c", "6f1c2d3e-4a5b-4c6d-ce7f-90a1b2c3d4e5", false},
		{"variant 7", "6f1c2d3e-4a5b-4c6d-7e7f-90a1b2c3d4e5", false},
		{"variant 0", "6f1c2d3e-4a5b-4c6d-0e7f-90a1b2c3d4e5", false},
		{"variant f", "6f1c2d3e-4a5b-4c6d-fe7f-90a1b2c3d4e5", false},
		{"35 bytes", testServerID[:35], false},
		{"37 bytes", testServerID + "0", false},
		{"trailing newline", testServerID + "\n", false},
		{"trailing CRLF", testServerID + "\r\n", false},
		{"leading space", " " + testServerID, false},
		{"trailing space", testServerID + " ", false},
		{"tab inside", "6f1c2d3e\t4a5b-4c6d-8e7f-90a1b2c3d4e5", false},
		{"BOM prefix", "\ufeff" + testServerID, false},
		{"braces", "{" + testServerID + "}", false},
		{"urn prefix", "urn:uuid:" + testServerID, false},
		{"no hyphens", strings.ReplaceAll(testServerID, "-", "") + "0000", false},
		{"hyphen moved", "6f1c2d3e4-a5b-4c6d-8e7f-90a1b2c3d4e5", false},
		{"underscores", strings.ReplaceAll(testServerID, "-", "_"), false},
		{"non-hex g", "6f1c2d3g-4a5b-4c6d-8e7f-90a1b2c3d4e5", false},
		{"NUL byte", "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e\x00", false},
		{"fullwidth digit", "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4\uff15", false},
		{"cyrillic a look-alike", "6f1c2d3e-4\u0430b-4c6d-8e7f-90a1b2c3d4e", false},
		{"path traversal", "../../../../../../../../etc/passwd/x", false},
		{"shell metachar", "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4;e", false},
		{"option injection", "--config=/tmp/x-4c6d-8e7f-90a1b2c3d4", false},
		{"10 KB", strings.Repeat("a", 10<<10), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateServerID(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("ValidateServerID(%q) = %v, want nil", tc.in, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidServerID) {
				t.Fatalf("ValidateServerID(%q) = %v, want ErrInvalidServerID", tc.in, err)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("Q", 43)
	prefix := "wdn1" + "_"
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid", canaryToken(), true},
		{"valid all classes", prefix + "Aa0-_" + strings.Repeat("z", 38), true},
		{"valid hyphen end", prefix + strings.Repeat("Q", 42) + "-", true},
		{"valid underscore start", prefix + "_" + strings.Repeat("Q", 42), true},

		{"empty", "", false},
		{"prefix only", prefix, false},
		{"47 chars", prefix + body[:42], false},
		{"49 chars", prefix + body + "Q", false},
		{"padding equals", prefix + body[:42] + "=", false},
		{"extra padding", prefix + body + "=", false},
		{"plus", prefix + "+" + body[:42], false},
		{"slash", prefix + "/" + body[:42], false},
		{"dot", prefix + "." + body[:42], false},
		{"wrong version wdn2", "wdn2" + "_" + body, false},
		{"uppercase prefix", "WDN1" + "_" + body, false},
		{"hyphen separator", "wdn1-" + body, false},
		{"no prefix 48 chars", strings.Repeat("Q", 48), false},
		{"non-ASCII 49 bytes", prefix + body[:42] + "\u00e9", false},
		{"non-ASCII 48 bytes", prefix + body[:41] + "\u00e9", false},
		{"trailing newline", prefix + body[:42] + "\n", false},
		{"trailing space", prefix + body[:42] + " ", false},
		{"NUL", prefix + body[:42] + "\x00", false},
		{"leading space", " " + prefix + body[:42], false},
		{"shell metachar", prefix + body[:42] + ";", false},
		{"dollar paren", prefix + "$(id)" + body[:38], false},
		{"10 KB", prefix + strings.Repeat("Q", 10<<10), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateToken(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("ValidateToken = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("ValidateToken(len %d) = %v, want ErrInvalidToken", len(tc.in), err)
			}
			// R20: never echo the token text back.
			if len(tc.in) >= 8 {
				assertNoLeak(t, err.Error(), nil, tc.in, tc.in[5:], strings.Repeat("Q", 16))
			}
		})
	}
}

func TestTokenHash(t *testing.T) {
	t.Parallel()
	for _, tok := range []string{canaryToken(), otherToken()} {
		got := TokenHash(tok)
		want := sha256.Sum256([]byte(tok))
		if got != want {
			t.Fatalf("TokenHash = %x, want sha256 of the 48 text bytes %x", got, want)
		}
	}
	if TokenHash(canaryToken()) == TokenHash(otherToken()) {
		t.Fatal("two different tokens hash equal")
	}
}

func TestValidateServerName(t *testing.T) {
	t.Parallel()
	l63 := strings.Repeat("a", 63)
	l64 := strings.Repeat("a", 64)
	n253 := l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 61)
	n254 := l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 62)
	if len(n253) != 253 || len(n254) != 254 {
		t.Fatalf("bad test lengths %d %d", len(n253), len(n254))
	}
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"dns", testServerName, true},
		{"single label", "localhost", true},
		{"digits and hyphens", "cp-01.region-2.example.test", true},
		{"punycode label", "xn--bcher-kva.example", true},
		{"uppercase letters", "CP.Example.Test", true},
		{"label 63", l63 + ".example", true},
		{"total 253", n253, true},
		{"ipv4", "192.0.2.10", true},
		{"ipv6", "2001:db8::10", true},
		{"ipv6 loopback", "::1", true},

		{"empty", "", false},
		{"label 64", l64 + ".example", false},
		{"total 254", n254, false},
		{"leading hyphen", "-cp.example.test", false},
		{"trailing hyphen", "cp-.example.test", false},
		{"label leading hyphen", "cp.-example.test", false},
		{"trailing dot", "cp.example.test.", false},
		{"leading dot", ".cp.example.test", false},
		{"lone dot", ".", false},
		{"empty label", "cp..example.test", false},
		{"wildcard", "*.example.test", false},
		{"wildcard inside", "cp.*.test", false},
		{"underscore", "cp_1.example.test", false},
		{"space", "cp example.test", false},
		{"trailing newline", testServerName + "\n", false},
		{"NUL", testServerName + "\x00", false},
		{"host port", testServerName + ":443", false},
		{"ipv4 port", "192.0.2.10:443", false},
		{"ipv6 brackets", "[2001:db8::10]", false},
		{"ipv6 brackets port", "[2001:db8::10]:443", false},
		{"ipv6 zone", "fe80::1%eth0", false},
		{"url", "https://" + testServerName, false},
		{"path", testServerName + "/x", false},
		{"userinfo", "user@" + testServerName, false},
		{"non-ASCII", "c\u00e9.example.test", false},
		{"cyrillic look-alike", "\u0441p.example.test", false},
		{"semicolon", "cp.example.test;id", false},
		{"option injection", "--config=/tmp/x", false},
		{"10 KB", strings.Repeat("a.", 5<<10), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateServerName(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("ValidateServerName(%q) = %v, want nil", tc.in, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidServerName) {
				t.Fatalf("ValidateServerName(%q) = %v, want ErrInvalidServerName", tc.in, err)
			}
		})
	}
}
