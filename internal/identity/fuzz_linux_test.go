//go:build linux

package identity

// Fuzz targets for the Linux-only file code and the state-file parsers.
// They live apart from fuzz_test.go because readOwnedFile and the state
// directory exist only on Linux.

import (
	"bytes"
	"errors"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var tokenExpiresRe = regexp.MustCompile(`^[1-9][0-9]{0,11}$`)

// FuzzReadOwnedFilePath fuzzes rel over a fixed tree (design §A.5). A
// success is only a clean relative path naming a file inside start, and
// the bytes are that file's; a file outside start is never returned.
func FuzzReadOwnedFilePath(f *testing.F) {
	root := f.TempDir()
	start := filepath.Join(root, "start")
	files := map[string][]byte{"a/b/file": []byte("GOOD"), "top": []byte("TOP")}
	for _, d := range []string{start, filepath.Join(start, "a"), filepath.Join(start, "a", "b")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			f.Fatal(err)
		}
	}
	for rel, data := range files {
		p := filepath.Join(start, rel)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			f.Fatal(err)
		}
	}
	outside := []byte("OUTSIDE-NEVER-READ")
	if err := os.WriteFile(filepath.Join(root, "outside"), outside, 0o600); err != nil {
		f.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), filepath.Join(start, "a", "link")); err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		"a/b/file", "top", "", ".", "..", "../outside", "a/../../outside", "a/link", "a/b/../../top",
		"./top", "a//b/file", "a/b/file/", "/top", "a/b/file\x00", "a\\b\\file", "a/b",
		"..%2foutside", strings.Repeat("a/", 2000) + "file", filepath.Join(root, "outside"),
	} {
		f.Add(s)
	}
	uid := os.Getuid()
	f.Fuzz(func(t *testing.T, rel string) {
		got, err := readOwnedFile(start, rel, uid, 1024)
		if err != nil {
			if got != nil {
				t.Fatal("content returned with an error")
			}
			return
		}
		if bytes.Contains(got, outside) {
			t.Fatalf("read a file outside start through %q", rel)
		}
		if path.IsAbs(rel) || path.Clean(rel) != rel || rel == "." || strings.HasPrefix(rel, "../") || rel == ".." {
			t.Fatalf("accepted the unclean path %q", rel)
		}
		for _, e := range strings.Split(rel, "/") {
			if e == "" || e == "." || e == ".." {
				t.Fatalf("accepted %q with element %q", rel, e)
			}
		}
		want, ok := files[rel]
		if !ok || !bytes.Equal(got, want) {
			t.Fatalf("readOwnedFile(%q) = %q; not that file's bytes", rel, got)
		}
	})
}

func FuzzParseTokenFile(f *testing.F) {
	tok := canaryToken()
	for _, s := range []string{tok, otherToken(), "", tok + "\n", tok + "\r\n", tok[:47], tok + "Q", tok[:47] + "+", " " + tok[1:], "\ufeff" + tok} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := parseTokenFile(data)
		want := len(data) == 48 && tokenRe.Match(data)
		if want != (err == nil) {
			t.Fatalf("parseTokenFile(len %d) = %v, want valid=%v", len(data), err, want)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidToken) || got != "" {
				t.Fatalf("wrong error or value: %v", err)
			}
			if len(data) >= 8 && strings.Contains(err.Error(), string(data)) {
				t.Fatal("error echoes the file")
			}
			return
		}
		if got != string(data) {
			t.Fatal("returned token differs from the file")
		}
	})
}

func FuzzParseTokenExpires(f *testing.F) {
	for _, s := range []string{"1", "1700000000", "999999999999", "1000000000000", "", "0", "01", "-1", "+1", " 1", "1\n", "1e9", "\uff11"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, ok := parseTokenExpires(data)
		if want := tokenExpiresRe.Match(data); want != ok {
			t.Fatalf("parseTokenExpires(%q) ok = %v, regex says %v", data, ok, want)
		}
		if !ok {
			return
		}
		if strconv.FormatInt(got, 10) != string(data) {
			t.Fatalf("parseTokenExpires(%q) = %d", data, got)
		}
	})
}
