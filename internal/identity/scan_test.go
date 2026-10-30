package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSourceScan is the AC15 / R24 source scan for this package: no file
// (production or test) disables certificate verification, and nothing opens
// a listening socket. The needles are assembled from fragments so this file
// does not match itself.
func TestSourceScan(t *testing.T) {
	t.Parallel()
	everywhere := []string{
		"Insecure" + "SkipVerify",
		"net." + "Listen",
		"tls." + "Listen",
		"net." + "FileListener",
		"http" + "test",
		"Listen" + "AndServe",
		"syscall." + "Listen",
		"unix." + "Listen",
	}
	// The agent never opens a listening socket (R24); production files of
	// this package open no network connection at all (doc.go).
	production := []string{
		"net." + "Dial",
		"tls." + "Dial",
		"\"net/" + "http\"",
		"grpc." + "Dial",
		"grpc." + "NewClient",
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 10 {
		t.Fatalf("found only %d Go files; is the test running in the package directory?", len(files))
	}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, n := range everywhere {
			if strings.Contains(text, n) {
				t.Errorf("%s contains %q", name, n)
			}
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		for _, n := range production {
			if strings.Contains(text, n) {
				t.Errorf("%s contains %q", name, n)
			}
		}
	}
}
