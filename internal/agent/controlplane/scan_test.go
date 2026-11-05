package controlplane_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSourceScan (R2, R3, R45, AC40, AC50): nothing in this package turns
// off certificate verification, uses insecure credentials, listens,
// registers or uses a compressor, reads status details through gRPC's
// non-strict decoder, decodes with plain proto.Unmarshal, runs a process
// or logs. Needles are built from fragments so this file does not match
// itself.
func TestSourceScan(t *testing.T) {
	t.Parallel()
	everywhere := []string{
		"Insecure" + "SkipVerify",
		"insecure." + "NewCredentials",
		"With" + "Insecure",
		"grpc/credentials/" + "insecure",
		"net." + "Listen",
		"tls." + "Listen",
		"net." + "FileListener",
		"http" + "test",
		"Listen" + "AndServe",
		"grpc/encoding/" + "gzip",
		"Use" + "Compressor",
		"Register" + "Compressor",
		"\"os/" + "exec\"",
		"syscall." + "Exec",
		"os." + "StartProcess",
	}
	production := []string{
		".Details" + "()",
		"proto." + "Unmarshal(",
		"\"" + "log\"",
		"\"log/" + "slog\"",
		"fmt." + "Print",
		"fmt." + "Fprint",
		"os." + "Stdout",
		"os." + "Stderr",
		"print" + "ln(",
		"grpc." + "Dial(",
		"grpc." + "DialContext(",
		"With" + "Block(",
		"math/" + "rand",
		"tls." + "Dial",
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	prod := 0
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
		prod++
		// Doc comments may name what is forbidden ("never
		// Status.Details()"); only code is scanned for these.
		code := stripLineComments(text)
		for _, n := range production {
			if strings.Contains(code, n) {
				t.Errorf("%s contains %q", name, n)
			}
		}
	}
	if prod < 3 {
		t.Fatalf("found only %d production files; is the test running in the package directory?", prod)
	}
}

// stripLineComments drops every line whose first non-blank text is //.
func stripLineComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
