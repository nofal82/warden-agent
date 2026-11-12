package logs_test

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nofal82/warden-agent/internal/agent/logs"
)

// FuzzParseOffsets: no panic; an accepted map meets every codec limit and
// survives an encode and parse round trip unchanged.
func FuzzParseOffsets(f *testing.F) {
	for _, m := range []map[string]logs.Position{
		validOffsets(),
		{"/var/log/nginx/error.log": {Dev: 1, Ino: 2, Offset: 3}},
		{},
	} {
		b, err := logs.EncodeOffsets(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
		if len(b) > 2 {
			f.Add(b[:len(b)-1])
			f.Add(append(append([]byte(nil), b...), b...))
		}
	}
	for _, s := range []string{"", "\x00", "\xff\xfe", `{"../../etc/shadow":{"Offset":-1}}`,
		"/var/log/../etc/shadow 1 2 -1\n", strings.Repeat("/a", 3000)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		m, err := logs.ParseOffsets(in)
		if err != nil {
			if len(m) != 0 {
				t.Fatalf("error with %d entries", len(m))
			}
			return
		}
		if len(in) > logs.MaxOffsetsFile {
			t.Fatalf("accepted %d bytes", len(in))
		}
		if len(m) > 256 {
			t.Fatalf("accepted %d entries", len(m))
		}
		for k, p := range m {
			if !filepath.IsAbs(k) || filepath.Clean(k) != k || len(k) > 4096 || strings.ContainsRune(k, 0) {
				t.Fatalf("accepted key %q", k)
			}
			if p.Offset < 0 {
				t.Fatalf("accepted offset %d", p.Offset)
			}
		}
		b, err := logs.EncodeOffsets(m)
		if err != nil {
			t.Fatalf("accepted map does not encode: %v", err)
		}
		m2, err := logs.ParseOffsets(b)
		if err != nil || !reflect.DeepEqual(m, m2) {
			t.Fatalf("round trip changed the map: %v", err)
		}
	})
}

// FuzzTailerPoll writes arbitrary bytes in two chunks and polls after
// each: no panic, every line at most MaxLineRead bytes, never a '\n'.
func FuzzTailerPoll(f *testing.F) {
	f.Add([]byte("a\nb\n"), uint16(1))
	f.Add([]byte("partial"), uint16(3))
	f.Add([]byte("crlf\r\n\r\n\n\n"), uint16(5))
	f.Add([]byte(strings.Repeat("A", logs.MaxLineRead+3)+"\nnext\n"), uint16(logs.MaxLineRead))
	f.Add([]byte("\x00\xff\n\x1b[31m\n"), uint16(0))
	f.Add([]byte{}, uint16(math.MaxUint16))
	f.Fuzz(func(t *testing.T, data []byte, cut uint16) {
		p := filepath.Join(t.TempDir(), "error.log")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		start := posOf(t, p, 0)
		tl := logs.NewTailer(p, &start)
		defer func() { _ = tl.Close() }()
		at := min(int(cut), len(data))
		check := func(lines []string) {
			for _, l := range lines {
				if len(l) > logs.MaxLineRead || strings.ContainsRune(l, '\n') {
					t.Fatalf("line of %d bytes, newline %v", len(l), strings.ContainsRune(l, '\n'))
				}
				if !strings.Contains(string(data), l) {
					t.Fatal("returned a line that is not in the file")
				}
			}
		}
		for _, chunk := range [][]byte{data[:at], data[at:]} {
			fh, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0) // #nosec G304 -- fuzz temp file
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fh.Write(chunk); err != nil {
				t.Fatal(err)
			}
			_ = fh.Close()
			lines, pos, err := tl.Poll(pollMax)
			if err != nil {
				t.Fatalf("Poll: %v", err)
			}
			check(lines)
			if pos.Offset < 0 || pos.Offset > int64(len(data)) {
				t.Fatalf("position %d outside the file", pos.Offset)
			}
		}
	})
}
