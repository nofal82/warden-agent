package logs_test

// Offsets state file (redaction R9a): codec limits, unsafe state files and
// atomic, symlink-safe saving.

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nofal82/warden-agent/internal/agent/logs"
)

func validOffsets() map[string]logs.Position {
	return map[string]logs.Position{
		"/var/log/nginx/error.log":                   {Dev: 2049, Ino: 1234, Offset: 0},
		"/var/log/postgresql/postgresql-14-main.log": {Dev: 2049, Ino: 99, Offset: math.MaxInt64},
		"/var/log/" + strings.Repeat("a", 4096-9):    {Dev: math.MaxUint64, Ino: math.MaxUint64, Offset: 7},
	}
}

func TestOffsetsCodec(t *testing.T) {
	m := validOffsets()
	b, err := logs.EncodeOffsets(m)
	if err != nil {
		t.Fatalf("EncodeOffsets(valid): %v", err)
	}
	if len(b) > logs.MaxOffsetsFile {
		t.Errorf("encoding is %d bytes, over MaxOffsetsFile", len(b))
	}
	got, err := logs.ParseOffsets(b)
	if err != nil || fmt.Sprint(got) != fmt.Sprint(m) {
		t.Fatalf("round trip = %v, %v", got, err)
	}
	full := map[string]logs.Position{}
	for i := 0; i < 256; i++ {
		full[fmt.Sprintf("/var/log/x/%03d.log", i)] = logs.Position{Ino: uint64(i)} // #nosec G115 -- small counter
	}
	if b, err := logs.EncodeOffsets(full); err != nil || len(b) > logs.MaxOffsetsFile {
		t.Errorf("256 entries: %d bytes, %v", len(b), err)
	}

	over := map[string]logs.Position{}
	for k, v := range full {
		over[k] = v
	}
	over["/var/log/x/256.log"] = logs.Position{}
	bad := map[string]map[string]logs.Position{
		"257 entries":       over,
		"relative key":      {"var/log/nginx/error.log": {}},
		"empty key":         {"": {}},
		"dot-dot key":       {"/var/log/../../etc/shadow": {}},
		"dot segment":       {"/var/log/./nginx/error.log": {}},
		"trailing slash":    {"/var/log/nginx/": {}},
		"double slash":      {"/var/log//nginx/error.log": {}},
		"NUL in key":        {"/var/log/nginx/error.log\x00x": {}},
		"newline in key":    {"/var/log/nginx/error.log\n/etc/shadow": {}},
		"key over 4096":     {"/" + strings.Repeat("a", 4096): {}},
		"negative offset":   {"/var/log/nginx/error.log": {Offset: -1}},
		"min int64 offset":  {"/var/log/nginx/error.log": {Offset: math.MinInt64}},
		"invalid UTF-8 key": {"/var/log/\xff.log": {}},
	}
	for name, m := range bad {
		if _, err := logs.EncodeOffsets(m); err == nil {
			t.Errorf("EncodeOffsets(%s) accepted", name)
		}
	}
	for name, in := range map[string][]byte{
		"garbage":         {0xff, 0xfe, 0xfd, 0x00},
		"oversized":       bytes.Repeat([]byte{'a'}, logs.MaxOffsetsFile+1),
		"truncated valid": b[:len(b)/2],
		"JSON look-alike": []byte(`{"../../etc/shadow":{"Offset":-1}}`),
	} {
		m, err := logs.ParseOffsets(in)
		if err == nil || len(m) != 0 {
			t.Errorf("ParseOffsets(%s) = %d entries, %v; want error and no entries", name, len(m), err)
		}
	}
}

// LoadOffsets never follows a symlink, never blocks on a FIFO, refuses
// oversized or corrupt files, and a missing file is a clean first start.
func TestLoadOffsetsUnsafe(t *testing.T) {
	dir := t.TempDir()
	good, err := logs.EncodeOffsets(validOffsets())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "elsewhere")
	writeFile(t, target, string(good))

	m, err := logs.LoadOffsets(filepath.Join(dir, "missing"))
	if err != nil || len(m) != 0 {
		t.Errorf("missing file = %v, %v; want empty, nil", m, err)
	}
	ok := filepath.Join(dir, "ok")
	writeFile(t, ok, string(good))
	if m, err := logs.LoadOffsets(ok); err != nil || len(m) != 3 {
		t.Errorf("valid file = %d entries, %v", len(m), err)
	}

	cases := map[string]func(p string){
		"symlink":   func(p string) { _ = os.Symlink(target, p) },
		"directory": func(p string) { _ = os.Mkdir(p, 0o700) },
		"oversized": func(p string) { writeFile(t, p, strings.Repeat("a", logs.MaxOffsetsFile+1)) },
		"corrupt":   func(p string) { writeFile(t, p, "\xff\xfe corrupt") },
		"FIFO":      func(p string) { _ = syscall.Mkfifo(p, 0o600) },
	}
	for name, mk := range cases {
		p := filepath.Join(dir, "state-"+strings.ReplaceAll(name, " ", "-"))
		mk(p)
		var m map[string]logs.Position
		err := openWithin(t, 3*time.Second, func() error {
			var e error
			m, e = logs.LoadOffsets(p)
			return e
		}, unblockFIFO(p))
		if err == nil || len(m) != 0 {
			t.Errorf("%s: LoadOffsets = %d entries, %v; want empty and an error", name, len(m), err)
		}
	}
}

func TestSaveOffsets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log-offsets")
	if err := logs.SaveOffsets(p, validOffsets()); err != nil {
		t.Fatalf("SaveOffsets: %v", err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
		t.Errorf("state file mode = %v, want regular 0600", fi.Mode())
	}
	if m, err := logs.LoadOffsets(p); err != nil || len(m) != 3 {
		t.Errorf("reload = %d, %v", len(m), err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("directory holds %d entries after save; temp files left behind", len(ents))
	}
	if err := logs.SaveOffsets(p, map[string]logs.Position{"relative": {}}); err == nil {
		t.Error("SaveOffsets accepted an invalid map")
	}
	if m, err := logs.LoadOffsets(p); err != nil || len(m) != 3 {
		t.Error("a refused save changed the state file")
	}

	// A symlink planted at the state path is never written through.
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "FAKE-SECRET-123 do not touch\n")
	link := filepath.Join(dir, "linked-offsets")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	_ = logs.SaveOffsets(link, validOffsets())
	if b, _ := os.ReadFile(victim); string(b) != "FAKE-SECRET-123 do not touch\n" { // #nosec G304 -- test file
		t.Error("SaveOffsets wrote through a symlink")
	}
	if err := logs.SaveOffsets(filepath.Join(dir, "no-such-dir", "x"), validOffsets()); err == nil {
		t.Error("SaveOffsets into a missing directory succeeded")
	}
}
