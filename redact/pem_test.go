package redact

// Multi-line key material (R13, section 4.2 pem-private-key, pem-body-line and
// pem-private-key-b64; AC5, AC39, AC60; rulings 2 and 3).

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const journalPrefix = "Oct 25 10:15:30 web1 app[4242]: "

// onlyMarkers reports whether s holds nothing but the given markers and LFs.
func onlyMarkers(s string, markers ...string) bool {
	for _, m := range markers {
		s = strings.ReplaceAll(s, m, "")
	}
	return strings.Trim(s, "\n") == ""
}

func pemMarkers() []string {
	return []string{Marker("pem-private-key"), Marker("pem-body-line"), ShortMarker}
}

func TestPEMFullBlock(t *testing.T) {
	k := getKeys(t)
	for name, p := range map[string]string{"RSA PKCS1 (C1)": k.rsaPEM, "PKCS8": k.pkcs8PEM, "OpenSSH ed25519 (C2)": k.opensshPEM} {
		t.Run(name, func(t *testing.T) {
			in := "key follows.\n" + p + "\ndone."
			out, rep := redactE(t, in)
			want := "key follows.\n" + Marker("pem-private-key") + "\ndone."
			if out != want {
				t.Errorf("got %q, want %q", lastN(out, 200), want)
			}
			if rep.Replaced["pem-private-key"] < 1 {
				t.Errorf("Replaced[pem-private-key] = %d", rep.Replaced["pem-private-key"])
			}
			assertNoLeak(t, name, out, pemBody(p)...)
		})
	}
}

// R13: a BEGIN marker without its END marker is redacted to the end of the
// input, including any later lines (AC5).
func TestPEMNoEndMarker(t *testing.T) {
	k := getKeys(t)
	body := pemBody(k.rsaPEM)
	in := "key follows.\n" + pemBeginLine(k.rsaPEM) + "\n" + strings.Join(body[:10], "\n")
	out, _ := redactE(t, in)
	if want := "key follows.\n" + Marker("pem-private-key"); out != want {
		t.Errorf("got %q, want %q", out, want)
	}
	in = in + "\nlater line."
	out, _ = redactE(t, in)
	if want := "key follows.\n" + Marker("pem-private-key"); out != want {
		t.Errorf("with a later line: got %q, want %q (to the end of the input)", out, want)
	}
	assertNoLeak(t, "no END", out, body[:10]...)
}

// Ruling 2 (deviation from R13's literal text): an END marker without a BEGIN
// marker redacts only the unbroken run of body lines directly above it.
func TestPEMEndWithoutBegin(t *testing.T) {
	k := getKeys(t)
	body := pemBody(k.rsaPEM)
	run := body[len(body)-6:]
	head := "service started normally\nloading key.\n"
	in := head + strings.Join(run, "\n") + "\n" + pemEndLine(k.rsaPEM) + "\ndone."
	out, _ := redactE(t, in)
	if !strings.HasPrefix(out, head) {
		t.Errorf("lines above the run changed: %q", out[:min(len(out), len(head)+20)])
	}
	if !strings.HasSuffix(out, "\ndone.") {
		t.Errorf("line after END changed: %q", lastN(out, 40))
	}
	if strings.Contains(out, "-----END") {
		t.Errorf("END marker kept")
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(out, head), "\ndone.")
	if !onlyMarkers(mid, pemMarkers()...) {
		t.Errorf("run not fully redacted: %q", mid)
	}
	assertNoLeak(t, "END without BEGIN", out, run...)
}

// The same with a journal prefix on every line: the prefix of each body line
// is kept and only its key-body part is replaced.
func TestPEMEndWithoutBeginPrefixed(t *testing.T) {
	k := getKeys(t)
	body := pemBody(k.rsaPEM)
	run := body[len(body)-5:]
	var lines []string
	lines = append(lines, journalPrefix+"service started normally", journalPrefix+"loading key.")
	for _, l := range run {
		lines = append(lines, journalPrefix+l)
	}
	lines = append(lines, journalPrefix+pemEndLine(k.rsaPEM), journalPrefix+"done.")
	out, _ := redactE(t, strings.Join(lines, "\n"))
	got := strings.Split(out, "\n")
	if len(got) != len(lines) {
		t.Fatalf("line count %d, want %d", len(got), len(lines))
	}
	if got[0] != lines[0] || got[1] != lines[1] || got[len(got)-1] != lines[len(lines)-1] {
		t.Errorf("lines outside the run changed")
	}
	for i := 2; i < 2+len(run); i++ {
		if got[i] != journalPrefix+Marker("pem-body-line") && got[i] != journalPrefix+Marker("pem-private-key") {
			t.Errorf("line %d = %q, want the prefix kept and the key-body part replaced", i, got[i])
		}
	}
	if strings.Contains(out, "-----END") {
		t.Errorf("END marker kept")
	}
	assertNoLeak(t, "prefixed END without BEGIN", out, run...)
}

// C4, AC5: body lines with no marker at all.
func TestPEMBodyLinesAlone(t *testing.T) {
	k := getKeys(t)
	body := pemBody(k.rsaPEM)
	in := "key follows.\n" + strings.Join(body, "\n") + "\ndone."
	out, rep := redactE(t, in)
	if !strings.HasPrefix(out, "key follows.\n") || !strings.HasSuffix(out, "\ndone.") {
		t.Errorf("lines around the body changed: %q", out)
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(out, "key follows.\n"), "\ndone.")
	if !onlyMarkers(mid, Marker("pem-body-line")) {
		t.Errorf("body not fully redacted: %q", lastN(mid, 200))
	}
	if rep.Replaced["pem-body-line"] < 1 {
		t.Errorf("Replaced[pem-body-line] = %d", rep.Replaced["pem-body-line"])
	}
	assertNoLeak(t, "C4", out, body...)
}

// AC39: an extract that starts and ends inside the block.
func TestPEMExtractInsideBlock(t *testing.T) {
	k := getKeys(t)
	body := pemBody(k.rsaPEM)
	part := body[3:15]
	out, _ := redactE(t, strings.Join(part, "\n"))
	if !onlyMarkers(out, Marker("pem-body-line")) {
		t.Errorf("inside-block extract not fully redacted: %q", lastN(out, 200))
	}
	assertNoLeak(t, "inside block", out, part...)
}

// AC39: the short last body line (under 60 characters) is redacted when it
// is next to a 60-76 character body line.
func TestPEMShortLastLine(t *testing.T) {
	k := getKeys(t)
	body := pemBody(k.rsaPEM)
	short := randFrom(alphaAlnum+"+/", 40) + "=="
	in := strings.Join(body[:5], "\n") + "\n" + short + "\ndone."
	out, _ := redactE(t, in)
	assertNoLeak(t, "short last line", out, append(append([]string{}, body[:5]...), short)...)
	if !strings.HasSuffix(out, "\ndone.") {
		t.Errorf("line after the body changed: %q", lastN(out, 40))
	}
	// The real last line of the generated key, whatever its length.
	in = "key follows.\n" + strings.Join(body[len(body)-3:], "\n") + "\ndone."
	out, _ = redactE(t, in)
	assertNoLeak(t, "real last line", out, body[len(body)-3:]...)
}

// Ruling 3: a short line matches only next to a 60-76 character body line or
// a BEGIN/END line; there is no chaining from short line to short line.
func TestPEMShortLinesDoNotChain(t *testing.T) {
	s1 := randFrom(alphaLetters, 40)
	s2 := randFrom(alphaLetters, 30)
	for name, in := range map[string]string{
		"short line alone":       "intro.\n" + s1 + "\nend.",
		"two short lines":        "intro.\n" + s1 + "\n" + s2 + "\nend.",
		"short line after words": "the service reported\n" + s1 + "\nend.",
	} {
		out, rep := redactE(t, in)
		if out != in {
			t.Errorf("%s: changed to %q", name, out)
		}
		if replacedTotal(rep) != 0 {
			t.Errorf("%s: replacements reported", name)
		}
	}
}

func TestPEMJournalPrefixEveryLine(t *testing.T) {
	k := getKeys(t)
	lines := pemLines(k.rsaPEM)
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(journalPrefix + l + "\n")
	}
	b.WriteString(journalPrefix + "done.")
	out, _ := redactE(t, b.String())
	if !strings.HasPrefix(out, journalPrefix) || !strings.HasSuffix(out, "\n"+journalPrefix+"done.") {
		t.Errorf("prefix or following line lost: %q", out)
	}
	if !strings.Contains(out, Marker("pem-private-key")) {
		t.Errorf("no pem-private-key marker: %q", out)
	}
	assertNoLeak(t, "journal prefix", out, pemBody(k.rsaPEM)...)
}

// Mid-block body lines with a journal prefix or YAML indentation keep the
// prefix; only the key-body part is replaced.
func TestPEMBodyLinePrefixKept(t *testing.T) {
	k := getKeys(t)
	part := pemBody(k.rsaPEM)[3:12]
	for name, prefix := range map[string]string{"journal": journalPrefix, "YAML indent": "    ", "key colon": "key:"} {
		t.Run(name, func(t *testing.T) {
			var lines []string
			for _, l := range part {
				lines = append(lines, prefix+l)
			}
			out, _ := redactE(t, strings.Join(lines, "\n"))
			got := strings.Split(out, "\n")
			if len(got) != len(lines) {
				t.Fatalf("line count %d, want %d", len(got), len(lines))
			}
			for i, l := range got {
				if l != prefix+Marker("pem-body-line") {
					t.Errorf("line %d = %q, want %q", i, l, prefix+Marker("pem-body-line"))
				}
			}
			assertNoLeak(t, name, out, part...)
		})
	}
}

func TestPEMYAMLBlock(t *testing.T) {
	k := getKeys(t)
	var b strings.Builder
	b.WriteString("tls:\n  key: |\n")
	for _, l := range pemLines(k.rsaPEM) {
		b.WriteString("    " + l + "\n")
	}
	b.WriteString("next: 1")
	out, _ := redactE(t, b.String())
	if !strings.HasPrefix(out, "tls:\n  key: |\n    ") || !strings.HasSuffix(out, "\nnext: 1") {
		t.Errorf("YAML structure lost: %q", out)
	}
	if !strings.Contains(out, Marker("pem-private-key")) {
		t.Errorf("no pem-private-key marker: %q", out)
	}
	assertNoLeak(t, "YAML", out, pemBody(k.rsaPEM)...)
}

// C22: CR LF line ends.
func TestPEMCRLF(t *testing.T) {
	k := getKeys(t)
	in := "key follows.\r\n" + strings.ReplaceAll(k.rsaPEM, "\n", "\r\n") + "\r\ndone."
	out, _ := redactE(t, in)
	if want := "key follows.\n" + Marker("pem-private-key") + "\ndone."; out != want {
		t.Errorf("got %q, want %q", lastN(out, 120), want)
	}
	assertNoLeak(t, "CRLF", out, pemBody(k.rsaPEM)...)
}

// C22: an extract that starts mid-block and holds the END marker.
func TestPEMStartMidBlock(t *testing.T) {
	k := getKeys(t)
	body := pemBody(k.rsaPEM)
	in := strings.Join(body[5:], "\n") + "\n" + pemEndLine(k.rsaPEM) + "\ndone."
	out, _ := redactE(t, in)
	if !strings.HasSuffix(out, "\ndone.") {
		t.Errorf("line after END changed: %q", lastN(out, 40))
	}
	if strings.Contains(out, "-----END") {
		t.Errorf("END marker kept")
	}
	assertNoLeak(t, "mid-block", out, body[5:]...)
}

// C3, AC5: the backslash-n escaped PKCS #8 key of a service-account file.
func TestPEMEscapedInJSON(t *testing.T) {
	k := getKeys(t)
	doc, err := json.Marshal(map[string]string{
		"type":        "service_account",
		"project_id":  "lab-project",
		"private_key": k.pkcs8PEM + "\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), bs+"n") {
		t.Fatalf("test setup: JSON does not hold escaped newlines")
	}
	out, _ := redactE(t, string(doc))
	if !strings.Contains(out, Marker("pem-private-key")) {
		t.Errorf("no pem-private-key marker: %q", lastN(out, 200))
	}
	for _, keep := range []string{`"project_id":"lab-project"`, `"type":"service_account"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %s: %q", keep, out)
		}
	}
	assertNoLeak(t, "C3", out, pemBody(k.pkcs8PEM)...)
}

// AC39, R33: a SHA-256 digest or a container ID alone on a line is kept.
func TestPEMHexLinesKept(t *testing.T) {
	h := randFrom(alphaHexLower, 64)
	for name, in := range map[string]string{
		"digest alone":       "sha256 of upload\n" + h + "\nstored.",
		"container ID":       journalPrefix + "container " + h,
		"digest with prefix": journalPrefix + h,
		"two digests":        h + "\n" + randFrom(alphaHexLower, 64),
	} {
		out, rep := redactE(t, in)
		if out != in {
			t.Errorf("%s: changed to %q", name, out)
		}
		if replacedTotal(rep) != 0 {
			t.Errorf("%s: replacements reported", name)
		}
	}
}

// C25, AC60: base64 of C1, standard and URL-safe, alone and as a JSON value.
func TestPEMBase64(t *testing.T) {
	k := getKeys(t)
	m := Marker("pem-private-key-b64")
	encs := map[string]string{
		"standard":     base64.StdEncoding.EncodeToString([]byte(k.rsaPEM)),
		"standard raw": base64.RawStdEncoding.EncodeToString([]byte(k.rsaPEM)),
		"URL-safe":     base64.URLEncoding.EncodeToString([]byte(k.rsaPEM)),
		"URL-safe raw": base64.RawURLEncoding.EncodeToString([]byte(k.rsaPEM)),
	}
	for name, b := range encs {
		t.Run(name, func(t *testing.T) {
			if !strings.HasPrefix(b, b64BeginPrefix()) {
				t.Fatalf("test setup: encoding does not start with the BEGIN prefix")
			}
			out, _ := redactE(t, b)
			if out != m {
				t.Errorf("alone: got %q, want %q", lastN(out, 80), m)
			}
			// The random base64 can, about once in 150 keys, hold a
			// secret-assignment keyword right before its "=" padding; that
			// value may then also take the closing quote (R33 accepts the
			// over-redaction), so only the marker and the prefix are fixed.
			out, _ = redactE(t, `{"blob":"`+b+`"}`)
			if want := `{"blob":"` + m; !strings.HasPrefix(out, want) || len(out) > len(want)+2 {
				t.Errorf("JSON value: got %q, want %q", lastN(out, 80), want+`"}`)
			}
			assertNoLeak(t, name, out, b)
		})
	}
}

func b64Rule(t *testing.T) detector {
	t.Helper()
	for _, d := range defaultRules() {
		if d.id == "pem-private-key-b64" {
			return d
		}
	}
	t.Fatal("no pem-private-key-b64 rule")
	return detector{}
}

// AC60: a 1 MiB base64 run that starts with the BEGIN prefix is decoded only
// up to 96 characters (decoder input counter). The whole run is replaced.
func TestB64DecoderIsBounded(t *testing.T) {
	d := b64Rule(t)
	_ = testRedactor()
	payload := make([]byte, 3*(1<<18)) // 768 KiB, a multiple of 3: no padding
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	head := []byte(strings.Repeat("-", 5) + "BEGIN " + pemType("RSA") + strings.Repeat("-", 5) + "\n")
	copy(payload, head)
	run := base64.StdEncoding.EncodeToString(payload)
	if len(run) < 1<<20 {
		t.Fatalf("test setup: run is %d bytes", len(run))
	}
	var calls, total, largest int
	setHooks(t, nil, func(n int) {
		calls++
		total += n
		largest = max(largest, n)
	}, nil)
	spans, err := d.find(run)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if calls == 0 {
		t.Errorf("the b64 decoder hook was never called")
	}
	if largest > 96 || total > 96 {
		t.Errorf("decoded %d characters in total (largest call %d), want at most 96", total, largest)
	}
	if len(spans) != 1 || spans[0].start != 0 || spans[0].end != len(run) {
		t.Errorf("spans %v, want the whole run [0,%d)", spans, len(run))
	}
}

// The same bound through the pipeline (with the post-check): a 15 KiB run in
// one line, under REDACT_MAX_LINE.
func TestB64DecoderBoundInPipeline(t *testing.T) {
	red := testRedactor()
	k := getKeys(t)
	var run string
	for len(run) < 15<<10 {
		run += base64.RawStdEncoding.EncodeToString([]byte(k.rsaPEM))
	}
	run = run[:15<<10]
	var largest, total int
	setHooks(t, nil, func(n int) {
		largest = max(largest, n)
		total += n
	}, nil)
	out, _, err := red.Redact(context.Background(), fieldFor(EText), run, nil)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if out != Marker("pem-private-key-b64") {
		t.Errorf("got %q", lastN(out, 80))
	}
	if largest > 96 || total > 2*96 {
		t.Errorf("decoder input: largest call %d, total %d; want <= 96 per candidate", largest, total)
	}
}

// AC39: a P4 messages[] group holding a key across messages. The marker goes
// in the first message of the span; the covered later messages are emptied.
func TestPEMGroupAcrossMessages(t *testing.T) {
	k := getKeys(t)
	first := "nginx: [emerg] cannot load key in /etc/nginx/tls.conf:"
	last := "nginx: configuration file /etc/nginx/nginx.conf test failed."
	msgs := append([]string{first}, pemLines(k.rsaPEM)...)
	msgs = append(msgs, last)
	out, rep, err := testRedactor().RedactGroup(context.Background(), fieldFor(TText), msgs, nil)
	if err != nil {
		t.Fatalf("RedactGroup: %v", err)
	}
	if len(out) != len(msgs) {
		t.Fatalf("got %d messages, want %d", len(out), len(msgs))
	}
	want := make([]string, len(msgs))
	want[0] = first
	want[1] = Marker("pem-private-key")
	want[len(want)-1] = last
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("message %d = %q, want %q", i, out[i], want[i])
		}
	}
	if rep.Replaced["pem-private-key"] < 1 {
		t.Errorf("Replaced[pem-private-key] = %d", rep.Replaced["pem-private-key"])
	}
	assertNoLeak(t, "group", strings.Join(out, "\n"), pemBody(k.rsaPEM)...)
}

// pem-body-line applies to the P4 group: body lines alone, one per message.
func TestPEMGroupBodyLinesOnly(t *testing.T) {
	k := getKeys(t)
	part := pemBody(k.rsaPEM)[2:9]
	msgs := append([]string{"nginx: [emerg] bad value:"}, part...)
	msgs = append(msgs, "nginx: test failed.")
	out, _, err := testRedactor().RedactGroup(context.Background(), fieldFor(TText), msgs, nil)
	if err != nil {
		t.Fatalf("RedactGroup: %v", err)
	}
	if len(out) != len(msgs) {
		t.Fatalf("got %d messages, want %d", len(out), len(msgs))
	}
	if out[0] != msgs[0] || out[len(out)-1] != msgs[len(msgs)-1] {
		t.Errorf("messages around the body changed")
	}
	assertNoLeak(t, "group body", strings.Join(out, "\n"), part...)
}
