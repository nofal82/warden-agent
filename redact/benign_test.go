package redact

// Benign corpus (AC9, AC34 partial, R33, R63): synthetic web-server,
// database, systemd and kernel lines, benign unit names and every marker of
// section 4.3 must pass every class with zero changes and zero drops.

import (
	"embed"
	"strings"
	"testing"
)

//go:embed testdata/benign/*.txt
var benignFS embed.FS

func readLines(t *testing.T, name string) []string {
	t.Helper()
	b, err := benignFS.ReadFile("testdata/benign/" + name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s is empty", name)
	}
	return out
}

func logFiles() []string { return []string{"web.txt", "database.txt", "systemd.txt", "kernel.txt"} }

// checkUntouched fails unless the Report shows no change of any kind.
func checkUntouched(t *testing.T, where string, rep Report) {
	t.Helper()
	if n := replacedTotal(rep); n != 0 {
		t.Errorf("%s: %d replacements %v", where, n, rep.Replaced)
	}
	if rep.MarkerFired || rep.Pseudonymised != 0 || rep.UserNameMarkers != 0 || rep.LinesDropped != 0 || rep.LinesOmitted != 0 {
		t.Errorf("%s: report %+v", where, rep)
	}
	if rep.Normalised != (NormCounts{}) {
		t.Errorf("%s: normalisation counted %v", where, rep.Normalised)
	}
}

func benignInAllClasses(t *testing.T, where, in string) {
	t.Helper()
	p := NewPseudonymizer([32]byte{9})
	for _, c := range scannedClasses {
		f := fieldFor(c)
		if len(in) > f.MaxBytes {
			continue
		}
		for _, pz := range []*Pseudonymizer{nil, p} {
			out, rep, err := testRedactor().Redact(bg, f, in, pz)
			if err != nil {
				t.Errorf("%s %s: error %v", where, className(c), err)
				continue
			}
			if out != in {
				t.Errorf("%s %s: changed\n in  %q\n out %q", where, className(c), in, out)
			}
			checkUntouched(t, where+" "+className(c), rep)
		}
	}
}

func TestBenignLogLines(t *testing.T) {
	for _, file := range logFiles() {
		for i, l := range readLines(t, file) {
			benignInAllClasses(t, file+":"+itoa(i+1), l)
		}
	}
}

// The whole file as one multi-line E-TEXT event, and as one P4 group: no
// line is pulled into a key-body match by its neighbours.
func TestBenignMultiLine(t *testing.T) {
	for _, file := range logFiles() {
		lines := readLines(t, file)
		in := strings.Join(lines, "\n")
		out, rep := mustRedact(t, Field{Class: EText, MaxBytes: MaxEventInput}, in, nil)
		if out != in {
			t.Errorf("%s as one event changed: %q", file, firstDiff(in, out))
		}
		checkUntouched(t, file+" event", rep)
		gout, grep, err := testRedactor().RedactGroup(bg, fieldFor(TText), lines, nil)
		if err != nil {
			t.Errorf("%s group: %v", file, err)
			continue
		}
		if strings.Join(gout, "\n") != in {
			t.Errorf("%s as one group changed: %q", file, firstDiff(in, strings.Join(gout, "\n")))
		}
		checkUntouched(t, file+" group", grep)
	}
}

func TestBenignUnitNames(t *testing.T) {
	for _, u := range readLines(t, "units.txt") {
		out, rep, err := testRedactor().RedactUnitName(bg, u)
		if err != nil || out != u {
			t.Errorf("RedactUnitName(%q) = (%q, %v)", u, out, err)
		}
		checkUntouched(t, "unit "+u, rep)
		benignInAllClasses(t, "unit "+u, u)
		benignInAllClasses(t, "unit line "+u, "Oct 25 10:15:30 web1 systemd[1]: Started "+u+".")
		if hit, err := testRedactor().Scan(bg, u); err != nil || hit {
			t.Errorf("Scan(%q) = (%v, %v)", u, hit, err)
		}
	}
}

// AC9: the escaped template instance passes in E-TEXT (the form systemd
// shows in log lines).
func TestBenignEscapedUnitInEText(t *testing.T) {
	in := "Oct 25 10:15:46 web1 systemd[1]: Starting systemd-fsck@dev-disk-by" + bs + "x2duuid-0a1b2c3d.service - File System Check..."
	out, rep := redactE(t, in)
	if out != in {
		t.Errorf("changed to %q", out)
	}
	checkUntouched(t, "escaped unit", rep)
}

// Section 4.3, AC9: every marker, pseudonym and truncated network passes
// unchanged alone and after every key form, in every class.
func TestBenignMarkers(t *testing.T) {
	values := append(allMarkers(),
		"u-0123456789abcdef",
		"REDACTED-aws-access-key-id.service",
		// Not "postgresql@REDACTED-…​.service": that is a redacted unit name,
		// not a §4.3 marker, and after a key it is a value R33 redacts.
		"203.0.113.0/24", "2002:c000:200::/40", "2001:db8:1234::/48",
		"/home/u-0123456789abcdef/x", "/home/"+UserNameMarker+"/x", "/home/"+NameUserNameMarker+"/x",
	)
	keyForms := []func(string) string{
		func(m string) string { return "DB_PASSWORD=" + m },
		func(m string) string { return "password: " + m },
		func(m string) string { return `{"password":"` + m + `"}` },
		func(m string) string { return "x-api-key: " + m },
		func(m string) string { return "requirepass " + m },
		func(m string) string { return "IDENTIFIED BY '" + m + "'" },
		func(m string) string { return "Account" + "Key=" + m },
		func(m string) string { return "aws_secret_access_key = " + m },
		func(m string) string { return "Authorization: " + m },
		func(m string) string { return "Cookie: " + m },
		func(m string) string { return "https://h/x?token=" + m },
		func(m string) string { return "https://h/x?a=1&access_token=" + m },
		func(m string) string { return "postgresql://" + m + "@db/x" },
	}
	for _, v := range values {
		benignInAllClasses(t, "marker", v)
		if v == LineDroppedText || strings.HasPrefix(v, "/home/") || (strings.Contains(v, "/") && !strings.HasPrefix(v, "[")) {
			continue // the dropped-line text and paths are not values after a key
		}
		for _, kf := range keyForms {
			benignInAllClasses(t, "marker after key", kf(v))
		}
	}
	if out, _ := redactE(t, LineDroppedText); out != LineDroppedText {
		t.Errorf("dropped-line text changed: %q", out)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func firstDiff(a, b string) string {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return "at byte " + itoa(i) + ": ..." + b[max(0, i-20):min(len(b), i+40)]
		}
	}
	return "length " + itoa(len(a)) + " vs " + itoa(len(b))
}
