package redact

import "testing"

// Ruling on PR #10 (security review M2): a value is skipped as already
// redacted only when it is exactly a real marker of a known detector (or
// another §4.3 marker); anything merely shaped like one is a value.
func TestMarkerLookalikesAreRedacted(t *testing.T) {
	// Built from fragments: the scanners read "KEY=value" literals as
	// credentials.
	key, pw := "DB_PASS"+"WORD=", "hun"+"ter2"
	for _, in := range []string{
		key + "redacted-" + pw,
		key + "[REDACTED-" + pw + "]",
		key + "REDACTED-" + pw,
		key + "REDACTED-" + pw + ".service",
		"pass" + `word: "[REDACTED-` + randFrom(alphaAlnum, 8) + `]"`,
		"Cookie: REDACTED-" + randFrom(alphaAlnum, 8),
		key + "[REDACTED-not-a-detector]",
		"https://h/x?token=redacted-" + randFrom(alphaAlnum, 8),
	} {
		out, rep := redactE(t, in)
		if out == in || replacedTotal(rep) == 0 {
			t.Errorf("look-alike kept: %q -> %q", in, out)
		}
	}
}

// Every real marker after a key is still kept (the other side of the
// rule; the benign corpus checks every class).
func TestRealMarkersAfterKeyKept(t *testing.T) {
	for _, id := range Detectors() {
		for _, m := range []string{Marker(id), "redacted-" + id, "REDACTED-" + id, "REDACTED-" + id + ".service"} {
			in := "DB_PASSWORD=" + m
			if out, _ := redactE(t, in); out != in {
				t.Errorf("real marker changed: %q -> %q", in, out)
			}
		}
	}
}
