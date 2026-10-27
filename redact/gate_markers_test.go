package redact

// Reviewer nits of the 13th review and issue #14: "[REDACTED-public-ip]"
// is not an exact marker; RedactReleaseVersion keeps its report on an
// error; exact detector markers are never taken for user names (R12a,
// §4.3), so a redacted T-PATH is a fixed point.

import (
	"errors"
	"strings"
	"testing"
)

// Nit: public-ip never writes a marker (R34), so "[REDACTED-public-ip]" is
// not in the exact-marker set of §4.3: after a key it is a value like any
// other and is redacted.
func TestPublicIPMarkerIsNotExact(t *testing.T) {
	for _, c := range scannedClasses {
		for _, v := range []string{Marker("public-ip"), "redacted-public-ip", "REDACTED-public-ip", "REDACTED-public-ip.service"} {
			in := "DB_PASSWORD=" + v
			out, rep := mustRedact(t, fieldFor(c), in, nil)
			if want := "DB_PASSWORD=" + classMarker(c, "secret-assignment"); out != want {
				t.Errorf("%s: %q -> %q, want %q", className(c), in, out, want)
			}
			if rep.Replaced["secret-assignment"] != 1 {
				t.Errorf("%s: %q: Replaced[secret-assignment] = %d, want 1", className(c), in, rep.Replaced["secret-assignment"])
			}
		}
	}
	// The real markers of every other detector stay exact markers.
	for _, id := range markerDetectorIDs() {
		in := "DB_PASSWORD=" + Marker(id)
		if out, rep := redactE(t, in); out != in || replacedTotal(rep) != 0 {
			t.Errorf("%q changed to %q", in, out)
		}
	}
	for _, m := range allMarkers() {
		if strings.Contains(m, "public-ip") {
			t.Errorf("allMarkers() lists %q, which is not a §4.3 marker", m)
		}
	}
}

// Nit: on an error after normalisation started, RedactReleaseVersion still
// returns the fixed value and keeps its report (the counts gathered so
// far), so the caller can count what normalisation did.
func TestRedactReleaseVersionKeepsReportOnError(t *testing.T) {
	zw := r(0x200B)
	t.Run("detector error", func(t *testing.T) {
		bad := stubDetector("bad", func(s string) ([]span, error) {
			if strings.Contains(s, "FAIL") {
				return nil, errors.New("stub failure")
			}
			return findAll("zz")(s)
		}, []string{"zz"}, []string{"a"})
		red := newRedactor([]detector{bad}, WithClock(frozenClock))
		if err := red.Err(); err != nil {
			t.Fatalf("self-test: %v", err)
		}
		out, rep, err := red.RedactReleaseVersion(bg, "1.0.0-FA"+zw+"IL")
		if err == nil || !isKnownErr(err) {
			t.Fatalf("err = %v, want a section 4.9 error", err)
		}
		if out != ReleaseVersionMarker {
			t.Errorf("out = %q, want %q", out, ReleaseVersionMarker)
		}
		if rep.Normalised[NormZeroWidth] != 1 {
			t.Errorf("report zeroed on error: Normalised = %v, want ZERO_WIDTH 1", rep.Normalised)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		fc := newFakeClock(0)
		slow := stubDetector("slow", func(s string) ([]span, error) {
			fc.advance(2 * ItemDeadline)
			return findAll("zz")(s)
		}, []string{"zz"}, []string{"a"})
		after := stubDetector("after", findAll("yy"), []string{"yy"}, []string{"a"})
		red := newRedactor([]detector{slow, after}, WithClock(fc.now))
		if err := red.Err(); err != nil {
			t.Fatalf("self-test: %v", err)
		}
		out, rep, err := red.RedactReleaseVersion(bg, "1.2"+zw+".3")
		if !errors.Is(err, ErrDeadline) || out != ReleaseVersionMarker {
			t.Fatalf("(%q, %v), want (%q, ErrDeadline)", out, err, ReleaseVersionMarker)
		}
		if rep.Normalised[NormZeroWidth] != 1 {
			t.Errorf("report zeroed on error: Normalised = %v, want ZERO_WIDTH 1", rep.Normalised)
		}
	})
	t.Run("input too large is reported before normalisation", func(t *testing.T) {
		out, rep, err := testRedactor().RedactReleaseVersion(bg, strings.Repeat("1", ReleaseVersionMaxBytes+1))
		if !errors.Is(err, ErrInputTooLarge) || out != ReleaseVersionMarker {
			t.Errorf("(%q, %v), want ErrInputTooLarge and the fixed value", out, err)
		}
		if rep.Normalised != (NormCounts{}) || replacedTotal(rep) != 0 {
			t.Errorf("counts reported for an item never normalised: %+v", rep)
		}
	})
}

// ---------------------------------------------------------------------------
// Issue #14 (FuzzRedactTPath crash): "/wdn1_<43 zeros>" in a HomeRoot
// T-PATH becomes "redacted-warden-enrollment-token" (extend, ruling 6);
// redacting that again took the marker for a user name and pseudonymised
// it. An exact detector marker is skipped before the home and db-user
// rules (R12a, §4.3).

func issue14Input() string { return "/" + "wdn1" + "_" + strings.Repeat("0", 43) }

func TestIssue14HomeRootTokenFixedPoint(t *testing.T) {
	f := Field{Class: TPath, MaxBytes: typedMax, HomeRoot: true}
	for _, p := range []*Pseudonymizer{fuzzPseudonymizer, nil} {
		out, _, err := testRedactor().Redact(bg, f, issue14Input(), p)
		if err != nil || out != "redacted-warden-enrollment-token" {
			t.Fatalf("first pass: (%q, %v), want redacted-warden-enrollment-token", out, err)
		}
		again, rep, err := testRedactor().Redact(bg, f, out, p)
		if err != nil || again != out {
			t.Errorf("second pass: (%q, %v), want it unchanged", again, err)
		}
		if rep.Pseudonymised != 0 || rep.UserNameMarkers != 0 || replacedTotal(rep) != 0 || rep.MarkerFired {
			t.Errorf("second pass reported changes: %+v", rep)
		}
	}
}

// Every exact detector marker, in every place a user name is read, is kept
// with no pseudonym and no user-name marker counted.
func TestDetectorMarkersAreNotUserNames(t *testing.T) {
	type place struct {
		name string
		f    Field
		in   func(m string) string
	}
	places := []place{
		{"HomeRoot first component alone", Field{Class: TPath, MaxBytes: typedMax, HomeRoot: true}, func(m string) string { return m }},
		{"HomeRoot first component", Field{Class: TPath, MaxBytes: typedMax, HomeRoot: true}, func(m string) string { return m + "/x" }},
		{"/home/<marker>/x in T-PATH", fieldFor(TPath), func(m string) string { return "/home/" + m + "/x" }},
		{"/home/<marker>/x in T-NAME", fieldFor(TName), func(m string) string { return "/home/" + m + "/x" }},
		{"/home/<marker>/x in T-TEXT", fieldFor(TText), func(m string) string { return "open /home/" + m + "/x failed" }},
		{"/home/<marker>/x in E-TEXT", fieldFor(EText), func(m string) string { return "open /home/" + m + "/x failed" }},
		{"/home/<marker>/x in L-VALUE", fieldFor(LValue), func(m string) string { return "/home/" + m + "/x" }},
		{"DBUser T-NAME", Field{Class: TName, MaxBytes: typedMax, DBUser: true}, func(m string) string { return m }},
	}
	for _, id := range markerDetectorIDs() {
		for _, pl := range places {
			for _, p := range []*Pseudonymizer{fuzzPseudonymizer, nil} {
				in := pl.in("redacted-" + id)
				out, rep, err := testRedactor().Redact(bg, pl.f, in, p)
				if err != nil || out != in {
					t.Errorf("%s, %s (pseudonymizer %v): (%q, %v), want it unchanged", id, pl.name, p != nil, out, err)
					continue
				}
				if rep.Pseudonymised != 0 || rep.UserNameMarkers != 0 || replacedTotal(rep) != 0 {
					t.Errorf("%s, %s: reported %+v, want nothing", id, pl.name, rep)
				}
			}
		}
	}
	// A value that only looks like a marker is still a user name (§4.3:
	// only the exact text is skipped).
	f := Field{Class: TName, MaxBytes: typedMax, DBUser: true}
	for _, in := range []string{"redacted-not-a-detector", "redacted-email-x", "redacted-public-ip"} {
		out, rep, err := testRedactor().Redact(bg, f, in, fuzzPseudonymizer)
		if err != nil || out == in || rep.Pseudonymised != 1 {
			t.Errorf("DBUser %q: (%q, %v, pseudonymised %d), want a pseudonym", in, out, err, rep.Pseudonymised)
		}
	}
}

// Found by FuzzRedactTPathSmallLimit (corpus 9c4b46bc7b678b1e), a variant
// of issue #14: extend (ruling 6) takes the leading "/" into the span, so
// the marker becomes the start of the first component; with text after it
// on the same component ("<marker> x"), the second pass read the whole
// component as a user name and pseudonymised it. Whatever the first pass
// writes must be a fixed point (R32, AC37): no pseudonym, no user-name
// marker, no replacement on the second pass.
func TestIssue14MarkerWithTextInFirstComponent(t *testing.T) {
	tok := "wdn1" + "_" + strings.Repeat("0", 43)
	f := Field{Class: TPath, MaxBytes: typedMax, HomeRoot: true}
	for _, in := range []string{
		"/" + tok + " ",
		"/" + tok + " x",
		"/" + tok + " x/y",
		"/" + tok + ",x",
		"/" + tok + "\tx",
		"/" + tok + " " + akia(),
		"/" + akia() + " x",
	} {
		for _, p := range []*Pseudonymizer{fuzzPseudonymizer, nil} {
			out, _, err := testRedactor().Redact(bg, f, in, p)
			if err != nil {
				continue // dropping the item is fail-closed and allowed
			}
			if strings.Contains(out, tok) {
				t.Errorf("%q: token left in %q", in, out)
			}
			again, rep, err := testRedactor().Redact(bg, f, out, p)
			if err != nil || again != out {
				t.Errorf("%q (pseudonymizer %v): first pass %q, second pass (%q, %v): not a fixed point",
					in, p != nil, out, again, err)
				continue
			}
			if rep.Pseudonymised != 0 || rep.UserNameMarkers != 0 || replacedTotal(rep) != 0 {
				t.Errorf("%q: second pass over %q reported %+v", in, out, rep)
			}
		}
	}
}
