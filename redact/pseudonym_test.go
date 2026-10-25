package redact

// User-name pseudonyms (R12a, R12c, R12d, ruling 4, AC28 partial).

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	homeLabel = "warden/agent-home-user/v1"
	dbLabel   = "warden/agent-db-user/v1"
)

// wantPseudonym computes R12a's pseudonym independently of the package.
func wantPseudonym(key [32]byte, label, name string) string {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(label))
	m.Write([]byte{0})
	m.Write([]byte(name))
	return "u-" + hex.EncodeToString(m.Sum(nil)[:8])
}

func randKey(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

// AC28: /home/<C24>/x becomes /home/u-<16 hex>/x with the same pseudonym in
// every class and every call.
func TestHomePseudonymAllClasses(t *testing.T) {
	key := randKey(t)
	p := NewPseudonymizer(key)
	name := c24Name()
	want := wantPseudonym(key, homeLabel, name)
	for _, c := range scannedClasses {
		for i := 0; i < 2; i++ {
			out, rep := mustRedact(t, fieldFor(c), "/home/"+name+"/x", p)
			if out != "/home/"+want+"/x" {
				t.Errorf("%s call %d: got %q, want %q", className(c), i, out, "/home/"+want+"/x")
			}
			if rep.Pseudonymised != 1 || rep.UserNameMarkers != 0 {
				t.Errorf("%s: Pseudonymised %d, UserNameMarkers %d", className(c), rep.Pseudonymised, rep.UserNameMarkers)
			}
			if rep.MarkerFired {
				t.Errorf("%s: a pseudonym set MarkerFired", className(c))
			}
			assertNoLeak(t, className(c), out, name)
		}
	}
	// A second Redactor and a second Pseudonymizer with the same key agree.
	out, _, err := New(WithClock(frozenClock)).Redact(bg, fieldFor(EText), "/home/"+name+"/x", NewPseudonymizer(key))
	if err != nil || out != "/home/"+want+"/x" {
		t.Errorf("another Redactor: (%q, %v)", out, err)
	}
	// Another key gives another pseudonym.
	out, _ = mustRedact(t, fieldFor(EText), "/home/"+name+"/x", NewPseudonymizer(randKey(t)))
	if out == "/home/"+want+"/x" {
		t.Errorf("a different key gave the same pseudonym")
	}
}

// AC28: a P9 session user named C24 gets the other label's pseudonym.
func TestDBUserPseudonym(t *testing.T) {
	key := randKey(t)
	p := NewPseudonymizer(key)
	name := c24Name()
	f := Field{Class: TName, MaxBytes: typedMax, DBUser: true}
	out, rep := mustRedact(t, f, name, p)
	want := wantPseudonym(key, dbLabel, name)
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
	if want == wantPseudonym(key, homeLabel, name) {
		t.Fatalf("test setup: labels give the same value")
	}
	if rep.Pseudonymised != 1 {
		t.Errorf("Pseudonymised = %d", rep.Pseudonymised)
	}
	out, rep = mustRedact(t, f, name, nil)
	if out != NameUserNameMarker || rep.UserNameMarkers != 1 || rep.Pseudonymised != 0 {
		t.Errorf("nil Pseudonymizer: (%q, %+v)", out, rep)
	}
	for _, kept := range []string{"u-0123456789abcdef", NameUserNameMarker} {
		out, rep = mustRedact(t, f, kept, p)
		if out != kept || rep.Pseudonymised != 0 || rep.UserNameMarkers != 0 {
			t.Errorf("%q: changed to %q", kept, out)
		}
	}
	out, _ = mustRedact(t, f, name[:5]+r(0x200B)+name[5:], p)
	if out != want {
		t.Errorf("name with a zero-width char: got %q, want %q", out, want)
	}
}

// R12a item 2: the first component of a P2 path under a /home request root.
func TestHomeRootRelativePath(t *testing.T) {
	key := randKey(t)
	p := NewPseudonymizer(key)
	name := c24Name()
	want := wantPseudonym(key, homeLabel, name)
	f := Field{Class: TPath, MaxBytes: typedMax, HomeRoot: true}
	for in, exp := range map[string]string{
		name + "/docs/a.txt":          want + "/docs/a.txt",
		name:                          want,
		"u-0123456789abcdef/docs":     "u-0123456789abcdef/docs",
		NameUserNameMarker + "/a.txt": NameUserNameMarker + "/a.txt",
		name + "/home/" + name + "/x": want + "/home/" + name + "/x",
	} {
		out, _ := mustRedact(t, f, in, p)
		if in == name+"/home/"+name+"/x" {
			// The second /home/ does not start the path: only the first
			// component is a user name here.
			if !strings.HasPrefix(out, want+"/") {
				t.Errorf("%q: got %q", in, out)
			}
			continue
		}
		if out != exp {
			t.Errorf("%q: got %q, want %q", in, out, exp)
		}
	}
	out, rep := mustRedact(t, f, name+"/docs/a.txt", nil)
	if out != NameUserNameMarker+"/docs/a.txt" || rep.UserNameMarkers != 1 {
		t.Errorf("nil Pseudonymizer: (%q, %d)", out, rep.UserNameMarkers)
	}
	// Without HomeRoot a relative path is untouched.
	out, rep = mustRedact(t, Field{Class: TPath, MaxBytes: typedMax}, name+"/docs/a.txt", p)
	if out != name+"/docs/a.txt" || rep.Pseudonymised != 0 {
		t.Errorf("without HomeRoot: got %q", out)
	}
}

// R12c, R12d: with no key the name becomes the class's user-name marker.
func TestHomeNilPseudonymizer(t *testing.T) {
	name := c24Name()
	for _, c := range scannedClasses {
		out, rep := mustRedact(t, fieldFor(c), "/home/"+name+"/x", nil)
		if want := "/home/" + classUserMarker(c) + "/x"; out != want {
			t.Errorf("%s: got %q, want %q", className(c), out, want)
		}
		if rep.UserNameMarkers != 1 || rep.Pseudonymised != 0 {
			t.Errorf("%s: UserNameMarkers %d, Pseudonymised %d", className(c), rep.UserNameMarkers, rep.Pseudonymised)
		}
		if rep.MarkerFired {
			t.Errorf("%s: a user-name marker set MarkerFired", className(c))
		}
		assertNoLeak(t, className(c), out, name)
	}
}

func TestHomeKeptForms(t *testing.T) {
	p := NewPseudonymizer(randKey(t))
	for _, c := range scannedClasses {
		for _, in := range []string{
			"/home/u-0123456789abcdef/x",
			"/home/" + UserNameMarker + "/x",
			"/home/" + NameUserNameMarker + "/x",
			"/root/x",
			"/srv/home/x",
			"srv/home/x",
			"/var/lib/home/x",
			"/homes/x",
			"/home",
		} {
			for _, pz := range []*Pseudonymizer{p, nil} {
				out, rep := mustRedact(t, fieldFor(c), in, pz)
				if out != in {
					t.Errorf("%s: %q changed to %q", className(c), in, out)
				}
				if rep.Pseudonymised != 0 || rep.UserNameMarkers != 0 {
					t.Errorf("%s: %q counted a user name", className(c), in)
				}
			}
		}
	}
}

// Almost-pseudonyms are names like any other.
func TestHomeNotQuitePseudonym(t *testing.T) {
	key := randKey(t)
	p := NewPseudonymizer(key)
	for _, n := range []string{"u-0123456789ABCDEF", "u-0123456789abcde", "u-0123456789abcdef0", "u-0123456789abcdeg"} {
		out, _ := mustRedact(t, fieldFor(EText), "/home/"+n+"/x", p)
		if want := "/home/" + wantPseudonym(key, homeLabel, n) + "/x"; out != want {
			t.Errorf("%q: got %q, want %q", n, out, want)
		}
	}
}

// R12a: where /home/ starts a path, and ruling 4: where the name ends.
func TestHomeStartAndEnd(t *testing.T) {
	key := randKey(t)
	p := NewPseudonymizer(key)
	name := c24Name()
	ps := wantPseudonym(key, homeLabel, name)
	for _, c := range []Class{EText, TText, TName, LValue} {
		for _, pre := range []string{"", "open ", `path="`, "path='", "HOME=", "cwd:", "(", "[", "a,", "a;"} {
			in := pre + "/home/" + name + "/x"
			out, _ := mustRedact(t, fieldFor(c), in, p)
			if want := pre + "/home/" + ps + "/x"; out != want {
				t.Errorf("%s start %q: got %q, want %q", className(c), pre, out, want)
			}
		}
		for _, end := range []string{"/", " ", `"`, "'", "`", ",", ";", ":", "(", ")", "[", "]", "{", "}", "<", ">", "=", "&", "|"} {
			in := "/home/" + name + end + "rest"
			out, _ := mustRedact(t, fieldFor(c), in, p)
			if want := "/home/" + ps + end + "rest"; out != want {
				t.Errorf("%s end %q: got %q, want %q", className(c), end, out, want)
			}
		}
		out, _ := mustRedact(t, fieldFor(c), "/home/"+name, p)
		if out != "/home/"+ps {
			t.Errorf("%s at end of input: got %q", className(c), out)
		}
		for _, notStart := range []string{"x/home/" + name + "/y", "/data/home/" + name + "/y"} {
			out, _ := mustRedact(t, fieldFor(c), notStart, p)
			if out != notStart {
				t.Errorf("%s: %q is not a home path, changed to %q", className(c), notStart, out)
			}
		}
	}
	// TAB starts a path in E-TEXT, where it is kept.
	out, _ := mustRedact(t, fieldFor(EText), "cd\t/home/"+name+"/x", p)
	if out != "cd\t/home/"+ps+"/x" {
		t.Errorf("after TAB: got %q", out)
	}
}

// R12a: the name is pseudonymised from its normalised bytes.
func TestPseudonymFromNormalisedName(t *testing.T) {
	key := randKey(t)
	p := NewPseudonymizer(key)
	name := c24Name()
	want := "/home/" + wantPseudonym(key, homeLabel, name) + "/x"
	for label, in := range map[string]string{
		"zero-width":  "/home/" + name[:4] + r(0x200B) + name[4:] + "/x",
		"ANSI":        "/home/" + name[:4] + "\x1b[0m" + name[4:] + "/x",
		"invalid":     "/home/" + name[:4] + "\xff" + name[4:] + "/x",
		"tag char":    "/home/" + name[:4] + r(0xE0041) + name[4:] + "/x",
		"soft hyphen": "/home/" + name[:4] + r(0x00AD) + name[4:] + "/x",
	} {
		out, _ := mustRedact(t, fieldFor(EText), in, p)
		if out != want {
			t.Errorf("%s: got %q, want %q", label, out, want)
		}
	}
}

func TestPseudonymCounts(t *testing.T) {
	p := NewPseudonymizer(randKey(t))
	a, b := c24Name(), c24Name()
	_, rep := mustRedact(t, fieldFor(EText), "cp /home/"+a+"/x /home/"+b+"/y", p)
	if rep.Pseudonymised != 2 {
		t.Errorf("Pseudonymised = %d, want 2", rep.Pseudonymised)
	}
	_, rep = mustRedact(t, fieldFor(EText), "cp /home/"+a+"/x /home/"+b+"/y", nil)
	if rep.UserNameMarkers != 2 {
		t.Errorf("UserNameMarkers = %d, want 2", rep.UserNameMarkers)
	}
}

// The pseudonym and the user-name marker are never themselves redacted, and
// a pseudonymised output is a fixed point.
func TestPseudonymFixedPoint(t *testing.T) {
	p := NewPseudonymizer(randKey(t))
	for _, c := range scannedClasses {
		out, _ := mustRedact(t, fieldFor(c), "/home/"+c24Name()+"/x", p)
		again, rep := mustRedact(t, fieldFor(c), out, p)
		if again != out || rep.Pseudonymised != 0 {
			t.Errorf("%s: second pass changed %q to %q", className(c), out, again)
		}
	}
}
