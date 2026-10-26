package agentapiv1_test

import (
	"regexp"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// TestValidUnitIDRejectsDotDot: typed-action-catalog §4.2 forbids ".." in
// a unit name; the pattern option alone accepts it, so the hand-written
// check is what stops it (security-reviewer MEDIUM-1 on PR #13).
func TestValidUnitIDRejectsDotDot(t *testing.T) {
	for _, s := range []string{
		"nginx..service",
		"a..b.service",
		"a...service",
		"x..y..z.service",
		"a.b..c.service",
	} {
		if agentapiv1.ValidUnitID(s) {
			t.Errorf("ValidUnitID(%q) = true, want false", s)
		}
	}
}

// TestUnitIDPatternAloneAcceptsDotDot shows the gap the code check closes:
// LogEvent.unit_id's pattern option matches a name with "..".
func TestUnitIDPatternAloneAcceptsDotDot(t *testing.T) {
	fd := (&agentapiv1.LogEvent{}).ProtoReflect().Descriptor().Fields().ByName("unit_id")
	re := regexp.MustCompile(proto.GetExtension(fd.Options(), wardenv1.E_Pattern).(string))
	for _, s := range []string{"nginx..service", "a..b.service"} {
		if !re.MatchString(s) {
			t.Errorf("pattern rejects %q; the code check would no longer be the only guard, update this test", s)
		}
	}
}

func TestValidUnitID(t *testing.T) {
	long := "a" + strings.Repeat("b", 240) + ".service" // 249 bytes, the pattern's longest
	for s, want := range map[string]bool{
		"nginx.service":              true,
		"a.b.service":                true,
		"systemd-journald@x.service": true,
		"A0:_.@-x.service":           true,
		long:                         true,
		"a" + strings.Repeat("b", 241) + ".service": false, // one over the pattern's bound
		"":                  false,
		".service":          false,
		"..service":         false,
		"-x.service":        false,
		"../etc.service":    false,
		"a/b.service":       false,
		`a\x2db.service`:    false,
		"nginx.socket":      false,
		"nginx.service\n":   false,
		"nginx.service.":    false,
		"nginx.service ":    false,
		"ngin\x00x.service": false,
		"nginx.service/..":  false,
		"énginx.service":    false,
	} {
		if got := agentapiv1.ValidUnitID(s); got != want {
			t.Errorf("ValidUnitID(%q) = %v, want %v", s, got, want)
		}
	}
}

// FuzzValidUnitID: whatever ValidUnitID accepts meets every rule of
// typed-action-catalog §4.2 and the field's 256-byte bound.
func FuzzValidUnitID(f *testing.F) {
	for _, s := range []string{
		"nginx.service", "a..b.service", "../x.service", "-x.service",
		"x.service\n", `a\x2db.service`, "a@b:c_d.e-f.service", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !agentapiv1.ValidUnitID(s) {
			return
		}
		switch {
		case len(s) > 256:
			t.Fatalf("accepted %d bytes", len(s))
		case strings.Contains(s, ".."):
			t.Fatalf("accepted %q with ..", s)
		case strings.ContainsAny(s, "/\\\x00\n"):
			t.Fatalf("accepted %q with a path, escape or control byte", s)
		case !strings.HasSuffix(s, ".service"):
			t.Fatalf("accepted %q without .service", s)
		case s[0] == '-' || s[0] == '.':
			t.Fatalf("accepted %q starting with %q", s, s[0])
		}
	})
}
