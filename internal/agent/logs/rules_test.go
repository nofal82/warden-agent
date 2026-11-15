package logs_test

// M1 fixed rule set (issue #44): file-name patterns are anchored over the
// base name and never match a traversal or a name carrying a separator;
// every derived unit matches the LogEvent.unit_id contract pattern.

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/logs"
)

func TestRulesFixedSet(t *testing.T) {
	rules := logs.Rules()
	var ids []string
	for _, r := range rules {
		ids = append(ids, r.ID)
		if !filepath.IsAbs(r.Dir) || filepath.Clean(r.Dir) != r.Dir {
			t.Errorf("%s: Dir %q is not absolute and clean", r.ID, r.Dir)
		}
		if r.File == nil || r.Match == nil {
			t.Fatalf("%s: nil File or Match", r.ID)
		}
	}
	want := []string{"apache-error", "httpd-error", "mariadb-rhel-error", "mysql-error", "mysqld-rhel-error",
		"nginx-error", "php-fpm-error", "php-fpm-rhel-error", "postgresql-error", "postgresql-pgdg-error", "postgresql-rhel-error"}
	slices.Sort(ids)
	if !slices.Equal(ids, want) {
		t.Errorf("rule IDs = %v, want %v", ids, want)
	}
	rules[0].ID = "tampered"
	rules[0].Dir = "/etc"
	for _, r := range logs.Rules() {
		if r.ID == "tampered" || r.Dir == "/etc" {
			t.Error("Rules returns shared state, not a copy")
		}
	}

	byID := map[string]logs.Rule{}
	for _, r := range logs.Rules() {
		byID[r.ID] = r
	}
	good := []struct{ id, base, unit string }{
		{"nginx-error", "error.log", "nginx.service"},
		{"apache-error", "error.log", "apache2.service"},
		{"httpd-error", "error_log", "httpd.service"},
		{"php-fpm-error", "php8.1-fpm.log", "php8.1-fpm.service"},
		{"php-fpm-rhel-error", "error.log", "php-fpm.service"},
		{"mysql-error", "error.log", "mysql.service"},
		{"mysqld-rhel-error", "mysqld.log", "mysqld.service"},
		{"mariadb-rhel-error", "mariadb.log", "mariadb.service"},
		{"postgresql-error", "postgresql-14-main.log", "postgresql@14-main.service"},
		{"postgresql-rhel-error", "postgresql-Mon.log", "postgresql.service"},
	}
	for _, g := range good {
		u, ok := byID[g.id].UnitFor(g.base)
		if !ok || u != g.unit {
			t.Errorf("%s.UnitFor(%q) = %q, %v; want %q", g.id, g.base, u, ok, g.unit)
		}
	}

	// Attack names: no rule may match them, whatever the rule.
	attacks := []string{
		"", ".", "..", "../error.log", "error.log/", "/error.log", "x/error.log", "error.log/..",
		"error.log.1", "error.log.gz", "error.log\x00", "error.log\n", " error.log", "error.log ",
		"error.log;reboot", "$(id).log", "`id`error.log", "-error.log", "--config=error.log",
		"php../-fpm.log", "php8.1/../-fpm.log", "php$(id)-fpm.log", "php8.1-fpm.log.1", "php8.1-fpm.log/x",
		"postgresql-../-main.log", "postgresql-14;id-main.log", "postgresql-1 4-main.log",
		"postgresql-14-main.log.1", "postgresql-14/../x-main.log", "postgresql-Mon.log\n",
		"error․log", "error．log", "erroŕ.log",
	}
	for _, r := range logs.Rules() {
		for _, a := range attacks {
			if u, ok := r.UnitFor(a); ok {
				t.Errorf("%s.UnitFor(%q) matched (unit %q)", r.ID, a, u)
			}
			if r.File.MatchString(a) {
				t.Errorf("%s.File matches %q", r.ID, a)
			}
		}
		// 10 KB names: refused, or a unit that still meets the contract.
		for _, long := range []string{"php" + strings.Repeat("9", 10<<10) + ".1-fpm.log",
			"postgresql-" + strings.Repeat("1", 10<<10) + "-main.log", strings.Repeat("a", 10<<10)} {
			if u, ok := r.UnitFor(long); ok && !agentapiv1.ValidUnitID(u) {
				t.Errorf("%s.UnitFor(10 KB name) = invalid unit of %d bytes", r.ID, len(u))
			}
		}
	}
}

func TestRuleMatchesSeverity(t *testing.T) {
	byID := map[string]logs.Rule{}
	for _, r := range logs.Rules() {
		byID[r.ID] = r
	}
	cases := []struct {
		id, line string
		want     bool
	}{
		{"nginx-error", "2026/11/12 10:00:00 [error] 1#1: *1 connect() failed", true},
		{"nginx-error", "2026/11/12 10:00:00 [crit] 1#1: open() failed", true},
		{"nginx-error", "2026/11/12 10:00:00 [alert] 1#1: worker exited", true},
		{"nginx-error", "2026/11/12 10:00:00 [emerg] 1#1: bind() failed", true},
		{"nginx-error", "2026/11/12 10:00:00 [warn] 1#1: conflicting server name", false},
		{"nginx-error", "2026/11/12 10:00:00 [notice] 1#1: signal process started", false},
		{"nginx-error", "", false},
		{"apache-error", "[Thu Nov 12 10:00:00.000000 2026] [core:error] [pid 1] AH00037: x", true},
		{"apache-error", "[Thu Nov 12 10:00:00.000000 2026] [mpm_prefork:notice] [pid 1] AH00163: x", false},
		{"php-fpm-error", "[12-Nov-2026 10:00:00] ERROR: unable to bind listening socket", true},
		{"php-fpm-error", "[12-Nov-2026 10:00:00] ALERT: oops", true},
		{"php-fpm-error", "[12-Nov-2026 10:00:00] EMERGENCY: oops", true},
		{"php-fpm-error", "[12-Nov-2026 10:00:00] NOTICE: fpm is running", false},
		{"php-fpm-error", "[12-Nov-2026 10:00:00] WARNING: [pool www] seems busy", false},
		{"mysql-error", "2026-11-12T10:00:00.000000Z 0 [ERROR] [MY-010119] [Server] Aborting", true},
		{"mysql-error", "2026-11-12T10:00:00.000000Z 0 [Warning] [MY-010068] [Server] x", false},
		{"mysql-error", "2026-11-12T10:00:00.000000Z 0 [Note] [MY-010311] [Server] x", false},
		{"mariadb-rhel-error", "2026-11-12 10:00:00 0 [ERROR] Can't start server", true},
		{"postgresql-error", "2026-11-12 10:00:00.000 UTC [1] ERROR:  relation \"x\" does not exist", true},
		{"postgresql-error", "2026-11-12 10:00:00.000 UTC [1] FATAL:  password authentication failed", true},
		{"postgresql-error", "2026-11-12 10:00:00.000 UTC [1] PANIC:  could not write", true},
		{"postgresql-error", "2026-11-12 10:00:00.000 UTC [1] LOG:  checkpoint starting", false},
		{"postgresql-error", "2026-11-12 10:00:00.000 UTC [1] WARNING:  out of shared memory", false},
	}
	for _, tc := range cases {
		r, ok := byID[tc.id]
		if !ok {
			t.Fatalf("no rule %s", tc.id)
		}
		if got := r.Matches(tc.line); got != tc.want {
			t.Errorf("%s.Matches(%q) = %v, want %v", tc.id, tc.line, got, tc.want)
		}
	}
}
