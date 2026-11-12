package logs

import (
	"regexp"
	"strings"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
)

// RulesVersion is the version of the M1 log rule set. Raise it on every
// change to Rules. It is shown locally only: the contract has no field for
// it (the HealthReport carries the redaction rule version).
const RulesVersion uint32 = 1

// Rule is one log source of the fixed rule set.
type Rule struct {
	// ID is LogEvent.rule_id.
	ID string
	// Dir is the absolute, clean directory holding the files, or, with
	// SubDir, the directory holding the version directories.
	Dir string
	// SubDir, when set, selects version directories under Dir (PGDG
	// PostgreSQL: /var/lib/pgsql/<major>); the files are then under
	// Dir/<match>/SubPath.
	SubDir  *regexp.Regexp
	SubPath string
	// File is an anchored pattern over the file's base name.
	File *regexp.Regexp
	// Unit is the unit_id template: "$1" is the File submatch, or the
	// SubDir submatch for a SubDir rule.
	Unit string
	// Match selects the lines that become events.
	Match *regexp.Regexp
}

var (
	reNginx   = regexp.MustCompile(`\[(?:emerg|alert|crit|error)\]`)
	reApache  = regexp.MustCompile(`\[[a-z_0-9]*:(?:emerg|alert|crit|error)\]`)
	rePHP     = regexp.MustCompile(`\] (?:ERROR|ALERT|EMERGENCY): `)
	reMySQL   = regexp.MustCompile(`\[ERROR\]`)
	rePG      = regexp.MustCompile(`(?:ERROR|FATAL|PANIC): `)
	literal   = func(s string) *regexp.Regexp { return regexp.MustCompile(`^` + regexp.QuoteMeta(s) + `$`) }
	pgWeekday = regexp.MustCompile(`^postgresql-(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\.log$`)
)

// rules is the M1 rule set. Paths are the package defaults of Ubuntu
// 20.04+, Debian 11+ and RHEL/Rocky/Alma 8+.
var rules = []Rule{
	{ID: "nginx-error", Dir: "/var/log/nginx", File: literal("error.log"), Unit: "nginx.service", Match: reNginx},
	{ID: "apache-error", Dir: "/var/log/apache2", File: literal("error.log"), Unit: "apache2.service", Match: reApache},
	{ID: "httpd-error", Dir: "/var/log/httpd", File: literal("error_log"), Unit: "httpd.service", Match: reApache},
	{ID: "php-fpm-error", Dir: "/var/log", File: regexp.MustCompile(`^php([5-9]\.[0-9])-fpm\.log$`), Unit: "php$1-fpm.service", Match: rePHP},
	{ID: "php-fpm-rhel-error", Dir: "/var/log/php-fpm", File: literal("error.log"), Unit: "php-fpm.service", Match: rePHP},
	{ID: "mysql-error", Dir: "/var/log/mysql", File: literal("error.log"), Unit: "mysql.service", Match: reMySQL},
	{ID: "mysqld-rhel-error", Dir: "/var/log/mysql", File: literal("mysqld.log"), Unit: "mysqld.service", Match: reMySQL},
	{ID: "mariadb-rhel-error", Dir: "/var/log/mariadb", File: literal("mariadb.log"), Unit: "mariadb.service", Match: reMySQL},
	{ID: "postgresql-error", Dir: "/var/log/postgresql", File: regexp.MustCompile(`^postgresql-([1-9][0-9]?)-main\.log$`), Unit: "postgresql@$1-main.service", Match: rePG},
	{ID: "postgresql-rhel-error", Dir: "/var/lib/pgsql/data/log", File: pgWeekday, Unit: "postgresql.service", Match: rePG},
	{ID: "postgresql-pgdg-error", Dir: "/var/lib/pgsql", SubDir: regexp.MustCompile(`^([1-9][0-9])$`), SubPath: "data/log", File: pgWeekday, Unit: "postgresql-$1.service", Match: rePG},
}

// Rules returns a copy of the fixed M1 rule set.
func Rules() []Rule { return append([]Rule(nil), rules...) }

// UnitFor returns the unit_id for a file base name of r and whether the
// name is one of r's files. A SubDir rule needs its version directory and
// never matches here.
func (r Rule) UnitFor(base string) (string, bool) {
	if r.SubDir != nil {
		return "", false
	}
	return r.unitFor("", base)
}

func (r Rule) unitFor(sub, base string) (string, bool) {
	if r.File == nil || len(base) > 255 {
		return "", false
	}
	m := r.File.FindStringSubmatchIndex(base)
	if m == nil {
		return "", false
	}
	src, re := base, r.File
	if r.SubDir != nil {
		if m = r.SubDir.FindStringSubmatchIndex(sub); m == nil {
			return "", false
		}
		src, re = sub, r.SubDir
	}
	u := string(re.ExpandString(nil, r.Unit, src, m))
	if !agentapiv1.ValidUnitID(u) || strings.Contains(u, "..") {
		return "", false
	}
	return u, true
}

// Matches reports whether line is selected by r.
func (r Rule) Matches(line string) bool { return r.Match != nil && r.Match.MatchString(line) }
