package envelope

import (
	"regexp"
	"strings"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// Field patterns from action-envelope §4.2. Go regexps are RE2 (linear
// time), and every input is length-bounded by MaxEnvelopeBytes.
var (
	uuidV7RE  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	uuidV4RE  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	uuidAnyRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	playbookIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	stepIDRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	idemKeyRE    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

	// SemVer 2.0.0 (semver.org's regular expression) without build metadata.
	semverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
		`(-(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*)?$`)
)

const (
	digestLen          = 32
	maxPlaybookVersion = 32
	minUnixTime        = 1
	maxUnixTime        = 1<<40 - 1 // R16
)

// bodyWithinLimits applies the §4.2 limits (check 5). format_version is left to
// check 6 (R14). The typed request's own fields are checked later by its
// primitive's validator (check 20); here it only has to be present.
func bodyWithinLimits(b *wardenv1.EnvelopeBody) bool {
	return uuidV7RE.MatchString(b.GetActionId()) &&
		uuidAnyRE.MatchString(b.GetTargetServerId()) &&
		playbookIDRE.MatchString(b.GetPlaybookId()) &&
		validPlaybookVersion(b.GetPlaybookVersion()) &&
		len(b.GetPlaybookDigest()) == digestLen &&
		stepIDRE.MatchString(b.GetStepId()) &&
		b.GetParams().GetRequest() != nil &&
		validPolicyDecision(b.GetPolicyDecision()) &&
		validTime(b.GetCreatedAt()) &&
		validTime(b.GetExpiresAt()) &&
		validIdempotencyKey(b.GetIdempotencyKey())
}

func validPlaybookVersion(s string) bool {
	return len(s) <= maxPlaybookVersion && semverRE.MatchString(s)
}

func validPolicyDecision(p *wardenv1.PolicyDecision) bool {
	if p == nil {
		return false
	}
	switch p.GetAutonomyLevel() {
	case wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L0, wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L1,
		wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L2, wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L3:
	default:
		return false
	}
	return uuidV4RE.MatchString(p.GetDecisionId()) &&
		len(p.GetPolicyBundleDigest()) == digestLen &&
		(p.GetApprovalId() == "" || uuidV4RE.MatchString(p.GetApprovalId()))
}

func validTime(t int64) bool {
	return minUnixTime <= t && t <= maxUnixTime
}

// validIdempotencyKey also refuses "..", which the character pattern
// alone would allow (Nofal, issue #3), so the key can never read as a path
// step wherever it is used.
func validIdempotencyKey(s string) bool {
	return idemKeyRE.MatchString(s) && !strings.Contains(s, "..")
}
