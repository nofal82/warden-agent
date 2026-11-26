package trustdoc

import (
	"crypto/sha256"
	"crypto/subtle"
	"math"
	"regexp"
	"strings"
	"time"

	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// MaxSkew is MAX_SKEW of action-envelope R16, in seconds: a manifest issued
// up to this far in the verifier's future is still accepted (R34). This is
// the manifest verifier's own copy (ceremony note 12.1); TestMaxSkewDrift
// in internal/envelope reads it from this file and fails the build when it
// differs from the contract's max_skew_seconds option (agent-api AC52).
// Keep it an integer literal.
const MaxSkew = 60

// List limits of §4.6.
const (
	maxPlaybooks        = 64
	maxUnfreeze         = 64
	maxBackupUnits      = 8
	maxAdminListedUnits = 32
	postRecoveryLen     = 24
)

var (
	// Server UUID v4 in lowercase canonical form (agent-identity §4.1).
	uuidV4RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	// Playbook id (action-envelope §4.2).
	playbookIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	// systemd service unit (typed-action-catalog §4.2).
	serviceUnitRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,240}\.service$`)
)

// Catalog is the installed, verified playbook catalog as the manifest check
// needs it. MaxActStepsPerHour returns the catalog's effective value for
// the playbook (3 when the catalog omits it, §4.5) and false when the
// playbook is not in the catalog.
type Catalog interface {
	MaxActStepsPerHour(playbookID string) (uint32, bool)
}

// ManifestConfig is the verifier's own trusted state; nothing in it comes
// from the sender of the manifest.
type ManifestConfig struct {
	// Keyset is the installed, verified keyset. Nil refuses every manifest
	// (trust state unavailable, D5).
	Keyset *Keyset
	// Catalog is the installed catalog. Nil refuses a manifest that enables
	// any playbook.
	Catalog Catalog
	// ServerID is this server's UUID from its own root-owned file.
	ServerID string
	// Now is the verifier's wall clock.
	Now func() time.Time
}

// Manifest is a server manifest that passed VerifyManifest. Body is the
// verifier's own decoded copy; callers treat it as read-only, as with
// envelope.Verified.
type Manifest struct {
	Body *wardenv1.ManifestBody
	// KeyID is the SHA-256 of the raw manifest-role key that signed it.
	KeyID [sha256.Size]byte
	// Hash is the R7 document hash, SHA-256(DOMAIN || 0x00 || body).
	Hash [sha256.Size]byte
}

// VerifyManifest verifies raw as a server manifest for this server (§4.6,
// action-envelope R34). The sequence number and the recovery marker are
// for the executor's store to judge (R34a, R37). Every failure is a
// *Rejection with CodeManifestInvalid (action-envelope D5).
func VerifyManifest(raw []byte, cfg ManifestConfig) (*Manifest, error) {
	m, reason := verifyManifest(raw, cfg)
	if reason != "" {
		return nil, reject(CodeManifestInvalid, reason)
	}
	return m, nil
}

func verifyManifest(raw []byte, cfg ManifestConfig) (*Manifest, string) {
	if cfg.Keyset == nil || cfg.Now == nil || !uuidV4RE.MatchString(cfg.ServerID) {
		return nil, "trust state unavailable"
	}
	doc, reason := openOuter(raw, MaxManifestBytes)
	if reason != "" {
		return nil, reason
	}
	now := cfg.Now().Unix()
	key, ok := manifestKey(cfg.Keyset, doc.GetKeyId(), now)
	if !ok {
		return nil, "not signed by a manifest-role key valid now"
	}
	body := new(wardenv1.ManifestBody)
	hash, reason := verifyAndDecode(key.PublicKey, DomainManifest, doc, body)
	if reason != "" {
		return nil, reason
	}
	if reason := checkManifestBody(body, cfg, now); reason != "" {
		return nil, reason
	}
	return &Manifest{Body: body, KeyID: sha256.Sum256(key.PublicKey), Hash: hash}, ""
}

// manifestKey finds the manifest-role key whose key_id (SHA-256 of the raw
// key, R10) is id and whose validity contains now. Envelope-role keys are
// never searched, and the keyset's checkpoint keys are not reachable.
func manifestKey(ks *Keyset, id []byte, now int64) (SigningKey, bool) {
	for _, k := range ks.manifest {
		kid := sha256.Sum256(k.PublicKey)
		if subtle.ConstantTimeCompare(kid[:], id) == 1 && k.validAt(now) {
			return k, true
		}
	}
	return SigningKey{}, false
}

func checkManifestBody(b *wardenv1.ManifestBody, cfg ManifestConfig, now int64) string {
	switch {
	case b.GetFormatVersion() != 1:
		return "unsupported format_version"
	case b.GetServerId() != cfg.ServerID:
		return "wrong server"
	case b.GetSequence() < 1 || b.GetSequence() > math.MaxInt64:
		return "sequence out of range"
	// issued_at is range-checked first and then compared as
	// issued_at − MaxSkew > now, which cannot overflow whatever now is.
	case b.GetIssuedAt() < 1 || b.GetIssuedAt() > maxTime:
		return "issued_at out of range"
	case b.GetIssuedAt()-MaxSkew > now:
		return "issued_at later than now + MAX_SKEW"
	case len(b.GetPostRecovery()) != 0 && len(b.GetPostRecovery()) != postRecoveryLen:
		return "post_recovery is neither empty nor 24 bytes"
	}
	if r := checkPlaybooks(b.GetPlaybooks(), cfg.Catalog); r != "" {
		return r
	}
	if !idList(b.GetUnfreeze(), maxUnfreeze) {
		return "malformed unfreeze list"
	}
	if !unitList(b.GetBackupUnits(), maxBackupUnits) {
		return "malformed backup_units list"
	}
	if !unitList(b.GetAdminListedUnits(), maxAdminListedUnits) {
		return "malformed admin_listed_units list"
	}
	return ""
}

func checkPlaybooks(pbs []*wardenv1.EnabledPlaybook, cat Catalog) string {
	if len(pbs) > maxPlaybooks {
		return "too many playbooks"
	}
	for i, p := range pbs {
		id := p.GetPlaybookId()
		if !playbookIDRE.MatchString(id) || (i > 0 && pbs[i-1].GetPlaybookId() >= id) {
			return "playbook id malformed, unsorted or duplicated"
		}
		switch p.GetAutonomyCeiling() {
		case wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L0, wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L1,
			wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L2, wardenv1.AutonomyLevel_AUTONOMY_LEVEL_L3:
		default:
			return "invalid autonomy_ceiling"
		}
		if cat == nil {
			return "no installed catalog"
		}
		limit, ok := cat.MaxActStepsPerHour(id)
		if !ok {
			return "playbook not in the installed catalog"
		}
		if p.MaxActStepsPerHour != nil && (p.GetMaxActStepsPerHour() < 1 || p.GetMaxActStepsPerHour() > limit) {
			return "max_act_steps_per_hour out of range"
		}
	}
	return ""
}

func idList(ids []string, limit int) bool {
	if len(ids) > limit || !sortedStrings(ids) {
		return false
	}
	for _, id := range ids {
		if !playbookIDRE.MatchString(id) {
			return false
		}
	}
	return true
}

// unitList accepts exact canonical service unit names only: no `..` and
// no template entry such as name@.service (§4.6, OQ15).
func unitList(units []string, limit int) bool {
	if len(units) > limit || !sortedStrings(units) {
		return false
	}
	for _, u := range units {
		if !serviceUnitRE.MatchString(u) || strings.Contains(u, "..") || strings.HasSuffix(u, "@.service") {
			return false
		}
	}
	return true
}
