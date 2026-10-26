package redact

import "regexp"

var (
	pseudonymRe = regexp.MustCompile(`u-[0-9a-f]{16}`)
	uuidRe      = regexp.MustCompile(`[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`)
	hexRunRe    = regexp.MustCompile(`[0-9A-Fa-f]{32,}`)
)

// markerSet is every exact marker text of §4.3 for the given detector IDs:
// the per-class detector markers, the unit-name marker with and without
// its suffix, and the fixed markers. Only these are skipped as already
// redacted (ruling on PR #10): a value merely shaped like a marker
// ("redacted-abc123") is a value like any other.
func markerSet(ids []string) map[string]bool {
	set := map[string]bool{}
	for _, id := range ids {
		for _, m := range []string{Marker(id), "redacted-" + id, "REDACTED-" + id, "REDACTED-" + id + ".service"} {
			set[m] = true
		}
	}
	for _, m := range []string{ShortMarker, NameShortMarker, UserNameMarker, NameUserNameMarker,
		ReleaseVersionMarker, AuditFailureMarker, LineDroppedText} {
		set[m] = true
	}
	return set
}

// isMarkerText reports whether t is exactly a marker of this rule set or a
// pseudonym. Such a value is never a match, so a value detector does not
// match its own output again (§4.3, R32).
func (r *Redactor) isMarkerText(t string) bool {
	return r.markers[t] || isPseudonym(t)
}
