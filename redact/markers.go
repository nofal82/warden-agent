package redact

import "regexp"

var (
	pseudonymRe = regexp.MustCompile(`u-[0-9a-f]{16}`)
	uuidRe      = regexp.MustCompile(`[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`)
	hexRunRe    = regexp.MustCompile(`[0-9A-Fa-f]{32,}`)
	markerRe    = regexp.MustCompile(`^(?:\[REDACTED(?:-[a-z0-9-]+)?\]|redacted(?:-[a-z0-9-]+)?|REDACTED-[a-z0-9-]+(?:\.service)?)$`)
)

// isMarkerText reports whether t is exactly a §4.3 marker, a pseudonym or
// the dropped-line text. Such a value is never a match, so a value
// detector does not match its own output again (§4.3, R32).
func isMarkerText(t string) bool {
	switch t {
	case ReleaseVersionMarker, LineDroppedText:
		return true
	}
	return isPseudonym(t) || markerRe.MatchString(t)
}
