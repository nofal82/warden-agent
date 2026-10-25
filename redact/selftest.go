package redact

import "regexp"

// unitNamePattern is the systemd service unit pattern of typed-action-catalog
// §4.2 that a redacted unit name must still match (R11).
var unitNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,240}\.service$`)

// selfTest runs every detector over its built-in samples (R42): each
// positive sample must match and no negative sample may.
func selfTest(rules []detector) bool {
	if len(rules) == 0 {
		return false
	}
	for i := range rules {
		if !detectorPasses(&rules[i]) {
			return false
		}
	}
	return true
}

func detectorPasses(d *detector) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if d.find == nil {
		return false
	}
	if d.samples == nil {
		return true
	}
	pos, neg := d.samples()
	for _, s := range pos {
		if spans, err := d.find(s); err != nil || len(spans) == 0 {
			return false
		}
	}
	for _, s := range neg {
		if spans, err := d.find(s); err != nil || len(spans) != 0 {
			return false
		}
	}
	return true
}
