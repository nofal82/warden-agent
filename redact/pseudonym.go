package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Pseudonymizer replaces user names by keyed pseudonyms (R12a). The caller
// loads the key; this package never reads it from anywhere (R12b).
type Pseudonymizer struct {
	key [32]byte
}

// NewPseudonymizer returns a pseudonymizer for the agent's 32-byte key.
func NewPseudonymizer(key [32]byte) *Pseudonymizer {
	return &Pseudonymizer{key: key}
}

// HMAC labels of R12a: they keep an operating-system user and a database
// user of the same name unlinkable.
const (
	labelHomeUser = "warden/agent-home-user/v1"
	labelDBUser   = "warden/agent-db-user/v1"
)

// pseudonym is "u-" and the lowercase hex of the first 8 bytes of
// HMAC-SHA-256(key, label || 0x00 || name). It is the only hash this
// package computes (R12).
func (p *Pseudonymizer) pseudonym(label, name string) string {
	m := hmac.New(sha256.New, p.key[:])
	m.Write([]byte(label))
	m.Write([]byte{0})
	m.Write([]byte(name))
	return "u-" + hex.EncodeToString(m.Sum(nil)[:8])
}

func isPseudonym(s string) bool {
	if len(s) != 18 || !strings.HasPrefix(s, "u-") {
		return false
	}
	return allLowerHex(s[2:])
}

// homeStartBefore are the characters after which "/home/" starts a path
// (R12a item 1).
const homeStartBefore = " \t\n\"'`=:([,;"

// homeNameEnd are the characters that end a user name after "/home/"
// (ruling on issue #9, point 4).
const homeNameEnd = "/ \t\n\"'`,;:()[]{}<>=&|"

// userNames applies R12a to one normalised field: it returns the text and
// the segments it inserted (markers may be shortened at a cut, R40).
func (ps *pass) userNames(s string, p *Pseudonymizer) (string, []seg) {
	if ps.f.MarkersOnly || ps.mode != modeField {
		return s, nil
	}
	nameMarker := UserNameMarker
	if ps.class == TName || ps.class == TPath {
		nameMarker = NameUserNameMarker
	}
	var b strings.Builder
	var segs []seg
	replace := func(name, label string) {
		if name == "" {
			return
		}
		if isPseudonym(name) || name == UserNameMarker || name == NameUserNameMarker {
			// Kept as it is, but still a unit the output limit may not cut
			// (R40), or a cut half would read as a raw name next time.
			segs = append(segs, seg{start: b.Len(), end: b.Len() + len(name), marker: !isPseudonym(name)})
			b.WriteString(name)
			return
		}
		r, marker := nameMarker, true
		if p != nil {
			r, marker = p.pseudonym(label, name), false
			ps.rep.Pseudonymised++
		} else {
			ps.rep.UserNameMarkers++
		}
		segs = append(segs, seg{start: b.Len(), end: b.Len() + len(r), marker: marker})
		b.WriteString(r)
	}
	switch {
	case ps.f.DBUser && ps.class == TName:
		replace(s, labelDBUser)
		return b.String(), segs
	case ps.f.HomeRoot && ps.class == TPath:
		first := s
		if i := strings.IndexByte(s, '/'); i >= 0 {
			first = s[:i]
		}
		replace(first, labelHomeUser)
		s = s[len(first):]
	}
	const home = "/home/"
	for {
		i := strings.Index(s, home)
		if i < 0 {
			break
		}
		start := i == 0 && b.Len() == 0 || i > 0 && strings.IndexByte(homeStartBefore, s[i-1]) >= 0
		b.WriteString(s[:i+len(home)])
		s = s[i+len(home):]
		if !start {
			continue
		}
		end := len(s)
		if j := strings.IndexAny(s, homeNameEnd); j >= 0 {
			end = j
		}
		replace(s[:end], labelHomeUser)
		s = s[end:]
	}
	b.WriteString(s)
	return b.String(), segs
}
