package redact

import (
	"regexp"
	"strings"
)

// The detectors' patterns are RE2 regexps (R30). RE2 cannot skip ahead
// through text when a pattern starts with a character class, \b or (?i),
// so such a pattern scans a 64 KiB extract at a few tens of MB/s. Where a
// pattern has a fixed part (a literal, a digit, a separator), the byte
// search below finds the places where a match can start and the pattern
// runs anchored ("^...") at each of them. A match is the same as the
// unanchored pattern's; only the scanning is cheaper.

// anchored compiles pattern so that it only matches at the start.
func anchored(pattern string) *regexp.Regexp {
	return regexp.MustCompile(`^(?:` + pattern + `)`)
}

// matchAt runs an anchored re at s[i:] and returns its submatch offsets
// made absolute, or nil.
func matchAt(re *regexp.Regexp, s string, i int) []int {
	m := re.FindStringSubmatchIndex(s[i:])
	if m == nil {
		work(1)
	} else {
		work(1 + m[1])
	}
	for k := range m {
		if m[k] >= 0 {
			m[k] += i
		}
	}
	return m
}

// eachIndex calls fn with the offset of every occurrence of lit in s.
func eachIndex(s, lit string, fn func(i int)) {
	for from := 0; from <= len(s)-len(lit); {
		i := strings.Index(s[from:], lit)
		if i < 0 {
			work(len(s) - from)
			return
		}
		work(i + 1)
		fn(from + i)
		from += i + 1
	}
}

// isWordByte is an ASCII word character, as RE2's \b sees it.
func isWordByte(c byte) bool { return isAlnum(c) || c == '_' }

// wordStart reports whether RE2's \b holds before s[i], a word character.
func wordStart(s string, i int) bool { return i == 0 || !isWordByte(s[i-1]) }

// literalSpans finds matches of an anchored re at each occurrence of any
// of lits, optionally only where \b holds before it, and returns the first
// non-empty group (group 1 and on) or, when group is false, the whole
// match. An occurrence inside an earlier match of the same literal is not
// tried again: its match would end at the same place (the patterns are
// greedy over a fixed alphabet), and re-scanning it for every occurrence
// would make a line of repeated literals cost quadratic time (security
// review H1).
func literalSpans(s string, lits []string, re *regexp.Regexp, boundary, group bool) []span {
	var out []span
	seen := map[int]bool{}
	for _, lit := range lits {
		covered := 0
		eachIndex(s, lit, func(i int) {
			if i < covered || seen[i] || (boundary && !wordStart(s, i)) {
				return
			}
			m := matchAt(re, s, i)
			if m == nil {
				return
			}
			seen[i] = true
			covered = m[1]
			if !group {
				out = append(out, span{start: m[0], end: m[1]})
				return
			}
			for g := 2; g+1 < len(m); g += 2 {
				if m[g] >= 0 && m[g+1] > m[g] {
					out = append(out, span{start: m[g], end: m[g+1]})
					return
				}
			}
		})
	}
	return out
}

// digitRuns returns the runs of re (an unanchored digit-run pattern) that
// are at least minBytes long: each match starts at a digit that follows
// no digit, because the pattern is greedy and leftmost. A digit is at
// least one byte, so a shorter run cannot hold minBytes digits.
func digitRuns(s string, re *regexp.Regexp, minBytes int) [][]int {
	var out [][]int
	work(len(s))
	for _, m := range re.FindAllStringIndex(s, -1) {
		if m[1]-m[0] >= minBytes {
			out = append(out, m)
		}
	}
	return out
}
