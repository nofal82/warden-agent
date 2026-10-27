package redact

import (
	"net/netip"
	"regexp"
	"strconv"
)

// IPv4 and IPv6 candidates; net/netip decides what is an address (R34).
const (
	ipv4Pattern = `(?:[0-9]{1,3}\.){3}[0-9]{1,3}`
	ipv6Pattern = `(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f]{0,4})`
)

// Truncation lengths of R34 (MA13: 6to4 keeps only its embedded /24).
const (
	ipv4Bits      = 24
	sixToFourBits = 40
	ipv6Bits      = 48
)

func publicIP() detector {
	v4 := anchored(ipv4Pattern)
	v6 := anchored(ipv6Pattern)
	return detector{
		id:      "public-ip",
		kind:    kindIP,
		classes: textClasses,
		res:     []*regexp.Regexp{v4, v6},
		tables:  []string{"anchor:token-start", "netip", "unmap-4in6", "kept-ranges", "prefix-suffix", "mapped-suffix-as-ipv4", "escape-before-network-consumed"},
		find:    func(s string) ([]span, error) { return ipSpans(v4, v6, s), nil },
		samples: func() ([]string, []string) {
			return []string{"client 203.0.113.77"}, []string{"client 10.1.2.3"}
		},
	}
}

// ipSpans finds address candidates where one can start: an IPv6
// candidate at the start of the hex-and-colon token around each ':', an
// IPv4 candidate at each digit that follows neither a digit nor a '.'.
// The boundary checks are the same as for an unanchored search.
// keptPrefixes are the ranges R34 keeps: unspecified and loopback,
// private (RFC 1918, ULA), RFC 6598, link-local, and the non-unicast
// ranges (OQ8). A table, so the rule-set digest covers it.
var keptPrefixes = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		ps = append(ps, netip.MustParsePrefix(p))
	}
	return ps
}()

func ipSpans(v4, v6 *regexp.Regexp, s string) []span {
	var out []span
	var v6s [][]int
	runEnd := -1
	eachIndex(s, ":", func(i int) {
		if i < runEnd {
			return // a later ':' of a hex-and-colon run already tried (H1)
		}
		a := i
		for a > 0 && (isHexByte(s[a-1]) || s[a-1] == ':') {
			a--
		}
		runEnd = i
		for runEnd < len(s) && (isHexByte(s[runEnd]) || s[runEnd] == ':') {
			runEnd++
		}
		work(runEnd - a)
		if a > 0 && (isAlnum(s[a-1]) || s[a-1] == '.') {
			return
		}
		m := matchAt(v6, s, a)
		if m == nil || (m[1] < len(s) && (isAlnum(s[m[1]]) || s[m[1]] == ':' || dotDigit(s, m[1]))) {
			return
		}
		addr, err := netip.ParseAddr(s[m[0]:m[1]])
		if err != nil {
			return
		}
		v6s = append(v6s, m[:2])
		if sp, ok := ipSpan(s, m[0], m[1], addr); ok {
			out = append(out, sp)
		}
	})
	// An IPv4 candidate starts up to three digits before its first '.'.
	last := -1
	eachIndex(s, ".", func(dot int) {
		i := dot
		for i > 0 && dot-i < 3 && isDigitByte(s[i-1]) {
			i--
		}
		if i == dot || i <= last || (i > 0 && (isDigitByte(s[i-1]) || s[i-1] == '.')) {
			return
		}
		m := matchAt(v4, s, i)
		if m == nil {
			return
		}
		last = m[1]
		if inside(v6s, m) || (m[1] < len(s) && (isDigitByte(s[m[1]]) || dotDigit(s, m[1]))) {
			return
		}
		addr, err := netip.ParseAddr(s[m[0]:m[1]])
		if err != nil {
			return
		}
		if sp, ok := ipSpan(s, m[0], m[1], addr); ok {
			out = append(out, sp)
		}
	})
	return out
}

func inside(spans [][]int, m []int) bool {
	for _, o := range spans {
		if m[0] >= o[0] && m[1] <= o[1] {
			return true
		}
	}
	return false
}

func dotDigit(s string, i int) bool {
	return s[i] == '.' && i+1 < len(s) && isDigitByte(s[i+1])
}

// ipSpan returns the replacement for a public address: its network at the
// R34 length. An address already written as a network no finer than that
// (for example this function's own output) is kept, so the post-check
// (R32) does not truncate it again.
func ipSpan(s string, a, b int, addr netip.Addr) (span, bool) {
	mapped := addr.Is4In6()
	addr = addr.Unmap()
	if keptIP(addr) {
		return span{}, false
	}
	bits := ipv4Bits
	if addr.Is6() {
		bits = ipv6Bits
		if b16 := addr.As16(); b16[0] == 0x20 && b16[1] == 0x02 {
			bits = sixToFourBits
		}
	}
	end, repl := b, ""
	if n, e, ok := prefixSuffix(s, b); ok {
		// The address and its /N go together (R34). A plain address is
		// kept when N is no finer than the truncation length and every
		// host bit is zero. A mapped address's /N is read against the
		// unmapped 32 bits (S2): when it is a valid prefix no finer than
		// /24, the output is that IPv4 network. Anything else becomes the
		// truncated network, never with a second suffix.
		end = e
		if p, err := addr.Prefix(n); err == nil && n <= bits {
			switch {
			case mapped:
				repl = p.String()
			case p.Addr() == addr:
				return span{}, false
			}
		}
	}
	if repl == "" {
		p, err := addr.Prefix(bits)
		if err != nil {
			return span{}, false
		}
		repl = p.String()
	}
	return span{start: escapeStart(s, a, repl), end: end, repl: repl}, true
}

// escapeStart moves the start of a replaced address back over the text
// that would form an R25a escape with the network written there (OQ15):
// the network is lowercase and can differ from the address, so "\E::1"
// would become "\e::/48" and "#::ffff:177.12.2.3" "#177.12.2.0/24", which
// a second pass (intake) would decode. Only an escape that ends inside the
// network counts; backslashes are read as pairs from the left.
func escapeStart(s string, a int, repl string) int {
	for j := max(a-5, 0); j < a; j++ {
		if s[j] == '\\' && oddBackslashRunEndsAt(s, j) {
			continue // the second half of a "\\" pair
		}
		if _, n, ok := escapeAt(s[j:a] + repl); ok && n > a-j {
			return j
		}
	}
	return a
}

// oddBackslashRunEndsAt reports whether s[j], a backslash, closes a pair:
// an odd number of backslashes directly precede it.
func oddBackslashRunEndsAt(s string, j int) bool {
	n := 0
	for j-n > 0 && s[j-n-1] == '\\' {
		n++
	}
	return n%2 == 1
}

// prefixSuffix reads "/N" after an address: a '/' and the run of digits
// after it (at most three, and not followed by another digit).
func prefixSuffix(s string, i int) (int, int, bool) {
	if i >= len(s) || s[i] != '/' {
		return 0, 0, false
	}
	j := i + 1
	for j < len(s) && j-i <= 3 && isDigitByte(s[j]) {
		j++
	}
	if j == i+1 || (j < len(s) && isDigitByte(s[j])) {
		return 0, 0, false
	}
	n, err := strconv.Atoi(s[i+1 : j])
	if err != nil {
		return 0, 0, false
	}
	return n, j, true
}

// keptIP reports whether a (unmapped) is in a range R34 keeps.
func keptIP(a netip.Addr) bool {
	for _, p := range keptPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
