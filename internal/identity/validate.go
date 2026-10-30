package identity

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"regexp"
)

var (
	serverIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenRE    = regexp.MustCompile(`^wdn1_[A-Za-z0-9_-]{43}$`)
)

const maxServerNameBytes = 253

// ValidateServerID checks s against §4.1: a UUID v4 in lowercase canonical
// form, exactly 36 bytes.
func ValidateServerID(s string) error {
	if !serverIDRE.MatchString(s) {
		return ErrInvalidServerID
	}
	return nil
}

// ValidateToken checks s against §4.2: "wdn1_" followed by 43 base64url
// characters without padding, exactly 48 bytes.
func ValidateToken(s string) error {
	if !tokenRE.MatchString(s) {
		return ErrInvalidToken
	}
	return nil
}

// TokenHash returns the SHA-256 of the token's 48 text bytes (§4.2), the
// value R12a binds a pending enrollment key to.
func TokenHash(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

// ValidateServerName checks the `server_name` of endpoints.json (§4.3): a
// DNS name (letters, digits and hyphens per label, labels of 1–63 bytes,
// no leading or trailing hyphen, no trailing dot, no wildcard) or an IP
// literal, at most 253 bytes.
func ValidateServerName(s string) error {
	if len(s) == 0 || len(s) > maxServerNameBytes {
		return fmt.Errorf("%w: length %d", ErrInvalidServerName, len(s))
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		// A zone ("fe80::1%eth0") is not an address a certificate can name.
		if addr.Zone() != "" {
			return fmt.Errorf("%w: IP literal with a zone", ErrInvalidServerName)
		}
		return nil
	}
	if !validDNSName(s) {
		return fmt.Errorf("%w: not a DNS name or IP literal", ErrInvalidServerName)
	}
	return nil
}

func validDNSName(s string) bool {
	label := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if label == 0 || s[i-1] == '-' {
				return false
			}
			label = 0
			continue
		case c == '-':
			if label == 0 {
				return false
			}
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		default:
			return false
		}
		label++
		if label > 63 {
			return false
		}
	}
	return label > 0 && s[len(s)-1] != '-'
}
