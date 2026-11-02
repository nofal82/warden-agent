package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Trust file names in ConfigDir (§4.7).
const (
	FileServerID       = "server-id"
	FileEndpoints      = "endpoints.json"
	FileAgentCA        = "agent-ca.pem"
	FileControlPlaneCA = "controlplane-ca.pem"
)

// Read limits of the trust files: the exact server-id length (§4.1), the
// bundle's 8 KiB CA limit (§4.3) and the executor's 16 KiB control-plane CA
// input limit (signing-and-updates R40a).
const (
	maxServerIDFileBytes = 36
	maxEndpointsBytes    = 4 << 10
	maxAgentCABytes      = 8 << 10
	maxControlPlaneBytes = 16 << 10
	maxEndpointBytes     = 253
)

var portRE = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)

// Endpoints is endpoints.json (§4.7): where the agent dials and the name
// the control-plane certificate must carry (R24).
type Endpoints struct {
	Enroll     string
	Agent      string
	ServerName string
}

// TrustFiles is what the agent loaded from ConfigDir under R10e.
// ControlPlaneCAs is the file as written, not yet the trusted set: only
// TrustedControlPlaneCAs, with a verified keyset, decides that (R10d).
type TrustFiles struct {
	ServerID        string
	Endpoints       Endpoints
	AgentCA         *x509.Certificate
	ControlPlaneCAs []*x509.Certificate
}

// ParseServerIDFile checks the agent copy of server-id (§4.1, R5): exactly
// the 36 bytes of a lowercase canonical UUID v4, nothing else.
func ParseServerIDFile(data []byte) (string, error) {
	s := string(data)
	if err := ValidateServerID(s); err != nil {
		return "", err
	}
	return s, nil
}

// ParseEndpoints decodes endpoints.json with the bundle's rules (§4.3): one
// JSON object holding exactly the string members enroll_endpoint,
// agent_endpoint and server_name, no duplicate or unknown member, nothing
// after it but white space. Each value is then validated.
func ParseEndpoints(data []byte) (Endpoints, error) {
	var ep Endpoints
	members, err := decodeStringObject(data)
	if err != nil {
		return ep, err
	}
	fields := map[string]*string{
		"enroll_endpoint": &ep.Enroll,
		"agent_endpoint":  &ep.Agent,
		"server_name":     &ep.ServerName,
	}
	if len(members) != len(fields) {
		return Endpoints{}, fmt.Errorf("%w: want exactly %d members", ErrInvalidEndpoints, len(fields))
	}
	for k, v := range members {
		dst, ok := fields[k]
		if !ok {
			return Endpoints{}, fmt.Errorf("%w: unknown member", ErrInvalidEndpoints)
		}
		*dst = v
	}
	if err := ValidateEndpoint(ep.Enroll); err != nil {
		return Endpoints{}, fmt.Errorf("enroll_endpoint: %w", err)
	}
	if err := ValidateEndpoint(ep.Agent); err != nil {
		return Endpoints{}, fmt.Errorf("agent_endpoint: %w", err)
	}
	if err := ValidateServerName(ep.ServerName); err != nil {
		return Endpoints{}, fmt.Errorf("%w: server_name: %w", ErrInvalidEndpoints, err)
	}
	return ep, nil
}

// decodeStringObject reads one JSON object whose members are all strings,
// refusing duplicate names, any other value type and trailing data.
// encoding/json would silently keep the last of two duplicate members, so
// the object is walked token by token.
func decodeStringObject(data []byte) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("%w: not a JSON object", ErrInvalidEndpoints)
	}
	out := map[string]string{}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: does not parse", ErrInvalidEndpoints)
		}
		name, _ := k.(string) // object keys are always strings
		v, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: does not parse", ErrInvalidEndpoints)
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%w: member is not a string", ErrInvalidEndpoints)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%w: duplicate member", ErrInvalidEndpoints)
		}
		out[name] = s
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, fmt.Errorf("%w: does not parse", ErrInvalidEndpoints)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after the object", ErrInvalidEndpoints)
	}
	return out, nil
}

// ValidateEndpoint checks a §4.3 endpoint: host:port of at most 253 bytes,
// host a DNS name or IP literal (ValidateServerName; IPv6 in brackets), port
// a decimal 1 … 65535 with no leading zero.
func ValidateEndpoint(s string) error {
	if len(s) == 0 || len(s) > maxEndpointBytes {
		return fmt.Errorf("%w: endpoint length %d", ErrInvalidEndpoints, len(s))
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("%w: endpoint is not host:port", ErrInvalidEndpoints)
	}
	if err := ValidateServerName(host); err != nil {
		return fmt.Errorf("%w: endpoint host: %w", ErrInvalidEndpoints, err)
	}
	// SplitHostPort refuses an unbracketed IPv6 host but accepts brackets
	// around anything; only an IPv6 literal may use them.
	if s[0] == '[' && !strings.Contains(host, ":") {
		return fmt.Errorf("%w: brackets around a non-IPv6 host", ErrInvalidEndpoints)
	}
	if !portRE.MatchString(port) {
		return fmt.Errorf("%w: endpoint port", ErrInvalidEndpoints)
	}
	if n, err := strconv.Atoi(port); err != nil || n > 65535 {
		return fmt.Errorf("%w: endpoint port", ErrInvalidEndpoints)
	}
	return nil
}

// ParseAgentCA decodes agent-ca.pem: exactly one canonical CERTIFICATE PEM
// block (§4.3) holding a CA certificate.
func ParseAgentCA(data []byte) (*x509.Certificate, error) {
	certs, err := parseCAFile(data, 1, 1)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// ParseControlPlaneCAs decodes controlplane-ca.pem (§4.7): 1 or 2
// canonical CERTIFICATE PEM blocks, each a CA certificate, with distinct
// DER sorted by its SHA-256. These are the file's CAs; R10d trusts only
// those the keyset carries (TrustedControlPlaneCAs).
func ParseControlPlaneCAs(data []byte) ([]*x509.Certificate, error) {
	return parseCAFile(data, 1, MaxTrustedControlPlaneCAs)
}

// parseCAFile accepts data only when it is byte for byte the canonical
// encoding of min … max CERTIFICATE blocks (pem.EncodeToMemory of each, one
// after the other) whose DER hashes are strictly increasing.
func parseCAFile(data []byte, minN, maxN int) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var prev []byte
	rest := data
	for len(rest) > 0 {
		if len(certs) == maxN {
			return nil, fmt.Errorf("%w: more than %d certificates", ErrInvalidTrust, maxN)
		}
		b, after := pem.Decode(rest)
		if b == nil || b.Type != pemTypeCertificate || len(b.Headers) != 0 ||
			!bytes.Equal(pem.EncodeToMemory(b), rest[:len(rest)-len(after)]) {
			return nil, fmt.Errorf("%w: not a canonical CERTIFICATE PEM block", ErrInvalidTrust)
		}
		sum := sha256.Sum256(b.Bytes)
		if prev != nil && bytes.Compare(prev, sum[:]) >= 0 {
			return nil, fmt.Errorf("%w: certificates not distinct and sorted by SHA-256", ErrInvalidTrust)
		}
		prev = sum[:]
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate does not parse", ErrInvalidTrust)
		}
		if !isCA(cert) {
			return nil, fmt.Errorf("%w: not a CA certificate", ErrInvalidTrust)
		}
		certs = append(certs, cert)
		rest = after
	}
	if len(certs) < minN {
		return nil, fmt.Errorf("%w: %d certificates, want at least %d", ErrInvalidTrust, len(certs), minN)
	}
	return certs, nil
}

// CAEntry is one controlplane_cas entry (signing-and-updates §4.4) of a
// keyset that has already been verified with root-key.pub; verifying the
// keyset is not done here. Bounds are Unix seconds, both inclusive.
type CAEntry struct {
	Fingerprint [sha256.Size]byte
	NotBefore   int64
	NotAfter    int64
}

// TrustedControlPlaneCAs computes the R10d set: each certificate of
// controlplane-ca.pem whose DER SHA-256 is the fingerprint of an entry
// valid at now, in file order. The agent calls it at start, before every
// connection and after every newer keyset (signing-and-updates R37), and
// passes the result to ClientTLSConfig. An empty set is
// ErrNoTrustedControlPlaneCA: the agent must not connect.
func TrustedControlPlaneCAs(fileCAs []*x509.Certificate, entries []CAEntry, now time.Time) ([]*x509.Certificate, error) {
	if len(fileCAs) == 0 || len(fileCAs) > MaxTrustedControlPlaneCAs {
		return nil, fmt.Errorf("%w: %d control-plane CA certificates", ErrInvalidTrust, len(fileCAs))
	}
	if len(entries) == 0 || len(entries) > MaxTrustedControlPlaneCAs {
		return nil, fmt.Errorf("%w: %d keyset CA entries", ErrInvalidTrust, len(entries))
	}
	valid := make(map[[sha256.Size]byte]bool, len(entries))
	t := now.Unix()
	for i, e := range entries {
		if e.NotBefore < 1 || e.NotBefore > e.NotAfter {
			return nil, fmt.Errorf("%w: keyset CA entry %d has an invalid validity period", ErrInvalidTrust, i)
		}
		if _, dup := valid[e.Fingerprint]; dup {
			return nil, fmt.Errorf("%w: duplicate keyset CA entry", ErrInvalidTrust)
		}
		valid[e.Fingerprint] = e.NotBefore <= t && t <= e.NotAfter
	}
	var out []*x509.Certificate
	for i, c := range fileCAs {
		if c == nil {
			return nil, fmt.Errorf("%w: control-plane CA %d is nil", ErrInvalidTrust, i)
		}
		if valid[sha256.Sum256(c.Raw)] {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoTrustedControlPlaneCA
	}
	return out, nil
}
