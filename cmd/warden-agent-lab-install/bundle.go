package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/nofal82/warden-agent/internal/identity"
)

// Bundle limits (agent-identity §4.3; executor-ipc R51).
const (
	maxBundleBytes   = 64 << 10
	maxCABytes       = 8 << 10
	bindingSecretLen = 32
)

// bindingContext is the R52 domain-separation prefix of the binding MAC.
const bindingContext = "warden/v1/executor-key-binding"

var (
	// errBundle: the bundle is not a valid §4.3 enroll bundle. Messages
	// never carry a field's value, only its name.
	errBundle = errors.New("lab-install: invalid enrollment bundle")
	// errUnsafe: a file or directory fails an ownership, mode, type or
	// link check, so the installer changes nothing.
	errUnsafe = errors.New("lab-install: unsafe file or directory")
	// errExists: a file the installer would write already exists. A lab
	// reinstall is the manual root steps of agent-identity R30.
	errExists = errors.New("lab-install: target already exists")
)

// §4.3 integers: format_version is exactly "1"; expires_at is the
// token-expires form of §4.7.
var expiresRE = regexp.MustCompile(`^[1-9][0-9]{0,11}$`)

// bundle is a decoded, validated §4.3 enroll bundle. secret is the
// executor_binding_secret; wipe clears it once the MAC is computed (R52).
type bundle struct {
	ServerID       string
	Token          string
	ExpiresAt      int64
	Endpoints      identity.Endpoints
	AgentCA        []byte // canonical PEM re-encoding of the DER
	ControlPlaneCA []byte // canonical PEM re-encoding of the DER
	secret         []byte
}

// wipe overwrites the secret in memory, best effort (R52). Go strings,
// such as the token, cannot be cleared.
func (b *bundle) wipe() {
	clear(b.secret)
	b.secret = nil
}

// bundleFields lists every §4.3 member; true means required for kind
// "enroll". Any other member is refused, and so is "manifest" (see fill).
var bundleFields = map[string]bool{
	"format_version":          true,
	"kind":                    true,
	"server_id":               true,
	"token":                   true,
	"expires_at":              true,
	"agent_ca":                true,
	"manifest":                false,
	"enroll_endpoint":         true,
	"agent_endpoint":          true,
	"server_name":             true,
	"executor_binding_secret": true,
	"controlplane_ca":         true,
}

// decodeBundle decodes and validates one §4.3 bundle. It accepts only kind
// "enroll" (the lab installer has no re-enrollment mode) and no manifest,
// and refuses a bundle whose expires_at is not after now.
func decodeBundle(data []byte, now time.Time) (*bundle, error) {
	if len(data) > maxBundleBytes {
		return nil, fmt.Errorf("%w: over %d bytes", errBundle, maxBundleBytes)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: not UTF-8", errBundle)
	}
	m, err := decodeObject(data)
	if err != nil {
		return nil, err
	}
	for name, required := range bundleFields {
		if _, ok := m[name]; required && !ok {
			return nil, fmt.Errorf("%w: missing %s", errBundle, name)
		}
	}
	b := &bundle{}
	if err := b.fill(m, now); err != nil {
		b.wipe()
		return nil, err
	}
	return b, nil
}

// fill validates each member of m into b.
func (b *bundle) fill(m map[string]any, now time.Time) error {
	if n, ok := m["format_version"].(json.Number); !ok || n.String() != "1" {
		return fmt.Errorf("%w: format_version must be 1", errBundle)
	}
	str := func(name string) (string, error) {
		s, ok := m[name].(string)
		if !ok {
			return "", fmt.Errorf("%w: %s is not a string", errBundle, name)
		}
		return s, nil
	}
	kind, err := str("kind")
	if err != nil {
		return err
	}
	if kind != "enroll" {
		return fmt.Errorf("%w: kind must be enroll", errBundle)
	}
	if b.ServerID, err = str("server_id"); err != nil {
		return err
	}
	if identity.ValidateServerID(b.ServerID) != nil {
		return fmt.Errorf("%w: server_id", errBundle)
	}
	if b.Token, err = str("token"); err != nil {
		return err
	}
	if identity.ValidateToken(b.Token) != nil {
		return fmt.Errorf("%w: token", errBundle)
	}
	if err := b.fillExpiry(m, now); err != nil {
		return err
	}
	if err := b.fillEndpoints(str); err != nil {
		return err
	}
	if err := b.fillCAs(str); err != nil {
		return err
	}
	if err := b.fillSecret(str); err != nil {
		return err
	}
	// M1 has no manifest key, so a manifest cannot be verified, and the
	// installer never stores unverified bytes (Nofal, 2026-11-09, PR #38).
	if _, ok := m["manifest"]; ok {
		return fmt.Errorf("%w: manifest not accepted in M1 (no manifest key)", errBundle)
	}
	return nil
}

func (b *bundle) fillExpiry(m map[string]any, now time.Time) error {
	n, ok := m["expires_at"].(json.Number)
	if !ok || !expiresRE.MatchString(n.String()) {
		return fmt.Errorf("%w: expires_at", errBundle)
	}
	v, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil {
		return fmt.Errorf("%w: expires_at", errBundle)
	}
	if v <= now.Unix() {
		return fmt.Errorf("%w: token already expired", errBundle)
	}
	b.ExpiresAt = v
	return nil
}

func (b *bundle) fillEndpoints(str func(string) (string, error)) error {
	var err error
	ep := &b.Endpoints
	if ep.Enroll, err = str("enroll_endpoint"); err != nil {
		return err
	}
	if ep.Agent, err = str("agent_endpoint"); err != nil {
		return err
	}
	if ep.ServerName, err = str("server_name"); err != nil {
		return err
	}
	if identity.ValidateEndpoint(ep.Enroll) != nil {
		return fmt.Errorf("%w: enroll_endpoint", errBundle)
	}
	if identity.ValidateEndpoint(ep.Agent) != nil {
		return fmt.Errorf("%w: agent_endpoint", errBundle)
	}
	if identity.ValidateServerName(ep.ServerName) != nil {
		return fmt.Errorf("%w: server_name", errBundle)
	}
	return nil
}

// fillCAs decodes both CA certificates canonically (§4.3) and keeps a
// canonical PEM re-encoding of the DER, never the input bytes.
func (b *bundle) fillCAs(str func(string) (string, error)) error {
	for _, f := range []struct {
		name  string
		parse func([]byte) error
		dst   *[]byte
	}{
		{"agent_ca", func(d []byte) error { _, err := identity.ParseAgentCA(d); return err }, &b.AgentCA},
		{"controlplane_ca", func(d []byte) error { c, err := identity.ParseControlPlaneCAs(d); return oneCA(c, err) }, &b.ControlPlaneCA},
	} {
		s, err := str(f.name)
		if err != nil {
			return err
		}
		if len(s) > maxCABytes || f.parse([]byte(s)) != nil {
			return fmt.Errorf("%w: %s", errBundle, f.name)
		}
		blk, _ := pem.Decode([]byte(s))
		*f.dst = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})
	}
	return nil
}

func oneCA[T any](certs []T, err error) error {
	if err == nil && len(certs) != 1 {
		return errBundle
	}
	return err
}

// fillSecret decodes executor_binding_secret: standard base64 with
// padding, exactly 32 bytes, and only its canonical spelling.
func (b *bundle) fillSecret(str func(string) (string, error)) error {
	s, err := str("executor_binding_secret")
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != bindingSecretLen || base64.StdEncoding.EncodeToString(raw) != s {
		clear(raw)
		return fmt.Errorf("%w: executor_binding_secret", errBundle)
	}
	b.secret = raw
	return nil
}

// decodeObject reads one JSON object whose values are strings or numbers,
// walking it token by token: encoding/json would silently keep the last of
// two duplicate members, and Token returns names unescaped, so a duplicate
// spelled with a JSON escape is caught too. Unknown members, other value
// types and trailing data are refused.
func decodeObject(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("%w: not a JSON object", errBundle)
	}
	out := map[string]any{}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: does not parse", errBundle)
		}
		name, _ := k.(string) // object keys are always strings
		if _, known := bundleFields[name]; !known {
			return nil, fmt.Errorf("%w: unknown member", errBundle)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%w: duplicate member %s", errBundle, name)
		}
		v, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: does not parse", errBundle)
		}
		switch v.(type) {
		case string, json.Number:
			out[name] = v
		default:
			return nil, fmt.Errorf("%w: %s has the wrong type", errBundle, name)
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, fmt.Errorf("%w: does not parse", errBundle)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after the object", errBundle)
	}
	return out, nil
}

// bindingMAC is executor-ipc R52: HMAC-SHA-256(secret,
// "warden/v1/executor-key-binding" || 0x00 || server_id || public_key).
func bindingMAC(secret []byte, serverID string, pub []byte) [sha256.Size]byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(bindingContext))
	h.Write([]byte{0})
	h.Write([]byte(serverID))
	h.Write(pub)
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return out
}
