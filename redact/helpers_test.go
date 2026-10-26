package redact

// Shared helpers for the redaction tests (warden/specs/redaction.md).
//
// Nothing in this package's tests is a real secret. Every canary is built at
// run time from fragments plus a crypto/rand part in the detector's alphabet
// (R58): private keys are generated with crypto/rsa and crypto/ed25519, card
// numbers and IBANs get their check digits computed here, and national-ID
// digits are random. Fragments are split so that no source line holds a
// pattern that the rule checker or gitleaks would flag.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// Alphabets for the random parts of canaries.
const (
	alphaDigits     = "0123456789"
	alphaUpper      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alphaLower      = "abcdefghijklmnopqrstuvwxyz"
	alphaLetters    = alphaUpper + alphaLower
	alphaUpperB32   = alphaUpper + "234567"
	alphaAlnum      = alphaLetters + alphaDigits
	alphaLowerAlnum = alphaLower + alphaDigits
	alphaUpperAlnum = alphaUpper + alphaDigits
	alphaB64URL     = alphaAlnum + "-_"
	alphaHexLower   = "0123456789abcdef"
	alphaAWSSecret  = alphaAlnum + "/+"
)

// bs is one backslash, used to build escape texts such as bs+"u0026" without
// writing them as Go escapes.
const bs = "\\"

// typedMax is the output limit used for T-NAME, T-PATH and T-TEXT fields in
// these tests (a typical typed-result string limit).
const typedMax = 4096

// randFrom returns n characters drawn uniformly from alphabet with crypto/rand.
func randFrom(alphabet string, n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		b[i] = alphabet[v.Int64()]
	}
	return string(b)
}

func randDigits(n int) string { return randFrom(alphaDigits, n) }

// randDigitsLead returns n digits whose first digit is from lead.
func randDigitsLead(lead string, n int) string {
	return randFrom(lead, 1) + randDigits(n-1)
}

// ---------------------------------------------------------------------------
// Check digits (computed by the test, never written as literals).

func luhnSum(digits string) int {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum
}

func luhnValid(digits string) bool { return len(digits) > 1 && luhnSum(digits)%10 == 0 }

// luhnComplete appends the Luhn check digit to payload.
func luhnComplete(payload string) string {
	for d := byte('0'); d <= '9'; d++ {
		if c := payload + string(d); luhnValid(c) {
			return c
		}
	}
	panic("unreachable")
}

// luhnBreak returns s with its last digit changed so the Luhn check fails.
func luhnBreak(s string) string {
	last := s[len(s)-1]
	for d := byte('0'); d <= '9'; d++ {
		if d == last {
			continue
		}
		if c := s[:len(s)-1] + string(d); !luhnValid(c) {
			return c
		}
	}
	panic("unreachable")
}

// makeCard returns a Luhn-valid card number of the given length and prefix.
func makeCard(prefix string, length int) string {
	return luhnComplete(prefix + randDigits(length-len(prefix)-1))
}

// group splits s into groups of the given sizes joined by sep.
func group(s string, sep string, sizes ...int) string {
	var parts []string
	i := 0
	for _, n := range sizes {
		parts = append(parts, s[i:i+n])
		i += n
	}
	if i < len(s) {
		parts = append(parts, s[i:])
	}
	return strings.Join(parts, sep)
}

func mod97(s string) int {
	m := 0
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			m = (m*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			m = (m*100 + int(c-'A'+10)) % 97
		default:
			panic("mod97: bad char")
		}
	}
	return m
}

// makeIBAN returns a mod-97-valid IBAN for country and bban.
func makeIBAN(country, bban string) string {
	check := 98 - mod97(bban+country+"00")
	return country + fmt.Sprintf("%02d", check) + bban
}

func ibanValid(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	return len(s) > 4 && mod97(s[4:]+s[:4]) == 1
}

// ibanBreak changes the check digits so mod 97 fails.
func ibanBreak(s string) string {
	c := (int(s[2]-'0')*10 + int(s[3]-'0') + 1) % 100
	out := s[:2] + fmt.Sprintf("%02d", c) + s[4:]
	if ibanValid(out) {
		panic("ibanBreak: still valid")
	}
	return out
}

func groupFours(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	parts = append(parts, s)
	return strings.Join(parts, " ")
}

// gbIBAN is a GB IBAN (22 characters) whose account digits start with 1, so
// no digit group can start a payment-card candidate.
func gbIBAN() string { return makeIBAN("GB", "WEST"+"1"+randDigits(13)) }

// joIBAN is a JO IBAN (30 characters).
func joIBAN() string { return makeIBAN("JO", "CBJO"+"0010"+"0"+randDigits(17)) }

func randUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// arabicIndic maps ASCII digits to U+0660–U+0669; eastern maps them to
// U+06F0–U+06F9; mixedDigits alternates ASCII, Arabic-Indic and Eastern.
func arabicIndic(s string) string { return mapDigits(s, func(int) rune { return 0x0660 }) }
func easternDigits(s string) string {
	return mapDigits(s, func(int) rune { return 0x06F0 })
}
func mixedDigits(s string) string {
	return mapDigits(s, func(i int) rune {
		switch i % 3 {
		case 0:
			return '0'
		case 1:
			return 0x0660
		default:
			return 0x06F0
		}
	})
}

func mapDigits(s string, base func(i int) rune) string {
	var b strings.Builder
	for i, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(base(i) + (c - '0'))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Private keys, generated once per test binary.

type testKeyMaterial struct {
	rsaPEM      string   // PKCS #1 RSA key (C1)
	rsaBody     []string // its base64 body lines (C4)
	pkcs8PEM    string   // PKCS #8 key (C3)
	pkcs8Body   []string
	opensshPEM  string // OpenSSH ed25519 key (C2)
	opensshBody []string
}

var (
	keysOnce sync.Once
	keysVal  testKeyMaterial
	keysErr  error
)

// pemType builds a PEM block type at run time.
func pemType(kind string) string {
	if kind == "" {
		return "PRIVATE" + " KEY"
	}
	return kind + " PRIVATE" + " KEY"
}

func getKeys(t testing.TB) *testKeyMaterial {
	t.Helper()
	keysOnce.Do(func() {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			keysErr = err
			return
		}
		keysVal.rsaPEM = strings.TrimSuffix(string(pem.EncodeToMemory(&pem.Block{
			Type: pemType("RSA"), Bytes: x509.MarshalPKCS1PrivateKey(rk),
		})), "\n")
		der, err := x509.MarshalPKCS8PrivateKey(rk)
		if err != nil {
			keysErr = err
			return
		}
		keysVal.pkcs8PEM = strings.TrimSuffix(string(pem.EncodeToMemory(&pem.Block{
			Type: pemType(""), Bytes: der,
		})), "\n")
		_, ek, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			keysErr = err
			return
		}
		keysVal.opensshPEM = strings.TrimSuffix(string(pem.EncodeToMemory(&pem.Block{
			Type: pemType("OPENSSH"), Bytes: marshalOpenSSHEd25519(ek),
		})), "\n")
		keysVal.rsaBody = pemBody(keysVal.rsaPEM)
		keysVal.pkcs8Body = pemBody(keysVal.pkcs8PEM)
		keysVal.opensshBody = pemBody(keysVal.opensshPEM)
	})
	if keysErr != nil {
		t.Fatalf("generating test keys: %v", keysErr)
	}
	return &keysVal
}

func pemLines(p string) []string { return strings.Split(p, "\n") }

func pemBody(p string) []string {
	l := pemLines(p)
	return l[1 : len(l)-1]
}

func pemBeginLine(p string) string { return pemLines(p)[0] }
func pemEndLine(p string) string {
	l := pemLines(p)
	return l[len(l)-1]
}

// marshalOpenSSHEd25519 encodes an ed25519 key in the "openssh-key-v1"
// format (unencrypted), standard library only.
func marshalOpenSSHEd25519(k ed25519.PrivateKey) []byte {
	str := func(b []byte) []byte {
		var n uint32 // counted, not converted: the fields are a few bytes
		for range b {
			n++
		}
		out := make([]byte, 4+len(b))
		binary.BigEndian.PutUint32(out, n)
		copy(out[4:], b)
		return out
	}
	u32 := func(v uint32) []byte {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, v)
		return out
	}
	pub := k.Public().(ed25519.PublicKey)
	keyType := []byte("ssh-ed25519")
	var pubBlob []byte
	pubBlob = append(pubBlob, str(keyType)...)
	pubBlob = append(pubBlob, str(pub)...)
	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		panic(err)
	}
	var priv []byte
	priv = append(priv, check[:]...)
	priv = append(priv, check[:]...)
	priv = append(priv, str(keyType)...)
	priv = append(priv, str(pub)...)
	priv = append(priv, str(k)...)
	priv = append(priv, str([]byte("lab"))...)
	for i := byte(1); len(priv)%8 != 0; i++ {
		priv = append(priv, i)
	}
	var out []byte
	out = append(out, []byte("openssh-key-v1\x00")...)
	out = append(out, str([]byte("none"))...)
	out = append(out, str([]byte("none"))...)
	out = append(out, str(nil)...)
	out = append(out, u32(1)...)
	out = append(out, str(pubBlob)...)
	out = append(out, str(priv)...)
	return out
}

// b64BeginPrefix is the 14-character base64 prefix of "-----BEGIN " that
// pem-private-key-b64 looks for, computed at run time.
func b64BeginPrefix() string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("-", 5) + "BEGIN "))[:14]
}

// ---------------------------------------------------------------------------
// Canary builders (§4.7). Each returns a fresh random value.

func akia() string { return "AK" + "IA" + randFrom(alphaUpperB32, 16) }
func wdnToken() string {
	return "wdn1" + "_" + randFrom(alphaB64URL, 43)
}
func c24Name() string { return "cn" + randFrom(alphaLowerAlnum, 10) }

// jwtHeader is base64url({"alg":"HS256","typ":"JWT"}).
func jwtHeader() string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
}

func makeJWT() string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + randFrom(alphaLowerAlnum, 16) + `","iat":1761385200}`))
	return jwtHeader() + "." + payload + "." + randFrom(alphaB64URL, 43)
}

// ---------------------------------------------------------------------------
// Markers.

func isNameClass(c Class) bool { return c == TName || c == TPath }

func classMarker(c Class, id string) string {
	if isNameClass(c) {
		return "redacted-" + id
	}
	return Marker(id)
}

func classShortMarker(c Class) string {
	if isNameClass(c) {
		return NameShortMarker
	}
	return ShortMarker
}

func classUserMarker(c Class) string {
	if isNameClass(c) {
		return NameUserNameMarker
	}
	return UserNameMarker
}

// specDetectorIDs is §4.2's detector list, in order.
var specDetectorIDs = []string{
	"pem-private-key", "pem-body-line", "pem-private-key-b64",
	"warden-enrollment-token", "aws-access-key-id", "aws-secret-key",
	"vendor-token", "jwt", "url-credentials", "url-secret-param",
	"authorization-header", "cookie-header", "secret-assignment",
	"email", "phone", "national-id-jo", "national-id-sa", "national-id-ae",
	"payment-card", "iban", "public-ip",
}

// allMarkers lists every fixed marker of §4.3 (text and name forms).
func allMarkers() []string {
	m := []string{
		ShortMarker, NameShortMarker, UserNameMarker, NameUserNameMarker,
		ReleaseVersionMarker, AuditFailureMarker, LineDroppedText,
	}
	for _, id := range specDetectorIDs {
		m = append(m, Marker(id), "redacted-"+id)
	}
	return m
}

// ---------------------------------------------------------------------------
// Fields, redactors and errors.

var frozenNow = time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)

func frozenClock() time.Time { return frozenNow }

var (
	sharedOnce sync.Once
	sharedRed  *Redactor
)

// testRedactor is the real rule table with a frozen clock, so no test is
// flaky on a slow machine. Deadline tests build their own redactor.
func testRedactor() *Redactor {
	sharedOnce.Do(func() { sharedRed = New(WithClock(frozenClock)) })
	return sharedRed
}

func fieldFor(c Class) Field {
	switch c {
	case EText:
		return Field{Class: EText, MaxBytes: ExtractMaxBytes}
	case LValue:
		return Field{Class: LValue, MaxBytes: LabelValueMaxBytes}
	default:
		return Field{Class: c, MaxBytes: typedMax}
	}
}

var scannedClasses = []Class{TName, TPath, TText, EText, LValue}

var allErrs = []error{
	ErrDeadline, ErrBudget, ErrInputTooLarge, ErrPostCheck,
	ErrPairing, ErrOutputTooLarge, ErrRulesUnavailable, ErrInternal,
}

func isKnownErr(err error) bool {
	for _, e := range allErrs {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func className(c Class) string {
	switch c {
	case TName:
		return "TName"
	case TPath:
		return "TPath"
	case TText:
		return "TText"
	case EText:
		return "EText"
	case LValue:
		return "LValue"
	case NPatterned:
		return "NPatterned"
	}
	return fmt.Sprintf("Class(%d)", c)
}

// mustRedact runs Redact with the shared redactor and fails on an error.
func mustRedact(t testing.TB, f Field, in string, p *Pseudonymizer) (string, Report) {
	t.Helper()
	out, rep, err := testRedactor().Redact(context.Background(), f, in, p)
	if err != nil {
		t.Fatalf("Redact(%s) error: %v", className(f.Class), err)
	}
	return out, rep
}

func redactE(t testing.TB, in string) (string, Report) {
	t.Helper()
	return mustRedact(t, fieldFor(EText), in, nil)
}

func replacedTotal(r Report) int {
	n := 0
	for _, v := range r.Replaced {
		n += v
	}
	return n
}

// checkReportKeys fails when Report.Replaced holds a key that is not a
// detector ID (R4: counters never carry content).
func checkReportKeys(t testing.TB, r Report, extra ...string) {
	t.Helper()
	ok := map[string]bool{}
	for _, id := range specDetectorIDs {
		ok[id] = true
	}
	for _, id := range extra {
		ok[id] = true
	}
	for k := range r.Replaced {
		if !ok[k] {
			t.Errorf("Report.Replaced has a key that is not a detector ID (len %d)", len(k))
		}
	}
}

// isControl reports a C0, DEL or C1 control.
func isControl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) }

// checkOutput checks the invariants every successful output must meet.
func checkOutput(t testing.TB, c Class, maxBytes int, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Errorf("%s output is not valid UTF-8", className(c))
	}
	if len(out) > maxBytes {
		t.Errorf("%s output is %d bytes, over its limit %d", className(c), len(out), maxBytes)
	}
	for _, r := range out {
		if !isControl(r) {
			continue
		}
		if c == EText && (r == '\n' || r == '\t') {
			continue
		}
		t.Errorf("%s output holds control character %U", className(c), r)
		break
	}
}

// checkNoPartialMarker fails when out ends with a proper prefix of a marker
// (R40: the limit never falls inside a marker). Only for constructed inputs.
func checkNoPartialMarker(t testing.TB, out string) {
	t.Helper()
	for _, m := range allMarkers() {
		for k := 2; k < len(m); k++ {
			if strings.HasSuffix(out, m[:k]) && !strings.HasSuffix(out, m) {
				// A full shorter marker can itself be a prefix: "redacted".
				full := false
				for _, m2 := range allMarkers() {
					if strings.HasSuffix(out, m2) {
						full = true
					}
				}
				if !full {
					t.Errorf("output ends inside a marker: ...%q", out[max(0, len(out)-12):])
					return
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// R61 search.

// leakFound reports whether hay holds secret as raw bytes, as any 12-byte
// substring (or the whole secret when shorter), case-insensitively, or in
// standard base64, URL-safe base64 or lowercase hex (R61).
func leakFound(hay, secret string) bool {
	if secret == "" {
		return false
	}
	lh := strings.ToLower(hay)
	ls := strings.ToLower(secret)
	if strings.Contains(lh, ls) {
		return true
	}
	for i := 0; i+12 <= len(ls); i++ {
		if strings.Contains(lh, ls[i:i+12]) {
			return true
		}
	}
	encs := []string{
		base64.StdEncoding.EncodeToString([]byte(secret)),
		base64.RawStdEncoding.EncodeToString([]byte(secret)),
		base64.URLEncoding.EncodeToString([]byte(secret)),
		base64.RawURLEncoding.EncodeToString([]byte(secret)),
		hex.EncodeToString([]byte(secret)),
	}
	for _, e := range encs {
		if strings.Contains(hay, e) {
			return true
		}
	}
	return false
}

func assertNoLeak(t testing.TB, where, hay string, secrets ...string) {
	t.Helper()
	for i, s := range secrets {
		if leakFound(hay, s) {
			t.Errorf("%s: secret part %d (len %d) found by the R61 search", where, i, len(s))
		}
	}
}

// ---------------------------------------------------------------------------
// Fake clock and stub detectors.

type fakeClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func newFakeClock(step time.Duration) *fakeClock { return &fakeClock{t: frozenNow, step: step} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.t
	c.t = c.t.Add(c.step)
	return t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func bit(c Class) classSet { return classSet(1) << c }

func classesOf(cs ...Class) classSet {
	var s classSet
	for _, c := range cs {
		s |= bit(c)
	}
	return s
}

var allScanned = classesOf(TName, TPath, TText, EText, LValue, NPatterned)

// findAll returns a span for each occurrence of sub.
func findAll(sub string) func(string) ([]span, error) {
	return func(s string) ([]span, error) {
		var out []span
		for i := 0; ; {
			j := strings.Index(s[i:], sub)
			if j < 0 {
				return out, nil
			}
			out = append(out, span{start: i + j, end: i + j + len(sub)})
			i += j + len(sub)
		}
	}
}

func stubDetector(id string, find func(string) ([]span, error), pos, neg []string) detector {
	return detector{
		id:      id,
		kind:    kindMarker,
		classes: allScanned,
		find:    find,
		samples: func() ([]string, []string) { return pos, neg },
	}
}

// setHooks installs test hooks and restores the previous ones at cleanup.
// Tests that call it must not call t.Parallel.
func setHooks(t *testing.T, detect func(string, int), b64 func(int), normalise func(Class, int)) {
	t.Helper()
	old := hooks
	t.Cleanup(func() { hooks = old })
	hooks.detect = detect
	hooks.b64 = b64
	hooks.normalise = normalise
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
