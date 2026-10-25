package redact

// detectorKind says how a detector's matches are replaced.
type detectorKind uint8

const (
	kindMarker detectorKind = iota // the match is replaced by a marker
	kindValue                      // only a value after a key or scheme; exempt from the UUID exclusion
	kindIP                         // public-ip: replaced by its truncated network (R34)
)

// classSet is a bit set of the classes a detector applies to.
type classSet uint16

// span is one match over normalised text, as byte offsets. repl is used
// only by kindIP.
type span struct {
	start, end int
	repl       string
}

// detector is one row of the §4.2 rule table.
type detector struct {
	id      string
	kind    detectorKind
	extend  bool
	classes classSet
	find    func(s string) ([]span, error)
	// samples returns the built-in positive and negative self-test inputs
	// (R42), built at run time from fragments.
	samples func() (pos, neg []string)
}

// hooks are test seams; nil in production.
var hooks struct {
	detect    func(id string, n int) // before each detector call, with its input length
	b64       func(n int)            // characters handed to the bounded base64 decoder
	normalise func(c Class, n int)   // before normalisation, with the input length
}

func defaultRules() []detector { return nil }
