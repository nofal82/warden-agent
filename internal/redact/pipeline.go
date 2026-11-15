package redact

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	pubredact "github.com/nofal82/warden-agent/redact"
)

// BytesPerMinute is REDACT_BYTES_PER_MIN (R37): telemetry input redacted
// per minute.
const BytesPerMinute = 2 << 20

// maxCounter is the contract limit of RedactDropCount.dropped.
const maxCounter = 1 << 40

// ErrDropped wraps every drop. The wrapped text is a fixed reason, never
// input content (R4).
var ErrDropped = errors.New("redact: item dropped")

// ruleIDPattern is LogEvent.rule_id (agent-api §4.7). rule_id is
// structural, so a value outside it is a collector bug, not data.
var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

// validUnit is LogEvent.unit_id's contract rule (typed-action-catalog
// §4.2, no ".."). The collector builds unit_id itself, so an input outside
// it is a collector bug: the event is dropped, never repaired by
// normalisation.
func validUnit(s string) bool { return agentapiv1.ValidUnitID(s) }

// Option configures a Pipeline.
type Option func(*config)

type config struct{ now func() time.Time }

// WithClock sets the clock of the budget's one-minute window.
func WithClock(now func() time.Time) Option { return func(c *config) { c.now = now } }

// LogInput is one matched log item before redaction. It lives only in the
// memory of the goroutine that holds it (R2).
type LogInput struct {
	RuleID     string
	UnitID     string
	Lines      []string
	ObservedAt time.Time
}

type dropKey struct {
	class  pubredact.Class
	reason string
}

type replKey struct {
	class pubredact.Class
	id    string
}

// Pipeline redacts log items for the telemetry buffer. It is safe for
// concurrent use; the spec's one worker (§7) is the collector's loop.
type Pipeline struct {
	r   *pubredact.Redactor
	p   *pubredact.Pseudonymizer
	now func() time.Time

	mu          sync.Mutex
	windowStart time.Time
	windowBytes int
	dropped     map[dropKey]uint64
	replaced    map[replKey]uint64
}

// New wraps r. p is the agent's pseudonymizer, or nil when no key is
// loaded: user names then get the user-name marker (R12c).
func New(r *pubredact.Redactor, p *pubredact.Pseudonymizer, opts ...Option) *Pipeline {
	c := config{now: time.Now}
	for _, o := range opts {
		o(&c)
	}
	if c.now == nil {
		c.now = time.Now
	}
	return &Pipeline{r: r, p: p, now: c.now, dropped: map[dropKey]uint64{}, replaced: map[replKey]uint64{}}
}

// RulesAvailable is false when the rule set failed its self-test (R42):
// then every item is dropped as RULES_UNAVAILABLE.
func (p *Pipeline) RulesAvailable() bool { return p.r != nil && p.r.Err() == nil }

// RedactLog returns the redacted LogEvent of in, or an error wrapping
// ErrDropped after counting the drop (R35, R41).
func (p *Pipeline) RedactLog(ctx context.Context, in LogInput) (ev *agentapiv1.LogEvent, err error) {
	defer func() {
		if recover() != nil { // R35: a panic is recovered per item
			ev, err = nil, p.drop(pubredact.EText, "ERROR")
		}
	}()
	if !p.RulesAvailable() {
		return nil, p.drop(pubredact.EText, "RULES_UNAVAILABLE")
	}
	if !ruleIDPattern.MatchString(in.RuleID) {
		return nil, p.drop(pubredact.EText, "ERROR")
	}
	if err := ctx.Err(); err != nil {
		return nil, p.drop(pubredact.EText, "TIMEOUT")
	}
	if !validUnit(in.UnitID) {
		return nil, p.drop(pubredact.NPatterned, "ERROR")
	}
	text := strings.Join(in.Lines, "\n")
	if !p.spend(len(text)) {
		return nil, p.drop(pubredact.EText, "BUDGET")
	}
	f := pubredact.Field{Class: pubredact.EText, MaxBytes: pubredact.ExtractMaxBytes}
	extract, rep, err := p.r.Redact(ctx, f, text, p.p)
	if err != nil {
		return nil, p.drop(pubredact.EText, pubredact.DropReason(err))
	}
	unit, urep, err := p.r.RedactUnitName(ctx, in.UnitID)
	if err != nil || !validUnit(unit) {
		return nil, p.drop(pubredact.NPatterned, pubredact.DropReason(err))
	}
	p.count(pubredact.EText, rep)
	p.count(pubredact.NPatterned, urep)
	return &agentapiv1.LogEvent{
		RuleId:       in.RuleID,
		UnitId:       unit,
		ObservedAtMs: in.ObservedAt.UnixMilli(),
		Count:        1,
		Extract:      extract,
	}, nil
}

// spend takes n bytes from the current minute's budget. An item that does
// not fit takes nothing, so a smaller later item may still pass (R37).
func (p *Pipeline) spend(n int) bool {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.windowStart.IsZero() || !now.Before(p.windowStart.Add(time.Minute)) || now.Before(p.windowStart) {
		p.windowStart, p.windowBytes = now, 0
	}
	if n > BytesPerMinute-p.windowBytes {
		return false
	}
	p.windowBytes += n
	return true
}

func (p *Pipeline) drop(c pubredact.Class, reason string) error {
	p.mu.Lock()
	p.dropped[dropKey{c, reason}]++
	p.mu.Unlock()
	return fmt.Errorf("%w: class %d, %s", ErrDropped, c, reason)
}

func (p *Pipeline) count(c pubredact.Class, rep pubredact.Report) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, n := range rep.Replaced {
		if n > 0 {
			p.replaced[replKey{c, id}] += uint64(n)
		}
	}
}

// Dropped returns redact_dropped_total for (class, reason) since start.
func (p *Pipeline) Dropped(c pubredact.Class, reason string) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dropped[dropKey{c, reason}]
}

// Replaced returns redact_replaced_total for (class, detector ID).
func (p *Pipeline) Replaced(c pubredact.Class, id string) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.replaced[replKey{c, id}]
}

// Drops is HealthReport field 10 (§4.6a): one entry per class with drops,
// sorted by class, each capped at 2^40. The result is a fresh copy.
func (p *Pipeline) Drops() []*agentapiv1.RedactDropCount {
	per := map[pubredact.Class]uint64{}
	p.mu.Lock()
	for k, n := range p.dropped {
		per[k.class] += n
	}
	p.mu.Unlock()
	classes := make([]pubredact.Class, 0, len(per))
	for c, n := range per {
		if n > 0 {
			classes = append(classes, c)
		}
	}
	slices.Sort(classes)
	out := make([]*agentapiv1.RedactDropCount, 0, len(classes))
	for _, c := range classes {
		out = append(out, &agentapiv1.RedactDropCount{
			Class:   agentapiv1.RedactClass(c), // the public classes are numbered as RedactClass (§4.6a)
			Dropped: min(per[c], maxCounter),
		})
	}
	return out
}
