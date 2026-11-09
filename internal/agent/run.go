package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	"github.com/nofal82/warden-agent/internal/agent/controlplane"
	"github.com/nofal82/warden-agent/internal/identity"
)

var (
	// ErrTrustCheckImpossible: no verified keyset from the executor or the
	// cache, so the agent must not connect (signing-and-updates R38).
	ErrTrustCheckImpossible = errors.New("agent: trust check impossible: executor unavailable")
	// ErrNoIdentity: R18a case 4, no valid identity and no token.
	ErrNoIdentity = errors.New("agent: " + identity.HealthNoIdentity)
)

// TrustFunc returns the trusted control-plane CA set at now (agent-identity
// R10d, signing-and-updates R37) from the certificates of
// controlplane-ca.pem.
type TrustFunc func(fileCAs []*x509.Certificate, now time.Time) ([]*x509.Certificate, error)

// KeysetTrust is the release trust check: TrustedControlPlaneCAs with the
// CA entries of the highest-sequence verified keyset from the executor or
// the cache (R35, R36). M1 has neither, so it always returns
// ErrTrustCheckImpossible (R38).
func KeysetTrust(_ []*x509.Certificate, _ time.Time) ([]*x509.Certificate, error) {
	return nil, ErrTrustCheckImpossible
}

// Deps are the steps of Run. DefaultDeps holds the real ones; tests
// replace them.
type Deps struct {
	CheckRules  func() error
	LoadTrust   func() (identity.TrustFiles, error)
	Trust       TrustFunc
	OpenState   func() (*identity.StateDir, error)
	LoadBinding func() (identity.ExecutorBinding, error)
	NewSender   func(trusted []*x509.Certificate, ep identity.Endpoints, now func() time.Time) (identity.EnrollFunc, error)
	Enroll      func(ctx context.Context, d *identity.StateDir, in identity.EnrollInput, send identity.EnrollFunc) (identity.Identity, error)
	Now         func() time.Time
}

// DefaultDeps returns the production steps with trust as the trust check.
func DefaultDeps(trust TrustFunc) Deps {
	return Deps{
		CheckRules:  agentapiv1.CheckRules,
		LoadTrust:   identity.LoadTrustFiles,
		Trust:       trust,
		OpenState:   func() (*identity.StateDir, error) { return identity.OpenStateDir(identity.StateDirPath) },
		LoadBinding: identity.LoadExecutorBinding,
		NewSender:   newSender,
		Enroll:      controlplane.RunEnroll,
		Now:         time.Now,
	}
}

func newSender(trusted []*x509.Certificate, ep identity.Endpoints, now func() time.Time) (identity.EnrollFunc, error) {
	c, err := controlplane.NewEnrollClient(ep.Enroll, trusted, ep.ServerName, now)
	if err != nil {
		return nil, err
	}
	return c.Enroll, nil
}

// Run is the agent start-up: contract rules (agent-api R52c), trust files
// (agent-identity R10e), trust check before any connection (R37, R38),
// start-up state (R18a), and enrollment for case 3. It returns the
// identity the agent now holds. Every failure stops before the next step.
func Run(ctx context.Context, deps Deps) (identity.Identity, error) {
	if err := deps.CheckRules(); err != nil {
		return identity.Identity{}, fmt.Errorf("agent: contract rules: %w", err)
	}
	tf, err := deps.LoadTrust()
	if err != nil {
		return identity.Identity{}, fmt.Errorf("agent: trust files: %w", err)
	}
	trusted, err := deps.Trust(tf.ControlPlaneCAs, deps.Now())
	if err != nil {
		return identity.Identity{}, err
	}
	d, err := deps.OpenState()
	if err != nil {
		return identity.Identity{}, fmt.Errorf("agent: state directory: %w", err)
	}
	st, err := identity.Decide(d, tf.ServerID, deps.Now())
	if err != nil {
		return identity.Identity{}, fmt.Errorf("agent: start-up state: %w", err)
	}
	switch st.State {
	case identity.StartUseIdentity, identity.StartUsePrevious:
		return st.Identity, nil
	case identity.StartTokenExpired:
		return identity.Identity{}, identity.ErrTokenExpired
	case identity.StartEnroll:
		return enroll(ctx, deps, d, tf, trusted)
	default:
		return identity.Identity{}, ErrNoIdentity
	}
}

func enroll(ctx context.Context, deps Deps, d *identity.StateDir, tf identity.TrustFiles, trusted []*x509.Certificate) (identity.Identity, error) {
	b, err := deps.LoadBinding()
	if err != nil {
		return identity.Identity{}, fmt.Errorf("agent: executor binding: %w", err)
	}
	send, err := deps.NewSender(trusted, tf.Endpoints, deps.Now)
	if err != nil {
		return identity.Identity{}, fmt.Errorf("agent: enroll client: %w", err)
	}
	in := identity.EnrollInput{ServerID: tf.ServerID, AgentCA: tf.AgentCA, Binding: b}
	id, err := deps.Enroll(ctx, d, in, send)
	if err != nil {
		return identity.Identity{}, fmt.Errorf("agent: enroll: %w", err)
	}
	return id, nil
}

// Main runs Run and returns the process exit code: 0 when start-up
// succeeded or ctx was cancelled (a stop signal), 1 on any other error,
// including controlplane.ErrEnrollStopped. Errors from identity and
// controlplane never carry a token, a key or a peer message (R20, R45),
// so they are safe to log.
func Main(ctx context.Context, deps Deps, log *slog.Logger) int {
	_, err := Run(ctx, deps)
	switch {
	case err == nil:
		log.Info("agent start-up complete; the agent stream is not part of this build")
		return 0
	case ctx.Err() != nil && errors.Is(err, ctx.Err()):
		log.Info("agent stopped")
		return 0
	default:
		log.Error("agent start-up refused", "error", err.Error())
		return 1
	}
}
