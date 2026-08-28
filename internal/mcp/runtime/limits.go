// Package runtime is the PR-5 live MCP listener boundary. It binds dedicated,
// physically and logically isolated Management and Gateway HTTP listeners that run
// the merged PR-1 protocol kernel, PR-3 authentication + immutable session-identity
// binding, and PR-2 registry/catalog checks, enforce Host/Origin on every request
// and HTTP/2 stream, and produce sanitized observe records. It is OBSERVE-ONLY: no
// policy engine (PR-6), credential materialization (PR-4 is not invoked here),
// upstream call, inspection, or durable event spool exists, so decision-point
// methods (tools/list, tools/call) end in a deterministic observe-only rejection.
//
// The runtime is DISABLED BY DEFAULT: when off it binds no socket, starts no
// goroutine/timer, allocates nothing on the SWG request path, and startup succeeds
// without MCP certificates, registry or auth configuration.
package runtime

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Hard-cap ceilings for a listener's runtime bounds (attacker-drivable dimensions).
const (
	capMaxConns           = 1 << 20
	capMaxConcurrent      = 1 << 18
	capQueueDepth         = 1 << 18
	capMaxSessions        = 1 << 20
	capMaxOutstanding     = 1 << 18
	capHeaderBytes        = 8 << 20  // 8 MiB
	capBodyBytes          = 64 << 20 // 64 MiB
	capResponseBytes      = 64 << 20
	capAuthConcurrency    = 1 << 16
	capDPoPConcurrency    = 1 << 16
	capObservationsFlight = 1 << 18
	capAdmissionBudget    = 1 << 20
	capCleanupPerOp       = 1 << 16
	capTimeout            = 10 * time.Minute
	capShutdown           = 5 * time.Minute
)

// Limits is the immutable, validated per-capability runtime bound set. Every
// dimension an attacker (or overload) can drive is finite and validated. Management
// and Gateway each hold their OWN Limits — a shared mutable limit object is
// forbidden (a saturation in one capability must never exhaust the other). A zero,
// negative, or over-ceiling value fails construction (fail closed).
type Limits struct{ c LimitConfig }

// LimitConfig is the mutable input to NewLimits.
type LimitConfig struct {
	MaxConns      int // accepted connections
	MaxConcurrent int // concurrent in-flight requests (worker pool size)
	QueueDepth    int // admission queue depth beyond the workers
	// MaxSessions mirrors the kernel bound for the listener-facing config; the cap
	// is ENFORCED by internal/mcp/session.Manager via ListenerConfig.SessionLimits.
	MaxSessions int
	// MaxOutstanding mirrors the kernel bound; outstanding-request accounting is
	// ENFORCED per (session, direction) in internal/mcp/session/ops.go.
	MaxOutstanding int
	MaxHeaderBytes int // request header bytes
	MaxBodyBytes   int // request body bytes
	// MaxResponseBytes: the observe runtime generates every response itself from
	// bounded internal values, so the attacker-sized case is the UPSTREAM leg,
	// where internal/mcp/upstreamclient enforces its own bound.
	MaxResponseBytes int
	AuthConcurrency  int // concurrent authentications
	DPoPConcurrency  int // concurrent DPoP verifications
	// MaxObservations is RESERVED: observe records are emitted synchronously on the
	// request goroutine, so in-flight records cannot exceed MaxConcurrent. It
	// becomes meaningful only if the sink becomes asynchronous.
	MaxObservations int
	// AdmissionBudget is RESERVED AND UNENFORCED (RISK-026). It is documented as a
	// per-source budget, but admission has no source identity and runs before
	// authentication, so nothing consumes it. Wiring it requires a
	// deployment-topology decision — see
	// docs/design/mcp/ADR-PROPOSAL-mcp-admission-fairness.md. The Limits ownership
	// wall (limits_ownership_test.go) fails the build if this is silently read.
	AdmissionBudget int
	// CleanupPerOp is RESERVED: the sweeper walks sessions the manager already caps
	// at MaxSessions, so the scan is bounded without it. (The credential broker's
	// MaxCleanupPerOp is a DIFFERENT, enforced bound.)
	CleanupPerOp      int
	ReadHeaderTimeout time.Duration // slowloris: header read deadline
	ReadTimeout       time.Duration // full request read deadline
	WriteTimeout      time.Duration // response write deadline
	IdleTimeout       time.Duration // idle keep-alive deadline
	// HandshakeTimeout: net/http bounds the TLS handshake itself from
	// max(ReadHeaderTimeout, ReadTimeout), which are set from this same set.
	HandshakeTimeout time.Duration
	RequestDeadline  time.Duration // absolute per-request deadline
	SessionTTL       time.Duration // idle session expiry
	ShutdownTimeout  time.Duration // graceful-shutdown budget
}

func limErr(detail string) error {
	return mcperr.New(mcperr.ReasonListenerConfigInvalid, "runtime.limits", detail)
}

// Validate enforces positivity, hard-cap ceilings, and consistency.
func (c LimitConfig) Validate() error {
	ints := []struct {
		name string
		v, c int
	}{
		{"MaxConns", c.MaxConns, capMaxConns},
		{"MaxConcurrent", c.MaxConcurrent, capMaxConcurrent},
		{"QueueDepth", c.QueueDepth, capQueueDepth},
		{"MaxSessions", c.MaxSessions, capMaxSessions},
		{"MaxOutstanding", c.MaxOutstanding, capMaxOutstanding},
		{"MaxHeaderBytes", c.MaxHeaderBytes, capHeaderBytes},
		{"MaxBodyBytes", c.MaxBodyBytes, capBodyBytes},
		{"MaxResponseBytes", c.MaxResponseBytes, capResponseBytes},
		{"AuthConcurrency", c.AuthConcurrency, capAuthConcurrency},
		{"DPoPConcurrency", c.DPoPConcurrency, capDPoPConcurrency},
		{"MaxObservations", c.MaxObservations, capObservationsFlight},
		{"AdmissionBudget", c.AdmissionBudget, capAdmissionBudget},
		{"CleanupPerOp", c.CleanupPerOp, capCleanupPerOp},
	}
	for _, p := range ints {
		if p.v <= 0 {
			return limErr(p.name + " must be positive")
		}
		if p.v > p.c {
			return limErr(p.name + " exceeds its hard-cap ceiling")
		}
	}
	durs := []struct {
		name string
		v, c time.Duration
	}{
		{"ReadHeaderTimeout", c.ReadHeaderTimeout, capTimeout},
		{"ReadTimeout", c.ReadTimeout, capTimeout},
		{"WriteTimeout", c.WriteTimeout, capTimeout},
		{"IdleTimeout", c.IdleTimeout, capTimeout},
		{"HandshakeTimeout", c.HandshakeTimeout, capTimeout},
		{"RequestDeadline", c.RequestDeadline, capTimeout},
		{"SessionTTL", c.SessionTTL, capTimeout},
		{"ShutdownTimeout", c.ShutdownTimeout, capShutdown},
	}
	for _, p := range durs {
		if p.v <= 0 {
			return limErr(p.name + " must be positive")
		}
		if p.v > p.c {
			return limErr(p.name + " exceeds its hard-cap ceiling")
		}
	}
	if c.MaxOutstanding < c.MaxConcurrent {
		return limErr("MaxOutstanding cannot be below MaxConcurrent")
	}
	if c.ReadTimeout < c.ReadHeaderTimeout {
		return limErr("ReadTimeout cannot be below ReadHeaderTimeout")
	}
	if c.MaxResponseBytes < c.MaxBodyBytes {
		return limErr("MaxResponseBytes should not be below MaxBodyBytes")
	}
	return nil
}

// NewLimits validates c into an immutable Limits.
func NewLimits(c LimitConfig) (Limits, error) {
	if err := c.Validate(); err != nil {
		return Limits{}, err
	}
	return Limits{c: c}, nil
}

// DefaultLimits returns a conservative, valid runtime bound set for tests and
// the dormant default wiring.
func DefaultLimits() Limits {
	l, err := NewLimits(LimitConfig{
		MaxConns: 1024, MaxConcurrent: 64, QueueDepth: 256, MaxSessions: 4096,
		MaxOutstanding: 8192, MaxHeaderBytes: 64 << 10, MaxBodyBytes: 1 << 20,
		MaxResponseBytes: 1 << 20, AuthConcurrency: 32, DPoPConcurrency: 32,
		MaxObservations: 4096, AdmissionBudget: 256, CleanupPerOp: 256,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		HandshakeTimeout: 5 * time.Second, RequestDeadline: 30 * time.Second,
		SessionTTL: 5 * time.Minute, ShutdownTimeout: 20 * time.Second,
	})
	if err != nil {
		panic("runtime: DefaultLimits invalid: " + err.Error())
	}
	return l
}

// Accessors (immutable). Each returns the corresponding validated bound.

// MaxConns returns the accepted-connection cap.
func (l Limits) MaxConns() int { return l.c.MaxConns }

// MaxConcurrent returns the concurrent in-flight request cap (worker-pool size).
func (l Limits) MaxConcurrent() int { return l.c.MaxConcurrent }

// QueueDepth returns the admission-queue depth beyond the workers.
func (l Limits) QueueDepth() int { return l.c.QueueDepth }

// MaxSessions returns the live-session cap.
func (l Limits) MaxSessions() int { return l.c.MaxSessions }

// MaxOutstanding returns the outstanding-request cap across sessions.
func (l Limits) MaxOutstanding() int { return l.c.MaxOutstanding }

// MaxHeaderBytes returns the request-header byte cap.
func (l Limits) MaxHeaderBytes() int { return l.c.MaxHeaderBytes }

// MaxBodyBytes returns the request-body byte cap.
func (l Limits) MaxBodyBytes() int { return l.c.MaxBodyBytes }

// MaxResponseBytes returns the response byte cap.
func (l Limits) MaxResponseBytes() int { return l.c.MaxResponseBytes }

// AuthConcurrency returns the concurrent-authentication cap.
func (l Limits) AuthConcurrency() int { return l.c.AuthConcurrency }

// DPoPConcurrency returns the concurrent DPoP-verification cap.
func (l Limits) DPoPConcurrency() int { return l.c.DPoPConcurrency }

// MaxObservations returns the in-flight observe-record cap.
func (l Limits) MaxObservations() int { return l.c.MaxObservations }

// AdmissionBudget returns the per-source admission token-bucket size.
func (l Limits) AdmissionBudget() int { return l.c.AdmissionBudget }

// CleanupPerOp returns the bounded per-operation cleanup-scan size.
func (l Limits) CleanupPerOp() int { return l.c.CleanupPerOp }

// ReadHeaderTimeout returns the header-read deadline (slowloris defense).
func (l Limits) ReadHeaderTimeout() time.Duration { return l.c.ReadHeaderTimeout }

// ReadTimeout returns the full-request read deadline.
func (l Limits) ReadTimeout() time.Duration { return l.c.ReadTimeout }

// WriteTimeout returns the response-write deadline.
func (l Limits) WriteTimeout() time.Duration { return l.c.WriteTimeout }

// IdleTimeout returns the idle keep-alive deadline.
func (l Limits) IdleTimeout() time.Duration { return l.c.IdleTimeout }

// HandshakeTimeout returns the TLS-handshake deadline.
func (l Limits) HandshakeTimeout() time.Duration { return l.c.HandshakeTimeout }

// RequestDeadline returns the absolute per-request deadline.
func (l Limits) RequestDeadline() time.Duration { return l.c.RequestDeadline }

// SessionTTL returns the idle-session expiry window.
func (l Limits) SessionTTL() time.Duration { return l.c.SessionTTL }

// ShutdownTimeout returns the graceful-shutdown budget.
func (l Limits) ShutdownTimeout() time.Duration { return l.c.ShutdownTimeout }
