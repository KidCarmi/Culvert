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

// RuntimeLimits is the immutable, validated per-capability runtime bound set. Every
// dimension an attacker (or overload) can drive is finite and validated. Management
// and Gateway each hold their OWN RuntimeLimits — a shared mutable limit object is
// forbidden (a saturation in one capability must never exhaust the other). A zero,
// negative, or over-ceiling value fails construction (fail closed).
type RuntimeLimits struct{ c RuntimeLimitConfig }

// RuntimeLimitConfig is the mutable input to NewRuntimeLimits.
type RuntimeLimitConfig struct {
	MaxConns          int           // accepted connections
	MaxConcurrent     int           // concurrent in-flight requests (worker pool size)
	QueueDepth        int           // admission queue depth beyond the workers
	MaxSessions       int           // live protocol sessions
	MaxOutstanding    int           // outstanding JSON-RPC requests across sessions
	MaxHeaderBytes    int           // request header bytes
	MaxBodyBytes      int           // request body bytes
	MaxResponseBytes  int           // response bytes
	AuthConcurrency   int           // concurrent authentications
	DPoPConcurrency   int           // concurrent DPoP verifications
	MaxObservations   int           // observe records in flight to the sink
	AdmissionBudget   int           // per-source admission budget (token bucket size)
	CleanupPerOp      int           // bounded cleanup scan per operation
	ReadHeaderTimeout time.Duration // slowloris: header read deadline
	ReadTimeout       time.Duration // full request read deadline
	WriteTimeout      time.Duration // response write deadline
	IdleTimeout       time.Duration // idle keep-alive deadline
	HandshakeTimeout  time.Duration // TLS handshake deadline
	RequestDeadline   time.Duration // absolute per-request deadline
	SessionTTL        time.Duration // idle session expiry
	ShutdownTimeout   time.Duration // graceful-shutdown budget
}

func limErr(detail string) error {
	return mcperr.New(mcperr.ReasonListenerConfigInvalid, "runtime.limits", detail)
}

// Validate enforces positivity, hard-cap ceilings, and consistency.
func (c RuntimeLimitConfig) Validate() error {
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

// NewRuntimeLimits validates c into an immutable RuntimeLimits.
func NewRuntimeLimits(c RuntimeLimitConfig) (RuntimeLimits, error) {
	if err := c.Validate(); err != nil {
		return RuntimeLimits{}, err
	}
	return RuntimeLimits{c: c}, nil
}

// DefaultRuntimeLimits returns a conservative, valid runtime bound set for tests and
// the dormant default wiring.
func DefaultRuntimeLimits() RuntimeLimits {
	l, err := NewRuntimeLimits(RuntimeLimitConfig{
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
		panic("runtime: DefaultRuntimeLimits invalid: " + err.Error())
	}
	return l
}

// Accessors (immutable).

func (l RuntimeLimits) MaxConns() int                    { return l.c.MaxConns }
func (l RuntimeLimits) MaxConcurrent() int               { return l.c.MaxConcurrent }
func (l RuntimeLimits) QueueDepth() int                  { return l.c.QueueDepth }
func (l RuntimeLimits) MaxSessions() int                 { return l.c.MaxSessions }
func (l RuntimeLimits) MaxOutstanding() int              { return l.c.MaxOutstanding }
func (l RuntimeLimits) MaxHeaderBytes() int              { return l.c.MaxHeaderBytes }
func (l RuntimeLimits) MaxBodyBytes() int                { return l.c.MaxBodyBytes }
func (l RuntimeLimits) MaxResponseBytes() int            { return l.c.MaxResponseBytes }
func (l RuntimeLimits) AuthConcurrency() int             { return l.c.AuthConcurrency }
func (l RuntimeLimits) DPoPConcurrency() int             { return l.c.DPoPConcurrency }
func (l RuntimeLimits) MaxObservations() int             { return l.c.MaxObservations }
func (l RuntimeLimits) AdmissionBudget() int             { return l.c.AdmissionBudget }
func (l RuntimeLimits) CleanupPerOp() int                { return l.c.CleanupPerOp }
func (l RuntimeLimits) ReadHeaderTimeout() time.Duration { return l.c.ReadHeaderTimeout }
func (l RuntimeLimits) ReadTimeout() time.Duration       { return l.c.ReadTimeout }
func (l RuntimeLimits) WriteTimeout() time.Duration      { return l.c.WriteTimeout }
func (l RuntimeLimits) IdleTimeout() time.Duration       { return l.c.IdleTimeout }
func (l RuntimeLimits) HandshakeTimeout() time.Duration  { return l.c.HandshakeTimeout }
func (l RuntimeLimits) RequestDeadline() time.Duration   { return l.c.RequestDeadline }
func (l RuntimeLimits) SessionTTL() time.Duration        { return l.c.SessionTTL }
func (l RuntimeLimits) ShutdownTimeout() time.Duration   { return l.c.ShutdownTimeout }
