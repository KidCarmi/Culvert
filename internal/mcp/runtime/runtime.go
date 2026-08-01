package runtime

import (
	"context"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Runtime owns the two dedicated MCP listeners (Gateway and Management) and their
// transactional lifecycle. It is DISABLED BY DEFAULT: when neither listener is
// enabled, Start binds no socket, starts no goroutine/timer, and the SWG request
// path is completely untouched.
type Runtime struct {
	cfg RuntimeConfig
	rev uint64

	mu         sync.Mutex
	started    bool
	stopped    bool
	gateway    *Listener
	management *Listener
}

// NewRuntime validates the whole configuration (both listeners + their isolation)
// and returns a Runtime. An unsafe/zero/negative/wildcard/conflicting configuration
// fails here, before anything binds.
func NewRuntime(cfg RuntimeConfig) (*Runtime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Runtime{cfg: cfg, rev: 1}, nil
}

// Enabled reports whether any MCP listener is enabled.
func (rt *Runtime) Enabled() bool { return rt.cfg.Enabled() }

// Start binds and serves every enabled listener TRANSACTIONALLY: both sockets are
// bound before either serves, so an address/port conflict (or any bind error) rolls
// back cleanly with nothing left serving. A disabled runtime returns nil immediately
// having bound nothing.
func (rt *Runtime) Start() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.started {
		return mcperr.New(mcperr.ReasonListenerConfigInvalid, "runtime.start", "runtime already started")
	}
	if !rt.cfg.Enabled() {
		return nil // disabled-by-default: bind nothing, start no goroutine
	}
	var bound []*Listener
	rollback := func() {
		for _, l := range bound {
			if l.netln != nil {
				_ = l.netln.Close() //nolint:errcheck // best-effort rollback close
			}
		}
	}
	if rt.cfg.Gateway.Enabled {
		l, err := newListener(rt.cfg.Gateway, rt.cfg.Deps, "gateway", rt.rev)
		if err != nil {
			return err
		}
		if err := l.bind(); err != nil {
			return mcperr.Wrap(mcperr.ReasonListenerConfigInvalid, "runtime.start", "gateway listener bind failed", err)
		}
		bound = append(bound, l)
		rt.gateway = l
	}
	if rt.cfg.Management.Enabled {
		l, err := newListener(rt.cfg.Management, rt.cfg.Deps, "management", rt.rev)
		if err != nil {
			rollback()
			rt.gateway = nil
			return err
		}
		if err := l.bind(); err != nil {
			rollback()
			rt.gateway = nil
			return mcperr.Wrap(mcperr.ReasonListenerConfigInvalid, "runtime.start", "management listener bind failed", err)
		}
		bound = append(bound, l)
		rt.management = l
	}
	for _, l := range bound {
		l.serve()
	}
	rt.started = true
	return nil
}

// Shutdown stops accepting new requests, drains in-flight requests bounded by ctx,
// force-closes anything still open at the deadline, closes the sockets and stops the
// sweepers — then leaves no goroutine, timer or socket behind. It is idempotent.
func (rt *Runtime) Shutdown(ctx context.Context) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.stopped || !rt.started {
		rt.stopped = true
		return nil
	}
	var wg sync.WaitGroup
	for _, l := range rt.listeners() {
		wg.Add(1)
		go func(l *Listener) {
			defer wg.Done()
			l.stop(ctx)
		}(l)
	}
	wg.Wait()
	rt.stopped = true
	return nil
}

// Addr returns the bound address of a capability's listener (after Start), or "" if
// that listener is not enabled/bound. Primarily for tests that bind port 0.
func (rt *Runtime) Addr(management bool) string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	l := rt.gateway
	if management {
		l = rt.management
	}
	if l == nil || l.netln == nil {
		return ""
	}
	return l.netln.Addr().String()
}

// Health returns the per-listener typed health snapshots (Gateway first when both
// are enabled). A disabled listener contributes a Disabled-phase snapshot.
func (rt *Runtime) Health() []HealthSnapshot {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]HealthSnapshot, 0, 2)
	if rt.gateway != nil {
		out = append(out, rt.gateway.health())
	}
	if rt.management != nil {
		out = append(out, rt.management.health())
	}
	return out
}

// listeners returns the live listeners (caller holds rt.mu).
func (rt *Runtime) listeners() []*Listener {
	var out []*Listener
	if rt.gateway != nil {
		out = append(out, rt.gateway)
	}
	if rt.management != nil {
		out = append(out, rt.management)
	}
	return out
}
