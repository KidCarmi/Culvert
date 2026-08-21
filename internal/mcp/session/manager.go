package session

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// Manager owns all live sessions and the per-capability outstanding-request
// budget. It bounds the session count and, INDEPENDENTLY per capability, the
// total outstanding requests across sessions, and drives expiration. Every
// mutating method is safe for concurrent use.
//
// Lock discipline (deadlock-free by construction): the outstanding counters are
// atomic, so the request hot paths (RegisterRequest / CorrelateResponse / Cancel)
// hold only the session lock and never acquire the manager lock. The manager lock
// is acquired only by session-directory operations (Open / Close / Sweep /
// Get / counts), which may then take a session lock — a single, consistent lock
// order (manager → session), so no ABBA cycle is possible.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	now      Clock

	gatewayLim limits.Limits
	mgmtLim    limits.Limits

	// outstanding is the fleet-wide in-flight count PER CAPABILITY, indexed by the
	// protocol.Capability value (Gateway, Management). Keeping them separate is the
	// capability-isolation guarantee: Gateway load can never exhaust Management's
	// budget or vice versa.
	outstanding [2]atomic.Int64
	// sessCount is the live-session count PER CAPABILITY (guarded by mu), so one
	// capability's session load never blocks the other from opening sessions.
	sessCount [2]int
}

// NewManager builds a Manager with independent Gateway and Management limit sets
// and an injected clock. A nil clock defaults to time.Now.
func NewManager(gatewayLim, mgmtLim limits.Limits, clk Clock) *Manager {
	if clk == nil {
		clk = time.Now
	}
	return &Manager{
		sessions:   make(map[string]*Session),
		now:        clk,
		gatewayLim: gatewayLim,
		mgmtLim:    mgmtLim,
	}
}

func (m *Manager) limitsFor(capability protocol.Capability) limits.Limits {
	if capability == protocol.Management {
		return m.mgmtLim
	}
	return m.gatewayLim
}

// Open creates a new session bound to a capability and peer role. It fails if the
// id is already open or the Manager is at its (capability-specific) session cap.
func (m *Manager) Open(id string, capability protocol.Capability, role protocol.PeerRole) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[id]; ok {
		return nil, mcperr.New(mcperr.ReasonInvalidLifecycle, "session.open", "session id already open")
	}
	lim := m.limitsFor(capability)
	if m.sessCount[capability] >= lim.MaxSessions() {
		return nil, mcperr.New(mcperr.ReasonResourceLimit, "session.open", "session cap reached")
	}
	s := &Session{
		id:         id,
		capability: capability,
		role:       role,
		state:      protocol.StateNew,
		lim:        lim,
		mgr:        m,
		lastActive: m.now(),
		dirs:       make(map[protocol.Direction]*dirState, 2),
	}
	m.sessions[id] = s
	m.sessCount[capability]++
	return s, nil
}

// Get returns a live session by id.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

// Close terminates a session and releases its outstanding budget back to the
// per-capability total. Idempotent.
func (m *Manager) Close(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeLocked(id)
}

func (m *Manager) closeLocked(id string) {
	s, ok := m.sessions[id]
	if !ok {
		return
	}
	s.mu.Lock()
	pending := s.pendingCountLocked()
	s.closed = true
	s.state = protocol.StateClosed
	capability := s.capability
	s.mu.Unlock()
	m.releaseN(capability, pending)
	delete(m.sessions, id)
	if m.sessCount[capability] > 0 {
		m.sessCount[capability]--
	}
}

// SessionCount returns the number of live sessions.
func (m *Manager) SessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// TotalOutstanding returns the fleet-wide pending-request count across both
// capabilities.
func (m *Manager) TotalOutstanding() int {
	return int(m.outstanding[protocol.Gateway].Load() + m.outstanding[protocol.Management].Load())
}

// OutstandingFor returns the fleet-wide pending count for one capability.
func (m *Manager) OutstandingFor(capability protocol.Capability) int {
	return int(m.outstanding[capability].Load())
}

// Sweep expires sessions idle for longer than their SessionTTL, and — on
// sessions that are still active — expires individual outstanding requests older
// than the same TTL so a peer that keeps a session busy (e.g. pinging) while
// withholding responses cannot pin the outstanding budget indefinitely. It is a
// bounded scan over live sessions (no per-entry timer goroutine) and returns the
// number of SESSIONS reclaimed. Callers invoke it on a cadence; it uses the
// injected clock.
func (m *Manager) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	var expired []string
	for id, s := range m.sessions {
		s.mu.Lock()
		idle := now.Sub(s.lastActive)
		ttl := s.lim.SessionTTL()
		if idle > ttl {
			s.mu.Unlock()
			expired = append(expired, id)
			continue
		}
		released := s.sweepStalePendingLocked(now)
		capability := s.capability
		s.mu.Unlock()
		m.releaseN(capability, released)
	}
	for _, id := range expired {
		m.closeLocked(id)
	}
	return len(expired)
}

// chargeOutstanding reserves one unit of a capability's fleet-wide outstanding
// budget via a lock-free CAS loop. It acquires NO manager lock, so it is safe to
// call while a session lock is held. Returns false if the capability's total cap
// is hit.
func (m *Manager) chargeOutstanding(capability protocol.Capability, lim limits.Limits) bool {
	ctr := &m.outstanding[capability]
	maxN := int64(lim.MaxTotalOutstanding())
	for {
		cur := ctr.Load()
		if cur >= maxN {
			return false
		}
		if ctr.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// releaseOutstanding returns one unit of a capability's outstanding budget.
func (m *Manager) releaseOutstanding(capability protocol.Capability) {
	m.releaseN(capability, 1)
}

// releaseN returns n units (n>=0), clamped so the counter never goes negative.
func (m *Manager) releaseN(capability protocol.Capability, n int) {
	if n <= 0 {
		return
	}
	ctr := &m.outstanding[capability]
	for {
		cur := ctr.Load()
		next := cur - int64(n)
		if next < 0 {
			next = 0
		}
		if ctr.CompareAndSwap(cur, next) {
			return
		}
	}
}
