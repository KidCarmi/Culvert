package session

import (
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// Manager owns all live sessions and the fleet-wide outstanding-request budget.
// It bounds the session count and the total outstanding requests across sessions,
// and drives expiration. Every mutating method is safe for concurrent use.
type Manager struct {
	mu               sync.Mutex
	sessions         map[string]*Session
	totalOutstanding int
	now              Clock

	gatewayLim limits.Limits
	mgmtLim    limits.Limits
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

func (m *Manager) limitsFor(cap protocol.Capability) limits.Limits {
	if cap == protocol.Management {
		return m.mgmtLim
	}
	return m.gatewayLim
}

// Open creates a new session bound to a capability and peer role. It fails if the
// id is already open or the Manager is at its (capability-specific) session cap.
func (m *Manager) Open(id string, cap protocol.Capability, role protocol.PeerRole) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[id]; ok {
		return nil, mcperr.New(mcperr.ReasonInvalidLifecycle, "session.open", "session id already open")
	}
	lim := m.limitsFor(cap)
	if len(m.sessions) >= lim.MaxSessions() {
		return nil, mcperr.New(mcperr.ReasonResourceLimit, "session.open", "session cap reached")
	}
	s := &Session{
		id:         id,
		cap:        cap,
		role:       role,
		state:      protocol.StateNew,
		lim:        lim,
		mgr:        m,
		lastActive: m.now(),
		dirs:       make(map[protocol.Direction]*dirState, 2),
	}
	m.sessions[id] = s
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
// fleet total. Idempotent.
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
	s.mu.Unlock()
	m.totalOutstanding -= pending
	if m.totalOutstanding < 0 {
		m.totalOutstanding = 0
	}
	delete(m.sessions, id)
}

// SessionCount returns the number of live sessions.
func (m *Manager) SessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// TotalOutstanding returns the fleet-wide pending-request count.
func (m *Manager) TotalOutstanding() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totalOutstanding
}

// Sweep expires sessions idle for longer than their SessionTTL, releasing their
// outstanding budget. It is a bounded scan over live sessions (there is no
// per-entry timer goroutine) and returns the number of sessions reclaimed.
// Callers invoke it on a cadence; it uses the injected clock.
func (m *Manager) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	var expired []string
	for id, s := range m.sessions {
		s.mu.Lock()
		idle := now.Sub(s.lastActive)
		ttl := s.lim.SessionTTL()
		s.mu.Unlock()
		if idle > ttl {
			expired = append(expired, id)
		}
	}
	for _, id := range expired {
		m.closeLocked(id)
	}
	return len(expired)
}

// chargeOutstanding attempts to reserve one unit of the fleet-wide outstanding
// budget. Caller holds no manager lock. Returns false if the total cap is hit.
func (m *Manager) chargeOutstanding(lim limits.Limits) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.totalOutstanding >= lim.MaxTotalOutstanding() {
		return false
	}
	m.totalOutstanding++
	return true
}

// releaseOutstanding returns one unit of the fleet-wide outstanding budget.
func (m *Manager) releaseOutstanding() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.totalOutstanding > 0 {
		m.totalOutstanding--
	}
}
