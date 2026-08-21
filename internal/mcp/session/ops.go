package session

import (
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// Session is one MCP protocol session. All fields are guarded by mu; callers use
// the methods, never the fields.
type Session struct {
	mu         sync.Mutex
	id         string
	capability protocol.Capability
	role       protocol.PeerRole

	state      protocol.State
	version    protocol.Version
	hasVersion bool

	dirs map[protocol.Direction]*dirState
	lim  limits.Limits
	mgr  *Manager

	lastActive time.Time
	closed     bool
}

// --- accessors -------------------------------------------------------------

// ID returns the session id.
func (s *Session) ID() string { return s.id }

// Capability returns the session's surface.
func (s *Session) Capability() protocol.Capability { return s.capability }

// Role returns the session's peer role (leg).
func (s *Session) Role() protocol.PeerRole { return s.role }

// State returns the current lifecycle state.
func (s *Session) State() protocol.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Version returns the negotiated version and whether one has been negotiated.
func (s *Session) Version() (protocol.Version, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version, s.hasVersion
}

// PendingCount returns the number of outstanding requests across both directions.
func (s *Session) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingCountLocked()
}

func (s *Session) pendingCountLocked() int {
	n := 0
	for _, ds := range s.dirs {
		n += len(ds.pending)
	}
	return n
}

func (s *Session) dirLocked(dir protocol.Direction) *dirState {
	ds := s.dirs[dir]
	if ds == nil {
		ds = newDirState(s.lim.MaxOutstandingPerSession())
		s.dirs[dir] = ds
	}
	return ds
}

func oppositeDir(d protocol.Direction) protocol.Direction {
	if d == protocol.ClientOriginated {
		return protocol.ServerOriginated
	}
	return protocol.ClientOriginated
}

// --- lifecycle + admission -------------------------------------------------

// SetNegotiatedVersion records the version chosen at initialize. It fails if a
// version is already negotiated (negotiation happens once) or the version is not
// supported (default deny — MCP-PROTO-010).
func (s *Session) SetNegotiatedVersion(v protocol.Version) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return mcperr.New(mcperr.ReasonInvalidLifecycle, "session.version", "session closed")
	}
	if s.hasVersion {
		return mcperr.New(mcperr.ReasonInvalidLifecycle, "session.version", "version already negotiated")
	}
	if !protocol.IsSupported(v) {
		return mcperr.New(mcperr.ReasonUnsupportedVersion, "session.version", "version not in supported allowlist")
	}
	s.version = v
	s.hasVersion = true
	return nil
}

// Admit gates a methodful message (request or notification) through the
// lifecycle rules (bootstrap + one-time handshake) and the reviewed method
// registry — including the wire-class check (a notification-only method must not
// carry an id and vice versa) — then advances the lifecycle state on an accepted
// handshake method. Responses are NOT admitted here — they are correlated
// (CorrelateResponse).
func (s *Session) Admit(dir protocol.Direction, class jsonrpc.Class, method string) (protocol.Admission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return protocol.Admission{Handling: protocol.HandlingRejected, Reason: mcperr.ReasonInvalidLifecycle},
			mcperr.New(mcperr.ReasonInvalidLifecycle, "admit", "session closed")
	}
	if !protocol.LifecycleAdmits(s.state, method) {
		return protocol.Admission{Handling: protocol.HandlingRejected, Reason: mcperr.ReasonInvalidLifecycle},
			mcperr.New(mcperr.ReasonInvalidLifecycle, "admit", "method not allowed in state "+s.state.String())
	}
	// The handshake cannot complete without a negotiated version: allowing
	// notifications/initialized (and thus steady-state admission) while hasVersion
	// is false would run the whole session outside the version allowlist/adapters.
	if method == "notifications/initialized" && !s.hasVersion {
		return protocol.Admission{Handling: protocol.HandlingRejected, Reason: mcperr.ReasonInvalidLifecycle},
			mcperr.New(mcperr.ReasonInvalidLifecycle, "admit", "handshake completion before version negotiation")
	}
	adm := protocol.Admit(s.capability, dir, class, method)
	if adm.Handling == protocol.HandlingRejected {
		return adm, mcperr.New(adm.Reason, "admit", adm.Detail)
	}
	s.state = protocol.LifecycleNext(s.state, method)
	s.lastActive = s.mgr.now()
	return adm, nil
}

// --- outstanding-request table --------------------------------------------

// RegisterRequest records an in-flight request in the (direction) outstanding
// table so its response or cancellation can be correlated. It enforces
// per-requestor id-uniqueness (a duplicate id already outstanding in this
// direction is rejected) and the per-session + fleet outstanding bounds. It does
// NOT interact with the other direction.
func (s *Session) RegisterRequest(dir protocol.Direction, owner string, id jsonrpc.ID, method string) error {
	if !id.Correlatable() {
		return mcperr.New(mcperr.ReasonInvalidJSONRPC, "register", "cannot register a request without a correlatable id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return mcperr.New(mcperr.ReasonInvalidLifecycle, "register", "session closed")
	}
	ds := s.dirLocked(dir)
	key := id.Key()
	if _, dup := ds.pending[key]; dup {
		return mcperr.New(mcperr.ReasonInvalidJSONRPC, "register", "request id already outstanding in this direction")
	}
	if len(ds.pending) >= s.lim.MaxOutstandingPerSession() {
		return mcperr.New(mcperr.ReasonResourceLimit, "register", "per-session outstanding cap reached")
	}
	if !s.mgr.chargeOutstanding(s.capability, s.lim) {
		return mcperr.New(mcperr.ReasonResourceLimit, "register", "fleet outstanding cap reached")
	}
	ds.pending[key] = &entry{id: id, owner: owner, method: method, registeredAt: s.mgr.now()}
	s.lastActive = s.mgr.now()
	return nil
}

// CorrelateResult is the outcome of correlating an inbound response.
type CorrelateResult int

const (
	// Completed — the response matched a pending request, which is now released.
	Completed CorrelateResult = iota + 1
	// ToleratedAfterCancel — the response arrived after the request was cancelled;
	// tolerated per the cancellation spec, not a fault.
	ToleratedAfterCancel
)

// CorrelateResponse matches an inbound response to a pending request in the SAME
// direction and releases it. It NEVER touches the other direction, and it
// releases ONLY on an exact same-direction pending match — an uncorrelated
// response deletes nothing (the remote-state-deletion guard, MCP-PROTO-013). A
// second completion of an already-completed request is a duplicate-completion
// fault; a response after a cancellation is tolerated.
func (s *Session) CorrelateResponse(dir protocol.Direction, id jsonrpc.ID) (CorrelateResult, error) {
	if !id.Correlatable() {
		return 0, mcperr.New(mcperr.ReasonInvalidJSONRPC, "correlate", "response id is not correlatable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, mcperr.New(mcperr.ReasonInvalidLifecycle, "correlate", "session closed")
	}
	key := id.Key()
	ds := s.dirs[dir]
	if ds == nil {
		return 0, mcperr.New(mcperr.ReasonUncorrelatedResponse, "correlate", "response id matches no outstanding request in this direction")
	}
	if _, ok := ds.pending[key]; ok {
		ds.resolve(key, resCompleted)
		s.mgr.releaseOutstanding(s.capability)
		s.lastActive = s.mgr.now()
		return Completed, nil
	}
	r, ok := ds.resolved[key]
	if !ok {
		return 0, mcperr.New(mcperr.ReasonUncorrelatedResponse, "correlate", "response id matches no outstanding request in this direction")
	}
	if r == resCancelled {
		s.lastActive = s.mgr.now()
		return ToleratedAfterCancel, nil
	}
	return 0, mcperr.New(mcperr.ReasonDuplicateCompletion, "correlate", "second completion for an already-completed request")
}

// CancelResult is the outcome of a cancellation.
type CancelResult int

const (
	// CancelApplied — a pending request owned by the canceller was released.
	CancelApplied CancelResult = iota + 1
	// CancelLate — the target was already resolved (completed or cancelled) —
	// tolerated no-op, no state changed.
	CancelLate
	// CancelNoTarget — no request with this id in this direction — tolerated no-op,
	// all state retained.
	CancelNoTarget
	// CancelRejectedOppositeDirection — the id is outstanding ONLY in the other
	// direction — rejected, the other direction's entry retained.
	CancelRejectedOppositeDirection
	// CancelRejectedWrongOwner — the id is pending in this direction but owned by a
	// different requestor — rejected, retained.
	CancelRejectedWrongOwner
	// CancelRejectedInitialize — the target is the initialize request, which must
	// not be cancelled — rejected, retained.
	CancelRejectedInitialize
)

// Applied reports whether the cancellation released a request.
func (r CancelResult) Applied() bool { return r == CancelApplied }

// Cancel applies a cancellation naming a request id, owned by owner, in direction
// dir. It enforces same-direction + owning-requestor + initialize-exempt rules
// and NEVER deletes state it is not entitled to: an opposite-direction id, a
// wrong-owner id, and the initialize request are all left intact. A late
// cancellation (target already resolved) and an unknown id are tolerated no-ops.
func (s *Session) Cancel(dir protocol.Direction, owner string, id jsonrpc.ID) CancelResult {
	if !id.Correlatable() {
		return CancelNoTarget
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return CancelNoTarget
	}
	key := id.Key()
	if res, owned := s.cancelInDirLocked(dir, owner, key); owned {
		return res
	}
	// Not in this direction: if it is outstanding in the OTHER direction, this is
	// an opposite-direction cancellation attempt — reject and retain it.
	if od := s.dirs[oppositeDir(dir)]; od != nil {
		if _, ok := od.pending[key]; ok {
			return CancelRejectedOppositeDirection
		}
	}
	return CancelNoTarget
}

// cancelInDirLocked applies a cancellation against direction dir's own state.
// It returns (result, true) when dir knows the id (pending or recently resolved)
// and (_, false) when dir has no knowledge of it. It never touches the other
// direction. Caller holds s.mu.
func (s *Session) cancelInDirLocked(dir protocol.Direction, owner, key string) (CancelResult, bool) {
	ds := s.dirs[dir]
	if ds == nil {
		return 0, false
	}
	if e, ok := ds.pending[key]; ok {
		switch {
		case e.method == "initialize":
			return CancelRejectedInitialize, true
		case e.owner != owner:
			return CancelRejectedWrongOwner, true
		default:
			ds.resolve(key, resCancelled)
			s.mgr.releaseOutstanding(s.capability)
			s.lastActive = s.mgr.now()
			return CancelApplied, true
		}
	}
	if _, ok := ds.resolved[key]; ok {
		return CancelLate, true
	}
	return 0, false
}

// sweepStalePendingLocked deletes pending requests older than the session TTL and
// returns how many were removed (so the caller can release that many outstanding
// budget units). It runs even while the session is otherwise active, so a peer
// that withholds responses cannot pin the budget. Caller holds s.mu.
func (s *Session) sweepStalePendingLocked(now time.Time) int {
	ttl := s.lim.SessionTTL()
	released := 0
	for _, ds := range s.dirs {
		for key, e := range ds.pending {
			if now.Sub(e.registeredAt) > ttl {
				delete(ds.pending, key)
				released++
			}
		}
	}
	return released
}
