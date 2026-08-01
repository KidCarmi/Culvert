package protocol

// State is a session's protocol lifecycle state. Lifecycle is validated so a
// session cannot skip establishment (MCP-PROTO-012): before negotiation the only
// admissible method is initialize (MCP-PROTO-002); the handshake methods are
// one-time.
type State int

const (
	// StateNew: created, not yet initialized. Only initialize is admissible.
	StateNew State = iota
	// StateInitializing: initialize accepted, awaiting notifications/initialized.
	StateInitializing
	// StateInitialized: steady state; all admitted non-handshake methods allowed.
	StateInitialized
	// StateClosed: terminal; nothing is admissible.
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateNew:
		return "new"
	case StateInitializing:
		return "initializing"
	case StateInitialized:
		return "initialized"
	default:
		return "closed"
	}
}

// LifecycleAdmits reports whether method is legal in state s, treating the
// handshake methods as one-time and gating everything else behind establishment.
// It is a pure function; the session package holds the state under its own lock.
//
//   - StateNew admits ONLY initialize (pre-negotiation bootstrap).
//   - StateInitializing admits notifications/initialized (to complete the
//     handshake) and ping.
//   - StateInitialized admits every method EXCEPT the one-time handshake pair, so
//     a duplicate initialize or a second notifications/initialized is an
//     invalid-lifecycle error, not a silent no-op.
//   - StateClosed admits nothing.
func LifecycleAdmits(s State, method string) bool {
	switch s {
	case StateNew:
		return method == "initialize"
	case StateInitializing:
		return method == "notifications/initialized" || method == "ping"
	case StateInitialized:
		return method != "initialize" && method != "notifications/initialized"
	default:
		return false
	}
}

// LifecycleNext returns the state after a method that LifecycleAdmits accepted.
// Only the two handshake methods advance the state; everything else leaves it
// unchanged.
func LifecycleNext(s State, method string) State {
	switch {
	case s == StateNew && method == "initialize":
		return StateInitializing
	case s == StateInitializing && method == "notifications/initialized":
		return StateInitialized
	default:
		return s
	}
}
