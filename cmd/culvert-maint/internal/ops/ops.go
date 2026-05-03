// Package ops models the Maintenance Agent's operation framework:
// operation records, the state machine, stage tracking, and the global
// maintenance lock.
//
// D1.6a ships the framework even though no state-changing operations
// exist yet. The lock is exercised by tests that submit synthetic ops;
// real ops land in D1.6b/c.
//
// See roadmap/D1.6-maintenance-agent-implementation-plan.md §§ 2.5,
// 4.9, 5.4.
package ops

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// State is the operation state-machine value.
type State string

// State values are part of the stable operation-record schema (D1.6 plan § 2.5).
const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
)

// IsTerminal reports whether s is a terminal state.
func (s State) IsTerminal() bool {
	return s == StateSucceeded || s == StateFailed || s == StateCancelled
}

// Stage tracks one phase of an operation flow.
type Stage struct {
	Name    string    `json:"stage"`
	State   State     `json:"state"`
	Started time.Time `json:"started_at,omitempty"`
	Ended   time.Time `json:"ended_at,omitempty"`
	Output  string    `json:"output,omitempty"`
}

// Op is the operation record. JSON-shaped for the API.
type Op struct {
	ID             string                 `json:"op_id"`
	Kind           string                 `json:"kind"`
	State          State                  `json:"state"`
	Actor          string                 `json:"actor"`
	IdempotencyKey string                 `json:"idempotency_key,omitempty"`
	LockHeldBy     string                 `json:"lock_held_by,omitempty"`
	Started        time.Time              `json:"started_at"`
	Finished       *time.Time             `json:"finished_at,omitempty"`
	FailureReason  string                 `json:"failure_reason,omitempty"`
	Params         map[string]interface{} `json:"params,omitempty"`
	Progress       []Stage                `json:"progress"`
	Result         map[string]interface{} `json:"result,omitempty"`
}

// stateChangingKinds is the production allowlist of operation kinds
// that acquire the global maintenance lock. D1.6a ships an empty list
// — there are no production state-changing kinds in this slice. Each
// future slice (D1.6b/c) adds its kinds here alongside the matching
// API handler, runner template, sudoers entry, and tests (per § 4.6
// four-step contract).
var stateChangingKinds = map[string]struct{}{
	// D1.6a: empty by design.
}

// SyntheticStateChangingKind is exported for tests that need to
// exercise the lock framework without introducing a production kind.
// Production handlers MUST NOT emit this kind.
const SyntheticStateChangingKind = "synthetic.state-changing"

// IsStateChanging reports whether kind mutates /data, /backup, the
// stack, or persistent state. Read-only kinds run concurrently;
// state-changing kinds compete for the global maintenance lock
// (§ 4.9). The synthetic kind is recognised so tests can exercise the
// lock framework; production handlers must not use it.
func IsStateChanging(kind string) bool {
	if kind == SyntheticStateChangingKind {
		return true
	}
	_, ok := stateChangingKinds[kind]
	return ok
}

// FailureReason is a stable string that classifies why an op failed.
// New values may be added; existing values must not change meaning.
type FailureReason string

// FailureReason values are part of the stable audit schema (D1.6 plan § 4.8).
const (
	ReasonTimeout                 FailureReason = "timeout"
	ReasonValidation              FailureReason = "validation"
	ReasonAuth                    FailureReason = "auth"
	ReasonHealthFailed            FailureReason = "health_failed"
	ReasonCLIError                FailureReason = "cli_error"
	ReasonCommandError            FailureReason = "command_error"
	ReasonConcurrencyConflict     FailureReason = "concurrency_conflict"
	ReasonAgentRestartInterrupted FailureReason = "agent_restart_interrupted"
)

// NewID generates a fresh ULID for an op_id. Time-prefixed and
// lexicographically sortable.
func NewID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}

// Conflict is returned by Manager.Begin when a state-changing op cannot
// acquire the lock because another state-changing op is in flight.
type Conflict struct {
	Holder *Op
}

func (c *Conflict) Error() string {
	if c.Holder == nil {
		return "ops: state-changing operation already in progress"
	}
	return fmt.Sprintf("ops: state-changing operation %s (%s, started_at=%s, actor=%s) already in progress",
		c.Holder.ID, c.Holder.Kind, c.Holder.Started.Format(time.RFC3339), c.Holder.Actor)
}

// IsConflict reports whether err is a *Conflict.
func IsConflict(err error) bool {
	var c *Conflict
	return errors.As(err, &c)
}

// Manager owns the in-memory active-op map and the global maintenance
// lock. Goroutine-safe.
type Manager struct {
	mu     sync.Mutex
	active map[string]*Op // by op_id
	holder *Op            // current state-changing op holding the lock, or nil
	now    func() time.Time
}

// NewManager returns a fresh Manager. clock may be nil (defaults to
// time.Now); tests inject a deterministic clock.
func NewManager(clock func() time.Time) *Manager {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Manager{
		active: map[string]*Op{},
		now:    clock,
	}
}

// Begin admits a new operation. If kind is state-changing and the lock
// is already held, returns *Conflict. On success, the op is added to
// the active map in StateRunning and (for state-changing kinds) the
// lock is acquired.
//
// Begin does not run the actual op flow — callers run their stages and
// then call Finish to release the slot.
func (m *Manager) Begin(kind, actor, idempotencyKey string, params map[string]interface{}) (*Op, error) {
	if kind == "" || actor == "" {
		return nil, errors.New("ops: kind and actor are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	stateChanging := IsStateChanging(kind)
	if stateChanging && m.holder != nil {
		// Return a stable snapshot so callers can render 409 bodies.
		return nil, &Conflict{Holder: m.cloneLocked(m.holder)}
	}

	op := &Op{
		ID:             NewID(),
		Kind:           kind,
		State:          StateRunning,
		Actor:          actor,
		IdempotencyKey: idempotencyKey,
		Started:        m.now(),
		Params:         params,
		Progress:       []Stage{},
	}
	if stateChanging {
		op.LockHeldBy = op.ID
		m.holder = op
	}
	m.active[op.ID] = op
	return m.cloneLocked(op), nil
}

// Finish transitions opID to terminal state. If reason is non-empty it
// is recorded on the op. Releases the lock if the op was holding it.
// finalState must be a terminal state.
func (m *Manager) Finish(opID string, finalState State, reason FailureReason, result map[string]interface{}) error {
	if !finalState.IsTerminal() {
		return fmt.Errorf("ops: Finish called with non-terminal state %q", finalState)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.active[opID]
	if !ok {
		return fmt.Errorf("ops: unknown op_id %q", opID)
	}
	if op.State.IsTerminal() {
		return fmt.Errorf("ops: op %s already in terminal state %q", opID, op.State)
	}
	now := m.now()
	op.State = finalState
	op.Finished = &now
	if reason != "" {
		op.FailureReason = string(reason)
	}
	if result != nil {
		op.Result = result
	}
	// Release the lock if this op held it.
	if m.holder != nil && m.holder.ID == opID {
		m.holder = nil
	}
	return nil
}

// AddStage appends a stage transition record to opID. The stage is
// stamped with m.now() unless start is non-zero.
func (m *Manager) AddStage(opID string, stage Stage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.active[opID]
	if !ok {
		return fmt.Errorf("ops: unknown op_id %q", opID)
	}
	if stage.Started.IsZero() {
		stage.Started = m.now()
	}
	op.Progress = append(op.Progress, stage)
	return nil
}

// Get returns a snapshot of the op record. Returns nil if not found.
func (m *Manager) Get(opID string) *Op {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.active[opID]
	if !ok {
		return nil
	}
	return m.cloneLocked(op)
}

// Holder returns the current lock-holding op or nil. Snapshot.
func (m *Manager) Holder() *Op {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.holder == nil {
		return nil
	}
	return m.cloneLocked(m.holder)
}

// MarkAllInterrupted is called at startup to scan persisted state and
// transition any pending/running ops to failed with
// ReasonAgentRestartInterrupted. The agent never guesses success after
// restart (§ 5.4).
//
// D1.6a in-memory model has no persistence to scan; the function is a
// no-op for D1.6a but ships now so the contract is in place. D1.6b/c
// wire it to the on-disk index.
func (m *Manager) MarkAllInterrupted() int {
	return 0
}

// cloneLocked returns a defensive copy. Caller must hold m.mu.
func (m *Manager) cloneLocked(op *Op) *Op {
	if op == nil {
		return nil
	}
	cp := *op
	if op.Finished != nil {
		f := *op.Finished
		cp.Finished = &f
	}
	if len(op.Progress) > 0 {
		cp.Progress = append([]Stage(nil), op.Progress...)
	}
	if op.Params != nil {
		cp.Params = make(map[string]interface{}, len(op.Params))
		for k, v := range op.Params {
			cp.Params[k] = v
		}
	}
	if op.Result != nil {
		cp.Result = make(map[string]interface{}, len(op.Result))
		for k, v := range op.Result {
			cp.Result[k] = v
		}
	}
	return &cp
}
