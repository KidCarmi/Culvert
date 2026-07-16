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
	"sort"
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

// Operation kind constants. Stable strings; part of the audit schema.
//
// Cleanup is split into .dryrun and .commit deliberately so the
// state-changing decision is encoded in the kind, not in the params.
// The lock-check path never has to inspect params — IsStateChanging
// resolves the question from the kind alone.
const (
	KindBackupCreate  = "backup.create"
	KindBackupList    = "backup.list"
	KindRestoreDryRun = "restore.dryrun"
	KindRestoreCommit = "restore.commit"
	KindCleanupDryRun = "cleanup.dryrun"
	KindCleanupCommit = "cleanup.commit"

	// KindUpgradeCheck is the D1.6c read-only upgrade check
	// (POST /v1/upgrades/check). It inspects the local and remote image
	// digests for a requested image_ref and reports whether an upgrade
	// is available. Read-only — it does NOT acquire the maintenance lock
	// and is intentionally absent from stateChangingKinds.
	KindUpgradeCheck = "upgrades.check"

	// KindUpgradeApply is the D1.6c destructive upgrade apply
	// (POST /v1/upgrades/apply): optional pre-backup, pull the pinned
	// proxy image, recreate the stack, health-gate, and verify the
	// running digest. State-changing and exclusive (acquires the
	// maintenance lock).
	KindUpgradeApply = "upgrades.apply"

	// KindRollbackCreate is the D1.6c image-mode rollback
	// (POST /v1/rollbacks, mode=image): pull a prior pinned digest,
	// recreate the proxy, health-gate, and verify. State-changing and
	// exclusive (acquires the maintenance lock).
	KindRollbackCreate = "rollbacks.create"
)

// stateChangingKinds is the production allowlist of operation kinds
// that acquire the global maintenance lock. D1.6b activates this for
// backup.create, restore.commit, and cleanup.commit. The four-step
// § 4.6 contract — handler + template + sudoers + tests — is
// satisfied for each entry by the matching D1.6b PR.
var stateChangingKinds = map[string]struct{}{
	KindBackupCreate:   {},
	KindRestoreCommit:  {},
	KindCleanupCommit:  {},
	KindUpgradeApply:   {},
	KindRollbackCreate: {},
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
	// ReasonAgentPanic marks an op whose orchestrator goroutine panicked and was
	// recovered by ops.Run's panic barrier. The op is failed and the maintenance
	// lock released, so one malformed op can never take down the whole agent or
	// strand the lock. Distinct from cli_error so the audit trail names the class.
	ReasonAgentPanic FailureReason = "agent_panic"
	// ReasonRollbackFailed marks an op that failed AND whose recovery
	// (inline auto-)rollback also failed to restore service. It is
	// surfaced via the narrow final-reason override (a recovery stage
	// flagged FlowStage.PromoteReasonOnFailure), not a generic
	// "last failure wins" rule. See D1.6c inline-auto-rollback plan §3/§10.
	ReasonRollbackFailed FailureReason = "rollback_failed"
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

// idempEntry caches the op_id we admitted for a given
// (actor, kind, idempotency_key) tuple so that a duplicate submission
// returns the same op_id rather than starting a parallel operation.
type idempEntry struct {
	OpID string
	When time.Time
}

// DefaultIdempCacheTTL bounds how long an idempotency-cache entry
// remains live. The TTL is a soft expiry — entries past their TTL
// are NOT actively purged on a timer; instead, BeginIdempotent
// purges expired entries opportunistically as it walks the cache.
// This keeps the manager goroutine-free and prevents unbounded
// growth from many unique keys over a long process lifetime.
//
// 24h is intentionally generous: the largest legitimate
// idempotency-replay window is "the operator retries a backup that
// took most of a day to run". Entries older than 24h are statistically
// stale (the original op has long since terminated; a "duplicate"
// after that is almost certainly a fresh-intent retry that the
// operator wants treated as new work).
const DefaultIdempCacheTTL = 24 * time.Hour

// DefaultActiveRetention is how long a TERMINAL op stays in the active map
// after it finishes, so GET /v1/operations/{id} can still answer while the CP
// polls for the outcome. After this window the op is reaped. Running ops are
// never reaped by age.
const DefaultActiveRetention = 1 * time.Hour

// DefaultMaxActive is the hard cap on the active map — a backstop against a
// burst of ops within the retention window. Beyond it, the oldest-finished
// TERMINAL ops are evicted early (running ops are never evicted). Bounds memory
// for a long-lived agent regardless of throughput.
const DefaultMaxActive = 1000

// Manager owns the in-memory active-op map and the global maintenance
// lock. Goroutine-safe.
type Manager struct {
	mu     sync.Mutex
	active map[string]*Op // by op_id
	holder *Op            // current state-changing op holding the lock, or nil
	// idempCache maps "actor|kind|idempotency_key" → most recent op_id
	// admitted for that tuple. Entries are purged opportunistically
	// once they exceed idempCacheTTL. Lifetime = process lifetime;
	// on restart the cache is empty (which is correct: prior ops
	// were marked interrupted, so a resubmit must produce a fresh op).
	idempCache    map[string]idempEntry
	idempCacheTTL time.Duration
	// activeRetention / maxActive bound the active map: without them terminal
	// ops accumulate for the whole process lifetime (a slow leak proportional to
	// total ops run — flagged by the resilience break-review). Reaped
	// opportunistically on admission, mirroring purgeIdempCacheLocked.
	activeRetention time.Duration
	maxActive       int
	now             func() time.Time
}

// NewManager returns a fresh Manager. clock may be nil (defaults to
// time.Now); tests inject a deterministic clock.
func NewManager(clock func() time.Time) *Manager {
	return NewManagerWithTTL(clock, DefaultIdempCacheTTL)
}

// NewManagerWithTTL constructs a Manager with a non-default
// idempotency-cache TTL. Mainly for tests that want to exercise
// purge logic against an artificially short window.
func NewManagerWithTTL(clock func() time.Time, idempTTL time.Duration) *Manager {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if idempTTL <= 0 {
		idempTTL = DefaultIdempCacheTTL
	}
	return &Manager{
		active:          map[string]*Op{},
		idempCache:      map[string]idempEntry{},
		idempCacheTTL:   idempTTL,
		activeRetention: DefaultActiveRetention,
		maxActive:       DefaultMaxActive,
		now:             clock,
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
	m.purgeActiveLocked() // bound the active map on every admission

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

// BeginIdempotent is the idempotency-aware Begin. If idempotencyKey is
// non-empty and a prior op was admitted for the same
// (actor, kind, idempotency_key) tuple — and that op still exists in
// the active map — the prior op snapshot is returned with
// deduped=true. Otherwise this admits a new op via Begin and records
// the (tuple → op_id) mapping in the idempotency cache.
//
// Dedup runs BEFORE the state-changing-lock check (per § 2.5). A
// duplicate submission of a state-changing op while the original is
// still running returns the original op snapshot — not a 409.
//
// Empty idempotencyKey disables dedup entirely; every call admits a
// fresh op.
func (m *Manager) BeginIdempotent(kind, actor, idempotencyKey string, params map[string]interface{}) (*Op, bool, error) {
	if kind == "" || actor == "" {
		return nil, false, errors.New("ops: kind and actor are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Opportunistic purge: walk the idempotency cache and drop any
	// entry whose age exceeds idempCacheTTL. This runs at most once
	// per BeginIdempotent call, in O(N) over the cache size, holding
	// m.mu — acceptable because (a) the cache is bounded by the
	// number of distinct (actor,kind,key) tuples seen within
	// idempCacheTTL, (b) the same lock is held for the rest of the
	// function anyway, and (c) the alternative (a goroutine-driven
	// timer) would complicate Manager's shutdown story. The purge is
	// also self-throttling: as the cache shrinks past the TTL
	// boundary, subsequent walks find less work to do.
	m.purgeIdempCacheLocked()
	m.purgeActiveLocked() // bound the active map on every admission

	if idempotencyKey != "" {
		cacheKey := idempCacheKey(actor, kind, idempotencyKey)
		if entry, ok := m.idempCache[cacheKey]; ok {
			if existing, alive := m.active[entry.OpID]; alive {
				return m.cloneLocked(existing), true, nil
			}
			// Cache references a dropped op; clear and fall through
			// to admit a fresh op. Defensive against future eviction.
			delete(m.idempCache, cacheKey)
		}
	}

	stateChanging := IsStateChanging(kind)
	if stateChanging && m.holder != nil {
		return nil, false, &Conflict{Holder: m.cloneLocked(m.holder)}
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
	if idempotencyKey != "" {
		m.idempCache[idempCacheKey(actor, kind, idempotencyKey)] = idempEntry{
			OpID: op.ID,
			When: m.now(),
		}
	}
	return m.cloneLocked(op), false, nil
}

// idempCacheKey is the shape of an entry in Manager.idempCache. Pipe
// is reserved (not allowed in actor/kind by upstream validators) so it
// cannot collide with an embedded user value.
func idempCacheKey(actor, kind, idempotencyKey string) string {
	return actor + "|" + kind + "|" + idempotencyKey
}

// purgeIdempCacheLocked drops every cache entry whose age exceeds
// m.idempCacheTTL. Caller MUST hold m.mu.
//
// We accept the O(N) walk on every BeginIdempotent because (a) the
// cache size is bounded by the number of unique
// (actor,kind,idempotency_key) tuples seen within the TTL window,
// (b) idempotency keys are operator-supplied and naturally bounded
// in practice (CP retries reuse keys), and (c) the alternative
// (a per-Manager goroutine + ticker) would require a Stop() method
// on Manager and complicate the shutdown story for tests and main.
func (m *Manager) purgeIdempCacheLocked() {
	if len(m.idempCache) == 0 {
		return
	}
	cutoff := m.now().Add(-m.idempCacheTTL)
	for k, e := range m.idempCache {
		if e.When.Before(cutoff) {
			delete(m.idempCache, k)
		}
	}
}

// IdempCacheSize returns the current count of entries in the
// idempotency cache. Mainly useful for tests that need to assert
// purge behavior; production code has no need to inspect this.
func (m *Manager) IdempCacheSize() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.idempCache)
}

// ActiveSize returns the current count of ops resident in the active map
// (running + not-yet-reaped terminal). For tests asserting reap behavior.
func (m *Manager) ActiveSize() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}

// purgeActiveLocked bounds the active map so terminal ops don't accumulate for
// the whole process lifetime. It drops TERMINAL ops finished before the
// retention cutoff and — if still over maxActive — evicts the oldest-finished
// terminal ops down to the cap. Running ops (including the lock holder) are
// NEVER reaped. Caller holds m.mu. Mirrors purgeIdempCacheLocked: O(N) over the
// map, run opportunistically on admission, self-throttling.
func (m *Manager) purgeActiveLocked() {
	if len(m.active) == 0 {
		return
	}
	cutoff := m.now().Add(-m.activeRetention)
	for id, op := range m.active {
		if op.State.IsTerminal() && op.Finished != nil && op.Finished.Before(cutoff) {
			delete(m.active, id)
		}
	}
	if m.maxActive <= 0 || len(m.active) <= m.maxActive {
		return
	}
	// Still over the hard cap: evict oldest-finished terminal ops first. Running
	// ops cannot be evicted, so the cap is best-effort if the overflow is all
	// live work (admission control bounds concurrent read-only ops separately).
	terminal := make([]*Op, 0, len(m.active))
	for _, op := range m.active {
		if op.State.IsTerminal() && op.Finished != nil {
			terminal = append(terminal, op)
		}
	}
	sort.Slice(terminal, func(i, j int) bool {
		return terminal[i].Finished.Before(*terminal[j].Finished)
	})
	excess := len(m.active) - m.maxActive
	for i := 0; i < len(terminal) && excess > 0; i++ {
		delete(m.active, terminal[i].ID)
		excess--
	}
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
			cp.Params[k] = deepCopyValue(v)
		}
	}
	if op.Result != nil {
		cp.Result = make(map[string]interface{}, len(op.Result))
		for k, v := range op.Result {
			cp.Result[k] = deepCopyValue(v)
		}
	}
	return &cp
}

// deepCopyValue recursively copies the JSON-shaped values that appear in a
// Params/Result map (nested maps and slices), so a snapshot handed to a status
// handler shares no mutable structure with the live op. Scalars (string, bool,
// numbers, nil) are immutable and returned as-is. Without this, cloneLocked's
// fresh TOP-LEVEL map still aliased nested maps/slices — a latent race against a
// concurrent JSON-encode of the "snapshot".
func deepCopyValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		m := make(map[string]interface{}, len(t))
		for k, vv := range t {
			m[k] = deepCopyValue(vv)
		}
		return m
	case []interface{}:
		s := make([]interface{}, len(t))
		for i, vv := range t {
			s[i] = deepCopyValue(vv)
		}
		return s
	default:
		return v
	}
}
