package apply

import (
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Config wires a capability-local Applier.
type Config struct {
	Capability cpdp.Capability
	Trust      *cpdp.TrustStore
	DPVersion  cpdp.CompatVersion
	Limits     cpdp.Limits
	NodeID     string
	Store      SnapStore     // durable persistence (fail seam)
	Clock      func() int64  // unix-nano; injected (never time.Now on the hot path)
	IDGen      func() string // acknowledgement id generator
}

// Applier is the capability-local Data-Plane apply engine. It owns the
// capability-local ActiveStore, the epoch ratchet, and the durable SnapStore. Apply
// and Rollback are serialized by a mutex the request path never touches; the
// request path reads the active pointer lock-free via Active().
type Applier struct {
	cfg     Config
	store   *cpdp.ActiveStore
	ratchet *cpdp.EpochRatchet

	mu           sync.Mutex // serializes Apply/Rollback; not held by readers
	curPrepared  *PreparedState
	prevPrepared *PreparedState
	pendingAck   *cpdp.Acknowledgement
}

// New returns a capability-local Applier. It does not read persisted state — call
// Recover for that.
func New(cfg Config) (*Applier, error) {
	if !cfg.Capability.Valid() {
		return nil, mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.apply", "invalid capability")
	}
	if cfg.Trust == nil || cfg.Store == nil || cfg.Clock == nil || cfg.IDGen == nil {
		return nil, mcperr.New(mcperr.ReasonSnapshotMalformed, "cpdp.apply", "incomplete applier config")
	}
	return &Applier{
		cfg:     cfg,
		store:   cpdp.NewActiveStore(cfg.Capability),
		ratchet: cpdp.NewEpochRatchet(0),
	}, nil
}

// Active returns the current active snapshot (lock-free read for the request path),
// or nil if the DP has no valid MCP snapshot for this capability (fail-closed).
func (a *Applier) Active() *cpdp.Envelope { return a.store.Active() }

// ActiveHash / PreviousHash expose the current/previous hashes for status + acks.
// ActiveHash returns the current active content hash, or "".
func (a *Applier) ActiveHash() string { return a.store.ActiveHash() }

// PreviousHash returns the retained previous content hash, or "".
func (a *Applier) PreviousHash() string { return a.store.PreviousHash() }

// TrustedEpoch returns the DP's last-seen trusted epoch.
func (a *Applier) TrustedEpoch() int64 { return a.ratchet.Last() }

// PreparedActive returns the prepared runtime for the active snapshot (nil if none).
func (a *Applier) PreparedActive() *PreparedState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.curPrepared
}

// Apply runs the complete DP application sequence for a received signed envelope.
// It NEVER mutates active state before validation and persistence both succeed.
// It returns a hash-bound acknowledgement for BOTH outcomes: on success the ack
// state is Applied; on any rejection the ack state is Rejected (with a bounded
// reason) and a non-nil error is returned. The active snapshot is byte-unchanged
// on any rejection.
func (a *Applier) Apply(env *cpdp.Envelope) (*cpdp.Acknowledgement, error) {
	if env == nil {
		return nil, mcperr.New(mcperr.ReasonSnapshotMalformed, "cpdp.apply", "nil envelope")
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	// Step 2: NON-mutating preliminary epoch check (before hash/sig work).
	if err := a.ratchet.CheckEpoch(env.Manifest.Epoch); err != nil {
		return a.reject(env, err), err
	}
	// Steps 3+4: verify canonical hash + Ed25519 signature, then validate capability,
	// revisions, minimum version, and all bounds — whole-snapshot validation.
	if err := cpdp.Validate(env, cpdp.ValidateInput{
		ExpectCapability: a.cfg.Capability,
		DPVersion:        a.cfg.DPVersion,
		LastEpoch:        a.ratchet.Last(),
		Trust:            a.cfg.Trust,
		Limits:           a.cfg.Limits,
	}); err != nil {
		return a.reject(env, err), err
	}
	// Step 4b: revision ordering + duplicate-revision guard against the current active
	// snapshot. The same-revision-but-different-content rejection MUST run BEFORE the
	// durable persist (below), not only inside the later atomic Activate — otherwise a
	// rejected candidate would be written to the state file and a subsequent restart
	// would Recover it as active, violating rejection atomicity.
	if cur := a.store.Active(); cur != nil {
		if err := cpdp.CheckMonotonic(cur.Manifest.Revisions, env.Manifest.Revisions, cur.Manifest.Epoch, env.Manifest.Epoch); err != nil {
			return a.reject(env, err), err
		}
		if cur.ContentHash != env.ContentHash &&
			cur.Manifest.Epoch == env.Manifest.Epoch &&
			cur.Manifest.Revisions.Config == env.Manifest.Revisions.Config {
			err := mcperr.New(mcperr.ReasonSnapshotRevisionRegression, "cpdp.apply", "same revision with a different content hash")
			return a.reject(env, err), err
		}
	}
	// Step 5+6: prepare runtime objects OFF the active path + run dry samples.
	prepared, err := Prepare(env)
	if err != nil {
		return a.reject(env, err), err
	}
	// Step 7: durably persist the candidate + activation metadata BEFORE any swap.
	// A persistence/fsync/rename failure aborts activation with active unchanged.
	ack := a.buildApplied(env)
	prevEnv := a.store.Active()
	st := &PersistedState{
		Version:    persistStateVersion,
		Capability: a.cfg.Capability,
		Current:    env,
		Previous:   prevEnv,
		Epoch:      env.Manifest.Epoch,
		Revisions:  env.Manifest.Revisions,
		PendingAck: ack,
	}
	if perr := a.cfg.Store.Persist(st); perr != nil {
		return a.reject(env, perr), perr
	}
	// Step 8: commit the trusted observed epoch (only now, after persistence).
	if _, err := a.ratchet.CommitObservedEpoch(env.Manifest.Epoch); err != nil {
		return a.reject(env, err), err
	}
	// Step 9: atomically swap the capability-local active pointer.
	if _, err := a.store.Activate(env); err != nil {
		return a.reject(env, err), err
	}
	// Step 10: retain previous prepared runtime.
	a.prevPrepared = a.curPrepared
	a.curPrepared = prepared
	// Step 11: the applied acknowledgement is now pending delivery.
	a.pendingAck = ack
	return ack, nil
}

// RejectAck builds a hash-bound REJECTED acknowledgement for env WITHOUT mutating
// any state. It is used by a transaction coordinator that decides, on grounds
// outside this applier's own validation (e.g. a coupled rollout precondition that
// fails closed), to reject an envelope BEFORE it is ever applied — so the active
// snapshot is never staged. It mirrors the ack Apply itself returns on its internal
// rejections: the ack is returned but pendingAck is left untouched (a rejection is
// not a durable delivery obligation).
func (a *Applier) RejectAck(env *cpdp.Envelope, cause error) *cpdp.Acknowledgement {
	a.mu.Lock()
	defer a.mu.Unlock()
	if env == nil {
		return a.reject(&cpdp.Envelope{}, cause)
	}
	return a.reject(env, cause)
}

// AbortApplied compensates a just-succeeded Apply: it atomically reverts the active
// pointer to the snapshot that was active BEFORE that Apply, persists the reverted
// state (persist-before-swap), and REPLACES the pending Applied acknowledgement with
// a Rejected one so no AckApplied can ever be delivered for the aborted envelope.
//
// It exists for a two-store transaction where distribution activation is the FIRST
// durable half and a coupled second half (the node-local rollout commit) then fails:
// the task contract forbids leaving a new distribution revision active while the
// rollout was rejected, so the coordinator calls AbortApplied to restore the prior
// active distribution state before returning failure. cause names the rollout error
// that triggered the abort (bounded reason only in the ack).
//
// Ordering matches the rest of the engine: the reverted state is durably persisted
// BEFORE the in-memory swap, so a crash mid-abort recovers the reverted (prior)
// snapshot, never a half-abort. A persistence failure here (the compensating write
// itself failing on a still-degraded disk) is returned to the caller with the active
// pointer left on the aborted envelope; startup recovery reconciliation is the
// documented backstop for that double-fault. The trusted epoch is never moved
// backwards.
func (a *Applier) AbortApplied(cause error) (*cpdp.Acknowledgement, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	aborted := a.store.Active()
	if aborted == nil {
		// Nothing was applied — nothing to abort. Fail-closed, non-mutating.
		return nil, mcperr.New(mcperr.ReasonSnapshotMalformed, "cpdp.apply.abort", "no active snapshot to abort")
	}
	target := a.store.Previous() // the snapshot active before the aborted Apply (may be nil)
	ack := a.reject(aborted, cause)

	revs := cpdp.Revisions{}
	if target != nil {
		revs = target.Manifest.Revisions
	}
	st := &PersistedState{
		Version:    persistStateVersion,
		Capability: a.cfg.Capability,
		Current:    target,
		Previous:   nil, // drop the aborted envelope from retention
		Epoch:      a.ratchet.Last(),
		Revisions:  revs,
		PendingAck: ack,
	}
	if perr := a.cfg.Store.Persist(st); perr != nil {
		// The compensating write itself failed: leave the active pointer on the aborted
		// envelope (we cannot durably prove the revert) and surface the failure. Recovery
		// reconciliation converges this on the next restart.
		return ack, perr
	}
	if err := a.store.Restore(target, nil); err != nil {
		return ack, err
	}
	a.curPrepared = a.prevPrepared
	a.prevPrepared = nil
	a.pendingAck = ack
	return ack, nil
}

// Recover reads and re-verifies persisted state at startup. It restores the
// current/previous snapshots, seeds the trusted epoch, and restores the pending
// acknowledgement. A corrupt or unverifiable state returns an error and leaves the
// applier with NO active snapshot (fail-closed / disabled) rather than a permissive
// empty configuration.
func (a *Applier) Recover() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	st, err := a.cfg.Store.Load()
	if err != nil {
		return err
	}
	if st == nil {
		return nil // fresh DP: no active snapshot, fail-closed until a snapshot arrives
	}
	if err := verifyRecovered(st, a.cfg.Capability, a.cfg.Trust, a.cfg.DPVersion, a.cfg.Limits); err != nil {
		return err
	}
	if st.Current == nil {
		return nil
	}
	if err := a.store.Restore(st.Current, st.Previous); err != nil {
		return err
	}
	// Rebuild prepared runtime for current (and previous, best-effort) off-path.
	prep, err := Prepare(st.Current)
	if err != nil {
		return err
	}
	a.curPrepared = prep
	if st.Previous != nil {
		if pp, perr := Prepare(st.Previous); perr == nil {
			a.prevPrepared = pp
		}
	}
	// Seed the trusted epoch monotonically from the persisted current.
	if _, err := a.ratchet.CommitObservedEpoch(st.Epoch); err != nil {
		return err
	}
	a.pendingAck = st.PendingAck
	return nil
}

// PendingAck returns the acknowledgement awaiting delivery, or nil.
func (a *Applier) PendingAck() *cpdp.Acknowledgement {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pendingAck
}

// ClearPendingAck marks the pending acknowledgement delivered. A delivery failure
// does NOT call this, so the ack survives for bounded retry — and never undoes a
// valid activation.
func (a *Applier) ClearPendingAck() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pendingAck = nil
}

// Rollback verifies a signed rollback directive and, on success, atomically
// reverts the active pointer to the retained target snapshot, re-verifying the
// target's signature/hash first. On any failure the current snapshot remains
// active and the trusted epoch does not move backwards. It returns a rolled_back
// acknowledgement on success.
func (a *Applier) Rollback(d *cpdp.RollbackDirective) (*cpdp.Acknowledgement, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	cur := a.store.Active()
	curHash := ""
	if cur != nil {
		curHash = cur.ContentHash
	}
	if err := cpdp.VerifyRollback(d, a.cfg.Trust, a.cfg.Capability, curHash, a.cfg.Clock(), a.cfg.DPVersion); err != nil {
		return nil, err
	}
	// Re-verify the retained target snapshot's signature/hash before swapping.
	target := a.store.Previous()
	if target == nil || target.ContentHash != d.TargetHash {
		return nil, mcperr.New(mcperr.ReasonRollbackTargetMissing, "cpdp.apply.rollback", "target not retained")
	}
	if err := cpdp.VerifySignature(target, a.cfg.Trust, a.cfg.Limits); err != nil {
		return nil, mcperr.Wrap(mcperr.ReasonRollbackTargetCorrupt, "cpdp.apply.rollback", "target failed re-verification", err)
	}
	// Persist the reverted state BEFORE the swap (persist-before-swap for rollback too).
	ack := a.buildRolledBack(target)
	st := &PersistedState{
		Version:      persistStateVersion,
		Capability:   a.cfg.Capability,
		Current:      target,
		Previous:     cur,
		Epoch:        a.ratchet.Last(), // epoch does NOT move backwards on rollback
		Revisions:    target.Manifest.Revisions,
		PendingAck:   ack,
		RollbackMeta: &PersistedRollbackMeta{RolledBackFromHash: curHash, CommandID: d.CommandID},
	}
	if err := a.cfg.Store.Persist(st); err != nil {
		return nil, err // current remains active
	}
	if _, err := a.store.Revert(d.TargetHash); err != nil {
		return nil, err
	}
	a.prevPrepared, a.curPrepared = a.curPrepared, a.prevPrepared
	a.pendingAck = ack
	return ack, nil
}

// --- acknowledgement builders --------------------------------------------------

func (a *Applier) buildApplied(env *cpdp.Envelope) *cpdp.Acknowledgement {
	return &cpdp.Acknowledgement{
		AckID:        a.cfg.IDGen(),
		NodeID:       a.cfg.NodeID,
		Capability:   a.cfg.Capability,
		ContentHash:  env.ContentHash,
		Epoch:        env.Manifest.Epoch,
		Revisions:    env.Manifest.Revisions,
		State:        cpdp.AckApplied,
		ActiveHash:   env.ContentHash,
		PreviousHash: a.store.ActiveHash(),
		DPVersion:    a.cfg.DPVersion,
		Health:       "ok",
		TimeUnixNano: a.cfg.Clock(),
	}
}

func (a *Applier) buildRolledBack(target *cpdp.Envelope) *cpdp.Acknowledgement {
	return &cpdp.Acknowledgement{
		AckID:        a.cfg.IDGen(),
		NodeID:       a.cfg.NodeID,
		Capability:   a.cfg.Capability,
		ContentHash:  target.ContentHash,
		Epoch:        a.ratchet.Last(),
		Revisions:    target.Manifest.Revisions,
		State:        cpdp.AckRolledBack,
		ActiveHash:   target.ContentHash,
		PreviousHash: a.store.ActiveHash(),
		DPVersion:    a.cfg.DPVersion,
		Health:       "ok",
		TimeUnixNano: a.cfg.Clock(),
	}
}

func (a *Applier) reject(env *cpdp.Envelope, cause error) *cpdp.Acknowledgement {
	return &cpdp.Acknowledgement{
		AckID:        a.cfg.IDGen(),
		NodeID:       a.cfg.NodeID,
		Capability:   a.cfg.Capability,
		ContentHash:  env.ContentHash,
		Epoch:        env.Manifest.Epoch,
		Revisions:    env.Manifest.Revisions,
		State:        cpdp.AckRejected,
		ActiveHash:   a.store.ActiveHash(),
		PreviousHash: a.store.PreviousHash(),
		DPVersion:    a.cfg.DPVersion,
		Health:       "degraded",
		RejectReason: mcperr.ReasonOf(cause).Code(),
		TimeUnixNano: a.cfg.Clock(),
	}
}
