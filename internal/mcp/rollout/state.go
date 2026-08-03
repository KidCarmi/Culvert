package rollout

import (
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// activeState is the immutable hot-path bundle read lock-free by the request path.
// A mutation builds a NEW activeState and atomically swaps the pointer; readers
// always observe one complete, consistent snapshot (never a half-applied mode).
type activeState struct {
	config      SignedConfig
	mode        Mode
	scope       Scope
	shadowScope Scope
	hasShadow   bool
	killed      bool
}

// State is the capability-local rollout runtime state: the active mode + compiled
// scope (read lock-free on the request path), the emergency kill switch, the
// desired mode, bounded transition history, rollback metadata, and the evidence
// summary. Gateway and Management each own an independent State; nothing is shared
// between them.
type State struct {
	capability Capability
	lim        Limits

	cur atomic.Pointer[activeState] // hot-path lock-free reads

	// swapMu serializes the read-modify-write of cur across ALL writers (config
	// apply + kill-switch engage/clear) so two concurrent mutators can never both
	// load the same prior pointer and lose one update (e.g. a config apply silently
	// re-enabling admission after an emergency disable). Readers stay lock-free.
	swapMu sync.Mutex

	mu       sync.Mutex // guards the cold-path bookkeeping below
	desired  Mode
	history  []TransitionRecord
	rollback RollbackState
	evidence EvidenceSummary
}

// TransitionRecord is one bounded, sanitized transition-history entry.
type TransitionRecord struct {
	From       Mode           `json:"from"`
	To         Mode           `json:"to"`
	Kind       TransitionKind `json:"kind"`
	ScopeHash  string         `json:"scope_hash"`
	Actor      string         `json:"actor"` // sanitized admin identity
	AtUnixNano int64          `json:"at_unix_nano"`
	Emergency  bool           `json:"emergency"`
	Note       string         `json:"note,omitempty"`
}

// RollbackState records the last rollback/demotion reference (truthful local vs
// fleet convergence is tracked by the distribution layer, not here).
type RollbackState struct {
	LastTargetHash string `json:"last_target_hash,omitempty"`
	LastCommandID  string `json:"last_command_id,omitempty"`
	AtUnixNano     int64  `json:"at_unix_nano,omitempty"`
}

// NewState returns a capability-local State seeded to Disabled with an empty scope.
func NewState(capability Capability, lim Limits) *State {
	s := &State{capability: capability, lim: lim, desired: ModeDisabled, evidence: newEvidenceSummary()}
	empty := EmptyScope(capability)
	s.cur.Store(&activeState{
		config: DisabledConfig(capability), mode: ModeDisabled, scope: empty, shadowScope: empty,
	})
	return s
}

// Capability returns the state's capability.
func (s *State) Capability() Capability { return s.capability }

// CurrentMode returns the active mode (lock-free).
func (s *State) CurrentMode() Mode { return s.cur.Load().mode }

// CurrentConfig returns the active signed config (lock-free).
func (s *State) CurrentConfig() SignedConfig { return s.cur.Load().config }

// Killed reports whether the emergency kill switch is engaged (lock-free). A
// killed capability refuses new admission (ReasonRolloutEmergencyActive).
func (s *State) Killed() bool { return s.cur.Load().killed }

// ScopeHash returns the active scope's content hash (lock-free).
func (s *State) ScopeHash() string { return s.cur.Load().scope.Hash() }

// InScope reports whether subj is inside the active mode's scope (lock-free).
func (s *State) InScope(subj Subject) bool { return s.cur.Load().scope.Contains(subj) }

// ShadowInScope reports whether subj is inside the shadow-scope fallback.
func (s *State) ShadowInScope(subj Subject) bool {
	a := s.cur.Load()
	return a.hasShadow && a.shadowScope.Contains(subj)
}

// ResolveFor combines the active mode/scope with a resolved policy action + hard
// failure to produce the effective disposition. It is the single entry the runtime
// executor calls at the seam; it reads state lock-free and delegates to Resolve.
func (s *State) ResolveFor(subj Subject, action ActionKind, hardFailure bool, hardReason mcperr.Reason, obligationsSatisfied bool) Resolution {
	a := s.cur.Load()
	return Resolve(ResolveInput{
		Mode:                 a.mode,
		InScope:              a.scope.Contains(subj),
		ShadowEnabled:        a.hasShadow,
		ShadowInScope:        a.hasShadow && a.shadowScope.Contains(subj),
		Action:               action,
		HardFailure:          hardFailure,
		HardReason:           hardReason,
		ObligationsSatisfied: obligationsSatisfied,
	})
}

// SetConfig validates cfg, compiles its scopes, and atomically installs it. It is
// used by the signed-snapshot apply path (the mode/scope are authoritative from
// the CP). It preserves the current kill-switch state (an emergency disable is not
// cleared by a config apply). A mode change is appended to history.
func (s *State) SetConfig(cfg SignedConfig, actor string, atUnixNano int64) error {
	if err := cfg.Validate(s.capability, s.lim); err != nil {
		return err
	}
	scope, err := cfg.CompileScope(s.lim)
	if err != nil {
		return err
	}
	shadow, err := cfg.CompileShadowScope(s.lim)
	if err != nil {
		return err
	}
	// Serialize the load→store so a concurrent kill-switch change is never lost.
	s.swapMu.Lock()
	prev := s.cur.Load()
	next := &activeState{
		config: cfg, mode: cfg.Mode, scope: scope, shadowScope: shadow,
		hasShadow: cfg.hasShadowScope(), killed: prev.killed,
	}
	s.cur.Store(next)
	s.swapMu.Unlock()
	if prev.mode != cfg.Mode {
		kind := TransitionDemotion
		if cfg.Mode.Rank() > prev.mode.Rank() {
			kind = TransitionPromotion
		}
		s.appendHistory(TransitionRecord{From: prev.mode, To: cfg.Mode, Kind: kind, ScopeHash: scope.Hash(), Actor: sanitize(actor), AtUnixNano: atUnixNano})
	}
	return nil
}

// EngageKillSwitch engages the emergency disable (admission stop) without changing
// the mode/scope. Idempotent. Restart-persistent via ToPersist.
func (s *State) EngageKillSwitch(actor string, atUnixNano int64) {
	s.swapMu.Lock()
	prev := s.cur.Load()
	if prev.killed {
		s.swapMu.Unlock()
		return
	}
	next := *prev
	next.killed = true
	s.cur.Store(&next)
	s.swapMu.Unlock()
	s.appendHistory(TransitionRecord{From: prev.mode, To: prev.mode, Kind: TransitionDemotion, ScopeHash: prev.scope.Hash(), Actor: sanitize(actor), AtUnixNano: atUnixNano, Emergency: true, Note: "kill-switch engaged"})
}

// ClearKillSwitch clears the emergency disable. Idempotent.
func (s *State) ClearKillSwitch() {
	s.swapMu.Lock()
	defer s.swapMu.Unlock()
	prev := s.cur.Load()
	if !prev.killed {
		return
	}
	next := *prev
	next.killed = false
	s.cur.Store(&next)
}

// RecordRollback records a rollback/demotion reference for status truthfulness.
func (s *State) RecordRollback(targetHash, commandID string, atUnixNano int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollback = RollbackState{LastTargetHash: targetHash, LastCommandID: commandID, AtUnixNano: atUnixNano}
}

// SetDesired records the operator's desired mode (the target of an in-flight
// promotion whose distribution may still be pending).
func (s *State) SetDesired(m Mode) {
	s.mu.Lock()
	s.desired = m
	s.mu.Unlock()
}

// Desired returns the desired mode.
func (s *State) Desired() Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.desired
}

// History returns a copy of the bounded transition history.
func (s *State) History() []TransitionRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TransitionRecord, len(s.history))
	copy(out, s.history)
	return out
}

// Evidence returns a copy of the evidence summary.
func (s *State) Evidence() EvidenceSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evidence
}

// UpdateEvidence applies fn to the evidence summary under the lock.
func (s *State) UpdateEvidence(fn func(*EvidenceSummary)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.evidence)
}

func (s *State) appendHistory(rec TransitionRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.history = append(s.history, rec)
	if maxHist := s.lim.MaxHistory(); len(s.history) > maxHist {
		s.history = s.history[len(s.history)-maxHist:]
	}
}

// StatePersist is the restart-durable, node-local DTO. It carries the kill-switch
// state, desired mode, bounded history, rollback metadata, and evidence — the
// node-local bits that must survive a restart. The active mode/scope are
// re-established from the signed snapshot on the DP (config is included for a CP
// that owns it locally).
type StatePersist struct {
	Version    int                `json:"version"`
	Capability Capability         `json:"capability"`
	Config     SignedConfig       `json:"config"`
	Killed     bool               `json:"killed"`
	Desired    Mode               `json:"desired"`
	History    []TransitionRecord `json:"history,omitempty"`
	Rollback   RollbackState      `json:"rollback"`
	Evidence   EvidenceSummary    `json:"evidence"`
}

const statePersistVersion = 1

// ToPersist snapshots the state into the restart-durable DTO.
func (s *State) ToPersist() StatePersist {
	a := s.cur.Load()
	s.mu.Lock()
	defer s.mu.Unlock()
	hist := make([]TransitionRecord, len(s.history))
	copy(hist, s.history)
	return StatePersist{
		Version: statePersistVersion, Capability: s.capability, Config: a.config,
		Killed: a.killed, Desired: s.desired, History: hist, Rollback: s.rollback, Evidence: s.evidence,
	}
}

// LoadPersist restores node-local state from a durable DTO. It re-validates and
// re-compiles the config (fail closed to Disabled on any error) and restores the
// kill switch, desired mode, history, rollback, and evidence.
func (s *State) LoadPersist(p StatePersist) error {
	if p.Version != statePersistVersion {
		return mcperr.New(mcperr.ReasonRolloutModeInvalid, "rollout.state", "unknown persisted-state version")
	}
	if p.Capability != s.capability {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "rollout.state", "persisted capability mismatch")
	}
	cfg := p.Config
	if cfg.Validate(s.capability, s.lim) != nil {
		cfg = DisabledConfig(s.capability) // fail closed
	}
	scope, err := cfg.CompileScope(s.lim)
	if err != nil {
		cfg = DisabledConfig(s.capability)
		scope = EmptyScope(s.capability)
	}
	shadow, _ := cfg.CompileShadowScope(s.lim)
	s.cur.Store(&activeState{config: cfg, mode: cfg.Mode, scope: scope, shadowScope: shadow, hasShadow: cfg.hasShadowScope(), killed: p.Killed})
	s.mu.Lock()
	s.desired = p.Desired
	s.history = append([]TransitionRecord(nil), p.History...)
	s.rollback = p.Rollback
	if p.Evidence.valid() {
		s.evidence = p.Evidence
	}
	s.mu.Unlock()
	return nil
}

// sanitize bounds and strips an actor string for safe storage/display.
func sanitize(s string) string { return mcperr.Sanitize(s, 128) }
