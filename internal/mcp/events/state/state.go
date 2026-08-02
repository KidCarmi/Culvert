// Package state implements the normative, scoped, restart-persistent, bounded
// durability degraded-state machine (MCP-OPS-005 / EVENT-MODEL.md §4b.5-4b.7).
// One Machine governs one node × capability. It carries two INDEPENDENT tracks:
//
//   - the critical track (normal / critical-durability-degraded / recovering),
//     driven by authenticated critical commit failures in P-CRIT; and
//   - the denial track (normal / denial-lane-degraded), driven by
//     attacker-mintable denial-lane failures in P-DEN.
//
// The two tracks NEVER interact: a denial-lane failure can never move the critical
// track, there is no edge from denial-lane-degraded to critical-durability-
// degraded, and the two loss counters are distinct at distinct severities. The
// state and its scope survive process restart (a restart is not a recovery
// mechanism), and ambiguous/corrupt persistent metadata fails toward the narrow
// local critical-durability-degraded state — never toward normal. There is no
// emergency-bypass state and no path that lets a critical operation run in a
// degraded domain without a durable event.
package state

import (
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// State is a degraded-state value. The zero value, StateUnknown, fails closed
// (treated as critical-durability-degraded on the critical track).
type State uint8

const (
	// StateUnknown is the zero value: unknown → fail closed.
	StateUnknown State = iota
	// StateNormal — all required partitions writable and below the high watermark.
	StateNormal
	// StateDenialLaneDegraded — a denial aggregate could not be committed, or P-DEN
	// hit its quota. Blocks nothing authenticated (denial track only).
	StateDenialLaneDegraded
	// StateCriticalDurabilityDegraded — an authenticated critical event failed to
	// commit in this domain. New critical operations here fail closed.
	StateCriticalDurabilityDegraded
	// StateRecovering — all exit criteria observed; restrictions remain until the
	// recovery marker is confirmed and the transition completes.
	StateRecovering
)

// String returns the stable machine string.
func (s State) String() string {
	switch s {
	case StateNormal:
		return "normal"
	case StateDenialLaneDegraded:
		return "denial-lane-degraded"
	case StateCriticalDurabilityDegraded:
		return "critical-durability-degraded"
	case StateRecovering:
		return "recovering"
	default:
		return "unknown"
	}
}

// Severity is the alert severity distinct per track.
type Severity uint8

const (
	// SevNone — no alert.
	SevNone Severity = iota
	// SevWarning — denial-lane / recovering.
	SevWarning
	// SevCritical — critical-durability-degraded.
	SevCritical
)

// Persist stores the integrity-protected degraded-state metadata durably in the
// same location as the spool. Save must be atomic; Load returns (nil, nil) when
// no metadata exists yet.
type Persist interface {
	Save(data []byte) error
	Load() ([]byte, error)
}

// Config parameterises a Machine.
type Config struct {
	Capability model.Capability
	NodeID     string
	Persist    Persist
	Clock      func() time.Time
}

// Machine is the per-domain degraded-state machine.
type Machine struct {
	mu    sync.Mutex
	cfg   Config
	clock func() time.Time

	critical     State
	denial       State
	scope        string
	reason       string
	entryNano    int64
	seq          uint64
	markerDigest string

	criticalLoss uint64
	denialLoss   uint64
}

// New builds a Machine in the normal state on both tracks. Call Load to
// reconstruct persistent state before use.
func New(cfg Config) *Machine {
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Machine{cfg: cfg, clock: clock, critical: StateNormal, denial: StateNormal}
}

// Load reconstructs the state from persistent metadata. Absent metadata is a
// fresh normal machine. Corrupt or ambiguous metadata FAILS TOWARD the narrow
// local critical-durability-degraded state (never normal, never fleet-wide), and
// the machine is persisted in that state so a subsequent restart stays consistent.
func (m *Machine) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	raw, err := m.cfg.Persist.Load()
	if err != nil {
		m.forceCriticalLocked("persistent metadata unreadable")
		return m.saveLocked()
	}
	if len(raw) == 0 {
		return nil // fresh normal
	}
	snap, derr := decodeSnapshot(raw)
	if derr != nil {
		m.forceCriticalLocked("persistent metadata corrupt")
		return m.saveLocked()
	}
	if model.Capability(snap.Capability) != m.cfg.Capability {
		m.forceCriticalLocked("persistent metadata capability mismatch")
		return m.saveLocked()
	}
	m.critical = State(snap.Critical)
	m.denial = State(snap.Denial)
	m.scope = snap.Scope
	m.reason = snap.Reason
	m.entryNano = snap.EntryNano
	m.seq = snap.TransitionSeq
	m.markerDigest = snap.MarkerDigest
	m.criticalLoss = snap.CriticalLoss
	m.denialLoss = snap.DenialLoss
	// A restart must not clear the lockout: an unknown/zero critical track (or a
	// stored recovering state, which is not a durable resting state) fails toward
	// critical.
	if m.critical == StateUnknown || m.critical == StateRecovering {
		m.forceCriticalLocked("restart reconstructed a non-resting critical state")
		return m.saveLocked()
	}
	if m.denial == StateUnknown {
		m.denial = StateNormal
	}
	return nil
}

// WriteAllowedCritical reports whether a new critical operation may run: true only
// when the critical track is normal. Degraded and recovering both block.
func (m *Machine) WriteAllowedCritical() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.critical == StateNormal
}

// CriticalState / DenialState return the current track states.
func (m *Machine) CriticalState() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.critical
}

func (m *Machine) DenialState() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.denial
}

// OnCriticalCommitFailure records an authenticated critical commit failure: enter
// (or stay in) critical-durability-degraded, increment the DISTINCT critical loss
// counter, and persist. Scope is the affected durability-domain id.
func (m *Machine) OnCriticalCommitFailure(scope, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.criticalLoss++
	if m.critical != StateCriticalDurabilityDegraded {
		m.critical = StateCriticalDurabilityDegraded
		m.scope = scope
		m.reason = reason
		m.entryNano = m.clock().UnixNano()
		m.seq++
		m.markerDigest = ""
	}
	return m.saveLocked()
}

// OnDenialLaneFailure records a denial-lane failure (aggregate commit failed or
// P-DEN quota reached): enter denial-lane-degraded, increment the DISTINCT denial
// loss counter, and persist. It NEVER touches the critical track.
func (m *Machine) OnDenialLaneFailure(reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.denialLoss++
	if m.denial != StateDenialLaneDegraded {
		m.denial = StateDenialLaneDegraded
		m.seq++
	}
	return m.saveLocked()
}

// OnDenialLaneRecovered clears the denial track back to normal when denial commits
// succeed again and P-DEN is below its low watermark.
func (m *Machine) OnDenialLaneRecovered() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.denial != StateNormal {
		m.denial = StateNormal
		m.seq++
		return m.saveLocked()
	}
	return nil
}

// ExitCriteria carries the four independently-required recovery-exit measurements
// (EVENT-MODEL.md §4b.6). The reserve watermark is a fraction OF THE RESERVE, and
// the pending bound is DERIVED, so (2) and (4) can never be configured to
// contradict.
type ExitCriteria struct {
	StorageWritable      bool   // (1) a probe write to P-CRIT succeeds
	ReserveFreeBytes     int64  // (2a) P-CRIT free bytes on disk
	ReserveRecoveryBytes int64  // (2b) reserve_recovery × reserve
	MarkerReadBack       bool   // (3) recovery marker durably committed AND read back
	MarkerDigest         string // (3) the confirmed marker digest
	PendingBacklogBytes  int64  // (4a) in-process accepted-not-committed critical backlog
	PendingBoundBytes    int64  // (4b) (1 - reserve_recovery) × reserve
}

// allHold reports whether all four criteria hold.
func (c ExitCriteria) allHold() bool {
	return c.StorageWritable &&
		c.ReserveFreeBytes >= c.ReserveRecoveryBytes &&
		c.MarkerReadBack && c.MarkerDigest != "" &&
		c.PendingBacklogBytes <= c.PendingBoundBytes
}

// BeginRecovery moves critical-durability-degraded → recovering when the
// non-marker criteria (1,2,4) hold, signalling the manager to commit and read back
// the recovery marker. It returns true when the machine entered recovering.
// Restrictions remain in recovering, so this never permits a critical operation.
func (m *Machine) BeginRecovery(c ExitCriteria) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.critical != StateCriticalDurabilityDegraded {
		return false, nil
	}
	if !c.StorageWritable || c.ReserveFreeBytes < c.ReserveRecoveryBytes || c.PendingBacklogBytes > c.PendingBoundBytes {
		return false, nil
	}
	m.critical = StateRecovering
	m.seq++
	return true, m.saveLocked()
}

// FinalizeRecovery completes the transition to normal when ALL FOUR criteria hold
// (including the committed-and-read-back marker). If any criterion fails, it falls
// back to critical-durability-degraded. It returns true only on a full transition
// to normal, which must occur within one probe interval of all four holding.
func (m *Machine) FinalizeRecovery(c ExitCriteria) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.critical != StateRecovering {
		return false, nil
	}
	if !c.allHold() {
		m.critical = StateCriticalDurabilityDegraded
		m.markerDigest = ""
		m.seq++
		return false, m.saveLocked()
	}
	m.critical = StateNormal
	m.scope = ""
	m.reason = ""
	m.markerDigest = c.MarkerDigest
	m.seq++
	return true, m.saveLocked()
}

// forceCriticalLocked drives the critical track to degraded with a reason (used by
// the fail-toward-critical corruption paths).
func (m *Machine) forceCriticalLocked(reason string) {
	m.critical = StateCriticalDurabilityDegraded
	m.reason = reason
	m.scope = m.cfg.NodeID + "|" + m.cfg.Capability.String() + "|" + model.PartCrit.String()
	m.entryNano = m.clock().UnixNano()
	m.seq++
	m.markerDigest = ""
}

// Snapshot is a safe, typed view of the machine for health surfaces.
type Snapshot struct {
	Capability   model.Capability
	Critical     State
	Denial       State
	Scope        string
	Reason       string
	EntryNano    int64
	CriticalLoss uint64
	DenialLoss   uint64
	Severity     Severity
}

// Snapshot returns the current state.
func (m *Machine) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{
		Capability: m.cfg.Capability, Critical: m.critical, Denial: m.denial,
		Scope: m.scope, Reason: m.reason, EntryNano: m.entryNano,
		CriticalLoss: m.criticalLoss, DenialLoss: m.denialLoss, Severity: m.severityLocked(),
	}
}

func (m *Machine) severityLocked() Severity {
	if m.critical == StateCriticalDurabilityDegraded {
		return SevCritical
	}
	if m.critical == StateRecovering || m.denial == StateDenialLaneDegraded {
		return SevWarning
	}
	return SevNone
}

// CriticalLoss / DenialLoss return the two DISTINCT integrity-protected counters.
func (m *Machine) CriticalLoss() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.criticalLoss
}

func (m *Machine) DenialLoss() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.denialLoss
}

func (m *Machine) saveLocked() error {
	snap := stateSnapshot{
		Version: snapshotVersion, Capability: byte(m.cfg.Capability),
		Critical: byte(m.critical), Denial: byte(m.denial), Scope: m.scope, Reason: m.reason,
		EntryNano: m.entryNano, TransitionSeq: m.seq, MarkerDigest: m.markerDigest,
		CriticalLoss: m.criticalLoss, DenialLoss: m.denialLoss,
	}
	body, err := snap.encode()
	if err != nil {
		return err
	}
	return m.cfg.Persist.Save(body)
}
