package events

import (
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/state"
)

// RecoverProbe runs one bounded recovery-probe tick for a capability's critical
// track. When the domain is critical-durability-degraded and the non-marker
// criteria (storage writable, reserve free, pending backlog) hold, it enters
// recovering, DURABLY COMMITS AND READS BACK a recovery marker (criterion 3 — a
// confirmed commit, not an enqueue), then finalizes to normal only when all four
// criteria hold. It returns true when the domain returned to normal this tick.
// There is no bypass: a failed marker commit/readback leaves the domain degraded.
func (m *Manager) RecoverProbe(capNS model.Capability) bool {
	d, err := m.domainFor(capNS)
	if err != nil {
		return false
	}
	if d.state.CriticalState() != state.StateCriticalDurabilityDegraded {
		return false
	}
	d.recoveryTries.Add(1)

	pre := m.measureCriteria(d, "")
	began, _ := d.state.BeginRecovery(pre)
	if !began {
		return false
	}
	// Criterion 3: durably commit a recovery marker and READ IT BACK.
	markerDigest, ok := m.commitAndReadbackMarker(d)
	final := m.measureCriteria(d, markerDigest)
	final.MarkerReadBack = ok
	recovered, _ := d.state.FinalizeRecovery(final)
	if recovered {
		d.recoveryOK.Add(1)
	}
	return recovered
}

// measureCriteria samples the four recovery-exit inputs from the live spool and
// the in-process backlog. The reserve watermark is a fraction OF THE RESERVE, and
// the pending bound is DERIVED — both come from the limits, so they can never be
// configured to contradict.
func (m *Manager) measureCriteria(d *domain, markerDigest string) state.ExitCriteria {
	st := d.spool.Stats()
	return state.ExitCriteria{
		StorageWritable:      d.spool.ProbeWritable(),
		ReserveFreeBytes:     st.CriticalFreeBytes,
		ReserveRecoveryBytes: int64(d.lim.ReserveRecoveryBytes()),
		MarkerDigest:         markerDigest,
		PendingBacklogBytes:  d.pendingCrit.Load(),
		PendingBoundBytes:    int64(d.lim.PendingBacklogBytes()),
	}
}

// commitAndReadbackMarker commits a recovery-marker event to P-CRIT and confirms
// it by reading it back through the spool's committed-export read. It returns the
// marker's digest and whether the read-back confirmed it. A commit or read-back
// failure returns ok=false so the domain stays degraded.
func (m *Manager) commitAndReadbackMarker(d *domain) (string, bool) {
	e := &model.Event{
		SchemaVersion: model.SchemaVersion,
		EventID:       randID("evt_"),
		Phase:         model.PhaseRecoveryMarker,
		Criticality:   model.CritCritical,
		Partition:     model.PartCrit,
		Capability:    d.capNS,
		ActionClass:   model.ActionClassNone,
		NodeID:        m.nodeID,
		DomainID:      d.spool.DomainID(model.PartCrit),
		TimeUnixNano:  m.clock().UnixNano(),
		ReplayID:      randID("rpl_"),
		CorrelationID: randID("cor_"),
		Marker: &model.MarkerEvidence{
			State: state.StateRecovering.String(), Scope: d.spool.DomainID(model.PartCrit), Reason: "recovery probe",
		},
	}
	// A recovery marker is a P-CRIT critical event but carries no action-class
	// binding; the model permits marker phases without one.
	if _, err := e.ComputeDigest(); err != nil {
		return "", false
	}
	rec, err := d.spool.Commit(e)
	if err != nil || !rec.Valid() {
		return "", false
	}
	// Read it back: the committed marker must be retrievable and verify.
	evs, _, _, rerr := d.spool.CommittedForExport(model.PartCrit, rec.Sequence()-1, 1)
	if rerr == nil && markerPresent(evs, e.EventID) {
		return rec.EventDigest(), true
	}
	// Fall back to a broader scan when sequence bookkeeping does not line up.
	all, _, _, aerr := d.spool.CommittedForExport(model.PartCrit, 0, d.lim.MaxRecoveryRecords())
	if aerr == nil && markerPresent(all, e.EventID) {
		return rec.EventDigest(), true
	}
	return "", false
}

// markerPresent reports whether a committed event with the given id is present and
// verifies. Index-based iteration avoids copying the 920-byte events per loop.
func markerPresent(evs []model.Event, id string) bool {
	for i := range evs {
		if evs[i].EventID == id && evs[i].VerifyDigest() {
			return true
		}
	}
	return false
}
