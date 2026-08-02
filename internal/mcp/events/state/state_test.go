package state

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

func newMachine(t *testing.T, p Persist) *Machine {
	t.Helper()
	m := New(Config{Capability: model.CapGateway, NodeID: "dp", Persist: p, Clock: func() time.Time { return time.Unix(0, 42) }})
	if err := m.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return m
}

func goodCriteria(marker string) ExitCriteria {
	return ExitCriteria{
		StorageWritable: true, ReserveFreeBytes: 100, ReserveRecoveryBytes: 50,
		MarkerReadBack: true, MarkerDigest: marker, PendingBacklogBytes: 10, PendingBoundBytes: 50,
	}
}

func TestZeroStateFailsClosed(t *testing.T) {
	if (State(0)) != StateUnknown {
		t.Fatal("zero must be StateUnknown")
	}
	// A machine that loads unknown critical must fail toward critical.
	p := NewMemPersist()
	m := New(Config{Capability: model.CapGateway, NodeID: "dp", Persist: p})
	// Persist an unknown-critical snapshot directly.
	snap := stateSnapshot{Version: snapshotVersion, Capability: byte(model.CapGateway), Critical: byte(StateUnknown), Denial: byte(StateNormal)}
	body, _ := snap.encode()
	_ = p.Save(body)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if m.CriticalState() != StateCriticalDurabilityDegraded {
		t.Fatalf("unknown critical did not fail closed: %v", m.CriticalState())
	}
}

func TestCriticalFailureBlocksAndCounts(t *testing.T) {
	m := newMachine(t, NewMemPersist())
	if !m.WriteAllowedCritical() {
		t.Fatal("fresh machine must allow critical")
	}
	if err := m.OnCriticalCommitFailure("dp|gateway|P-CRIT", "fsync failed"); err != nil {
		t.Fatal(err)
	}
	if m.WriteAllowedCritical() {
		t.Fatal("critical must be blocked after commit failure")
	}
	if m.CriticalLoss() != 1 {
		t.Fatalf("critical loss = %d", m.CriticalLoss())
	}
	if m.Snapshot().Severity != SevCritical {
		t.Fatal("severity must be critical")
	}
}

func TestDenialFailureNeverTouchesCritical(t *testing.T) {
	m := newMachine(t, NewMemPersist())
	for i := 0; i < 1000; i++ {
		_ = m.OnDenialLaneFailure("denial flood")
	}
	// The critical track stays normal — no edge from denial to critical.
	if !m.WriteAllowedCritical() {
		t.Fatal("denial-lane failure blocked authenticated critical work")
	}
	if m.CriticalState() != StateNormal {
		t.Fatal("denial-lane failure moved the critical track")
	}
	if m.DenialState() != StateDenialLaneDegraded {
		t.Fatal("denial track not degraded")
	}
	// Distinct counters.
	if m.DenialLoss() != 1000 || m.CriticalLoss() != 0 {
		t.Fatalf("counters conflated: denial=%d critical=%d", m.DenialLoss(), m.CriticalLoss())
	}
	if m.Snapshot().Severity != SevWarning {
		t.Fatal("denial degradation must be warning severity")
	}
}

func TestRestartPersistsCriticalDegraded(t *testing.T) {
	p := NewMemPersist()
	m := newMachine(t, p)
	_ = m.OnCriticalCommitFailure("scope", "enospc")
	// Restart: a new machine over the same persistence must reconstruct the state.
	m2 := New(Config{Capability: model.CapGateway, NodeID: "dp", Persist: p, Clock: func() time.Time { return time.Unix(0, 99) }})
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if m2.WriteAllowedCritical() {
		t.Fatal("restart cleared the critical lockout")
	}
	if m2.CriticalState() != StateCriticalDurabilityDegraded {
		t.Fatal("restart did not reconstruct critical-degraded")
	}
}

func TestCorruptMetadataFailsTowardCritical(t *testing.T) {
	p := NewMemPersist()
	m := newMachine(t, p)
	_ = m.OnDenialLaneFailure("x") // ensure something is persisted
	p.Corrupt()
	m2 := New(Config{Capability: model.CapGateway, NodeID: "dp", Persist: p})
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if m2.CriticalState() != StateCriticalDurabilityDegraded {
		t.Fatal("corrupt metadata must fail toward critical, not normal")
	}
}

func TestUnreadableMetadataFailsTowardCritical(t *testing.T) {
	p := NewMemPersist()
	p.FailLoad = true
	m := New(Config{Capability: model.CapGateway, NodeID: "dp", Persist: p})
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if m.CriticalState() != StateCriticalDurabilityDegraded {
		t.Fatal("unreadable metadata must fail toward critical")
	}
}

func TestRecoveryRequiresAllFourCriteria(t *testing.T) {
	m := newMachine(t, NewMemPersist())
	_ = m.OnCriticalCommitFailure("scope", "fault")

	// Each single missing criterion must prevent the transition to normal.
	mutators := []func(c *ExitCriteria){
		func(c *ExitCriteria) { c.StorageWritable = false },
		func(c *ExitCriteria) { c.ReserveFreeBytes = 10 }, // < ReserveRecoveryBytes
		func(c *ExitCriteria) { c.MarkerReadBack = false },
		func(c *ExitCriteria) { c.PendingBacklogBytes = 1000 }, // > bound
	}
	for i, mut := range mutators {
		c := goodCriteria("mk")
		mut(&c)
		// BeginRecovery only checks 1,2,4; criterion 3 (marker) is checked in Finalize.
		began, _ := m.BeginRecovery(c)
		if began {
			// If it began (only the marker criterion missing), Finalize must reject.
			ok, _ := m.FinalizeRecovery(c)
			if ok {
				t.Fatalf("case %d: recovered to normal with a missing criterion", i)
			}
			// Reset back to degraded for the next case.
			if m.CriticalState() != StateCriticalDurabilityDegraded {
				t.Fatalf("case %d: not back in degraded", i)
			}
			continue
		}
		if m.WriteAllowedCritical() {
			t.Fatalf("case %d: recovered without all criteria", i)
		}
	}

	// All four hold → recovery completes, within the transition.
	c := goodCriteria("mk-final")
	began, err := m.BeginRecovery(c)
	if err != nil || !began {
		t.Fatalf("BeginRecovery: began=%v err=%v", began, err)
	}
	if m.WriteAllowedCritical() {
		t.Fatal("recovering must still block critical work")
	}
	ok, err := m.FinalizeRecovery(c)
	if err != nil || !ok {
		t.Fatalf("FinalizeRecovery: ok=%v err=%v", ok, err)
	}
	if !m.WriteAllowedCritical() {
		t.Fatal("did not return to normal after all four criteria")
	}
}

func TestReserveWatermarkUsesReserveNotSpool(t *testing.T) {
	// Criterion (2) compares ReserveFreeBytes against ReserveRecoveryBytes (a
	// fraction of the RESERVE). A machine given reserve-relative values recovers;
	// a spool-relative (much larger) threshold would never be reachable.
	m := newMachine(t, NewMemPersist())
	_ = m.OnCriticalCommitFailure("scope", "fault")
	c := goodCriteria("mk")
	c.ReserveFreeBytes = 50
	c.ReserveRecoveryBytes = 50 // exactly at the reserve fraction → holds
	began, _ := m.BeginRecovery(c)
	ok, _ := m.FinalizeRecovery(c)
	if !began || !ok {
		t.Fatal("reserve-relative watermark did not permit a reachable exit")
	}
}
