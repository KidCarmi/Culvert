package events

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// TestProperty_MonotonicSequence proves committed P-CRIT sequences are strictly
// monotonic across many commits.
func TestProperty_MonotonicSequence(t *testing.T) {
	m := newMgr(t, t.TempDir(), nil)
	defer m.Close()
	var last uint64
	for i := 0; i < 50; i++ {
		rec, err := m.CommitDecision(critFacts(model.CapGateway, "acme"))
		if err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
		if rec.Sequence() <= last && i > 0 {
			t.Fatalf("sequence not strictly monotonic: %d after %d", rec.Sequence(), last)
		}
		last = rec.Sequence()
	}
}

// TestProperty_RecoveredEventEqualsCommitted proves a committed event round-trips
// through recovery to an identical safe event (same digest).
func TestProperty_RecoveredEventEqualsCommitted(t *testing.T) {
	dir := t.TempDir()
	m := newMgr(t, dir, nil)
	facts := critFacts(model.CapGateway, "acme")
	rec, err := m.CommitDecision(facts)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	wantDigest := rec.EventDigest()
	_ = m.Close()

	// Reopen and read the committed event back; its digest must match and verify.
	m2 := newMgr(t, dir, nil)
	defer m2.Close()
	evs, _, _, rerr := m2.Spool(model.CapGateway).CommittedForExport(model.PartCrit, 0, 10)
	if rerr != nil {
		t.Fatalf("read back: %v", rerr)
	}
	found := false
	for _, e := range evs {
		if e.EventDigest == wantDigest {
			if !e.VerifyDigest() {
				t.Fatal("recovered event fails digest verification")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("committed event not recovered with an identical digest")
	}
}

// TestProperty_ManagementGatewayIsolation proves the two capability state machines
// cannot affect one another: degrading one leaves the other's critical track normal.
func TestProperty_ManagementGatewayIsolation(t *testing.T) {
	be := newFaultBackend()
	m := newMgr(t, t.TempDir(), be)
	defer m.Close()
	be.failAppendFor("management/P-CRIT", false)
	_, _ = m.CommitDecision(critFacts(model.CapManagement, "acme"))
	if m.WriteAllowedCritical(model.CapManagement) {
		t.Fatal("management should be degraded")
	}
	if !m.WriteAllowedCritical(model.CapGateway) {
		t.Fatal("gateway degraded by a management failure (isolation broken)")
	}
}
