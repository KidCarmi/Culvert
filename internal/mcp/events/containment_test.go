package events

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/secret"
)

func testMgrKEK() *secret.Provider {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 3)
	}
	return secret.MemoryProvider(k)
}

func newMgr(t *testing.T, dir string, be spool.Backend) *Manager {
	t.Helper()
	m, err := NewManager(ManagerConfig{
		NodeID: "dp-1", DataDir: dir, KEK: testMgrKEK(),
		GatewayLimits: limits.DefaultGatewayEvent(), ManagementLimits: limits.DefaultManagementEvent(),
		Backend: be, Clock: func() time.Time { return time.Unix(0, 1) },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func critFacts(cap model.Capability, tenant string) DecisionFacts {
	return DecisionFacts{
		Capability: cap, Criticality: model.CritCritical, ActionClass: model.ActionClassWrite,
		Identity: model.IdentityEvidence{Tenant: tenant, PrincipalID: "u", PrincipalType: "human"},
		Decision: model.DecisionEvidence{Action: "ALLOW", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 1, CatalogRevision: 1},
	}
}

func denialIn(cap model.Capability, i int) DenialInput {
	return DenialInput{Capability: cap, Listener: "gw", Source: "203.0.113." + itoa(i%250), Reason: "auth_failed"}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// Test 1 — Headline attacker: flood Gateway denials at max rate while authenticated
// critical work in a DIFFERENT capability (Management) runs throughout and MUST
// succeed for the whole duration.
func TestT075_1_HeadlineAttacker(t *testing.T) {
	m := newMgr(t, t.TempDir(), nil)
	defer m.Close()
	// Attacker floods Gateway denials. Observations are O(1) in-memory; the flood
	// is large while the durable commits stay bounded by coalescing.
	for round := 0; round < 5; round++ {
		for i := 0; i < 5000; i++ {
			m.ObserveDenial(denialIn(model.CapGateway, i))
		}
		m.FlushDenials(model.CapGateway)
		// Throughout the flood, a Management critical operation must succeed.
		if _, err := m.CommitDecision(critFacts(model.CapManagement, "acme")); err != nil {
			t.Fatalf("round %d: authenticated critical work blocked by denial flood: %v", round, err)
		}
		// And a Gateway critical operation (different domain: P-CRIT reserve) too.
		if _, err := m.CommitDecision(critFacts(model.CapGateway, "acme")); err != nil {
			t.Fatalf("round %d: gateway critical blocked by denial flood: %v", round, err)
		}
	}
}

// Test 2 — Coalescing: N equivalent denials → O(1) durable aggregate.
func TestT075_2_Coalescing(t *testing.T) {
	m := newMgr(t, t.TempDir(), nil)
	defer m.Close()
	for i := 0; i < 10000; i++ {
		m.ObserveDenial(DenialInput{Capability: model.CapGateway, Listener: "gw", Source: "198.51.100.1", Reason: "auth_failed"})
	}
	// Advance the clock past the window and flush.
	committed, lost := m.flushDomainDenials(m.domains[model.CapGateway], true)
	if lost != 0 {
		t.Fatalf("lost %d aggregates", lost)
	}
	if committed != 1 {
		t.Fatalf("N denials produced %d durable records, want 1 (O(1))", committed)
	}
}

// Test 3 — Reserved partition: saturate P-DEN, then an authenticated critical event
// still commits from the reserve.
func TestT075_3_ReservedPartition(t *testing.T) {
	dir := t.TempDir()
	m := newMgr(t, dir, nil)
	defer m.Close()
	// Load P-DEN with committed aggregates (deep saturation is proven at the spool
	// level; here we prove the manager preserves the reserve under denial load).
	for i := 0; i < 60; i++ {
		m.ObserveDenial(DenialInput{Capability: model.CapGateway, Listener: "gw", Source: "10.1.2." + itoa(i), Reason: "auth_failed"})
	}
	m.flushDomainDenials(m.domains[model.CapGateway], true)
	// Critical still commits.
	if _, err := m.CommitDecision(critFacts(model.CapGateway, "acme")); err != nil {
		t.Fatalf("critical commit failed with P-DEN loaded: %v", err)
	}
}

// Test 4 — Local-scope containment: Gateway critical degradation does not block
// Management, and vice versa.
func TestT075_4_LocalScopeContainment(t *testing.T) {
	be := newFaultBackend()
	m := newMgr(t, t.TempDir(), be)
	defer m.Close()
	// Fail Gateway P-CRIT commits only.
	be.failAppendFor("gateway/P-CRIT", false)
	if _, err := m.CommitDecision(critFacts(model.CapGateway, "acme")); err == nil {
		t.Fatal("gateway critical should have failed closed")
	}
	if m.WriteAllowedCritical(model.CapGateway) {
		t.Fatal("gateway should be degraded")
	}
	// Management must be UNAFFECTED.
	if !m.WriteAllowedCritical(model.CapManagement) {
		t.Fatal("management degraded by a gateway failure (cross-capability leak)")
	}
	if _, err := m.CommitDecision(critFacts(model.CapManagement, "acme")); err != nil {
		t.Fatalf("management critical blocked by gateway degradation: %v", err)
	}
}

// Test 5 — Preserved fail-closed: (b) post-admission commit failure. The critical
// operation fails closed BEFORE its irreversible action; the harness callback and
// the credential gate's materialization are never reached.
func TestT075_5_FailClosed_PostAdmission(t *testing.T) {
	be := newFaultBackend()
	m := newMgr(t, t.TempDir(), be)
	defer m.Close()
	be.failAppendFor("gateway/P-CRIT", true) // ENOSPC

	called := false
	err := m.CommitThenAct(critFacts(model.CapGateway, "acme"), func(spool.CommitReceipt) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("post-admission commit failure must fail closed")
	}
	if called {
		t.Fatal("irreversible callback ran despite a failed commit (commit-before-side-effect violated)")
	}
	if m.WriteAllowedCritical(model.CapGateway) {
		t.Fatal("domain not degraded after critical commit failure")
	}
}

// Test 5 — Preserved fail-closed: (a) queue/admission saturation. Uses a tiny
// spool whose P-CRIT reserve is exhausted so admission itself fails.
func TestT075_5_FailClosed_Saturation(t *testing.T) {
	dir := t.TempDir()
	lim, err := limits.NewEvent(tinyCritConfig())
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(ManagerConfig{
		NodeID: "dp-1", DataDir: dir, KEK: testMgrKEK(),
		GatewayLimits: lim, ManagementLimits: lim, Clock: func() time.Time { return time.Unix(0, 1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	// Fill P-CRIT until admission saturates (a tiny spool saturates in a few
	// hundred commits).
	saturated := false
	for i := 0; i < 5000 && !saturated; i++ {
		if _, err := m.CommitDecision(critFacts(model.CapGateway, "acme")); err != nil {
			saturated = true
			break
		}
	}
	if !saturated {
		t.Fatal("could not saturate P-CRIT")
	}
	// The domain is now critical-degraded; further critical work fails closed and
	// the harness callback never runs.
	called := false
	if err := m.CommitThenAct(critFacts(model.CapGateway, "acme"), func(spool.CommitReceipt) error { called = true; return nil }); err == nil {
		t.Fatal("critical work must fail closed under saturation")
	}
	if called {
		t.Fatal("callback ran under saturation")
	}
}

// Test 6 — Recovery termination: restore durability, probe recovers to normal.
func TestT075_6_RecoveryTermination(t *testing.T) {
	be := newFaultBackend()
	m := newMgr(t, t.TempDir(), be)
	defer m.Close()
	be.failAppendFor("gateway/P-CRIT", false)
	_, _ = m.CommitDecision(critFacts(model.CapGateway, "acme"))
	if m.WriteAllowedCritical(model.CapGateway) {
		t.Fatal("expected degraded")
	}
	// Restore durability.
	be.failAppendFor("", false)
	// Probe should recover within one tick now that all four criteria hold.
	if !m.RecoverProbe(model.CapGateway) {
		t.Fatal("recovery probe did not terminate the degraded state")
	}
	if !m.WriteAllowedCritical(model.CapGateway) {
		t.Fatal("critical still blocked after recovery")
	}
}

// Test 7 — Restart persistence: restart while degraded keeps the lockout.
func TestT075_7_RestartPersistence(t *testing.T) {
	dir := t.TempDir()
	be := newFaultBackend()
	m := newMgr(t, dir, be)
	be.failAppendFor("gateway/P-CRIT", false)
	_, _ = m.CommitDecision(critFacts(model.CapGateway, "acme"))
	if m.WriteAllowedCritical(model.CapGateway) {
		t.Fatal("expected degraded before restart")
	}
	_ = m.Close()
	// Restart with a HEALTHY backend: restart alone must not clear the lockout.
	m2 := newMgr(t, dir, nil)
	defer m2.Close()
	if m2.WriteAllowedCritical(model.CapGateway) {
		t.Fatal("restart cleared the critical lockout")
	}
}

// Test 8 — Storage reclamation is proven at the spool level
// (spool.TestReclamationOrder); here we assert the manager preserves the
// reserved-partition guarantee under denial pressure (a manager-level check that
// denial traffic never consumes the critical reserve).
func TestT075_8_ReserveNotConsumedByDenial(t *testing.T) {
	m := newMgr(t, t.TempDir(), nil)
	defer m.Close()
	for i := 0; i < 80; i++ {
		m.ObserveDenial(DenialInput{Capability: model.CapGateway, Listener: "gw", Source: "10.9.3." + itoa(i), Reason: "auth_failed"})
	}
	m.flushDomainDenials(m.domains[model.CapGateway], true)
	st := m.domains[model.CapGateway].spool.Stats()
	// Critical still has its full headroom; denial bytes never crossed into it.
	if st.CriticalFreeBytes < int64(limits.DefaultGatewayEvent().CriticalReserveBytes()) {
		t.Fatalf("critical headroom eroded by denial traffic: free=%d reserve=%d", st.CriticalFreeBytes, limits.DefaultGatewayEvent().CriticalReserveBytes())
	}
	if _, err := m.CommitDecision(critFacts(model.CapGateway, "acme")); err != nil {
		t.Fatalf("critical commit failed after denial pressure: %v", err)
	}
}

// Test 9 — Counter integrity: denial-lane loss and critical commit failure use
// SEPARATE counters at SEPARATE severities.
func TestT075_9_CounterIntegrity(t *testing.T) {
	be := newFaultBackend()
	m := newMgr(t, t.TempDir(), be)
	defer m.Close()

	// Induce a critical commit failure.
	be.failAppendFor("gateway/P-CRIT", false)
	_, _ = m.CommitDecision(critFacts(model.CapGateway, "acme"))
	be.failAppendFor("", false)

	// Induce denial-lane loss on Management independently (fail its P-DEN commits).
	be.failAppendFor("management/P-DEN", false)
	m.ObserveDenial(DenialInput{Capability: model.CapManagement, Listener: "mg", Source: "203.0.113.9", Reason: "auth_failed"})
	m.flushDomainDenials(m.domains[model.CapManagement], true)

	gw := m.domains[model.CapGateway].state.Snapshot()
	mg := m.domains[model.CapManagement].state.Snapshot()
	if gw.CriticalLoss == 0 {
		t.Fatal("gateway critical loss counter did not move")
	}
	if gw.DenialLoss != 0 {
		t.Fatal("gateway denial loss moved on a critical failure (counters conflated)")
	}
	if mg.DenialLoss == 0 {
		t.Fatal("management denial loss counter did not move")
	}
	if mg.CriticalLoss != 0 {
		t.Fatal("management critical loss moved on a denial failure (counters conflated)")
	}
}

func tinyCritConfig() limits.EventConfig {
	return limits.EventConfig{
		SpoolMaxBytes: 256 << 10, CriticalReserveBytes: 96 << 10,
		OrdinaryQuotaBytes: 96 << 10, DenialQuotaBytes: 32 << 10,
		SegmentMaxBytes: 16 << 10, MaxEventBytes: 8 << 10, MaxMetadataBytes: 64 << 10,
		MaxSafeResultBytes: 64 << 10, MaxSegments: 1024, MaxQueuePerPartition: 4096,
		MaxInFlightCommits: 64, CommitBatchSize: 64, MaxSyncOps: 16, MaxDenialBuckets: 4096,
		MaxBucketsPerSource: 128, MaxCoalescePerAggregate: 1 << 20, MaxRecoveryScanBytes: 8 << 20,
		MaxRecoverySegments: 1024, MaxRecoveryRecords: 65536, MaxReclaimPerPass: 256,
		ExporterWorkers: 2, ExportBatchRecords: 256, ExportBatchBytes: 1 << 20, ExportMaxRetries: 4,
		ReplayWindowEntries: 65536, TenantExportMaxRecords: 4096, TenantExportMaxBytes: 4 << 20,
		HighWatermarkPct: 90, LowWatermarkPct: 80, ReserveRecoveryPct: 50,
		AggregationWindow: time.Second, RetentionWindow: time.Hour, ProbeInterval: time.Second,
		CommitBatchDelay: time.Millisecond, ShutdownDrain: time.Second,
	}
}

var _ = mcperr.ReasonEventDurabilityDegraded
