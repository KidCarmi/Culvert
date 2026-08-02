package events

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/secret"
)

func benchManager(b *testing.B) *Manager {
	b.Helper()
	k := make([]byte, 32)
	m, err := NewManager(ManagerConfig{
		NodeID: "dp", DataDir: b.TempDir(), KEK: secret.MemoryProvider(k),
		GatewayLimits: limits.DefaultGatewayEvent(), ManagementLimits: limits.DefaultManagementEvent(),
		Clock: func() time.Time { return time.Unix(0, 1) },
	})
	if err != nil {
		b.Fatal(err)
	}
	return m
}

// BenchmarkCriticalCommit measures a full durable critical commit (build + encrypt
// + append + fsync + checkpoint + readback). Encryption and sync dominate; the
// stable property is a bounded, per-commit allocation with no per-event goroutine.
func BenchmarkCriticalCommit(b *testing.B) {
	m := benchManager(b)
	defer m.Close()
	f := DecisionFacts{
		Capability: model.CapGateway, Criticality: model.CritCritical, ActionClass: model.ActionClassWrite,
		Identity: model.IdentityEvidence{Tenant: "acme", PrincipalID: "u", PrincipalType: "human"},
		Decision: model.DecisionEvidence{Action: "ALLOW", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 1, CatalogRevision: 1},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := m.CommitDecision(f); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDenialObserve measures the O(1) in-memory denial-lane admission path
// (no I/O until a bounded flush). It should be allocation-light per observation.
func BenchmarkDenialObserve(b *testing.B) {
	m := benchManager(b)
	defer m.Close()
	in := DenialInput{Capability: model.CapGateway, Listener: "gw", Source: "203.0.113.7", Reason: "auth_failed"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ObserveDenial(in)
	}
}

// BenchmarkHealthSnapshot measures the safe health snapshot (no I/O).
func BenchmarkHealthSnapshot(b *testing.B) {
	m := benchManager(b)
	defer m.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Health()
	}
}
