package adminapi

import (
	"sync"
	"testing"
)

func TestHealth_CapabilityIsolation(t *testing.T) {
	src := HealthSources{
		Durability: func(cap string) DurabilityHealth {
			if cap == "management" {
				return DurabilityHealth{CriticalState: "critical-durability-degraded", Severity: "critical"}
			}
			return DurabilityHealth{CriticalState: "normal", Severity: "none"}
		},
		Runtime: func(cap string) RuntimeStateHealth {
			if cap == "management" {
				return RuntimeStateHealth{State: "degraded"}
			}
			return RuntimeStateHealth{State: "ready", ListenerReady: true}
		},
	}
	h := NewHealthService(src, DefaultLimits())
	v := h.Snapshot()
	// Management degraded must NOT rewrite Gateway health.
	if v.Gateway.Durability.CriticalState != "normal" || v.Gateway.Runtime.State != "ready" {
		t.Fatalf("gateway health was affected by management degradation: %+v", v.Gateway)
	}
	if v.Management.Durability.CriticalState != "critical-durability-degraded" {
		t.Fatalf("management degradation not reflected: %+v", v.Management)
	}
	if v.DistributionState != "local_only" {
		t.Fatalf("distribution state must be local_only, got %q", v.DistributionState)
	}
}

func TestHealth_ManagementAccessFromConfig(t *testing.T) {
	cfg := NewConfigStore(1 << 20)
	c := DefaultMCPConfig()
	c.Management.Enabled = true
	c.Management.DefaultMinRole = "operator"
	if err := cfg.Set(c); err != nil {
		t.Fatalf("Set: %v", err)
	}
	h := NewHealthService(HealthSources{Config: cfg}, DefaultLimits())
	v := h.Snapshot()
	if !v.ManagementAccess.Enabled || v.ManagementAccess.DefaultMinRole != "operator" {
		t.Fatalf("management access health wrong: %+v", v.ManagementAccess)
	}
	if v.ManagementAccess.MutationEnabled {
		t.Fatal("mutation must be reported off")
	}
}

// TestHealth_ConcurrentSnapshots is a race-detector smoke test for concurrent
// reads (run under -race in CI).
func TestHealth_ConcurrentSnapshots(t *testing.T) {
	cfg := NewConfigStore(1 << 20)
	h := NewHealthService(HealthSources{
		Config:     cfg,
		Durability: func(string) DurabilityHealth { return DurabilityHealth{CriticalState: "normal"} },
		Runtime:    func(string) RuntimeStateHealth { return RuntimeStateHealth{State: "ready"} },
	}, DefaultLimits())
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.Snapshot()
		}()
	}
	wg.Wait()
}
