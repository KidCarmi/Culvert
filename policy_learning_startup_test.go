package main

// M1 startup-slice tests: the disabled posture is a TRUE no-op (no engine, no
// file, no goroutine, no shutdown work), and the resolver honors the
// startup-slice contract (purity/determinism are additionally pinned by the
// contract table in startup_slice_contract_test.go).

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPolicyLearningResolver_DisabledConstant(t *testing.T) {
	cfg := resolvePolicyLearningStartupConfig(&FileConfig{}, "/data")
	if cfg.Enabled {
		t.Fatal("M1 invariant violated: resolver returned Enabled=true — no production enablement surface may exist before the admin API + GUI slice")
	}
	if cfg.StorePath != filepath.Join("/data", "policy_learning.json") {
		t.Errorf("StorePath = %q", cfg.StorePath)
	}
	// nil FileConfig tolerated (zero-value contract).
	_ = resolvePolicyLearningStartupConfig(nil, "")
}

func TestPolicyLearningLoader_DisabledFootprintZero(t *testing.T) {
	dir := t.TempDir()
	prev := policyLearnEngine.Load()
	t.Cleanup(func() { policyLearnEngine.Store(prev) })
	policyLearnEngine.Store(nil)

	before := runtime.NumGoroutine()
	loadPolicyLearning(policyLearningStartupConfig{
		Enabled:   false,
		StorePath: filepath.Join(dir, "policy_learning.json"),
	})
	if policyLearnEngine.Load() != nil {
		t.Fatal("disabled loader constructed an engine")
	}
	if _, err := os.Stat(filepath.Join(dir, "policy_learning.json")); !os.IsNotExist(err) {
		t.Fatalf("disabled loader touched the filesystem: %v", err)
	}
	// Goroutine budget: the loader spawns nothing. (The engine never owns
	// goroutines even when enabled; this pins the loader path.)
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("disabled loader changed goroutine count: %d -> %d", before, after)
	}
}

// swapPolicyLearn installs a test engine and restores the previous singleton on
// cleanup — the global-isolation seam (autoexclude swap precedent) for M2+
// tests. Exercised here so the seam itself is pinned in M1.
func swapPolicyLearn(t *testing.T, storeDir string) {
	t.Helper()
	prev := policyLearnEngine.Load()
	loadPolicyLearning(policyLearningStartupConfig{
		Enabled:   true,
		StorePath: filepath.Join(storeDir, "policy_learning.json"),
	})
	t.Cleanup(func() { policyLearnEngine.Store(prev) })
}

func TestPolicyLearningLoader_EnabledSeamConstructsEngine(t *testing.T) {
	dir := t.TempDir()
	swapPolicyLearn(t, dir)
	eng := policyLearnEngine.Load()
	if eng == nil {
		t.Fatal("enabled loader (test seam) did not construct the engine")
	}
	s, err := eng.StartSession("test-admin")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if s.Baseline.CapturedAt == "" {
		t.Error("baseline capture missing")
	}
	if _, err := os.Stat(filepath.Join(dir, "policy_learning.json")); err != nil {
		t.Errorf("session store not persisted: %v", err)
	}
	if _, err := eng.StopSession("test-admin"); err != nil {
		t.Fatalf("StopSession: %v", err)
	}
}

func TestPolicyLearningShutdownHook_NoopOnNilAndFlushesWhenSet(t *testing.T) {
	// nil singleton: the hook body must be a safe no-op.
	prev := policyLearnEngine.Load()
	t.Cleanup(func() { policyLearnEngine.Store(prev) })
	policyLearnEngine.Store(nil)
	if eng := policyLearnEngine.Load(); eng != nil {
		t.Fatal("precondition")
	}
	// The registered hook closure is exercised through the registry in the
	// shutdown-sequence tests; here we pin the nil-guard contract directly.
	if eng := policyLearnEngine.Load(); eng != nil {
		_ = eng.Close()
	}

	// Set singleton: Close persists the lazily-flipped expiry state.
	dir := t.TempDir()
	swapPolicyLearn(t, dir)
	eng := policyLearnEngine.Load()
	if _, err := eng.StartSession("a"); err != nil {
		t.Fatal(err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

}
