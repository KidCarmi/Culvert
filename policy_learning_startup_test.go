package main

// Startup-slice tests (M1 + M5A): the disabled posture is a TRUE no-op (no
// engine, no file, no goroutine, no shutdown work), the resolver honors the
// startup-slice contract, and enablement has no YAML/env/CLI path — the
// governed AdminSettings state is the only input the loader materializes.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPolicyLearningResolver_PathsOnlyNoEnablement(t *testing.T) {
	cfg := resolvePolicyLearningStartupConfig(&FileConfig{}, "/data")
	if cfg.StorePath != filepath.Join("/data", "policy_learning.json") {
		t.Errorf("StorePath = %q", cfg.StorePath)
	}
	if cfg.SubjectKeyPath != filepath.Join("/data", "policy_learning_subject.key") {
		t.Errorf("SubjectKeyPath = %q", cfg.SubjectKeyPath)
	}
	// nil FileConfig tolerated (zero-value contract).
	_ = resolvePolicyLearningStartupConfig(nil, "")
}

func TestPolicyLearningLoader_DisabledFootprintZero(t *testing.T) {
	dir := t.TempDir()
	prev := policyLearnEngine.Load()
	prevPaths := policyLearnPaths
	prevState, prevSaved := policyLearnSnapshotState()
	t.Cleanup(func() {
		policyLearnEngine.Store(prev)
		policyLearnPaths = prevPaths
		policyLearnSetState(prevState, prevSaved)
	})
	policyLearnEngine.Store(nil)
	policyLearnSetState(policyLearnSettings{}, false) // never governed ⇒ disabled

	before := runtime.NumGoroutine()
	loadPolicyLearning(policyLearningStartupConfig{
		StorePath:      filepath.Join(dir, "policy_learning.json"),
		SubjectKeyPath: filepath.Join(dir, "policy_learning_subject.key"),
	})
	if policyLearnEngine.Load() != nil {
		t.Fatal("disabled loader constructed an engine")
	}
	if _, err := os.Stat(filepath.Join(dir, "policy_learning.json")); !os.IsNotExist(err) {
		t.Fatalf("disabled loader touched the filesystem: %v", err)
	}
	// Goroutine budget: the loader spawns nothing.
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("disabled loader changed goroutine count: %d -> %d", before, after)
	}
}

// swapPolicyLearn installs a REAL production-wired engine over storeDir (the
// governed-enabled posture) and restores every touched global on cleanup — the
// global-isolation seam (autoexclude swap precedent) for M2+ tests.
func swapPolicyLearn(t *testing.T, storeDir string) {
	t.Helper()
	prev := policyLearnEngine.Load()
	prevPaths := policyLearnPaths
	prevState, prevSaved := policyLearnSnapshotState()
	policyLearnEngine.Store(nil)
	policyLearnSetState(policyLearnSettings{Enabled: true}, true)
	loadPolicyLearning(policyLearningStartupConfig{
		StorePath:      filepath.Join(storeDir, "policy_learning.json"),
		SubjectKeyPath: filepath.Join(storeDir, "policy_learning_subject.key"),
	})
	t.Cleanup(func() {
		if eng := policyLearnEngine.Load(); eng != nil && eng != prev {
			_ = eng.Close()
		}
		policyLearnEngine.Store(prev)
		policyLearnPaths = prevPaths
		policyLearnSetState(prevState, prevSaved)
		policyLearnSetRunErr("")
	})
}

func TestPolicyLearningLoader_EnabledSeamConstructsEngine(t *testing.T) {
	dir := t.TempDir()
	swapPolicyLearn(t, dir)
	eng := policyLearnEngine.Load()
	if eng == nil {
		t.Fatal("enabled loader (test seam) did not construct the engine")
	}
	if eng.LearningActive() {
		t.Fatal("M5A §1 violated: enabling the feature armed observation without a Start Learning transition")
	}
	s, err := eng.StartSession("test-admin")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if s.Baseline.CapturedAt == "" {
		t.Error("baseline capture missing")
	}
	if s.Baseline.PolicyContentHash == "" {
		t.Error("M5A §6: baseline missing the canonical policy content identity")
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
