package main

// Policy Learning Mode startup slice — loader (ADR-0025, slices M1 + M5A).

// loadPolicyLearning wires the learning engine at startup. ORDER IS THE
// CONTRACT:
//  1. initPersistentAdminState (LoadAdminSettings) has already run and
//     RECORDED the governed desired state (applyAdminPolicyLearning — intent
//     only, no engine construction there: settings load runs before this
//     slice resolves the store paths).
//  2. This loader stores the resolved paths and MATERIALIZES the desired
//     state: disabled (the shipped default, and the only state when no admin
//     ever governed the feature) is a TRUE no-op — no engine, no file, no
//     goroutine, the singleton stays nil, and the shutdown hook no-ops.
//  3. Enabled ⇒ the engine is constructed BEFORE any traffic could observe
//     it. Enabling the FEATURE does not start LEARNING: observation stays
//     disarmed until an explicit Start Learning transition (M5A §1).
//
// There is deliberately NO YAML key, env var, or CLI flag for enablement —
// the governed admin surface (AdminSettings + API + GUI) is the only path.
func loadPolicyLearning(cfg policyLearningStartupConfig) {
	policyLearnAdminMu.Lock()
	defer policyLearnAdminMu.Unlock()
	policyLearnPaths = cfg
	desired, _ := policyLearnSnapshotState()
	if !desired.Enabled {
		return
	}
	policyLearnApplyDesiredLocked(desired)
}
