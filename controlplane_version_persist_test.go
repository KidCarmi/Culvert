package main

// controlplane_version_persist_test.go — CHAOS-01 regression coverage.
//
// ConfigStore.version was in-memory only: a CP restart reset the counter to
// 0 while every long-running DP still held the pre-restart value, so the
// DP-side "snap.Version <= lastVersion" short-circuit silently suppressed
// all post-restart config changes. armVersionPersistence seeds the counter
// with max(persisted floor, wall clock) and Update persists the floor.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestConfigStoreVersion_SurvivesRestart is the core CHAOS-01 regression:
// a "restarted" CP (fresh ConfigStore over the same floor file) must publish
// versions strictly above everything the previous incarnation published, so
// a DP holding the old lastVersion keeps applying snapshots.
func TestConfigStoreVersion_SurvivesRestart(t *testing.T) {
	floor := filepath.Join(t.TempDir(), cpConfigVersionFile)

	cp1 := &ConfigStore{}
	cp1.armVersionPersistence(floor)
	cp1.Update(ConfigSnapshot{})
	cp1.Update(ConfigSnapshot{})
	dpLastVersion := cp1.Get().Version // what a running DP has already seen

	cp2 := &ConfigStore{} // simulated CP restart: counter starts at zero
	cp2.armVersionPersistence(floor)
	cp2.Update(ConfigSnapshot{})
	if got := cp2.Get().Version; got <= dpLastVersion {
		t.Fatalf("post-restart version %d <= pre-restart version %d — DPs would silently ignore all post-restart config (CHAOS-01)", got, dpLastVersion)
	}
}

// TestConfigStoreVersion_PersistedFloorBeatsClock pins the clock-rollback
// half of the seed: when the persisted floor is AHEAD of the wall clock
// (VM snapshot restore, NTP step-back), the floor must win.
func TestConfigStoreVersion_PersistedFloorBeatsClock(t *testing.T) {
	floor := filepath.Join(t.TempDir(), cpConfigVersionFile)
	future := time.Now().Unix() + 1_000_000
	data, err := json.Marshal(cpConfigVersionState{Version: future})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(floor, data, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &ConfigStore{}
	s.armVersionPersistence(floor)
	s.Update(ConfigSnapshot{})
	if got := s.Get().Version; got <= future {
		t.Fatalf("version %d <= persisted floor %d — clock rollback would re-issue already-seen versions", got, future)
	}
}

// TestConfigStoreVersion_MissingFloorSeedsFromClock pins the file-loss half
// of the seed: with no floor file at all, the counter must still start at
// wall-clock scale (not 0), so a wiped dataDir cannot reintroduce the
// silent-staleness bug against running DPs.
func TestConfigStoreVersion_MissingFloorSeedsFromClock(t *testing.T) {
	floor := filepath.Join(t.TempDir(), cpConfigVersionFile)
	before := time.Now().Unix()

	s := &ConfigStore{}
	s.armVersionPersistence(floor)
	s.Update(ConfigSnapshot{})
	if got := s.Get().Version; got <= before {
		t.Fatalf("version %d not seeded from clock (want > %d) with missing floor file", got, before)
	}
	// The publish must also have (re)written a parseable floor.
	data, err := os.ReadFile(floor)
	if err != nil {
		t.Fatalf("floor file not written after Update: %v", err)
	}
	var st cpConfigVersionState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("floor file unparseable: %v", err)
	}
	if st.Version != s.Get().Version {
		t.Fatalf("persisted floor %d != published version %d", st.Version, s.Get().Version)
	}
}

// TestConfigStoreVersion_CorruptFloorFallsBackToClock pins the fail-safe
// response to a torn/corrupt floor file: recover via the clock seed (never
// fatal, never seed 0) and overwrite the corrupt file on the next publish.
func TestConfigStoreVersion_CorruptFloorFallsBackToClock(t *testing.T) {
	floor := filepath.Join(t.TempDir(), cpConfigVersionFile)
	if err := os.WriteFile(floor, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := time.Now().Unix()

	s := &ConfigStore{}
	s.armVersionPersistence(floor)
	s.Update(ConfigSnapshot{})
	if got := s.Get().Version; got <= before {
		t.Fatalf("version %d not reseeded from clock (want > %d) with corrupt floor file", got, before)
	}
	data, err := os.ReadFile(floor)
	if err != nil {
		t.Fatal(err)
	}
	var st cpConfigVersionState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("corrupt floor not replaced with a valid one on publish: %v", err)
	}
}

// TestConfigStoreVersion_UnarmedStoreDoesNotPersist pins that bare
// ConfigStores (DP-only processes, other tests) keep the pre-CHAOS-01
// behavior: no floor file writes.
func TestConfigStoreVersion_UnarmedStoreDoesNotPersist(t *testing.T) {
	s := &ConfigStore{}
	s.Update(ConfigSnapshot{})
	if got := s.Get().Version; got != 1 {
		t.Fatalf("unarmed store version = %d, want 1", got)
	}
}

// resetReplicatedLeaderVersion isolates the process-global replicated-leader
// watermark for one test and restores it afterwards.
func resetReplicatedLeaderVersion(t *testing.T) {
	t.Helper()
	prev := replicatedLeaderConfigVersion.Load()
	replicatedLeaderConfigVersion.Store(0)
	t.Cleanup(func() { replicatedLeaderConfigVersion.Store(prev) })
}

// TestConfigStoreVersion_HAPromotionSeedsFromReplicatedLeader is the
// HA-promotion regression: a freshly promoted standby whose own floor file is
// ABSENT (it was never a CP) and whose wall-clock-derived seed is BELOW the old
// leader's replicated Version must still publish a version strictly greater
// than that leader Version — otherwise every DP holding the old leader's
// lastVersion would silently short-circuit fetchAndApply and apply NO
// post-failover config.
func TestConfigStoreVersion_HAPromotionSeedsFromReplicatedLeader(t *testing.T) {
	resetReplicatedLeaderVersion(t)

	// The old leader's counter ran far ahead of wall-clock seconds (many rapid
	// config updates), so the standby's clock-derived seed is well below it.
	// This is exactly the value a running DP has already applied.
	leaderVersion := time.Now().Unix() + 5_000_000
	noteReplicatedLeaderVersion(leaderVersion)

	// Promotion arms the floor over the (absent) file + clock + replicated
	// version, then publishes its first snapshot.
	floor := filepath.Join(t.TempDir(), cpConfigVersionFile) // never written: fresh promotee
	cp := &ConfigStore{}
	cp.armVersionPersistence(floor)
	cp.Update(ConfigSnapshot{})

	if got := cp.Get().Version; got <= leaderVersion {
		t.Fatalf("post-promotion version %d <= replicated leader version %d — DPs would silently ignore all post-failover config (CHAOS-01 HA promotion)", got, leaderVersion)
	}
}

// TestApplyHABundle_FailureDoesNotRecordReplicatedLeaderVersion ensures a
// rejected local bundle cannot publish HA freshness metadata.
func TestApplyHABundle_FailureDoesNotRecordReplicatedLeaderVersion(t *testing.T) {
	resetReplicatedLeaderVersion(t)

	const leaderVersion int64 = 987654
	if applyHABundle(&HAStateBundle{Version: leaderVersion}, "tok") {
		t.Fatal("applyHABundle should return false when cluster state is absent")
	}
	if got := replicatedLeaderConfigVersion.Load(); got != 0 {
		t.Fatalf("failed bundle recorded leader version %d", got)
	}
}
