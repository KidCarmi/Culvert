package main

import (
	"encoding/json"
	"testing"
)

// The snapshot marshal caches are keyed on a version number, and a version
// identifies one snapshot only within one ConfigStore. A different store
// restarts its versions; a cache keyed on the number alone then served the
// PREVIOUS store's bytes as the new store's snapshot at that version. In the
// suite that made a data plane apply another test's configuration whenever a
// fixture installed a fresh store without resetting the caches (two red
// determinism runs). The caches now remember the store they were built from.
func TestSnapshotCaches_AnotherStoreAtTheSameVersionIsAMiss(t *testing.T) {
	orig := globalConfigStore
	t.Cleanup(func() {
		globalConfigStore = orig
		gcMarshalCache.reset()
		gcDeltaRemainderCache.reset()
	})
	gcMarshalCache.reset()
	gcDeltaRemainderCache.reset()

	publish := func(ruleName string) int64 {
		t.Helper()
		globalConfigStore = &ConfigStore{}
		if err := globalConfigStore.Update(ConfigSnapshot{
			PolicyRules: []PolicyRule{{Name: ruleName, Action: ActionAllow}},
		}); err != nil {
			t.Fatalf("publish %s: %v", ruleName, err)
		}
		return globalConfigStore.Version()
	}
	servedRule := func(raw json.RawMessage) string {
		t.Helper()
		var snap ConfigSnapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(snap.PolicyRules) != 1 {
			t.Fatalf("served %d rules, want 1", len(snap.PolicyRules))
		}
		return snap.PolicyRules[0].Name
	}

	v1 := publish("store-one")
	full, err := gcMarshalCache.serve("")
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	rem, err := gcDeltaRemainderCache.serve(v1, "", true)
	if err != nil {
		t.Fatalf("remainder: %v", err)
	}
	if servedRule(full) != "store-one" || servedRule(rem) != "store-one" {
		t.Fatal("premise: the first store's snapshot is served and cached")
	}

	// A second store reaches the SAME version with different content; the
	// caches are deliberately not reset in between.
	v2 := publish("store-two")
	if v2 != v1 {
		t.Fatalf("premise: both stores must be at the same version (got %d and %d)", v1, v2)
	}
	full, err = gcMarshalCache.serve("")
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if got := servedRule(full); got != "store-two" {
		t.Errorf("full snapshot cache served %q for the second store, want store-two", got)
	}
	rem, err = gcDeltaRemainderCache.serve(v2, "", true)
	if err != nil {
		t.Fatalf("remainder: %v", err)
	}
	if got := servedRule(rem); got != "store-two" {
		t.Errorf("delta remainder cache served %q for the second store, want store-two", got)
	}
}
