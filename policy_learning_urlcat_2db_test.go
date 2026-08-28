package main

// 2D-B §47 — Policy Learning taxonomy-epoch regression over the HARDENED
// catStore mutation domain:
//
//  1. an admin taxonomy semantic edit (a fenced durable mutation) moves the
//     category epoch,
//  2. the SAME persisted taxonomy reloaded after a restart yields the SAME
//     epoch (the admin half is the restart-stable ContentFingerprint —
//     never a process-local counter),
//  3. an override-set change moves the signed taxonomy identity
//     (saasFeedOverridesFingerprint — the coordinator's ConfigRevision).
//
// The signed effective-view half (GenerationID:ConfigRevision) is pinned by
// the existing F3b activation/recompose suites; the UT1 community DB is
// DELIBERATELY outside this fence (recorded limitation — not claimed
// otherwise anywhere).

import (
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catoverride"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

func TestPolicyLearning2DB_AdminEditMovesEpoch_RestartKeepsIt(t *testing.T) {
	orig := catStore
	t.Cleanup(func() { catStore = orig })
	path := filepath.Join(t.TempDir(), "url_categories.json")
	fresh := urlcat.New(nil)
	fresh.SetPathForTest(path)
	catStore = fresh
	if err := catStore.CreateDurable(nil, "Learn2DB", []string{"seed.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	epochBefore := learnCategoryEpoch()

	// (1) A fenced durable semantic edit moves the epoch.
	rev := catStore.ContentFingerprint()
	if err := catStore.AddHostDurable(&rev, "Learn2DB", "added.example"); err != nil {
		t.Fatalf("edit: %v", err)
	}
	epochAfter := learnCategoryEpoch()
	if epochAfter == epochBefore {
		t.Fatal("an admin taxonomy semantic edit must move the category epoch")
	}

	// (2) Restart: a FRESH store over the same persisted file serves the SAME
	// epoch — no process-local counter leaks into the identity.
	reloaded := urlcat.New(nil)
	if err := reloaded.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	catStore = reloaded
	if got := learnCategoryEpoch(); got != epochAfter {
		t.Fatalf("epoch changed across restart of identical taxonomy: %q vs %q", got, epochAfter)
	}
}

func TestPolicyLearning2DB_OverrideChangeMovesSignedIdentity(t *testing.T) {
	empty := saasFeedOverridesFingerprint(catoverride.Overrides{})
	withOverride := saasFeedOverridesFingerprint(catoverride.Overrides{
		Added: map[string]string{"work.example.com": "business"},
	})
	if empty != saasFeedNoOverridesSentinel {
		t.Fatalf("empty set fingerprint = %q, want the sentinel", empty)
	}
	if withOverride == empty {
		t.Fatal("an override change must move the signed taxonomy identity")
	}
	// Deterministic across recomputation (a node-independent identity).
	again := saasFeedOverridesFingerprint(catoverride.Overrides{
		Added: map[string]string{"work.example.com": "business"},
	})
	if again != withOverride {
		t.Fatal("override fingerprint must be deterministic")
	}
}
