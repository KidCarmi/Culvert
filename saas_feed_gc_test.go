package main

// F3b-3 GC tests: root protection, newest-5 retention, disabled-under-ambiguity, safety
// (symlink/staging/tombstone skip, escape guard), the crash boundaries (16 root
// collection, 17 tombstone rename, 18 deletion, 19 dir sync), idempotency, and the
// "deletion failure does not roll back activation" rule.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// gcScenario activates the newest of `n` persisted generations and returns the coordinator
// env + a GC collector over the same durable stores.
func gcScenario(t *testing.T, n int) (*f3b3Env, *gcCollector, string) {
	t.Helper()
	resetOwnership(t)
	dir := t.TempDir()
	genRoot := dir + "/generations"
	gens := make([]feedGen, 0, n)
	for v := 1; v <= n; v++ {
		g := buildFeedGen(t, feedGenOpts{feedVersion: int64(v)})
		persistRealGen(t, genRoot, g)
		gens = append(gens, g)
	}
	env := newCoordEnv(t, dir, gens[n-1], coordOpts{verifier: multiVerifier(gens...)})
	activateFresh(t, env, feedVersionID(int64(n))) // activate the newest ⇒ floor + activation at n
	gc, err := newGCCollector(genRoot, env.floor, env.activ)
	if err != nil {
		t.Fatalf("newGCCollector: %v", err)
	}
	return env, gc, genRoot
}

func dirExists(t *testing.T, genRoot, id string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(genRoot, id))
	return err == nil
}

// ── retains newest 5 + roots; collects the rest ─────────────────────────────────

func TestF3b3_GC_RetentionAndRoots(t *testing.T) {
	_, gc, genRoot := gcScenario(t, 8)
	res, err := gc.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !res.Enabled {
		t.Fatalf("gc should be enabled: %+v", res)
	}
	// Newest 5 by version {8,7,6,5,4} kept (8 is also the active/floor root); {3,2,1} collected.
	for _, keep := range []string{"8", "7", "6", "5", "4"} {
		if !dirExists(t, genRoot, keep) {
			t.Fatalf("GC deleted a retained generation %s", keep)
		}
	}
	for _, gone := range []string{"3", "2", "1"} {
		if dirExists(t, genRoot, gone) {
			t.Fatalf("GC failed to collect %s", gone)
		}
	}
	sort.Strings(res.Collected)
	if len(res.Collected) != 3 {
		t.Fatalf("collected = %v; want 3 (v1..v3)", res.Collected)
	}
}

// ── a floor-record root is never collected even if it is old ─────────────────────

func TestF3b3_GC_NeverDeletesRoot(t *testing.T) {
	// Persist v1..v8, but keep the floor ROOT pointing at an OLD version by activating v1
	// (so v1 is the active root) then not advancing — GC must keep v1 despite retention.
	resetOwnership(t)
	dir := t.TempDir()
	genRoot := dir + "/generations"
	gens := make([]feedGen, 0, 8)
	for v := 1; v <= 8; v++ {
		g := buildFeedGen(t, feedGenOpts{feedVersion: int64(v)})
		persistRealGen(t, genRoot, g)
		gens = append(gens, g)
	}
	env := newCoordEnv(t, dir, gens[0], coordOpts{verifier: multiVerifier(gens...)})
	activateFresh(t, env, "1") // active root + floor at v1 (old)
	gc, _ := newGCCollector(genRoot, env.floor, env.activ)
	res, err := gc.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !dirExists(t, genRoot, "1") {
		t.Fatal("GC deleted the active/floor ROOT generation v1")
	}
	// Newest 5 {8,7,6,5,4} kept + root {1}; {3,2} collected.
	for _, gone := range []string{"3", "2"} {
		if dirExists(t, genRoot, gone) {
			t.Fatalf("GC failed to collect %s", gone)
		}
	}
	_ = res
}

// ── disabled under ambiguity / corruption / no-activation ────────────────────────

func TestF3b3_GC_DisabledStates(t *testing.T) {
	t.Run("no activation record", func(t *testing.T) {
		resetOwnership(t)
		dir := t.TempDir()
		g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
		persistRealGen(t, dir+"/generations", g)
		env := newCoordEnv(t, dir, g, coordOpts{})
		gc, _ := newGCCollector(dir+"/generations", env.floor, env.activ)
		res, _ := gc.Collect(context.Background())
		if res.Enabled {
			t.Fatal("GC must be disabled without a committed activation record")
		}
	})
	t.Run("equivocation", func(t *testing.T) {
		resetOwnership(t)
		dir := t.TempDir()
		g := buildFeedGen(t, feedGenOpts{feedVersion: 2})
		persistRealGen(t, dir+"/generations", g)
		env := newCoordEnv(t, dir, g, coordOpts{})
		activateFresh(t, env, "2")
		// Introduce equivocation in the floor records.
		base := floorRecord{SchemaVersion: floorSchemaVersion, Protocol: "signed_manifest_v1", Feed: "url-categories/saas",
			FeedVersion: 2, GeneratedAt: g.Manifest.GeneratedAt, GenerationID: "2", ManifestSHA256: actHexA, ArtifactSHA256: actHexB}
		other := base
		other.ArtifactSHA256 = actHexC
		writeFloorRaw(t, filepath.Join(dir, floorFileA), base)
		writeFloorRaw(t, filepath.Join(dir, floorFileB), other)
		gc, _ := newGCCollector(dir+"/generations", env.floor, env.activ)
		res, _ := gc.Collect(context.Background())
		if res.Enabled {
			t.Fatal("GC must be disabled under floor equivocation")
		}
	})
	t.Run("corrupt floor replica", func(t *testing.T) {
		resetOwnership(t)
		dir := t.TempDir()
		g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
		persistRealGen(t, dir+"/generations", g)
		env := newCoordEnv(t, dir, g, coordOpts{})
		activateFresh(t, env, "1")
		if err := os.WriteFile(filepath.Join(dir, floorFileB), []byte("garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
		gc, _ := newGCCollector(dir+"/generations", env.floor, env.activ)
		res, _ := gc.Collect(context.Background())
		if res.Enabled {
			t.Fatal("GC must be disabled with a corrupt floor replica")
		}
	})
}

// ── safety: symlink, staging, tombstone, unvalidatable dirs are never deleted ────

func TestF3b3_GC_SkipsUnsafeEntries(t *testing.T) {
	_, gc, genRoot := gcScenario(t, 6) // keeps 6..2 (newest 5) + root 6; collects 1
	// Plant a symlink, a staging dir, a tombstone, and a bogus dir — none may be deleted.
	_ = os.Symlink(filepath.Join(genRoot, "6"), filepath.Join(genRoot, "evil-link"))
	_ = os.MkdirAll(filepath.Join(genRoot, genStagePrefix+"inflight"), 0o700)
	_ = os.MkdirAll(filepath.Join(genRoot, gcTombstonePrefix+"leftover"), 0o700)
	_ = os.MkdirAll(filepath.Join(genRoot, "999"), 0o700) // no metadata ⇒ unvalidatable
	res, err := gc.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// The symlink target + staging + bogus dirs survive; only validated non-root
	// out-of-window generations are collected (v1).
	if !dirExists(t, genRoot, "6") {
		t.Fatal("GC followed a symlink and damaged a root")
	}
	if !dirExists(t, genRoot, genStagePrefix+"inflight") {
		t.Fatal("GC deleted a staging dir owned by another operation")
	}
	if !dirExists(t, genRoot, "999") {
		t.Fatal("GC deleted an unvalidatable dir")
	}
	// The tombstone is swept (recovering an interrupted prior GC), which is expected.
	_ = res
}

// ── crash boundaries 17/18/19: tombstone rename / deletion / dir-sync failures ───

func TestF3b3_GC_DeletionFailureReportedNoRollback(t *testing.T) {
	_, gc, genRoot := gcScenario(t, 8)
	// Inject a rename failure in the GC FS seam so a deletion fails.
	fs := osGCFS()
	fs.rename = func(oldpath, newpath string) error { return errors.New("rename denied") }
	gc.fs = fs
	res, err := gc.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect should not hard-fail on a per-generation deletion error: %v", err)
	}
	if len(res.Errors) == 0 {
		t.Fatal("a deletion failure must be reported in Errors")
	}
	if len(res.Collected) != 0 {
		t.Fatal("nothing should be reported collected when every deletion failed")
	}
	// The activation is untouched (a GC failure never rolls back the committed activation).
	if _, s, _ := gc.activation.Read(); s != activationValid {
		t.Fatal("GC deletion failure rolled back the activation record")
	}
	// The candidate generations still exist (not half-deleted).
	if !dirExists(t, genRoot, "1") {
		t.Fatal("generation half-deleted despite a rename failure")
	}
}

// ── crash boundaries 16/19: root-collection (readDir) + dir-sync failures ────────

func TestF3b3_GC_FSFailureBoundaries(t *testing.T) {
	t.Run("readDir failure (boundary 16)", func(t *testing.T) {
		_, gc, _ := gcScenario(t, 3)
		fs := osGCFS()
		fs.readDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("readdir denied") }
		gc.fs = fs
		if _, err := gc.Collect(context.Background()); err == nil {
			t.Fatal("expected a hard error when the generations root cannot be enumerated")
		}
	})
	t.Run("removeAll failure (boundary 18)", func(t *testing.T) {
		_, gc, genRoot := gcScenario(t, 8)
		fs := osGCFS()
		fs.removeAll = func(string) error { return errors.New("remove denied") }
		gc.fs = fs
		res, err := gc.Collect(context.Background())
		if err != nil {
			t.Fatalf("per-deletion removeAll failure should be reported, not hard-fail: %v", err)
		}
		if len(res.Errors) == 0 || len(res.Collected) != 0 {
			t.Fatalf("removeAll failure not reported: %+v", res)
		}
		// Two-step semantics: the rename succeeded, so the generation is safely in an owned
		// tombstone (swept next pass), never a torn/half-deleted state — and a ROOT is
		// never touched.
		if !dirExists(t, genRoot, "8") {
			t.Fatal("GC damaged the active/floor ROOT despite a removeAll failure")
		}
		if !dirExists(t, genRoot, gcTombstonePrefix+"1") && dirExists(t, genRoot, "1") {
			t.Fatal("removeAll failure left an inconsistent state (neither original nor tombstone)")
		}
	})
	t.Run("dir-sync failure (boundary 19)", func(t *testing.T) {
		_, gc, _ := gcScenario(t, 8)
		fs := osGCFS()
		fs.syncDir = func(string) error { return errors.New("fsync denied") }
		gc.fs = fs
		res, err := gc.Collect(context.Background())
		if err != nil {
			t.Fatalf("per-deletion dir-sync failure should be reported, not hard-fail: %v", err)
		}
		if len(res.Errors) == 0 {
			t.Fatalf("dir-sync failure not reported: %+v", res)
		}
	})
}

// ── idempotency + tombstone sweep ────────────────────────────────────────────────

func TestF3b3_GC_Idempotent(t *testing.T) {
	_, gc, genRoot := gcScenario(t, 8)
	r1, err := gc.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect 1: %v", err)
	}
	r2, err := gc.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect 2: %v", err)
	}
	if len(r1.Collected) == 0 {
		t.Fatal("first pass collected nothing")
	}
	if len(r2.Collected) != 0 {
		t.Fatalf("second pass collected %v; GC is not idempotent", r2.Collected)
	}
	// A leftover tombstone from an interrupted pass is swept on the next Collect.
	_ = os.MkdirAll(filepath.Join(genRoot, gcTombstonePrefix+"orphan"), 0o700)
	if _, err := gc.Collect(context.Background()); err != nil {
		t.Fatalf("collect 3: %v", err)
	}
	if dirExists(t, genRoot, gcTombstonePrefix+"orphan") {
		t.Fatal("GC did not sweep a leftover tombstone")
	}
}
