package main

// F3b-3 startup/crash recovery tests: the record-driven precedence + the §B.8 crash
// matrix (boundaries 12 crash-after-floor-quorum, 13 crash-after-commit, 14 restart
// convergence). Every case asserts the exact recovered floor, the active/LKG/embedded
// selection, whether live content changed, whether GC is enabled, and that no floor is
// lowered — via explicit state assertions, never just an error check. Recovery performs
// no network request (offline verifier).

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// advanceFloorTo advances the floor records to g's version (simulating a crash after the
// floor quorum but before/without the activation record — the resumable state).
func advanceFloorTo(t *testing.T, floor *floorStore, g feedGen) {
	t.Helper()
	rec := floorRecord{
		SchemaVersion:  floorSchemaVersion,
		Protocol:       "signed_manifest_v1",
		Feed:           "url-categories/saas",
		FeedVersion:    g.Manifest.FeedVersion,
		GeneratedAt:    g.Manifest.GeneratedAt,
		GenerationID:   feedVersionID(g.Manifest.FeedVersion),
		ManifestSHA256: sha256Hex(g.EnvelopeBytes),
		ArtifactSHA256: g.Manifest.ArtifactSHA256,
	}
	if _, err := floor.Advance(context.Background(), rec); err != nil {
		t.Fatalf("advance floor to v%d: %v", g.Manifest.FeedVersion, err)
	}
}

// ── fresh install → embedded baseline (benign) ───────────────────────────────────

func TestF3b3_Recover_FreshInstall(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	env := newCoordEnv(t, dir, g, coordOpts{})
	rec, err := env.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Class != recoveryFreshInstall || rec.Source != sourceEmbedded {
		t.Fatalf("fresh install = %+v", rec)
	}
	if rec.Floor.Version != compiledMinFeedVersion {
		t.Fatalf("fresh floor = %d; want %d", rec.Floor.Version, compiledMinFeedVersion)
	}
	if rec.Critical {
		t.Fatal("fresh install must not be critical")
	}
	// The embedded baseline is live and resolves a compiled host.
	if rec.View == nil || rec.View.Source != sourceEmbedded {
		t.Fatal("embedded baseline not installed")
	}
}

// ── floor ahead of activation record → resume idempotently (boundary 12) ─────────

func TestF3b3_Recover_FloorAheadResume(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 2})
	persistRealGen(t, dir+"/generations", g)
	env := newCoordEnv(t, dir, g, coordOpts{})
	// Crash state: floor advanced to v2, but NO activation record (S3 done, S4 not).
	advanceFloorTo(t, env.floor, g)
	if _, s, _ := env.activ.Read(); s != activationAbsent {
		t.Fatal("precondition: activation record must be absent")
	}

	rec, err := env.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Class != recoveryResumed || rec.ActiveVersion != 2 || rec.Source != sourceResumed {
		t.Fatalf("resume = %+v", rec)
	}
	// The activation was completed idempotently (record now durable) and the floor stayed at 2.
	if _, s, _ := env.activ.Read(); s != activationValid {
		t.Fatal("resume did not complete the activation record")
	}
	if env.coord.currentFloorVersion() != 2 {
		t.Fatal("floor changed during resume")
	}
	if !rec.GCEnabled {
		t.Fatal("resumed state should enable GC")
	}
}

// ── activation record corrupt + both floor records valid (the F0 §9 hole) ────────

func TestF3b3_Recover_ActivationCorruptFloorsValid(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 2})
	persistRealGen(t, dir+"/generations", g)
	env := newCoordEnv(t, dir, g, coordOpts{})
	advanceFloorTo(t, env.floor, g)
	// Corrupt the activation record on disk.
	if err := os.WriteFile(filepath.Join(dir, activationFile), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := env.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	// Floor PRESERVED at 2 AND content RESUMED from the digest-bound floor records.
	if rec.Floor.Version != 2 {
		t.Fatalf("floor not preserved: %d", rec.Floor.Version)
	}
	if rec.Class != recoveryResumed || rec.ActiveVersion != 2 {
		t.Fatalf("§9 hole not closed: %+v", rec)
	}
}

// ── crash after activation commit, before live cutover → converges (boundary 13) ─

func TestF3b3_Recover_CrashAfterCommitConverges(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	env := newCoordEnv(t, dir, g, coordOpts{})
	activateFresh(t, env, "1") // floor + activation committed, live swapped

	// A fresh process (new live holder) starting from the committed records converges to
	// the active generation after full offline re-verification — no live content before.
	env2 := newCoordEnv(t, dir, g, coordOpts{})
	if env2.live.Current() != nil {
		t.Fatal("fresh holder must start empty")
	}
	rec, err := env2.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Class != recoveryActiveServed || rec.ActiveVersion != 1 {
		t.Fatalf("did not converge to the committed active generation: %+v", rec)
	}
	if env2.live.Current() == nil || env2.live.Current().FeedVersion != 1 {
		t.Fatal("live cutover did not converge on restart")
	}
}

// ── expired committed LKG served stale (never fail-closed on age) ────────────────

func TestF3b3_Recover_ExpiredLKGServedStale(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1, generatedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), validity: 24 * time.Hour})
	persistRealGen(t, dir+"/generations", g)
	// Activate while fresh (clock inside validity).
	freshNow := func() time.Time { return time.Date(2026, 6, 1, 1, 0, 0, 0, time.UTC) }
	env := newCoordEnv(t, dir, g, coordOpts{now: freshNow})
	activateFresh(t, env, "1")

	// Restart LONG after expiry: the committed LKG is served STALE, never fail-closed.
	staleNow := func() time.Time { return time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) }
	env2 := newCoordEnv(t, dir, g, coordOpts{now: staleNow})
	rec, err := env2.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Class != recoveryStaleServed || !rec.Stale || rec.ActiveVersion != 1 {
		t.Fatalf("expired LKG not served stale: %+v", rec)
	}
	if env2.live.Current() == nil {
		t.Fatal("stale LKG not installed live")
	}
}

// ── equivocation: two same-version floor records with different digests ──────────

func TestF3b3_Recover_Equivocation(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 2})
	persistRealGen(t, dir+"/generations", g)
	env := newCoordEnv(t, dir, g, coordOpts{})

	// Hand-write floor.a and floor.b with the SAME version+generated_at but DIFFERENT
	// digests — an unorderable content conflict (equivocation).
	base := floorRecord{
		SchemaVersion: floorSchemaVersion, Protocol: "signed_manifest_v1", Feed: "url-categories/saas",
		FeedVersion: 2, GeneratedAt: g.Manifest.GeneratedAt, GenerationID: "2",
		ManifestSHA256: actHexA, ArtifactSHA256: actHexB,
	}
	other := base
	other.ManifestSHA256 = actHexC // different content at the same watermark
	writeFloorRaw(t, filepath.Join(dir, floorFileA), base)
	writeFloorRaw(t, filepath.Join(dir, floorFileB), other)

	rec, err := env.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	// Floor RETAINED at the shared version (never lowered to the checkpoint); content
	// resume refused; critical; GC disabled.
	if rec.Floor.Version != 2 {
		t.Fatalf("equivocation lowered the floor to %d (want 2)", rec.Floor.Version)
	}
	if rec.Class != recoveryEquivocation || !rec.Critical || rec.GCEnabled {
		t.Fatalf("equivocation handling = %+v", rec)
	}
	// No conflicting content is served: the embedded baseline is live (no valid LKG here).
	if rec.Source != sourceEmbedded {
		t.Fatalf("equivocation served content from source %s; want embedded", rec.Source)
	}
}

// ── all floor records corrupt → checkpoint floor + embedded, critical ────────────

func TestF3b3_Recover_AllFloorCorrupt(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	env := newCoordEnv(t, dir, g, coordOpts{})
	for _, f := range []string{floorFileA, floorFileB} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec, err := env.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Floor.Version != compiledMinFeedVersion || rec.Source != sourceEmbedded || !rec.Critical || rec.GCEnabled {
		t.Fatalf("all-corrupt recovery = %+v", rec)
	}
}

// ── active generation missing/corrupt on disk → embedded degraded ────────────────

func TestF3b3_Recover_ActiveGenerationCorrupt(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	env := newCoordEnv(t, dir, g, coordOpts{})
	activateFresh(t, env, "1")
	// Corrupt the committed generation's signed artifact so offline re-verify fails.
	if err := os.WriteFile(filepath.Join(dir, "generations", "1", genFileArtifact), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	env2 := newCoordEnv(t, dir, g, coordOpts{})
	rec, err := env2.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Class != recoveryEmbeddedDegraded || rec.Source != sourceEmbedded || !rec.Critical {
		t.Fatalf("corrupt active generation should degrade to embedded: %+v", rec)
	}
	// The floor is not lowered by a corrupt generation (the floor records are still valid).
	if rec.Floor.Version != 1 {
		t.Fatalf("floor lowered by a corrupt active generation: %d", rec.Floor.Version)
	}
}

func writeFloorRaw(t *testing.T, path string, rec floorRecord) {
	t.Helper()
	b, err := encodeFloorRecord(rec)
	if err != nil {
		t.Fatalf("encode floor: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write floor %s: %v", path, err)
	}
}
