package main

import (
	"context"
	"testing"
)

// TestF3b3Probe_ActivateThenRecover de-risks the full F3b-3 wiring: persist a real
// generation, activate it (floor + activation record + live cutover), then simulate a
// restart (fresh coordinator over the same on-disk state) and prove recovery re-verifies
// and serves the committed active generation.
func TestF3b3Probe_ActivateThenRecover(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)

	env := newCoordEnv(t, dir, g, coordOpts{})
	res, err := env.coord.Activate(context.Background(), activateInput{
		GenerationID: "1", Provenance: activationProvenanceDownloaded,
	})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if res.Outcome != activationCommitted || res.Version != 1 {
		t.Fatalf("activate outcome=%s version=%d", res.Outcome, res.Version)
	}
	// The live view is the composed feed snapshot; a feed host resolves.
	live := env.live.Current()
	if live == nil || live.FeedVersion != 1 || live.Source != sourceDownloaded {
		t.Fatalf("live view = %+v", live)
	}
	if cat, ok := live.LookupHost("chat.example"); !ok || cat != "ai" {
		t.Fatalf("lookup chat.example = %q,%v; want ai,true", cat, ok)
	}
	// The floor advanced to v1; the activation record is durable.
	if fv := env.coord.currentFloorVersion(); fv != 1 {
		t.Fatalf("floor version = %d; want 1", fv)
	}

	// Restart: a fresh coordinator over the same on-disk records recovers by re-verifying.
	env2 := newCoordEnv(t, dir, g, coordOpts{})
	rec, err := env2.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Class != recoveryActiveServed || rec.ActiveVersion != 1 || rec.Source != sourceCached {
		t.Fatalf("recover = %+v", rec)
	}
	if rec.View == nil || func() bool { c, ok := rec.View.LookupHost("api.example.ai"); return !ok || c != "ai" }() {
		t.Fatal("recovered view missing feed host")
	}
	if !rec.GCEnabled || rec.Critical {
		t.Fatalf("healthy recovery should have GC enabled, non-critical: %+v", rec)
	}
}
