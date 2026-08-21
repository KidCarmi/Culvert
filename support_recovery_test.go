package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/support"
)

// TestRecoveryBundle_L0BuildsOfflineWithNoFailedSections is the recovery-mode
// wall (M5 PR-E). `culvert --support-bundle <path>` runs headless in
// handleOneShotCommands (main.go) BEFORE any init* — no server, no DB, no CP
// client, no loaded CA. This pins that the L0 recovery bundle STILL builds a
// valid bundle with ZERO failed sections in that state, so the "GUI is down"
// escape hatch never degrades to an abort or a wall of failed sections.
//
// The test binary is itself a faithful recovery environment for the dependency
// class the handoff worries about: anything a collector would reach that is
// wired in an init* / startup path (the badger DB, the CP gRPC client, live
// server state) is nil/unstarted here exactly as it is in the one-shot, so a
// future collector that assumes such a live subsystem fails its section and
// trips this wall. Package-init singletons (certMgr, globalThreatFeed, …) are
// non-nil but UNCONFIGURED in both worlds, and the L0 collectors already read
// them as empty-but-valid — which is why the recovery bundle is clean today.
func TestRecoveryBundle_L0BuildsOfflineWithNoFailedSections(t *testing.T) {
	res, err := buildSupportBundle(context.Background(), support.L0, "standard", "")
	if err != nil {
		t.Fatalf("recovery (L0) bundle build must succeed headless: %v", err)
	}

	// No section may FAIL: the recovery escape hatch must degrade to ok/skipped,
	// never a failed/panicked collector (the runner isolates panics, but a
	// failed mandatory section is exactly the regression this wall guards).
	for i := range res.Manifest.Sections {
		s := res.Manifest.Sections[i]
		if s.Status == support.StatusFailed {
			t.Errorf("L0 recovery section %q failed (note=%q) — a collector is assuming a live subsystem", s.ID, s.Note)
		}
	}
	if res.Manifest.Collection.Failed != 0 {
		t.Fatalf("recovery bundle had %d failed section(s); L0 must be fully offline-safe", res.Manifest.Collection.Failed)
	}

	// The mandatory L0 sections must be present AND ok — an offline reader relies
	// on product/health/readiness to triage a node whose GUI is down.
	wantOK := map[string]bool{"product": false, "health": false, "readiness": false}
	for i := range res.Manifest.Sections {
		s := res.Manifest.Sections[i]
		if _, want := wantOK[s.ID]; !want {
			continue
		}
		if s.Status != support.StatusOK {
			t.Errorf("mandatory L0 section %q status=%q, want ok", s.ID, s.Status)
		}
		wantOK[s.ID] = true
	}
	for id, seen := range wantOK {
		if !seen {
			t.Errorf("mandatory L0 section %q missing from the recovery bundle", id)
		}
	}
}

// TestRecoveryBundle_HeadlessCommandWritesValidBundle drives the actual one-shot
// entrypoint (runSupportBundleCommand) end to end and asserts it writes a
// non-empty, well-formed gzip bundle to the target path with no live server.
func TestRecoveryBundle_HeadlessCommandWritesValidBundle(t *testing.T) {
	out := filepath.Join(t.TempDir(), "recovery-bundle.tar.gz")
	if err := runSupportBundleCommand(out); err != nil {
		t.Fatalf("runSupportBundleCommand headless: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read written bundle: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("recovery bundle is empty")
	}
	// gzip magic — the bundle is a .tar.gz.
	if !bytes.HasPrefix(b, []byte{0x1f, 0x8b}) {
		t.Fatalf("recovery bundle is not gzip (first bytes %x)", b[:min(4, len(b))])
	}
	// Written 0600 (secret hygiene — same as the API-side persisted bundle).
	if fi, err := os.Stat(out); err == nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("recovery bundle mode = %v, want 0600", fi.Mode().Perm())
	}
}
