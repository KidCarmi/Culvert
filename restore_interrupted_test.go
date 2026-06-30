package main

// restore_interrupted_test.go — RISK-005: the boot-time guard
// checkInterruptedRestore refuses to start on a data dir left missing by a
// restore commit that was killed mid-rename, so the process never silently
// boots on an empty data dir and loses the operator's data.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dataDir present → no-op (normal boot).
func TestCheckInterruptedRestore_DataDirPresent(t *testing.T) {
	parent := t.TempDir()
	dataDir := seedDataDir(t, parent)
	// A stray .bak sibling must NOT matter while dataDir exists.
	makeDir(t, parent, leftoverName("bak", time.Unix(1_700_000_000, 0), 1234))

	if err := checkInterruptedRestore(dataDir); err != nil {
		t.Fatalf("present dataDir must boot cleanly, got: %v", err)
	}
}

// dataDir absent + no .bak sibling → genuine fresh install → no-op.
func TestCheckInterruptedRestore_FreshInstall(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "data") // never created

	if err := checkInterruptedRestore(dataDir); err != nil {
		t.Fatalf("fresh install must boot cleanly, got: %v", err)
	}
}

// dataDir absent + .bak sibling present → refuse to boot, name the revert move.
func TestCheckInterruptedRestore_BakOnly(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "data") // absent (renamed aside, commit killed)
	bak := makeDir(t, parent, leftoverName("bak", time.Unix(1_700_000_000, 0), 4242))

	err := checkInterruptedRestore(dataDir)
	if err == nil {
		t.Fatal("expected refusal to boot when dataDir is missing and a .bak exists")
	}
	msg := err.Error()
	if !strings.Contains(msg, "interrupted restore detected") {
		t.Errorf("error must name the condition: %v", msg)
	}
	if !strings.Contains(msg, bak) || !strings.Contains(msg, "mv") {
		t.Errorf("error must give an actionable `mv <bak> <dataDir>` recovery: %v", msg)
	}
}

// dataDir absent + correlated .bak AND .staging → both recovery options named.
func TestCheckInterruptedRestore_BakAndStaging(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "data")
	ts := time.Unix(1_700_000_500, 0)
	bak := makeDir(t, parent, leftoverName("bak", ts, 777))
	staging := makeDir(t, parent, leftoverName("staging", ts, 777))

	err := checkInterruptedRestore(dataDir)
	if err == nil {
		t.Fatal("expected refusal to boot")
	}
	msg := err.Error()
	if !strings.Contains(msg, bak) {
		t.Errorf("error must offer REVERT via the .bak: %v", msg)
	}
	if !strings.Contains(msg, staging) {
		t.Errorf("error must offer COMPLETE via the .staging: %v", msg)
	}
}

// dataDir absent + a lone .staging (no .bak) → NOT the RISK-005 state; the
// previous data was never moved aside, so don't block boot.
func TestCheckInterruptedRestore_StagingOnlyDoesNotBlock(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "data")
	makeDir(t, parent, leftoverName("staging", time.Unix(1_700_000_900, 0), 9))

	if err := checkInterruptedRestore(dataDir); err != nil {
		t.Fatalf("a lone staging dir (no .bak) must not block boot, got: %v", err)
	}
}

// When multiple .bak generations exist (repeated failed restores), the guard
// points at the NEWEST one.
func TestCheckInterruptedRestore_PicksNewestBak(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "data")
	makeDir(t, parent, leftoverName("bak", time.Unix(1_700_000_000, 0), 1))
	newest := makeDir(t, parent, leftoverName("bak", time.Unix(1_700_009_999, 0), 2))

	err := checkInterruptedRestore(dataDir)
	if err == nil {
		t.Fatal("expected refusal to boot")
	}
	if !strings.Contains(err.Error(), newest) {
		t.Errorf("guard must point at the newest .bak %q, got: %v", newest, err.Error())
	}
}
