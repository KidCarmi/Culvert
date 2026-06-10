package main

import (
	"sort"
	"testing"
)

// Rate-limit exemptions are configurable, locally rollback-able, and
// restart-durable, but were never carried in the CP→DP ConfigSnapshot — so in
// a cluster, exemptions set on the control plane were silently not enforced on
// data-plane nodes. These tests pin the capture/apply round-trip and the
// nil→skip / []→clear convention shared with the config-version rollback
// surface.

func snapshotRLExemptions(t *testing.T) {
	t.Helper()
	orig := rl.ListExemptions()
	t.Cleanup(func() { rl.ReplaceExemptions(orig) })
	rl.ReplaceExemptions(nil) // clean baseline
}

func TestCurrentConfigSnapshot_CapturesRateLimitExempt(t *testing.T) {
	snapshotRLExemptions(t)
	if err := rl.AddExemption("203.0.113.7"); err != nil {
		t.Fatalf("AddExemption: %v", err)
	}
	if err := rl.AddExemption("198.51.100.0/24"); err != nil {
		t.Fatalf("AddExemption CIDR: %v", err)
	}

	got := CurrentConfigSnapshot().RateLimitExempt
	sort.Strings(got)
	want := []string{"198.51.100.0/24", "203.0.113.7"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("snapshot RateLimitExempt = %v, want %v", got, want)
	}
}

func TestApplyConfigSnapshot_ReplacesRateLimitExempt(t *testing.T) {
	snapshotRLExemptions(t)
	// Pre-existing exemption that the snapshot does NOT contain — apply must
	// replace, not merge, so this one goes away.
	if err := rl.AddExemption("192.0.2.50"); err != nil {
		t.Fatalf("AddExemption: %v", err)
	}

	applyConfigSnapshot(ConfigSnapshot{Version: 1, RateLimitExempt: []string{"203.0.113.9"}})

	if !rl.IsExempt("203.0.113.9") {
		t.Error("203.0.113.9 should be exempt after apply")
	}
	if rl.IsExempt("192.0.2.50") {
		t.Error("192.0.2.50 should have been replaced (apply must not merge)")
	}
}

func TestApplyConfigSnapshot_RateLimitExemptNilSkipsEmptyClears(t *testing.T) {
	snapshotRLExemptions(t)
	if err := rl.AddExemption("203.0.113.11"); err != nil {
		t.Fatalf("AddExemption: %v", err)
	}

	// nil → skip: a snapshot from an older CP (field absent) must not wipe.
	applyConfigSnapshot(ConfigSnapshot{Version: 2, RateLimitExempt: nil})
	if !rl.IsExempt("203.0.113.11") {
		t.Error("nil RateLimitExempt must leave existing exemptions intact (skip)")
	}

	// [] → clear: an explicit empty list wipes the whitelist.
	applyConfigSnapshot(ConfigSnapshot{Version: 3, RateLimitExempt: []string{}})
	if rl.IsExempt("203.0.113.11") {
		t.Error("empty RateLimitExempt must clear exemptions")
	}
}

func TestValidateConfigSnapshot_RejectsRateLimitExemptOverflow(t *testing.T) {
	snap := ConfigSnapshot{RateLimitExempt: make([]string, maxSnapRateLimitExempt+1)}
	if err := validateConfigSnapshot(snap); err == nil {
		t.Fatal("validateConfigSnapshot accepted an over-cap RateLimitExempt")
	}
}
