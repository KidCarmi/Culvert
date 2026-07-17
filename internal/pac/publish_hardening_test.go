package pac

// publish_hardening_test.go — Palo review round-2 coverage: private→direct
// confirmation gating, revision-history cap, and glob-matcher DoS resistance.

import (
	"strings"
	"testing"
)

func hardeningPools() map[string]Pool {
	return map[string]Pool{"main": {ID: "main", Name: "Main", Endpoints: []PoolEndpoint{{Host: "p1.example", Port: 8080}}}}
}

func TestEvaluatePublish_PrivateDirectRequiresConfirmation(t *testing.T) {
	pools := hardeningPools()
	active := Profile{ID: "hq", Name: "HQ", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateProxy}
	// Flip private-networks proxy→direct: a new-DIRECT vector that must gate.
	draft := Profile{ID: "hq", Name: "HQ", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateDirect}

	chk := EvaluatePublish(draft, pools, active, true)
	if !chk.RequiresConfirmation {
		t.Fatalf("private→direct flip must require typed confirmation: %+v", chk)
	}
	found := false
	for _, p := range chk.NewDirectPaths {
		if strings.Contains(p, "private-networks=direct") {
			found = true
		}
	}
	if !found {
		t.Errorf("new-DIRECT list should name the private-networks flip: %v", chk.NewDirectPaths)
	}

	// Secure mode must NOT flag it (secure neutralizes DIRECT).
	sec := draft
	sec.AvailabilityMode = ModeSecure
	if EvaluatePublish(sec, pools, active, true).RequiresConfirmation {
		t.Error("secure mode must not require private-direct confirmation (DIRECT is neutralized)")
	}

	// Already-private-direct active → no NEW direct path on republish.
	activeDirect := active
	activeDirect.PrivateNetworks = PrivateDirect
	if EvaluatePublish(draft, pools, activeDirect, true).RequiresConfirmation {
		t.Error("no new DIRECT when the active revision was already private-direct")
	}
}

func TestProfileLifecycle_RevisionHistoryCapped(t *testing.T) {
	lc := &ProfileLifecycle{ProfileID: "hq"}
	spec := Profile{ID: "hq", Name: "HQ", PoolID: "main", AvailabilityMode: ModeBalanced}
	for i := 0; i < maxRevisionsPerProfile+25; i++ {
		lc.Publish(spec, "digest", "actor", "", "ts")
	}
	if len(lc.Revisions) != maxRevisionsPerProfile {
		t.Fatalf("history should be capped at %d, got %d", maxRevisionsPerProfile, len(lc.Revisions))
	}
	// Numbers stay monotonic and the newest is preserved (oldest dropped).
	last := lc.Revisions[len(lc.Revisions)-1].N
	if last != int64(maxRevisionsPerProfile+25) {
		t.Errorf("newest revision N should be %d, got %d", maxRevisionsPerProfile+25, last)
	}
	if lc.ActiveN != last {
		t.Errorf("ActiveN should track the newest revision, got %d", lc.ActiveN)
	}
	if lc.nextRevisionN() != last+1 {
		t.Errorf("nextRevisionN must stay monotonic after trimming: got %d want %d", lc.nextRevisionN(), last+1)
	}
}

func TestGlobMatch_NoCatastrophicBacktracking(t *testing.T) {
	// A pathological pattern that would explode under naive per-star recursion.
	// The linear matcher must return promptly (this test would hang/OOM if the
	// exponential implementation regressed).
	pattern := strings.Repeat("*a", 40) + "*b"
	s := strings.Repeat("a", 80)
	if globMatch(pattern, s) {
		t.Error("no trailing 'b' — pattern must NOT match")
	}
	// Sanity: correctness on ordinary globs.
	cases := []struct {
		pat, in string
		want    bool
	}{
		{"*.example", "a.example", true},
		{"*.example", "example", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"*", "anything", true},
		{"cdn.*.example", "cdn.eu.example", true},
		{"cdn.*.example", "cdn.example", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.in); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pat, c.in, got, c.want)
		}
	}
}
