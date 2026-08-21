package urlcat

import (
	"reflect"
	"testing"
)

// These tests pin the AddHost incremental index fold (addHostToIndexes)
// against the wholesale rebuild it replaces. Ported from the competing
// PR #1171 implementation (its Codex P1: a per-host wholesale rebuild during
// the SaaS feed merge loop stalls the request path once per added host) and
// adapted to the eager patternRef index that shipped here.

// freshEntries builds a small mixed taxonomy for the fold tests.
func freshEntries() []*Entry {
	return []*Entry{
		{Name: "Alpha", BuiltIn: true, Hosts: []string{"alpha.example", "shared.example"}},
		{Name: "Beta", BuiltIn: false, Hosts: []string{"beta.example"}},
		{Name: "Gamma", BuiltIn: false, Hosts: []string{"gamma.example", "late.example"}},
	}
}

// cloneEntries deep-copies so the rebuilt reference store cannot alias the
// incrementally-maintained one.
func cloneEntries(in []*Entry) []*Entry {
	out := make([]*Entry, len(in))
	for i, e := range in {
		hosts := append([]string(nil), e.Hosts...)
		out[i] = &Entry{Name: e.Name, Hosts: hosts, BuiltIn: e.BuiltIn}
	}
	return out
}

// TestAddHost_IncrementalMatchesRebuild drives a sequence of AddHost calls
// through the incremental fold and asserts every lookup surface agrees with a
// store rebuilt wholesale from the identical final entries.
func TestAddHost_IncrementalMatchesRebuild(t *testing.T) {
	s := New(freshEntries())
	adds := []struct{ cat, host string }{
		{"Alpha", "new-a.example"},
		{"Beta", "shared.example"}, // duplicate pattern, later entry: Alpha must keep the win
		{"Gamma", "beta.example"},  // duplicate of an earlier admin entry
		{"Beta", "b2.example"},
		{"Alpha", "late.example"}, // earlier entry now claims a pattern a later entry held
	}
	for _, a := range adds {
		if err := s.AddHost(a.cat, a.host); err != nil {
			t.Fatalf("AddHost(%s,%s): %v", a.cat, a.host, err)
		}
	}

	s.mu.RLock()
	ref := New(cloneEntries(s.entries))
	s.mu.RUnlock()
	probes := []string{
		"alpha.example", "shared.example", "beta.example", "gamma.example",
		"late.example", "new-a.example", "b2.example", "sub.late.example",
		"deep.sub.shared.example", "unrelated.invalid",
	}
	for _, h := range probes {
		gc, gm, gok := s.LookupHost(h)
		wc, wm, wok := ref.LookupHost(h)
		if gc != wc || gm != wm || gok != wok {
			t.Fatalf("LookupHost(%q): incremental (%q,%q,%v) != rebuild (%q,%q,%v)", h, gc, gm, gok, wc, wm, wok)
		}
		ga, gma, goka := s.LookupHostAdmin(h)
		wa, wma, woka := ref.LookupHostAdmin(h)
		if ga != wa || gma != wma || goka != woka {
			t.Fatalf("LookupHostAdmin(%q): incremental (%q,%q,%v) != rebuild (%q,%q,%v)", h, ga, gma, goka, wa, wma, woka)
		}
		for _, cat := range []Category{"Alpha", "Beta", "Gamma"} {
			if got, want := s.MatchesHost(cat, h), ref.MatchesHost(cat, h); got != want {
				t.Fatalf("MatchesHost(%s,%q): incremental %v != rebuild %v", cat, h, got, want)
			}
			if got, want := s.MatchesHostAdmin(cat, h), ref.MatchesHostAdmin(cat, h); got != want {
				t.Fatalf("MatchesHostAdmin(%s,%q): incremental %v != rebuild %v", cat, h, got, want)
			}
		}
	}
}

// TestAddHost_IncrementalKeepsScanPrecedence pins the load-bearing invariant:
// the winner stays the FIRST (entry, host) position in scan order, in both
// directions an append can land relative to an existing duplicate pattern.
func TestAddHost_IncrementalKeepsScanPrecedence(t *testing.T) {
	s := New(freshEntries())

	// Append a duplicate of an EARLIER entry's pattern to a LATER entry: the
	// earlier declaration must keep the win.
	if err := s.AddHost("Gamma", "alpha.example"); err != nil {
		t.Fatal(err)
	}
	if cat, _, ok := s.LookupHost("alpha.example"); !ok || cat != "Alpha" {
		t.Fatalf("later duplicate stole the win: got (%q,%v), want Alpha", cat, ok)
	}

	// Append to an EARLIER entry a pattern only a LATER entry held: the new,
	// earlier position must now win — exactly what a wholesale rebuild yields.
	if cat, _, ok := s.LookupHost("late.example"); !ok || cat != "Gamma" {
		t.Fatalf("precondition: late.example should start at Gamma, got (%q,%v)", cat, ok)
	}
	if err := s.AddHost("Alpha", "late.example"); err != nil {
		t.Fatal(err)
	}
	if cat, _, ok := s.LookupHost("late.example"); !ok || cat != "Alpha" {
		t.Fatalf("earlier append did not take the win: got (%q,%v), want Alpha", cat, ok)
	}
}

// TestAddHost_DoesNotRebuildWholeIndex pins the O(one category) bound
// structurally: appending a host to one category must not reallocate the
// forward sets of untouched categories (a wholesale rebuild replaces every
// inner map), and must not mutate the previously-published set of the touched
// category in place (MatchesHost probes that set outside the lock).
func TestAddHost_DoesNotRebuildWholeIndex(t *testing.T) {
	s := New(freshEntries())

	s.mu.RLock()
	alphaBefore := reflect.ValueOf(s.index["alpha"]).Pointer()
	betaBefore := reflect.ValueOf(s.index["beta"]).Pointer()
	gammaBefore := reflect.ValueOf(s.index["gamma"]).Pointer()
	s.mu.RUnlock()

	if err := s.AddHost("Beta", "brand-new.example"); err != nil {
		t.Fatal(err)
	}

	s.mu.RLock()
	alphaAfter := reflect.ValueOf(s.index["alpha"]).Pointer()
	betaAfter := reflect.ValueOf(s.index["beta"]).Pointer()
	gammaAfter := reflect.ValueOf(s.index["gamma"]).Pointer()
	s.mu.RUnlock()

	if alphaAfter != alphaBefore || gammaAfter != gammaBefore {
		t.Fatal("AddHost reallocated untouched categories' sets — it is rebuilding wholesale again")
	}
	if betaAfter == betaBefore {
		t.Fatal("AddHost mutated the touched category's published set in place — MatchesHost probes it outside the lock (clone-and-swap required)")
	}
}
