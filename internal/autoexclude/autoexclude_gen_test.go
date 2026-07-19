package autoexclude

import "testing"

// PR2: the cache fences learned exclusions to the security generation they were
// learned under. These engine tests pin the (scope, gen, host) semantics directly.

// TestContains_GenMismatchMisses — an entry learned under genA is a HIT under genA
// and a MISS under a different gen (the profile's security posture changed).
func TestContains_GenMismatchMisses(t *testing.T) {
	c := New(Config{ConfirmN: 1})
	if !c.Observe("scope", "genA", "Scope", "h.example", ReasonUnsupportedParams, "id:u1") {
		t.Fatal("confirmN=1 must promote on the first observation")
	}
	if _, ok := c.Contains("scope", "genA", "h.example"); !ok {
		t.Fatal("must hit under the SAME gen it was learned")
	}
	if _, ok := c.Contains("scope", "genB", "h.example"); ok {
		t.Fatal("must MISS under a different gen (security posture changed → re-inspect)")
	}
	// Empty gen (a non-fenced caller) must also not match a gen-fenced entry.
	if _, ok := c.Contains("scope", "", "h.example"); ok {
		t.Fatal("empty gen must not match a gen-fenced entry")
	}
}

// TestObserve_NewGenOverwritesStale — a promotion under a new gen replaces the
// stale-gen entry at (scope, host); there is exactly one active entry and only the
// new gen matches.
func TestObserve_NewGenOverwritesStale(t *testing.T) {
	c := New(Config{ConfirmN: 1})
	c.Observe("scope", "genA", "Scope", "h.example", ReasonUnsupportedParams, "id:u1")
	// A stale-gen active entry must NOT block a new-gen promotion.
	if !c.Observe("scope", "genB", "Scope", "h.example", ReasonUnsupportedParams, "id:u1") {
		t.Fatal("a stale-gen active entry must not block a new-gen promotion")
	}
	if n := c.Len(); n != 1 {
		t.Fatalf("expected exactly one active entry after overwrite, got %d", n)
	}
	if _, ok := c.Contains("scope", "genB", "h.example"); !ok {
		t.Fatal("new gen must hit after overwrite")
	}
	if _, ok := c.Contains("scope", "genA", "h.example"); ok {
		t.Fatal("stale gen must miss after overwrite")
	}
}

// TestObserve_SameGenAlreadyExcludedIsNoop — re-observing under the SAME gen while
// already excluded is a no-op (returns false), as before.
func TestObserve_SameGenAlreadyExcludedIsNoop(t *testing.T) {
	c := New(Config{ConfirmN: 1})
	c.Observe("scope", "genA", "Scope", "h.example", ReasonUnsupportedParams, "id:u1")
	if c.Observe("scope", "genA", "Scope", "h.example", ReasonUnsupportedParams, "id:u2") {
		t.Fatal("re-observe under the same gen while excluded must be a no-op")
	}
}

// TestPending_GenScoped — evidence never merges across generations: with confirmN=2,
// one token under genA plus one token under genB must NOT promote (each posture
// accumulates its own confirm-count).
func TestPending_GenScoped(t *testing.T) {
	c := New(Config{ConfirmN: 2})
	if c.Observe("scope", "genA", "Scope", "h.example", ReasonUnsupportedParams, "id:u1") {
		t.Fatal("one token under genA must not promote at confirmN=2")
	}
	if c.Observe("scope", "genB", "Scope", "h.example", ReasonUnsupportedParams, "id:u2") {
		t.Fatal("a token under a DIFFERENT gen must not complete genA's confirm-count")
	}
	if _, ok := c.Contains("scope", "genA", "h.example"); ok {
		t.Fatal("genA must not be excluded — evidence was split across generations")
	}
	// Two tokens under the SAME gen DO promote.
	if !c.Observe("scope", "genA", "Scope", "h.example", ReasonUnsupportedParams, "id:u3") {
		t.Fatal("second distinct token under genA must promote")
	}
}

// TestList_CarriesSecurityGen — the exported snapshot exposes the gen for
// operator/fleet visibility.
func TestList_CarriesSecurityGen(t *testing.T) {
	c := New(Config{ConfirmN: 1})
	c.Observe("scope", "gen-xyz", "Scope", "h.example", ReasonUnsupportedParams, "id:u1")
	list := c.List()
	if len(list) != 1 || list[0].SecurityGen != "gen-xyz" {
		t.Fatalf("List did not carry the security gen: %+v", list)
	}
}
