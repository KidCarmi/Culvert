package main

// Tests for the request-independent per-rule precompute (perf F5): parsed CIDR
// (srcIPNet), matched-conditions summary (matchedConds), and the shared
// schedule-timezone location cache. Each precompute follows the normFQDN
// contract — sortLocked populates it on every mutation, and the hot path falls
// back to the allocating implementation when it is absent, so correctness
// never depends on the precompute having run.

import (
	"testing"
	"time"
)

// TestPolicyPrecompute_CIDRMatch verifies the precomputed-srcIPNet path end to
// end through every mutator: a CIDR-scoped rule matches clients inside the
// subnet and rejects clients outside it, after ReplaceAll, Add, and Update.
func TestPolicyPrecompute_CIDRMatch(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{
		Priority: 1, Name: "lan", SourceIP: "10.1.0.0/16", DestFQDN: "*", Action: ActionAllow,
	}})
	if m := ps.Evaluate("10.1.2.3", "", "unauth", "example.com", nil); m == nil || m.Rule.Name != "lan" {
		t.Fatalf("ReplaceAll: client inside CIDR should match, got %v", m)
	}
	if m := ps.Evaluate("10.2.0.1", "", "unauth", "example.com", nil); m != nil {
		t.Fatalf("ReplaceAll: client outside CIDR should not match, got rule %q", m.Rule.Name)
	}

	ps.Add(PolicyRule{Priority: 2, Name: "guest", SourceIP: "192.168.5.0/24", DestFQDN: "*", Action: ActionBlockPage})
	if m := ps.Evaluate("192.168.5.9", "", "unauth", "example.com", nil); m == nil || m.Rule.Name != "guest" {
		t.Fatalf("Add: client inside CIDR should match, got %v", m)
	}

	if !ps.Update(2, PolicyRule{Priority: 2, Name: "guest", SourceIP: "172.16.0.0/12", DestFQDN: "*", Action: ActionBlockPage}) {
		t.Fatal("Update returned false")
	}
	if m := ps.Evaluate("172.16.44.1", "", "unauth", "example.com", nil); m == nil || m.Rule.Name != "guest" {
		t.Fatalf("Update: client inside new CIDR should match, got %v", m)
	}
	if m := ps.Evaluate("192.168.5.9", "", "unauth", "example.com", nil); m != nil {
		t.Fatalf("Update: old CIDR should no longer match, got rule %q", m.Rule.Name)
	}
}

// TestPolicyPrecompute_InvalidCIDRFailsClosed verifies an unparseable CIDR
// leaves srcIPNet nil and the fallback path rejects everything — identical to
// the pre-precompute behavior (net.ParseCIDR error ⇒ no match).
func TestPolicyPrecompute_InvalidCIDRFailsClosed(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{
		Priority: 1, Name: "broken", SourceIP: "10.0.0.0/99", DestFQDN: "*", Action: ActionAllow,
	}})
	if m := ps.Evaluate("10.0.0.1", "", "unauth", "example.com", nil); m != nil {
		t.Fatalf("invalid CIDR must never match, got rule %q", m.Rule.Name)
	}
}

// TestPolicyPrecompute_ExactIPStillMatches verifies a plain (non-CIDR)
// SourceIP keeps its exact string-equality semantics — no srcIPNet is
// precomputed and the comparison path is unchanged.
func TestPolicyPrecompute_ExactIPStillMatches(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{
		Priority: 1, Name: "one-host", SourceIP: "203.0.113.7", DestFQDN: "*", Action: ActionAllow,
	}})
	if m := ps.Evaluate("203.0.113.7", "", "unauth", "example.com", nil); m == nil {
		t.Fatal("exact SourceIP should match")
	}
	if m := ps.Evaluate("203.0.113.8", "", "unauth", "example.com", nil); m != nil {
		t.Fatalf("different client IP should not match, got rule %q", m.Rule.Name)
	}
}

// TestPolicyPrecompute_MatchedConditions verifies the precomputed summary on
// an Evaluate match is identical to what buildMatchedConditions produces —
// the audit-trail string must not change shape with the precompute.
func TestPolicyPrecompute_MatchedConditions(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{
		Priority: 1, Name: "audit", SourceIP: "10.0.0.0/8", DestFQDN: "*.example.com", Action: ActionAllow,
	}})
	m := ps.Evaluate("10.9.8.7", "", "unauth", "www.example.com", nil)
	if m == nil {
		t.Fatal("expected match")
	}
	want := buildMatchedConditions(m.Rule)
	if m.MatchedConditions != want {
		t.Errorf("MatchedConditions = %q, want %q (precompute drifted from buildMatchedConditions)", m.MatchedConditions, want)
	}
	if m.MatchedConditions == "" {
		t.Error("MatchedConditions must never be empty on a match")
	}

	// A rule with no configured conditions summarizes as "any".
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "wide-open", Action: ActionAllow}})
	if m := ps.Evaluate("10.9.8.7", "", "unauth", "www.example.com", nil); m == nil || m.MatchedConditions != "any" {
		t.Errorf("unconditional rule: MatchedConditions should be %q, got %v", "any", m)
	}
}

// TestPolicyPrecompute_MatchSourceFallback verifies matchSource still works on
// a hand-built rule that never went through sortLocked (srcIPNet nil ⇒
// allocating matchIPOrCIDR fallback) — the simulator and CDR paths build rules
// this way.
func TestPolicyPrecompute_MatchSourceFallback(t *testing.T) {
	rule := &PolicyRule{SourceIP: "10.1.0.0/16"}
	if !matchSource(rule, "10.1.2.3", "", "unauth", nil) {
		t.Error("fallback path: client inside CIDR should match")
	}
	if matchSource(rule, "10.2.0.1", "", "unauth", nil) {
		t.Error("fallback path: client outside CIDR should not match")
	}
}

// TestScheduleLocation_CachesAndFallsBack verifies the timezone cache returns
// the canonical location for a valid IANA name (the same instance on repeat
// calls — one disk read per process, not per request) and caches the UTC
// fallback for an invalid name.
func TestScheduleLocation_CachesAndFallsBack(t *testing.T) {
	l1 := scheduleLocation("America/New_York")
	if l1 == nil || l1.String() != "America/New_York" {
		t.Fatalf("scheduleLocation returned %v, want America/New_York", l1)
	}
	if l2 := scheduleLocation("America/New_York"); l2 != l1 {
		t.Error("repeat lookup should return the cached *time.Location instance")
	}
	if bad := scheduleLocation("Not/A_Zone"); bad != time.UTC {
		t.Errorf("invalid timezone should fall back to UTC, got %v", bad)
	}
	if bad2 := scheduleLocation("Not/A_Zone"); bad2 != time.UTC {
		t.Errorf("invalid timezone should stay cached as UTC, got %v", bad2)
	}
}

// TestPolicyPrecompute_ScheduleTimezone verifies a timezone-pinned schedule
// still gates Evaluate correctly through the location cache: an all-day window
// matches, an empty (never-matching) day list does not.
func TestPolicyPrecompute_ScheduleTimezone(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{
		Priority: 1, Name: "workday", DestFQDN: "*",
		Schedule: &PolicySchedule{TimeStart: "00:00", TimeEnd: "23:59", Timezone: "America/New_York"},
		Action:   ActionAllow,
	}})
	if m := ps.Evaluate("203.0.113.7", "", "unauth", "example.com", nil); m == nil {
		t.Error("all-day schedule in a valid timezone should match")
	}

	ps.ReplaceAll([]PolicyRule{{
		Priority: 1, Name: "never", DestFQDN: "*",
		Schedule: &PolicySchedule{Days: []string{"Nod"}, Timezone: "America/New_York"},
		Action:   ActionAllow,
	}})
	if m := ps.Evaluate("203.0.113.7", "", "unauth", "example.com", nil); m != nil {
		t.Errorf("non-matching day should not match, got rule %q", m.Rule.Name)
	}
}
