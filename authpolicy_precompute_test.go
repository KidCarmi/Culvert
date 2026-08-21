package main

// Correctness wall for the Stage-1 hot-path precompute (subject-CIDR parsing at
// publication + cached timezone resolution).
//
// The optimization is only safe if the precomputed form is INDISTINGUISHABLE
// from the allocating path it replaced. These tests pin that equivalence, the
// fallback contract (a rule that never reached sortLocked still matches), and —
// most importantly — that a precomputed net can never outlive an edit to the
// Values it was derived from (a stale net would widen or narrow a subject scope
// silently, which is a security defect, not a performance one).

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// referenceCIDRPredicateMatch is a verbatim copy of the pre-optimization
// matcher (the former cidrPredicateMatchesAddr): parse every value on every
// call, no precompute. It lives HERE, not in production code, precisely so it
// can never be quietly refactored alongside the implementation it is supposed
// to hold to account — it is the frozen oracle for the equivalence test below.
func referenceCIDRPredicateMatch(values []string, clientIP string, clientAddr net.IP) bool {
	for _, v := range values {
		if matchIPOrCIDRAddr(v, clientIP, clientAddr) {
			return true
		}
	}
	return false
}

func cidrSubject(values ...string) *SubjectMatch {
	return &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{
		{Type: subjectPredicateCIDR, Values: values},
	}}
}

func authRuleWithSubject(priority int, name string, sm *SubjectMatch) PolicyRule {
	return PolicyRule{
		Priority:     priority,
		Name:         name,
		RuleType:     ruleTypeAuth,
		SubjectMatch: sm,
		DestFQDN:     "*",
		Auth:         &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "test", Reason: "test"},
	}
}

// TestPrecomputeSubjectNets_MatchesUnprecomputed is the core equivalence proof:
// for a broad matrix of predicate values and client IPs, the precomputed
// matcher and the original per-value parsing matcher must agree exactly.
func TestPrecomputeSubjectNets_MatchesUnprecomputed(t *testing.T) {
	valueSets := [][]string{
		{"10.0.0.0/8"},
		{"10.0.0.0/8", "192.168.0.0/16"},
		{"203.0.113.7"},                 // bare IP — no precompute, string equality
		{"203.0.113.7", "10.0.0.0/8"},   // mixed bare + CIDR
		{"10.0.0.0/33"},                 // invalid CIDR — must fail closed
		{"not-an-ip"},                   // garbage — must fail closed
		{"10.0.0.0/8", "10.0.0.0/33"},   // one good, one invalid
		{"2001:db8::/32"},               // IPv6 CIDR
		{"2001:db8::1"},                 // IPv6 bare
		{"0.0.0.0/0"},                   // match-all
		{"10.1.2.3/32"},                 // single-host CIDR
		{},                              // empty — fails closed
		{"::ffff:10.0.0.0/104"},         // v4-mapped v6 CIDR
		{"192.168.1.0/24", "not-an-ip"}, // good + garbage
	}
	clientIPs := []string{
		"10.1.2.3", "192.168.1.9", "203.0.113.7", "8.8.8.8",
		"2001:db8::1", "2001:db9::1", "", "garbage", "10.0.0.0",
	}

	for vi, values := range valueSets {
		for _, clientIP := range clientIPs {
			clientAddr := net.ParseIP(clientIP)

			// Reference: the original path, no precompute anywhere.
			want := referenceCIDRPredicateMatch(values, clientIP, clientAddr)

			// Subject under test: same values, published through precompute.
			sm := cidrSubject(values...)
			precomputeSubjectNets(sm)
			got := cidrPredicateMatches(&sm.All[0], clientIP, clientAddr)

			if got != want {
				t.Errorf("values[%d]=%v client=%q: precomputed=%v, reference=%v (must agree)",
					vi, values, clientIP, got, want)
			}

			// And the whole-subject entry point must agree too.
			if smGot := matchSubjectAddr(sm, clientIP, clientAddr); smGot != want {
				t.Errorf("values[%d]=%v client=%q: matchSubjectAddr=%v, reference=%v",
					vi, values, clientIP, smGot, want)
			}
		}
	}
}

// TestPrecomputeSubjectNets_FallsBackWithoutPrecompute pins the contract that
// correctness never DEPENDS on the precompute: a rule that reached the
// evaluator without going through sortLocked matches identically, just slower.
func TestPrecomputeSubjectNets_FallsBackWithoutPrecompute(t *testing.T) {
	sm := cidrSubject("10.0.0.0/8")
	if sm.All[0].nets != nil {
		t.Fatal("fixture should start un-precomputed")
	}
	if !matchSubjectAddr(sm, "10.1.2.3", net.ParseIP("10.1.2.3")) {
		t.Error("in-range client must match without precompute")
	}
	if matchSubjectAddr(sm, "8.8.8.8", net.ParseIP("8.8.8.8")) {
		t.Error("out-of-range client must not match without precompute")
	}
}

// TestPrecomputeSubjectNets_OnlyStoresParseableCIDRs pins the shape: bare IPs
// keep the allocation-free string path (nil element), and a predicate with no
// parseable CIDR carries no slice at all.
func TestPrecomputeSubjectNets_OnlyStoresParseableCIDRs(t *testing.T) {
	sm := cidrSubject("203.0.113.7", "10.0.0.0/8", "10.0.0.0/33")
	precomputeSubjectNets(sm)
	nets := sm.All[0].nets
	if len(nets) != 3 {
		t.Fatalf("nets must be index-aligned with Values: got len %d, want 3", len(nets))
	}
	if nets[0] != nil {
		t.Error("bare IP must not be precomputed (string equality is already allocation-free)")
	}
	if nets[1] == nil {
		t.Error("valid CIDR must be precomputed")
	}
	if nets[2] != nil {
		t.Error("invalid CIDR must not be precomputed (falls back and fails closed)")
	}

	bareOnly := cidrSubject("203.0.113.7")
	precomputeSubjectNets(bareOnly)
	if bareOnly.All[0].nets != nil {
		t.Error("predicate with no parseable CIDR must carry a nil nets slice")
	}

	nonCIDRType := &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{
		{Type: "identity", Values: []string{"10.0.0.0/8"}},
	}}
	precomputeSubjectNets(nonCIDRType)
	if nonCIDRType.All[0].nets != nil {
		t.Error("non-CIDR predicate types must never be precomputed")
	}

	precomputeSubjectNets(nil) // must not panic
}

// TestPrecomputeSubjectNets_NoStaleNetAfterEdit is the security-relevant case: a
// narrowed subject scope must take effect immediately. If a copy could retain a
// net parsed from the PREVIOUS Values, an admin tightening 10.0.0.0/8 to
// 10.1.0.0/16 would keep matching the old, broader range.
func TestPrecomputeSubjectNets_NoStaleNetAfterEdit(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{authRuleWithSubject(1, "scoped", cidrSubject("10.0.0.0/8"))})

	ctx := RequestContext{ClientIP: "10.9.9.9", Host: "target.example.com", Protocol: "connect", Method: "CONNECT"}
	if d := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx); d.Outcome != OutcomeCredentialRequired {
		t.Fatalf("broad rule must match 10.9.9.9: got %q", d.Outcome)
	}

	// Narrow the scope. The republished rule must not carry the /8.
	ps.ReplaceAll([]PolicyRule{authRuleWithSubject(1, "scoped", cidrSubject("10.1.0.0/16"))})
	if d := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx); d.Outcome != OutcomeDefault {
		t.Errorf("STALE PRECOMPUTE: narrowed rule still matches 10.9.9.9 (outcome %q) — "+
			"a precomputed net outlived the Values edit it was derived from", d.Outcome)
	}
	inRange := RequestContext{ClientIP: "10.1.2.3", Host: "target.example.com", Protocol: "connect", Method: "CONNECT"}
	if d := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), inRange); d.Outcome != OutcomeCredentialRequired {
		t.Errorf("narrowed rule must still match in-range 10.1.2.3: got %q", d.Outcome)
	}
}

// TestPrecomputeSubjectNets_PublicationClearsCopyPrecompute pins the mechanism
// behind the test above: the detached copy never carries the parent's nets.
func TestPrecomputeSubjectNets_PublicationClearsCopyPrecompute(t *testing.T) {
	src := authRuleWithSubject(1, "src", cidrSubject("10.0.0.0/8"))
	precomputeSubjectNets(src.SubjectMatch)
	if src.SubjectMatch.All[0].nets == nil {
		t.Fatal("fixture must be precomputed")
	}
	var dst PolicyRule
	copyPolicyRuleForPublication(&dst, &src)
	if dst.SubjectMatch.All[0].nets != nil {
		t.Error("copyPolicyRuleForPublication must clear the subject precompute, mirroring srcIPNet")
	}
}

// TestPolicyStorePublishesSubjectNets pins that the store's mutators actually
// run the precompute — the optimization is inert otherwise, and the benchgate
// would be the only thing to notice.
func TestPolicyStorePublishesSubjectNets(t *testing.T) {
	rule := authRuleWithSubject(1, "published", cidrSubject("10.0.0.0/8"))
	for _, tc := range []struct {
		name  string
		apply func(ps *PolicyStore)
	}{
		{"ReplaceAll", func(ps *PolicyStore) { ps.ReplaceAll([]PolicyRule{rule}) }},
		{"Add", func(ps *PolicyStore) { ps.Add(rule) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := &PolicyStore{}
			tc.apply(ps)
			snap := ps.evaluationSnapshot()
			if len(snap) != 1 {
				t.Fatalf("expected 1 published rule, got %d", len(snap))
			}
			if snap[0].SubjectMatch == nil || snap[0].SubjectMatch.All[0].nets == nil {
				t.Error("published auth rule must carry precomputed subject nets")
			}
		})
	}
}

// TestAuthScheduleParseable_CachedResolution pins the Stage-1 timezone gate:
// same fail-closed semantics as the direct time.LoadLocation call it replaced,
// now served from the shared cache.
func TestAuthScheduleParseable_CachedResolution(t *testing.T) {
	for _, tc := range []struct {
		name string
		sch  *PolicySchedule
		want bool
	}{
		{"nil schedule", nil, true},
		{"empty timezone", &PolicySchedule{}, true},
		{"valid timezone", &PolicySchedule{Timezone: "America/New_York"}, true},
		{"UTC", &PolicySchedule{Timezone: "UTC"}, true},
		{"invalid timezone", &PolicySchedule{Timezone: "Not/AZone"}, false},
		{"garbage timezone", &PolicySchedule{Timezone: "../../etc/passwd"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Twice: the second call is served from the cache and must agree.
			if got := authScheduleParseable(tc.sch); got != tc.want {
				t.Fatalf("first call: got %v, want %v", got, tc.want)
			}
			if got := authScheduleParseable(tc.sch); got != tc.want {
				t.Errorf("cached call: got %v, want %v (cache must preserve the outcome)", got, tc.want)
			}
		})
	}
}

// TestScheduleLocationResolved_ReportsFailureDistinctly pins the reason the
// cache had to carry the outcome: "resolved to UTC" and "failed, fell back to
// UTC" are the same *time.Location but must NOT be the same answer for the
// Stage-1 gate, which fails closed on a timezone it cannot evaluate.
func TestScheduleLocationResolved_ReportsFailureDistinctly(t *testing.T) {
	loc, ok := scheduleLocationResolved("UTC")
	if !ok || loc != time.UTC {
		t.Errorf(`"UTC" must resolve ok: loc=%v ok=%v`, loc, ok)
	}
	loc, ok = scheduleLocationResolved("Not/AZone")
	if ok {
		t.Error("an unparseable timezone must report ok=false, not a silent UTC fallback")
	}
	if loc != time.UTC {
		t.Errorf("failed resolution must still hand back UTC for Stage-2's lenient path, got %v", loc)
	}
	// scheduleLocation keeps its lenient contract for existing callers.
	if got := scheduleLocation("Not/AZone"); got != time.UTC {
		t.Errorf("scheduleLocation must stay lenient (UTC on failure), got %v", got)
	}
}

// TestAuthResolve_ScheduledRuleFailsClosedOnBadTZ end-to-end: an auth rule whose
// timezone cannot be evaluated must not grant a Stage-1 outcome, cached or not.
func TestAuthResolve_ScheduledRuleFailsClosedOnBadTZ(t *testing.T) {
	rule := authRuleWithSubject(1, "bad-tz", cidrSubject("10.0.0.0/8"))
	rule.Auth.Outcome = OutcomeExempt
	rule.Schedule = &PolicySchedule{Timezone: "Not/AZone", Days: []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}}
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{rule})

	ctx := RequestContext{ClientIP: "10.1.2.3", Host: "target.example.com", Protocol: "connect", Method: "CONNECT"}
	for i := 0; i < 2; i++ { // second pass exercises the cached resolution
		if d := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx); d.Outcome != OutcomeDefault {
			t.Fatalf("pass %d: rule with unevaluable timezone granted %q — must fail closed", i, d.Outcome)
		}
	}
}

// TestAuthResolve_ConcurrentSnapshotReadsWhilePublishing exercises the published
// nets under -race: many readers evaluating while a writer republishes the
// rulebase. The precomputed *net.IPNet values are only ever written before
// publication and read after, so this must be race-free.
func TestAuthResolve_ConcurrentSnapshotReadsWhilePublishing(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{authRuleWithSubject(1, "r", cidrSubject("10.0.0.0/8"))})
	ctx := RequestContext{ClientIP: "10.1.2.3", Host: "target.example.com", Protocol: "connect", Method: "CONNECT"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			ps.ReplaceAll([]PolicyRule{
				authRuleWithSubject(1, fmt.Sprintf("r-%d", i), cidrSubject("10.0.0.0/8", "192.168.0.0/16")),
			})
		}
	}()
	for i := 0; i < 2000; i++ {
		if d := resolveAuthOutcomeSnapshot(ps.evaluationSnapshot(), ctx); d.Outcome != OutcomeCredentialRequired {
			t.Fatalf("iteration %d: in-range client lost its match during republication (%q)", i, d.Outcome)
		}
	}
	<-done
}
