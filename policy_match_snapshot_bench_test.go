package main

// policy_match_snapshot_bench_test.go — per-request cost of the DETACHED rule
// snapshot a policy decision carries (copyPolicyRuleForMatch, policy.go).
//
// Run:
//
//	go test -run '^$' -bench 'MatchSnapshot' -benchmem -count=6 .
//
// WHY THIS FILE EXISTS. BenchmarkPerfQual_Evaluate measures a match at
// 1 alloc/op, and that number is an artifact of its fixture. Its rules are
// PolicyRule literals carrying only Priority/Name/DestFQDN/Action, so every
// optional pointer and slice field is nil and copyPolicyRuleForPublication —
// which copyPolicyRuleForMatch calls to detach the snapshot — takes none of its
// per-field branches. No rule a deployment actually runs has that shape:
// PolicyStore.Add fills Enabled on EVERY rule created through the admin API
// (policy.go), so the smallest real rule already takes one of those branches on
// every matched request, and a rule that also sets the logging/ALPN switches
// takes three. The arms below are the shapes a rulebase really holds, so the
// detaching cost is attributed where it is paid:
//
//	bare       the perfqual fixture shape — every optional field nil
//	enabled    + Enabled (*bool)       — what PolicyStore.Add guarantees
//	logging    + LogTraffic, StripALPN — the per-rule logging/ALPN switches
//	scheduled  + Schedule              — a time-scoped rule
//
// Measured on this machine (Go 1.27.3, linux/amd64, 4 vCPU Xeon @2.10GHz,
// 100-rule store, match at scan position 1, -count=10 -benchtime=2s, medians):
//
//	Stage-2 PolicyStore.Evaluate      Stage-1 resolveAuthOutcomeSnapshot
//	bare       1 alloc   640 B        bare       6 allocs  848 B
//	enabled    2 allocs  641 B        enabled    7 allocs  849 B
//	logging    4 allocs  643 B        logging    9 allocs  851 B
//	scheduled  6 allocs  835 B        scheduled  9 allocs  851 B
//
// (The Stage-1 arms are higher throughout because a persistable auth rule
// requires a SubjectMatch source scope, whose detach is a constant 3 allocations
// across the arms. Its scheduled arm equals its logging arm because schedule
// matching is not what that half measures and the field is cleared.)
//
// MEASURED NEGATIVE RESULT — do not "fix" the three *bool allocations by
// folding cells into the snapshot. It was implemented and rejected on these
// numbers. Both snapshots already allocate one object with room in their
// struct padding, so the obvious move is to carry the three bool cells inside
// it (PolicyMatch 632 -> 640 bytes, the standalone auth snapshot 568 -> 576)
// and point LogTraffic/StripALPN/Enabled at them. Allocations fall exactly as
// predicted — Stage-2 logging 4 -> 1, Stage-1 logging 9 -> 6 — and it is still
// a LOSS:
//
//	enabled    518.7 -> 543.1 ns/op (+4.7%)   641 -> 704 B/op (+63)
//	logging    539.5 -> 530.3 ns/op (-1.7%)   643 -> 704 B/op (+61)
//
// Two allocator facts explain it, and both are why "fewer allocs/op" is not by
// itself evidence of a faster path:
//
//   - A detached *bool is a 1-byte POINTER-FREE object, so it is served by Go's
//     tiny allocator: several share one 16-byte block and no span lookup or
//     bitmap write is paid per field. That is what 641 and 643 B/op report —
//     ~1 amortized byte per cell, not 8 or 16. These are among the cheapest
//     allocations the runtime can make, so removing three of them buys little.
//   - An object LARGER than 512 bytes that CONTAINS POINTERS carries an 8-byte
//     malloc header, which counts against its size class. PolicyMatch at 632
//     bytes and PolicyRule at 568 therefore land exactly at the top of the
//     640- and 576-byte classes: both are already packed as tightly as the
//     allocator permits, and the NEXT byte added to either costs a full class
//     step (+64 B/op on every match). Folding the cells in spent 64 real bytes
//     of per-request garbage to save three near-free tiny allocations.
//
// TestBenchGate_MatchSnapshotAllocs (bench_regression_test.go) gates the
// numbers above, and TestBenchGate_MatchSnapshotSizeClassHeadroom gates the
// headroom that makes the second fact load-bearing.
//
// Still open, and NOT addressed here: the variable-length nested values
// (DestCountry, Schedule.Days, Auth.ProviderRefs, SubjectMatch values) and the
// 72-byte *PolicySchedule are real per-match allocations that inline storage
// cannot absorb for free, for the same size-class reason. The scheduled arm
// keeps their cost measurable so a later change can be argued from numbers
// rather than from the shape of the code.

import (
	"fmt"
	"testing"
)

// benchSnapshotShape names a rule shape and the fields that give it that shape.
type benchSnapshotShape struct {
	name  string
	apply func(r *PolicyRule)
}

// benchSnapshotShapes is ordered cheapest-first so the arms read as the cost
// each additional real-world field adds, not as four unrelated numbers.
func benchSnapshotShapes() []benchSnapshotShape {
	yes, no := true, false
	return []benchSnapshotShape{
		{"bare", func(*PolicyRule) {}},
		{"enabled", func(r *PolicyRule) { r.Enabled = &yes }},
		{"logging", func(r *PolicyRule) {
			r.Enabled = &yes
			r.LogTraffic = &yes
			r.StripALPN = &no
		}},
		{"scheduled", func(r *PolicyRule) {
			r.Enabled = &yes
			r.LogTraffic = &yes
			r.StripALPN = &no
			r.Schedule = &PolicySchedule{
				Days:      []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
				TimeStart: "09:00",
				TimeEnd:   "17:00",
				Timezone:  "UTC",
			}
		}},
	}
}

// buildSnapshotShapeStore returns a published store of `size` rules in which
// exactly the FIRST rule matches benchSnapshotHost, so the scan cost is O(1)
// and the measurement isolates the snapshot. shape is applied to the matching
// rule — the one whose fields the snapshot has to detach.
//
// The schedule arm must stay ACTIVE for the whole benchmark or the rule stops
// matching, so it spans every day of the week across the full day;
// matchesSchedule is not what is being measured here.
//
// The end bound is "24:00", not "23:59". scheduleTimeMatchMinutes (policy.go)
// compares `cur < end`, so "23:59" leaves the rule UNMATCHED for the whole
// 23:59:00-23:59:59 minute in the schedule's timezone — a once-a-day window in
// which this benchmark would silently measure the no-match path, or fail
// part-way through a run that crosses the boundary. parseClockMinutes accepts
// "24:00" as 1440 precisely as the exclusive end-of-day bound for a full-day
// window (Codex review, PR #1756).
func buildSnapshotShapeStore(size int, shape benchSnapshotShape) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, size)
	for i := range rules {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("rule-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		}
	}
	rules[0].Name = "match"
	rules[0].DestFQDN = benchSnapshotHost
	shape.apply(&rules[0])
	if s := rules[0].Schedule; s != nil {
		s.Days = []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
		s.TimeStart = "00:00"
		s.TimeEnd = "24:00" // exclusive end-of-day; "23:59" is dead for one minute a day
	}
	ps.ReplaceAll(rules)
	return ps
}

const benchSnapshotHost = "target.example.com"

// benchMatchSnapshot runs Evaluate against a store whose matching rule has the
// given shape. It is shared with the gate test so both measure one code path.
func benchMatchSnapshot(b *testing.B, shape benchSnapshotShape) {
	ps := buildSnapshotShapeStore(100, shape)
	// Prove the shape actually matches before measuring: a rule that stopped
	// matching would report the (cheaper) no-match path as a win.
	if m := ps.Evaluate("203.0.113.7", "", "unauth", benchSnapshotHost, nil); m == nil {
		b.Fatalf("shape %q does not match — the benchmark would measure the no-match path", shape.name)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := ps.Evaluate("203.0.113.7", "", "unauth", benchSnapshotHost, nil)
		if m == nil {
			b.Fatal("no match")
		}
	}
}

func BenchmarkMatchSnapshot(b *testing.B) {
	for _, shape := range benchSnapshotShapes() {
		b.Run(shape.name, func(b *testing.B) { benchMatchSnapshot(b, shape) })
	}
}

// benchAuthMatchSnapshot is the Stage-1 half of the same question.
// resolveAuthOutcomeSnapshot detaches its matched rule through the same helper,
// into a standalone PolicyRule rather than into a PolicyMatch, so it pays the
// same per-field allocations on every un-credentialed request that matches an
// auth rule. BenchmarkResolveAuthOutcome_AuthRuleMatch already measures that
// path on a SubjectMatch-bearing rule; these arms vary only the fixed-size
// nested fields, so the *bool cost is attributable on its own.
//
// Shared with TestBenchGate_MatchSnapshotAllocs so the gate and the benchmark
// measure one code path.
func benchAuthMatchSnapshot(b *testing.B, shape benchSnapshotShape) {
	// A persistable auth rule REQUIRES a subjectMatch source scope, so every arm
	// carries the same one: its own detach cost is constant across the arms and
	// the *bool delta stays attributable.
	match := PolicyRule{
		Priority: 1, Name: "auth-match", RuleType: ruleTypeAuth,
		DestFQDN: benchSnapshotHost,
		SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{
			{Type: subjectPredicateCIDR, Values: []string{"203.0.113.0/24"}},
		}},
		Auth: &AuthRuleSpec{
			Outcome: OutcomeCredentialRequired, Owner: "bench", Reason: "bench",
		},
	}
	shape.apply(&match)
	match.Schedule = nil // schedule matching is not what this half measures
	ps := buildAuthResolveStore(100, match)
	ctx := RequestContext{
		ClientIP: "203.0.113.7", Host: benchSnapshotHost,
		Protocol: "connect", Method: "CONNECT",
	}
	rules := ps.evaluationSnapshot()
	if d := resolveAuthOutcomeSnapshot(rules, ctx); d.Outcome != OutcomeCredentialRequired {
		b.Fatalf("shape %q: outcome %q, want CredentialRequired — the benchmark would measure the no-match path", shape.name, d.Outcome)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d := resolveAuthOutcomeSnapshot(rules, ctx); d.Rule == nil {
			b.Fatal("no match")
		}
	}
}

func BenchmarkAuthMatchSnapshot(b *testing.B) {
	for _, shape := range benchSnapshotShapes() {
		b.Run(shape.name, func(b *testing.B) { benchAuthMatchSnapshot(b, shape) })
	}
}
