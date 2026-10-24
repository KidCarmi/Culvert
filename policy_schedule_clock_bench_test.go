package main

// Benchmarks for the evaluation-scoped schedule memo (scheduleClock).
//
// BenchmarkPolicyEvaluate_ScheduledRules in policy_bench_test.go is the headline
// regression gate for the common posture (one timezone across the rulebase). The
// benchmarks here cover what that one does not:
//
//   - CONCURRENCY. The work the memo removes was a probe of a process-wide
//     sync.Map, i.e. shared state read by every proxy goroutine at once. A
//     serial measurement cannot see that cost, so the parallel variant is the
//     one that speaks to the real multi-connection proxy.
//   - The WORST CASE. The memo holds one entry, so a rulebase that alternates
//     timezones rule-by-rule evicts on every rule and re-derives. That shape
//     must degrade to roughly the pre-memo cost and never past it — a memo that
//     made its own pathological case SLOWER would be a bad trade regardless of
//     how good the common case looked.

import (
	"fmt"
	"testing"
	"time"
)

// buildMultiTimezoneScheduledPolicyStore returns a store of n scheduled rules
// whose timezones CYCLE, so consecutive rules disagree and the single-entry memo
// misses on every one. Zones are real tzdata entries spanning several offsets.
func buildMultiTimezoneScheduledPolicyStore(n, distinctZones int) *PolicyStore {
	zones := []string{
		"America/New_York", "Australia/Sydney", "Asia/Kolkata", "Europe/London",
		"America/Los_Angeles", "Asia/Tokyo", "Europe/Berlin", "America/Sao_Paulo",
	}
	if distinctZones > len(zones) {
		distinctZones = len(zones)
	}
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("sched-tz-rule-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Schedule: &PolicySchedule{
				TimeStart: "00:00", TimeEnd: "23:59",
				Timezone: zones[i%distinctZones],
			},
			Action: ActionAllow,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

// BenchmarkPolicyEvaluate_ScheduledRulesParallel is the contention measure: all
// GOMAXPROCS goroutines evaluating the same scheduled rulebase, as concurrent
// proxy requests do. Pre-memo this put (rules x goroutines) probes per second
// through one process-wide sync.Map; the memo serves all but the first from the
// goroutine's own stack, so the shared structure is touched once per request.
func BenchmarkPolicyEvaluate_ScheduledRulesParallel(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		ps := buildScheduledPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m != nil {
						b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
					}
				}
			})
		})
	}
}

// BenchmarkPolicyEvaluate_ScheduledRulesMultiTimezone is the memo's worst case:
// every rule in a different zone from the one before it, so every rule misses.
// Expect it to land near the pre-memo cost — that is the floor the memo degrades
// to, and the measurement that keeps "one entry is enough" honest.
func BenchmarkPolicyEvaluate_ScheduledRulesMultiTimezone(b *testing.B) {
	for _, zones := range []int{1, 2, 4, 8} {
		ps := buildMultiTimezoneScheduledPolicyStore(1000, zones)
		b.Run(fmt.Sprintf("rules=1000/zones=%d", zones), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m != nil {
					b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
				}
			}
		})
	}
}

// BenchmarkMatchScheduleMemo_SharedVsOneShot isolates the memo from the rest of
// the scan, so the per-rule saving is attributable rather than inferred from an
// end-to-end delta. "shared" reuses one memo across the rules of a scan (the
// Stage-2 path); "oneshot" builds a fresh memo per rule, which is the pre-change
// cost and exactly what matchScheduleAt still does for its single-rule callers.
func BenchmarkMatchScheduleMemo_SharedVsOneShot(b *testing.B) {
	const rules = 100
	s := &PolicySchedule{TimeStart: "00:00", TimeEnd: "23:59", Timezone: "America/New_York"}
	now := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC) // a Monday, mid-window

	b.Run("shared", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c := scheduleClock{now: now}
			for r := 0; r < rules; r++ {
				if !matchScheduleMemo(s, &c) {
					b.Fatal("always-active schedule should match")
				}
			}
		}
	})

	b.Run("oneshot", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for r := 0; r < rules; r++ {
				if !matchScheduleAt(s, now) {
					b.Fatal("always-active schedule should match")
				}
			}
		}
	})
}
