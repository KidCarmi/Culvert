package main

import (
	"fmt"
	"testing"
)

// buildPublishInput returns n access rules in the shape a real rulebase
// publishes: distinct FQDN-scoped allow rules in ascending priority, a tenth of
// them source-scoped by CIDR (so the publication precompute does the
// ParseCIDR/prefix work it does in production) and a tenth schedule-bearing.
func buildPublishInput(n int) []PolicyRule {
	rules := make([]PolicyRule, n)
	for i := range rules {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("rule-%d", i),
			DestFQDN: fmt.Sprintf("host-%d.example.invalid", i),
			Action:   ActionAllow,
		}
		if i%10 == 0 {
			rules[i].SourceIP = "203.0.113.0/24"
		}
		if i%10 == 5 {
			rules[i].Schedule = &PolicySchedule{
				Days:      []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
				TimeStart: "09:00",
				TimeEnd:   "17:00",
				Timezone:  "UTC",
			}
		}
	}
	return rules
}

// BenchmarkPolicyPublish_SortLocked measures ONE publication of an installed
// rulebase: the clone of every definition, the priority ordering and the
// per-rule precompute (normFQDN, srcIPNet/srcPrefix, matchedConds).
//
// This is a control-plane cost with a data-plane consequence. sortLocked runs
// under ps.mu — the WRITER lock — and Evaluate's evaluationSnapshot has to take
// the matching RLock before every scan, so the whole proxy's policy evaluation
// is stalled for exactly as long as a publication takes. Any policy edit,
// config-version restore or cluster config sync pays it, so its allocation
// count and wall time are latency figures, not just reload figures.
func BenchmarkPolicyPublish_SortLocked(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			ps := &PolicyStore{}
			ps.ReplaceAll(buildPublishInput(n))
			if got := len(ps.List()); got != n {
				b.Fatalf("installed %d rules, want %d", got, n)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ps.mu.Lock()
				ps.sortLocked()
				ps.mu.Unlock()
			}
		})
	}
}

// BenchmarkPolicyPublish_ReplaceAll measures the whole shipped bulk-replace
// path (validation, ID uniqueness, then the publication above), so the
// sortLocked figure can be read against the real per-reload total.
func BenchmarkPolicyPublish_ReplaceAll(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		in := buildPublishInput(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			ps := &PolicyStore{}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ps.ReplaceAll(in)
			}
		})
	}
}

// BenchmarkPolicyPublish_EvaluateDuringPublish is the CONCURRENCY arm, and the
// one that measures why a publication's cost is a latency figure: evaluators
// run in parallel while a single background publisher republishes the same
// rulebase in a loop, so the reported ns/op is per-request evaluation latency
// WITH the writer lock being taken and released underneath it. Compare it to
// BenchmarkPolicyEvaluate_NoMatch at the same rule count to read the stall.
//
// The publisher is rate-free on purpose (a tight republish loop is the worst
// case, not the expected one); the figure is therefore an upper bound on the
// contention, useful for before/after comparison and not as an absolute.
func BenchmarkPolicyPublish_EvaluateDuringPublish(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			ps := &PolicyStore{}
			ps.ReplaceAll(buildPublishInput(n))

			stop := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					select {
					case <-stop:
						return
					default:
					}
					ps.mu.Lock()
					ps.sortLocked()
					ps.mu.Unlock()
				}
			}()
			b.Cleanup(func() {
				close(stop)
				<-done
			})

			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m != nil {
						b.Errorf("unexpected match %q", m.Rule.Name)
						return
					}
				}
			})
		})
	}
}
