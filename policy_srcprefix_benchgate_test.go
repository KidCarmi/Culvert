//go:build benchgate

package main

// Cost gates for the precomputed source-CIDR prefix (PolicyRule.srcPrefix).
//
//	go test -tags benchgate -run 'TestBenchGate_PolicySourceCIDR' -v .

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// buildSrcCIDRStore returns n access rules that ALL pass the source check for
// the probe IP, so every rule pays the full source-IP match before failing on
// the FQDN — the worst case for a source-scoped rulebase, and how enterprise
// deployments scope rules by client subnet.
func buildSrcCIDRStore(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("src-rule-%d", i),
			SourceIP: "203.0.113.0/24",
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

const srcGateProbeIP = "203.0.113.7"

// TestBenchGate_PolicySourceCIDRAllocFree pins the zero-allocation contract for
// a source-scoped scan.
//
// This gate is DETERMINISTIC — an allocation count, not a duration — so it
// fails identically on any hardware, at any load, with or without -race.
//
// It exists because the obvious way to write this optimization breaks the
// contract silently. The first working draft carried the parsed net.IP inside
// clientSource; because the struct is returned by value, that made
// net.ParseIP's backing array escape and cost 1 alloc/op (16 B) on EVERY
// proxied request. The verdict was identical and every correctness test passed,
// so nothing but an allocation gate could see it. The same trap is one edit
// away at any time: give clientSource a slice, map, or interface field, or let
// matchSourceAddr retain the pointer it is handed, and the scan starts
// allocating again.
func TestBenchGate_PolicySourceCIDRAllocFree(t *testing.T) {
	for _, n := range []int{1, 10, 100} {
		ps := buildSrcCIDRStore(n)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ps.Evaluate(srcGateProbeIP, "", "unauth", "target.example.com", nil)
			}
		})
		if got := res.AllocsPerOp(); got != 0 {
			t.Errorf("rules=%d: policy scan allocates %d/op, want 0 — a source-scoped scan must stay allocation-free", n, got)
		}
	}
}

// TestBenchGate_PolicySourceCIDRUsesPrefix locks in that the per-rule source
// check actually goes through the precomputed netip.Prefix rather than
// net.(*IPNet).Contains.
//
// GATE DESIGN. This is a RATIO gate between two matchers measured against each
// other IN THE SAME RUN, not against an absolute nanosecond budget, so it is
// machine-independent. The control is legacySourceIPMatch — the verbatim
// pre-change arm, which the differential test already uses as its correctness
// oracle — so a passing gate cannot mean "the source check stopped happening":
// both sides compute the same verdict over the same rule and address.
//
// net.IPNet stores its address and mask as byte slices of unspecified length,
// so Contains re-derives their shape on every call (networkNumberAndMask -> To4
// -> isZeros). Profiling BenchmarkPolicyEvaluate_CIDRRules at 1000 rules
// attributed 34.4% of the ENTIRE policy evaluation to that one call. A
// netip.Prefix has its family already decided, so Contains is a masked compare.
//
// Measured on the development machine: the prefix arm is ~3x faster than the
// IPNet arm. The bound is set at "merely no slower" (1.0) rather than at the
// measured margin, because the gate's job is to catch the fast path being
// REMOVED — which returns the full ~3x — not to police small movements in it;
// a tight bound on a shared CI runner would flake, and a gate that flakes gets
// muted.
func TestBenchGate_PolicySourceCIDRUsesPrefix(t *testing.T) {
	if testing.Short() {
		t.Skip("cost-shape gate skipped in -short")
	}
	rule := buildSrcCIDRStore(1).rules[0]
	if !rule.srcPrefix.IsValid() {
		t.Fatal("published rule carries no srcPrefix — the fast path is not wired at all")
	}
	legacyAddr := net.ParseIP(srcGateProbeIP)

	const iters = 200000
	measure := func(fn func()) time.Duration {
		for i := 0; i < iters/10; i++ { // warm up so neither side pays first-touch
			fn()
		}
		start := time.Now()
		for i := 0; i < iters; i++ {
			fn()
		}
		return time.Since(start)
	}
	// Best-of-three: a scheduler hiccup inflates a sample, never deflates it,
	// so taking the minimum removes the flake direction.
	best := func(fn func()) time.Duration {
		d := measure(fn)
		for i := 0; i < 2; i++ {
			if e := measure(fn); e < d {
				d = e
			}
		}
		return d
	}

	// Both arms are measured PER RULE with the client address already parsed,
	// because that is the shape of the thing being compared: one scan parses
	// once and then matches once per rule, so folding a parse into one arm and
	// not the other would measure the harness rather than the matcher. The
	// pre-change scan hoisted net.ParseIP the same way (legacyAddr below).
	src := newClientSource(srcGateProbeIP)
	src.address() // memoise, as the scan's first source-scoped rule does

	var sink bool
	prefixArm := best(func() { sink = matchSourceAddr(rule, &src, "", "", nil) })
	legacyArm := best(func() { sink = legacySourceIPMatch(rule, srcGateProbeIP, legacyAddr) })
	_ = sink

	ratio := float64(prefixArm) / float64(legacyArm)
	t.Logf("prefix arm %v, net.IPNet arm %v over %d iters (ratio %.2fx)", prefixArm, legacyArm, iters, ratio)
	if ratio > 1.0 {
		t.Errorf("source-IP match is %.2fx the cost of net.(*IPNet).Contains (prefix=%v ipnet=%v) — "+
			"the srcPrefix fast path looks bypassed", ratio, prefixArm, legacyArm)
	}
}
