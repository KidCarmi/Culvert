//go:build benchgate

package main

// Cost gates for the precomputed source-CIDR prefix (PolicyRule.srcPrefix).
//
//	go test -tags benchgate -run 'TestBenchGate_PolicySourceCIDR' -v .
//
// BOTH gates in this file are DETERMINISTIC — one asserts an allocation count,
// the other a verdict; neither measures a duration — so they fail identically
// on any hardware, at any load, with or without -race. That is deliberate and
// uniform: see TestBenchGate_PolicySourceCIDRUsesPrefix for why the second one
// stopped being a timing ratio.

import (
	"fmt"
	"net"
	"testing"
)

const (
	// srcGateProbeCIDR is the source network every gate rule is scoped to, and
	// srcGateProbeIP an address inside it.
	srcGateProbeCIDR = "203.0.113.0/24" // TEST-NET-3
	srcGateProbeIP   = "203.0.113.7"

	// srcGateDecoyCIDR is DISJOINT from srcGateProbeCIDR, and srcGateDecoyIP
	// sits inside the decoy and outside the probe network. The pair is what
	// lets TestBenchGate_PolicySourceCIDRUsesPrefix tell the two matchers
	// apart by the verdict they produce.
	srcGateDecoyCIDR = "198.51.100.0/24" // TEST-NET-2
	srcGateDecoyIP   = "198.51.100.7"

	// srcGateProbeHost is the destination every gate Evaluate()s against. The
	// two rulebases relate to it DELIBERATELY oppositely: buildSrcMatchStore's
	// rule matches it, so its verdict turns purely on the source check, while
	// buildSrcCIDRStore's rules never match it, so its scan pays every rule's
	// source check and then falls through — the worst case the alloc gate wants.
	srcGateProbeHost = "target.example.com"
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
			SourceIP: srcGateProbeCIDR,
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

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
				ps.Evaluate(srcGateProbeIP, "", "unauth", srcGateProbeHost, nil)
			}
		})
		if got := res.AllocsPerOp(); got != 0 {
			t.Errorf("rules=%d: policy scan allocates %d/op, want 0 — a source-scoped scan must stay allocation-free", n, got)
		}
	}
}

// buildSrcMatchStore publishes ONE source-scoped rule through the real store
// mutator, carrying exactly the precomputed state (srcIPNet AND srcPrefix) the
// hot path sees. Its destination matches srcGateProbeHost, so an Evaluate
// verdict turns purely on the source check: a non-nil PolicyMatch means the
// client address matched the rule's source network, nil means it did not.
func buildSrcMatchStore(t *testing.T) *PolicyStore {
	t.Helper()
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{
		Priority: 1,
		Name:     "src-gate",
		SourceIP: srcGateProbeCIDR,
		DestFQDN: srcGateProbeHost,
		Action:   ActionAllow,
	}})
	if len(ps.rules) != 1 {
		t.Fatalf("expected 1 published rule, got %d", len(ps.rules))
	}
	return ps
}

// TestBenchGate_PolicySourceCIDRUsesPrefix locks in that the per-rule source
// check actually goes through the precomputed netip.Prefix rather than
// net.(*IPNet).Contains.
//
// net.IPNet stores its address and mask as byte slices of unspecified length,
// so Contains re-derives their shape on every call (networkNumberAndMask -> To4
// -> isZeros). Profiling BenchmarkPolicyEvaluate_CIDRRules at 1000 rules
// attributed 34.4% of the ENTIRE policy evaluation to that one call. A
// netip.Prefix has its family already decided, so Contains is a masked compare;
// measured on the development machine the prefix arm is ~3x faster.
//
// GATE DESIGN — STRUCTURAL, NOT TIMED.
//
// This gate used to be a RATIO between the two matchers measured against each
// other in the same run, on the argument that a same-run ratio is
// machine-independent. That argument holds only for noise that hits BOTH arms,
// and on a shared runner it does not: the two arms were measured in contiguous
// blocks (all three samples of one, then all three of the other), each block
// ~7 ms long, so any scheduling episode longer than one ~2 ms sample inflated
// every sample of whichever arm it landed on and the best-of-three min stayed
// inflated. It went red on PR #1423 — a diff touching none of policy.go,
// clientSource, matchSourceAddr, srcPrefix or legacySourceIPMatch — with the
// IPNet arm at 1.06x its local time and the prefix arm at 2.35x. One arm
// moved; the runner was not slow.
//
// So the claim is now proven by a VERDICT instead of a duration, which is this
// repo's standing answer to exactly this failure mode (internal/connlimit, the
// latency histogram, internal/threatfeed, sanitizeLog — each rejected a
// timing/ratio gate for a structural one, on the reasoning that a gate that can
// flake gets muted). Three steps:
//
//  1. The store mutator must PRECOMPUTE the fast path (a valid srcPrefix).
//  2. The matcher must still reach the OLD verdict for every probe, checked
//     against legacySourceIPMatch — the verbatim pre-change arm that the
//     differential test uses as its correctness oracle — so a passing gate can
//     never mean "the source check stopped happening", which is the coupling
//     the ratio form also carried.
//  3. The matcher must DECIDE with srcPrefix. The published rule's srcIPNet is
//     then pointed at a DISJOINT network, so the two precomputes disagree, and
//     the real scan is run through ps.Evaluate: the probe address is inside
//     srcPrefix only and the decoy address inside srcIPNet only, so each
//     verdict names which matcher ran.
//
// The old -short skip is gone with the timing loops: the gate is now a handful
// of map-free comparisons, so there is nothing left to skip. Do not re-add it.
//
// A discriminating probe is preferred over an AST walk over matchSourceAddr
// because it proves which value actually DECIDED at run time, through the
// production scan, rather than what the source text looks like — it therefore
// also covers evalAccessRules growing its own inlined IPNet check, which an
// AST assertion scoped to matchSourceAddr would not see.
//
// Step 3 deliberately makes one rule internally inconsistent, which is legal
// nowhere else: the invariant that a populated srcPrefix describes the SAME
// network as srcIPNet is pinned by TestSrcPrefix_PrecomputeAgreesWithIPNet, and
// the inconsistency here exists only to separate two matchers that are
// otherwise indistinguishable by their output. It is applied to a store this
// test owns, after step 2 has used the consistent rule as its oracle input.
func TestBenchGate_PolicySourceCIDRUsesPrefix(t *testing.T) {
	ps := buildSrcMatchStore(t)
	rule := ps.rules[0]

	// (1) The fast path has to be wired at all.
	if !rule.srcPrefix.IsValid() {
		t.Fatal("published rule carries no srcPrefix — the fast path is not wired at all")
	}
	if rule.srcIPNet == nil {
		// Not a product defect on its own — but the discriminator in step 3
		// separates the two matchers by making them disagree, so with nothing
		// to disagree WITH it would pass whichever one ran. Failing here is the
		// honest answer: if srcIPNet is deliberately gone, this gate needs a
		// new discriminator, not a green tick.
		t.Fatal("published rule carries no srcIPNet — step 3 can no longer tell the two matchers apart")
	}

	// (2) Same verdicts as the pre-change matcher, on the CONSISTENT rule.
	var sawMatch, sawMiss bool
	for _, probe := range []string{
		srcGateProbeIP, srcGateDecoyIP, "203.0.113.0", "203.0.113.255",
		"10.0.0.1", "::ffff:203.0.113.7", "fe80::1", "not-an-ip", "",
	} {
		want := legacySourceIPMatch(rule, probe, net.ParseIP(probe))
		if got := matchSourceAddrFor(rule, probe); got != want {
			t.Fatalf("client %q: production matcher says %v, pre-change matcher says %v — "+
				"the fast path changed a verdict, so no cost claim about it is meaningful", probe, got, want)
		}
		if want {
			sawMatch = true
		} else {
			sawMiss = true
		}
	}
	if !sawMatch || !sawMiss {
		t.Fatalf("probe set no longer produces both verdicts (match=%v miss=%v) — "+
			"a matcher stuck on one answer would satisfy step 2 vacuously", sawMatch, sawMiss)
	}

	// (3) Point srcIPNet at a disjoint network and run the REAL scan: whichever
	// precompute decided is now named by the verdict.
	_, decoy, err := net.ParseCIDR(srcGateDecoyCIDR)
	if err != nil {
		t.Fatalf("parsing the decoy network %q: %v", srcGateDecoyCIDR, err)
	}
	rule.srcIPNet = decoy
	// The discriminator rests entirely on the scan evaluating THIS object:
	// evaluationSnapshot hands out the published pointers, so it does. A
	// snapshot that instead re-derived the precompute, or handed back one
	// cached at publication time, would evaluate a self-consistent rule — both
	// assertions below would then pass whichever matcher decided and the gate
	// would quietly stop proving anything. (A copy taken AFTER this line is
	// harmless: it carries the mutation. Verified by injecting both shapes.)
	// Pin the assumption rather than rely on it.
	if got := ps.evaluationSnapshot()[0]; got.srcIPNet != decoy {
		t.Fatalf("the scan does not observe this test's srcIPNet mutation (sees %v, set %v) — "+
			"the assertions below would pass whichever matcher decided, i.e. prove nothing", got.srcIPNet, decoy)
	}

	if m := ps.Evaluate(srcGateProbeIP, "", "unauth", srcGateProbeHost, nil); m == nil {
		t.Errorf("client %s matched no rule although it is inside the rule's srcPrefix (%s) — "+
			"the scan decided with srcIPNet (%s), so the srcPrefix fast path is bypassed",
			srcGateProbeIP, rule.srcPrefix, decoy)
	}
	if m := ps.Evaluate(srcGateDecoyIP, "", "unauth", srcGateProbeHost, nil); m != nil {
		t.Errorf("client %s matched rule %q although only srcIPNet (%s) contains it, not srcPrefix (%s) — "+
			"the scan decided with srcIPNet, so the srcPrefix fast path is bypassed",
			srcGateDecoyIP, m.Rule.Name, decoy, rule.srcPrefix)
	}
}
