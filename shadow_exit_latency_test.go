package main

// Shadow Exit Gap Closure — Criterion 7: Shadow-evaluation latency budget (Phase A).
//
// The soak deliberately recorded latency as INFORMATIONAL only (§16) and asserted no SLA,
// on the correct principle that a performance threshold must not be invented to make a phase
// pass. This closes the criterion the right way, following Culvert's OWN performance-gate
// convention (the benchgate RATIO gates: machine-independent, "detect a meaningful regression
// without hardware-speed CI flake"): the budget is expressed as a RATIO of the Shadow path to
// a same-run, same-machine Observe baseline, NOT an absolute millisecond SLA.
//
// Why a ratio, and what it isolates. A Shadow tools/call and an Observe tools/call traverse the
// IDENTICAL listener + TLS + OAuth + policy-evaluation + durable-commit path; the ONLY delta is
// the Shadow evaluation itself (decide()) plus the larger schema-v2 evidence record in place of
// the v1 decision event. So (Shadow p99 / Observe p99) is a hardware-independent measure of the
// Shadow-evaluation + evidence OVERHEAD as a multiple of the shared base cost — exactly the
// "separate listener/auth cost from shadow-eval/evidence cost" the brief asks for. Both are
// measured over a warmed, keep-alive session (one handshake), so per-request TLS setup is not
// in the sample and the ratio is stable.
//
// The regression gate is generous by design (catch a gross regression — an accidental O(n) scan,
// a double durable commit, a per-request allocation storm — not micro-noise), with a baseline
// floor so a near-zero denominator can never manufacture a flaky ratio. The PRECISE,
// deterministic mutation guard ("bypass the latency regression gate") is a pure table test on
// the gate function itself, which cannot flake on any hardware.
//
// BOUNDARIES: this composes only the Shadow node; NO Canary, NO Production, NO LiveExecutor, NO
// upstream execution — upstream=0 is reasserted, and the measurement itself proves the Shadow
// path performs no upstream I/O (a real upstream call would dwarf the budget).

import (
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// shadowLatencyBudgetRatio is the Shadow-over-Observe p99 ceiling. Justification: the Shadow
// path adds decide() (a bounded, allocation-lean, non-executing decision) plus a schema-v2
// evidence commit in place of the v1 decision commit — both durable, both O(1) in the request.
// A correct implementation is a small multiple of the shared base; 5x is comfortably above the
// real overhead (measured ~1–2x) yet far below what a genuine regression (an unbounded scan, a
// second commit, a per-request re-hash) would produce. It is a RATIO, so it is identical on any
// CI hardware. Mirrors the repo's benchgate ratio-bound convention.
const shadowLatencyBudgetRatio = 5.0

// shadowLatencyBaselineFloor is the minimum Observe-baseline p99 below which the ratio is not
// meaningful (a sub-threshold denominator would make the ratio noise-dominated). A real TLS
// keep-alive round trip is far above this; the floor only guards a degenerate fast path.
const shadowLatencyBaselineFloor = 20 * time.Microsecond

// latencyRatioExceeds is the pure, deterministic regression gate: it reports whether the Shadow
// p99 exceeds ratio× the Observe baseline p99. It is the single decision the measured gate makes,
// factored out so the "bypass the gate" mutation is caught by a hardware-independent table test.
func latencyRatioExceeds(shadowP99, baselineP99 time.Duration, ratio float64) bool {
	return float64(shadowP99) > ratio*float64(baselineP99)
}

// percentiles returns p50/p95/p99/max of a sample (nearest-rank; input is copied+sorted).
func percentiles(samples []time.Duration) (p50, p95, p99, pMax time.Duration) {
	s := append([]time.Duration(nil), samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := func(q float64) int {
		i := int(float64(len(s)) * q)
		if i >= len(s) {
			i = len(s) - 1
		}
		return i
	}
	return s[idx(0.50)], s[idx(0.95)], s[idx(0.99)], s[len(s)-1]
}

// measureToolsCall issues n warmup + n measured echo tools/call requests on one warmed session
// and returns the measured per-request durations.
func measureToolsCall(t *testing.T, env *gapEnv, tok, sid string, warmup, n int) []time.Duration {
	t.Helper()
	for i := 0; i < warmup; i++ {
		st, _ := toolsCall(t, env.cli, env.base, tok, sid, itoaGap(1_000_000+i), toolEcho, `{"text":"warm"}`)
		req(t, st == 200, "latency warmup: status=%d", st)
	}
	out := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		st, _ := toolsCall(t, env.cli, env.base, tok, sid, itoaGap(2_000_000+i), toolEcho, `{"text":"m"}`)
		d := time.Since(start)
		req(t, st == 200, "latency measure: status=%d", st)
		out = append(out, d)
	}
	return out
}

// TestShadowExitC7_LatencyBudget measures the Shadow-evaluation latency budget as a same-run
// ratio over an Observe baseline, records p50/p95/p99/max for both, and enforces the generous
// regression ratio. It proves the budget WITHOUT an arbitrary absolute SLA and without CI
// hardware-speed flake.
func TestShadowExitC7_LatencyBudget(t *testing.T) {
	var hits int64
	resetShadowGlobalsForRun(t)
	env := newGapEnv(t, &hits, controlledInventoryJSON,
		gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoRule), nil)
	_ = approveToUsable(t, env.cat, ctrlServer, toolEcho)
	_ = approveToUsable(t, env.cat, ctrlServer, toolDanger)

	const warmup, n = 40, 300
	tok := env.token(ctrlPrincip)

	// Baseline: Observe mode — listener + auth + policy + durable decision commit, no Shadow eval.
	env.applyGateway(mcpObserveRollout(rollout.CapabilityGateway))
	req(t, getMCPRollout().gateway.CurrentMode() == rollout.ModeObserve, "observe activation failed")
	obsSid := handshake(t, env.cli, env.base, ctrlServer, tok)
	obs := measureToolsCall(t, env, tok, obsSid, warmup, n)
	oP50, oP95, oP99, oMax := percentiles(obs)

	// Shadow: the same path + decide() + schema-v2 evidence.
	env.activateShadow(controlledScope())
	shSid := handshake(t, env.cli, env.base, ctrlServer, tok)
	sh := measureToolsCall(t, env, tok, shSid, warmup, n)
	sP50, sP95, sP99, sMax := percentiles(sh)

	env.ev("C7 latency observe (n=%d): p50=%v p95=%v p99=%v max=%v", n, oP50, oP95, oP99, oMax)
	env.ev("C7 latency shadow  (n=%d): p50=%v p95=%v p99=%v max=%v", n, sP50, sP95, sP99, sMax)
	ratio := float64(sP99) / float64(oP99)
	env.ev("C7 latency budget: shadow_p99/observe_p99 = %.2fx (ceiling %.1fx, machine-independent)", ratio, shadowLatencyBudgetRatio)

	// The regression gate. Enforce only above the baseline floor (a near-zero denominator would
	// make the ratio noise, not signal); below it the absolute p99 is already trivially fast.
	if oP99 >= shadowLatencyBaselineFloor {
		req(t, !latencyRatioExceeds(sP99, oP99, shadowLatencyBudgetRatio),
			"C7: Shadow p99 %v exceeds %.1fx the Observe baseline p99 %v (%.2fx) — a meaningful Shadow-evaluation latency regression",
			sP99, shadowLatencyBudgetRatio, oP99, ratio)
	} else {
		env.ev("C7 latency: baseline p99 %v below floor %v; ratio gate skipped (absolute cost already trivial)", oP99, shadowLatencyBaselineFloor)
	}

	// No admission saturation: every one of the n measured Shadow requests completed (200); the
	// loop's per-request 200 assertion already established that, and upstream stayed at zero
	// (a Shadow evaluation performs no upstream I/O — a real call would dwarf this budget).
	req(t, atomic.LoadInt64(&hits) == 0, "SECURITY: upstream invoked during C7 latency measurement: %d", atomic.LoadInt64(&hits))
	req(t, !liveExecDepsConfigured(false), "SECURITY: live executor must stay unarmed through C7")
	env.ev("C7 VERDICT: shadow-eval latency within a %.1fx regression budget of the Observe baseline; no admission saturation; upstream=0", shadowLatencyBudgetRatio)
}

// TestShadowExitC7_RegressionGateIsNotBypassable is the deterministic mutation guard for
// "bypass the latency regression gate": the pure gate function MUST flag a Shadow p99 that
// exceeds the budget and MUST pass one within it. This is machine-independent (fixed inputs),
// so a mutation that neutered the comparison (always-false, or an infinite ratio) fails here
// with no dependence on measured timing.
func TestShadowExitC7_RegressionGateIsNotBypassable(t *testing.T) {
	base := 100 * time.Microsecond
	cases := []struct {
		name   string
		shadow time.Duration
		want   bool // want the gate to flag it as a regression
	}{
		{"within_budget_1x", 100 * time.Microsecond, false},
		{"within_budget_just_under", 499 * time.Microsecond, false},
		{"at_ceiling", 500 * time.Microsecond, false},
		{"over_budget_just_over", 501 * time.Microsecond, true},
		{"gross_regression_10x", 1000 * time.Microsecond, true},
	}
	for _, c := range cases {
		got := latencyRatioExceeds(c.shadow, base, shadowLatencyBudgetRatio)
		if got != c.want {
			t.Fatalf("%s: latencyRatioExceeds(%v, %v, %.1f) = %v, want %v — the gate must not be bypassable",
				c.name, c.shadow, base, shadowLatencyBudgetRatio, got, c.want)
		}
	}
}
