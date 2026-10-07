package admission

import (
	"fmt"
	"testing"
	"time"
)

// The zero value of both admission engines must be USABLE, not merely
// non-crashing.
//
// Why this is worth pinning. ADR-0039 moved IPFilter and RateLimiter out of
// package main into this package, which made both types EXPORTED and therefore
// constructible by any caller in the module as a composite literal. Their
// constructors (NewIPFilter, NewRateLimiter) are what initialise the maps the
// write paths assign into, and nothing in the type system or in the ADR-0039
// boundary wall requires a caller to use them. Configure() is the sharp edge:
// it sets only the three atomics (limit, window, enabled) and initialises no
// map, so a zero-value RateLimiter is ONE ordinary call from reporting
// Enabled() and reaching a write into a nil map.
//
// The pre-guard failure mode was a panic in the request path. It was contained
// on both paths that reach it — recoverGoroutine in handleSOCKS5 and
// net/http's own per-request recovery — so it failed CLOSED and was never a
// bypass; but it cost the session and recorded a crash where a rate-limit
// verdict belonged. The IPFilter half was worse: addLocked is reached from
// applySnapshotAdmission on the DP config-apply path, which runs in a
// goroutine with NO panic guard, so there a nil-map panic would terminate the
// whole appliance — proxy, admin UI and health endpoints together — the
// outcome CHAOS-57 and CHAOS-66 both exist to prevent.
//
// These gates assert the ADMISSION VERDICT, never just the absence of a panic.
// "Did not panic" is satisfied by an engine that admits everything, which would
// be a rate limiter that does not limit — so each gate drives the configured
// limit to its boundary and requires the refusal.

// rlVerdicts drives n requests from one IP through allow and returns the
// verdict sequence, so a gate can assert enforcement rather than survival.
func rlVerdicts(t *testing.T, allow func(string) bool, ip string, n int) []bool {
	t.Helper()
	out := make([]bool, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, allow(ip))
	}
	return out
}

func wantVerdicts(t *testing.T, got []bool, want []bool, what string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d verdicts, want %d", what, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: verdict sequence %v, want %v", what, got, want)
		}
	}
}

// TestZeroValueRateLimiter_EnforcesLimitWithoutPanicking is the defect gate for
// RateLimiter.Allow. It fails by PANIC against the unguarded shape.
func TestZeroValueRateLimiter_EnforcesLimitWithoutPanicking(t *testing.T) {
	r := &RateLimiter{} // deliberately NOT NewRateLimiter: every shard map is nil
	r.Configure(2, time.Minute)
	if !r.Enabled() {
		t.Fatal("Configure(2, …) must enable the limiter — otherwise this gate proves nothing")
	}
	got := rlVerdicts(t, r.Allow, "198.51.100.7", 4)
	wantVerdicts(t, got, []bool{true, true, false, false}, "zero-value Allow")
}

// TestZeroValueRateLimiter_ClusterAwareEnforcesLimitWithoutPanicking covers the
// SECOND admission entry point. Both gates are required: before this change the
// identical cold branch was written out twice, and a guard added to one copy
// would have left the other panicking while this file still went green.
func TestZeroValueRateLimiter_ClusterAwareEnforcesLimitWithoutPanicking(t *testing.T) {
	r := &RateLimiter{}
	r.Configure(2, time.Minute)
	got := rlVerdicts(t, r.AllowClusterAware, "198.51.100.8", 4)
	wantVerdicts(t, got, []bool{true, true, false, false}, "zero-value AllowClusterAware")
}

// TestZeroValueIPFilter_EnforcesModeWithoutPanicking is the defect gate for
// IPFilter.addLocked, reached through both the single-entry and bulk paths.
func TestZeroValueIPFilter_EnforcesModeWithoutPanicking(t *testing.T) {
	for _, tc := range []struct {
		name string
		load func(*IPFilter)
	}{
		{"Add", func(f *IPFilter) {
			if err := f.Add("203.0.113.5"); err != nil {
				t.Fatalf("Add: %v", err)
			}
		}},
		{"AddAll", func(f *IPFilter) {
			if bad := f.AddAll([]string{"203.0.113.5"}); len(bad) != 0 {
				t.Fatalf("AddAll rejected a valid entry: %v", bad)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &IPFilter{} // deliberately NOT NewIPFilter: f.single is nil
			f.SetMode("allow")
			tc.load(f)
			// Allow-list mode: the loaded address is admitted, everything else
			// is refused. Asserting BOTH directions is what makes this a gate
			// on the filter rather than on the absence of a panic.
			if !f.Allowed("203.0.113.5") {
				t.Error("loaded address must be admitted in allow mode")
			}
			if f.Allowed("203.0.113.6") {
				t.Error("unlisted address must be refused in allow mode")
			}
		})
	}
}

// TestGuardedZeroValueMatchesConstructed is the CONTROL. The cheapest way to
// pass every gate above is to make the engines permissive, and the second
// cheapest is to change what a CONSTRUCTED engine does. This requires the
// guarded zero value and the constructor to produce the SAME verdict sequence
// over a mixed workload, so the guard is proved to be additive — it may make an
// uninitialised engine work, and it may not alter an initialised one.
func TestGuardedZeroValueMatchesConstructed(t *testing.T) {
	const limit = 3
	ips := []string{"192.0.2.10", "192.0.2.11", "192.0.2.10", "192.0.2.12", "192.0.2.10", "192.0.2.10"}

	run := func(r *RateLimiter) []bool {
		r.Configure(limit, time.Minute)
		out := make([]bool, 0, len(ips))
		for _, ip := range ips {
			out = append(out, r.Allow(ip))
		}
		return out
	}

	zero, made := run(&RateLimiter{}), run(NewRateLimiter())
	if fmt.Sprint(zero) != fmt.Sprint(made) {
		t.Fatalf("zero-value verdicts %v != constructed verdicts %v — the guard changed admission behaviour", zero, made)
	}
	// Not vacuous: the shared workload must actually reach a refusal, or two
	// all-admit sequences would compare equal and prove nothing.
	refused := false
	for _, v := range made {
		if !v {
			refused = true
		}
	}
	if !refused {
		t.Fatal("workload never reached the limit; this control would pass against a limiter that admits everything")
	}
}

// TestZeroValueIPFilterMatchesConstructed is the IPFilter half of the control.
func TestZeroValueIPFilterMatchesConstructed(t *testing.T) {
	probes := []string{"203.0.113.5", "203.0.113.6", "10.0.0.1", "not-an-ip"}
	load := func(f *IPFilter) []bool {
		f.SetMode("block")
		f.AddAll([]string{"203.0.113.5", "10.0.0.0/8"})
		out := make([]bool, 0, len(probes))
		for _, p := range probes {
			out = append(out, f.Allowed(p))
		}
		return out
	}
	zero, made := load(&IPFilter{}), load(NewIPFilter())
	if fmt.Sprint(zero) != fmt.Sprint(made) {
		t.Fatalf("zero-value verdicts %v != constructed verdicts %v — the guard changed filtering behaviour", zero, made)
	}
	if fmt.Sprint(made) == fmt.Sprint([]bool{true, true, true, true}) {
		t.Fatal("block-mode probes never reached a refusal; this control would pass against a filter that admits everything")
	}
}
