package admission

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// A bare composite literal — IPFilter{} / RateLimiter{} — is a REACHABLE shape,
// not a hypothetical one: every field of both types is unexported, so after the
// ADR-0039 extraction it is the only literal form available outside this
// package. TestRLExemptView_BareLiteralLimiterIsSafe already pins the invariant
// for the exemption path ("it must still accept a first mutation"); these gates
// complete it for the three remaining map writes, which were nil-map panics:
//
//	IPFilter.Add / AddAll  — reached from the DP snapshot apply path
//	                         (applySnapshotAdmission → AddAll), so the panic
//	                         lands on a node applying a Control Plane push.
//	RateLimiter.Allow      — the request hot path.
//	RateLimiter.AllowClusterAware — the clustered request hot path.
//
// Every gate asserts the MUTATION TOOK EFFECT rather than merely that nothing
// panicked. "No panic" is satisfied by making Add a no-op or by never denying,
// which would turn an availability bug into a silent enforcement bypass — so a
// bare-literal filter must actually DENY, and a bare-literal limiter must
// actually refuse past its limit. The differential gate at the end is the
// strongest form: a bare instance must agree with a constructed one.

func TestBareLiteral_IPFilterAcceptsFirstMutationAndEnforces(t *testing.T) {
	f := &IPFilter{} // the only literal form package main can write
	if err := f.Add("203.0.113.7"); err != nil {
		t.Fatalf("Add on a bare-literal filter: %v", err)
	}
	f.SetMode("block")

	// The entry must actually be enforced. A no-op Add would pass a
	// panic-only assertion and silently stop blocking.
	if f.Allowed("203.0.113.7") {
		t.Fatal("blocklisted entry added to a bare-literal filter is not enforced")
	}
	if !f.Allowed("198.51.100.9") {
		t.Fatal("bare-literal filter in block mode denied an unlisted address")
	}
}

func TestBareLiteral_IPFilterAddAllIsTheSnapshotPath(t *testing.T) {
	// applySnapshotAdmission bulk-loads the CP's IP list through AddAll.
	f := &IPFilter{}
	invalid := f.AddAll([]string{"203.0.113.7", "10.0.0.0/8", "not-an-ip", ""})
	f.SetMode("allow")

	// Malformed input is still reported, not swallowed.
	if len(invalid) != 2 {
		t.Fatalf("AddAll reported %d invalid entries, want 2: %v", len(invalid), invalid)
	}
	// Allow mode: listed addresses permitted, everything else denied.
	for _, ip := range []string{"203.0.113.7", "10.1.2.3"} {
		if !f.Allowed(ip) {
			t.Errorf("allowlisted %q denied after bulk load on a bare-literal filter", ip)
		}
	}
	if f.Allowed("198.51.100.9") {
		t.Error("allow mode on a bare-literal filter admitted an unlisted address")
	}
}

func TestBareLiteral_ConfiguredLimiterEnforcesOnBothRequestPaths(t *testing.T) {
	for _, tc := range []struct {
		name  string
		allow func(*RateLimiter, string) bool
	}{
		{"Allow", func(r *RateLimiter, ip string) bool { return r.Allow(ip) }},
		{"AllowClusterAware", func(r *RateLimiter, ip string) bool { return r.AllowClusterAware(ip) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &RateLimiter{}
			r.Configure(3, time.Minute)

			const ip = "203.0.113.7"
			for i := 0; i < 3; i++ {
				if !tc.allow(r, ip) {
					t.Fatalf("request %d under the limit was denied", i+1)
				}
			}
			// Fail closed past the limit: a limiter that never denies would
			// satisfy a panic-only assertion while enforcing nothing.
			if tc.allow(r, ip) {
				t.Fatal("bare-literal limiter admitted a request past its limit")
			}
			// An unrelated client keeps its own budget.
			if !tc.allow(r, "198.51.100.9") {
				t.Fatal("per-IP budgets are not independent on a bare-literal limiter")
			}
		})
	}
}

// The first mutation and the first request are exactly where a lazily
// initialized map can be raced. Run under -race.
func TestBareLiteral_ConcurrentFirstUseIsRaceFree(t *testing.T) {
	f := &IPFilter{}
	r := &RateLimiter{}
	r.Configure(1_000_000, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = f.Add(fmt.Sprintf("203.0.113.%d", i%256))
			_ = f.Allowed("203.0.113.7")
			_ = r.Allow(fmt.Sprintf("198.51.100.%d", i%256))
			_ = r.AllowClusterAware(fmt.Sprintf("198.51.100.%d", i%256))
		}(i)
	}
	wg.Wait()

	f.SetMode("block")
	if f.Allowed("203.0.113.7") {
		t.Fatal("entry added under concurrent first use is not enforced")
	}
}

// The differential: a bare literal and a constructed instance must be
// indistinguishable. This is what keeps the lazy init from quietly becoming a
// second, divergent construction path.
func TestBareLiteral_MatchesConstructedInstance(t *testing.T) {
	entries := []string{"203.0.113.7", "10.0.0.0/8", "2001:db8::/32", "bogus", ""}
	probes := []string{"203.0.113.7", "10.1.2.3", "2001:db8::1", "198.51.100.9", "garbage", ""}

	for _, mode := range []string{"", "allow", "block", "corrupt"} {
		t.Run("mode="+mode, func(t *testing.T) {
			bare, built := &IPFilter{}, NewIPFilter()
			bareInvalid, builtInvalid := bare.AddAll(entries), built.AddAll(entries)
			bare.SetMode(mode)
			built.SetMode(mode)

			if len(bareInvalid) != len(builtInvalid) {
				t.Errorf("invalid-entry reports differ: bare=%d built=%d", len(bareInvalid), len(builtInvalid))
			}
			for _, ip := range probes {
				if got, want := bare.Allowed(ip), built.Allowed(ip); got != want {
					t.Errorf("Allowed(%q): bare=%v constructed=%v", ip, got, want)
				}
			}
			if got, want := bare.Mode(), built.Mode(); got != want {
				t.Errorf("Mode(): bare=%q constructed=%q", got, want)
			}
			if len(bare.List()) != len(built.List()) {
				t.Errorf("List(): bare=%d constructed=%d", len(bare.List()), len(built.List()))
			}
		})
	}

	bareRL, builtRL := &RateLimiter{}, NewRateLimiter()
	bareRL.Configure(2, time.Minute)
	builtRL.Configure(2, time.Minute)
	for i := 0; i < 4; i++ {
		if got, want := bareRL.Allow("203.0.113.7"), builtRL.Allow("203.0.113.7"); got != want {
			t.Errorf("Allow request %d: bare=%v constructed=%v", i+1, got, want)
		}
	}
}
