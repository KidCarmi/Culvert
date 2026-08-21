package pac

// inventory_generated_test.go — closes gap #1 (finite matrix): a seeded,
// deterministic generator produces a large population of random profiles and
// asserts the no-under-report invariant on every one of them. Seeded so the run
// is reproducible under -count/-shuffle (no wall-clock, no unseeded rand).
// Also closes gap #2 for the engine: exhaustive atoiPrefix branch coverage.

import (
	"fmt"
	"math/rand"
	"testing"
)

// TestInventory_NoUnderReport_Generated fuzzes ~600 random profiles through the
// evaluator and the inventory and asserts the security invariant holds on all:
// any (profile, input) that yields a definite DIRECT (or a DirectPossible
// terminal) implies the inventory flags that profile DIRECT-capable.
func TestInventory_NoUnderReport_Generated(t *testing.T) {
	const seed int64 = 0x1F2E3D4C5B6A7988 // fixed → reproducible
	// #nosec G404 -- deterministic seeded generator for reproducible test
	// fuzzing; not a security context.
	rng := rand.New(rand.NewSource(seed))

	modes := []string{ModeSecure, ModeBalanced, ModeAvailability}
	privs := []string{PrivateProxy, PrivateDirect}
	kinds := []string{RuleKindDomain, RuleKindSuffix, RuleKindWildcard, RuleKindCIDR4}
	actions := []string{ActionDirect, ActionUsePool}
	patterns := map[string][]string{
		RuleKindDomain:   {"vendor.example", "corp.example", "bad\"quote", ""},
		RuleKindSuffix:   {"cdn.example", "svc.example", ""},
		RuleKindWildcard: {"*.cdn.example", "*.corp.example", "bad quote"},
		RuleKindCIDR4:    {"10.0.0.0/16", "192.168.0.0/24", "not-a-cidr", "10.0.0.0/33"},
	}
	pools := map[string]Pool{"p": {ID: "p", Name: "P", Endpoints: []PoolEndpoint{{Host: "proxy.example", Port: 8080}}}}

	// Host battery incl. resolved IPs so cidr/private evaluate definitely.
	inputs := []SimInput{
		{Host: "intranet"},
		{Host: "www.example.com", ResolvedIP: "8.8.8.8"},
		{Host: "vendor.example", ResolvedIP: "8.8.8.8"},
		{Host: "a.cdn.example", ResolvedIP: "8.8.8.8"},
		{Host: "svc.corp.example", ResolvedIP: "10.0.0.9"},
		{Host: "host.local", ResolvedIP: "192.168.0.4"},
	}

	const n = 600
	for i := 0; i < n; i++ {
		p := Profile{
			ID: fmt.Sprintf("g%d", i), Name: fmt.Sprintf("g%d", i), Enabled: rng.Intn(2) == 0,
			PoolID: "p", PrivateNetworks: privs[rng.Intn(len(privs))],
			AvailabilityMode: modes[rng.Intn(len(modes))], Revision: 1,
		}
		for r := 0; r < rng.Intn(4); r++ {
			k := kinds[rng.Intn(len(kinds))]
			pats := patterns[k]
			p.Rules = append(p.Rules, Rule{
				Kind: k, Pattern: pats[rng.Intn(len(pats))],
				Action: actions[rng.Intn(len(actions))], PoolID: "p",
			})
		}

		inv := BuildDirectInventory(ProfilesConfig{Pools: []Pool{pools["p"]}, Profiles: []Profile{p}})
		reported := inv.Profiles[0].DirectCapable

		var observed bool
		var why string
		for _, in := range inputs {
			res := Simulate(p, pools, in)
			if res.Outcome == OutcomeMatched && res.Directive == "DIRECT" {
				observed, why = true, in.Host+"→DIRECT"
				break
			}
			if res.DirectPossible {
				observed, why = true, in.Host+"→DirectPossible("+res.Directive+")"
				break
			}
		}
		if observed && !reported {
			t.Fatalf("UNDER-REPORT (seed %#x, profile #%d %+v): evaluator DIRECT via %s but inventory not capable (%+v)",
				seed, i, p, why, inv.Profiles[0].DirectPaths)
		}
	}
}

// TestAtoiPrefix_AllBranches closes gap #2 for atoiPrefix: every reject path
// (empty, too long, non-digit, out-of-range) and the valid range.
func TestAtoiPrefix_AllBranches(t *testing.T) {
	cases := []struct {
		in     string
		want   int
		wantOK bool
	}{
		{"", 0, false},    // empty
		{"123", 0, false}, // len > 2
		{"1a", 0, false},  // non-digit
		{"33", 0, false},  // > 32
		{"99", 0, false},  // > 32, two digits
		{"0", 0, true},    // valid low
		{"8", 8, true},    // valid single
		{"16", 16, true},  // valid two-digit
		{"32", 32, true},  // valid boundary
	}
	for _, c := range cases {
		got, ok := atoiPrefix(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("atoiPrefix(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}
