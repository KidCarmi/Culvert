package pac

// simulate_hardening_test.go — Palo review round-2 simulator↔compiler parity:
// private-network branch, missing-pool-override degradation, and dropped
// kind/pattern-mismatched rules.

import (
	"strings"
	"testing"
)

func simPools() map[string]Pool {
	return map[string]Pool{"main": {ID: "main", Endpoints: []PoolEndpoint{{Host: "p1.example", Port: 8080}}}}
}

func TestSimulate_PrivateNetworkBranch(t *testing.T) {
	p := Profile{ID: "hq", Name: "HQ", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateDirect}
	pools := simPools()

	// (a) no resolved IP → undetermined DNS + warning, not a guess.
	res := Simulate(p, pools, SimInput{Host: "intranet.corp"})
	// "intranet.corp" has a dot, so it is not caught by the plain-host branch;
	// the private-network rule needs DNS.
	if res.Outcome != OutcomeUndeterminedDNS {
		t.Errorf("private-network without resolvedIp should be undetermined, got %q (%+v)", res.Outcome, res)
	}

	// (b) private resolved IP → DIRECT.
	res = Simulate(p, pools, SimInput{Host: "intranet.corp", ResolvedIP: "10.1.2.3"})
	if res.Directive != "DIRECT" {
		t.Errorf("private IP should bypass to DIRECT, got %q", res.Directive)
	}

	// (c) public resolved IP → falls through to the pool terminal.
	res = Simulate(p, pools, SimInput{Host: "cdn.example", ResolvedIP: "8.8.8.8"})
	if res.Directive != "PROXY p1.example:8080" {
		t.Errorf("public IP should reach the pool terminal, got %q", res.Directive)
	}
}

func TestSimulate_MissingPoolOverrideDegradesToTerminal(t *testing.T) {
	// A use_pool rule whose pool override is absent must degrade to the profile
	// terminal (matching the compiler's writeProfileRule), not an empty result.
	p := Profile{ID: "hq", Name: "HQ", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateProxy,
		Rules: []Rule{{Kind: RuleKindDomain, Pattern: "x.example", Action: ActionUsePool, PoolID: "gone"}}}
	res := Simulate(p, simPools(), SimInput{Host: "x.example"})
	if res.Directive != "PROXY p1.example:8080" {
		t.Errorf("missing pool override should degrade to the terminal, got %q", res.Directive)
	}
	if res.Directive == "" {
		t.Error("directive must never be empty")
	}
}

func TestSimulate_KindPatternMismatchIsDropped(t *testing.T) {
	// A domain rule whose pattern is actually a wildcard is DROPPED by the
	// compiler; the simulator must not honor it either.
	p := Profile{ID: "hq", Name: "HQ", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateProxy,
		Rules: []Rule{{Kind: RuleKindDomain, Pattern: "*.foo.example", Action: ActionDirect}}}
	res := Simulate(p, simPools(), SimInput{Host: "a.foo.example"})
	if res.Directive == "DIRECT" {
		t.Errorf("a domain rule with a wildcard pattern is dropped; expected terminal, got DIRECT")
	}
	if !strings.HasPrefix(res.Directive, "PROXY ") {
		t.Errorf("dropped rule should fall through to the pool terminal, got %q", res.Directive)
	}
}
