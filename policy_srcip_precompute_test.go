package main

// Tests for the precomputed source-CIDR matcher (srcIPNet). The contract
// mirrors normFQDN: sortLocked() precomputes the parsed network on every
// mutation, Evaluate reuses one client-IP parse across all CIDR rules, and a
// rule that never passed through the mutators (srcIPNet nil) falls back to the
// parsing matchIPOrCIDR path — so both paths must agree on every input shape.

import "testing"

// TestEvaluate_SourceCIDR_PrecomputeParity drives each SourceIP shape through
// BOTH matchers: the store path (ReplaceAll → sortLocked → precomputed
// srcIPNet, read by Evaluate) and the fallback path (a hand-built rule that
// never saw sortLocked). Any divergence between the two is a regression in the
// precompute contract.
func TestEvaluate_SourceCIDR_PrecomputeParity(t *testing.T) {
	cases := []struct {
		name     string
		sourceIP string
		clientIP string
		want     bool
	}{
		{"ipv4-cidr-inside", "10.0.0.0/8", "10.1.2.3", true},
		{"ipv4-cidr-outside", "10.0.0.0/8", "192.168.1.1", false},
		{"ipv4-cidr-last-addr", "203.0.113.0/24", "203.0.113.255", true},
		{"ipv6-cidr-inside", "2001:db8::/32", "2001:db8::1", true},
		{"ipv6-cidr-outside", "2001:db8::/32", "2001:db9::1", false},
		{"plain-ip-match", "203.0.113.7", "203.0.113.7", true},
		{"plain-ip-mismatch", "203.0.113.7", "203.0.113.8", false},
		{"invalid-cidr-fails-closed", "10.0.0.0/99", "10.1.2.3", false},
		{"invalid-client-ip-fails-closed", "10.0.0.0/8", "not-an-ip", false},
		{"empty-client-ip-fails-closed", "10.0.0.0/8", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Store path: the rule flows through ReplaceAll → sortLocked, so
			// Evaluate uses the precomputed srcIPNet (when the CIDR is valid).
			ps := &PolicyStore{}
			ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "src-scoped", SourceIP: c.sourceIP, Action: ActionAllow}})
			got := ps.Evaluate(c.clientIP, "", "unauth", "target.example.com", nil) != nil
			if got != c.want {
				t.Errorf("Evaluate (precomputed): SourceIP=%q clientIP=%q = %v, want %v", c.sourceIP, c.clientIP, got, c.want)
			}

			// Fallback path: a rule built outside the mutators has srcIPNet nil
			// and must produce the identical decision via matchIPOrCIDR.
			raw := &PolicyRule{SourceIP: c.sourceIP}
			if fb := matchSource(raw, c.clientIP, "", "unauth", nil); fb != c.want {
				t.Errorf("matchSource (fallback): SourceIP=%q clientIP=%q = %v, want %v", c.sourceIP, c.clientIP, fb, c.want)
			}
		})
	}
}

// TestSourceCIDR_PrecomputeInvalidatedOnUpdate guards cache invalidation: an
// Update that changes SourceIP must re-precompute, never serve the stale
// network of the replaced rule.
func TestSourceCIDR_PrecomputeInvalidatedOnUpdate(t *testing.T) {
	ps := &PolicyStore{}
	added := ps.Add(PolicyRule{Priority: 1, Name: "src-scoped", SourceIP: "10.0.0.0/8", Action: ActionAllow})
	if ps.Evaluate("10.1.2.3", "", "unauth", "target.example.com", nil) == nil {
		t.Fatal("expected 10.1.2.3 to match 10.0.0.0/8 before update")
	}
	if !ps.Update(added.Priority, PolicyRule{Priority: added.Priority, Name: "src-scoped", SourceIP: "172.16.0.0/12", Action: ActionAllow}) {
		t.Fatal("Update returned false")
	}
	if ps.Evaluate("10.1.2.3", "", "unauth", "target.example.com", nil) != nil {
		t.Error("10.1.2.3 still matches after SourceIP changed to 172.16.0.0/12 — stale precomputed srcIPNet")
	}
	if ps.Evaluate("172.20.1.2", "", "unauth", "target.example.com", nil) == nil {
		t.Error("172.20.1.2 does not match the updated 172.16.0.0/12 rule")
	}
}

// TestEvaluate_MixedCIDRAndPlainIPRules exercises one scan across CIDR-scoped,
// plain-IP-scoped, and unscoped rules so the single lazy client-IP parse is
// shared across CIDR rules while plain-IP rules keep exact string matching.
func TestEvaluate_MixedCIDRAndPlainIPRules(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "cidr-miss", SourceIP: "192.168.0.0/16", DestFQDN: "*", Action: ActionDrop},
		{Priority: 2, Name: "plain-miss", SourceIP: "203.0.113.9", DestFQDN: "*", Action: ActionDrop},
		{Priority: 3, Name: "cidr-hit", SourceIP: "10.0.0.0/8", DestFQDN: "*", Action: ActionAllow},
	})
	m := ps.Evaluate("10.42.0.7", "", "unauth", "target.example.com", nil)
	if m == nil || m.Rule.Name != "cidr-hit" {
		t.Fatalf("expected cidr-hit match, got %+v", m)
	}
}
