package main

// Regression guard for the Edge-Case Validation Lab (see edge-case-lab/).
//
// The lab drives real traffic through the proxy to fixtures bound to the TEST-NET-1
// address 192.0.2.2, which the SSRF guard treats as a PUBLIC destination. This test
// pins two invariants that the lab depends on and that must never silently change:
//
//  1. NO test-only SSRF exemption is active in a normal (production) build — loopback
//     and RFC-1918 destinations remain BLOCKED. (ssrf.AllowLoopbackForTest must never
//     leak into a non-test path.) This proves the lab does not rely on, and cannot be
//     confused with, a weakened production SSRF guard.
//  2. TEST-NET-1 (192.0.2.0/24) remains OUTSIDE the blocklist. If future SSRF hardening
//     adds it, this test fails loudly so the lab's fixture mechanism is updated
//     deliberately (a dedicated test CIDR / netns) rather than silently going red.
//
// This is a test-only addition; it changes no product behavior.
import "testing"

func TestSSRFGuard_NoTestExemptionActive(t *testing.T) {
	// Loopback + RFC-1918 + link-local metadata must be BLOCKED in a normal build.
	blocked := []string{
		"127.0.0.1:80",
		"127.0.0.53:443",
		"10.0.0.1:80",
		"192.168.1.1:80",
		"172.16.0.1:80",
		"169.254.169.254:80", // cloud metadata
	}
	for _, hp := range blocked {
		if err := isPrivateHost(hp); err == nil {
			t.Errorf("SSRF guard exemption LEAK: %s was allowed but must be blocked "+
				"(a test-only loopback exemption is active in this build)", hp)
		}
	}
}

func TestSSRFGuard_TestNetRemainsAllowed(t *testing.T) {
	// The lab's fixture address. If this ever starts failing, SSRF was hardened to
	// include TEST-NET-1 — update the lab's fixture transport (dedicated CIDR/netns)
	// rather than weakening the guard.
	for _, hp := range []string{"192.0.2.2:18091", "192.0.2.2:18453", "198.51.100.10:80", "203.0.113.10:80"} {
		if err := isPrivateHost(hp); err != nil {
			t.Errorf("TEST-NET address %s is now blocked by the SSRF guard (%v). The "+
				"edge-case lab depends on TEST-NET being dialable; migrate the fixture "+
				"mechanism to a dedicated test CIDR / network namespace before hardening.", hp, err)
		}
	}
}
