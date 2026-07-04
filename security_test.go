package main

import (
	"testing"
	"time"
)

// ── IPFilter tests ────────────────────────────────────────────────────────────

func freshIPF() *IPFilter {
	return &IPFilter{single: map[string]bool{}}
}

func TestIPFilter_ModeOff(t *testing.T) {
	f := freshIPF()
	// With no mode set, everything is allowed.
	for _, ip := range []string{"1.2.3.4", "192.168.1.1", "10.0.0.1"} {
		if !f.Allowed(ip) {
			t.Errorf("mode off: expected %s to be allowed", ip)
		}
	}
}

// TestIPFilter_CorruptModeDeniesAll pins the fail-closed contract: an
// unrecognized (corrupt) mode reaching the filter through a raw
// persistence/snapshot path (config reload / admin_settings restore /
// config-version rollback / cluster ConfigSnapshot) must DENY ALL traffic.
// Denying-all (not coercing to "block") is the only safe choice: a corrupted
// allowlist deployment coerced to a blocklist would admit every non-listed IP
// (fail open). Here we prove BOTH a listed and an unlisted IP are denied.
func TestIPFilter_CorruptModeDeniesAll(t *testing.T) {
	for _, bad := range []string{"deny", "blockk", "ALLOW", "off", "enabled", "x"} {
		f := freshIPF()
		f.SetMode(bad)
		f.Add("203.0.113.9") //nolint:errcheck // valid IP literal, Add cannot fail here
		if f.Allowed("203.0.113.9") {
			t.Errorf("SetMode(%q): listed IP allowed — corrupt mode must deny all (fail closed)", bad)
		}
		if f.Allowed("198.51.100.7") {
			t.Errorf("SetMode(%q): unlisted IP allowed — corrupt allowlist must NOT become a permissive blocklist", bad)
		}
	}
}

// TestIPFilter_ValidModesAndDisabled pins that the three valid states behave
// correctly: "" disables (all pass), and "allow"/"block" round-trip through
// Mode() unchanged.
func TestIPFilter_ValidModesAndDisabled(t *testing.T) {
	for _, ok := range []string{"allow", "block", ""} {
		f := freshIPF()
		f.SetMode(ok)
		if got := f.Mode(); got != ok {
			t.Errorf("SetMode(%q): Mode() = %q, want unchanged", ok, got)
		}
	}
	// "" is disabled — every IP passes.
	f := freshIPF()
	f.SetMode("")
	f.Add("203.0.113.9") //nolint:errcheck // valid IP literal
	if !f.Allowed("203.0.113.9") || !f.Allowed("8.8.8.8") {
		t.Error(`empty mode must disable the filter (all IPs allowed)`)
	}
}

func TestIPFilter_AllowMode(t *testing.T) {
	f := freshIPF()
	f.SetMode("allow")
	f.Add("192.168.1.5") //nolint:errcheck
	f.Add("10.0.0.0/24") //nolint:errcheck

	allowed := []string{"192.168.1.5", "10.0.0.1", "10.0.0.254"}
	for _, ip := range allowed {
		if !f.Allowed(ip) {
			t.Errorf("allow mode: expected %s to be allowed", ip)
		}
	}

	denied := []string{"8.8.8.8", "192.168.1.6", "172.16.0.1"}
	for _, ip := range denied {
		if f.Allowed(ip) {
			t.Errorf("allow mode: expected %s to be denied", ip)
		}
	}
}

func TestIPFilter_BlockMode(t *testing.T) {
	f := freshIPF()
	f.SetMode("block")
	f.Add("1.2.3.4")      //nolint:errcheck
	f.Add("10.10.0.0/16") //nolint:errcheck

	blocked := []string{"1.2.3.4", "10.10.1.1", "10.10.255.254"}
	for _, ip := range blocked {
		if f.Allowed(ip) {
			t.Errorf("block mode: expected %s to be denied", ip)
		}
	}

	allowed := []string{"8.8.8.8", "192.168.1.1"}
	for _, ip := range allowed {
		if !f.Allowed(ip) {
			t.Errorf("block mode: expected %s to be allowed", ip)
		}
	}
}

func TestIPFilter_InvalidEntry(t *testing.T) {
	f := freshIPF()
	if err := f.Add("not-an-ip"); err == nil {
		t.Error("expected error for invalid IP entry")
	}
}

func TestIPFilter_Remove(t *testing.T) {
	f := freshIPF()
	f.SetMode("block")
	f.Add("1.2.3.4") //nolint:errcheck
	f.Remove("1.2.3.4")
	if !f.Allowed("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be allowed after Remove")
	}
}

func TestIPFilter_List(t *testing.T) {
	f := freshIPF()
	f.Add("5.5.5.5")    //nolint:errcheck
	f.Add("10.0.0.0/8") //nolint:errcheck
	list := f.List()
	if len(list) != 2 {
		t.Errorf("expected 2 entries, got %d", len(list))
	}
}

// ── RateLimiter tests ─────────────────────────────────────────────────────────

func freshRL() *RateLimiter {
	return newRateLimiter()
}

func TestRateLimiter_Disabled(t *testing.T) {
	r := freshRL()
	// Not configured → always allowed.
	for i := 0; i < 100; i++ {
		if !r.Allow("1.2.3.4") {
			t.Error("disabled rate limiter should always allow")
		}
	}
}

func TestRateLimiter_BasicLimit(t *testing.T) {
	r := freshRL()
	r.Configure(5, time.Minute)

	ip := "1.2.3.4"
	for i := 0; i < 5; i++ {
		if !r.Allow(ip) {
			t.Fatalf("request %d should be allowed (limit=5)", i+1)
		}
	}
	// 6th request must be denied.
	if r.Allow(ip) {
		t.Error("6th request should be rate-limited")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	r := freshRL()
	r.Configure(2, time.Minute)

	if !r.Allow("1.1.1.1") {
		t.Error("ip1 req1 should be allowed")
	}
	if !r.Allow("1.1.1.1") {
		t.Error("ip1 req2 should be allowed")
	}
	if r.Allow("1.1.1.1") {
		t.Error("ip1 req3 should be denied")
	}

	// Different IP has its own bucket.
	if !r.Allow("2.2.2.2") {
		t.Error("ip2 req1 should be allowed")
	}
	if !r.Allow("2.2.2.2") {
		t.Error("ip2 req2 should be allowed")
	}
	if r.Allow("2.2.2.2") {
		t.Error("ip2 req3 should be denied")
	}
}

func TestRateLimiter_Reconfigure(t *testing.T) {
	r := freshRL()
	r.Configure(3, time.Minute)
	if !r.Enabled() {
		t.Error("should be enabled after Configure(3,...)")
	}
	if r.Limit() != 3 {
		t.Errorf("Limit() = %d, want 3", r.Limit())
	}
	r.Configure(0, time.Minute)
	if r.Enabled() {
		t.Error("should be disabled after Configure(0,...)")
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	r := freshRL()
	r.Configure(100, 10*time.Millisecond)
	r.Allow("stale-ip")
	time.Sleep(30 * time.Millisecond)
	r.Cleanup()
	// After cleanup the stale IP should be gone — Allow should work fresh.
	// Verify by checking that the IP gets a fresh budget.
	r.Configure(1, 10*time.Millisecond)
	if !r.Allow("stale-ip") {
		t.Error("stale client should have been cleaned up and get fresh budget")
	}
}
