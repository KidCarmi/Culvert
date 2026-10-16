package admission

import (
	"testing"
	"time"
)

func TestIPFilterClearAll(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	_ = f.Add("10.0.0.1")
	_ = f.Add("192.168.0.0/16")
	if len(f.List()) == 0 {
		t.Fatal("expected entries before ClearAll")
	}
	f.ClearAll()
	if len(f.List()) != 0 {
		t.Error("expected empty list after ClearAll")
	}
}

func TestRateLimiterExemption(t *testing.T) {
	r := NewRateLimiter()
	r.Configure(1, time.Minute) // 1 req/min

	// Add exemptions.
	if err := r.AddExemption("10.0.0.5"); err != nil {
		t.Fatalf("AddExemption IP: %v", err)
	}
	if err := r.AddExemption("192.168.0.0/16"); err != nil {
		t.Fatalf("AddExemption CIDR: %v", err)
	}

	// Invalid entry.
	if err := r.AddExemption("not-an-ip"); err == nil {
		t.Error("expected error for invalid IP")
	}

	// Check exemption.
	if !r.IsExempt("10.0.0.5") {
		t.Error("10.0.0.5 should be exempt")
	}
	if !r.IsExempt("192.168.1.100") {
		t.Error("192.168.1.100 should be exempt (CIDR match)")
	}
	if r.IsExempt("8.8.8.8") {
		t.Error("8.8.8.8 should not be exempt")
	}
	if r.IsExempt("not-an-ip") {
		t.Error("invalid IP should not be exempt")
	}

	// Exempt IP should always be allowed even when rate limited.
	if !r.Allow("10.0.0.5") {
		t.Error("exempt IP should always be allowed")
	}
	if !r.Allow("10.0.0.5") {
		t.Error("exempt IP should always be allowed (2nd request)")
	}

	// List exemptions.
	list := r.ListExemptions()
	if len(list) != 2 {
		t.Errorf("expected 2 exemptions, got %d", len(list))
	}

	// Remove exemption.
	r.RemoveExemption("10.0.0.5")
	if r.IsExempt("10.0.0.5") {
		t.Error("10.0.0.5 should no longer be exempt")
	}
	r.RemoveExemption("192.168.0.0/16")
	if r.IsExempt("192.168.1.100") {
		t.Error("192.168.1.100 should no longer be exempt")
	}
}
