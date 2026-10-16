package admission

import (
	"testing"
)

func TestIPFilter_AddRemove(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	if err := f.Add("10.0.0.1"); err != nil {
		t.Fatalf("Add IP error: %v", err)
	}
	if err := f.Add("192.168.0.0/24"); err != nil {
		t.Fatalf("Add CIDR error: %v", err)
	}
	list := f.List()
	if len(list) < 2 {
		t.Errorf("List should contain 2 entries, got %d", len(list))
	}
	f.Remove("10.0.0.1")
	f.Remove("192.168.0.0/24")
}

func TestIPFilter_SetGetMode(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	f.SetMode("allow")
	if got := f.Mode(); got != "allow" {
		t.Errorf("Mode() = %q, want allow", got)
	}
}

func TestRateLimiter_Window(_ *testing.T) {
	// An independently constructed limiter supports the same accessors.
	rl := NewRateLimiter()
	w := rl.Window()
	_ = w
	l := rl.Limit()
	_ = l
}
