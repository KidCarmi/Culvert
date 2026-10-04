package admission

import "testing"

// Add accepts an entry in any textual spelling and stores it canonically
// (net.IP.String / IPNet.String). Remove must accept the SAME spelling the
// admin used to add it; otherwise the entry silently stays in an allow/block
// list while the API reports success.
func TestIPFilterRemove_AcceptsSpellingUsedToAdd(t *testing.T) {
	cases := []struct {
		name, entry, probe string
	}{
		{"ipv6 upper-case", "2001:DB8::1", "2001:db8::1"},
		{"ipv6 expanded", "0:0:0:0:0:0:0:1", "::1"},
		{"cidr with host bits", "10.0.0.5/8", "10.9.9.9"},
		{"ipv4-mapped", "::ffff:1.2.3.4", "1.2.3.4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewIPFilter()
			f.SetMode("block")
			if err := f.Add(tc.entry); err != nil {
				t.Fatal(err)
			}
			if f.Allowed(tc.probe) {
				t.Fatalf("precondition: %s should be blocked after Add(%q)", tc.probe, tc.entry)
			}
			f.Remove(tc.entry)
			if !f.Allowed(tc.probe) {
				t.Fatalf("Remove(%q) left the entry in place: %v", tc.entry, f.List())
			}
		})
	}
}

func TestRateLimiterRemoveExemption_AcceptsSpellingUsedToAdd(t *testing.T) {
	for _, entry := range []string{"2001:DB8::1", "0:0:0:0:0:0:0:1", "10.0.0.5/8"} {
		r := NewRateLimiter()
		if err := r.AddExemption(entry); err != nil {
			t.Fatal(err)
		}
		r.RemoveExemption(entry)
		if got := r.ListExemptions(); len(got) != 0 {
			t.Errorf("RemoveExemption(%q) left %v", entry, got)
		}
	}
}
