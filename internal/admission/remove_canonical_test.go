package admission

import "testing"

// An admin removes an entry by typing the same text they added it with. Add
// canonicalises (ParseIP().String() / the CIDR network address), so Remove must
// canonicalise the same way or the revocation is silently a no-op while the
// API still answers ok — in allow mode that leaves a revoked IP admitted.
func TestIPFilterRemove_AcceptsTheSpellingAddAccepted(t *testing.T) {
	cases := []struct{ name, add, probe string }{
		{"ipv6 uppercase", "2001:DB8::1", "2001:db8::1"},
		{"ipv6 expanded", "2001:0db8:0:0:0:0:0:1", "2001:db8::1"},
		{"cidr with host bits", "10.1.2.3/8", "10.9.9.9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := NewIPFilter()
			f.SetMode("allow")
			if err := f.Add(c.add); err != nil {
				t.Fatal(err)
			}
			if !f.Allowed(c.probe) {
				t.Fatalf("precondition: %s should be allowed after Add(%q)", c.probe, c.add)
			}
			f.Remove(c.add)
			if f.Allowed(c.probe) {
				t.Fatalf("Remove(%q) left %s allowed; entries=%v", c.add, c.probe, f.List())
			}
		})
	}
}

func TestRateLimitRemoveExemption_AcceptsTheSpellingAddAccepted(t *testing.T) {
	cases := []struct{ name, add, probe string }{
		{"ipv6 uppercase", "2001:DB8::1", "2001:db8::1"},
		{"cidr with host bits", "10.1.2.3/8", "10.9.9.9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewRateLimiter()
			if err := r.AddExemption(c.add); err != nil {
				t.Fatal(err)
			}
			if !r.IsExempt(c.probe) {
				t.Fatalf("precondition: %s should be exempt", c.probe)
			}
			r.RemoveExemption(c.add)
			if r.IsExempt(c.probe) {
				t.Fatalf("RemoveExemption(%q) left %s exempt; entries=%v", c.add, c.probe, r.ListExemptions())
			}
		})
	}
}
