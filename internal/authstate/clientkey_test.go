package authstate

import "testing"

// The key must not be mintable at will: IPv6 collapses to its /64, IPv4 stays
// raw, and anything that is not an address shares the "" bucket.
func TestClientKeyShape(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10.0.0.1", "10.0.0.1"},
		{"::ffff:10.0.0.1", "10.0.0.1"}, // IPv4-mapped is the same IPv4 client
		{"2001:db8::1", "2001:db8::/64"},
		{"2001:db8::dead:beef", "2001:db8::/64"},
		{"2001:db8:0:1::1", "2001:db8:0:1::/64"}, // a neighbouring /64 is another client
		{"10.0.0.1:8080", ""},                    // host:port is not a resolved address
		{"not-an-ip", ""},
		{"", ""},
	} {
		if got := ClientKey(tc.in); got != tc.want {
			t.Errorf("ClientKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
