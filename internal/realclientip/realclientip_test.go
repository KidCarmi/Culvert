package realclientip

import (
	"net/http"
	"sync"
	"testing"
)

func req(remoteAddr string, xff ...string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func mustSet(t *testing.T, r *Resolver, cidrs ...string) {
	t.Helper()
	if err := r.SetTrustedProxies(cidrs); err != nil {
		t.Fatalf("SetTrustedProxies(%v): %v", cidrs, err)
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		remote  string
		xff     []string
		want    string
	}{
		{"zero value ignores XFF", nil, "203.0.113.9:44321", []string{"1.2.3.4"}, "203.0.113.9"},
		{"untrusted peer ignores XFF", []string{"10.0.0.0/8"}, "203.0.113.9:5", []string{"8.8.8.8"}, "203.0.113.9"},
		{"trusted peer, single hop", []string{"10.0.0.0/8"}, "10.0.0.5:5", []string{"203.0.113.9"}, "203.0.113.9"},
		{"rightmost untrusted hop wins", []string{"10.0.0.0/8"}, "10.0.0.5:5", []string{"1.1.1.1, 203.0.113.9, 10.0.0.7, 10.0.0.8"}, "203.0.113.9"},
		{"all-trusted chain falls back to peer", []string{"10.0.0.0/8"}, "10.0.0.5:5", []string{"10.0.0.9, 10.0.0.7"}, "10.0.0.5"},
		{"trusted peer without XFF", []string{"10.0.0.0/8"}, "10.0.0.5:5", nil, "10.0.0.5"},
		{"malformed hop skipped", []string{"10.0.0.0/8"}, "10.0.0.5:5", []string{"203.0.113.9, garbage"}, "203.0.113.9"},
		{"only malformed hops falls back to peer", []string{"10.0.0.0/8"}, "10.0.0.5:5", []string{"garbage, ,"}, "10.0.0.5"},
		{"bare IP entry is a /32", []string{"192.0.2.1"}, "192.0.2.1:9", []string{"198.51.100.4"}, "198.51.100.4"},
		{"bare IP entry does not cover its neighbour", []string{"192.0.2.1"}, "192.0.2.2:9", []string{"198.51.100.4"}, "192.0.2.2"},
		{"IPv6 proxy and client", []string{"2001:db8::/32"}, "[2001:db8::5]:9", []string{"2606:4700::1111, 2001:db8::7"}, "2606:4700::1111"},
		{"remote addr without port", nil, "203.0.113.9", nil, "203.0.113.9"},
		{"unparseable peer is never trusted", []string{"10.0.0.0/8"}, "not-an-ip:1", []string{"8.8.8.8"}, "not-an-ip"},
		{"mapped IPv6 client is canonicalized", []string{"10.0.0.0/8"}, "10.0.0.5:5", []string{"::ffff:198.51.100.9"}, "198.51.100.9"},
		{"second header field is not dropped", []string{"10.0.0.0/8"}, "10.0.0.5:9", []string{"10.0.0.99", "203.0.113.7"}, "203.0.113.7"},
		{"forged first field loses to appended field", []string{"10.0.0.0/8"}, "10.0.0.5:9", []string{"198.51.100.1", "45.33.22.11"}, "45.33.22.11"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r Resolver
			mustSet(t, &r, c.trusted...)
			if got := r.ClientIP(req(c.remote, c.xff...)); got != c.want {
				t.Errorf("ClientIP(remote=%q, xff=%q) = %q, want %q", c.remote, c.xff, got, c.want)
			}
		})
	}
}

// A direct attacker (peer outside every trusted CIDR) can never choose the
// returned IP through X-Forwarded-For.
func TestClientIP_SpoofDefense(t *testing.T) {
	var r Resolver
	mustSet(t, &r, "10.0.0.0/8")
	for _, xff := range []string{"10.0.0.1", "127.0.0.1", "203.0.113.50, 10.0.0.1", "10.0.0.1, 10.0.0.2"} {
		if got := r.ClientIP(req("198.51.100.66:1234", xff)); got != "198.51.100.66" {
			t.Errorf("XFF=%q changed the client IP to %q", xff, got)
		}
	}
}

func TestSetTrustedProxies_Validation(t *testing.T) {
	var r Resolver
	mustSet(t, &r, "172.16.0.0/12")
	for _, bad := range [][]string{{"10.0.0.0/8", "not-an-ip"}, {"192.168.0.0/16", "bad/33"}} {
		if err := r.SetTrustedProxies(bad); err == nil {
			t.Fatalf("SetTrustedProxies(%v) accepted an invalid entry", bad)
		}
		if got := r.TrustedProxies(); len(got) != 1 || got[0] != "172.16.0.0/12" {
			t.Fatalf("failed set mutated state: %v", got)
		}
	}
	if err := r.SetTrustedProxies([]string{"nope"}); err == nil || err.Error() != "invalid IP/CIDR: nope" {
		t.Fatalf("error text changed: %v", err)
	}
	mustSet(t, &r, "", "  ", " 10.0.0.1 ", "2001:db8::1")
	if got := r.TrustedProxies(); len(got) != 2 || got[0] != "10.0.0.1/32" || got[1] != "2001:db8::1/128" {
		t.Fatalf("blank entries or bare IPs mishandled: %v", got)
	}
	mustSet(t, &r)
	if got := r.TrustedProxies(); got == nil || len(got) != 0 {
		t.Fatalf("empty list must clear to a non-nil empty slice, got %#v", got)
	}
}

// The trust set is per instance: configuring one Resolver must not make
// another honour X-Forwarded-For.
func TestResolversAreIndependent(t *testing.T) {
	var a, b Resolver
	mustSet(t, &a, "10.0.0.0/8")
	r := req("10.0.0.5:5", "203.0.113.9")
	if got := a.ClientIP(r); got != "203.0.113.9" {
		t.Fatalf("a = %q", got)
	}
	if got := b.ClientIP(r); got != "10.0.0.5" {
		t.Fatalf("b trusted XFF through a's set: %q", got)
	}
}

func TestConcurrentSetAndResolve(t *testing.T) {
	var r Resolver
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = r.SetTrustedProxies([]string{"10.0.0.0/8"})
				_ = r.SetTrustedProxies(nil)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				got := r.ClientIP(req("10.0.0.5:5", "203.0.113.9"))
				if got != "203.0.113.9" && got != "10.0.0.5" {
					t.Errorf("torn result %q", got)
					return
				}
				_ = r.TrustedProxies()
			}
		}()
	}
	wg.Wait()
}
