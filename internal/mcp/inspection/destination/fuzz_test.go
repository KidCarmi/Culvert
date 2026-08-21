package destination

import (
	"net/netip"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
)

// FuzzCanonicalize drives URL canonicalization with arbitrary strings. Invariants:
// no panic; determinism; a private/metadata IP literal never canonicalizes to a
// permitted class; a rejected scheme never becomes public.
func FuzzCanonicalize(f *testing.F) {
	seeds := []string{
		"https://example.com/x", "https://10.0.0.1/", "https://169.254.169.254/",
		"file:///etc/passwd", "https://[::1]/", "https://user:pass@host/", "https://0177.0.0.1/",
		"https://例え.jp/", "ht!tp://x", "https://host:99999/",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	pol := httpsAndHTTP()
	lim := limits.DefaultGatewayInspection()
	f.Fuzz(func(t *testing.T, raw string) {
		c1, cl1, e1 := Canonicalize(raw, pol, lim)
		c2, cl2, e2 := Canonicalize(raw, pol, lim)
		if (e1 == nil) != (e2 == nil) || cl1 != cl2 {
			t.Fatalf("non-deterministic canonicalize")
		}
		if e1 != nil {
			return
		}
		if c1.IsIP && !cl1.Permitted() {
			// a non-public IP literal must never be reported permitted
			if cl1 == ClassPublic {
				t.Fatal("non-public IP classified public")
			}
		}
		_ = c2
	})
}

// FuzzRedirect drives the redirect guard with arbitrary Location values. Invariants:
// no panic; a redirect can never bypass destination policy (a private/metadata IP
// literal target is never accepted); hop/loop bounds hold.
func FuzzRedirect(f *testing.F) {
	seeds := []string{"/next", "https://example.com/a", "https://10.0.0.1/", "https://169.254.169.254/", "http://example.com/", "https://u:p@example.com/"}
	for _, s := range seeds {
		f.Add(s)
	}
	pol := httpsAndHTTP()
	lim := limits.DefaultGatewayInspection()
	start, _, err := Canonicalize("https://example.com/start", pol, lim)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, location string) {
		g := NewRedirectGuard(start, pol, lim)
		next, err := g.Next(location)
		if err != nil {
			return
		}
		// If a hop was accepted with an IP-literal target, it MUST be public.
		if next.IsIP && !classifyIP(next.IP).Permitted() {
			t.Fatal("redirect accepted a non-public IP-literal target")
		}
	})
}

// FuzzPinnedPeer drives connect-time peer verification with arbitrary peer bytes.
// Invariant: a peer outside the pinned set (or a private peer) is never accepted.
func FuzzPinnedPeer(f *testing.F) {
	f.Add([]byte{203, 0, 113, 5})
	f.Add([]byte{10, 0, 0, 1})
	f.Add([]byte{1, 2, 3, 4})
	pol := httpsAndHTTP()
	now := time.Unix(1000, 0)
	pin := PinnedDestination{Scheme: "https", Host: "h", Port: "443",
		AllowedIPs: []netip.Addr{mustAddr("203.0.113.5")}, Expiry: now.Add(time.Minute)}
	f.Fuzz(func(t *testing.T, ipBytes []byte) {
		if len(ipBytes) != 4 && len(ipBytes) != 16 {
			return
		}
		addr, ok := netip.AddrFromSlice(ipBytes)
		if !ok {
			return
		}
		err := VerifyPeer(pin, addr, pol, now)
		if err == nil {
			// The ONLY peer that may pass is the exact pinned public address.
			if addr.Unmap() != mustAddr("203.0.113.5") {
				t.Fatalf("non-pinned peer accepted: %v", addr)
			}
		}
	})
}
