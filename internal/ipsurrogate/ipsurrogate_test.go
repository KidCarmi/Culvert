package ipsurrogate

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func on(n int) *Store { s := New(n); s.SetEnabled(true); return s }

func alice() Identity {
	return Identity{Sub: "alice", Email: "alice@corp", Provider: "corp", Groups: []string{"eng"}}
}

func TestBindLookupExpiry(t *testing.T) {
	s := on(8)
	a := netip.MustParseAddr("10.1.2.3")
	if _, err := s.Bind(a, alice(), time.Hour, t0); err != nil {
		t.Fatal(err)
	}
	if id, ok := s.Lookup(a, t0.Add(59*time.Minute)); !ok || id.Sub != "alice" || id.Groups[0] != "eng" {
		t.Fatalf("live lookup: %+v %v", id, ok)
	}
	if _, ok := s.Lookup(a, t0.Add(time.Hour)); ok {
		t.Fatal("binding outlived its expiry")
	}
	if _, ok := s.Lookup(netip.MustParseAddr("10.1.2.4"), t0); ok {
		t.Fatal("unbound address hit")
	}
}

// A disabled store answers nothing, whatever it holds.
func TestDisabledMisses(t *testing.T) {
	s := on(8)
	a := netip.MustParseAddr("10.1.2.3")
	if _, err := s.Bind(a, alice(), time.Hour, t0); err != nil {
		t.Fatal(err)
	}
	s.SetEnabled(false)
	if _, ok := s.Lookup(a, t0); ok {
		t.Fatal("disabled store answered a lookup")
	}
	s.SetEnabled(true)
	if _, ok := s.Lookup(a, t0); !ok {
		t.Fatal("re-enabling lost the binding")
	}
}

// An IPv4-mapped IPv6 address is the same client as the plain IPv4 one.
func TestMappedAddressIsTheSameClient(t *testing.T) {
	s := on(8)
	if _, err := s.Bind(netip.MustParseAddr("::ffff:10.1.2.3"), alice(), time.Hour, t0); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(netip.MustParseAddr("10.1.2.3"), t0); !ok {
		t.Fatal("mapped bind not found by the plain address")
	}
	if s.Len() != 1 {
		t.Fatalf("len %d", s.Len())
	}
}

func TestRevokeAndRevokeSubject(t *testing.T) {
	s := on(8)
	a, b, c := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")
	_, _ = s.Bind(a, alice(), time.Hour, t0)
	_, _ = s.Bind(b, alice(), time.Hour, t0)
	_, _ = s.Bind(c, Identity{Sub: "bob"}, time.Hour, t0)
	if !s.Revoke(a) || s.Revoke(a) {
		t.Fatal("revoke should report exactly one removal")
	}
	if n := s.RevokeIdentity("other-idp", "alice"); n != 0 {
		t.Fatalf("RevokeIdentity matched another provider's alice (%d)", n)
	}
	if n := s.RevokeIdentity("corp", "alice"); n != 1 {
		t.Fatalf("RevokeIdentity removed %d, want 1", n)
	}
	if _, ok := s.Lookup(c, t0); !ok || s.Len() != 1 {
		t.Fatalf("bob's binding affected (len %d)", s.Len())
	}
	if s.Clear() != 1 || s.Len() != 0 {
		t.Fatal("clear")
	}
}

// At capacity a new bind is REFUSED — a live binding is never evicted to make
// room (that would silently de-authenticate someone else). Expired bindings
// are swept first, and rebinding an existing address needs no new slot.
func TestCapacityRefusesNeverEvicts(t *testing.T) {
	s := on(2)
	a, b, c := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")
	_, _ = s.Bind(a, alice(), time.Hour, t0)
	_, _ = s.Bind(b, Identity{Sub: "bob"}, 10*time.Minute, t0)
	if _, err := s.Bind(c, Identity{Sub: "carol"}, time.Hour, t0); !errors.Is(err, ErrFull) {
		t.Fatalf("bind at capacity: %v, want ErrFull", err)
	}
	if _, ok := s.Lookup(a, t0); !ok {
		t.Fatal("a live binding was evicted")
	}
	if _, err := s.Bind(a, Identity{Sub: "alice2"}, time.Hour, t0); err != nil {
		t.Fatalf("rebind of an existing address refused: %v", err)
	}
	if _, err := s.Bind(c, Identity{Sub: "carol"}, time.Hour, t0.Add(11*time.Minute)); err != nil {
		t.Fatalf("bind after an expiry was not swept in: %v", err)
	}
	if s.Len() != 2 {
		t.Fatalf("len %d, want 2", s.Len())
	}
}

func TestInvalidBinds(t *testing.T) {
	s := on(4)
	for name, f := range map[string]func() error{
		"zero addr": func() error { _, err := s.Bind(netip.Addr{}, alice(), time.Hour, t0); return err },
		"no sub":    func() error { _, err := s.Bind(netip.MustParseAddr("10.0.0.1"), Identity{}, time.Hour, t0); return err },
		"ttl 0":     func() error { _, err := s.Bind(netip.MustParseAddr("10.0.0.1"), alice(), 0, t0); return err },
	} {
		if err := f(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The caller's group slice is copied: mutating it after Bind changes nothing.
func TestBindCopiesGroups(t *testing.T) {
	s := on(4)
	id := alice()
	_, _ = s.Bind(netip.MustParseAddr("10.0.0.1"), id, time.Hour, t0)
	id.Groups[0] = "admins"
	got, _ := s.Lookup(netip.MustParseAddr("10.0.0.1"), t0)
	if got.Groups[0] != "eng" {
		t.Fatal("binding aliased the caller's group slice")
	}
}

func TestListOrderAndLive(t *testing.T) {
	s := on(8)
	_, _ = s.Bind(netip.MustParseAddr("10.0.0.2"), alice(), time.Hour, t0.Add(time.Second))
	_, _ = s.Bind(netip.MustParseAddr("10.0.0.9"), alice(), time.Minute, t0)
	_, _ = s.Bind(netip.MustParseAddr("10.0.0.1"), alice(), time.Hour, t0.Add(time.Second))
	l := s.List(t0.Add(2 * time.Minute))
	if len(l) != 2 || l[0].Addr.String() != "10.0.0.1" || l[1].Addr.String() != "10.0.0.2" {
		t.Fatalf("list %+v", l)
	}
}

// Concurrent binds across shards never overshoot the bound, and every
// mutator is safe against concurrent lookups (run under -race).
func TestConcurrentBindsRespectTheBound(t *testing.T) {
	s := on(100)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				a := netip.MustParseAddr(fmt.Sprintf("10.%d.%d.%d", g, i/250, i%250))
				_, _ = s.Bind(a, alice(), time.Hour, t0)
				s.Lookup(a, t0)
				if i%50 == 0 {
					s.Revoke(a)
				}
			}
		}(g)
	}
	wg.Wait()
	if s.Len() > s.Max() || s.Len() != len(s.List(t0)) {
		t.Fatalf("len %d, max %d, listed %d", s.Len(), s.Max(), len(s.List(t0)))
	}
}

func TestLookupAllocFree(t *testing.T) {
	s := on(8)
	a := netip.MustParseAddr("10.0.0.1")
	_, _ = s.Bind(a, alice(), time.Hour, t0)
	if n := testing.AllocsPerRun(200, func() { s.Lookup(a, t0) }); n != 0 {
		t.Fatalf("lookup allocates %v", n)
	}
	s.SetEnabled(false)
	if n := testing.AllocsPerRun(200, func() { s.Lookup(a, t0) }); n != 0 {
		t.Fatalf("disabled lookup allocates %v", n)
	}
}

// Replacing a LIVE binding of a different identity reports who was displaced
// (the visible signal of a shared address); re-binding the same identity, or
// replacing an expired binding, reports nothing.
func TestBindReportsADisplacedIdentity(t *testing.T) {
	s := on(8)
	a := netip.MustParseAddr("10.0.0.1")
	if prev, _ := s.Bind(a, alice(), time.Hour, t0); prev != nil {
		t.Fatal("first bind displaced someone")
	}
	if prev, _ := s.Bind(a, alice(), time.Hour, t0.Add(time.Minute)); prev != nil {
		t.Fatal("re-bind of the same identity reported a displacement")
	}
	bob := Identity{Sub: "bob", Provider: "corp"}
	if prev, _ := s.Bind(a, bob, time.Hour, t0.Add(2*time.Minute)); prev == nil || prev.Sub != "alice" {
		t.Fatalf("takeover not reported: %+v", prev)
	}
	if prev, _ := s.Bind(a, alice(), time.Hour, t0.Add(3*time.Hour)); prev != nil {
		t.Fatal("replacing an EXPIRED binding reported a displacement")
	}
	if got, ok := s.Lookup(a, t0.Add(3*time.Hour)); !ok || got.Sub != "alice" {
		t.Fatal("most recent login does not win")
	}
}

func TestRemoveIfClampExpiryLiveCountHits(t *testing.T) {
	s := on(8)
	for i := 1; i <= 4; i++ {
		_, _ = s.Bind(netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i)), alice(), 24*time.Hour, t0)
	}
	if n := s.RemoveIf(func(a netip.Addr, _ Identity) bool { return a.String() == "10.0.0.4" }); n != 1 || s.Len() != 3 {
		t.Fatalf("RemoveIf removed %d, len %d", n, s.Len())
	}
	s.ClampExpiry(t0.Add(time.Hour))
	if _, ok := s.Lookup(netip.MustParseAddr("10.0.0.1"), t0.Add(61*time.Minute)); ok {
		t.Fatal("a clamped binding outlived its new expiry")
	}
	if s.LiveCount(t0) != 3 || s.LiveCount(t0.Add(2*time.Hour)) != 0 {
		t.Fatalf("live count %d / %d", s.LiveCount(t0), s.LiveCount(t0.Add(2*time.Hour)))
	}
	before := s.Hits()
	s.Lookup(netip.MustParseAddr("10.0.0.1"), t0)
	s.Lookup(netip.MustParseAddr("10.9.9.9"), t0)
	if s.Hits() != before+1 {
		t.Fatalf("hits %d → %d, want +1 (misses do not count)", before, s.Hits())
	}
	if n := testing.AllocsPerRun(100, func() { s.LiveCount(t0) }); n != 0 {
		t.Fatalf("LiveCount allocates %v", n)
	}
}
