package ssrf

// A zoned IPv6 address ("fe80::1%eth0") names a link-local, loopback or
// unique-local destination on a specific interface. The pre-flight guard read
// the resolver's answers with net.ParseIP, which returns nil for a zoned
// address, and treated "not parseable" as "not private": the destination was
// classified PUBLIC and that verdict cached. Measured before the fix, with the
// system resolver (which answers an address literal with itself, zone and all):
//
//	PrivateHost("[fe80::1%lo]:80")  = nil   (want: blocked)
//	PrivateHost("[::1%lo]:80")      = nil
//	PrivateHost("[fd00::1%lo]:80")  = nil

import (
	"context"
	"errors"
	"testing"
)

func TestPrivateHost_ZonedLiteralIsClassifiedByItsAddress(t *testing.T) {
	CacheReset()
	t.Cleanup(CacheReset)
	for _, hostport := range []string{
		"[fe80::1%lo]:80", "[fe80::1%eth0]:443", "fe80::1%lo",
		"[::1%lo]:80", "[fd00::1%lo]:80", "[::ffff:10.0.0.1%lo]:80",
	} {
		err := PrivateHost(hostport)
		if err == nil {
			t.Errorf("PrivateHost(%q) = nil: a zoned internal address is classified public", hostport)
			continue
		}
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("PrivateHost(%q) = %v, want an ErrBlocked refusal (the address is known to be internal)", hostport, err)
		}
	}
	// Controls: the same addresses without a zone were always refused, and a
	// public literal is still accepted.
	for _, hostport := range []string{"[fe80::1]:80", "[::1]:80", "[fd00::1]:80"} {
		if err := PrivateHost(hostport); !errors.Is(err, ErrBlocked) {
			t.Errorf("control PrivateHost(%q) = %v, want ErrBlocked", hostport, err)
		}
	}
	if err := PrivateHost("[2606:4700:4700::1111]:443"); err != nil {
		t.Errorf("control: public literal refused: %v", err)
	}
}

// A NAME can resolve to a zoned address too (getaddrinfo returns scoped
// link-local answers for mDNS and /etc/hosts entries). And an answer the guard
// cannot parse at all demonstrates nothing about the destination: it must fail
// closed, not be skipped.
func TestPrivateHost_ResolverAnswersAreNeverSkipped(t *testing.T) {
	for _, tc := range []struct {
		label   string
		answers []string
		blocked bool // ErrBlocked (known internal) vs refused-as-undetermined
	}{
		{"zoned link-local answer", []string{"fe80::1%eth0"}, true},
		{"public first, zoned link-local second", []string{"93.184.216.34", "fe80::1%eth0"}, true},
		{"zoned loopback answer", []string{"::1%lo"}, true},
		{"unparseable answer", []string{"not-an-address"}, false},
		{"public first, unparseable second", []string{"93.184.216.34", "[::1]"}, false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			t.Cleanup(SetLookupHostForTest(func(context.Context, string) ([]string, error) { return tc.answers, nil }))
			err := PrivateHost("name.example:443")
			if err == nil {
				t.Fatalf("PrivateHost = nil for answers %v: classified public", tc.answers)
			}
			if errors.Is(err, ErrBlocked) != tc.blocked {
				t.Errorf("PrivateHost = %v; ErrBlocked=%v, want %v", err, errors.Is(err, ErrBlocked), tc.blocked)
			}
			// The verdict must hold on the cached path too.
			if err := PrivateHost("name.example:443"); err == nil {
				t.Error("second call (cache) = nil: a public verdict was cached")
			}
		})
	}
	// Control: ordinary public answers are accepted.
	t.Cleanup(SetLookupHostForTest(func(context.Context, string) ([]string, error) {
		return []string{"93.184.216.34", "2606:2800:220:1::1"}, nil
	}))
	if err := PrivateHost("name.example:443"); err != nil {
		t.Errorf("control: public answers refused: %v", err)
	}
}

// A zone names a local interface, so a zoned address is never a public
// destination even when the address itself is in a global range.
func TestZonedGlobalAddressIsNotPublic(t *testing.T) {
	if got, err := classifyAnswers([]string{"2606:4700:4700::1111%eth0"}); err != nil || got == "" {
		t.Fatalf("classifyAnswers(zoned global) = (%q, %v), want it reported as private", got, err)
	}
	if got, err := classifyAnswers([]string{"2606:4700:4700::1111"}); err != nil || got != "" {
		t.Fatalf("classifyAnswers(unzoned global) = (%q, %v), want public", got, err)
	}
}
