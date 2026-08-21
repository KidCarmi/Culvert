package ssrf

import (
	"net"
	"net/netip"
	"testing"
)

// The guard table moved from []*net.IPNet + net.IPNet.Contains to
// []netip.Prefix + netip.Prefix.Contains for speed (the table is scanned
// linearly per X-Forwarded-For hop per proxied request). That is a rewrite of a
// SECURITY classifier, so equivalence is proven differentially against the
// previous implementation rather than argued: legacyPrivateIP below is the
// verbatim pre-change code, and the corpus tests are asserted against it.

// legacyPrivateCIDRs is the pre-change table, compiled the pre-change way.
var legacyPrivateCIDRs = func() []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(privateRanges))
	for _, r := range privateRanges {
		_, cidr, _ := net.ParseCIDR(r)
		if cidr != nil {
			nets = append(nets, cidr)
		}
	}
	return nets
}()

// legacyPrivateIP is the verbatim pre-change PrivateIP implementation.
func legacyPrivateIP(ip net.IP) bool {
	for _, cidr := range legacyPrivateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// privateAddrCorpus spans every shape that reaches the guard: each listed
// range's network/middle/broadcast-ish addresses, the public addresses that
// must stay public, and the mapped/zoned/malformed forms that have historically
// been used to bypass private-range checks.
var privateAddrCorpus = []string{
	// Boundaries of every IPv4 range in the table, plus the addresses just
	// outside them (the off-by-one class).
	"0.0.0.0", "0.0.0.1", "0.255.255.255", "1.0.0.0",
	"9.255.255.255", "10.0.0.0", "10.0.0.1", "10.255.255.255", "11.0.0.0",
	"100.63.255.255", "100.64.0.0", "100.100.100.100", "100.127.255.255", "100.128.0.0",
	"126.255.255.255", "127.0.0.0", "127.0.0.1", "127.255.255.255", "128.0.0.0",
	"169.253.255.255", "169.254.0.0", "169.254.169.254", "169.254.255.255", "169.255.0.0",
	"172.15.255.255", "172.16.0.0", "172.20.10.5", "172.31.255.255", "172.32.0.0",
	"192.167.255.255", "192.168.0.0", "192.168.1.1", "192.168.255.255", "192.169.0.0",
	"198.17.255.255", "198.18.0.0", "198.19.255.255", "198.20.0.0",
	"223.255.255.255", "224.0.0.0", "224.0.0.1", "239.255.255.255",
	"240.0.0.0", "255.255.255.254", "255.255.255.255",
	// Public IPv4 (documentation ranges + real-world routable space).
	"203.0.113.9", "198.51.100.4", "192.0.2.33", "8.8.8.8", "1.1.1.1",
	"93.184.216.34", "13.107.42.14", "104.16.132.229",
	// IPv6: table ranges and their neighbours.
	"::", "::1", "::2",
	"64:ff9b::", "64:ff9b::1", "64:ff9b:0:ffff:ffff:ffff:ffff:ffff", "64:ff9c::",
	"100::", "100::1", "100::ffff:ffff:ffff:ffff", "100:0:0:1::",
	"fbff:ffff::", "fc00::", "fc00::1", "fd00::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe00::",
	"fe7f:ffff::", "fe80::", "fe80::1", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fec0::",
	"feff::", "ff00::", "ff02::1", "ffff::1",
	// Public IPv6.
	"2001:db8::1", "2606:4700:4700::1111", "2620:fe::fe", "2a00:1450:4001:81b::200e",
	// IPv4-mapped IPv6 — the documented bypass class. Every one of these MUST
	// classify identically to its bare IPv4 form.
	"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:192.168.1.1", "::ffff:169.254.169.254",
	"::ffff:0.0.0.0", "::ffff:255.255.255.255", "::ffff:203.0.113.9", "::ffff:8.8.8.8",
	// IPv4-compatible IPv6 (deprecated, ::a.b.c.d) — NOT mapped, so it must be
	// treated as an IPv6 address by both implementations.
	"::203.0.113.9",
}

// TestPrivateAddr_MatchesLegacyImplementation is the equivalence proof over the
// corpus: for every address, the netip classifier must agree with the previous
// net.IPNet classifier. A disagreement is either a newly-opened SSRF bypass or a
// newly-blocked legitimate destination.
func TestPrivateAddr_MatchesLegacyImplementation(t *testing.T) {
	for _, s := range privateAddrCorpus {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("corpus entry %q does not parse with net.ParseIP — fix the corpus", s)
		}
		want := legacyPrivateIP(ip)

		if got := PrivateIP(ip); got != want {
			t.Errorf("PrivateIP(%s) = %v, legacy = %v — the net.IP façade diverged from the pre-change table", s, got, want)
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("corpus entry %q does not parse with netip.ParseAddr: %v", s, err)
		}
		if got := PrivateAddr(addr); got != want {
			t.Errorf("PrivateAddr(%s) = %v, legacy net.IPNet = %v — the netip guard table diverged", s, got, want)
		}
		// A 4-byte net.IP and its 16-byte To16 form must classify alike, exactly
		// as net.IPNet.Contains did (it called To4 on the input).
		if v4 := ip.To4(); v4 != nil {
			if got := PrivateIP(v4); got != want {
				t.Errorf("PrivateIP(%s) 4-byte form = %v, want %v", s, got, want)
			}
			if got := PrivateIP(ip.To16()); got != want {
				t.Errorf("PrivateIP(%s) 16-byte mapped form = %v, want %v", s, got, want)
			}
		}
	}
}

// TestPrivateAddr_MappedFormsFollowTheirIPv4 pins the bypass class explicitly:
// ::ffff:X must never classify as public when X is private. netip.Prefix.Contains
// returns false for a 4-in-6 address against an IPv4 prefix, so this fails
// immediately if the Unmap in PrivateAddr is ever dropped.
func TestPrivateAddr_MappedFormsFollowTheirIPv4(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "203.0.113.9"} {
		bare := netip.MustParseAddr(s)
		mapped := netip.MustParseAddr("::ffff:" + s)
		if PrivateAddr(bare) != PrivateAddr(mapped) {
			t.Errorf("PrivateAddr(%s) = %v but PrivateAddr(::ffff:%s) = %v — the IPv4-mapped bypass is open",
				s, PrivateAddr(bare), s, PrivateAddr(mapped))
		}
	}
}

// TestPrivateAddr_ZonedAddressesClassifyLikeTheirBareForm pins the second
// normalisation: netip.Prefix.Contains rejects any zoned address outright, so a
// link-local carrying a zone would read as public without the zone strip.
func TestPrivateAddr_ZonedAddressesClassifyLikeTheirBareForm(t *testing.T) {
	for _, s := range []string{"fe80::1", "::1", "2001:db8::1", "ff02::1"} {
		bare := netip.MustParseAddr(s)
		zoned := netip.MustParseAddr(s + "%eth0")
		if PrivateAddr(bare) != PrivateAddr(zoned) {
			t.Errorf("PrivateAddr(%s) = %v but PrivateAddr(%s%%eth0) = %v — a zone flips the verdict",
				s, PrivateAddr(bare), s, PrivateAddr(zoned))
		}
	}
}

// TestPrivateAddr_InvalidInputsMatchNothing pins the fail-open-on-garbage parity
// with net.IPNet.Contains, which rejected any IP whose length was neither 4 nor
// 16 on its length check. Callers treat "not private" as "needs a real check
// elsewhere"; every production caller guards on a successful parse first.
func TestPrivateAddr_InvalidInputsMatchNothing(t *testing.T) {
	if PrivateAddr(netip.Addr{}) {
		t.Error("PrivateAddr(zero Addr) = true, want false")
	}
	for _, ip := range []net.IP{nil, {}, {10}, {10, 0, 0}, {10, 0, 0, 0, 1}, make(net.IP, 15), make(net.IP, 17)} {
		if got, want := PrivateIP(ip), legacyPrivateIP(ip); got != want {
			t.Errorf("PrivateIP(%v len=%d) = %v, legacy = %v", []byte(ip), len(ip), got, want)
		}
	}
}

// TestPrivateAddr_AllocationFree pins the reason the netip entry point exists:
// classification must not allocate, so the per-hop scrub can be allocation-free.
func TestPrivateAddr_AllocationFree(t *testing.T) {
	for _, s := range []string{"203.0.113.9", "10.0.0.1", "2001:db8::1", "fe80::1"} {
		addr := netip.MustParseAddr(s)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = PrivateAddr(addr)
			}
		})
		allocs := res.AllocsPerOp()
		if allocs != 0 {
			t.Errorf("PrivateAddr(%s) allocates %d/op, want 0 — the classifier is on the per-request scrub path", s, allocs)
		}
		t.Logf("PrivateAddr(%s): %d ns/op, %d allocs/op", s, res.NsPerOp(), allocs)
	}
}

// TestAllowLoopbackForTest_FiltersAndRestores pins the E2E test seam across the
// table swap: it must still drop exactly the loopback ranges and restore them.
func TestAllowLoopbackForTest_FiltersAndRestores(t *testing.T) {
	lo4, lo6 := net.ParseIP("127.0.0.1"), net.ParseIP("::1")
	if !PrivateIP(lo4) || !PrivateIP(lo6) {
		t.Fatal("loopback not private before the swap")
	}
	restore := AllowLoopbackForTest()
	if PrivateIP(lo4) {
		t.Error("127.0.0.1 still private after AllowLoopbackForTest")
	}
	if PrivateIP(lo6) {
		t.Error("::1 still private after AllowLoopbackForTest")
	}
	// Non-loopback ranges must be untouched by the filter.
	for _, s := range []string{"10.0.0.1", "192.168.1.1", "169.254.169.254", "fe80::1", "0.0.0.1"} {
		if !PrivateIP(net.ParseIP(s)) {
			t.Errorf("AllowLoopbackForTest dropped a non-loopback range: %s reads public", s)
		}
	}
	restore()
	if !PrivateIP(lo4) || !PrivateIP(lo6) {
		t.Error("loopback not restored to private after restore()")
	}
}

// TestPrivateRanges_AllCompile guards the table itself: a typo in privateRanges
// would silently drop a range (ParsePrefix error → skipped), leaving a hole in
// the guard. Every declared range must appear in exactly one family bucket, and
// the two buckets together must account for all of them.
func TestPrivateRanges_AllCompile(t *testing.T) {
	total := len(privatePrefixes.v4) + len(privatePrefixes.v6)
	if total != len(privateRanges) {
		t.Fatalf("compiled %d prefixes (%d v4 + %d v6) from %d declared ranges — a range failed to parse and is NOT being enforced",
			total, len(privatePrefixes.v4), len(privatePrefixes.v6), len(privateRanges))
	}
	in := func(bucket []netip.Prefix, want netip.Prefix) bool {
		for _, p := range bucket {
			if p == want {
				return true
			}
		}
		return false
	}
	for _, r := range privateRanges {
		want := netip.MustParsePrefix(r).Masked()
		bucket, other := privatePrefixes.v6, privatePrefixes.v4
		family := "v6"
		if want.Addr().Is4() {
			bucket, other, family = privatePrefixes.v4, privatePrefixes.v6, "v4"
		}
		if !in(bucket, want) {
			t.Errorf("range %q (%v) is missing from the %s bucket — it is NOT being enforced", r, want, family)
		}
		if in(other, want) {
			t.Errorf("range %q (%v) landed in the wrong family bucket", r, want)
		}
	}
}

// TestGuardTable_FamilySplitCoversBothBuckets pins the assumption the split
// rests on: after unmapping, an address can only match prefixes of its own
// family, so consulting one bucket loses nothing. Asserted directly — every
// prefix must reject every address of the other family.
func TestGuardTable_FamilySplitCoversBothBuckets(t *testing.T) {
	if len(privatePrefixes.v4) == 0 || len(privatePrefixes.v6) == 0 {
		t.Fatal("expected both family buckets to be populated")
	}
	v4Samples := []string{"0.0.0.0", "10.0.0.1", "127.0.0.1", "203.0.113.9", "255.255.255.255"}
	v6Samples := []string{"::", "::1", "fe80::1", "2001:db8::1", "ff02::1"}
	for _, s := range v4Samples {
		addr := netip.MustParseAddr(s)
		for _, p := range privatePrefixes.v6 {
			if p.Contains(addr) {
				t.Errorf("v6 prefix %v contains the IPv4 address %s — the family split would skip a real match", p, s)
			}
		}
	}
	for _, s := range v6Samples {
		addr := netip.MustParseAddr(s)
		for _, p := range privatePrefixes.v4 {
			if p.Contains(addr) {
				t.Errorf("v4 prefix %v contains the IPv6 address %s — the family split would skip a real match", p, s)
			}
		}
	}
}

// TestPrivateAddr_RandomizedAgreement widens the differential proof past the
// hand-picked corpus: a deterministic sweep across the whole IPv4 space and a
// structured IPv6 sweep must agree with the legacy classifier everywhere.
func TestPrivateAddr_RandomizedAgreement(t *testing.T) {
	// Deterministic stride over the full IPv4 space (~4M samples at this step,
	// hitting every /12 boundary class without being a 4-billion-iteration test).
	const step = 1021 // prime: walks all octet alignments
	for u := uint64(0); u <= 0xFFFFFFFF; u += step {
		v := uint32(u)
		// #nosec G115 -- v is a uint32; each shifted byte is bounded by construction
		addr := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		want := legacyPrivateIP(net.IP(addr.AsSlice()))
		if got := PrivateAddr(addr); got != want {
			t.Fatalf("PrivateAddr(%v) = %v, legacy = %v", addr, got, want)
		}
	}
	// IPv6: sweep the high 16 bits (covers every prefix in the table plus the
	// public space between them) with a fixed low half.
	for hi := 0; hi < 0x10000; hi++ {
		var b [16]byte
		b[0], b[1] = byte(hi>>8), byte(hi) // #nosec G115 -- hi < 0x10000 by the loop bound
		b[15] = 1
		addr := netip.AddrFrom16(b)
		want := legacyPrivateIP(net.IP(addr.AsSlice()))
		if got := PrivateAddr(addr); got != want {
			t.Fatalf("PrivateAddr(%v) = %v, legacy = %v", addr, got, want)
		}
	}
}

func BenchmarkPrivateAddr_PublicV4(b *testing.B) {
	b.ReportAllocs()
	addr := netip.MustParseAddr("203.0.113.9")
	for i := 0; i < b.N; i++ {
		if PrivateAddr(addr) {
			b.Fatal("public classified private")
		}
	}
}

func BenchmarkPrivateAddr_PrivateV4(b *testing.B) {
	b.ReportAllocs()
	addr := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < b.N; i++ {
		if !PrivateAddr(addr) {
			b.Fatal("private classified public")
		}
	}
}

func BenchmarkPrivateAddr_PublicV6(b *testing.B) {
	b.ReportAllocs()
	addr := netip.MustParseAddr("2001:db8::1")
	for i := 0; i < b.N; i++ {
		_ = PrivateAddr(addr)
	}
}

// BenchmarkPrivateIP_LegacyTable is the before-side of the comparison, kept so
// the speedup is reproducible from the tree rather than quoted from a commit
// message.
func BenchmarkPrivateIP_LegacyTable(b *testing.B) {
	b.ReportAllocs()
	ip := net.ParseIP("203.0.113.9")
	for i := 0; i < b.N; i++ {
		if legacyPrivateIP(ip) {
			b.Fatal("public classified private")
		}
	}
}
