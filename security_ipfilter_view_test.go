package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests cover the IPFilter read-view change (lock-free Allowed, netip
// -keyed exact set, prefix-length-bucketed CIDR membership). The change is a
// COST change only: every verdict it produces must be the one the previous
// implementation produced, so the centrepiece is a differential test against a
// verbatim copy of the old algorithm.

// ─── The pre-change algorithm, kept verbatim as the differential oracle ──────

// legacyContains is character-for-character the pre-change IPFilter.contains:
// net.ParseIP, an exact-match probe against the String()-keyed set, then a
// linear scan calling net.IPNet.Contains on every configured CIDR. It is the
// reference the new view is checked against and must not be "modernised".
func legacyContains(single map[string]bool, nets []*net.IPNet, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if single[ip.String()] {
		return true
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// legacyAllowed is the pre-change IPFilter.Allowed, including its fail-closed
// default arm.
func legacyAllowed(mode string, single map[string]bool, nets []*net.IPNet, ipStr string) bool {
	switch mode {
	case "allow":
		return legacyContains(single, nets, ipStr)
	case "block":
		return !legacyContains(single, nets, ipStr)
	case "":
		return true
	default:
		return false
	}
}

// buildFilter constructs an IPFilter through the public mutators and returns
// it alongside the raw write-side state, so the oracle sees exactly the same
// entries the view was derived from.
func buildFilter(t *testing.T, mode string, entries []string) (*IPFilter, map[string]bool, []*net.IPNet) {
	t.Helper()
	f := &IPFilter{single: map[string]bool{}}
	for _, e := range entries {
		_ = f.Add(e) // invalid entries are ignored by both sides alike
	}
	f.SetMode(mode)
	f.mu.RLock()
	single := make(map[string]bool, len(f.single))
	for k, v := range f.single {
		single[k] = v
	}
	nets := append([]*net.IPNet(nil), f.nets...)
	f.mu.RUnlock()
	return f, single, nets
}

// TestIPFilterView_DifferentialAgainstLegacy is the correctness spine: for a
// battery of hand-picked entry/probe shapes chosen to hit every place the two
// representations could diverge, the new view must return the legacy verdict.
func TestIPFilterView_DifferentialAgainstLegacy(t *testing.T) {
	entrySets := [][]string{
		nil,
		{"10.0.0.1"},
		{"10.0.0.0/8"},
		{"10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/24", "10.0.0.0/32"}, // nested, many lengths
		{"0.0.0.0/0"},                          // v4 default route
		{"::/0"},                               // v6 default route — must NOT match v4
		{"::1", "2001:db8::/32"},               // v6 entries
		{"::ffff:10.0.0.0/104"},                // 4-in-6 CIDR, stored 16-byte
		{"10.0.0.1", "10.0.0.1"},               // duplicate exact entries
		{"192.0.2.0/24", "192.0.2.0/24"},       // duplicate CIDRs
		{"198.51.100.7", "198.51.100.0/24"},    // exact inside its own CIDR
		{"2001:db8::/32", "2001:db8:1::/48"},   // nested v6
		{"10.0.0.0/8", "2001:db8::/32", "::1"}, // mixed families
		{"255.255.255.255/32"},
		{"127.0.0.0/8"},
	}
	probes := []string{
		"10.0.0.1", "10.0.0.2", "10.255.255.255", "11.0.0.1",
		"0.0.0.0", "255.255.255.255", "127.0.0.1",
		"192.0.2.5", "198.51.100.7", "198.51.100.8", "203.0.113.47",
		"::1", "::", "2001:db8::1", "2001:db8:1::5", "2001:db9::1",
		"::ffff:10.0.0.1",    // IPv4-mapped: net treats this as IPv4
		"::ffff:203.0.113.1", // IPv4-mapped, outside every fixture
		"fe80::1",
		// Parser-divergence probes. netip.ParseAddr and net.ParseIP are
		// different parsers, and the view swaps one for the other, so every
		// shape where they might disagree has to produce the same verdict.
		// Zones are the known divergence: netip accepts them, net rejects
		// them, and a rejected parse means "matches nothing".
		"fe80::1%eth0", "::ffff:10.0.0.1%eth0", "fe80::1%", "%eth0",
		"0:0:0:0:0:ffff:10.0.0.1", // long-form IPv4-mapped
		"::ffff:0:10.0.0.1",       // IPv4-compatible-ish, not 4-in-6
		"not-an-ip", "", "10.0.0.256", "010.0.0.1", "10.0.0.1/24",
		"0x0a.0.0.1", "1.2.3.4.5", "1.2.3", " 10.0.0.1", "10.0.0.1 ",
		"10.0.0.1\n", "[10.0.0.1]", "::ffff:10.0.0.0/104",
	}
	modes := []string{"", "allow", "block", "bogus"}

	for _, entries := range entrySets {
		for _, mode := range modes {
			f, single, nets := buildFilter(t, mode, entries)
			for _, probe := range probes {
				want := legacyAllowed(mode, single, nets, probe)
				got := f.Allowed(probe)
				if got != want {
					t.Errorf("Allowed(%q) = %v, legacy = %v (mode=%q entries=%v)",
						probe, got, want, mode, entries)
				}
			}
		}
	}
}

// TestIPFilterView_DifferentialRandomized widens the differential test over
// randomly generated filters and probes. A fixed seed keeps failures
// reproducible.
func TestIPFilterView_DifferentialRandomized(t *testing.T) {
	// #nosec G404 -- deterministic seeded generator for reproducible test data
	rng := rand.New(rand.NewSource(20260823))

	randV4 := func() string {
		return fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
	}
	randEntry := func() string {
		switch rng.Intn(4) {
		case 0:
			return randV4()
		case 1:
			return fmt.Sprintf("%s/%d", randV4(), rng.Intn(33))
		case 2:
			return fmt.Sprintf("2001:db8:%x::/%d", rng.Intn(65536), 32+rng.Intn(65))
		default:
			return fmt.Sprintf("2001:db8:%x::%x", rng.Intn(65536), rng.Intn(65536))
		}
	}

	modes := []string{"", "allow", "block", "corrupt"}
	for iter := 0; iter < 300; iter++ {
		entries := make([]string, rng.Intn(12))
		for i := range entries {
			entries[i] = randEntry()
		}
		mode := modes[rng.Intn(len(modes))]
		f, single, nets := buildFilter(t, mode, entries)

		for p := 0; p < 20; p++ {
			var probe string
			switch {
			case p < 12:
				probe = randV4()
			case p < 16:
				probe = fmt.Sprintf("2001:db8:%x::%x", rng.Intn(65536), rng.Intn(65536))
			case p < 18 && len(entries) > 0:
				// Probe an entry verbatim (bare IP entries become exact hits;
				// CIDR entries exercise the network-address boundary).
				probe = entries[rng.Intn(len(entries))]
				if i := strings.IndexByte(probe, '/'); i >= 0 {
					probe = probe[:i]
				}
			default:
				probe = fmt.Sprintf("::ffff:%s", randV4())
			}
			want := legacyAllowed(mode, single, nets, probe)
			if got := f.Allowed(probe); got != want {
				t.Fatalf("iter %d: Allowed(%q) = %v, legacy = %v (mode=%q entries=%v)",
					iter, probe, got, want, mode, entries)
			}
		}
	}
}

// ─── The publish contract ───────────────────────────────────────────────────

// TestIPFilterView_EveryMutatorRepublishes is the security half of the read-
// view contract. A mutator that changes the write-side state without calling
// publishView leaves readers on a stale view: a revoked allowlist entry keeps
// admitting traffic, a removed blocklist entry keeps denying it. Every mutator
// gets a case here, and a new one must be added alongside.
func TestIPFilterView_EveryMutatorRepublishes(t *testing.T) {
	t.Run("SetMode", func(t *testing.T) {
		f := &IPFilter{single: map[string]bool{}}
		if err := f.Add("203.0.113.47"); err != nil {
			t.Fatal(err)
		}
		if !f.Allowed("203.0.113.47") {
			t.Fatal("disabled filter must allow")
		}
		f.SetMode("block")
		if f.Allowed("203.0.113.47") {
			t.Error("SetMode did not republish: blocklisted IP still allowed")
		}
	})

	t.Run("Add", func(t *testing.T) {
		f := &IPFilter{single: map[string]bool{}}
		f.SetMode("block")
		if !f.Allowed("203.0.113.47") {
			t.Fatal("empty blocklist must allow")
		}
		if err := f.Add("203.0.113.47"); err != nil {
			t.Fatal(err)
		}
		if f.Allowed("203.0.113.47") {
			t.Error("Add did not republish: newly blocked IP still allowed")
		}
	})

	t.Run("AddCIDR", func(t *testing.T) {
		f := &IPFilter{single: map[string]bool{}}
		f.SetMode("block")
		if err := f.Add("203.0.113.0/24"); err != nil {
			t.Fatal(err)
		}
		if f.Allowed("203.0.113.47") {
			t.Error("Add(CIDR) did not republish: newly blocked range still allowed")
		}
	})

	t.Run("Remove", func(t *testing.T) {
		f := &IPFilter{single: map[string]bool{}}
		f.SetMode("allow")
		if err := f.Add("203.0.113.0/24"); err != nil {
			t.Fatal(err)
		}
		if !f.Allowed("203.0.113.47") {
			t.Fatal("allowlisted range must pass")
		}
		f.Remove("203.0.113.0/24")
		if f.Allowed("203.0.113.47") {
			t.Error("Remove did not republish: revoked allowlist entry still admits")
		}
	})

	t.Run("ClearAll", func(t *testing.T) {
		f := &IPFilter{single: map[string]bool{}}
		f.SetMode("allow")
		if err := f.Add("203.0.113.47"); err != nil {
			t.Fatal(err)
		}
		if !f.Allowed("203.0.113.47") {
			t.Fatal("allowlisted IP must pass")
		}
		f.ClearAll()
		if f.Allowed("203.0.113.47") {
			t.Error("ClearAll did not republish: cleared allowlist still admits")
		}
	})
}

// TestIPFilterView_UnpublishedFilterAllowsAll pins the nil-view fallback: a
// bare composite literal (how the DP snapshot path and several tests build
// one) is a disabled filter, and Allowed must answer before any mutator has
// published.
func TestIPFilterView_UnpublishedFilterAllowsAll(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	for _, ip := range []string{"203.0.113.47", "10.0.0.1", "::1", "garbage"} {
		if !f.Allowed(ip) {
			t.Errorf("unpublished (disabled) filter denied %q", ip)
		}
	}
}

// TestIPFilterView_RejectedAddLeavesViewIntact pins that a failed Add — which
// changes nothing — cannot disturb the live view.
func TestIPFilterView_RejectedAddLeavesViewIntact(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	f.SetMode("allow")
	if err := f.Add("203.0.113.47"); err != nil {
		t.Fatal(err)
	}
	if err := f.Add("not-an-ip"); err == nil {
		t.Fatal("Add(\"not-an-ip\") should have failed")
	}
	if !f.Allowed("203.0.113.47") {
		t.Error("a rejected Add disturbed the published view")
	}
	if f.Allowed("198.51.100.1") {
		t.Error("a rejected Add widened the allowlist")
	}
}

// ─── Concurrency ────────────────────────────────────────────────────────────

// TestIPFilterView_ConcurrentReadersAndWriters is the in-place-mutation guard:
// under -race, a writer that edited a map reachable from a published view
// instead of installing a replacement would be reported here.
func TestIPFilterView_ConcurrentReadersAndWriters(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	f.SetMode("block")

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			probe := fmt.Sprintf("198.51.100.%d", n)
			for {
				select {
				case <-stop:
					return
				default:
					_ = f.Allowed(probe)
				}
			}
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = f.Add(fmt.Sprintf("203.0.113.%d", i%256))
			_ = f.Add(fmt.Sprintf("10.%d.0.0/16", i%256))
			f.Remove(fmt.Sprintf("10.%d.0.0/16", i%256))
			if i%50 == 0 {
				f.ClearAll()
				f.SetMode("block")
			}
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// ─── Bulk load (AddAll) ─────────────────────────────────────────────────────

// TestIPFilterAddAll_MatchesAddLoop is the equivalence check for the bulk
// primitive: AddAll must leave the filter in exactly the state a loop of Add
// calls would, for every mode and every verdict — it is only allowed to be
// cheaper, never different.
func TestIPFilterAddAll_MatchesAddLoop(t *testing.T) {
	entrySets := [][]string{
		nil,
		{},
		{"10.0.0.1"},
		{"10.0.0.0/8", "192.0.2.0/24", "198.51.100.7"},
		{"2001:db8::/32", "::1", "10.0.0.0/8"},
		{"10.0.0.1", "10.0.0.1", "10.0.0.0/8", "10.0.0.0/8"}, // duplicates
		{"not-an-ip", "10.0.0.1", "", "10.0.0.256"},          // mixed valid/invalid
		{"nope", "also-nope"},                                // all invalid
	}
	probes := []string{
		"10.0.0.1", "10.0.0.2", "11.0.0.1", "192.0.2.5", "198.51.100.7",
		"203.0.113.47", "::1", "2001:db8::1", "::ffff:10.0.0.1",
	}

	for _, mode := range []string{"", "allow", "block", "bogus"} {
		for _, entries := range entrySets {
			assertAddAllMatchesAddLoop(t, mode, entries, probes)
		}
	}
}

// assertAddAllMatchesAddLoop builds the same filter twice — once entry by entry
// through Add, once in bulk through AddAll — and requires the two to be
// indistinguishable in verdicts, in List membership, and in which entries they
// rejected.
func assertAddAllMatchesAddLoop(t *testing.T, mode string, entries, probes []string) {
	t.Helper()

	viaLoop := &IPFilter{single: map[string]bool{}}
	viaLoop.SetMode(mode)
	for _, e := range entries {
		_ = viaLoop.Add(e)
	}

	viaBulk := &IPFilter{single: map[string]bool{}}
	viaBulk.SetMode(mode)
	invalid := viaBulk.AddAll(entries)

	for _, probe := range probes {
		if got, want := viaBulk.Allowed(probe), viaLoop.Allowed(probe); got != want {
			t.Errorf("AddAll: Allowed(%q) = %v, Add-loop = %v (mode=%q entries=%v)",
				probe, got, want, mode, entries)
		}
	}

	// List membership must match too — it feeds export and the CP→DP snapshot.
	if got, want := len(viaBulk.List()), len(viaLoop.List()); got != want {
		t.Errorf("AddAll: len(List()) = %d, Add-loop = %d (entries=%v)", got, want, entries)
	}

	if got, want := len(invalid), countRejectedEntries(entries); got != want {
		t.Errorf("AddAll reported %d invalid entries, want %d (entries=%v)", got, want, entries)
	}
	for _, bad := range invalid {
		if bad.Err == nil {
			t.Errorf("AddAll reported entry %q with a nil Err", bad.Entry)
		}
	}
}

// countRejectedEntries is the oracle for AddAll's invalid-entry report: how
// many of these entries a single-shot Add would refuse.
func countRejectedEntries(entries []string) int {
	var n int
	for _, e := range entries {
		if (&IPFilter{single: map[string]bool{}}).Add(e) != nil {
			n++
		}
	}
	return n
}

// TestIPFilterAddAll_PublishesOnce pins that the bulk path still satisfies the
// publish contract — the loaded entries must be live the moment AddAll
// returns, exactly as they are after Add.
func TestIPFilterAddAll_PublishesOnce(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	f.SetMode("block")
	f.AddAll([]string{"203.0.113.0/24", "198.51.100.7"})
	if f.Allowed("203.0.113.47") {
		t.Error("AddAll did not publish: newly blocked range still allowed")
	}
	if f.Allowed("198.51.100.7") {
		t.Error("AddAll did not publish: newly blocked IP still allowed")
	}
	if !f.Allowed("192.0.2.1") {
		t.Error("AddAll blocked an unlisted IP")
	}
}

// TestBenchGate_IPFilterBulkLoadIsLinear is the regression gate for the
// quadratic bulk load. publishView rebuilds the derived view from the entire
// entry set, so publishing per entry makes a list load O(N²) — measured, an
// Add loop cost 46 ms at 1k entries and 3.27 s at 8k, and this list's
// ConfigSnapshot cap is maxSnapIPList (2,000,000), so that would stall a boot
// or a snapshot apply.
//
// A RATIO gate, so it is machine-independent: 4x the entries should cost ~4x
// if the load is linear and ~16x if it is quadratic. The bound is 8x, midway
// on a log scale, so the gate has wide margin under -race on a shared runner
// while still failing hard if per-entry publishing returns.
func TestBenchGate_IPFilterBulkLoadIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("cost-shape gate skipped in -short")
	}
	const (
		small = 2000
		large = 8000 // 4x
		bound = 8.0
	)

	entries := func(n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("10.%d.%d.1", i/256, i%256))
		}
		return out
	}

	measure := func(n int) time.Duration {
		list := entries(n)
		f := &IPFilter{single: map[string]bool{}}
		f.SetMode("allow")
		start := time.Now()
		f.AddAll(list)
		return time.Since(start)
	}

	// Best-of-three: a scheduler hiccup inflates a sample, never deflates it.
	best := func(n int) time.Duration {
		d := measure(n)
		for i := 0; i < 2; i++ {
			if e := measure(n); e < d {
				d = e
			}
		}
		return d
	}

	dSmall, dLarge := best(small), best(large)
	ratio := float64(dLarge) / float64(dSmall)
	t.Logf("entries=%d: %v, entries=%d: %v, ratio=%.2fx (linear ~4x, quadratic ~16x, bound %.1fx)",
		small, dSmall, large, dLarge, ratio, bound)
	if ratio > bound {
		t.Errorf("bulk IP-filter load scales superlinearly (%.2fx for 4x the entries, bound %.1fx): "+
			"the view is being republished per entry again", ratio, bound)
	}
}

// ─── Cost-shape gates ───────────────────────────────────────────────────────

// TestBenchGate_IPFilterAllowedTakesNoLock is STRUCTURAL, not timing-based: it
// holds the filter's write lock and requires Allowed to answer anyway. A
// return to a lock-guarded read path deadlocks the helper goroutine and the
// test fails deterministically on any hardware, at any load, with or without
// -race. (A scaling-ratio gate on the disabled path was considered and
// rejected for the reason recorded elsewhere in this repo: a gate that can
// flake gets muted.)
func TestBenchGate_IPFilterAllowedTakesNoLock(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	f.SetMode("block")
	if err := f.Add("198.51.100.0/24"); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	probes := []struct {
		ip   string
		want bool
		note string
	}{
		{"203.0.113.47", true, "unlisted IP passes a blocklist"},
		{"198.51.100.9", false, "IP inside a blocklisted range is denied"},
	}

	type result struct {
		i   int
		got bool
	}
	done := make(chan result, len(probes))
	for i := range probes {
		go func(i int, ip string) { done <- result{i, f.Allowed(ip)} }(i, probes[i].ip)
	}

	// Completion order is not deterministic, so each result carries its index
	// and every verdict is checked individually — the gate proves the read path
	// still ANSWERS under the write lock, and still answers CORRECTLY.
	for range probes {
		select {
		case r := <-done:
			if p := probes[r.i]; r.got != p.want {
				t.Errorf("Allowed(%q) = %v, want %v (%s)", p.ip, r.got, p.want, p.note)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Allowed blocked while the write lock was held: the per-request " +
				"read path has taken a lock again")
		}
	}
}

// TestBenchGate_IPFilterAllowedIsFlatInCIDRCount is a RATIO gate, so it is
// machine-independent: it compares the filter against itself at two sizes
// rather than against an absolute nanosecond budget.
//
// The pre-change linear scan cost ~14 ns per configured CIDR, so 256 prefixes
// cost ~35x what 1 costs — 3.8 µs of CPU per request, inside the request
// goroutine, before any policy work. Bucketing by prefix length makes the cost
// depend on the number of DISTINCT prefix lengths (here: one, /24) instead.
// Measured ratio after the change is ~1.0; the bound is set at 4x so the gate
// has a wide margin under -race on a shared CI runner while still failing hard
// if the linear scan returns.
func TestBenchGate_IPFilterAllowedIsFlatInCIDRCount(t *testing.T) {
	if testing.Short() {
		t.Skip("cost-shape gate skipped in -short")
	}
	const (
		small = 1
		large = 256
		bound = 4.0
	)

	measure := func(n int) time.Duration {
		f := &IPFilter{single: map[string]bool{}}
		for i := 0; i < n; i++ {
			if err := f.Add(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)); err != nil {
				t.Fatal(err)
			}
		}
		f.SetMode("allow")
		const iters = 20000
		// Warm up so neither size pays first-touch costs the other does not.
		for i := 0; i < 1000; i++ {
			_ = f.Allowed(benchProbeIP)
		}
		start := time.Now()
		for i := 0; i < iters; i++ {
			_ = f.Allowed(benchProbeIP)
		}
		return time.Since(start)
	}

	// Best-of-three on each size: a scheduler hiccup inflates a sample, never
	// deflates it, so taking the minimum removes the flake direction.
	best := func(n int) time.Duration {
		d := measure(n)
		for i := 0; i < 2; i++ {
			if e := measure(n); e < d {
				d = e
			}
		}
		return d
	}

	dSmall, dLarge := best(small), best(large)
	ratio := float64(dLarge) / float64(dSmall)
	t.Logf("cidrs=%d: %v, cidrs=%d: %v, ratio=%.2fx (bound %.1fx)",
		small, dSmall, large, dLarge, ratio, bound)
	if ratio > bound {
		t.Errorf("Allowed cost scales with CIDR count (%.2fx from %d to %d prefixes, bound %.1fx): "+
			"the per-request membership test has returned to a linear scan", ratio, small, large, bound)
	}
}

// TestBenchGate_IPFilterAllowedAllocsFree pins the allocation contract. The
// pre-change path spent one allocation (16 B) per request on net.ParseIP plus
// net.IP.String() to build a map key; a per-request allocation is GC pressure
// on 100% of proxy traffic.
func TestBenchGate_IPFilterAllowedAllocsFree(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		entries []string
	}{
		{"disabled", "", nil},
		{"block_miss", "block", benchBlockList},
		{"allow_hit", "allow", []string{benchProbeIP}},
		{"allow_cidr_miss", "allow", benchCIDRs(64)},
		{"v6", "block", []string{"2001:db8::/32", "::1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newBenchIPFilter(tc.mode, tc.entries)
			probe := benchProbeIP
			if tc.name == "v6" {
				probe = "2001:db8::1"
			}
			if got := testing.AllocsPerRun(200, func() { _ = f.Allowed(probe) }); got != 0 {
				t.Errorf("Allowed allocates %.1f times per call, want 0", got)
			}
		})
	}
}
