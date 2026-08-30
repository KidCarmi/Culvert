package main

import (
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// normalizeHost and stripHostPort moved to internal/hostutil (ADR-0002/0003).
// These thin wrappers keep the unqualified package-main call sites (policy,
// store, catdb, scanner, security_scan) and the existing tests unchanged.
func normalizeHost(host string) string { return hostutil.NormalizeHost(host) }
func stripHostPort(host string) string { return hostutil.StripHostPort(host) }

// normalizeHostStrict is the fail-closed variant used by the request-path
// dispatch gates (handleRequest, SOCKS5): ok=false means the host cannot be
// IDNA-canonicalized and the request must be REJECTED rather than evaluated
// against policy/blocklist with an un-normalized host (RISK-013).
func normalizeHostStrict(host string) (string, bool) { return hostutil.NormalizeHostStrict(host) }

// ─── SSRF guard (moved to internal/ssrf, ADR-0002) ──────────────────────────
// The CIDR table, DNS-cached host check, and connect-time dialer control live
// in internal/ssrf. These thin wrappers keep every unqualified call site (and
// the CodeQL inline-guard convention at those sites) unchanged.

// isPrivateIP reports whether ip falls within any private/internal range.
func isPrivateIP(ip net.IP) bool { return ssrf.PrivateIP(ip) }

// isPrivateHost resolves host (host or host:port) and returns an error if any
// resolved IP falls within a private/internal range (30s-TTL DNS cache;
// fail-closed on resolution errors).
func isPrivateHost(hostport string) error { return ssrf.PrivateHost(hostport) }

// ssrfControl is the connect-time guard (net.Dialer.Control) — rejects dials
// whose resolved address is private/internal. Re-exposed for the CONNECT and
// SOCKS5 paths, which build their own dialers.
var ssrfControl = ssrf.Control

// errSSRFBlocked is the sentinel a connect-time ssrfControl rejection wraps, so
// a dial-error site can errors.Is() a DNS-rebinding/private-IP security block
// apart from a genuine unreachable-origin dial error.
var errSSRFBlocked = ssrf.ErrBlocked

// ssrfSafeDialContext is a net.Dialer.DialContext replacement that rejects
// connections to private/internal IPs at connect time (DNS-rebinding safe).
//
// Declared as a variable so that tests can temporarily replace it with a
// plain dialer that permits localhost webhook targets.
var ssrfSafeDialContext = ssrf.SafeDialContext

// ─── IP Filter ────────────────────────────────────────────────────────────────

// IPFilter supports allowlist and blocklist mode with CIDR ranges.
// Mode "allow"  → only IPs in the list are permitted (default: allow all).
// Mode "block"  → IPs in the list are denied.
//
// Allowed() runs on EVERY proxied request (handleRequest, and the SOCKS5
// handler) before any other work, so the read path is LOCK-FREE: it loads an
// immutable *ipFilterView through an atomic.Pointer and never touches mu. The
// mu-guarded fields below stay the authoritative write-side state — Add,
// Remove, ClearAll, List and Mode keep their exact previous semantics — and
// every mutator republishes a freshly derived view before releasing the lock.
// Same contract, and the same reason, as internal/threatfeed's read view.
//
// A mutator added WITHOUT a publishView() call is a silent SECURITY failure,
// not a performance one: a revoked allowlist entry that keeps admitting, or a
// removed blocklist entry that keeps denying. It is pinned per mutator by
// TestIPFilterView_EveryMutatorRepublishes.
type IPFilter struct {
	mu     sync.RWMutex
	mode   string // "allow" | "block" | "" (disabled)
	nets   []*net.IPNet
	single map[string]bool

	// view is the derived, immutable read-side snapshot. Written only under
	// mu (by publishView); read without any lock by Allowed.
	view atomic.Pointer[ipFilterView]
}

// ipFilterView is an immutable snapshot of an IPFilter's decision state.
//
// Nothing reachable from a published view is ever mutated in place — a mutator
// builds a REPLACEMENT and stores it — so readers need no synchronisation
// beyond the atomic load.
//
// The membership test is bucketed by prefix length rather than run as a linear
// scan over the CIDR list: "does any configured prefix contain this address"
// is answered by masking the address to each DISTINCT prefix length present
// and probing a set. The number of distinct lengths is bounded by 33 (v4) /
// 129 (v6) and is 2–5 in any real operator config, so the cost is flat in the
// number of prefixes instead of proportional to it.
type ipFilterView struct {
	mode string

	// singles is the exact-address set. Keyed by netip.Addr rather than by
	// net.IP.String() so a lookup formats no string and allocates nothing.
	singles map[netip.Addr]struct{}

	// prefixes holds every configured CIDR in canonical (masked) form;
	// v4Lens/v6Lens are the sorted distinct prefix lengths present in it,
	// split by address family so a v4 probe never tests a v6 prefix (which
	// is what net.IPNet.Contains does via its length check).
	prefixes map[netip.Prefix]struct{}
	v4Lens   []int
	v6Lens   []int

	// oddNets carries any *net.IPNet that could not be represented as a
	// netip.Prefix (a non-contiguous mask). net.ParseCIDR — the only writer
	// of IPFilter.nets — cannot produce one, so this is unreachable in
	// practice; it exists so the representation change can never silently
	// drop an entry from a security filter. Scanned linearly, empty in every
	// real config.
	oddNets []*net.IPNet
}

// emptyIPFilterView is the view of a freshly constructed IPFilter: filter
// disabled, no entries. Filters are built as bare composite literals in
// several places (the DP snapshot path, tests), so Allowed must have a
// well-defined answer before the first mutator publishes.
var emptyIPFilterView = ipFilterView{}

var ipf = &IPFilter{single: map[string]bool{}}

// loadView returns the current read-side snapshot, never nil.
func (f *IPFilter) loadView() *ipFilterView {
	if v := f.view.Load(); v != nil {
		return v
	}
	return &emptyIPFilterView
}

// publishView rebuilds the read-side snapshot from the authoritative
// mu-guarded state and stores it. MUST be called by every mutator, with mu
// held for writing.
func (f *IPFilter) publishView() {
	v := &ipFilterView{mode: f.mode}

	if len(f.single) > 0 {
		v.singles = make(map[netip.Addr]struct{}, len(f.single))
		for s := range f.single {
			// Keys are produced by net.IP.String(), so they always parse and
			// never carry a zone. Skipping an unparseable key is defensive
			// only: the probe side canonicalises identically, so such a key
			// could not have matched anything before this change either.
			if a, err := netip.ParseAddr(s); err == nil {
				v.singles[a.Unmap()] = struct{}{}
			}
		}
	}

	if len(f.nets) > 0 {
		v.prefixes = make(map[netip.Prefix]struct{}, len(f.nets))
		v4 := map[int]struct{}{}
		v6 := map[int]struct{}{}
		for _, n := range f.nets {
			p, ok := prefixFromIPNet(n)
			if !ok {
				v.oddNets = append(v.oddNets, n)
				continue
			}
			v.prefixes[p] = struct{}{}
			if p.Addr().Is4() {
				v4[p.Bits()] = struct{}{}
			} else {
				v6[p.Bits()] = struct{}{}
			}
		}
		v.v4Lens = sortedPrefixLens(v4)
		v.v6Lens = sortedPrefixLens(v6)
	}

	f.view.Store(v)
}

// sortedPrefixLens returns the prefix lengths in ascending order, for a
// deterministic probe order.
func sortedPrefixLens(m map[int]struct{}) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// prefixFromIPNet converts a *net.IPNet into its canonical netip.Prefix.
// ok=false for a non-contiguous mask or a width combination net itself
// rejects — see ipFilterView.oddNets.
//
// The family normalisation here MIRRORS net.networkNumberAndMask, which is
// what net.IPNet.Contains uses, and it is not obvious: a network address that
// To4() accepts is an IPv4 network however many bytes it is STORED in, and a
// 16-byte mask is then re-read as its low four bytes. That makes
// "::ffff:10.0.0.0/104" behave exactly like "10.0.0.0/8" — including matching
// the plain IPv4 address 10.0.0.1 — which a naive "16 bytes means IPv6"
// reading gets wrong in the fail-open direction for a blocklist. Pinned by
// TestIPFilterView_DifferentialAgainstLegacy, which caught precisely this.
//
// A genuinely-IPv6 prefix keeps its 128-bit width, so it goes on failing to
// match IPv4 probes exactly as it does today.
func prefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 0 { // non-contiguous mask
		return netip.Prefix{}, false
	}
	ip := n.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
		if bits == 128 {
			// net drops the leading 96 mask bits (m = m[12:]); the same
			// prefix expressed over 32 bits is 96 bits shorter. To4 only
			// succeeds when those 96 bits survived masking, so ones >= 96.
			ones -= 96
			bits = 32
		}
		if ones < 0 || bits != 32 {
			return netip.Prefix{}, false
		}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || addr.BitLen() != bits {
		return netip.Prefix{}, false
	}
	// Masked() canonicalises so the key equals what a probe's Addr.Prefix(n)
	// produces. net.ParseCIDR already masks, so this is normally a no-op.
	return netip.PrefixFrom(addr, ones).Masked(), true
}

// contains reports whether ipStr matches any entry in the view. Allocation-
// free: netip.ParseAddr returns a value type and every probe is a comparison
// or a map lookup on that value.
func (v *ipFilterView) contains(ipStr string) bool {
	if len(v.singles) == 0 && len(v.prefixes) == 0 && len(v.oddNets) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	// net.ParseIP — what this path used before — rejects a zoned address
	// outright, and a rejected parse means "matches nothing". netip.ParseAddr
	// accepts zones, so drop them here to keep the previous verdict.
	if addr.Zone() != "" {
		return false
	}
	// An IPv4-mapped IPv6 address ("::ffff:10.0.0.1") is an IPv4 address to
	// net.IP.String() and to net.IPNet.Contains (both go through To4). Unmap
	// so it keeps matching v4 entries and keeps NOT matching v6 ones.
	addr = addr.Unmap()

	if _, ok := v.singles[addr]; ok {
		return true
	}

	lens := v.v4Lens
	if !addr.Is4() {
		lens = v.v6Lens
	}
	for _, n := range lens {
		p, err := addr.Prefix(n)
		if err != nil {
			continue // n > addr.BitLen(); cannot happen, family-split above
		}
		if _, ok := v.prefixes[p]; ok {
			return true
		}
	}

	if len(v.oddNets) > 0 {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false
		}
		for _, n := range v.oddNets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// SetMode sets the IP-filter mode. Valid values are "allow" (allowlist),
// "block" (blocklist), and "" (disabled). The mode is stored verbatim — the
// fail-closed handling lives in Allowed(), which denies ALL traffic for any
// unrecognized (corrupt) mode. This is safer than coercing a corrupt value to
// "block" here, which would silently convert a corrupted *allowlist*
// deployment into a permissive blocklist (admitting every non-listed IP). The
// validated admin API path only ever passes "allow"/"block"; the raw
// persistence/snapshot paths (config reload, admin_settings restore,
// config-version rollback, cluster ConfigSnapshot) may carry corruption, and
// Allowed() fails closed on it.
func (f *IPFilter) SetMode(mode string) {
	f.mu.Lock()
	f.mode = mode
	f.publishView()
	f.mu.Unlock()
}

func (f *IPFilter) Mode() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mode
}

// Add accepts plain IPs ("1.2.3.4") or CIDR ("10.0.0.0/8").
//
// Use AddAll to load a LIST — Add publishes the derived view on every call
// (it must: a single admin edit has to take effect immediately), and
// publishView rebuilds that view from the whole entry set, so Add in a loop is
// quadratic. See AddAll.
func (f *IPFilter) Add(entry string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := f.addLocked(entry)
	if err != nil {
		// Rejected entry: nothing changed, so the published view is still current.
		return err
	}
	f.publishView()
	return nil
}

// InvalidIPEntry names one entry AddAll could not parse, so the caller can log
// it exactly as its previous per-entry Add loop did — after the lock is
// released, never underneath it.
type InvalidIPEntry struct {
	Entry string
	Err   error
}

// AddAll appends every valid entry in ONE pass, under ONE lock, publishing the
// derived view ONCE at the end. Invalid entries are skipped and returned; a nil
// result means every entry was accepted.
//
// This is the bulk-load primitive every list-restoring caller must use —
// startup (connlimit_startup.go), admin_settings restore, config-version
// rollback, config import, and the CP→DP snapshot apply. Publishing per entry
// instead makes a bulk load O(N²) in the entry count: measured on a 4-core
// Xeon, an Add loop costs 46 ms at 1k entries, 857 ms at 4k and 3.27 s at 8k
// (each doubling ~4x), which extrapolates to minutes at 100k — and the
// ConfigSnapshot cap for this list is maxSnapIPList (2,000,000). That would
// stall a boot or a snapshot apply on a legitimate enterprise allowlist.
// AddAll is linear. Pinned by TestBenchGate_IPFilterBulkLoadIsLinear.
func (f *IPFilter) AddAll(entries []string) []InvalidIPEntry {
	if len(entries) == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var invalid []InvalidIPEntry
	for _, entry := range entries {
		if err := f.addLocked(entry); err != nil {
			invalid = append(invalid, InvalidIPEntry{Entry: entry, Err: err})
		}
	}
	f.publishView()
	return invalid
}

// addLocked inserts entry into the authoritative write-side state WITHOUT
// publishing. Callers must hold mu for writing and MUST publishView before
// releasing it.
func (f *IPFilter) addLocked(entry string) error {
	if _, cidr, err := net.ParseCIDR(entry); err == nil {
		f.nets = append(f.nets, cidr)
		return nil
	}
	if ip := net.ParseIP(entry); ip != nil {
		f.single[ip.String()] = true
		return nil
	}
	return &net.AddrError{Err: "invalid IP or CIDR", Addr: entry}
}

func (f *IPFilter) Remove(entry string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.single, entry)
	// Remove from nets slice.
	filtered := f.nets[:0]
	for _, n := range f.nets {
		if n.String() != entry {
			filtered = append(filtered, n)
		}
	}
	f.nets = filtered
	f.publishView()
}

// ClearAll removes all IP filter entries. Used by config import "replace" mode.
func (f *IPFilter) ClearAll() {
	f.mu.Lock()
	f.nets = nil
	f.single = map[string]bool{}
	f.publishView()
	f.mu.Unlock()
}

func (f *IPFilter) List() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]string, 0, len(f.single)+len(f.nets))
	for ip := range f.single {
		out = append(out, ip)
	}
	for _, n := range f.nets {
		out = append(out, n.String())
	}
	return out
}

// The membership test itself now lives on the immutable view
// (ipFilterView.contains) — the former (*IPFilter).contains helper existed
// only to be called by Allowed under the read lock that Allowed no longer
// takes.

// Allowed returns true when the IP should be allowed through.
//
// Mode semantics: "allow" = allowlist (only listed IPs pass), "block" =
// blocklist (listed IPs are denied), "" = disabled (filter off, all pass).
// ANY OTHER value is treated as corruption and DENIES ALL traffic (fail
// closed). Coercing a corrupt mode to "block" instead would be unsafe: a
// corrupted *allowlist* deployment (mode was "allow" with a list of the only
// trusted IPs) would become a blocklist that admits every IP not on the list —
// fail open. When we cannot trust the mode, we cannot reason about the list, so
// we deny everything until an operator restores a valid config.
//
// Reads ONE atomic pointer and takes no lock: this runs on every proxied
// request, and an RWMutex.RLock is an atomic read-modify-write on a single
// shared word, so the previous shape made every request in the process
// contend on one cache line — including the default posture, where the filter
// is disabled and the lock guarded a decision that never changes. The mode and
// the entry set are read from ONE view, so a concurrent mutation can no longer
// be observed half-applied either.
func (f *IPFilter) Allowed(ipStr string) bool {
	v := f.loadView()
	switch v.mode {
	case "allow":
		return v.contains(ipStr)
	case "block":
		return !v.contains(ipStr)
	case "":
		return true // filter disabled
	default:
		return false // corrupt/unknown mode — deny all (fail closed)
	}
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

// RateLimiter is a per-IP sliding-window rate limiter using sharded locks to
// minimise contention in the hot path. 64 shards are chosen so that concurrent
// requests from different IPs almost never compete for the same lock.

const rlShardCount = 64

type rlShard struct {
	mu      sync.Mutex
	clients map[string]*clientBucket
}

// RateLimiter is a per-IP sliding-window rate limiter.
type RateLimiter struct {
	shards  [rlShardCount]rlShard
	limit   atomic.Int64
	window  atomic.Int64 // nanoseconds
	enabled atomic.Bool

	// Exempt list — exempt IPs/CIDRs that bypass rate limiting (e.g. monitoring).
	exemptMu   sync.RWMutex
	exemptNets []*net.IPNet
	exemptIPs  map[string]bool
}

// clientBucket is one IP's sliding window of in-window request stamps, held as
// a CIRCULAR BUFFER rather than a plain slice.
//
// Allow runs on every proxied request (handleRequest, socks5.go) and its window
// maintenance used to be a filter-and-copy over the WHOLE bucket:
//
//	valid := b.timestamps[:0]
//	for _, t := range b.timestamps { if t.After(cutoff) { valid = append(valid, t) } }
//	b.timestamps = valid
//
// so the per-request cost was proportional to the bucket's occupancy, which the
// accept test bounds by the CONFIGURED LIMIT. That made the price of the gate
// an operator's rate-limit setting, paid on every request from that IP and paid
// while HOLDING the shard mutex — so it also blocked every other IP hashing to
// the same shard (1/64 of the process's traffic). Measured on a 4-core Xeon
// @2.80GHz, one window-maintenance-plus-accept at half occupancy
// (security_ratelimit_window_bench_test.go, which benchmarks the verbatim
// pre-change algorithm alongside this one so the comparison stays in-tree):
//
//	rate_limit (rpm) │  before   │  after   │ speedup
//	─────────────────┼───────────┼──────────┼─────────
//	        60       │   172 ns  │  24.6 ns │     7x
//	       600       │  1.38 us  │  22.2 ns │    62x
//	     6 000       │  13.2 us  │  22.8 ns │   578x
//	    60 000       │   133 us  │  22.4 ns │  5917x
//
// (medians of n=3; the "before" column is measured in the SAME run, not quoted
// from history — see the bench file.) End to end, Allow across 256 IPs each
// sitting at their cap — the flood shape — is now flat at ~145-170 ns/op and
// 0 allocs/op for both a 600/min and a 6000/min policy, at 1 and 4 cores.
//
// The scan was doing two things linearly that neither needs to be. Stamps are
// APPENDED IN NON-DECREASING ORDER, so the expired entries are always a PREFIX:
// the survivors need no predicate test at all, and the copy that moved them
// back to index 0 exists only because a slice has no other way to drop a head.
// A ring drops the head by advancing an index, so expire stops at the first
// live entry and each stamp is examined exactly once over its whole lifetime —
// amortized O(1) per request, flat in the configured limit.
//
// Memory is unchanged: the ring GROWS LAZILY (doubling, capped at the limit)
// exactly as append did, so an IP that sends two requests under a 6000/min
// policy still holds a handful of slots, not 6000. Pre-sizing to the limit
// would have been simpler and is deliberately not done — at 10k tracked IPs it
// would turn a 6000/min policy into ~1.4 GB of resident buckets.
//
// This is a COST change, not a POLICY change: for any sequence of arrivals with
// non-decreasing stamps — which is every sequence a single goroutine produces —
// the accept/reject decision is identical to the filter-and-copy form, pinned
// against a verbatim copy of it by TestRateLimitWindow_DifferentialAgainstLegacy
// over 300 randomized (limit, window, gap) shapes. The one case that is not
// verdict-identical is a concurrent OUT-OF-ORDER arrival, and it is bounded and
// fail-closed by construction — see the clamp on add.
type clientBucket struct {
	// stamps is the ring storage; its LENGTH is the capacity. head indexes the
	// oldest in-window stamp and n counts them, so the live entries are
	// stamps[head], stamps[head+1], … modulo len(stamps).
	stamps   []time.Time
	head     int
	n        int
	lastSeen time.Time
}

// expire drops every stamp at or before cutoff, stopping at the first live
// one. That is exact — not an approximation of the predicate scan it replaces —
// because add maintains the ring in non-decreasing stamp order.
//
// The test is `!After(cutoff)` so the boundary matches the legacy loop's
// `if t.After(cutoff)` keep-condition exactly (a stamp EQUAL to cutoff is
// expired in both).
func (b *clientBucket) expire(cutoff time.Time) {
	for b.n > 0 && !b.stamps[b.head].After(cutoff) {
		b.head++
		if b.head == len(b.stamps) {
			b.head = 0
		}
		b.n--
	}
}

// add records one stamp, growing the ring first when it is full.
//
// ── Why the stamp is clamped ─────────────────────────────────────────────────
//
// Allow reads time.Now() BEFORE taking the shard lock, so two goroutines can
// sample the clock in one order and reach the append in the other: the arrival
// order is not the stamp order. The old filter-and-copy tested every entry, so
// it did not care; prefix-expiry does, and an out-of-order stamp would make
// expire stop early and leave an already-expired entry counted behind it.
//
// Clamping the new stamp up to the newest one present restores the ordering
// invariant BY CONSTRUCTION, and it is the cheap half of the two available
// fixes: the alternative — moving the clock read inside the shard lock — was
// built and measured, and it costs ~45% of the end-to-end gate at 4 cores
// (153 -> 230 ns/op) because it lengthens a critical section that 1/64 of all
// traffic serialises on. The clamp is one comparison on a value already in
// cache.
//
// What the clamp gives up is bounded and lands FAIL-CLOSED: an inverted stamp
// is recorded as its predecessor's time, so it can only expire EARLIER than
// its true arrival, never later — the window can never admit more than the
// limit. The inversion is bounded by the gap between the clock read and the
// lock acquisition (microseconds) against a window measured in seconds.
func (b *clientBucket) add(t time.Time, limit int) {
	if b.n == len(b.stamps) {
		b.grow(limit)
	}
	i := b.head + b.n
	if i >= len(b.stamps) {
		i -= len(b.stamps)
	}
	if b.n > 0 {
		j := i - 1
		if j < 0 {
			j = len(b.stamps) - 1
		}
		if newest := b.stamps[j]; t.Before(newest) {
			t = newest
		}
	}
	b.stamps[i] = t
	b.n++
}

// grow doubles the ring (from 4), clamped to limit — the occupancy the accept
// test already bounds the window by, so the clamp never truncates a live entry.
// The `b.n+1` floor keeps that true even if the limit was lowered at runtime
// below a bucket's current occupancy.
func (b *clientBucket) grow(limit int) {
	c := len(b.stamps) * 2
	if c == 0 {
		c = 4
	}
	if limit > 0 && c > limit {
		c = limit
	}
	if c <= b.n {
		c = b.n + 1
	}
	next := make([]time.Time, c)
	// Re-lay the ring out linearly so head returns to 0.
	k := copy(next, b.stamps[b.head:])
	copy(next[k:], b.stamps[:b.head])
	b.stamps, b.head = next, 0
}

var rl = newRateLimiter()

func newRateLimiter() *RateLimiter {
	r := &RateLimiter{exemptIPs: map[string]bool{}}
	for i := range r.shards {
		r.shards[i].clients = make(map[string]*clientBucket)
	}
	return r
}

// IsExempt returns true if the IP is in the rate-limit exempt list.
func (r *RateLimiter) IsExempt(ip string) bool {
	r.exemptMu.RLock()
	defer r.exemptMu.RUnlock()
	if r.exemptIPs[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range r.exemptNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// AddExemption adds an IP or CIDR to the rate-limit exempt list.
func (r *RateLimiter) AddExemption(entry string) error {
	r.exemptMu.Lock()
	defer r.exemptMu.Unlock()
	if _, cidr, err := net.ParseCIDR(entry); err == nil {
		r.exemptNets = append(r.exemptNets, cidr)
		return nil
	}
	if ip := net.ParseIP(entry); ip != nil {
		r.exemptIPs[ip.String()] = true
		return nil
	}
	return &net.AddrError{Err: "invalid IP or CIDR", Addr: entry}
}

// RemoveExemption removes an IP or CIDR from the rate-limit exempt list.
func (r *RateLimiter) RemoveExemption(entry string) {
	r.exemptMu.Lock()
	defer r.exemptMu.Unlock()
	delete(r.exemptIPs, entry)
	filtered := r.exemptNets[:0]
	for _, n := range r.exemptNets {
		if n.String() != entry {
			filtered = append(filtered, n)
		}
	}
	r.exemptNets = filtered
}

// ReplaceExemptions atomically replaces the entire rate-limit exempt list.
// Invalid entries are skipped; a nil or empty slice clears the exempt list.
// The new IP/CIDR structures are built OUTSIDE the lock and swapped under a
// single Lock, so a concurrent IsExempt reader never observes a partial or
// stale-mixed state. Used by applyConfigBackup for config-version rollback
// (the missing clear/replace primitive for the RateLimitExempt surface).
func (r *RateLimiter) ReplaceExemptions(entries []string) {
	ips := make(map[string]bool, len(entries))
	var nets []*net.IPNet
	for _, entry := range entries {
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, cidr)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			ips[ip.String()] = true
		}
	}
	r.exemptMu.Lock()
	r.exemptIPs = ips
	r.exemptNets = nets
	r.exemptMu.Unlock()
}

// ListExemptions returns all rate-limit exempt list entries.
func (r *RateLimiter) ListExemptions() []string {
	r.exemptMu.RLock()
	defer r.exemptMu.RUnlock()
	out := make([]string, 0, len(r.exemptIPs)+len(r.exemptNets))
	for ip := range r.exemptIPs {
		out = append(out, ip)
	}
	for _, n := range r.exemptNets {
		out = append(out, n.String())
	}
	return out
}

func (r *RateLimiter) shard(ip string) *rlShard {
	// FNV-1a inspired hash — fast, good distribution.
	h := uint64(14695981039346656037)
	for i := 0; i < len(ip); i++ {
		h ^= uint64(ip[i])
		h *= 1099511628211
	}
	return &r.shards[h%rlShardCount]
}

func (r *RateLimiter) Configure(limit int, window time.Duration) {
	r.limit.Store(int64(limit))
	r.window.Store(int64(window))
	r.enabled.Store(limit > 0)
}

func (r *RateLimiter) Enabled() bool {
	return r.enabled.Load()
}

// Allow returns true if the IP is within its rate limit or is exempt.
func (r *RateLimiter) Allow(ip string) bool {
	if !r.enabled.Load() {
		return true
	}
	if r.IsExempt(ip) {
		return true
	}
	limit := int(r.limit.Load())
	window := time.Duration(r.window.Load())
	now := time.Now()
	cutoff := now.Add(-window)

	s := r.shard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.clients[ip]
	if !ok {
		b = &clientBucket{}
		s.clients[ip] = b
	}
	b.lastSeen = now

	// Evict old timestamps (amortized O(1) — see clientBucket).
	b.expire(cutoff)

	if b.n >= limit {
		return false
	}
	b.add(now, limit)
	return true
}

// Cleanup removes stale client entries (call periodically).
func (r *RateLimiter) Cleanup() {
	window := time.Duration(r.window.Load())
	cutoff := time.Now().Add(-window * 2)
	for i := range r.shards {
		s := &r.shards[i]
		s.mu.Lock()
		for ip, b := range s.clients {
			if b.lastSeen.Before(cutoff) {
				delete(s.clients, ip)
			}
		}
		s.mu.Unlock()
	}
}

func (r *RateLimiter) Limit() int {
	return int(r.limit.Load())
}

func (r *RateLimiter) Window() time.Duration {
	return time.Duration(r.window.Load())
}

// ─── Distributed rate limiting (gossip-based) ────────────────────────────────
//
// Each Data Plane node tracks local per-IP request counts. Periodically, "hot"
// IPs (those exceeding hotThresholdPct of the limit) are reported as deltas to
// the Control Plane. The CP aggregates cluster-wide totals and broadcasts them
// back. Each DP node's Allow() checks: localCount + clusterRemoteCount >= limit.
//
// This avoids Redis: counters stay in-memory, only delta gossip crosses the
// wire, and only for IPs that actually matter.

// hotThresholdPct is the percentage of the rate limit an IP must reach before
// its counts are synced to the Control Plane. Keeps gossip traffic minimal.
const hotThresholdPct = 50

// RateLimitDelta is a per-IP request count delta sent from DP → CP.
type RateLimitDelta struct {
	IP    string `json:"ip"`
	Count int    `json:"count"` // requests since last sync
}

// RateLimitGossip is the DP → CP message containing hot-IP deltas.
type RateLimitGossip struct {
	NodeID string           `json:"node_id"`
	Deltas []RateLimitDelta `json:"deltas"`
}

// RateLimitBroadcast is the CP → DP response with cluster-wide totals
// (excluding the requesting node's own counts, so the DP can add them locally).
type RateLimitBroadcast struct {
	// RemoteCounts maps IP → total requests from OTHER nodes in the current window.
	RemoteCounts map[string]int `json:"remote_counts"`
}

// clusterCounts holds per-IP request totals received from the Control Plane
// (other nodes' aggregated counts). Protected by its own mutex to avoid
// contention with the hot-path Allow() sharded locks.
type clusterCountStore struct {
	mu     sync.RWMutex
	counts map[string]int // IP → remote cluster count in current window
}

var clusterCounts = &clusterCountStore{counts: map[string]int{}}

// Get returns the cluster-remote count for an IP.
func (c *clusterCountStore) Get(ip string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.counts[ip]
}

// Apply replaces the cluster-remote counts with a new broadcast.
func (c *clusterCountStore) Apply(remote map[string]int) {
	c.mu.Lock()
	c.counts = remote
	c.mu.Unlock()
}

// Count returns the number of IPs tracked.
func (c *clusterCountStore) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.counts)
}

// ExportHotDeltas returns per-IP request count deltas for IPs that have
// reached at least hotThresholdPct of the configured limit since the last
// call. Counts are reset after export (delta, not absolute).
func (r *RateLimiter) ExportHotDeltas() []RateLimitDelta {
	if !r.enabled.Load() {
		return nil
	}
	limit := int(r.limit.Load())
	if limit <= 0 {
		return nil
	}
	threshold := limit * hotThresholdPct / 100
	if threshold < 1 {
		threshold = 1
	}
	window := time.Duration(r.window.Load())
	cutoff := time.Now().Add(-window)

	var deltas []RateLimitDelta
	for i := range r.shards {
		s := &r.shards[i]
		s.mu.Lock()
		for ip, b := range s.clients {
			// Count only in-window timestamps. Dropping the expired prefix
			// here rather than counting past it is the same verdict (an
			// expired stamp was never counted) and leaves less for the next
			// Allow to walk.
			b.expire(cutoff)
			count := b.n
			if count >= threshold {
				deltas = append(deltas, RateLimitDelta{IP: ip, Count: count})
			}
		}
		s.mu.Unlock()
	}
	return deltas
}

// clusterRateLimitEnabled is set to true when this node is a Data Plane
// receiving cluster-wide rate limit gossip. Checked by AllowAuto().
var clusterRateLimitEnabled atomic.Bool

// AllowAuto dispatches to AllowClusterAware when cluster rate limiting is
// active, or plain Allow when running standalone. This is the method that
// proxy.go and socks5.go should call.
func (r *RateLimiter) AllowAuto(ip string) bool {
	if clusterRateLimitEnabled.Load() {
		return r.AllowClusterAware(ip)
	}
	return r.Allow(ip)
}

// AllowClusterAware is like Allow but also considers cluster-remote counts.
// Used when the node is operating as a Data Plane in a cluster.
func (r *RateLimiter) AllowClusterAware(ip string) bool {
	if !r.enabled.Load() {
		return true
	}
	if r.IsExempt(ip) {
		return true
	}
	limit := int(r.limit.Load())
	window := time.Duration(r.window.Load())
	now := time.Now()
	cutoff := now.Add(-window)

	s := r.shard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.clients[ip]
	if !ok {
		b = &clientBucket{}
		s.clients[ip] = b
	}
	b.lastSeen = now

	// Evict old timestamps (amortized O(1) — see clientBucket).
	b.expire(cutoff)

	// Check local + remote cluster count against limit.
	localCount := b.n
	remoteCount := clusterCounts.Get(ip)
	if localCount+remoteCount >= limit {
		return false
	}
	b.add(now, limit)
	return true
}
