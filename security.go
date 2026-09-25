package main

import (
	"context"
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

// isPrivateHostContext is isPrivateHost with the DNS lookup bounded by ctx.
//
// CHAOS-71: isPrivateHost resolves under context.Background(), so a wedged
// resolver blocks for the OS budget. On a path that already owns a deadline —
// an IdP metadata fetch during boot or a config sync — a pre-flight guard that
// outlives that deadline is the unbounded-resolver-call shape CHAOS-60/64
// closed, reintroduced by the guard rather than by the request. Use this form
// wherever the caller has a deadline; the guard must never be the unbounded
// step in a bounded operation.
func isPrivateHostContext(ctx context.Context, hostport string) error {
	return ssrf.PrivateHostContext(ctx, hostport)
}

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
// scan over the CIDR list — see prefixSet.
type ipFilterView struct {
	mode string

	// singles is the exact-address set. Keyed by netip.Addr rather than by
	// net.IP.String() so a lookup formats no string and allocates nothing.
	singles map[netip.Addr]struct{}

	// nets answers the CIDR half of the decision.
	nets prefixSet
}

// prefixSet answers ONE question — "does any configured CIDR contain this
// address?" — in time FLAT in the number of CIDRs.
//
// The naive form is a linear scan of net.IPNet.Contains, which makes the
// length of an operator's list the price of every probe. Instead the set is
// bucketed by prefix LENGTH: the address is masked to each DISTINCT length
// present and the result looked up in a map. The number of distinct lengths is
// bounded by 33 (v4) / 129 (v6) and is 2–5 in any real operator config, so the
// cost tracks the number of distinct LENGTHS rather than the number of
// prefixes.
//
// Shared by IPFilter's per-request Allowed() gate and RateLimiter's
// per-request IsExempt() gate. It is deliberately ONE implementation: the
// family normalisation in prefixFromIPNet mirrors net.networkNumberAndMask in
// a way that is easy to get wrong in the FAIL-OPEN direction (see that
// function's comment), and a second copy of it is how that protection rots.
type prefixSet struct {
	// prefixes holds every configured CIDR in canonical (masked) form;
	// v4Lens/v6Lens are the sorted distinct prefix lengths present in it,
	// split by address family so a v4 probe never tests a v6 prefix (which
	// is what net.IPNet.Contains does via its length check).
	prefixes map[netip.Prefix]struct{}
	v4Lens   []int
	v6Lens   []int

	// oddNets carries any *net.IPNet that could not be represented as a
	// netip.Prefix (a non-contiguous mask). net.ParseCIDR — the only writer
	// of either caller's CIDR list — cannot produce one, so this is
	// unreachable in practice; it exists so the representation change can
	// never silently drop an entry from a security filter. Scanned linearly,
	// empty in every real config.
	oddNets []*net.IPNet
}

// buildPrefixSet derives the bucketed form from an authoritative CIDR list.
//
// The result never ALIASES nets: both callers publish it for lock-free reading
// while continuing to mutate their own slice under a write lock, and one of
// those mutators (RemoveExemption / IPFilter.Remove) compacts that slice IN
// PLACE.
func buildPrefixSet(nets []*net.IPNet) prefixSet {
	var s prefixSet
	if len(nets) == 0 {
		return s
	}
	s.prefixes = make(map[netip.Prefix]struct{}, len(nets))
	v4 := map[int]struct{}{}
	v6 := map[int]struct{}{}
	for _, n := range nets {
		p, ok := prefixFromIPNet(n)
		if !ok {
			s.oddNets = append(s.oddNets, n)
			continue
		}
		s.prefixes[p] = struct{}{}
		if p.Addr().Is4() {
			v4[p.Bits()] = struct{}{}
		} else {
			v6[p.Bits()] = struct{}{}
		}
	}
	s.v4Lens = sortedPrefixLens(v4)
	s.v6Lens = sortedPrefixLens(v6)
	return s
}

// empty reports whether the set can match nothing, so a caller can skip
// parsing the probe address entirely.
func (s *prefixSet) empty() bool {
	return len(s.prefixes) == 0 && len(s.oddNets) == 0
}

// contains reports whether any CIDR in the set covers addr, which MUST already
// be Unmap()ped (see ipFilterView.contains for why). Allocation-free on the
// reachable path.
//
// ipStr is the probe's original textual form and is used ONLY by the
// unreachable oddNets fallback, which needs a net.IP to call Contains.
func (s *prefixSet) contains(addr netip.Addr, ipStr string) bool {
	lens := s.v4Lens
	if !addr.Is4() {
		lens = s.v6Lens
	}
	for _, n := range lens {
		p, err := addr.Prefix(n)
		if err != nil {
			continue // n > addr.BitLen(); cannot happen, family-split above
		}
		if _, ok := s.prefixes[p]; ok {
			return true
		}
	}

	if len(s.oddNets) > 0 {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false
		}
		for _, n := range s.oddNets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// emptyIPFilterView is the view of a freshly constructed IPFilter: filter
// disabled, no entries. Filters are built as bare composite literals in
// several places (the DP snapshot path, tests), so Allowed must have a
// well-defined answer before the first mutator publishes.
var emptyIPFilterView = ipFilterView{}

var ipf = &IPFilter{single: map[string]bool{}}

// ipFilterPublishHook is a TEST-ONLY observer of publishView (nil in
// production: one atomic load per publish, which is admin-rate). It lets the
// republish tests prove at RUNTIME which mutator published.
var ipFilterPublishHook atomic.Pointer[func(*IPFilter)]

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

	v.nets = buildPrefixSet(f.nets)

	f.view.Store(v)
	if h := ipFilterPublishHook.Load(); h != nil {
		(*h)(f)
	}
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
	if len(v.singles) == 0 && v.nets.empty() {
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

	return v.nets.contains(addr, ipStr)
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
	//
	// IsExempt is the FIRST decision inside Allow/AllowClusterAware, so once a
	// rate limit is configured it runs on every proxied request. Its read path
	// is therefore LOCK-FREE and FLAT in the CIDR count: it loads an immutable
	// *rlExemptView through an atomic.Pointer and never touches exemptMu. The
	// exemptMu-guarded fields below stay the authoritative write-side state —
	// AddExemption, RemoveExemption, ReplaceExemptions and ListExemptions keep
	// their exact previous semantics — and every mutator republishes a freshly
	// derived view before releasing the lock.
	//
	// A mutator added WITHOUT a publishExemptViewLocked() call is a silent
	// SECURITY failure, not a performance one: a revoked exemption that keeps
	// bypassing the rate limit. Pinned per mutator by
	// TestRLExemptView_EveryMutatorRepublishes.
	exemptMu   sync.RWMutex
	exemptNets []*net.IPNet
	exemptIPs  map[string]bool

	// exemptView is the derived, immutable read-side snapshot. Written only
	// under exemptMu (by publishExemptViewLocked); read without any lock by
	// IsExempt.
	exemptView atomic.Pointer[rlExemptView]
}

// rlExemptView is an immutable snapshot of a RateLimiter's exempt list.
//
// Nothing reachable from a published view is ever mutated in place — a mutator
// builds a REPLACEMENT and stores it — so readers need no synchronisation
// beyond the atomic load.
type rlExemptView struct {
	// ips is the exact-address set, keyed by the RAW probe string exactly as
	// the pre-view map was, and probed with the caller's string verbatim.
	//
	// This is DELIBERATELY not canonicalised to a netip.Addr the way
	// ipFilterView.singles is. AddExemption stores net.ParseIP(entry).String(),
	// so today an IPv4-MAPPED probe ("::ffff:198.51.100.7") misses a single-IP
	// exemption stored as "198.51.100.7". Canonicalising both sides would make
	// it hit — which WIDENS an exemption, i.e. hands a client a rate-limit
	// bypass it does not have today. This change is a COST change, not a
	// POLICY change, so the verdict is preserved byte for byte.
	ips  map[string]bool
	nets prefixSet
}

// emptyRLExemptView is the view of a RateLimiter built as a bare composite
// literal (`&RateLimiter{}`, which the cluster tests do), so IsExempt has a
// well-defined answer before the first mutator publishes.
var emptyRLExemptView = rlExemptView{}

// loadExemptView returns the current read-side snapshot, never nil.
func (r *RateLimiter) loadExemptView() *rlExemptView {
	if v := r.exemptView.Load(); v != nil {
		return v
	}
	return &emptyRLExemptView
}

// publishExemptViewLocked rebuilds the read-side snapshot from the
// authoritative exemptMu-guarded state and stores it. MUST be called by every
// mutator, with exemptMu held for writing.
func (r *RateLimiter) publishExemptViewLocked() {
	v := &rlExemptView{nets: buildPrefixSet(r.exemptNets)}
	if len(r.exemptIPs) > 0 {
		// Copied, not aliased: AddExemption mutates r.exemptIPs in place.
		v.ips = make(map[string]bool, len(r.exemptIPs))
		for ip := range r.exemptIPs {
			v.ips[ip] = true
		}
	}
	r.exemptView.Store(v)
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
//
// Reads ONE atomic pointer and takes no lock: this is the first decision on
// every proxied request once a rate limit is configured, and an
// RWMutex.RLock is an atomic read-modify-write on a single shared word, so the
// previous shape made every request in the process contend on one cache line.
// The CIDR half is answered by prefixSet, so its cost no longer scales with
// the length of the operator's exempt list — measured on a 4-core Xeon, the
// linear scan it replaces cost 3.6 µs per request at 256 exempt CIDRs, which
// was ~74% of the entire rate-limit gate.
//
// An entirely empty exempt list — the common posture for a deployment that
// rate-limits but exempts nothing — short-circuits before the probe address is
// parsed at all. The pre-view shape parsed it unconditionally and then ran an
// empty loop, so the parse was pure waste.
func (r *RateLimiter) IsExempt(ip string) bool {
	v := r.loadExemptView()
	if len(v.ips) == 0 && v.nets.empty() {
		return false
	}
	if v.ips[ip] {
		return true
	}
	if v.nets.empty() {
		return false
	}
	// net.ParseIP — what this path used before — rejects a zoned address
	// outright, and a rejected parse means "exempt nothing". netip.ParseAddr
	// accepts zones, so drop them here to keep the previous verdict.
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return false
	}
	// An IPv4-mapped IPv6 address is an IPv4 address to net.IPNet.Contains
	// (which goes through To4). Unmap so it keeps matching v4 CIDRs and keeps
	// NOT matching v6 ones.
	return v.nets.contains(addr.Unmap(), ip)
}

// AddExemption adds an IP or CIDR to the rate-limit exempt list.
//
// Use AddExemptions to load a LIST — AddExemption publishes the derived view
// on every call (it must: a single admin edit has to take effect immediately),
// and publishing rebuilds that view from the whole entry set, so AddExemption
// in a loop is quadratic. See AddExemptions.
func (r *RateLimiter) AddExemption(entry string) error {
	r.exemptMu.Lock()
	defer r.exemptMu.Unlock()
	if err := r.addExemptionLocked(entry); err != nil {
		// Rejected entry: nothing changed, so the published view is current.
		return err
	}
	r.publishExemptViewLocked()
	return nil
}

// AddExemptions appends every valid entry in ONE pass, under ONE lock,
// publishing the derived view ONCE at the end. Invalid entries are skipped and
// returned; a nil result means every entry was accepted.
//
// This is the bulk-load primitive every list-restoring caller must use — the
// admin_settings restore at boot and config import. Publishing per entry
// instead makes a bulk load O(N²) in the entry count, and the ConfigSnapshot
// cap for this list is maxSnapRateLimitExempt (10,000). Same trap, same shape
// and same reason as IPFilter.AddAll; pinned by
// TestBenchGate_RateLimitExemptBulkLoadIsLinear.
func (r *RateLimiter) AddExemptions(entries []string) []InvalidIPEntry {
	if len(entries) == 0 {
		return nil
	}
	r.exemptMu.Lock()
	defer r.exemptMu.Unlock()
	var invalid []InvalidIPEntry
	for _, entry := range entries {
		if err := r.addExemptionLocked(entry); err != nil {
			invalid = append(invalid, InvalidIPEntry{Entry: entry, Err: err})
		}
	}
	r.publishExemptViewLocked()
	return invalid
}

// addExemptionLocked inserts entry into the authoritative write-side state
// WITHOUT publishing. Callers must hold exemptMu for writing and MUST
// publishExemptViewLocked before releasing it.
func (r *RateLimiter) addExemptionLocked(entry string) error {
	if _, cidr, err := net.ParseCIDR(entry); err == nil {
		r.exemptNets = append(r.exemptNets, cidr)
		return nil
	}
	if ip := net.ParseIP(entry); ip != nil {
		if r.exemptIPs == nil {
			r.exemptIPs = map[string]bool{}
		}
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
	r.publishExemptViewLocked()
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
	r.publishExemptViewLocked()
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
//
// CHAOS-61 — a broadcast EXPIRES. RemoteCounts is, by its own definition, "the
// total from other nodes IN THE CURRENT WINDOW": a broadcast received at T
// describes request timestamps in [T-W, T], where W is the rate limiter's
// sliding window. At now > T+W every timestamp it counted has aged out, so its
// contribution to the current window is exactly zero. That is arithmetic, not a
// posture choice — and until appliedAtNano existed the store had no way to say
// it, because Apply is called ONLY from the DP gossip loop's success branch
// (controlplane_client.go). A failed SyncRateLimits `continue`s, so the last
// broadcast stayed frozen in this map for the rest of the process lifetime
// while AllowClusterAware kept adding it to every local count. An IP whose
// remote total happened to be near the limit when the Control Plane went away
// was then denied on this node PERMANENTLY — a total blackhole for that client,
// on a healthy proxy, cleared only by the CP returning or a restart.
//
// The Control Plane already applies this exact reasoning in the other
// direction: rateLimitAggregator.ClusterTotalsExcluding prunes any node that
// has not reported for two minutes, precisely so a dead DP's frozen counts stop
// suppressing fleet traffic (controlplane.go). Nothing applied it to a dead CP,
// which is the side that actually makes the allow/deny call on live traffic.
//
// The stamp is an atomic OUTSIDE the mutex so the hot path can rule a broadcast
// stale with one atomic load and no lock at all — the case that matters is
// exactly the one where the map is not being replaced and every request would
// otherwise queue on the RWMutex for a value that cannot apply. Apply stores the
// stamp AFTER releasing the write lock, so a reader that observes the new stamp
// necessarily observes the new map.
type clusterCountStore struct {
	mu     sync.RWMutex
	counts map[string]int // IP → remote cluster count in current window
	// appliedAtNano is the wall-clock instant of the last APPLIED broadcast
	// (0 = none ever received). Freshness is evaluated at read time against it;
	// nothing latches, so recovery needs no separate clearing path.
	appliedAtNano atomic.Int64
}

var clusterCounts = &clusterCountStore{counts: map[string]int{}}

// clusterRemoteCountFallbackMaxAge bounds a broadcast's usefulness when the
// rate limiter reports no window (defensive — Configure always sets one). It
// matches the only window the product ships, so the fallback can never be more
// permissive than the real rule.
const clusterRemoteCountFallbackMaxAge = time.Minute

// clusterRemoteCountMaxAge is how long an applied broadcast can still describe
// the current window: the window itself. Kept as a function so the rule stays
// derived from the live limiter rather than duplicated as a second constant
// that could drift away from it.
func clusterRemoteCountMaxAge(window time.Duration) time.Duration {
	if window <= 0 {
		return clusterRemoteCountFallbackMaxAge
	}
	return window
}

// FreshCount returns the cluster-remote count for an IP, or 0 when the applied
// broadcast is older than maxAge (or none has ever been applied). It is the ONLY
// read accessor for enforcement — there is deliberately no unconditional Get, so
// a future caller cannot reintroduce the frozen-count path by accident.
// A NEGATIVE age (the clock moved back between the stamp and this read) is
// stale, not fresh. `age >= maxAge` alone reads a future stamp as brand new and
// would honour the broadcast for however far back the clock went — and it would
// disagree with clusterRateLimitFreshness, which reports the same condition as
// stale. Two answers to one question is the defect; both fail toward the local
// decision, which is where every other failure on this path lands.
func (c *clusterCountStore) FreshCount(ip string, now time.Time, maxAge time.Duration) int {
	applied := c.appliedAtNano.Load()
	if applied == 0 {
		return 0
	}
	if age := now.Sub(time.Unix(0, applied)); age < 0 || age >= maxAge {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.counts[ip]
}

// Apply replaces the cluster-remote counts with a new broadcast and stamps the
// instant it landed. A nil/empty map is a legitimate broadcast (no hot IPs
// anywhere else in the fleet) and correctly clears the previous one.
func (c *clusterCountStore) Apply(remote map[string]int) {
	c.mu.Lock()
	c.counts = remote
	c.mu.Unlock()
	c.appliedAtNano.Store(time.Now().UnixNano())
}

// AppliedAt returns the instant of the last applied broadcast and whether one
// has ever been applied. Read-only; used by the freshness health surface.
func (c *clusterCountStore) AppliedAt() (time.Time, bool) {
	applied := c.appliedAtNano.Load()
	if applied == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, applied), true
}

// Count returns the number of IPs tracked. This is the SIZE of the last applied
// broadcast whether or not it is still fresh — the freshness surface reports
// that separately, so an operator can tell "no hot IPs in the fleet" from "a
// map we stopped consulting".
func (c *clusterCountStore) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.counts)
}

// resetForTest clears the store and its freshness stamp.
func (c *clusterCountStore) resetForTest() {
	c.mu.Lock()
	c.counts = map[string]int{}
	c.mu.Unlock()
	c.appliedAtNano.Store(0)
}

// applyAtForTest applies a broadcast as if it had landed at ts, so a test can
// age a broadcast without sleeping.
func (c *clusterCountStore) applyAtForTest(remote map[string]int, ts time.Time) {
	c.mu.Lock()
	c.counts = remote
	c.mu.Unlock()
	c.appliedAtNano.Store(ts.UnixNano())
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
	//
	// CHAOS-61: the remote half is consulted only while the broadcast carrying
	// it can still describe THIS window. Past that it is not a conservative
	// estimate, it is a count of timestamps that have all aged out — so a
	// Control-Plane outage degrades this node to plain local rate limiting
	// instead of enforcing a frozen snapshot of the past forever.
	localCount := b.n
	remoteCount := clusterCounts.FreshCount(ip, now, clusterRemoteCountMaxAge(window))
	if localCount+remoteCount >= limit {
		return false
	}
	b.add(now, limit)
	return true
}
