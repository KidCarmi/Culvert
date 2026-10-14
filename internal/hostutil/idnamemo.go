package hostutil

import (
	"hash/maphash"
	"strings"
	"sync/atomic"
)

// ── Memoized IDNA normalization (the NormalizeHostStrict slow path) ──────────
//
// NormalizeHostStrict's already-canonical fast path (hostutil.go) covers a host
// that is pure ASCII and carries no ACE label, which is most traffic, at 0
// allocations. Everything else — an "xn--" A-label or a Unicode U-label — falls
// through to idna.ToASCII, and that is the expensive branch:
//
//	shape                              cost per call (Xeon @2.10GHz, Go 1.26)
//	ACELabel    xn--bcher-kva.example.com   ~785 ns   256 B    7 allocs
//	UnicodeIDN  bücher.example.com          ~645 ns   192 B    5 allocs
//	ASCII       sub.cdn.assets.example.com   ~70 ns     0 B    0 allocs
//
// The cost that matters is not one call: it is that the SAME destination host is
// normalized ~10x per proxied request by engines that each defensively normalize
// their own input (the strict dispatch gate, SOCKS5, policy Evaluate, auth
// policy, category resolution, the blocklist, the threat feed, the SSL-bypass
// matcher, autoexclude, urlcat, traffic redaction). That fan-out is deliberate
// and correct — every engine owns its own canonicalization — so the fix is not
// to thread one value through all of them, it is to make the repeat cheap.
//
// Un-memoized, an internationalized destination therefore costs ~8 µs of CPU and
// ~70 allocations per request on host normalization alone, against ~0.7 µs and 0
// allocations for an ASCII destination: an ~11x asymmetry on a path every request
// walks. And this is NOT an exotic shape. Browsers put the A-label in the HTTP
// Host header and the CONNECT authority — a user who types "bücher.example.com"
// sends "xn--bcher-kva.example.com" — so the 7-allocation row above is the live
// cost of every request to an internationalized domain, not a Unicode edge case.
// The asymmetry is also client-selectable: an authority full of ACE labels costs
// the sender nothing and costs this process the full fan-out.
//
// ── Why a memo is safe here, specifically ───────────────────────────────────
//
// IDNA normalization is a PURE function of its input. The mapping from host to
// canonical form has no clock, no configuration, no I/O and no dependence on
// process state; it changes only when golang.org/x/net/idna is upgraded, which
// is a new binary and therefore a new process with an empty table. So this is a
// memo, not a cache: there is no staleness to reason about, no invalidation to
// get wrong, and no TTL to tune. A hit is indistinguishable from recomputing.
//
// ── Bounding, because the key is client-controlled ──────────────────────────
//
// The key is a destination authority, so the key space is attacker-chosen and
// unbounded. The table is therefore DIRECT-MAPPED with a fixed slot count: one
// entry per slot, and a colliding host simply overwrites the entry that was
// there. That gives a hard memory ceiling with no eviction bookkeeping, O(1)
// work on every path, and the only failure mode is a miss — which costs exactly
// what the code costs today. The table cannot grow, cannot be made to return a
// wrong answer (every hit re-verifies the full key), and cannot be made to leak:
// worst case it degenerates to the current behaviour.
//
// The slot is chosen with a per-process random maphash seed, so an adversary
// cannot precompute a set of hosts that collide into one slot and thrash the
// memo. Even if they could, see above: the penalty is recomputation.
//
// Only slow-path hosts are ever inserted. Ordinary ASCII traffic returns from
// the fast path above and never touches this table — it adds no lookup, no
// write, and no cache-line traffic to the common case. That is deliberate: the
// fast path is already 0-alloc and must stay exactly as cheap as it is.

// normMemoSlots is the fixed number of direct-mapped slots. Power of two so the
// slot index is a mask rather than a division.
//
// Sizing: a deployment's set of live internationalized destinations is small —
// this is the IDN tail of the destination set, not the destination set — so 1024
// slots hold far more than a real working set while bounding the table at
// 1024 x (entry header + two strings of at most maxMemoHostLen bytes each),
// i.e. well under 1 MB even if every slot were filled with maximum-length
// hosts, and a few tens of KB in practice. The table is read-mostly (a write
// happens only on a cold miss), so the 8 KB of pointers sharing cache lines
// costs nothing measurable; padding each slot to a cache line would trade
// 56 KB of footprint for no win.
const normMemoSlots = 1024

// maxMemoHostLen is the longest string this table will retain, per entry field.
// It is the RFC 1035 maximum length of a DNS name, and it is what makes the
// footprint ceiling above a provable bound rather than an expectation.
//
// It is load-bearing, not cosmetic. The zero-option idna.ToASCII profile does
// NOT enforce the DNS length limit (the bidi and length checks are disabled —
// see NormalizeHostStrict), and on the HTTP path the destination authority
// reaches here BEFORE the 253-byte canonical refusal: handleRequest's raw
// pre-cap admits up to maxRawDestAuthorityBytes (1 KiB), canonicalDestHost
// normalizes it, and only then does rejectOversizeCanonicalHost refuse it. So
// without this check a client could park ~1 KiB per slot — measured at ~2.1 MB
// across a full table, four times the ceiling documented above — and the
// non-request callers (feed parsing, admin patterns) are not bounded by that
// 1 KiB gate at all.
//
// What it does NOT justify is the claim this comment used to make — that
// refusing to memoize such a host "costs nothing", because "a name longer than
// this cannot be resolved by any DNS server, and both dispatch gates refuse it
// immediately after canonicalizing it". Both halves of that are wrong, because
// the bound is measured on the key as the CLIENT SPELLED IT, which is not the
// length DNS ever sees. IDNA SHRINKS a U-label authority: proxy_host_bounds.go
// records the worst LEGITIMATE case as 883 raw bytes collapsing to a 251-byte
// A-label, which is why the raw pre-cap is 1 KiB and not 253. So a host whose
// raw spelling exceeds this bound can canonicalize well inside the DNS limit,
// with every label inside the 63-byte A-label limit too — a resolvable,
// ordinary internationalized destination. Both dispatch gates then ACCEPT it.
// It is not refused; it walks the full ~10x per-request fan-out with nothing
// memoized, which is the asymmetry this file exists to close.
//
// Measured per NORMALIZATION of one such accepted destination — 8 U-labels of
// 20 CJK code points plus ".example.com", i.e. 499 raw bytes, 227 canonical,
// longest canonical label 26 (Xeon @2.80GHz, go1.26.9, -count=2):
//
//	stage of NormalizeHostStrict                    cost        allocs
//	strings.ToLower + TrimSuffix                  2 840 ns        0
//	isCanonicalASCIIHost scan                         1.3 ns      0
//	idna.ToASCII                                  5 320 ns       18
//	memo lookup, warm hit (replaces idna)            71 ns        0
//	whole function, ASCII destination                 50 ns        0
//
// So the main tier's key bound left ~5.3 µs and 18 allocations per call on this
// shape, ~53 µs and 180 allocations per request across the fan-out.
// TestIDNMemo_LongRawULabelHostIsAcceptedAndRetained pins it: the host is
// DNS-valid (every canonical label inside the 63-byte limit), both gate
// predicates admit it, its raw spelling is past this bound, and it must be
// retained.
//
// The verdict is unaffected either way — a host over the bound is still
// normalized, just not retained — so this was a completeness gap in an
// optimization, never a wrong answer or a policy decision. Raising THIS bound
// to cover it would multiply the ceiling above by the raw/canonical ratio, so
// the shape is retained in a separately bounded tier instead; see
// maxMemoLongKeyLen.
//
// ── The residual, stated plainly ────────────────────────────────────────────
//
// The table above also says what the memo does NOT fix. strings.ToLower runs
// strings.Map(unicode.ToLower, …) for a non-ASCII input — a per-rune table walk
// over the whole authority — and it sits in NormalizeHostStrict AHEAD of both
// the fast path and this memo, so no tier can collapse it. At ~2.84 µs per call
// it is ~28 µs per request across the fan-out, against ~50 ns for an ASCII
// destination, and it is selected by the client at the cost of ~500 header
// bytes. That asymmetry is NOT closed here: hoisting or narrowing the lowering
// pass would change what canonicalization does to non-ASCII input, which is the
// IDN-homograph contract NormalizeHost exists to enforce (RISK-013), and that
// is a change for the differential fuzz harness and review, not a perf patch.
const maxMemoHostLen = 253

// normMemoMask turns a hash into a main-tier slot index.
//
// Typed uint64 so the mask needs no conversion at the call site. An
// `&uint64(len(table)-1)` computed from the slice instead is a runtime
// int->uint64 conversion, which gosec reports as G115 (CWE-190) at HIGH — and
// correctly, as a matter of form: on a zero-length table len-1 is -1, which
// converts to an all-ones mask and indexes out of range. That cannot happen
// here (a nil table returns before the lookup and both tiers are non-empty
// constants), but the fix is to not perform the conversion rather than to
// suppress the report, so the shape carries no latent out-of-range index for a
// later reader to re-derive.
const normMemoMask uint64 = normMemoSlots - 1

// maxMemoLongKeyLen is the longest KEY the long tier retains. The long tier
// exists for exactly one shape: the U-label authority whose RAW spelling is
// over maxMemoHostLen but whose CANONICAL form is inside it, which both
// dispatch gates accept and which the main tier therefore refused to retain
// while it walked the full per-request fan-out (see maxMemoHostLen).
//
// It is set to the request path's RAW pre-cap (maxRawDestAuthorityBytes in
// proxy_host_bounds.go, 1 KiB), which makes the property this tier exists for
// hold BY CONSTRUCTION: every authority a dispatch gate can admit is an
// authority the memo can retain. Sizing it to the empirical maximum IDN
// expansion instead — 883 raw bytes for a 253-byte canonical authority, pinned
// by that file's TestChaos69_ControlRawCapExceedsMaximumIDNExpansion — would
// re-open the same gap in miniature, narrower but resting on a measurement
// rather than a bound: an authority in the 883..1024 band that canonicalized
// inside the DNS limit would be accepted and still not retained. The extra
// 17 KiB of ceiling is a better trade than that doubt, and the root
// TestHostutilLongRawULabelReachesTheMemo asserts the relation rather than the
// number, so raising the raw pre-cap fails there instead of silently
// reintroducing the asymmetry.
//
// Callers that are NOT bounded by that gate — threat-feed parsing, admin
// patterns — can still exceed this, and are normalized without being retained
// exactly as before.
const maxMemoLongKeyLen = 1024

// normMemoLongSlots is the long tier's fixed slot count. Power of two, so the
// slot index is a mask rather than a division, like the main tier's. It is
// deliberately SMALL. Legitimate traffic barely produces this shape at all — a browser puts
// the A-label in the Host header and the CONNECT authority, so a long raw
// U-label reaches the proxy only from a client that sends Unicode verbatim —
// so the live working set is a handful of destinations, not a tail. 128 slots
// hold that many times over while bounding this tier at
// 128 x (entry header + maxMemoLongKeyLen + maxMemoHostLen), i.e. ~165 KB, so
// the two tiers together stay well inside a megabyte.
//
// The sizing is also what keeps this honest about what it does and does not
// buy. A direct-mapped miss costs exactly what the code cost before the memo,
// so an adversary ROTATING long U-label hosts gets the pre-memo behaviour
// either way — the memo never claimed to bound that, and this tier does not
// either. What it removes is the repeated-destination case: ~53 µs of CPU and
// 180 allocations per request for one accepted destination requested over and
// over, whether by an attacker or by a legitimate client of a long
// internationalized name. The ~28 µs lowering pass documented under
// maxMemoHostLen remains in both cases.
const normMemoLongSlots = 128

// normMemoLongMask turns a hash into a long-tier slot index. Typed for the same
// reason as normMemoMask.
const normMemoLongMask uint64 = normMemoLongSlots - 1

// normMemoEntry is one memoized answer. Entries are immutable once published:
// a writer builds a new one and stores the pointer, so a concurrent reader sees
// either the previous entry or this one, never a half-written mix. host is the
// EXACT key the entry answers for (post-lowering, post-dot-trim), re-verified on
// every hit, which is what makes a direct-mapped collision a miss rather than a
// wrong answer.
type normMemoEntry struct {
	host string
	norm string
	ok   bool
}

var (
	// normMemoSeed randomizes slot selection per process (see above).
	normMemoSeed = maphash.MakeSeed()
	// normMemo is the main table, for keys within maxMemoHostLen. A nil slot
	// has never been filled.
	normMemo [normMemoSlots]atomic.Pointer[normMemoEntry]
	// normMemoLong is the long tier, for keys within maxMemoLongKeyLen. Same
	// entry type, same immutability and same re-verification; only the slot
	// count and the key bound differ.
	normMemoLong [normMemoLongSlots]atomic.Pointer[normMemoEntry]
)

// normMemoTableFor returns the tier that may retain host and that tier's slot
// mask, or nil when no tier may. Both tiers are returned as slices so one
// lookup body serves both; the slice header is stack-allocated and the hit path
// stays 0-alloc (pinned by TestIDNMemo_AllocRegression and
// TestIDNMemo_LongTierHitIsAllocationFree).
//
// The mask travels WITH the table rather than being derived from len(table) at
// the call site, so it is a typed constant and never a conversion — see
// normMemoMask. TestIDNMemo_TierMasksMatchTheirTables pins each pair.
func normMemoTableFor(host string) (table []atomic.Pointer[normMemoEntry], mask uint64) {
	switch {
	case len(host) <= maxMemoHostLen:
		return normMemo[:], normMemoMask
	case len(host) <= maxMemoLongKeyLen:
		return normMemoLong[:], normMemoLongMask
	default:
		return nil, 0
	}
}

// normalizeHostStrictMemo answers the slow path for host, which the caller has
// already lowercased, dot-trimmed and established is neither empty nor
// already-canonical ASCII. On a hit it allocates nothing.
func normalizeHostStrictMemo(host string) (norm string, ok bool) {
	// Too long for either tier to retain (see maxMemoLongKeyLen): normalize and
	// answer, store nothing. Decided before the slot lookup because nothing
	// that long is ever stored, so the probe could only ever miss.
	table, mask := normMemoTableFor(host)
	if table == nil {
		return normalizeHostStrictUncached(host)
	}

	slot := &table[maphash.String(normMemoSeed, host)&mask]
	if e := slot.Load(); e != nil && e.host == host {
		return e.norm, e.ok
	}

	norm, ok = normalizeHostStrictUncached(host)
	// A FAILED normalization is retained only in the main tier. In the long
	// tier it buys nothing and costs the whole key, so it is not stored.
	//
	// The asymmetry is in the dispatch gates, not in this table. An
	// unnormalizable host whose bare form exceeds maxDestHostLen is refused
	// IMMEDIATELY: on HTTP by rejectOversizeUnnormalizableHost, which runs right
	// after canonicalDestHost and ahead of the connection limiter, the rate
	// limiter, Stage-1 auth and every matcher; on SOCKS5 by the RISK-013 gate at
	// the normalization point itself, ahead of every matcher. One normalization,
	// no fan-out — so a hit could never pay back the ~1 KiB key clone and the
	// entry allocation that storing it costs, and a client sending UNIQUE
	// malformed long authorities would pay that on every request for nothing.
	//
	// A SHORT unnormalizable host is different, and that is why the main tier
	// still memoizes failures: its bare form is inside maxDestHostLen, so the
	// oversize gate does not fire and it proceeds through the limiters into
	// Stage-1 authentication — which resolves category fusion through
	// authRuleMatchesScratch — before the RISK-013 refusal is reached. That path
	// does normalize repeatedly, and the MalformedACE benchmark row (311 ns ->
	// 31 ns) is it. Found by Codex review on PR #1624; verified against both
	// dispatch gates.
	if !ok && len(host) > maxMemoHostLen {
		return norm, ok
	}

	// The VALUE bound, enforced for both tiers. maxMemoHostLen is the DNS name
	// maximum, so a canonical form longer than it is refused by the dispatch
	// gates (canonicalHostOversize) and retaining it would buy nothing while
	// loosening the ceiling. A main-tier input can in principle grow past the
	// bound through punycode encoding, and a long-tier input reaches here
	// precisely because its raw form is longer — so for the long tier this is
	// the live check, not a defensive one. Either way the ceiling holds by
	// construction, and TestIDNMemo_StoredEntriesRespectTheBound asserts the
	// invariant over every live entry in both tiers rather than over this branch.
	if len(norm) > maxMemoHostLen {
		return norm, ok
	}

	// Store a CLONE of the key, never the caller's string. host here is a
	// substring of whatever the caller passed in (strings.ToLower returns its
	// input unchanged when there is nothing to lower, and TrimSuffix returns a
	// substring), so keeping it would pin that whole backing array — a request
	// header's buffer — for as long as the entry lives. The clone is bounded by
	// the host length and is paid only on a cold miss.
	key := strings.Clone(host)
	if norm == host {
		// The IP-literal branch returns the input verbatim. Share the clone
		// rather than allocating a second copy, and return it: it is the same
		// value, and it drops the caller's backing array for this result too.
		norm = key
	}
	slot.Store(&normMemoEntry{host: key, norm: norm, ok: ok})
	return norm, ok
}
