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
// 1024 x (entry header + two hosts of at most 253 bytes each), i.e. well under
// 1 MB even if every slot were filled with maximum-length hosts, and a few tens
// of KB in practice. The table is read-mostly (a write happens only on a cold
// miss), so the 8 KB of pointers sharing cache lines costs nothing measurable;
// padding each slot to a cache line would trade 56 KB of footprint for no win.
const normMemoSlots = 1024

// normMemoMask turns a hash into a slot index.
const normMemoMask = normMemoSlots - 1

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
	// normMemo is the table. A nil slot has never been filled.
	normMemo [normMemoSlots]atomic.Pointer[normMemoEntry]
)

// normMemoSlot returns the slot a key maps to. maphash.String is allocation-free.
func normMemoSlot(host string) *atomic.Pointer[normMemoEntry] {
	return &normMemo[maphash.String(normMemoSeed, host)&normMemoMask]
}

// normalizeHostStrictMemo answers the slow path for host, which the caller has
// already lowercased, dot-trimmed and established is neither empty nor
// already-canonical ASCII. On a hit it allocates nothing.
func normalizeHostStrictMemo(host string) (norm string, ok bool) {
	slot := normMemoSlot(host)
	if e := slot.Load(); e != nil && e.host == host {
		return e.norm, e.ok
	}

	norm, ok = normalizeHostStrictUncached(host)

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
