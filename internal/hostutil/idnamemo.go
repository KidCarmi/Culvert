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
// The check is on the RAW key, not on the canonical form, because the key is
// what an entry RETAINS and therefore what the ceiling above is derived from.
// That has two consequences, and only the first one is free.
//
// A raw host whose CANONICAL form is also oversize is refused by the dispatch
// gates immediately after canonicalizing it (rejectOversizeCanonicalHost, or
// rejectOversizeUnnormalizableHost when it has no canonical form at all), so it
// never reaches the ~10x per-request fan-out the memo exists to collapse. Not
// retaining such a host costs nothing. Dot-dense ASCII is this shape: it does
// not shrink under IDNA, so 1 KiB raw measures 1 KiB canonical and is refused.
//
// A raw host whose canonical form FITS is a different case, and it is a
// LEGITIMATE one — which is why this paragraph exists rather than the single
// sentence that used to stand here ("a name longer than this cannot be resolved
// by any DNS server"). That sentence is true of a canonical name and false of
// the raw input this check measures: Punycode SHRINKS a wide IDN, and the widest
// legitimate internationalized destination measures 883 raw bytes against 251
// canonical. proxy_host_bounds.go's maxRawDestAuthorityBytes (1 KiB) is sized
// for exactly that host, both dispatch gates therefore ADMIT it, and it resolves
// — so it is never memoized and keeps paying the full un-memoized fan-out.
//
// That gap is deliberate and accepted, not an oversight: covering it means
// retaining keys up to the raw cap, which multiplies the ceiling above by the
// same factor (1024 slots x ~1.3 KB of strings = ~1.3 MB, against the ~554 KB
// TestIDNMemo_BoundedFootprint asserts). The band therefore keeps exactly the
// behaviour it had before this memo existed, which is the one outcome that is
// never a regression. Do NOT move this check onto the normalized form on the
// strength of the retired sentence above without re-deriving that ceiling;
// TestIDNMemo_MaximalLegitimateIDNIsAnswerTransparent re-measures the 883/251
// figure against the real x/net/idna and fails if either half moves.
//
// The verdict is unaffected either way — an oversize host is still normalized,
// just not retained.
const maxMemoHostLen = 253

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
	// Too long to retain (see maxMemoHostLen): normalize and answer, store
	// nothing. Checked before the slot lookup because nothing oversize is ever
	// stored, so the probe could only ever miss.
	if len(host) > maxMemoHostLen {
		return normalizeHostStrictUncached(host)
	}

	slot := normMemoSlot(host)
	if e := slot.Load(); e != nil && e.host == host {
		return e.norm, e.ok
	}

	norm, ok = normalizeHostStrictUncached(host)
	// An in-limit input can in principle grow past the limit through punycode
	// encoding. Punycode shrinks the shapes that matter in practice (a 252-byte
	// CJK host measures 98 bytes as an A-label), so this branch is not expected
	// to be reached — it is here so the ceiling holds by construction rather
	// than by that expectation, and TestIDNMemo_StoredEntriesRespectTheBound
	// asserts the invariant over every entry rather than over this branch.
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
