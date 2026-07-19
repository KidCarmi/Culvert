# T3 P2 — Compact blocklist representation + feed-id attribution (10M unlocker)

**Status:** DESIGN (decision-complete, pre-red-team). P1 (delta sync) shipped and
was reviewed; P2 is the MEMORY PRECONDITION that gates any growth past ~2–3M. This
doc makes concrete engineering decisions so a red-team can break the DESIGN before
any hot-path code is written.

## Why P1 is not enough (the honest memory ceiling)

At 10M exact hosts the current engine (`internal/blocklist`) holds:

- `exact map[string]bool` — Go map bucket overhead (~48–64 B/entry) + string header
  (16 B) + string bytes (~25 B avg host) ≈ **~95–105 B/entry → ~1.0 GB**.
- `feedSrc map[string]string` (host → feed URL) — a second map PLUS a non-interned
  URL string copy per host (~30 B) ≈ **~1.3–1.6 GB**. This is the single biggest
  waste: 10M hosts from a handful of feeds still store 10M URL copies.
- `manual`/`exceptions` — small.

≈ **2.3–2.6 GB steady, ~4 GB with rebuild transients** — an OOM on a 4–8 GB DP
co-resident with the proxy. The P0-2 build-then-swap and the last-good persist all
double this transiently. **10M is not reachable by tuning; it needs the two
structural changes below.**

Target budget: **≤ ~1.5 GB for the blocklist at 10M**, steady AND during a full
rebuild, co-resident with the proxy.

## The two structural changes

### C1 — Compact exact set: immutable packed arena + open-addressing index + delta overlay

Replace `exact map[string]bool` (the millions) with a two-tier structure. Wildcards
stay a small map (thousands, not millions — the label-walk hot path is unchanged).

**Tier 1 — immutable compact base (built on full sync):**
- `arena []byte`: all normalized exact hosts concatenated (no separators; bounds via
  the index). ~25 B/host → **~250 MB at 10M**.
- `index []uint32` or a custom open-addressing hash table: `hash(host) → arena offset`.
  Open addressing at load factor 0.7 with an 8-byte (hash-tag + offset) slot ≈
  **~150–170 MB at 10M**. On a hash hit, the actual host bytes are compared against
  the arena slice → **zero false positives** (the hash only narrows the candidate).
- Parallel `feedIDs []uint32` (see C2), 4 B/host → **~40 MB**.
- Base total ≈ **~450 MB at 10M** (vs ~1.0 GB map), immutable → shareable via an
  atomic pointer, no lock on the read path.

**Tier 2 — mutable delta overlay (ApplyDelta since last compaction):**
- `overlayAdd map[string]struct{}` and `overlayDel map[string]struct{}` — the hosts
  added/removed by deltas since the base was built. Small (deltas between full syncs
  are thousands, not millions), so map overhead is negligible.
- `IsBlocked` exact check: `if overlayDel[host] → not listed; if overlayAdd[host] →
  listed; else → base.contains(host)`. Overlay wins over base (delta semantics).

**Compaction:** when the overlay grows past a threshold (e.g. 5% of base size, or on
the next full ReplaceFeedEntries), rebuild the base from base∖overlayDel ∪ overlayAdd
and clear the overlay. Rebuild is build-then-swap (allocate the new arena+index,
atomic-swap the base pointer, then drop the old) — one compact copy transient, not a
2× map transient. ReplaceFeedEntries IS a compaction (build a fresh base from the CP
list, empty overlay).

**Concurrency:** the base is an immutable `*compactSet` behind an `atomic.Pointer`;
readers load it lock-free. The overlay is guarded by the existing `b.mu`. IsBlocked
takes `b.mu.RLock` only for the (tiny) overlay probe + wildcard/exception maps; the
base probe is lock-free. Writers (ApplyDelta/compaction) hold `b.mu.Lock`.

### C2 — Feed-id attribution: uint32 feed-id + feedID→URL table (replaces feedSrc)

Replace `feedSrc map[string]string` (host → URL, ~1.5 GB) with:
- `feeds []string` — the feed-id → URL table (a few hundred entries; feed-id is the
  index). Interned: one URL string per feed, not per host.
- `feedIDs []uint32` — per-host feed-id, parallel to the base index (0 = a reserved
  "unattributed/legacy" id; manual is tracked separately in `manual`). **~40 MB at
  10M** vs ~1.5 GB. This is the dominant win.
- `RemoveByFeedSource(url)` → resolve url→feed-id, then scan `feedIDs` and drop
  matching (non-manual) hosts. O(N) scan, but cascade-delete is an admin action, not
  hot-path. `CountByFeedSource` likewise.
- Overlay-added hosts carry their feed-id in a parallel `overlayAddFeed map[string]uint32`.

## IsBlocked semantics (frozen)

Order, per request (unchanged verdict for every existing input):
1. `exceptions` (never-block) — small map, unchanged.
2. exact: overlay (del→false, add→true) → compact base (`contains`).
3. wildcard label-walk over `wildcards` (small map) — unchanged.
4. `mode` (block vs allow) inversion — unchanged.

**No false positives** (arena verification). **No false negatives** — a host in the
base OR overlayAdd and not overlayDel is listed. Manual blocks are re-injected on
every compaction (the PR #249 invariant) and live in `overlayAdd`/base + `manual`.

## The hot-path benchmark gate (NON-NEGOTIABLE)

`IsBlocked` is on every proxy + SOCKS5 request. A compact structure that regresses
p99 lookup is unacceptable. A benchgate (`//go:build benchgate`) asserts:
- p99 `IsBlocked` latency for a 10M base does NOT regress vs the current map beyond a
  fixed budget (e.g. ≤ 1.5× the map's ns/op; open-addressing + one arena compare
  should be within ~1.2×).
- allocs/op on the read path is ZERO (no per-lookup allocation — the host is already
  a string; hashing is alloc-free).
- the overlay probe adds bounded cost even at the compaction threshold.

## Migration / rollout (fail-safe)

- **Threshold-gated:** the compact engine activates only above a host count where it
  pays (e.g. ≥ 500k exact); below that the existing `map[string]bool` path is kept
  BYTE-IDENTICAL. Small deployments are untouched and unrisked.
- **Feature flag:** `CULVERT_BLOCKLIST_COMPACT` (default: auto by threshold; `off`
  forces the legacy map; `on` forces compact) — read once at load, node-local.
- **No wire/format change:** the on-disk blocklist file + sidecars are unchanged; the
  compact set is an in-memory representation built at Load/ReplaceFeedEntries. The CP
  ConfigSnapshot, delta wire contract, and synced fingerprint are UNCHANGED (the
  fingerprint is defined over the host set, representation-independent).
- **Rollback-safe:** switching the flag off rebuilds the map from the same file.

## REVISED SEQUENCING (post-analysis): the duplicate-map elimination is the dominant, low-risk win — do it FIRST, arena LATER

A closer look at the memory model changes the order. Today every host is stored
TWICE in memory: once as a key in `exact map[string]bool` (~0.9 GB at 10M) and
AGAIN as a key in `feedSrc map[string]string` (~1.35 GB — the host key repeated
PLUS a non-interned URL string copy per host). The single biggest waste is the
DUPLICATE KEY, not just the URL copy.

**Slice 1 = merge attribution INTO the exact map + intern feed URLs, eliminating
the `feedSrc` map entirely.** `exact` becomes `map[string]uint32` where presence =
blocked and the value = a feed-id into a tiny interned `feeds []string` table
(0 = unattributed/legacy; manual stays tracked in `manual`). This:
- kills the ~1.35 GB second map → ~0.93 GB total at 10M (a **~1.3 GB cut**), so
  **10M fits an 8 GB DP with NO arena/overlay/compaction**;
- touches the hot path minimally — `IsBlocked` still does ONE map probe and
  ignores the value (no torn-read risk, no overlay-first regression, no
  open-addressing/hash-flood surface — the concerns the C1 arena introduced);
- keeps the on-disk `.sources` format unchanged (resolve id→URL on Save) — no
  wire/format change, fingerprint unchanged.

**C1 (the arena + overlay + compaction) is DEFERRED to an optional later slice**,
justified only if 4 GB DPs must hold 10M (measure Slice-1 RSS first). This
sidesteps the entire high-risk hot-path rewrite unless the numbers demand it.

Risk that remains for Slice 1: it rewrites ~8 interdependent, frozen,
security-relevant methods (RemoveByFeedSource / CountByFeedSource / ListWithSource
/ RestoreFeedSources / RemoveUnattributedFeedEntries / SnapshotFeedSources /
ClearAll / Remove / Add / ReplaceFeedEntries) against feed-ids. Mitigation:
byte-identical semantic-parity tests for every method (same verdict, same
attribution, same cascade-delete set) + a code red-team after implementation (the
P1 pattern), NOT a design red-team.

### SHIPPED — Slice 1a: intern the feed URLs (map[string]uint32 + feeds table)

Sequencing decision (unattended-implementation discipline): the risky part of the
merge is changing `exact`'s type and the `IsBlocked` hot path. The URL interning —
`feedSrc map[string]string` → `map[string]uint32` + an interned `feeds []string`
(ID 0 = unattributed) + a `feedIDs` intern index — captures a large share of the
memory win (10 M non-interned ~30-byte URL copies, ~0.5 GiB, collapse to a
few-hundred-entry table + a 4-byte ID/host) and touches ONLY the ~8 attribution
methods — NEVER `exact`, `manual`, `wildcards`, or the `IsBlocked` hot path. The
on-disk `.sources` format (host→URL JSON) and every public accessor
(SnapshotFeedSources/RestoreFeedSources/ListWithSource return host→URL by
resolving IDs) are unchanged, so nothing outside `internal/blocklist` moves. This
alone brings 10 M under an 8 GiB DP.

**Slice 1b (still C1's dominant win, deferred):** merge `feedSrc` INTO `exact`
(`exact map[string]uint32`, presence = blocked, value = feed-ID) to eliminate the
DUPLICATE HOST KEY — the ~0.9 GiB the two maps each pay for storing every host
string. That is the change that unlocks 4 GiB DPs; it touches the `IsBlocked`
probe (bool → presence check) and warrants its own slice + code red-team.

## Slicing (each independently shippable + benchmarked)

- **P2.1 — compactSet (arena + open-addressing index), read-only + benchgate.** Build
  from a host list, `contains`, iteration. No overlay, no attribution yet. Prove the
  hot-path budget on a 10M synthetic set BEFORE wiring it in.
- **P2.2 — overlay + compaction**, wire `contains`/ApplyDelta through it; the Store's
  exact set becomes compactSet+overlay behind the flag/threshold. Keep the legacy path.
- **P2.3 — feed-id attribution** (feeds table + feedIDs), rewrite RemoveByFeedSource /
  CountByFeedSource / ListWithSource / RestoreFeedSources / RemoveUnattributedFeedEntries
  against feed-ids; drop feedSrc for the compact path.
- **P2.4 — flip the default** above the threshold once P2.1–P2.3 are proven; document
  the per-DP RAM budget curve (hosts → measured RSS).

## Non-negotiable invariants (carried from P1 + red-team)

- IsBlocked verdict is byte-identical to the map for every input (no false pos/neg).
- Manual blocks survive every compaction/rebuild (PR #249).
- The synced fingerprint is representation-independent (unchanged over C1/C2).
- ALLOW-mode set changes are atomic build-then-swap (a partial set denies all traffic).
- The p99 hot-path benchmark gate must pass before P2.4 flips the default.
- No phase advertises a host count its own measured RSS cannot hold.

## Open decisions for the red-team

- Arena+open-addressing vs. a sorted-arena binary search vs. a compressed trie —
  which actually wins p99 at 10M with zero read allocs? (This doc picks
  open-addressing; prove or break it.)
- Overlay compaction threshold + whether a long-lived overlay can degrade p99.
- The uint32 feed-id ceiling (4B distinct feeds — fine) and the 0=unattributed
  reservation vs. manual tracking overlap.
- Whether wildcards ever reach a scale that needs the same treatment (today: no).
- 32-bit arena offset ⇒ a 4 GiB arena ceiling (~160M avg-length hosts) — headroom at
  10M, but is uint32 the right offset width, or do we need uint64 for safety?
