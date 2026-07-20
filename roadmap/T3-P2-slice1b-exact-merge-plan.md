# T3 P2 slice 1b — merge feedSrc INTO exact (eliminate the duplicate host key)

**Status:** DESIGN (decision-complete, pre-red-team). Slice 1a (feed-URL
interning → `feedSrc map[string]uint32` + `feeds` table) shipped. Slice 1b
eliminates the DUPLICATE HOST KEY: today every host string is stored twice — once
as a key in `exact` (`map[string]uint32` after... no — `exact` is still
`map[string]bool`) and again as a key in `feedSrc`. At 10 M hosts the second
key-set is ~0.9 GiB. This slice folds attribution INTO the enforcement maps so a
host string is stored ONCE.

## The change

- `exact map[string]bool` → **`exact map[string]uint32`** (presence ⇒ blocked;
  value = feed-source ID, 0 = unattributed/manual).
- `wildcards map[string]bool` → **`wildcards map[string]uint32`** (same; keyed by
  the `.example.com` suffix as today). Wildcards are few (thousands), but they
  ALSO carry feed attribution today (feedSrc holds `*.x` keys), so their
  attribution must move here too — otherwise RemoveByFeedSource/ListWithSource
  lose wildcard attribution.
- **`feedSrc` is DELETED.** `feeds []string` + `feedIDs map[string]uint32` stay.
- `manual map[string]bool`, `exceptions map[string]bool` unchanged.

Memory at 10 M: the ~0.9 GiB second key-set disappears; net blocklist ≈ ~0.93 GiB
(from ~1.6 GiB after 1a). This is the change that lets a 4 GiB DP hold 10 M.

## Hot-path change (the risk)

`isListed` / `IsBlocked`:
```
if b.exact[host] { … }                       →  if _, ok := b.exact[host]; ok { … }
… b.wildcards[host[i:]] …                     →  _, ok := b.wildcards[host[i:]]; ok
b.wildcards["."+host]                         →  _, ok := b.wildcards["."+host]; ok
```
Presence (`, ok`) replaces the bool value. This is behavior-identical because the
maps only ever stored `true` (present ⟺ true), and the uint32 value is NEVER
consulted for the block/allow verdict — it is attribution metadata only. allocs/op
on the read path is unchanged (a map probe with the comma-ok form is the same
lookup). The benchgate p99 IsBlocked must not regress.

## Every write/read site that must change (the enumerated surface)

1. **isListed** (hot path) — presence checks, as above. `isExcepted` unchanged
   (exceptions stays `map[string]bool`).
2. **Add(host)** — `b.exact[host] = 0` (feed sync stamps the ID separately) or set
   directly; but must NOT clobber an existing non-zero ID → `if _, ok := b.exact[host]; !ok { b.exact[host] = 0 }`.
3. **AddManual / AddManualBulk** — add to `manual`; for `exact`/`wildcards`, add
   only if ABSENT (do NOT reset an existing feed-ID to 0): a host that is both
   feed-carried and admin-manual keeps its feed-ID in the map but is shown/treated
   as manual (manual[] wins in ListWithSource + is skipped by RemoveByFeedSource),
   matching 1a exactly.
4. **MergeFromLines** (feed import) — add-if-absent, then stamp `exact[line]=id` /
   `wildcards[suffix]=id` for `source!="" && !manual[line]`. Replaces the old
   feedSrc stamp. The `added` counter still counts only newly-present hosts.
5. **ReplaceFeedEntries** (CP→DP apply, rollback, import-replace) — THE SUBTLE ONE.
   It rebuilds exact/wildcards from a plain host list (NO feed-IDs) and re-injects
   manual. Naively rebuilding would RESET every host's feed-ID to 0, wiping
   attribution — a regression vs 1a (where feedSrc is a separate map ReplaceFeedEntries
   never touches). Fix: carry forward the OLD map's feed-ID for each surviving
   host: `newExact[h] = oldExact[h]` (0 if the host is new). One O(1) lookup per
   host during the rebuild (already O(N)). Manual re-injection sets ID 0 for
   manual-only hosts (unchanged block behavior). syncedFP recompute unchanged
   (it hashes host tokens, representation-independent).
6. **ApplyDelta** (delta path) — adds/removes hosts. Added feed hosts have no
   feed-ID (delta is CP-authoritative, not feed-attributed) → ID 0. Removed hosts
   delete from exact/wildcards (+ the old `delete(feedSrc,...)` is gone; the ID
   dies with the map entry). Manual protection unchanged. The syncedFP XOR
   maintenance is unchanged.
7. **Remove(host)** — `delete(exact/wildcards)` + `delete(manual)`; the old
   `delete(feedSrc,host)` is gone (ID dies with the entry).
8. **List / FeedList / Count** — iterate map keys (unchanged); FeedList excludes
   manual (unchanged).
9. **ListWithSource** — `feed := b.feedURL(b.exact[h])` (or wildcards); manual[] wins.
10. **RemoveByFeedSource(url)** — resolve url→ID via feedIDs; iterate exact AND
    wildcards for `value==ID && !manual`, delete. (Today it iterates feedSrc; now
    it iterates the two enforcement maps — same result set.)
11. **CountByFeedSource(url)** — same, count.
12. **RemoveUnattributedFeedEntries** — remove `!manual && value==0` from exact +
    wildcards (was `feedSrc[h]==0`). Identical set.
13. **SnapshotFeedSources** → host→URL for `value!=0 && !manual` across exact +
    wildcards.
14. **RestoreFeedSources(map[string]string)** — re-stamp `exact[h]/wildcards[suffix] = feedID(url)`
    for currently-listed non-manual hosts whose ID is currently 0 (don't overwrite
    an existing attribution — matches 1a's `if !exists`). "not yet attributed" is
    now `value==0`, not `absent`.
15. **ClearAll** — reset exact/wildcards to `map[string]uint32{}`, feeds/feedIDs.
16. **Load** — scanBlocklistEntries builds exact/wildcards with value 0; then apply
    the .sources sidecar (host→ID) into the maps. **scanBlocklistEntries return
    type changes** (`map[string]bool` → `map[string]uint32`).
17. **Save** — main file = host lines (unchanged); .sources = reconstruct host→URL
    from `value!=0 && !manual` (was from feedSrc).

## Persistence & wire (unchanged)

- Main blocklist file: hostnames only, unchanged.
- `.sources` sidecar: host→URL JSON, unchanged (IDs resolved on Save, re-interned
  on Load). No format/migration.
- CP↔DP `ConfigSnapshot.BlockedHosts` = `bl.List()` (hostnames), unchanged. The
  synced fingerprint is over host tokens, representation-independent — a merged DP
  and an un-merged (1a) DP compute the SAME fingerprint, so mixed fleets converge.

## Invariants (must hold, red-team to break)

- IsBlocked verdict byte-identical to 1a for every input (presence ⟺ blocked;
  value never affects the verdict; allow-mode inversion unchanged).
- No false positive / false negative introduced by the bool→uint32 switch.
- Feed attribution survives ReplaceFeedEntries (carry-forward), ApplyDelta, and a
  Save→Load round-trip — identical to 1a.
- Manual protection: a manual host is never removed by RemoveByFeedSource or
  RemoveUnattributedFeedEntries; manual[] wins in ListWithSource; a
  feed+manual host keeps its ID but reads as manual.
- p99 IsBlocked + allocs/op do NOT regress (benchgate).
- Nothing outside internal/blocklist changes (exact/wildcards are unexported).

## Open questions for the red-team

- Did the enumerated surface (1–17) MISS a `b.exact[...]`/`b.wildcards[...]`
  bool-context read that silently compiles wrong (e.g. a `!b.exact[h]` that must
  become `_, ok; !ok`)? Grep-complete or not?
- ReplaceFeedEntries carry-forward: is a per-host old-map lookup correct under all
  paths (rollback, import-replace, CP apply), and does it interact correctly with
  the manual re-injection (which must land ID 0, not clobber a carried ID)?
- The feed+manual overlap host across every method — any divergence from 1a?
- wildcards attribution: are all wildcard `*.x` ↔ `.x` suffix conversions correct
  in the merged maps (ListWithSource renders `*`+suffix; RemoveByFeedSource keys
  by suffix)?
- Is there any code that range-iterates `b.exact` expecting `for h := range` and a
  bool, that now gets a uint32 value it ignores — harmless, or a hidden assumption?
- Memory: recompute the real saving with Go's map[string]uint32 overhead — is the
  duplicate-key elimination actually ~0.9 GiB, or less after alignment/bucket
  padding? Does 10 M truly fit 4 GiB co-resident with the proxy?
- Benchgate: does the comma-ok presence form actually match the bool-value form on
  p99, or is there a measurable hot-path cost?
