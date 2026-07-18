# T3 — CP↔DP config-sync at 10M+ host scale

**Status:** DRAFT for adversarial review. Not yet implemented.
**Goal:** scale CP→DP blocklist/IP/URL-category distribution to **10M+ entries**
without the current per-change O(full-snapshot) transfer, without the 128 MiB
frame ceiling, and without the DP full-rebuild memory peak.

## 0. Where we are after T1/T2

- The CP distributes one monolithic `ConfigSnapshot`; each DP polls `GetConfig`.
- **Version-conditional (P0-3):** an unchanged poll returns a tiny sentinel.
- **Marshal cache (T2):** N enrolled DPs polling the same change share ONE
  CP-side marshal.
- **Still O(full) on a change:** any config change ships the WHOLE snapshot
  (~60 MiB @ 2M hosts) to every DP, which applies it via `bl.ReplaceFeedEntries`
  (full build-then-swap, ~410 MiB transient @ 2M).
- Hard bounds: `maxSnapBlockedHosts = 2M`, `maxClusterGRPCMsgSize = 128 MiB`,
  `maxSnapshotWireBytes = 120 MiB`.

The blocklist store (`internal/blocklist`) already tracks **per-host feed-source
attribution** (`feedSrc: host→URL`), supports `RemoveByFeedSource`, `Add`,
`Remove`, `ReplaceFeedEntries`, `Count`, `List`, and `MergeFromLines`. Existing
feed machinery: `internal/feedsync`, `internal/threatfeed`,
`internal/blocklistfeed`.

## 1. The core problem at 10M

10M hosts ≈ **~300 MiB** serialized — past the frame, past every cap. Three
distinct costs must be removed, not just relocated:

1. **Wire (per change):** N × full snapshot. A one-host edit re-ships everything.
2. **Apply memory (per change):** full map rebuild (build-then-swap peak).
3. **Local footprint (steady):** 10M in a Go `map[string]bool` ≈ **~900 MiB–1 GiB**
   RAM — a problem *even standalone*, independent of sync.

## 2. Design — two complementary mechanisms + reconciliation

### Mechanism A — Feed-source distribution (the 10M enabler)

The CP distributes **feed descriptors**, NOT expanded hosts:

```
FeedDescriptor{ id, url, format, refresh_interval, content_hash/etag, enabled }
```

- Each DP runs the existing feedsync machinery locally to fetch + expand each
  feed, attributing hosts to their source (the `feedSrc` map already does this).
- The config wire carries **O(feed_count)** — a handful of descriptors —
  regardless of host count. 10M feed-derived hosts cost ~nothing on CP↔DP.
- **Network-restricted DPs:** many DP nodes have no outbound egress (the reason
  the CP-central-fetch model exists). Mitigation: the CP acts as a **feed
  mirror** — it fetches once and serves the feed content at a CP endpoint; DPs
  fetch from the CP via a **chunked/streamed bulk download** (not a gRPC
  snapshot), SSRF-guarded, integrity-checked by `content_hash`.

### Mechanism B — Delta sync (CP-authoritative incremental changes)

For the **CP-authoritative** host set (manual/admin adds+removes) and for
feed-mirror deltas:

- The CP computes a diff `{added[], removed[]}` between the DP's `KnownVersion`
  and current, and ships only that.
- The DP applies via `bl.Add`/`bl.Remove` — **incremental, no full rebuild** →
  the apply memory peak disappears.
- The CP keeps a **bounded ring of per-version deltas** (last K versions). A DP
  whose `KnownVersion` predates the ring falls back to full/chunked sync.

### Reconciliation — the anti-drift spine

Every published version carries a **content hash** of the canonical host set
(sorted rolling hash / Merkle root). The DP recomputes its local hash after
applying a delta and compares:

- **match** → healthy.
- **mismatch** → the DP requests a **full/chunked resync** (a missed or
  misapplied delta can never silently persist).

A periodic reconciliation tick verifies the hash even with no version change.

### Initial / full sync at scale (chunked stream)

A brand-new or drifted DP needs the full set once (300 MiB @ 10M — past the
frame). Full sync becomes a **server-streaming RPC** (or HTTP range download
from the CP mirror): host set shipped in bounded chunks, applied incrementally.
No single 300 MiB frame.

## 3. Local footprint at 10M (separate scaling axis)

10M in `map[string]bool` ≈ ~1 GiB. Independent of sync — even a standalone box
hits it. Options (P4): a compact packed/sorted set with binary search, a
succinct structure, or a bloom-prefilter + on-disk exact set. **Called out so
"10M sync" is not mistaken for "10M is free to hold."**

## 4. Protocol

- Extend the config service with:
  - `GetConfigDelta(KnownVersion, KnownHash) → { mode: unchanged|delta|full|resync, version, hash, added[], removed[], feed_descriptors[] }`
  - `StreamConfigHosts(FromVersion) → stream<HostChunk>` for full/initial sync.
- `GetConfig` (full snapshot) stays for the small non-host config
  (policy/PAC/etc.) and as the compat path for old DPs.
- Backward compatible: an old DP keeps using `GetConfig` full; a new DP prefers
  the delta RPC and falls back to full on `Unimplemented` (CP-first, mirrors the
  gzip migration).

## 5. Blocklist API additions

- `bl.ApplyDelta(added, removed []string, source string)` — incremental under lock.
- `bl.ContentHash() string` — deterministic hash of the current feed+manual set.
- Feed-descriptor wiring: DP starts feedsync from distributed descriptors.

## 6. Phasing

- **P1 — Feed-source distribution.** Descriptors over the wire; DP fetches
  (direct or via CP mirror). Biggest single win; reuses feedsync + feedSrc.
- **P2 — Delta sync + content-hash drift detection** for the CP-authoritative set.
- **P3 — Chunked/streamed full sync** (removes the frame ceiling for initial/resync).
- **P4 — Compact 10M local blocklist representation** (memory).

## 7. Failure handling (the contract)

- Delta ring miss → full/chunked sync (never a partial apply).
- Hash mismatch → resync (drift never persists).
- Feed fetch failure on a DP → keep last-good feed content; alert; the DP is
  degraded-but-serving, not empty.
- CP mirror unavailable → DPs keep last-good; a network-restricted DP without a
  reachable mirror is a hard dependency (documented; matches PAN-OS EDL reality).
- HA: the delta ring + per-version hashes must survive failover (or a promoted
  standby forces a full resync of the fleet — safe default).

## 8. Security

- **Feed descriptors are attacker-relevant:** a malicious/compromised CP could
  point DPs at an SSRF target or a poisoned feed. The DP fetch MUST SSRF-guard
  the URL and verify `content_hash` (ideally a signature). This is a NEW trust
  surface the monolithic model did not have (the CP fetched, DPs never did).
- Delta application must be bounded (a malicious delta can't exceed caps/aggregate).
- Content hash must be collision-resistant (SHA-256 class), not a weak checksum.

## 9. Open questions for review

1. Is feed-source distribution acceptable given network-restricted DPs, or must
   the CP-mirror path be mandatory (making the CP a bulk-serving bottleneck)?
2. Delta-ring memory on the CP vs. history depth vs. resync frequency — sizing?
3. Content-hash cost at 10M (rehash per change) — incremental Merkle vs. full rehash?
4. Consistency window: DPs fetch feeds at different times → transient divergence.
   Acceptable bound? How does it interact with the reconciliation hash (which
   would flag legitimately-in-flight feeds as "drift")?
5. Does P4 (compact local structure) gate the others, or ship independently?
6. HA/fencing interaction with the delta ring and streaming full-sync.
