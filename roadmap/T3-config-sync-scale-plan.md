# T3 — CP↔DP config-sync scale program (REVISED after red-team)

**Status:** REVISED design after a 6-axis Palo red-team broke draft-1 (verdict:
major_rework, all six axes). This version resolves the fatal breaks. Sequenced,
not one-shot.

**Honest target (draft-1 claimed 10M; corrected):**
- **~2–3M today** (roughly the current `maxSnapBlockedHosts` cap) — the `map[string]bool`
  exact set (~700 MiB–1 GiB) + the mandatory `feedSrc` host→URL map (~1.3–1.6 GiB
  of non-interned URL copies) ≈ 2.2–2.5 GiB steady, ~3.5–4 GiB with rebuild
  transients — an OOM on a 4–8 GiB DP co-resident with the proxy.
- **~3–5M** after the compact host set alone.
- **~10M only** after BOTH (a) a compact packed/sorted host set AND (b)
  **feed-count-scoped attribution** (per-host `uint32` feed-id + a tiny
  `feedID→URL` table, ~40 MB instead of ~1.5 GB). Draft-1's P4 addressed only
  `map[string]bool` and never the attribution map — so even "fixed" P4 was ~1.5 GB
  over budget. **10M requires the attribution redesign; without it the honest
  hard ceiling is ~3–5M.**
- **A concrete per-DP RAM budget is a design input, not an afterthought** (below).

## Why draft-1 failed (the load-bearing breaks)

1. **Reconciliation was self-contradictory.** One fleet-wide content hash over
   feed+manual (draft §5) cannot coexist with per-DP local feed fetch (Mechanism
   A): a rotating feed (URLhaus) fetched 90 s apart yields different sets, so no
   DP ever matches the CP hash → the anti-drift spine fires a continuous
   fleet-wide resync storm against the CP mirror.
2. **Memory phasing backwards.** P1–P3 distribute + apply 10M while the DP
   physically cannot hold it → a green sync is a delayed OOM-kill of the proxy.
3. **`bl.Remove` deletes manual blocks.** A compromised-CP delta
   `{removed:[admin-blocked-C2]}` unblocks admin manual blocks (reintroduces the
   PR #249 defect on every incremental apply), and `bl.Add` adds are unattributed
   and eaten by `RemoveUnattributedFeedEntries`.
4. **Integrity anchored at the attacker.** `content_hash`/version hash are all
   CP-supplied → zero defense against the H5 compromised-but-authenticated CP the
   plan names. The one real control (signature vs. offline root) was "ideally".
5. **New RPCs bypassed ADR-0005 fencing** and `dpLastSeenEpoch` resets to 0 on DP
   restart → a zombie mTLS-authenticated CP poisons the incremental base, which
   (unlike a self-healing monolithic snapshot) compounds forever.
6. **No base-version linkage, torn durability, no reverse telemetry** → silent
   divergence and unobservable convergence.

## P0 — design decisions that MUST land before any code

**D1. Two disjoint reconciliation checks (resolves break 1).**
- **Drift hash:** a cryptographic **SHA-256 over the CP-AUTHORITATIVE set only**
  (manual/admin hosts), computed over a *canonical* encoding, fleet-wide,
  delta-covered. **Feed-derived hosts are explicitly EXCLUDED.**
- **Feed freshness:** compared per-feed by **descriptor `content_hash`/etag
  equality** — "did the DP fetch the same feed *version* the descriptor names" —
  NEVER by re-hashing an independently-fetched expansion. Forbid rolling/additive
  hashes.

**D2. Canonical host-set encoding (versioned wire contract).** Pin exactly:
dedup, comment-strip, wildcard `*.`↔`.` normalization, IDN→punycode, case-fold,
trailing-dot strip, sort order. The drift hash is defined over this. Any change
is a wire-contract version bump.

**D3. Integrity anchored off the CP (resolves break 4).** MANDATORY signature
(reuse the in-tree Sigstore/ed25519 release-catalog trust roots) over (a) each
published CP-authoritative host-set hash and (b) feed content, verified on the DP
against an **offline admin/release trust root**. A CP-supplied SHA-256 defends
only transport corruption and is documented as NOT an H5 control.

**D4. Epoch-fence the new RPCs (resolves break 5).** Every delta/stream RPC
carries the issuing CP's lease epoch and is subject to the same puller-side epoch
verify + no-live-holder reject + monotonic `dpLastSeenEpoch` ratchet as
`GetConfig`. **Persist `dpLastSeenEpoch` durably** so restart cannot reopen the
epoch-0 window; on any epoch advance, force a base-integrity re-check.

**D5. Per-DP RAM budget + honest target stated in the plan.** e.g. "a DP node
holds ≤ N M hosts within a B GiB budget co-resident with the proxy" — the number
gates every growth phase.

## Phasing (REORDERED — memory precondition moved up)

### P1 — CP-authoritative delta sync ONLY, at today's scale (the smallest valuable slice)

No feeds, no memory rework. Delivers real per-change wire savings on the churny
admin set at today's caps; touches neither of the two hardest subsystems.

- `GetConfigDelta(base_version, known_hash) → { mode: unchanged|delta|resync,
  base_version, target_version, added[], removed[], cp_authoritative_hash, epoch, sig }`.
- **Strict sequential apply:** the DP REJECTS and falls back to full sync unless
  `base_version == its current KnownVersion`. Gap-free, no reorder/duplicate.
- **`bl.ApplyDelta` (new):** never removes a host present in `b.manual`; stamps
  CP-authoritative adds with a reserved `"cp-authoritative"` source that
  `RemoveUnattributedFeedEntries`/`RemoveByFeedSource` both exempt; tracks
  feed-derived vs CP-authoritative membership **separately** (a remove drops a
  host only if no feed source still covers it). Fix `bl.Add` to persist the main
  file. **Atomic (version, content) commit:** write-ahead delta → apply → fsync →
  advance version; never advance KnownVersion until content is durable.
- **Cryptographic CP-authoritative-only hash** (D1), signed (D3), epoch-fenced (D4).
- **Reverse telemetry:** heartbeat carries `{config_version, cp_authoritative_hash}`;
  CP exposes a fleet-convergence API + panel + straggler alert.
- Regression tests: "a CP delta can NEVER delete a manual block"; "a CP-pushed add
  survives unattributed-cleanup"; reorder/duplicate/SIGKILL-mid-apply → resync,
  never divergence.

### P2 — Compact 10M local representation + feed-count-scoped attribution (memory PRECONDITION)

Its own design doc. A chosen compact structure (packed/sorted set), a per-host
`uint32` feed-id + `feedID→URL` table (`RemoveByFeedSource` rewritten against
feed-ids), explicit wildcard + false-positive semantics for `IsBlocked`, and a
**p99 `IsBlocked` hot-path benchmark gate** (must not regress). **Gates any growth
past ~2–3M.** Incremental content hash maintained on Add/Remove/ApplyDelta (not an
O(N log N) recompute under the blocklist lock).

### P3 — Feed-source distribution (only AFTER memory is bounded), egress-capable DPs first

- **Operator-approved, admin-signed descriptor allowlist** — NOT CP-pushed
  arbitrary URLs.
- DP-side fail-closed caps BEFORE trusting content: response-body byte cap
  (`io.LimitReader`), max-line-count, decompression-ratio limit, per-DP total-host
  ceiling checked incrementally, refresh jitter, per-DP fetch-rate/concurrency cap.
- Bounded per-source **delete-on-drop** (diff old-vs-new → Add/Remove) — do NOT
  rely on `blocklistfeed` (add-only) or claim `feedsync` reuse (it is the UT1
  category-tarball→catdb syncer — wrong package).
- ALLOW-mode apply MUST be atomic build-then-swap (a partially-visible set denies
  all traffic → fleet outage).
- Staged/canary descriptor rollout + per-descriptor max-delta guardrail;
  descriptor rollback = force re-fetch + `RemoveByFeedSource` cascade.

### P4 — Bulk / mirror / chunked full sync

- Chunked/streamed full/initial sync applied **incrementally into the compact
  arena** (approach 1× not 2× steady footprint).
- CP mirror as a first-class component: rides mTLS (not raw-URL SSRF-checked as
  public), redirects disabled, content independently signed, served from a single
  mmap/on-disk artifact, rate-limited + concurrency-capped, HA-replicated, with an
  **offline sideload path for air-gapped fleets**.
- **Fleet-wide concurrent-resync cap + jitter** so failover/forced-resync cannot
  thunder. Replicate the delta ring + per-version hashes to the standby; on
  promotion, version-rebind when content hash equals what DPs already hold (avoid
  the failover resync stampede); bound the CP delta ring by TOTAL BYTES and
  collapse an oversized single delta to a resync marker.

## Non-negotiable invariants (red-team-derived)

- A CP delta can never delete a manual/admin block.
- Feed-derived and CP-authoritative membership are tracked separately.
- The drift hash covers ONLY the CP-authoritative set; feeds are checked by etag.
- Integrity is signed against an offline root; a CP-asserted hash is not an H5 control.
- Every new sync RPC is epoch-fenced; `dpLastSeenEpoch` is durable.
- Deltas carry base+target version; apply is sequential/gap-free/atomic-with-version.
- No phase advertises a host count its own memory model cannot hold.
- ALLOW-mode set changes are atomic build-then-swap.

## P1 IMPLEMENTATION STATUS (shipped) + red-team fix pass

P1 (CP-authoritative delta sync at today's scale) is implemented end-to-end and
was put through a 6-lens Palo adversarial review. The core protocol was confirmed
sound (the wire-protocol lens found no P0/correctness-P1: version-uniqueness +
`latest==cur` binding + terminal-fingerprint resync form a closed loop; concurrent
out-of-order records only shrink the ring → spurious resync, never a wrong chain).
Shipped:

- `blocklist.ApplyDelta` (dedup + hash-outside-lock), `FeedSetFingerprint` /
  `SyncedFingerprint` (wire-fed XOR set fingerprint), `FeedList` (CP-authoritative).
- CP delta ring (bounded count+bytes, resync markers, nil-baseline markers) fed by
  `ConfigStore.Update`; `GetConfigDelta` RPC (epoch-fenced, capped, cached remainder,
  frame-bounded, KnownFP idle-drift, redaction-walled); DP consumer with
  full-path fallback, strict sequential apply, and durable epoch ratchet (D4).

**Red-team fixes landed:** dedup closes the even-multiplicity silent-divergence;
hash-outside-lock removes the hot-path stall; delta-apply cap closes the memory-DoS
bypass; the redaction-parity wall now covers GetConfigDelta; the reply is
cache-shared + frame-bounded; `dpLastSeenEpoch` is durable (D4); `TargetVersion` is
forward-bounded; fp is checked before `bl.Save()`; the delta re-probes after an
in-place CP upgrade.

**D3 (off-CP signing) — DEFERRED with recorded sign-off.** The plan named a
mandatory off-CP signature a P0 for P1. It is deferred because it is NOT a P1
regression: the full-snapshot path has IDENTICAL exposure (a compromised current
leader can already push an arbitrary full snapshot), so the delta path does not
weaken the existing CP→DP trust model — which rests on mTLS + the epoch fence. The
synced fingerprint is explicitly NOT an authenticity control (it is linear/forgeable
by a content-controlling party). Signing is a cross-cutting hardening that must
cover BOTH the full and delta paths (reusing the in-tree Sigstore/ed25519
release-catalog roots) and is tracked as its own slice, not smuggled into P1.

**Efficiency debt (tracked, not regressions — parity with the pre-existing full
path):** the DP still writes a full ~60 MiB last-good per delta apply (Perf-F3), and
`Update` re-diffs+re-hashes the blocklist on every publish even when it is unchanged
(Perf-F4). Both are admin-action-rate and match the full path's existing cost;
optimize with a blocklist generation counter + coalesced last-good in a follow-up.

## Open items still requiring a decision (down from draft-1)

- The compact-structure choice + concurrency model (P2 design doc).
- CP delta-ring byte bound + published resync-frequency SLO.
- Air-gap story for feed distribution (mandatory CP mirror vs. offline sideload).
- D3 signing slice (covers both full + delta paths) + Perf-F3/F4 efficiency debt.
  **D3 designed + 4-lens red-teamed → RESCOPE + DEFER** (`T3-D3-offcp-signing-plan.md`
  STATUS block). The kernel (absolute-state manifest + off-CP key + DP hash-rebind)
  was CONFIRMED to defeat the post-sign TOCTOU, but the design as scoped/constructed
  named 6 P0s (version-bind fleet-brick; `FeedList()`-recompute brick; non-injective
  hash forge; blind-sign in the UI-preserving custody mode; enforce-default self-DoS;
  bootstrap brick) and is **capacity-orthogonal** — `maxSnapBlockedHosts=2M` gates
  10M, not integrity, so D3 is NOT "the 10M prerequisite." A corrected,
  decision-advanced design is captured; build trigger = a concrete H5-facing
  requirement AND the capacity work (cap raise + P2 + P3) shipping. Correct first
  surface is `policy_rules` (the cheap-attack path), not the host set.
