# Durable Configuration Publication — Architecture Review & Decision

**Status:** DRAFT / for owner review — NOT adopted. No implementation migration has been performed.
**Branch under review:** `decision-integrity-hardening`
**Evidence base:** commit `e10a18e` (the mislabeled `fixup!`) + uncommitted `internal/filetxn/` and `config_apply_txn.go`, audited against `main` @ `e24de46` and PR #738 (`031a8ec`).
**Method:** five independent read-only specialist audits (storage durability, HA/distributed-systems, concurrency, test/fault-injection, architecture simplification). Every claim below carries a `file:line` reference from those audits.

> **Purpose of this document.** An overnight prototype ("the drift") grew a generic file-transaction primitive plus cross-store orchestration while an older single-purpose mechanism still exists beside it. This document converts that prototype into a reviewable engineering decision: it inventories every configuration-publication surface, evaluates the proposed invariants against the actual code, decides the abstraction boundary, builds a fault model, and proposes minimal provable slices. **The objective is not to preserve the drift because effort was invested** — it is to determine whether Culvert needs a first-class Durable Configuration Publication architecture, and if so, to introduce it through minimal, provable slices.

---

## 0. Executive summary

**What the drift discovered (genuine, valuable):** Culvert publishes configuration across ~15 on-disk stores through *at least three* different durability mechanisms with *two* independent crash-recovery entrypoints, no cross-store atomicity contract, and no reader-side generation isolation. The drift is the first attempt to give this a coherent contract. The core `internal/filetxn` primitive is **mechanically sound** — its crash-point matrix genuinely resolves to all-old/all-new at every injectable boundary, `AtomicWrite` fsyncs content before rename, and the `ErrSimulatedCrash` seam faithfully models power-loss.

**Why it cannot merge as-is:** the generalization *added* a second mechanism beside the old one instead of replacing it, and it conflates *disk atomicity* (which filetxn provides) with *reader visibility isolation* and *HA reachability semantics* (which it does not). Concretely, the audits found:

| # | Finding | Sev | Invariant implicated |
|---|---|---|---|
| A1 | Superseded-but-committed journal on the **shared policy file** → `Fatalf` boot wedge (startup DoS) | **HIGH** | #5, #8 |
| A2 | `filetxn.syncDir` re-fsyncs the dir **without** the unsupported-fs tolerance `AtomicWrite` has → filetxn is *less* portable than the primitive it wraps (fails on tmpfs/overlay/NFS) | **HIGH** | #9 |
| A3 | Invariant #4 leaks: local TLS-material failure in `buildClientTLS`/`NewDataPlaneClient` counts as "leader unreachable" → **legacy-mode split-brain from a purely local fault** | **HIGH** | #4 |
| A4 | Invariant #2 fails: multi-store `publish()` is a sequence of independent `ReplaceAll` swaps with **no reader barrier**; the DP/HA window spans `bl.Save()`/`sslBypass.Save()`/`dpiScanner.Save()` disk I/O → a proxy request evaluates **old policy against new taxonomy** | **MED-HIGH** | #2 |
| A5 | Three durability tiers over the **same** `policy.json`+`.meta`: filetxn (checksum+before-image) vs inline `policySaveTxn` (no checksum, restores raw bytes unverified) vs draft path (bare `AtomicWrite`) | **MED-HIGH** | #10, #8 |
| A6 | Two independent recovery roots (`recoverPolicySave` at policy-load vs `recoverCrossStoreTransactions` at startup) over overlapping files → recovery metadata is a second ambiguous source of truth | **MED** | #8 |
| A7 | Dependency stores (categories/groups/profiles) have **no gate equivalent to `saveMu`** against live CRUD → lost update vs a concurrent apply | **MED** | #2 |
| A8 | `codes.Unknown`/`codes.Internal` bucketed as "reachable" → a wrapped transport error from a dead leader can **suppress failover indefinitely** | **MED** | #4 (availability) |
| A9 | `ipf` global pointer bare-reassigned on the DP path (`ipf = newIPF`) while the proxy hot path reads it unsynchronized → `-race`-detectable data race | **MED** | #2 |
| A10 | No CP-side convergence signal: a DP stuck retrying `vN` keeps heartbeating "healthy" | **MED** | operability |
| A11 | Draft-commit vs apply are half-serialized: apply passes `expected=nil` (opts out of OCC), so a DP push can silently erase a locally-committed draft | **LOW-MED** | #7 (documented exception) |
| A12 | Test gaps: `recoverCrossStoreTransactions` is **never called by any test**; no journal-absent compatibility test; no fsync/ENOSPC/rename injection; no idempotent/restart-during-recovery; two-systems interaction unpinned; no fsync-latency benchmark | **MED** | #5, verification |

**Recommendation (see §7): PROCEED WITH REDESIGN.** Keep `internal/filetxn` as a narrow, ADR-recorded durable-write primitive; keep the prepare/publish pattern per-domain; **fix A1/A2/A3 before any extraction**; resolve the invariant-#2 reader-consistency question as an explicit decision; and **collapse the policy duplication (A5/A6) rather than shipping two mechanisms**. Do **not** merge the branch as a single unit and do **not** rebase-drop yet — the committed `e10a18e` and the uncommitted primitive are architectural evidence for the slices in §6.

**What is already correct (do not regress):** invariant #1 (failed persistence never becomes visible in memory) is strongly covered across DP/HA/draft/cross-store paths; invariant #7 is satisfied for the rule-CRUD/draft paths (check and write share the lock); the epoch ratchet is correct; there is no deadlock (acyclic lock order `configApplyMu → saveMu → ps.mu`).

---

## 1. Configuration-surface inventory

Fifteen surfaces. For each: authoritative source, files/stores, candidate stage, validation, durability boundary, publication point, rollback, restart recovery, concurrency model, generation semantics, operator-visible outcome.

### 1.1 Live policy + policy metadata
- **Source of truth:** `PolicyStore` (in-memory rules + `version`), persisted to `policy.json` + `policy.json.meta`.
- **Stores/files:** `policy.json`, `policy.json.meta`, transient `policy.json.txn` (inline) / participation in `config_apply.txn` (cross-store).
- **Candidate:** `prepareReplacement(rules, expected)` builds a detached generation under `saveMu` (`policy.go:820-884`); or `beginPolicySave` snapshots current files (`policy.go:494`).
- **Validation:** rule validation + ID migration before publication; optimistic `expected` version re-checked under lock.
- **Durability boundary:** two co-existing — inline `policySaveTxn` (`policy.go:413-557`, no checksum) on the API save path; `filetxn` on cross-store paths. **A5/A6.**
- **Publication:** `preparedPolicyReplacement.Publish()` swaps rules+version+updatedAt under one `ps.mu.Lock` (`policy.go:867-873`) — atomic *for the policy store alone*.
- **Rollback:** `Abort()` releases the candidate under `saveMu`; crash → recovery restores before-images.
- **Restart recovery:** `recoverPolicySave(path)` at policy load (`policy.go:260`) **and** `recoverCrossStoreTransactions` at startup (`main.go:184`) — two roots over the same files.
- **Concurrency:** `saveMu` is the true generation gate (correct); `ps.mu` (RWMutex) guards field reads for the hot path.
- **Generation:** monotonic `version`; OCC via `expected`.
- **Operator outcome:** rule edits are all-or-nothing; a failed save returns an error with disk rolled back.

### 1.2 Policy drafts
- **Source of truth:** `policyDraftCoordinator` (`policy_draft.go`), persisted to a draft snapshot + `.commit` journal + inactive tombstone.
- **Candidate:** `detachedPolicyDraftStore(src)` forks rules+generation; staged edits via `mutateAndPersist` under `c.mu`.
- **Validation:** base-generation staleness blocks commit (`errPolicyDraftInactive`, OCC).
- **Durability boundary:** bespoke — `persistLocked`/`persistCandidateLocked`/`writeCommitJournalLocked`/`writeInactiveTombstoneLocked` use **bare `AtomicWrite`**, no journal checksum, no before-images (**A5**, third tier).
- **Publication:** `commitWithRules` → `policyStore.ReplaceAllAndSaveAtVersion(cand, BaseGeneration)` — bridges into the policy store's `saveMu`.
- **Rollback:** revert clears memory then publishes an inactive tombstone; failed tombstone cleanup is safely ignored on restart (invariant #6 — held here).
- **Restart recovery:** `initPolicyDraft` replays the `.commit` journal (domain-specific "did running absorb candidate?" check, *not* a before-image restore).
- **Concurrency:** `c.mu` serializes stage/commit/revert/cascade; commit-vs-revert races are serialized (tested). **But** commit vs apply are on disjoint locks (**A11**).
- **Generation:** `BaseGeneration` + OCC.
- **Operator outcome:** staged edits isolated; save failure → 500, draft retained, nothing published.

### 1.3 Configuration import (`apiConfigImport`, `ui_config.go`)
- **Source of truth:** the imported `configBackup`; leaf-first apply (categories → groups → policy).
- **Candidate:** `preparePolicyTaxonomyApply` (`config_apply_txn.go:38`).
- **Durability boundary:** `config_apply.txn` via `filetxn` under `configApplyMu` (`ui_config.go:888`).
- **Publication:** `publish()` → deps then policy — **not atomic to readers (A4)**; import never wipes (absent/empty fields skip).
- **Restart recovery:** `recoverCrossStoreTransactions`.
- **Concurrency:** `configApplyMu` serializes apply-vs-apply, but **not** vs direct dependency CRUD (**A7**).
- **Operator outcome:** partial import cannot leave mixed policy+taxonomy on disk; a transient reader window exists.

### 1.4 Rollback (config-version, `configversion.go`)
- **Source of truth:** numbered snapshots in `/data/config_versions/` (`configver`, 50 max).
- **Candidate/durability/publication:** same `config_apply.txn` path as import, under `configApplyMu` (`configversion.go:295`).
- **Notable:** apply passes `expected=nil` (no OCC) → "last writer wins" vs a concurrent draft commit (**A11**); `ipf` mutated **in place** here vs bare-reassigned on the DP path (**A9**, inconsistent discipline).
- **Operator outcome:** rollback restores a prior generation atomically on disk; reader window per A4.

### 1.5 IdP registry replacement (`auth_idp.go`)
- **Source of truth:** `IdPRegistry` (compiled providers), single file.
- **Candidate:** `prepareIdPReplacement(profiles)` compiles before any mutation; `prepareReplacementForTxn` participates in cross-store txns.
- **Durability boundary:** single-file `atomicWriteFile` (`applyReplacement`) — **a single atomic rename already gives all-or-nothing; journaling is not required for the standalone path.**
- **Publication:** `ReplaceAll` swaps after compile+persist; restore external-auth settings on rejection.
- **Concurrency:** `txnMu`.
- **Operator outcome:** IdP set is compiled-and-durable before live; correct as-is. **Do not push onto filetxn for the standalone case.**

### 1.6 Control-plane → data-plane snapshot (`controlplane_snapshot.go`)
- **Source of truth:** CP `ConfigSnapshot`; DP applies + records last-good.
- **Candidate:** `preparePolicyTaxonomyApply` + IdP; `applyConfigSnapshotWithIdP`.
- **Durability boundary:** `dp_config_apply.txn` via `filetxn` bundling policy+taxonomy+idp+**last-good snapshot** all-or-nothing (`controlplane_snapshot.go:435,464`).
- **Publication:** `publishDependencies()` → `applySnapshotPolicyAndTraffic` (bl/ssl/dpi `Save()`) → … → `publishPolicy()` **last**. The siblings in `applySnapshotPolicyAndTraffic`/`…ClusterRuntime`/`…ExtendedState` are persisted **individually, non-atomically, errors logged only** — declared "intentionally infallible after commit" (`controlplane_snapshot.go:477`). **A4 + HA-F2.**
- **Rollback/recovery:** last-good re-applied on restart (`dp_enrollment.go:258`) reconverges siblings; note `persistDPLastGoodConfigSnapshot` (`:778`) has **no production callers** (tests use a different path — A-test).
- **Generation:** `Epoch` fence + `lastVersion` (advances only on full success).
- **Operator outcome:** DP publishes a durable atomic policy+taxonomy generation; siblings may lag briefly; the CP has **no visibility** into a stuck DP (**A10**).

### 1.7 HA synchronization & promotion (`ha.go`, `ha_failover.go`, `ha_lease.go`, `ha_fencing.go`)
- **Source of truth:** leader's replicated bundle; standby applies; fencing lease (etcd, ADR-0005) or legacy ADR-0004.
- **Candidate/durability:** `ha_bundle.txn` via `filetxn` (`ha.go:722`) bundling ca.crt/key+policy+meta+taxonomy+idp+cluster-state+version-floor.
- **Reachability semantics:** `syncFromLeader` returns `(ok, leaderReachable)`; `haRPCErrorProvesReachability` classifies RPC errors; `handleSyncResult` resets `failCount` on a reachable-but-rejected leader (**invariant #4 — holds for the RPC path**).
- **Promotion:** lease mode → `leaseAutoPromote` (hysteresis 30s → freshness 10m → Acquire); legacy → `autoFailoverEnabled` gate + unconditional `acquireLeaseForLeadership`.
- **Gaps:** **A3** (client-reconstruction TLS-material failure counts as unreachable → legacy split-brain); **A8** (`codes.Unknown/Internal` latched reachable → failover suppression).
- **Generation:** epoch = lease `create_revision`; DP `dpLastSeenEpoch` CAS ratchet (correct, benign on failed apply).
- **Operator outcome:** local disk faults inside `applyHABundle` do not promote; local **TLS-material** faults still can (legacy).

### 1.8 Cluster state (`enrollment.go` `ClusterStore.ImportFullState`)
- **Durability boundary:** builds a `filetxn.Write` in `prepareImport` **but `ImportFullState` calls `atomicWriteFile(write.Path,…)` directly** — borrows the type, not the transaction. Inconsistent participant (Phase-1 finding).
- **Recommendation:** either a real single-file `filetxn` participant or drop the `filetxn.Write` borrow; do not half-adopt.

### 1.9 Supporting / lower-tier surfaces (individually atomic today, non-transactional)
`admin_settings.json` (restart durability + sentinels), `config_versions/` (numbered), blocklist, SSL-bypass, DPI, threat-feed allowlist, file-block extensions, bandwidth, node-groups, PAC, OTLP, session HMAC. These ride `applySnapshot*` as **non-atomic siblings** (A4). Most are individually `AtomicWrite`-durable; none participate in the cross-store generation.

---

## 2. Required invariants — evaluated & refined

Each proposed invariant, its verdict in the current code, and the refinement.

1. **Ack only after required durable state is complete.** *Holds for the transactional subset; VIOLATED for siblings* — `publish()` acks (returns success) while ~10 sibling `Save()`s run non-atomically with swallowed errors (A4/HA-F2). **Refine:** define "required durable state" as an explicit per-surface set; a store either joins the transaction or is documented as best-effort-eventually-converged — no silent middle.
2. **Readers see previous-complete or new-complete, never mixed.** **NOT satisfied** (A4/A9). filetxn gives *disk* atomicity, not *reader* isolation. **Refine/split into 2a (disk) — held — and 2b (reader visibility) — requires a generation-epoch snapshot (single atomic read of {policy,categories,groups,profiles} pointers per request), which filetxn structurally cannot and should not provide.** This is the central open design decision (§7 Q1).
3. **Validate + persist candidate before live publication.** **Satisfied** — prepare precedes publish everywhere (`prepareReplacement`/`preparePolicyTaxonomyApply`).
4. **A local persistence/apply failure must not be read as "leader unavailable."** **Partially satisfied** — holds for `syncFromLeader`/`applyHABundle`/`applyConfigSnapshotWithIdP`; **VIOLATED** for `NewDataPlaneClient`/`buildClientTLS` local TLS-material faults (A3). **Refine:** classify *all* local-disk/at-rest-KEK/PEM errors — including client construction — as local-not-unreachable; reconsider `codes.Unknown/Internal` (A8), letting the fence arbitrate ambiguous errors rather than latching them reachable.
5. **Restart recovery deterministic & idempotent.** **Deterministic in logic, but VIOLATED operationally** by A1 (a superseded committed journal → `Fatalf`) and **unproven** by tests (A12: no double-Recover, no restart-during-recovery). **Refine:** verify-only committed-recovery must **degrade to cleanup** when the recorded generation is superseded (not fatal); recovery must be proven idempotent by test.
6. **Failed cleanup must not reactivate stale state after restart.** **Satisfied** for the draft tombstone; **at risk** for filetxn via A1 (a lingering committed journal is not "reactivated" but *is* mis-read as corruption). Tie the fix to #5.
7. **OCC checks evaluated inside the serialized mutation boundary.** **Satisfied** for rule-CRUD/draft (check and write share `saveMu`/`c.mu`; the early HTTP `policyVersionConflict` is non-authoritative UX). **Documented exception:** bulk apply passes `expected=nil` by design (A11) — must be *documented*, and the draft-erase asymmetry acknowledged or closed.
8. **Recovery metadata must never become a second ambiguous source of truth.** **VIOLATED** — two recovery roots (`recoverPolicySave` + `recoverCrossStoreTransactions`) over overlapping files, two journal schemes on the same `policy.json` (A5/A6). **This is the headline structural violation.** Refine to: exactly one recovery authority per file.
9. **Transaction success includes file + directory durability.** **Satisfied but over-eager** — filetxn does file-fsync-before-rename + dir-fsync, but `syncDir` re-fsyncs without the unsupported-fs tolerance, making it *less portable* than `AtomicWrite` (A2). **Refine:** reuse `AtomicWrite`'s tolerant dir-fsync; do not double-fsync.
10. **No surface may silently use weaker semantics without a documented exception.** **VIOLATED** — three durability tiers over one file (A5). **Refine:** either unify policy publication on filetxn (with migration shim) or explicitly document why the inline path is retained; standalone single-file renames (IdP, single CA) are a *documented, justified* weaker tier (a rename is already atomic).

**Two invariants to ADD:**
11. **A durable primitive claims disk atomicity only, never in-memory/reader atomicity** (forces A4 to be designed, not assumed).
12. **Exactly one recovery authority owns each on-disk file** (operationalizes #8).

---

## 3. Abstraction boundary decision

**Verdict: COMBINATION — narrow primitive + per-domain publication + one deletion + recovery-ownership refactor.**

The consumer × guarantee matrix (architecture audit) shows guarantees genuinely coincide only for the **multi-store publishers** (cross-store apply, DP snapshot, HA bundle) and, as a strict subset, the policy 2-file save. They do **not** coincide for standalone IdP / single-file CA (a rename is already atomic — journaling is dead weight) or for policy drafts (a phased handoff into another store, with domain-specific recovery).

- **Belongs in `internal/filetxn`:** `Write`, `Begin/Apply/Commit/Abort/Finish/Recover`, before-image capture+restore, journal checksum, file+dir fsync (tolerant), cleanup, corruption rejection. It correctly imports **no domain package** — the boundary of the primitive itself is right.
- **Must stay owned by each domain (package main):** candidate construction, the store→bytes marshal into `filetxn.Write`, the in-memory `Publish()/Abort()` lock handoff (coupled to each store's mutex and memory model — **cannot** be hoisted into `internal/`), and any non-before-image recovery (policy draft's "did running absorb candidate?"). The **real reusable seam is the `prepareX → Writes() → Publish()/Abort()` pattern**, and it is per-domain by nature.
- **`policySaveTxn`: ADAPT** to route `saveLocked` through filetxn (single participant, +checksum, −~145 lines) **gated on an old-format migration shim** (`filetxn.Recover` returns *fatal* on a legacy `policy.json.txn`; a crash-before-upgrade would wedge boot). **Absent the shim, RETAIN** — but the current *coexistence* (two schemes, two recovery roots on the same files) is the worst option and must not ship.
- **`config_apply_txn.go` is the right *integration* layer for the policy+taxonomy bundle** (those four genuinely co-travel), **but over-reaches on recovery**: `recoverCrossStoreTransactions` hardcodes HA's and DP's journal names, making a module named "config apply" the de-facto owner of three domains' recovery contract. **Refactor:** each multi-store domain registers/owns its journal name; keep the policy+taxonomy candidate bundle here.
- **What would create false safety / over-coupling:** an API that *looks* atomic across stores but whose in-memory `Publish` is a sequence of independent swaps (exactly A4). A shared primitive must **explicitly disclaim** reader isolation (new invariant #11) or callers will assume it.
- **Governance:** a cross-cutting `internal/` engine touching policy/HA/DP/config/rollback requires a recorded ADR under ADR-0002 / the evidence-first constitution. filetxn currently has only a package comment. **An ADR is a merge prerequisite.**

---

## 4. Fault model / failure matrix

Legend — **Persisted:** on-disk state after the fault. **Live:** in-memory state. **Restart:** outcome of the next boot. **Retry:** safe to retry the operation? **Promote:** may HA auto-promote? **Test:** required coverage (⛔ = currently missing, A12).

| Fault | Persisted | Live | Restart | Operator error | Retry | Promote | Test |
|---|---|---|---|---|---|---|---|
| crash before journal creation | all-old | all-old | all-old | none | yes | n/a | covered |
| crash after journal, no writes (`after-journal`) | journal + all-old | all-old | Recover no-ops → all-old, journal removed | none | yes | n/a | ⛔ hook point never injected |
| crash after first file write | journal + file0-new | all-old | restore before-images → all-old | none | yes | n/a | covered |
| crash between related writes | journal + partial | all-old | all-old | none | yes | n/a | covered |
| crash after all writes, before commit marker (`before-commit`) | journal(uncommitted)+all-new | all-old | rollback → all-old | none | yes | n/a | ⛔ point not injected (logically covered) |
| crash after commit, before cleanup (`before-finish`) | journal(committed)+all-new | all-old→new on Publish | keep all-new, remove journal | none | yes | n/a | ⛔ point not injected (logically covered) |
| **committed journal superseded by inline save** | committed journal, on-disk digest ≠ recorded | — | **`Fatalf` — boot wedged (A1)** | fatal boot | no | n/a | ⛔ **must add; must fix** |
| ENOSPC | temp removed, error | unchanged | all-old | write error | yes | no | ⛔ no injection |
| EIO | as ENOSPC | unchanged | all-old | I/O error | yes | no | ⛔ |
| permission failure | error | unchanged | all-old | EACCES | after fix | no | partial (dir-as-file) |
| failed write | abort→restore | unchanged | all-old | write error | yes | no | covered |
| partial write | impossible (temp+rename) | — | all-old | none | yes | n/a | ⛔ not adversarially tested |
| failed rename | temp cleaned | unchanged | all-old | rename error | yes | no | ⛔ |
| failed file fsync | temp cleaned | unchanged | all-old | fsync error | yes | no | ⛔ |
| **failed dir fsync** | error (A2: even on unsupported-fs) | unchanged | all-old | **spurious on tmpfs/overlay/NFS** | after fix | no | ⛔ **must add; must fix** |
| corrupted journal | rejected | — | **`Fatalf` at boot / soft-fail at Begin** (A-storage-F3, inconsistent) | fatal or soft | after manual delete | no | covered (rejection); ⛔ boot behavior |
| missing before-image (existing file, no capture) | — | — | — | — | — | — | partial |
| stale journal (leftover) | — | — | Begin auto-recovers | none | yes | n/a | ⛔ Begin-with-stale-journal untested |
| concurrent writers (two applies) | serialized by `configApplyMu` | serialized | deterministic | none | yes | n/a | ⛔ no serialization test |
| concurrent readers during commit | old until Publish; **mixed cross-store (A4)** | mixed window | n/a | misclassified traffic | n/a | n/a | ⛔ mid-commit reader untested |
| restart during recovery | partial restore | — | must converge to all-old | none | yes | no | ⛔ **missing** |
| repeated (idempotent) recovery | idempotent by inspection | — | no-op 2nd time | none | yes | n/a | ⛔ **missing at txn layer** |
| draft commit racing revert | serialized (`c.mu`) | serialized | consistent | conflict or ok | n/a | n/a | covered |
| import racing another mutation | serialized (apply) / **unguarded vs dep CRUD (A7)** | lost update possible | last-writer-wins | silent drop | n/a | n/a | partial |
| reachable leader + local apply rejection | old | old | old | poll failing | yes | **no (correct)** | covered |
| actual transport failure | old | old | old | leader unreachable | — | yes (fence-gated) | covered |
| **local TLS-material failure (client build)** | old | old | old | looks like unreachable | after fix | **yes → legacy split-brain (A3)** | ⛔ **must add; must fix** |
| leader timeout | old | old | old | hysteresis | — | after hysteresis | partial (no ctx-deadline injection) |
| leader response invalid config | rejected | old | old | reject logged | yes | no | partial (CA cases only) |
| DP rejection after CP publish | old (retries `vN`) | old | old | **CP blind (A10)** | yes (self-heal) | no | covered (DP side) |

---

## 5. (folded into §3/§6)

---

## 6. Proposed implementation slices

Small, independently reviewable PRs. Policy, drafts, IdP, snapshots, HA, and the generic primitive stay **out of a single mega-PR**. Order adjusted from the proposed sequence because **A1/A2/A3 are correctness prerequisites** to any extraction, and the invariant-#2 decision must precede shared-primitive extraction.

**PR-0 — Preconditions & ADR (blocking).**
- Scope: ADR for `internal/filetxn` fixing its guarantee boundary (disk atomicity only; explicitly disclaims reader isolation — invariant #11). Decide invariant-#2 posture (§7 Q1).
- Non-goals: no code migration.
- Tests: none. Rollback: doc-only. Compat risk: none. External behavior: none. Depends on: nothing.

**PR-1 — Fix the boot-wedge & portability (A1, A2). CORRECTNESS.**
- Scope: `filetxn.Recover` committed-branch degrades to cleanup when the on-disk digest indicates a superseded generation (no `Fatalf`); `syncDir` reuses `AtomicWrite`'s tolerant dir-fsync (no double-fsync, no spurious tmpfs failure). Quarantine-aside for corrupt journals instead of fatal.
- Files: `internal/filetxn/filetxn.go`, `config_apply_txn.go`, `main.go`.
- Non-goals: no consumer changes. Invariants: #5, #9. Tests: superseded-committed-journal, unsupported-dir-fsync, corrupt-journal-quarantine, idempotent double-Recover. Rollback: revert file. Compat: **improves** boot robustness. External: none (fixes a crash). Depends on: PR-0.

**PR-2 — HA reachability vs local rejection (A3, A8). CORRECTNESS.**
- Scope: classify `NewDataPlaneClient`/`buildClientTLS` local-disk/KEK/PEM errors as local-not-unreachable so they never advance `failCount`; reconsider `codes.Unknown/Internal` classification.
- Files: `ha.go`, `controlplane_client.go`, `controlplane_tls.go`.
- Non-goals: no lease/fence redesign. Invariants: #4. Tests: local-TLS-failure-no-promote (end-to-end through the standby loop, not just `handleSyncResult`); dead-leader-wrapped-error-does-promote. Rollback: revert. Compat: none. External: legacy split-brain closed. Depends on: PR-0.

**PR-3 — Reader-consistency decision & (if chosen) generation epoch (A4, A9). Invariant #2.**
- Scope: EITHER (a) document that cross-store publish is not reader-atomic and the deps-first ordering is the accepted posture, OR (b) introduce a per-request generation snapshot (single atomic read of {policy,categories,groups,profiles} pointers) + fix the `ipf` bare-reassign race. **Owner decision required (Q1).**
- Files: `policy.go` (Evaluate), `config_apply_txn.go`, `controlplane_snapshot.go`, `ha.go`.
- Non-goals: not part of the durability primitive. Invariants: #2, #2b, #11. Tests: mid-commit reader sees consistent generation; `-race` on `ipf`. Rollback: feature-flag the epoch read. Compat: none. External: eliminates the misclassification window. Depends on: PR-0.

**PR-4 — Policy two-file durable publication: collapse the duplication (A5, A6). Invariant #8/#10.**
- Scope: route `saveLocked` through `filetxn` (single participant) **with an old-format `policy.json.txn` migration shim**; delete `policySaveTxn`; unify on one recovery authority per file (invariant #12). Fold the draft path's bare-AtomicWrite journal into the same tier or document it.
- Files: `policy.go`, `policy_draft.go`, `config_apply_txn.go`.
- Non-goals: no dependency-store changes. Invariants: #8, #10, #12. Tests: legacy-`.txn`-recovery-then-upgrade, single-participant crash matrix, two-systems-no-longer-coexist assertion. Rollback: retain `policySaveTxn` behind the shim. Compat: **must** read main-written configs (journal-absent) — pin it. External: none. Depends on: PR-1.

**PR-5 — Policy draft serialization/durability hardening (A11).**
- Scope: document (or close) the commit-vs-apply OCC asymmetry (apply `expected=nil`); ensure a DP push cannot silently erase a locally-committed draft without an operator-visible signal.
- Files: `policy_draft.go`, `config_apply_txn.go`. Invariants: #7 (documented exception). Tests: draft-commit-then-apply precedence. Depends on: PR-4.

**PR-6 — CP-side convergence visibility (A10). OPERABILITY.**
- Scope: `MetricsReport`/heartbeat carries applied-config-version + reject signal; CP surfaces a cluster "applied version" convergence view.
- Files: `controlplane.go`, `controlplane_server.go`, `controlplane_client.go`, `diagnostics.go`, UI. Non-goals: no apply-path change. Tests: stuck-DP-visible-on-CP. Depends on: PR-2.

**PR-7 — Recovery-ownership refactor + `ClusterStore` participant fix (A6, §1.8).**
- Scope: each multi-store domain registers its journal name instead of `config_apply_txn.go` hardcoding HA/DP; make `ImportFullState` a real single-file `filetxn` participant or drop the `filetxn.Write` borrow. Depends on: PR-4.

**PR-8 — Shared-primitive extraction ONLY after ≥2 production consumers prove identical semantics (the user's step 7).**
- Scope: only if PR-4 + the DP/HA consumers demonstrably share guarantees, finalize the primitive surface; otherwise stop at per-domain adapters. Non-goals: no speculative generalization. Depends on: PR-4, PR-7.

**PR-9 — Migration & removal of duplicated mechanisms + verification harness (§7).** Depends on: all above.

---

## 7. Verification plan (beyond unit tests)

Do **not** claim "crash-safe", "atomic", or "durable" without evidence from this harness.

1. **Deterministic fault injection at the fs layer** — add an injectable `writeFile`/`syncDir`/`rename` seam to `filetxn` (mirroring `beginCrossStoreTxn`) returning ENOSPC/EIO on file-write, file-fsync, rename, and **dir-fsync independently**; assert all-old + nothing published. *Closes the single biggest hole.*
2. **Real-temp-dir restart recovery** — call the **production** `recoverCrossStoreTransactions(dataDir)` (currently untested) with: no journals (clean load of main-written config — the compatibility contract), one committed + one uncommitted, and a corrupt journal.
3. **Process-kill / simulated-crash boundary** — a subprocess (`os/exec` re-invoking the test binary) `SIGKILL`'d between file-fsync and the commit marker; a fresh process runs recovery and asserts all-old/all-new. *The only way to validate the fsync-durability the in-process harness assumes.*
4. **Concurrency & race** — two concurrent `commitPreparedConfig`/`applyHABundle`/rollback on one journal (serialization); Evaluate/List hammered while a `filetxn.Commit` is mid-flight (extends the publication-race suite to the txn layer); `-race` on `ipf`.
5. **Corrupted-state** — already partly covered; add quarantine-not-fatal assertions (PR-1).
6. **Idempotent recovery** — `filetxn.Recover` twice = clean no-op; boundary failure *inside* `Recover`'s restore loop then re-run converges (restart-during-recovery).
7. **HA state-machine** — end-to-end: injected local persistence failure drives the real standby loop and proves no promotion + poll-failing health (join the two halves currently tested separately); local TLS-material failure no-promote (A3); dead-leader-wrapped-error does promote (A8).
8. **Before/after generation assertions** — every apply test asserts the *whole* generation (policy+deps) old-or-new, not just policy.
9. **Failed-persistence-never-visible** — keep the strong existing coverage; extend to the sibling-store window (A4).
10. **Compatibility** — boot from configs written by current `main` (no journal) — pin as a contract test.
11. **Benchmarks** — `BenchmarkCommitPreparedConfig` / `BenchmarkApplyHABundle` quantify the per-commit fsync tax (~10 fsync pairs per HA bundle) and guard admin-latency regression.

---

## 8. Risk register

| ID | Risk | Severity | Blast radius | Mitigation (PR) |
|---|---|---|---|---|
| R1 | Superseded committed journal wedges boot | **HIGH** | Every node with a lingering `config_apply.txn` after an inline policy edit → total outage on restart | PR-1 |
| R2 | filetxn non-portability on unsupported dir-fsync | **HIGH** | Any tmpfs/overlay/NFS `/data` → all cross-store applies + HA/DP sync fail | PR-1 |
| R3 | Legacy split-brain from local TLS-material fault | **HIGH** | Legacy (non-lease) HA clusters → dual leaders, divergent config | PR-2 |
| R4 | Mixed-generation reader window (policy-old/deps-new) | **MED-HIGH** | Every DP/HA publish → transient traffic misclassification (allow/deny) for the I/O window | PR-3 |
| R5 | Two durability tiers + two recovery roots on `policy.json` | **MED-HIGH** | Ambiguous recovery → wrong/stale rules restored unverified | PR-4 |
| R6 | `ipf` pointer data race | **MED** | DP snapshot apply → `-race` failure, torn IP-filter reads | PR-3 |
| R7 | Dependency CRUD lost update vs apply | **MED** | Concurrent admin edit + apply → silently dropped group/category | PR-5/§3 |
| R8 | Failover suppressed by `codes.Unknown` latch | **MED** | Dead-leader wrapped error → no failover, availability loss | PR-2 |
| R9 | CP blind to stuck DP | **MED** | DP serves stale config while "healthy" | PR-6 |
| R10 | Verification claims outrun evidence | **MED** | "crash-safe" asserted without kill/fsync tests → false confidence | PR-1/§7 |
| R11 | No ADR for cross-cutting engine | **LOW-MED** | Governance drift; future re-inlining | PR-0 |
| R12 | Draft silently erased by DP push | **LOW-MED** | Operator loses staged work | PR-5 |

---

## 9. Recommendation

**PROCEED WITH REDESIGN — retain selected changes, introduce the architecture through minimal provable slices; do not merge the branch as one unit, do not rebase-drop yet.**

- **Retain (as evidence, then re-land via slices):** the `internal/filetxn` primitive (boundary is correct), the `prepareX/Publish` pattern, the HA `(ok, leaderReachable)` split, the DP last-good atomic bundling. These are genuinely valuable and enterprise-aligned.
- **Fix before extraction (blocking):** A1 (boot wedge), A2 (portability), A3 (split-brain). These are correctness bugs the drift *introduced or exposed*; shipping the primitive without them makes reliability worse, not better.
- **Decide, don't default:** invariant #2 reader consistency (Q1) — the drift silently chose "deps-first ordering, not reader-atomic"; that must be an explicit owner decision, not an accident of publish order.
- **Collapse, don't coexist:** the policy duplication (A5/A6) is the clearest "the generalization added instead of replaced" defect. One mechanism, one recovery authority.
- **Do NOT generalize further than evidence supports:** standalone IdP / single-file CA must stay single-rename; the shared primitive is justified for the multi-store publishers only, and only after ≥2 prove identical semantics (PR-8).
- **Preserve provenance:** keep tag `preserve/decision-integrity-e10a18e` and `.review-evidence/` until PR-9 lands. The two already-merged commits (`6ac980d`, `62f6b46`, now in main via #738) should be dropped only as part of the slice rebase, not before this review is accepted.

---

## 10. Questions requiring owner approval

1. **Invariant #2 posture (blocking PR-3).** Is cross-store *reader* consistency a hard requirement? If yes → per-request generation-epoch snapshot (added complexity in the proxy hot path). If no → we *document* the deps-first ordering as the accepted transient window. Which?
2. **Policy duplication resolution (PR-4).** Adapt `saveLocked` onto filetxn *with* a legacy-`.txn` migration shim (preferred), or retain `policySaveTxn` and formally document it as a second tier? The shim is the only way to avoid a crash-before-upgrade boot wedge.
3. **Legacy HA mode (PR-2).** Is legacy (non-lease) auto-failover still supported in enterprise deployments? If it is being retired, A3's split-brain severity drops and PR-2 can be scoped to classification-only.
4. **Sibling-store scope (invariant #1 refinement).** Should blocklist/SSL-bypass/DPI/threat-feed join the atomic generation (bigger transactions, more fsync tax), or remain best-effort-eventually-converged via last-good re-apply? This sets the transaction's true boundary.
5. **ADR ownership (PR-0).** Who signs the `internal/filetxn` ADR, and does it supersede any part of ADR-0002's "engines in internal/" guidance for cross-cutting infrastructure?
6. **CP convergence surface (PR-6).** Is a cluster-wide "applied config version" view in scope now, or deferred? It is the only way an operator learns a DP is stuck.
7. **Verification bar.** Is a real process-kill crash-consistency harness (§7.3) required before we may use the words "crash-safe"/"durable" in operator docs, or is the in-process boundary harness acceptable with the claim scoped accordingly?

---

*Appendix — provenance: five specialist audits (storage durability, HA/distributed-systems, concurrency, test/fault-injection, architecture simplification), each read-only, each required to return code references and challenges. Full finding-level detail with `file:line` evidence is summarized inline above and preserved in the review record.*
