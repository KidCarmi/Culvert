# ADR-0012: Durable Configuration Publication — the `internal/filetxn` guarantee boundary

- **Status:** Proposed (decision contract only — **no runtime behavior changes in this ADR**)
- **Date:** 2026-07-18
- **Deciders:** Engineering Advisor (proposed); project maintainer (to ratify)
- **Depends on:** ADR-0002 (flat→`internal/` decomposition — a new cross-cutting `internal/` engine
  requires a recorded design). Relates to ADR-0004/0005 (HA fencing/lease — the HA-bundle publication
  surface) and ADR-0001 (records the ADR process itself).
- **Supersedes / replaces:** nothing. This ADR does **not** adopt the prototype; it fixes the
  *contract* the prototype must satisfy before any consumer is wired.

> **Provenance.** An overnight prototype ("the drift") grew a generic file-transaction primitive
> (`internal/filetxn`) plus a cross-store orchestration layer (`config_apply_txn.go`) while the older
> single-purpose `policySaveTxn` mechanism still exists beside it. The full read-only audit
> (five independent specialist passes) is archived verbatim at
> `docs/architecture/DURABLE-CONFIG-PUBLICATION.md` on branch
> `archive/decision-integrity-hardening-prototype-20260718` (commit `097b0a5`). Baseline under review:
> `decision-integrity-hardening` @ `e10a18e`. This ADR distills that audit into a ratifiable
> decision contract. It decides **only** what is safe to decide now (§6.1) and explicitly defers the
> owner-gated questions (§6.2).

## Context

Culvert publishes configuration across ~15 on-disk stores (policy + policy-meta, drafts, URL-category,
category-groups, decryption-profiles, IdP registry, CP→DP snapshot, HA bundle, cluster state, config
versions, blocklist/SSL-bypass/DPI/threat-feed siblings) through **at least three** different durability
mechanisms with **two** independent crash-recovery entrypoints, no cross-store atomicity contract, and no
reader-side generation isolation. The drift is the first attempt to give this a coherent contract.

The prototype primitive `internal/filetxn` (archived at `internal/filetxn/filetxn.go`) is **mechanically
sound** for what it actually is — a recoverable all-old/all-new publication for a small, caller-serialized
set of files:

- content is fsynced before rename (`fileutil.AtomicWrite`, `internal/fileutil/fileutil.go`), and the
  parent directory is fsynced after rename;
- a JSON journal records per-file before-images + SHA-256 digests and a whole-record checksum
  (`filetxn.go:39-45`, `writeRecord` `245-259`, `recordChecksum` `313-320`);
- the crash-point matrix resolves to all-old or all-new at every injectable boundary via the
  `WithBoundaryHook`/`ErrSimulatedCrash` seam (`filetxn.go:47-55`, `131-156`).

It **cannot be adopted as-is** for two classes of reason, which this ADR separates:

1. **Contract defects that are safe to fix now** (correctness, no design choice required):
   - **A1 — boot-wedge.** `Recover`'s committed branch (`filetxn.go:215-231`) returns a hard error when
     an on-disk artifact digest no longer matches the journal's recorded `AfterSHA256`. A journal that
     *committed* but was then *superseded* by a newer authoritative write (e.g. an inline `policySaveTxn`
     to the same `policy.json`) trips this. Wired through `recoverCrossStoreTransactions` →
     `logger.Fatalf` at boot (archived `main.go:184-185`), a single stale-but-committed journal
     **permanently wedges startup** (a self-inflicted DoS). Same for a corrupt/invalid journal
     (`filetxn.go:191-214`), which currently hard-errors instead of being quarantined aside.
   - **A2 — portability regression.** `AtomicWrite` performs a **tolerant** parent-directory fsync — it
     ignores `EINVAL`/`ENOTSUP`/`EOPNOTSUPP` and treats a dir-open failure as best-effort
     (`internal/fileutil/fileutil.go`, the `d.Sync()` block). `filetxn.durableWrite` calls `AtomicWrite`
     **and then** `syncDir` again (`filetxn.go:282-306`), and that second `syncDir` is **intolerant** —
     it returns any `dir.Sync()`/`os.Open` error. So `filetxn` **double-fsyncs** and **fails on
     tmpfs/overlay/NFS** where the very primitive it wraps succeeds — it is *less* portable than
     `AtomicWrite`.
   - (A3, HA reachability-vs-local-fault, is a sibling correctness defect handled by its own slice; it is
     not a `filetxn` contract issue and is out of scope for this ADR beyond invariant #4 below.)

2. **A design choice that must NOT be defaulted silently** (§6.2): whether cross-store publication owes
   readers a *consistent generation* (invariant #2b). The drift silently chose "deps-first ordering, not
   reader-atomic." That is an owner decision, not an accident of publish order.

CLAUDE.md records that new `internal/` engines "go here with a recorded design; do not re-inline them,"
and the audit notes a cross-cutting engine touching policy/HA/DP/config/rollback "requires a recorded ADR
… An ADR is a merge prerequisite." `filetxn` currently carries only a package comment. **This ADR is that
prerequisite.**

## Decision (proposed)

### 1. `internal/filetxn` guarantee boundary — what it IS

`internal/filetxn` is a **narrow durable-write primitive**: recoverable *all-old/all-new* publication of a
small, **caller-serialized** set of regular files, plus deterministic restart recovery. Its complete
contract:

- **Disk atomicity (invariant #2a).** After `Commit` returns, every artifact is durably the new content;
  before `Commit`, a crash leaves every artifact durably the old content (or absent, if it did not
  previously exist). There is no partial on-disk generation observable after recovery.
- **Durability (invariant #9).** Content is fsynced before rename; the containing directory is fsynced
  after each create/rename/remove, using the **same tolerant classification as `AtomicWrite`** — an
  unsupported-filesystem dir-fsync is a success, not a durability failure (fixes A2).
- **Deterministic, idempotent recovery (invariant #5).** `Recover` on a journal is a pure function of
  on-disk state: uncommitted → restore before-images; committed-and-current → keep new, drop journal;
  **committed-but-superseded → drop journal (cleanup), never fatal** (fixes A1); corrupt/unparseable →
  **quarantine aside, never fatal** (fixes A1). Running `Recover` twice is a no-op the second time.
- **Integrity.** Journals carry per-artifact before/after SHA-256 and a whole-record checksum; a
  tampered or truncated journal is detected and refused (quarantined, not obeyed).
- **Single recovery authority (invariant #12).** Exactly one recovery caller owns each on-disk file. The
  primitive provides the mechanism; **ownership of *which* journal recovers *which* file is a caller
  responsibility** and must not be duplicated across two roots (today `recoverPolicySave` and
  `recoverCrossStoreTransactions` both touch `policy.json` — the headline structural violation #8, closed
  by a later slice, not here).

### 2. Guarantee boundary — what it is NOT (invariant #11, the disclaimer that must be explicit)

**`filetxn` provides disk atomicity only. It does NOT provide in-memory / reader-visibility atomicity.**

A multi-store `publish()` that swaps in-memory pointers one store at a time is a **sequence of independent
swaps**; a concurrent reader (e.g. the proxy hot path evaluating policy against the URL-category taxonomy)
can observe **new store A against old store B** during the swap window, *even though every file on disk is
individually atomic*. `filetxn` structurally cannot and should not close that window — reader isolation is
a **generation-epoch** concern owned by the consuming domain, not a file-transaction concern.

Invariant #11 is added precisely so that a future caller cannot look at an "atomic" transaction API and
*assume* reader isolation it does not get. Any consumer that needs reader consistency must implement a
per-request generation snapshot itself (see §6.2 Q1). This is the central open design decision and is
**deferred**, not decided, by this ADR.

### 3. Intended transaction semantics (the caller contract)

The reusable seam is the **`prepareX → Writes() → Commit → Publish()/Abort()`** pattern, which is
**per-domain by nature** and stays in `package main`:

1. **Prepare** — under the domain's serialization lock, validate inputs and build a detached candidate
   generation plus the `[]filetxn.Write` (path, bytes, mode). No live state is mutated. (Invariant #3:
   validate + persist candidate before publication.)
2. **Begin/Apply/Commit** — `filetxn` writes the journal, applies the artifact writes, then flips the
   commit marker. A crash at any boundary recovers to all-old (pre-commit) or all-new (post-commit).
3. **Publish** (domain) — *only after* `Commit` returns, swap the in-memory pointers. A failed persist is
   never made visible in memory (invariant #1: ack only after required durable state is complete). This
   step is coupled to each store's mutex/memory model and **cannot** be hoisted into `internal/`.
4. **Abort** (domain) — release the candidate; recovery restores before-images on the next boot.

**What belongs in `internal/filetxn`:** `Write`, `Begin/Apply/Commit/Abort/Finish/Recover`, before-image
capture+restore, journal checksum, tolerant file+dir fsync, cleanup, corruption quarantine. It correctly
imports **no domain package** — the boundary of the primitive is right.

**What stays in `package main` (per domain):** candidate construction, the store→bytes marshal, the
in-memory `Publish()/Abort()` lock handoff, and any non-before-image recovery (e.g. the policy draft's
"did the running generation already absorb this candidate?" replay, which is domain logic, not a
before-image restore).

### 4. Invariants — the ratified set

This ADR ratifies the refined invariant set from the audit (§2 of the archived doc). Held today and **not
to be regressed**: #1 (failed persistence never visible in memory), #3 (prepare before publish), #7 (OCC
inside the serialized boundary, with the documented `expected=nil` bulk-apply exception), #2a (disk
atomicity). To be established by the correctness slices: #5 (deterministic/idempotent recovery — A1),
#9 (tolerant durability — A2), #4 (a local persistence/TLS-material failure must not read as "leader
unavailable" — A3, separate slice). Structural targets for later slices: #8/#12 (exactly one recovery
authority per file), #10 (no silently-weaker tier). **Open and owner-gated:** #2b (reader visibility) and
#11's consequence — see §6.2.

### 5. Fault model (ratified)

The failure matrix in §4 of the archived audit is adopted as the specification the primitive's tests must
prove. The two rows this ADR's contract changes:

| Fault | Old behavior | Contract after A1/A2 fix |
|---|---|---|
| committed journal superseded by a newer authoritative write | `Recover` hard-errors → `Fatalf` → **boot wedged** | `Recover` treats the recorded generation as superseded → **cleanup journal, return nil** |
| corrupt / unparseable journal at boot | hard-errors → `Fatalf` | **quarantine aside** (rename to a sidecar), surface a typed/observable signal, **do not wedge boot** |
| dir fsync on tmpfs/overlay/NFS | intolerant `syncDir` → spurious failure | tolerant (mirror `AtomicWrite`) → success; **no double-fsync** |

## Consequences

- **Positive.** A ratified, testable contract; the primitive can be adopted incrementally by later slices
  without callers assuming guarantees it does not provide; boot robustness is *specified* (no journal can
  wedge startup); the ADR-0002 governance requirement for a new `internal/` engine is satisfied.
- **Negative / cost.** The contract makes explicit that reader isolation is *not* provided, which means
  the invariant-#2b decision (§6.2 Q1) cannot be dodged — a real design cost deferred to PR-3, not erased.
- **Neutral.** This ADR changes **no code and no runtime behavior.** It is a decision contract only.

## 6. Decision scope — what this ADR settles vs. defers

### 6.1 Safe to decide now (settled by this ADR)

1. Keep `internal/filetxn` as a **narrow durable-write primitive** with the boundary in §1–§3; do **not**
   generalize it further until ≥2 production consumers prove identical semantics.
2. `filetxn` provides **disk atomicity only** and **explicitly disclaims reader isolation** (invariant #11).
3. The **A1 and A2 contract fixes are correctness fixes**, not design choices, and are approved to land as
   the next slice (a corrected primitive with fault-injection tests, **no consumers wired**).
4. An ADR is a **merge prerequisite** for the `internal/filetxn` engine; this is it.
5. The **`prepareX → Commit → Publish/Abort` pattern stays per-domain** in `package main`; the in-memory
   publish handoff is not hoisted into `internal/`.

### 6.2 Requires owner approval (explicitly deferred — NOT decided here)

These are recorded so they are **decided, not defaulted**. This ADR takes no position on them.

- **Q1 — Invariant #2b (reader consistency). BLOCKING for the reader-consistency slice.** Is cross-store
  *reader* consistency a hard requirement? If **yes** → a per-request generation-epoch snapshot (a single
  atomic read of the `{policy, categories, groups, profiles}` pointers) plus fixing the `ipf` bare
  pointer-reassign race — added complexity on the proxy hot path. If **no** → we *document* the deps-first
  ordering as the accepted transient window. **The prototype silently assumed "no." That assumption is not
  ratified by this ADR.**
- **Q2 — Policy-store consolidation.** Whether to route `saveLocked` through `filetxn` and **delete**
  `policySaveTxn` (with an old-format `policy.json.txn` migration shim), versus retaining it behind a
  documented exception. The current *coexistence* (two schemes + two recovery roots on the same files) is
  the worst option and must not ship — but which way to collapse it is an owner call (later slice).
- **Q3 — Sibling-store transaction boundary.** Whether blocklist / SSL-bypass / DPI / threat-feed join the
  atomic generation (larger transactions, more fsync tax) or remain best-effort-eventually-converged. This
  sets the transaction's true boundary and is out of scope until Q1 is answered.

Nothing in §6.2 is implemented or pre-committed by adopting this ADR. Landing the A1/A2 primitive fixes
does **not** decide Q1/Q2/Q3.

## Validation against the codebase

Every claim above is anchored to code inspected at review time:

- A1 boot-wedge: `internal/filetxn/filetxn.go:215-231` (committed re-verify hard-error), `191-214`
  (corrupt-journal hard-error), archived `main.go:184-185` (`recoverCrossStoreTransactions` →
  `logger.Fatalf`), archived `config_apply_txn.go:165-170` (`recoverCrossStoreTransactions` loops
  `filetxn.Recover` over hardcoded journal names).
- A2 portability: `internal/fileutil/fileutil.go` `AtomicWrite` tolerant dir-fsync (`EINVAL`/`ENOTSUP`/
  `EOPNOTSUPP` ignored; dir-open failure best-effort) vs `internal/filetxn/filetxn.go:282-306`
  (`durableWrite` re-`syncDir`, intolerant).
- Reader window (#2b/#11): archived `config_apply_txn.go:90-124` (`publishDependencies`/`publishPolicy`/
  `publish` — independent in-memory swaps, no reader barrier).
- Recovery duplication (#8/#12): `policy.go` `recoverPolicySave` at policy load vs archived
  `config_apply_txn.go:165-170` at startup, both over `policy.json`.
