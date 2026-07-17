# RISK-022 PR-E — `ReconcileOnStartup` design record

**Status:** DESIGN — awaiting owner sign-off before any executable code (this
slice runs `docker` at boot; it is the one destructive slice of the RISK-022
program).
**Authority:** `roadmap/MAINTENANCE-AGENT-RESILIENCE-HARDENING.md` (Tier 1,
T1.1–T1.6) and `roadmap/RISK-022-crash-recovery-journal-plan.md`.
**Consumes:** the durable journal (PR-C #748), the lifecycle wiring +
`MarkAllInterrupted` (PR-D #750), the phase progression + `PhaseRestarting`
write-ahead barrier (PR-D2 #754), and the structural digest selection (#751).

**Revision:** v2 — hardened by a five-lens adversarial red-team (crash-consistency,
decision-table completeness, security/privilege, multi-arch digest-class,
availability). §0 below records the MUST-FIX findings that supersede the original
design (§1–§11). The originals are retained beneath for the review trail; **where
§0 and a later section conflict, §0 wins.**

---

## 0. Red-team hardening (v2) — MUST-FIX before build

The design as first written (§1–§11) has **six P0-class defects** that would make
the reconciler roll back healthy upgrades, brick boot, or run unauthenticated
`docker` as root. None are cosmetic; each has a code-traced scenario. This
section is the authoritative spec; the slicing in §11 is revised at the end.

### P0-A — Digest comparison is doubly class-broken → false-rollback of EVERY healthy interrupted upgrade
Two independent bugs, either one fatal:
1. **Prefix mismatch (arch-independent).** Shipped `foldIdentifiers`
   (`journal_phases.go`) stores `rec.TargetDigest`/`PriorDigest` **stripped** of
   the `sha256:` prefix, but `bareDigests`/`extractDigests` (the capture/tag
   sources) keep it (`digestRE.FindString` includes the prefix). So
   `digestSetsIntersect(running, {rec.TargetDigest})` compares `"sha256:abc…"`
   vs `"abc…"` → **always empty** → every `restarting`/`restarted`/`verified`
   record falls through to *indeterminate → rollback-to-prior*. Apply never hits
   this because it only ever intersects two same-(prefixed)-class sets.
2. **Digest-class mismatch (multi-arch).** `rec.TargetDigest` is the **per-platform
   manifest descriptor** digest (from `resolveTargetManifestDigest`). A running
   image obtained by TAG — the fresh-install seed (`install.sh` does
   `docker pull :tag` → `docker tag … culvert/proxy:pinned`), or any operator
   `compose pull` — reports the **manifest-LIST** digest in `RepoDigests`.
   Per-platform ∩ list = ∅ for the *identical healthy version* → false rollback.
**FIX (required, defines E1):**
- Normalize prefix on both sides (or store record digests WITH the `sha256:`
  prefix — recommended, consistent with the rest of the codebase). **This also
  corrects the shipped `foldIdentifiers`** — do it in E1.
- Add the **class-invariant image config digest** (`RunningImageID` / `.Id`) to
  the `Record` (a new `PriorImageID`/`TargetImageID`) and make it the **primary
  adopt key**, compared **config-vs-config** (the config digest is stable across
  tag-vs-digest pulls — the one class that survives the seed/manual-pull lineage).
- The manifest-digest axis must mirror **`verifyRunningImage`'s exact operand**
  (`pinnedDigest ∈ running RepoDigests`, prefixed) — never a generic set
  intersection that straddles classes.
- Record full RepoDigest **sets**, not `priorDigests[0]` scalars (`[0]` is the
  lexicographically-smallest, arbitrary w.r.t. class).
- Test plan MUST include **mixed-class fixtures** (stripped-record vs prefixed-
  capture; list-class running vs per-platform target; `.Id` in the set). Same-class
  fixtures pass while the bug is live — they are not sufficient.

### P0-B — Phase A freezes the op terminal before Phase B can adopt (Manager can't re-terminalize)
`MarkAllInterrupted` inserts the op as `StateFailed`+`Finished` (terminal), and
`Manager.Finish` hard-refuses a terminal→terminal transition. So the adopt path
**cannot** mark an op `succeeded(reconciled)` — the API would report `failed`
forever while `/v1/status` claims success (the two-sources-of-truth split, made
unexpressible).
**FIX:** Reconcile-**before**-mark for journaled danger-window records:
`MarkAllInterrupted` SKIPS records with a journal entry at phase ≥ `restarting`
(and `rollbacks.create`); Phase B owns their terminal transition. Non-journaled
orphans + safe-boundary records still get marked in Phase A. (Alternative: add an
explicit `Manager.Reconcile(opID,state,reason)` override.) Name the single source
of truth and pin it with a test.

### P0-C — Bind-first, reconcile-in-background: never let reconcile dark the agent
Running Phase B fully before the listener binds (original §7) means: (a) no
phase-level deadline → each `docker` stage burns up to the 5m `StageTimeout`
(`OperationTimeout` is NOT applied on the boot path) → tens of minutes of a dark
agent; (b) the agent is **un-commandable exactly when reconcile is wedged** — the
CP's own last-resort recovery is disabled by the recovery mechanism.
**FIX:**
- **Bind the UDS listener FIRST**; run reconcile in a background goroutine holding
  the flock. Serve `/v1/health`, `/v1/status`, `/v1/audit` immediately with
  `reconcile: in_progress|done|abandoned`.
- Preserve "no operator op races reconcile" by returning **409** on
  stack-mutating ops while the flock is held (not by blacking out the listener).
- Add a hard `reconcile_deadline` (config+env, default ≈ 2×StageTimeout) wrapping
  ALL of Phase B; on expiry, mark unfinished records
  `failed(interrupted, reconcile_deadline)` and serve degraded. Reconcile must
  never block the bind.
- Expose `POST /v1/reconcile/cancel` so the CP can abort a bad reconcile.

### P0-D — Unbounded boot→reconcile→crash loop
A reconcile-issued rollback is itself a journaled `rollbacks.create` op, so a
crash in *its* danger window re-reconciles next boot → unbounded loop on an
OOM/crash-looping host; images can oscillate every boot. (Original §6 also
contradicts §7: §7 says "upgrades.apply records only," so §6's "recoverable next
boot" is false without processing reconcile-origin records.)
**FIX:** Add `ReconcileAttempts int` + `Origin` ("operator"|"reconcile") +
`LastAttemptAt` to `Record`. Cap attempts (default 2–3) per `op_id`, then
**stop acting** → `failed(reconcile_exhausted, manual_required)`, keep serving,
leave the stack untouched. Boot-to-boot exponential backoff. State definitively
that reconcile DOES process reconcile-origin `rollbacks.create` records (so §6
holds) but each counts against the cap.

### P0-E — Unauthenticated on-disk refs → root `docker` at boot (re-validation invariant missing)
The reconciler feeds `PriorRef`/`TargetRef` from an unauthenticated JSON file to
`docker pull`/`tag` **as root**, and the doc never states the re-validation that
keeps that safe. Today `validatePinnedDigestRef` + the proxyRepo-bound sudoers
pattern block `evil.io/malware`, but the `image_allowlist` gate is enforced only
by the apply *handler* (reconcile has none), and a future "local retag fast-path"
could bypass `validatePinnedDigestRef` entirely.
**FIX (explicit invariant):** Every ref sourced from a record
(`PriorRef`/`TargetRef`) is re-validated with `validatePinnedDigestRef(ref,
proxyRepo)` AND its embedded digest must equal the record's bare-digest field
(`PriorRef`⇔`PriorDigest`), before ANY `pull`/`tag`/`inspect`. Failure ⇒
loud-stop (`failed(interrupted, invalid_record_ref)`), never acted on. The
local-first probe must use the **validated** ref. Reconcile acts ONLY on
immutable `@sha256` digests already in the record — it never resolves a
tag→digest at boot (hostile-registry-safe). **Refinement (E1c, Codex-reviewed):**
`image_allowlist` is deliberately NOT re-checked at reconcile. It is an
ADMISSION-time policy matched by the apply handler against the operator's
ORIGINAL ref (possibly a TAG), and the journal stores the RESOLVED `repo@sha256:`
ref — so re-matching a tag-scoped allowlist against the digest ref would
spuriously loud-stop a policy-admitted upgrade. Repo-binding + ref⇔digest is the
sufficient reconcile-time gate: it blocks foreign-repo injection, and an attacker
who can push a malicious digest to the configured proxyRepo has already
compromised the source of truth (the allowlist would not have helped).

### P0-F — Shared rollback core has no write-ahead barrier
`imageRollbackStages` calls `ComposeTagPinned` with **no `PhaseRestarting`
barrier** ahead of it, and the standalone/inline/reconcile rollback paths are not
phase-instrumented — so a crash during a rollback's tag advance leaves the record
at `admitted` (a "safe boundary" the main table no-ops), while the tag actually
moved → reopens RISK-022 on the rollback path. §6's "own barrier" claim is
unbacked.
**FIX:** Insert the fail-closed `PhaseRestarting` write-ahead barrier +
phase/digest folding into the **shared `imageRollbackStages` core** (before its
`ComposeTagPinned`), covering standalone `POST /v1/rollbacks`, apply's inline
auto-rollback, AND reconcile-issued rollbacks in one place (anti-drift). This is
a prerequisite of E3 and closes the D1 standalone gap.

### P1 hardening (fold into the relevant slice)
- **dockerd readiness gate + capture-error ≠ empty (decision D2 / avail F6).**
  A `CaptureRunningProxyImage` **error** (daemon not up at boot) must NOT be read
  as `running=∅`→rollback. Probe `docker version` (bounded ~5–10s) before Phase B;
  if not ready, skip reconcile → mark-only → serve. Require `After=docker.service`
  + `Requires=docker.service` in the unit. Only a *successful* inspect returning
  zero proxy containers is the "stack genuinely down" trigger.
- **`(Kind, Mode)` router ahead of the phase table (decision D3).**
  `upgrades.apply`→image table; `rollbacks.create,image`→image table (per P0-F);
  `rollbacks.create,data`→**never touch Docker**, emit loud-detection (recovery
  command + `/v1/status.last_reconcile.data_window` + audit), then
  `failed(interrupted, data_window_manual)`. A `mode=data` record can never enter
  the image table. (`Mode` is durably journaled — the discriminator exists.)
- **Reconcile health gate strictly more conservative than inline (avail F5).**
  A dedicated, larger `reconcile_health_budget` that is actually PLUMBED (the
  factory currently supplies the 30s default, not T3.2's bigger budget).
  Distinguish a probe **timeout** from a **definitive-unhealthy** `/ready`: if
  `running==target` and the probe only timed out, **adopt and mark warming** —
  do not roll back a healthy-but-slow cold start. Roll back only on a definitive
  bad signal or `running ∉ {prior,target}`. The `verified` re-probe (keep it — a
  post-reboot stack's pre-crash health is stale) rides the same conservative gate.
- **No-offline floor (avail F4).** Never take a running proxy DOWN for rollback
  unless the rollback target is **confirmed local** (`docker image inspect` hit).
  On pull-miss + registry-fail, do NOT `down`/recreate — abort, leave the running
  stack, loud-mark `no_recovery_target`. mark-only beats making a degraded-but-up
  proxy fully down.
- **Remove the record on EVERY terminal branch (crash F3).** adopt, rollback,
  no-op, and loud-mark all `Remove` the source record (unlink + parent-dir fsync)
  once journaled/acted — else the dir never drains and every boot re-reconciles
  (a latent refuse-to-serve amplifier). The fresh reconcile-rollback op owns its
  own lifecycle.
- **Safe-boundary rows must Docker-verify, and the `tag` fact must be used or
  dropped (crash F4 / multiarch F4).** The main table currently no-ops
  `admitted..pulled` on phase alone — the exact elided-fsync case §3's preamble
  warns about. Either verify `running ∩ target = ∅` before no-op'ing AND add the
  branch that consumes `tag` (`tag ∩ target ≠ ∅` while phase `< restarting` ⇒
  elided-fsync ⇒ treat as danger window), or drop `ComposeImageInspectPinned`
  entirely and key purely on `running` (authoritative). Do not ship a dead input.
- **Dedicated enumerated sudoers line for the pinned inspect (security 3).** Do
  NOT reuse the `docker image inspect *` wildcard (the doc miscalled it
  "enumerated"; the wildcard already lets a compromised agent dump `.Config.Env`
  at root). Add `/usr/bin/docker image inspect culvert/proxy\:pinned` (no
  wildcard), mirroring the container-inspect enumeration.
- **Quarantine junk records; do not brick boot (security 4).** A single
  unparseable/junk `.json` currently fails `List()` closed → permanent
  refuse-to-serve (a resilience regression). Distinguish an *actionable
  danger-window record* from a *junk file*: move-aside + loud alert on
  corrupt/invalid-name entries; refuse-to-serve only for a record that genuinely
  parses as a danger-window op it cannot act on.

### P2 hardening (note in the doc; batch)
- **StateDir/reconcile symlink safety (security 5).** Verify StateDir +
  `reconcile/` are agent-owned, non-symlink, mode ≤0750, not group/other-writable
  before arming the flock or reading records; open the lock with `O_NOFOLLOW`.
  Document StateDir must be host-local agent storage, **never** a container-shared
  volume (the proxy container MUST NOT be able to write `reconcile/`).
- **TOCTOU re-capture (crash F7).** For any *acting* branch, re-capture `running`
  immediately before `tag`+`up` and converge-then-verify
  (`tag prior → up → re-capture → assert running∩prior`).
- **Reframe "atomic Finish+Remove" (crash F6).** A mutex is not crash-atomicity.
  The durability boundary is Remove-then-parent-dir-fsync; the real guard against
  a resurrected record → spurious rollback is the §3 `running∩target` healthy →
  **adopt** path. Drop "atomic under one lock."
- **Bound docker stdout (security 6).** Extract only structural `sha256:<64hex>`
  tokens (reuse #751 selector / `digestRE`); non-conforming inspect output ⇒
  loud-stop, never a guessed branch. Decisions never key on free-form labels/tags.
- **Set-overlap ordering + `prior==target` (decision D4/D5).** State the
  sub-decision as an ordered first-match ladder (`running∩target` first); add an
  early guard: if the prior digest-set == target digest-set, verify-and-adopt,
  never roll back.

### Posture change — ship v1 default-OFF (mark-only)
Multiple lenses (avail F7, security 8) converge: `reconcile_on_startup` should
default **OFF (mark-only)** for v1. Auto-`docker`-at-boot is the single
destructive slice, at the least-observable moment; a latent decision-table bug on
a correlated-reboot event (bad kernel update, datacenter power) becomes a
**fleet-wide brick**. Phase A's loud, queryable mark-only already closes the
silent-stranding gap. Flip to default-on only after the T3 acceptance suite runs
on **real hardware** + a field bake. The cost of default-off is one manual
command; the cost of a default-on bug is a fleet.

### Revised slicing (supersedes §11)
- **E1 — decision core + digest correctness (SAFE, build first on approval).**
  Pure `reconcileDecision(rec, running, tag, imageID) → action` (no Docker side
  effects); the **digest-class fix** (prefix normalization + config-digest
  primary key + full sets — *including correcting the shipped `foldIdentifiers`*);
  record-ref re-validation (`validatePinnedDigestRef`+allowlist+ref⇔digest);
  the `(Kind,Mode)` router; `ReconcileAttempts`/`Origin` schema; **mixed-class +
  attempt-bound unit tests**. No boot hook, nothing runs docker.
- **E2 — shared-core barrier + local-first rollback.** Insert the `PhaseRestarting`
  barrier into `imageRollbackStages` (P0-F); local-first retag-from-local with the
  no-offline floor (avail F4); the dedicated enumerated sudoers line. Improves the
  existing rollback paths; still no boot hook.
- **E3 — the boot hook (GATED).** `ReconcileOnStartup` wired **after** the bind
  (P0-C), in a flock-held goroutine, behind the **default-OFF** switch, with the
  reconcile deadline, dockerd-readiness gate, reconcile-before-mark (P0-B),
  degraded-serve + cancel endpoint, junk-quarantine, `/v1/status` surface, and the
  **T3 acceptance on real hardware**. This is the slice that first runs `docker`
  at boot — the final go/no-go, not to be enabled-by-default until field-baked.

---

## 1. What is already shipped (do NOT re-do)

| Capability | Where | PR |
|---|---|---|
| Durable per-op journal (`Record`/`Phase`, fail-closed atomic writer, strict-ULID paths, corrupt-record `ErrCorruptRecord`) | `internal/journal` | #748 |
| `PhaseAdmitted` at admission (fail-closed); terminal removal via `OrchestratorDeps.Journal`; `MarkAllInterrupted(orphans)` marks orphaned ops `failed(agent_restart_interrupted)`; startup reads journal fail-closed (corrupt ⇒ refuse to serve) | `handlers_d16b.go`, `orchestrator.go`, `main.go::initJournal` | #750 |
| Phase progression `captured→resolved→pulled→restarting→restarted→verified`, folding target/prior digests; **fail-closed `PhaseRestarting` write-ahead barrier** before the tag advance (re-creates a missing record) | `journal_phases.go` | #754 |
| Structural manifest-digest selection (host-platform, fail-closed) — the T1.2 "part 1" | `manifest_digest.go` | #751 |

**PR-E is Phase B only** — the boot-time *reconcile* that acts on the records
Phase A (`MarkAllInterrupted`) already surfaces. Phase A stays as-is.

---

## 2. Goal & non-goals

**Goal:** after an agent crash / host reboot / OOM that interrupted an
`upgrades.apply` (or standalone `rollbacks.create`) inside the danger window,
the agent — at its NEXT startup, before serving any request — drives the
`culvert/proxy:pinned` tag + running stack back to a **known-good** digest
(the recorded prior), or confirms the new image is healthy and adopts it. No
manual `docker` surgery. Closes `FAILURE-INJECTION-TEST-PLAN.md` T3.

**Non-goals (explicitly deferred):**
- **Data-rollback (`mode=data`) reconciliation** — the `/data`-swap window is
  NOT auto-reconciled (RISK-005 fail-closed boot already guards it). PR-E only
  does **loud detection** (T1.6): surface the exact recovery command via
  `/v1/status` + audit; never auto-`mv`.
- Multi-node / CP-driven reconcile — this is host-local only.

---

## 3. The decision: Docker truth, not the journal phase alone (T1.2 part 2)

The reconcile decision must NOT trust `rec.Phase` in isolation (an elided
parent-fsync could make the journal read `pulled` while the tag already
advanced). It is grounded in **three** facts, compared by **digest-set
intersection** (never scalar equality — multi-arch list-vs-platform):

1. **Tag target** — the digest `culvert/proxy:pinned` currently resolves to.
   *Needs a new runner method* `ComposeImageInspectPinned` →
   `docker image inspect culvert/proxy:pinned` → `RepoDigests`/`Id`. (Sudoers:
   reuse the existing enumerated `docker image inspect *` line — already
   allow-listed, read-only.)
2. **Running digest** — `CaptureRunningProxyImage` (already exists), the
   digests the live proxy container reports.
3. **Journal record** — `rec.Phase` + `rec.PriorRef`/`PriorDigest` +
   `rec.TargetRef`/`TargetDigest`.

### Decision table (per interrupted `upgrades.apply` record)

| Phase reached | Meaning | Reconcile action |
|---|---|---|
| `admitted`, `captured`, `resolved`, `pulled` | **SAFE boundary** — tag NOT advanced | **No-op.** Mark `failed(interrupted)`; nothing to undo. |
| `restarting` | **Danger window** — barrier fsync'd, tag advance may or may not have completed | **Inspect Docker.** See sub-table. |
| `restarted`, `verified` | tag advanced; on `verified` health already passed | **Verify-then-adopt-or-rollback.** See sub-table. |

### Danger-window sub-decision (`restarting` / `restarted` / `verified`)

Let `prior` = `rec.Prior*`, `target` = `rec.Target*`, `running` = live digests,
`tag` = pinned-tag target digests.

- **`running` ∩ `target` ≠ ∅** (new image is live):
  - bounded health-probe retry (reuse `HealthProbeFactory`, T3.2 budget).
    - healthy → **adopt** (the upgrade effectively succeeded; mark
      `succeeded(reconciled)`; remove record).
    - unhealthy AND `prior` valid → **rollback to prior** (local-first, §4).
      Mark `failed(interrupted)`; the rollback is a fresh journaled op.
- **`running` ∩ `prior` ≠ ∅** (already on the prior — tag never advanced, or a
  prior partial rollback landed): **no-op**, mark `failed(interrupted)`.
- **`running` ∩ (`prior` ∪ `target`) = ∅** (indeterminate — running something
  else, or stack down) AND `prior` valid → **rollback to prior** (fail-safe:
  restore the last known-good). Stack-down is included here.
- **`prior` invalid** (`no_prior_digest` — e.g. locally-built image, T3.1):
  cannot safely roll back → **loud mark only** (`failed(interrupted,
  no_recovery_target)`), surface via `/v1/status` + audit. Never guess.

Every branch is **fail-safe**: when in doubt and a known-good prior exists,
restore it; when no safe target exists, stop loudly rather than act blindly.

---

## 4. Local-first rollback (T1.1)

The rollback `pull` must NOT unconditionally hit the registry — the fault that
crashed us is frequently the *same* network/disk fault that would make a
registry pull fail (or the prior may have been GC'd → unrecoverable). PR-E adds
(and the inline/standalone rollback paths reuse):

- `docker image inspect <prior_ref>` → if the prior digest is **local**, retag
  from the local store (`ComposeTagPinned`) and skip the pull.
- Only on local cache-miss, `ComposePullDigest(prior)` with a **small bounded
  retry + backoff**.
- This is the single change that makes recovery survive the outage that caused
  it. Shared via the existing `imageRollbackStages` core so manual and
  automatic rollback cannot diverge.

---

## 5. Cross-process single-instance guard (T1.5)

`systemd Restart=always` + tight `RestartSec` after a mid-reconcile crash can
start a **second** agent that races reconcile-against-reconcile (two
`docker tag`+`compose up` on the same project). The in-memory maintenance lock
does not span processes.

**Fix:** `flock(LOCK_EX|LOCK_NB)` on `<state_dir>/reconcile/.reconcile.lock`
(held for the whole Phase A+B window) BEFORE any reconcile work. A second
instance that cannot acquire it **refuses to reconcile** (and, per the existing
`Serve` reorder, does not serve operator ops until the holder finishes). Held
via an open FD for the reconcile duration; released on exit. Documented in the
operator runbook.

---

## 6. Atomicity & durability (T1.3 / T1.4)

- **Refuse-to-serve on corrupt** (already in `initJournal`): a
  present-but-unparseable `<op_id>.json` halts startup — extended so PR-E's
  reconcile treats an unreadable record as loud-stop, never a silent skip that
  strands the ungated tag.
- **Atomic terminal (Finish + Remove)** — fold journal removal into
  `Manager.Finish` under one lock so a crash between them can't resurrect a
  succeeded op (→ Phase A marks it interrupted → Phase B rolls back a healthy
  upgrade). fsync the reconcile parent dir after `Remove`.
- A reconcile that itself issues a rollback does so as a **fresh journaled op**
  (own record, own barrier), so a crash *during* reconcile is itself
  recoverable on the next boot (idempotent convergence).

---

## 7. Startup ordering (`main.go` / `server.Serve`)

```
config → journal open (fail-closed) → flock reconcile guard
  → Phase A: MarkAllInterrupted (already shipped)
  → Phase B: ReconcileOnStartup  ← NEW (this PR)
      for each interrupted upgrades.apply record (danger window):
        inspect tag + running → decide (§3) → act (§4) → finalize record
  → release nothing yet (guard held) → start HTTP listener → serve
  → guard released on shutdown
```

Read-only ops may serve after Phase B; the guard prevents a sibling process
from concurrently reconciling. `startDataPlane`/HTTP bind happen **after**
Phase B so no operator op races the reconcile.

---

## 8. Surfaces (GUI parity)

- `/v1/status` gains a `last_reconcile` block: `{ op_id, decision, from_digest,
  to_digest, outcome, at }` and any `no_recovery_target` / data-window
  detection so the CP/GUI shows what the agent did at boot without log-diving.
- Audit: one `reconcile` event per acted-on record (actor = `agent:reconcile`),
  with the decision + digests (parsed identifiers only, never raw JSON).
- No new operator *input* surface — reconcile is automatic and boot-scoped
  (documented GUI-parity deferral, like the HA fencing-lease status card).

---

## 9. Test plan (the acceptance gate)

- **T3 acceptance** (`FAILURE-INJECTION-TEST-PLAN.md`): SIGKILL mid-apply at
  each phase → next boot → op queryable `failed`/`succeeded(reconciled)` +
  Docker reconciled to a known-good digest, **no manual surgery**. Driven by
  the `applyRig` with a seeded journal record + a fake pre-set running/tag
  digest.
- Decision-table unit tests: every row of §3 (adopt-healthy, rollback-unhealthy,
  already-on-prior no-op, indeterminate→prior, prior-invalid→loud-mark).
- Local-first rollback: prior local → retag-no-pull; prior absent → bounded
  pull; registry-down → recovers from local cache (the T1.1 guarantee).
- Cross-process guard: second instance cannot acquire the flock → refuses to
  reconcile (no double `tag`+`up`).
- Corrupt record at reconcile → refuse-to-serve.
- Idempotent convergence: reconcile that crashes mid-rollback → next boot
  finishes it.

---

## 10. Rollout / risk posture

- **Blast radius:** boot-time only, host-local, one `docker tag`+`compose up`
  (or a bounded rollback) per interrupted op. Every decision is fail-safe
  (restore known-good) or fail-loud (stop). Nothing runs when the journal is
  empty (the common case) — zero overhead on a clean boot.
- **Kill switch:** a config flag (`reconcile_on_startup`, default **on**) to
  disable auto-reconcile and fall back to mark-only (loud, queryable) for
  operators who want manual control. Env + config parity.
- **Reversibility:** the reconciler only ever moves the stack to a digest the
  journal recorded (prior or target) — both were real, verified images. It
  cannot invent a target.

---

## 11. Proposed slicing (if approved)

1. **E1** — `ComposeImageInspectPinned` runner method + the pure decision
   function `reconcileDecision(rec, running, tag) → action` (no Docker side
   effects) + full decision-table unit tests. *Non-destructive; reviewable in
   isolation.*
2. **E2** — local-first rollback in the shared `imageRollbackStages` core
   (retag-from-local, bounded pull on miss) + tests. *Improves existing
   rollback; still destructive-adjacent but no boot hook yet.*
3. **E3** — the boot hook: `ReconcileOnStartup` wiring in `main`/`Serve`, the
   flock guard, atomic Finish+Remove, `/v1/status` surface, T3 acceptance.
   **This is the slice that first runs `docker` at boot — the one needing the
   final go/no-go.**

Sign-off can be staged: E1 (pure logic) is safe to build immediately on
approval; E3 is the gated one.
