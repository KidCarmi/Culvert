# RISK-022 PR-E — `ReconcileOnStartup` design record

**Status:** DESIGN — awaiting owner sign-off before any executable code (this
slice runs `docker` at boot; it is the one destructive slice of the RISK-022
program).
**Authority:** `roadmap/MAINTENANCE-AGENT-RESILIENCE-HARDENING.md` (Tier 1,
T1.1–T1.6) and `roadmap/RISK-022-crash-recovery-journal-plan.md`.
**Consumes:** the durable journal (PR-C #748), the lifecycle wiring +
`MarkAllInterrupted` (PR-D #750), the phase progression + `PhaseRestarting`
write-ahead barrier (PR-D2 #754), and the structural digest selection (#751).

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
