# RISK-022 — Maintenance-agent crash-recovery op journal (design + plan)

**Status:** DESIGN — awaiting owner sign-off before implementation
**Risk:** RISK-022 (HIGH, OPEN) — `docs/engineering/TECHNICAL-RISK-REGISTER.md:346`
**Acceptance test:** `roadmap/FAILURE-INJECTION-TEST-PLAN.md` T3

## 1. Problem

The maintenance agent holds operation state **only in memory** (`ops.Manager.active`,
`cmd/culvert-maint/internal/ops/ops.go:206`). `MarkAllInterrupted()` (`ops.go:468`) is a
literal `return 0`, called at startup (`main.go:130`). On restart `Manager.active` starts
**empty**, so "mark all interrupted" over the in-memory map is a no-op by construction —
**there is no cross-restart record of an in-flight op.**

The danger window is inside `tagAndUp` (`internal/server/rollback_stages.go:45`), shared by
`upgrades.apply`'s `restart` stage and `rollbacks.create` (mode=image): it advances the fixed
tag `culvert/proxy:pinned` to the new digest (`ComposeTagPinned`, line 46) and then runs
`compose up -d` (`ComposeUp`, line 55). A process kill (crash, host reboot, OOM) between the
tag-advance and a passing health gate leaves Docker indeterminate — the fixed tag may point at
an **ungated** new digest that any later `up` silently adopts — with **no reconciliation and no
automatic rollback** on the next agent start, and the op is not queryable.

## 2. Two structural facts that shape the design

**Fact 1 — `cmd/culvert-maint` is its own Go module** (`module culvert-maint`; root is
`github.com/KidCarmi/Culvert`; no `go.work`). The root's `internal/fileutil.AtomicWrite` is
**not importable** here. The journal ships its own stdlib-only atomic writer (write temp →
chmod → `fsync(file)` → rename → `fsync(parent)`), mirroring the audit logger's existing fsync
discipline (`internal/audit/audit.go:111`).

**Fact 2 — `MarkAllInterrupted` lives on `ops.Manager`, which has no Docker/health access, and
is called too early** (`main.go:130`, before `newRunner` at `:132` and the `Server` at `:142`).
`ops.Manager` is deliberately docker-free. So the fix splits into two layers and the startup
sequence is reordered:
- **Phase A (ops layer)** — mark orphaned journal ops `failed(agent_restart_interrupted)` so
  `GET /v1/operations/{id}` answers post-restart (no Docker needed).
- **Phase B (server layer)** — reconcile Docker (running digest vs journal) using the `Runner`
  + health probe, resuming-safe or rolling back. Runs **before `srv.Serve`** so no operator op
  can race the reconcile.

## 3. Phase / crash-window table — `upgrades.apply`

Stages from `buildUpgradeApplyStages` (`handlers_upgrade_apply.go:202`). "Prior" = rollback
digest; "Target" = pinned new digest.

| # | Stage | Re-runnable? | Docker state on crash-after | Prior? | Target? |
|---|---|---|---|---|---|
| 1 | `capture_before` | yes (read-only) | untouched, proxy on prior | **set here** | — |
| 2 | `resolve_target` | yes (registry inspect) | untouched | yes | **set here** |
| 3 | `pre_backup` | yes (redo harmless) | untouched; possibly-partial backup (restore validates) | yes | yes |
| 4 | `pull` | **yes** (digest-pinned) | new image in local store, **tag NOT advanced → proxy still on prior. SAFE** | yes | yes |
| 5 | **`restart` → `tagAndUp`** | indeterminate | **DANGER WINDOW.** tag advanced to new digest; `up` half-done; health never gated | yes | yes |
| 6 | `health_gate` | yes (read-only) | proxy on new image, health unverified | yes | yes |
| 7 | `verify` | yes (read-only) | effectively complete, op not terminal | yes | yes |
| 8 | `recovery:rollback_*` | see rollback core | only on post-restart failure | yes | yes |
| 9 | `report` | yes | complete | yes | yes |

**The RISK-022 window is stages 5–6.** Everything ≤ 4 is safe (fixed tag unmoved).

**`rollbacks.create` (mode=image)** has the identical gap — `buildImageRollbackStages`
(`handlers_rollback.go:123`) calls the same `tagAndUp`. In scope.

**`rollbacks.create` (mode=data)** is the D1.3b.2b operator-driven contract, explicitly
non-resumable (§5.4). The journal **records** it interrupted and marks it
`failed(agent_restart_interrupted)`, but drives **no** automatic data reconcile.

## 4. Journal schema

New package `cmd/culvert-maint/internal/journal` (stdlib-only; owns the atomic writer, so `ops`
stays docker-free and the module boundary holds). **One file per live op** at
`<state_dir>/reconcile/<op_id>.json` (mode 0640, parent 0750) — self-contained atomic writes,
no read-modify-write race.

```go
type Record struct {
    OpID         string
    Kind         string    // "upgrades.apply" | "rollbacks.create"
    Mode         string    // "" | "image" | "data"
    Phase        Phase
    TargetRef    string    // repo@sha256:<digest> we move TO
    TargetDigest string
    PriorRef     string    // repo@sha256:<digest> rollback target (may be "")
    PriorDigest  string
    Actor        string
    StartedAt    time.Time
    UpdatedAt    time.Time
}

type Phase string
const (
    PhaseAdmitted   Phase = "admitted"   // begun, nothing mutated
    PhaseCaptured   Phase = "captured"   // prior digest known
    PhaseResolved   Phase = "resolved"   // target digest known
    PhasePulled     Phase = "pulled"     // new image local; tag NOT advanced (SAFE boundary)
    PhaseRestarting Phase = "restarting" // WRITE-AHEAD: fsync'd immediately BEFORE tagAndUp's tag
    PhaseRestarted  Phase = "restarted"  // up returned; tag advanced, health not gated
    PhaseVerified   Phase = "verified"   // health+verify passed; success imminent
)
```

**Write points (each = atomic write + fsync):**
- Create `PhaseAdmitted` at admission in `startAsyncOp` (`handlers_d16b.go:178`), gated to the
  two journaled kinds — durable the instant the op holds the lock.
- `PhaseCaptured` + prior at end of `capture_before`; `PhaseResolved` + target at end of
  `resolve_target`; `PhasePulled` at end of `pull` (the safe boundary).
- **`PhaseRestarting` — the write-ahead barrier — fsync'd inside `tagAndUp` immediately before
  `ComposeTagPinned` (`rollback_stages.go:46`).** The one write that must be durable before the
  mutation. Because `tagAndUp` is the shared choke point (apply, inline rollback, standalone
  rollback, AND the reconciler's own rollback), the reconcile rollback is crash-journaled for
  free.
- `PhaseRestarted` right after `ComposeUp` returns (any error = indeterminate).
- `PhaseVerified` at end of `verify` / `rollback_verify`.
- **Remove at terminal** via a `Journal` handle on `OrchestratorDeps` (`orchestrator.go:61`),
  removed where the orchestrator calls `Manager.Finish` (`orchestrator.go:253`) — so every
  terminal path (success/failure/timeout/panic-defer) retires the record exactly once.

The phase is the source of truth for *whether this op entered the mutating window*; the live
running-digest query is the source of truth for *what is running*. Together they let reconcile
treat `pulled` (and earlier) as a pure no-op without touching the daemon.

## 5. Reconciliation algorithm

**Phase A — `ops.Manager.MarkAllInterrupted(j)`** reads every live record and registers the op
into `active` as `failed`, `failure_reason=agent_restart_interrupted`, `finished_at=startup`;
returns the count. (No Docker.) This alone makes the op queryable — the first half of T3.

**Phase B — `Server.ReconcileOnStartup(ctx)`**, per live record:

```
switch rec.Phase {
case admitted, captured, resolved, pulled:
    // Tag never advanced. No Docker action. journal.Remove; continue.

case restarting, restarted, verified:
    ri := Runner.CaptureRunningProxyImage(ctx)         // capture_running.go:88
    if running == rec.TargetDigest && healthProbe().Run(ctx) OK:
        // Forward completed AND healthy. Idempotent no-op.
        // Do NOT roll back a healthy image; do NOT claim success (never-guess).
        // Leave op failed(agent_restart_interrupted) + reconcile note. journal.Remove; continue.

    // Every other case (target-but-unhealthy / prior / indeterminate / capture failed):
    if rec.PriorRef == "":
        // Cannot auto-recover. Loud audit + WARN. Leave failed. journal.Remove; continue.
    stages := s.buildImageRollbackStages(rec.PriorRef)  // REUSE — handlers_rollback.go:123
    run synchronously under a fresh reconcile op + lock + oplog + audit
    mark failed(agent_restart_interrupted) if rollback verified, else failed(rollback_failed)
    journal.Remove; continue.
}
// Mode=="data": Phase A already marked it; never reconcile Docker. journal.Remove.
```

The reconcile rollback **reuses `buildImageRollbackStages` verbatim** (pull→restart→health→
verify pinned to `rec.PriorRef`) — exactly "roll back to a prior digest + health-check," no new
runner template / sudoers line / logic fork (same anti-drift the inline path relies on,
`inline_rollback.go:71`).

**Startup reorder (`main.go`):** build runner + status + server, run Phase A + Phase B
**before `srv.Serve`** (`main.go:169`). The socket isn't listening until the stack is in a known
state — the correct posture; no operator op can race reconcile.

## 6. Decision: roll-back-to-prior is the fail-safe default

The **only** non-rollback outcome is the positively-verified "running == target **and** health
passes" idempotent no-op. Every ambiguous/unhealthy state drives to the prior digest and
health-gates it. Matches §5.4's "never guess": the reconciler never marks an op `succeeded` —
even the healthy no-op leaves it `failed(agent_restart_interrupted)`, because the post-restart
`verify`/`report` provably did not run, so the CP/operator must re-drive. This upgrades the
currently-documented "restart mid-rollback → failed, no auto-resume"
(`D1.6c-inline-auto-rollback-plan.md:342`) from *no action* to *drive to a known-good prior +
health-gate* — strictly safer.

## 7. PR slicing

- **PR1 — journal package (infra only).** `internal/journal`: `Record`, `Phase`, stdlib atomic
  writer, `Write/Read/List/Remove`, strict-ULID path validation (mirror `OpenOpLog`,
  `oplog.go:68`). Unit tests incl. torn-write / crash-mid-write. No wiring, no behavior change.
- **PR2 — write journal + mark-interrupted.** Thread the journal through `startAsyncOp`
  (admission), the apply/rollback stage builders (phase updates), and `tagAndUp` (the
  write-ahead). Add `Journal` to `OrchestratorDeps` + remove-on-terminal. Rewrite
  `MarkAllInterrupted` to read the journal and mark orphans; return the count; update
  `ops_test.go`. **T3's "returns 1 / queryable" half passes here.**
- **PR3 — the Docker reconciler.** `Server.ReconcileOnStartup`, the running-digest-vs-journal
  decision, the `buildImageRollbackStages` reuse, a reconcile audit sub-action, and the
  `main.go` startup reorder. **Closes T3.**
- **PR4 — edges, audit, docs.** Data-rollback mark-only path, `no_prior_digest` loud-surface,
  a `recovered`/reconcile audit event + `/v1/status` surfacing, and doc updates (§5.4 + RISK-022
  register close-out).

## 8. Open questions / risks

1. **Prior digest gone from the registry.** `ComposePullDigest` always pulls from the registry;
   if it's unreachable at restart, the reconcile rollback's `rollback_pull` fails →
   `rollback_failed` → page, even though the prior image is very likely still in the local store
   (it was running moments ago). **Proposed enhancement:** a "retag-local-if-present, pull only
   on cache-miss" fast path in `tagAndUp`/reconcile, making reconcile robust to registry
   outages (the most common real restart condition). **Scope decision needed — see below.**
2. **Health-gate flakiness → unnecessary rollback.** The healthy-at-target no-op gates on one
   probe; a transient failure would demote a good forward-completed upgrade into a rollback.
   Mitigation: a bounded retry on the reconcile health probe. Conservative default still errs
   safe.
3. **Concurrent agents.** Two overlapping processes (aggressive systemd restart) could both
   reconcile. Mitigation: `flock` on `<state_dir>/reconcile/` or systemd single-instance
   (`Type=notify`); document it.
4. **`restarting` written but tag never advanced** (crash between fsync and `docker tag`):
   running==prior & healthy → reconcile re-pins prior = idempotent, mildly wasteful. Acceptable.
5. **CP ergonomics.** Even a healthy reconciled stack leaves the op `failed`, so the reconcile
   result/audit must carry enough (`reconcile_action=none|rolled_back|rollback_failed`,
   `final_running_digest`) for the CP to distinguish "service OK, re-verify" from "paged." Model
   on `upgradeApplyResult` (`inline_rollback.go:203`).

## 9. Acceptance

`FAILURE-INJECTION-TEST-PLAN.md` T3 — SIGKILL the agent mid-apply (in the `restart` window),
restart, assert: (a) the interrupted op is queryable as `failed(agent_restart_interrupted)`;
(b) Docker is reconciled to a known-good digest (prior, health-gated) — not left on an ungated
tag; (c) no manual `docker` surgery required.
