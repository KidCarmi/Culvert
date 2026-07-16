# Maintenance-agent resilience hardening — "never crash / always recover"

**Status:** DESIGN — awaiting owner sign-off on scope + sequence
**Origin:** 6-angle adversarial break-review of `cmd/culvert-maint/` (2026-07)
**Goal:** enterprise-EDR-grade resilience — the privileged day-2 agent must never crash the
process, never strand the appliance, never leak/exhaust, and always self-heal an interrupted op.
**Supersedes/extends:** `roadmap/RISK-022-crash-recovery-journal-plan.md` (the journal is Tier 1
here, hardened by the attack findings).

## What held up (verified sound — no work needed)

- **Sudoers boundary matches the P1.4 claim exactly** — `docker pull`/`tag` bound to the rendered
  repo literal + 64 enumerated hex classes, no trailing wildcard, retag dest fixed; runner
  re-enforces `validatePinnedDigestRef`. No crafted request escapes it. **No auth-bypass, no
  escalation.**
- **No shell ever** (`exec.CommandContext` + closed template registry, `os.Environ()` not
  inherited). Body/JSON hardened (16 KiB `MaxBytesReader` + `DisallowUnknownFields`, typed
  structs — no request-controlled `interface{}` assertion). Path/op_id/backup-name validated
  (strict ULID, basename regex, `IsAllowedBackupPath`). Peer-auth `SO_PEERCRED` is not a TOCTOU.
- Per-command + op-level timeouts validated positive; command output bounded (1 MiB/stream);
  ps-scanner bounded; type assertions all comma-ok; slice indexing all length-guarded; FDs
  deferred-closed. The panic *surface* is small — the risk is the missing goroutine barrier, not
  a live reproducible input.

## Tier 0 — NEVER CRASH / NEVER CORRUPT (highest value, small, self-contained)

### T0.1 — Panic barrier in `ops.Run` + deferred `Finish` (unanimous: 3 of 6 agents)
`recover()` appears **zero times** in the whole binary. The orchestrator runs on a bare
goroutine (`handlers_d16b.go:221` → `ops.Run`, `orchestrator.go:101`); `net/http` recovers only
*synchronous* handler panics, so any stage/`resultFn` panic **terminates the entire daemon** —
every in-flight + future op dies. And `m.holder` is released only by `Manager.Finish`
(`ops.go:417`), so even a survived panic would strand the maintenance lock forever → permanent
409.
**Fix:** at the top of `ops.Run`, `defer` a recover that logs the panic+stack to the op-log,
emits a `failed` audit event, and calls `Manager.Finish(opID, StateFailed, "agent_panic", …)`.
The `Finish` MUST be in the deferred path (not the tail call) so it runs on *every* exit incl.
panic — converting "whole-daemon death + stuck lock" into "one failed op, lock released." **Do
not add recover without the deferred Finish** (that trades a crash for a permanent lock leak).

### T0.2 — Kill the real process tree, not the `sudo` wrapper (C-H3)
`privilege_mode=sudoers` runs `sudo -n docker …`; the runner sets no `SysProcAttr` and
`cmd.Cancel` signals `cmd.Process` only (`runner.go:458`) — i.e. the **`sudo` wrapper**. On stage
timeout the `docker`/`compose` child is reparented to init and **keeps running**, then the
orchestrator advances (or fires rollback) and the orphan's `compose up` **races the rollback on
the same project** → indeterminate/corrupted container state, flapping pinned tag.
**Fix:** `SysProcAttr{Setpgid:true}` and signal the process **group** on cancel/timeout (kill
`-pgid`), so a timeout actually terminates docker and cannot orphan a stack-mutating command.

## Tier 1 — RISK-022 crash-recovery journal, HARDENED by the attacks

The `RISK-022-...-plan.md` journal (durable per-op record + `MarkAllInterrupted` +
`ReconcileOnStartup`, fail-safe roll-back-to-prior) stands, with these **mandatory** upgrades the
break-review proved are required for it to actually work:

### T1.1 — Local-first rollback (strong consensus: A-U2, C-H2). **Promote from "open question" to committed.**
Reconcile + inline + standalone rollback all run `rollback_pull` = `ComposePullDigest(prior)`
**unconditionally from the registry** (`rollback_stages.go:76`). The prior image was running
seconds ago and is almost always still local — but a registry/network/disk fault (frequently the
*same* fault that triggered the restart/rollback) makes recovery **impossible**, and if the prior
was GC'd, **truly unrecoverable**.
**Fix:** in `tagAndUp`/rollback, `docker image inspect` the target digest and **retag from the
local store**, pulling only on cache-miss, with a small bounded retry+backoff. This is the single
change that makes recovery survive the outage that caused it.

### T1.2 — Ground reconcile in Docker truth, not just the journal phase (A-C1, A-C4, C-H1)
The reconcile decision keys only on `rec.Phase` + running-container digest; there is **no runner
method to read the `culvert/proxy:pinned` tag's current target**. One elided/failed parent-fsync
→ journal reads `pulled` while the tag already advanced → reconcile does nothing → the ungated
tag is adopted (the original bug, invisibly). Worse, the digest comparison is **scalar equality**
on a digest selected by `extractDigests` = **regex-sort every `sha256:` in `manifest inspect
--verbose` and take `[0]`** (`handlers_upgrade_apply.go:248`) — which grabs a config/layer/child
digest, not the manifest digest → failed pulls, **false-positive rollbacks of healthy multi-arch
upgrades**, and a hostile-registry digest-steering vector.
**Fix (two parts):**
- **Structural digest selection**: parse the manifest JSON, select the manifest/manifest-list
  digest; pin+verify against the **same digest class** the running `RepoDigests` reports.
- **Reconcile decision = tag-target + running-digest + phase**, compared by **digest-set
  intersection** (reuse `digestSetsIntersect`/`verifyRunningImage`), with a **bounded health-probe
  retry**. Add a `docker image inspect culvert/proxy:pinned` runner method. Closes C1 (tag moved
  without durable phase becomes visible), C4/H1 (multi-arch list-vs-platform stops causing false
  rollbacks), D2 (probe flake).

### T1.3 — Fail-closed journal writes + refuse-to-serve on corrupt (D-#1, D-#2)
The `PhaseRestarting` write-ahead fsync must be a **hard error that aborts the op before
`ComposeTagPinned`** (never `_ =`) — else a full disk (the very condition the journal exists to
survive) silently skips the barrier and reopens the danger window. And the reconciler must treat
a present-but-unparseable `<op_id>.json` as **loud, refuse-to-serve** (not a silent skip that
strands the ungated tag). Add ENOSPC + corrupt-record injection tests (T3 variants).

### T1.4 — Atomic terminal (Finish + Remove) + parent-dir fsync (A-C2, D-#3)
`Finish` and `journal.Remove` are two steps; a crash between them **resurrects a succeeded op** →
Phase A marks it `failed(interrupted)` → Phase B can **roll back a completed, healthy upgrade**.
Fold removal into `Finish` under one lock (tombstone/remove-then-ack), and `fsync` the parent dir
after `Remove` (and after `audit.jsonl` creation) so the unlink/create is durable.

### T1.5 — Cross-process single-instance guard (A-C3)
The maintenance lock is per-process in-memory. `systemd Restart=always` with a tight `RestartSec`
after a mid-reconcile crash starts a second agent that **races reconcile-against-reconcile** —
two `docker tag`+`compose up` on the same project. The `Serve` reorder stops only *operator* ops.
**Fix:** `flock` on `<state_dir>/reconcile/` (or systemd `Type=notify` single-instance) before
Phase A/B; document it.

### T1.6 — Data-rollback `/data`-swap window: loud auto-detection (A-U1, A-D1)
`mode=data` restore killed between the two `/data` renames (`restore.go:878`) leaves `/data`
absent + stack down; the proxy's `checkInterruptedRestore` (`restore.go:932`) fail-closed refuses
to boot (RISK-005) → **appliance down until a human runs `mv`**. The journal deliberately drives
no data reconcile — but it should at least **reuse `discoverLeftovers`/`checkInterruptedRestore`
for loud, actionable auto-detection** (surface the exact recovery command via `/v1/status` +
audit) instead of a bare mark-only.

## Tier 2 — Resource exhaustion / DoS (bound everything; long-lived daemon must stay flat)

- **T2.1 — Bound `Manager.active`** (B-#3, F-#2, E-#2): terminal ops are **never evicted**
  (`Finish` only flips state); the map grows for the process lifetime. Reap terminal ops on a
  TTL/keep-last-N grace window (mirror the existing `purgeIdempCacheLocked`). Also deep-copy
  nested `Params`/`Result` in `cloneLocked` (B-#4).
- **T2.2 — Enforce `LogRetentionDays` + rotate audit + tail-bound reads** (D-#5/#7, F-#3, E-#2):
  the config knob is parsed but **enforced nowhere**; `operations/*.log` accumulate forever;
  `audit.jsonl` has no rotation; `audit.Recent` does `io.ReadAll` of the whole file per
  `/v1/audit`. Add a startup+periodic sweep, rotate audit (reuse the root `fileutil` size-cap
  pattern), and seek-from-EOF for `Recent`. (These also disarm the ENOSPC that arms T1.3.)
- **T2.3 — Admission control** (E-#3): read-only kinds (`upgrades.check`) don't take the lock and
  admit unboundedly → a flood spawns unbounded **root** `docker` subprocesses. Add a bounded
  worker semaphore covering read-only ops + a `netutil.LimitListener` on the UDS.
- **T2.4 — SIGTERM drain** (B-#2): orchestrator ctx is `context.Background()`, detached from
  shutdown, with no `WaitGroup`. SIGTERM mid-`restore.commit` exits the process with the stack
  **down** and the op abandoned. Add a `WaitGroup` + shutdown-linked parent ctx and drain
  in-flight state-changing ops (bounded) before exit.

## Tier 3 — Robustness edges

- **T3.1 — Empty/ambiguous `RepoDigests` disables rollback** (C-M5): a **locally-built** proxy
  image has empty `RepoDigests` → `deriveRollbackTarget` returns `no_prior_digest` → a broken
  upgrade is left in place with no auto-rollback. Add a fallback (image ID / `docker inspect` of
  the running container) so rollback still has a target.
- **T3.2 — Configurable, larger health budget** (C-M4): hardcoded 30s black-box `/ready` probe
  spuriously rolls back slow-but-healthy cold starts (GeoIP/policy/CA warm-up). Make it operator-
  configurable with a larger default; correlate the probe with the running digest where possible.
- **T3.3 — Perms repair + fail-closed audit for state-changing ops** (D-#4, D-#8): `chmod`-repair
  `state_dir`(0750)/`audit.jsonl`(0640)/`*.log`(0640) on startup even when pre-existing; promote
  a failed *durable* audit write for a **state-changing** op from a swallowed warning to an
  admission-time failure (no destructive op runs without a durable record). Fix op-log capture
  buffer aliasing (F-#4). fsync the op-log at stage boundaries so post-crash forensics survive.

## Proposed sequencing (small, reviewable PRs)

1. **PR-A (Tier 0) — never-crash core. ✅ SHIPPED.** T0.1 panic barrier in `ops.Run` (recover →
   `ReasonAgentPanic` → deferred `Finish` releases the lock); T0.2 process-group kill
   (`Setpgid` + group SIGTERM/SIGKILL, platform-gated `procgroup_{linux,other}.go`) so a wedged
   `docker` child can't be orphaned to race a rollback. Tests: stage/`resultFn` panic contained +
   op failed + lock released; group kill reaps a grandchild. Small, self-contained, no journal
   dependency.
2. **PR-B..PR-B4 (Tier 2 bounds) — stop the leaks.** Split into focused, independently-reviewable
   slices (all independent of the journal; disarm the disk-full the journal must survive):
   - **PR-B (T2.1) — ✅ SHIPPED.** Bound `Manager.active`: opportunistic reap of terminal ops on
     admission (retention TTL + hard-cap oldest-first eviction; running ops never reaped) +
     deep-copy nested `Params`/`Result` in `cloneLocked`.
   - **PR-B2 (T2.4) — ✅ SHIPPED.** SIGTERM drain: orchestrator goroutines are tracked via a
     `sync.WaitGroup` (`Server.goOp`); on shutdown `Serve` waits for them within a bounded
     `OpDrainTimeout` (default 30s) before returning, so an in-flight state-changing op is drained
     (or reaches a safe point) rather than abandoned with the stack half-mutated. State-changing
     ops are NOT cancelled mid-flight (that is the corruption risk) — the drain waits.
   - **PR-B3 (T2.2a) — ✅ SHIPPED.** Tail-bounded `audit.Recent` (seek-from-EOF backward block
     read; O(n events) not O(file size), so `/v1/audit` can't OOM on an unbounded log) +
     `LogRetentionDays` enforcement (startup + daily sweep of `operations/*.log` via
     `ops.SweepOpLogs`; running-op logs are too fresh to sweep).
   - **PR-B3b (T2.2b)** — audit.jsonl size-based rotation (deferred: the riskier piece; the
     tail-read already removes the OOM-on-read, so rotation is disk-bound-only and separable).
   - **PR-B4 (T2.3) — ✅ SHIPPED (semaphore half).** Admission control: a bounded semaphore caps
     concurrently-executing READ-ONLY ops (`DefaultMaxConcurrentReadOnlyOps` = 8) with **429**
     backpressure at capacity, so a flood can't spawn unbounded root docker subprocesses;
     state-changing ops bypass it (the maintenance lock already caps them at one). The slot is
     acquired at admission and released when the op flow finishes (or on any early-return path).
     UDS `LimitListener` (connection-count bound) is a small follow-up.
3. **PR-C (Tier 1 infra) — journal package + structural digest.** The `internal/journal` package
   (fail-closed writer, corrupt-record refuse-to-serve) + T1.2 structural digest selection +
   the `image inspect` tag-target runner method. No behavior change beyond digest-selection fix.
4. **PR-D (Tier 1 write+mark) — wire journal + MarkAllInterrupted.** Journal write points
   (incl. the fail-closed barrier), atomic Finish+Remove, mark orphans queryable.
5. **PR-E (Tier 1 reconcile) — ReconcileOnStartup.** Docker-truth decision (digest-set
   intersection + bounded health retry), local-first rollback (T1.1), cross-process guard (T1.5),
   startup reorder. **Closes the T3 acceptance test.**
6. **PR-F (Tier 1/3 edges) — data-window detection + robustness.** T1.6 loud data-rollback
   detection, T3.1 rollback-target fallback, T3.2 health budget, T3.3 perms/audit/forensics.

## Acceptance

- `FAILURE-INJECTION-TEST-PLAN.md` T3 (SIGKILL mid-apply → queryable failed + Docker reconciled to
  a known-good digest, no manual surgery) — closed by PR-E.
- New injection tests: stage-panic → agent survives + op failed + lock released (PR-A); orphaned
  docker on timeout killed (PR-A); ENOSPC on barrier aborts before tag-advance (PR-C/D); corrupt
  journal record → refuse-to-serve (PR-C); registry-down reconcile recovers from local cache
  (PR-E); op-flood stays memory/disk-flat (PR-B).

## Open decisions for the owner

1. **Scope**: all six PRs (full Cortex-XDR-grade), or Tier 0 + Tier 1 first and Tier 2/3 as a
   follow-up program?
2. **`sudo` process-group kill (T0.2)**: `Setpgid`+group-signal within the sudoers model, or is
   this the moment to move to the socket-activated/setuid helper the design has contemplated?
   (The former is smaller and unblocks now; the latter is the deeper fix.)
3. **Health budget default (T3.2)**: what cold-start ceiling should the default assume for a
   loaded appliance (GeoIP + large policy/category DB + CA warm-up)?
