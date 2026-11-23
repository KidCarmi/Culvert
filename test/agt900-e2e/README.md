# AGT-900 real-Docker e2e

This is the evidence for contract **AGT-900** (`contracts/registry.yaml`): the
maintenance agent's opt-in startup reconcile, `reconcile_on_startup =
"converge"`, run against a **real Docker daemon**. It covers:

- every kill point of the fake-Docker suites
  (`cmd/culvert-maint/startup_crash_recovery_test.go` and
  `startup_reconcile_converge_test.go`);
- kills inside the reconcile itself;
- repeated restarts on one record;
- the durable journal and audit log, read directly after every kill and every
  restart;
- three mutants as negative controls.

Every case is checked against the AGT-900 / AGT-004 / AGT-005 transitions on
real Docker state.

It is a manual evidence run. It is **not** a PR gate, and it changes neither the
status of AGT-900 nor the default of `reconcile_on_startup`. The owner decides
both.

## Running

```bash
sudo test/agt900-e2e/run.sh                      # both image stores (about 20 min)
sudo test/agt900-e2e/run.sh --store classic      # one store
sudo test/agt900-e2e/run.sh --cases '^repeat_'   # a subset (Go regexp on case names)
sudo test/agt900-e2e/run.sh --negative-control   # the three mutants (about 6 min)
```

Options and environment:

- `--keep` keeps the work dir (`/tmp/agt900.*`), which holds the per-process
  agent logs and docker call logs.
- `AGT900_REGISTRY_BIN` points to a prebuilt `distribution/v3` registry and
  skips the `go install`.
- `AGT900_REGISTRY_PORT` (default 5443) and `AGT900_PROXY_PORT` (default 18480)
  move the ports.

There are four verdicts:

| Verdict | Meaning |
|---|---|
| **PASS** | Every check held. |
| **FAIL** | A contract check failed. |
| **ERROR** | The harness could not evaluate the case (a setup, crash or mutate step failed, a polled kill missed its window, or nothing was checked), and no contract check failed. It fails a normal run, and with `--negative-control` it never counts as catching a mutant, so an infrastructure failure cannot certify a negative control. |
| **GAP** | Every contract check held, but an owner-requested property that is stricter than the AGT-900 contract was violated. GAP is reported and never folded into PASS. |

Exit codes:

| Exit | Meaning |
|---|---|
| 0 | All rows PASS. With `--negative-control`: every mutant was caught by a failed contract check (FAIL), never by an ERROR. |
| 1 | At least one FAIL or ERROR. |
| 3 | No FAIL or ERROR, but at least one GAP. |
| 2 | Incomplete: a prerequisite or setup failed, or the harness produced no rows. |

**Prerequisites:** root, Go, the Docker engine binaries (`dockerd`,
`containerd`, `runc`, and the `docker` CLI with the compose plugin), `openssl`,
`curl`, `chattr` and `python3`. The run needs no Docker Hub and no outbound
network, apart from the `go install` of the registry when
`AGT900_REGISTRY_BIN` is unset. Keep `GOMAXPROCS=2` (the script's default) on
small machines.

## What it builds

- **A TLS registry**, built from source (`distribution` v3.0.0).
  - It needs TLS because the agent's `docker manifest inspect` has no
    `--insecure` flag.
  - The daemon accepts the certificate because `localhost` is an implicit
    insecure registry.
  - The CLI trusts it through `SSL_CERT_FILE`, which the shim sets.
- **Three FROM-scratch images** of `fakeproxy/main.go`, which serves only
  `/health` and `/ready`:
  - `prior`: the image that runs before the upgrade;
  - `good`: a target that passes the health gate;
  - `bad`: a target whose `/ready` always answers 503, so the gate fails and the
    inline rollback runs.

  All three are pushed, then pulled back by digest, the way a customer host
  gets them.
- **A private `dockerd` per image store**, each with its own data-root,
  exec-root, socket and managed containerd:
  - `--feature containerd-snapshotter=true` for the containerd store (the
    Docker 29 default);
  - `=false` for the classic overlay2 store.

  The host's daemon, its images and its `culvert/proxy:pinned` tag are never
  touched. The "Docker unavailable" cases stop a real daemon.
- **A compose project** (`docker-compose.yml`) that mirrors the proxy service of
  `test/e2e/maint-agent/docker-compose.e2e.yml`. It has:
  - the fixed `culvert/proxy:pinned` tag and a fixed container name;
  - `restart: unless-stopped`;
  - the loopback-published port, a `/data` volume and a healthcheck;
  - one test-only bind mount, `./ctl:/ctl`, so the harness can stall `/ready`.
- **The real agent binary**, built from `cmd/culvert-maint`. It runs as root
  with `privilege_mode = "docker_group_lab"`, a real config and a real
  `state_dir`, and is killed with real SIGKILLs and really restarted.

The Go harness is `cmd/culvert-maint/agt900_realdocker_e2e_test.go`, behind the
build tag `agt900_e2e`, so a plain `go build`, `go vet` or `go test` never
compiles it.

### How the kills land

The kills are deterministic. The first `docker` on the agent's `PATH` is a
**pass-through shim** that execs the real CLI. It logs every argv and can hold
one call at a named point:

- `<cmd>_before:<n>` holds before the real command runs;
- `<cmd>_after:<n>` holds after the real command completed, before the agent
  sees it return.

`<cmd>` is the compose subcommand, or else the docker subcommand. `n` counts per
agent process. While the agent is held, the harness either SIGKILLs it or
releases the call. Nothing in Docker is simulated.

Three kills have no Docker call to hold on to:

- **Inside a health probe:** the harness holds `up_after:<n>`, creates
  `/ctl/hang_ready` and releases the hold. The SIGKILL lands when the probe
  reaches `/ready`.
- **Between `verified` and retirement:** the harness polls the journal record
  and SIGKILLs on `"phase": "verified"`.
- **Between the reconcile's audit write and its record removal:** the harness
  polls `audit.jsonl` and SIGKILLs when the record's `:reconciled` entry
  appears.

A polled kill that lands after the record is gone is retried from scratch, up
to 6 times, and the row says so. In the recorded runs every polled kill landed
on the first try.

The reconcile issues its Docker calls in this order, counted per process:

| Step | Calls |
|---|---|
| Wait for Docker | `ps:1` |
| Facts | `ps:2` |
| TOCTOU re-read after the write-ahead attempt record | `ps:3` |
| Action | `tag:1` or `up:1` |
| Verify | `ps:4` |

Each read is `compose ps`, then `inspect`, then 1 or 4 `image inspect` calls,
so `image:13` is the last read of the verify.

## What is checked

**The fake-Docker suite's expectation for the same kill point**, for every
converge restart:

- the decision and reason;
- the restart's exact state-changing Docker commands;
- the tag and the container afterwards;
- whether the record was retired, and its outcome;
- the `reconcile.startup` op state;
- `status.recovery_required`.

**The AGT-900 invariants on real Docker state.** These are independent of the
table above. "Real Docker state" means `docker inspect` of the compose
container, the id that `culvert/proxy:pinned` resolves to, and `/ready`.

| Id | Invariant |
|---|---|
| I1 | The only Docker changes are a tag to the recorded prior ref, and `up` while the tag is already on prior. Never `pull`, `down`, or a tag to a target. |
| I2 | A Docker-converged record (`converged` or `converged_not_retired`) leaves the tag and the container on the same image, running and ready. That image is the prior image, or an `adopt` of a target whose journal said `verified` before the restart. |
| I3 | Anything else leaves Docker unchanged: the same container id, image, state and tag. |
| I4 | No ungated image is **started** by the reconcile. If a target runs afterwards, the reconcile ran no `up` and the container is the one that was there before. |
| I5 | A failed-gate image is never accepted as converged. |
| I6 | The interrupted op stays `failed(agent_restart_interrupted)`. |
| I7 | A record is retired iff the outcome is `converged`, and never without at least one `:reconciled` audit entry (AGT-005). |
| AGT-004 | No `pull` at startup. |

**Journal and audit consistency (J).** After every kill and every restart, the
harness reads `<state_dir>/reconcile/` and `audit.jsonl` directly, not through
the agent:

- every record file parses and names its own op;
- nothing else is in the directory except `.lock` and the journal's own
  `.journal-*.tmp` files, which are counted and are never parsed as records;
- `phase`, `reconcile_attempts` and `interrupted_seen` never go backwards;
- attempts stay at or below the cap of 2;
- a retired record never reappears;
- `prior_image_id` and `target_image_id` are the real local ids for this store;
- `rollback_armed` appears only at `restarting` or later;
- a record at a safe phase (`admitted` to `pulled`) has the tag and the
  container on the prior image (the write-ahead barrier);
- every audit line parses;
- a retired record has a `:reconciled` audit entry.

**Owner-requested properties (reported as GAP when violated):**

- **OWNER-ungated:** no image that has not passed its health gate is left
  running after the reconcile. The contract only forbids *starting* one (I4).
- **OWNER-audit:** exactly one `:reconciled` audit entry per retirement, and
  none for a kept record. The contract (AGT-005) only requires audit-first.

## Recorded results: 2026-11-23

**Environment:**
- Docker Engine 29.10.0 (containerd v2.4.2, runc 1.5.3), Compose v5.7.1, on
  Linux 6.18 x86_64.
- Agent source: `agt900-converge-startup` at `dbbf38f04`. Production code is
  unchanged; the run was made from the harness commit on top of it.
- **Both image stores** were run, in one invocation.

| Store | Daemon reports | Container `.Image` / image `.Id` |
|---|---|---|
| containerd | `overlayfs`, `driver-type io.containerd.snapshotter.v1` | the registry (index) digest |
| classic | `overlay2` | the image config digest, distinct from the registry digest |

**Totals (identical in both stores):** 37 cases per store, 74 rows in all.

| Verdict | Rows |
|---|---|
| PASS | 58 |
| FAIL | 0 |
| GAP | 16 (8 cases × 2 stores) |

Per store, 807 checks passed and 12 owner checks reported GAP. The containerd
run took 533 s and the classic run 502 s. `run.sh` exited 3, meaning no FAIL
but GAPs.

### Kill points of the fake-Docker suites, plus extra converge cases

| Case (kill point) | Result in both stores | Verdict |
|---|---|---|
| control_good_upgrade (no kill) | op succeeded, tag=good run=good, journal empty | PASS |
| control_bad_upgrade_rolls_back (no kill) | op failed(health_failed), rollback_succeeded, tag=prior run=prior, journal empty | PASS |
| admitted_at_capture (`ps_before:1`) | noop/safe_boundary_unchanged, no change, retired | PASS |
| captured_at_resolve (`manifest_before:1`) | noop/safe_boundary_unchanged, retired | PASS |
| resolved_at_pull (`pull_before:1`) | noop/safe_boundary_unchanged, retired | PASS |
| barrier_before_tag (`tag_before:1`) | noop/already_on_prior, retired | PASS |
| tag_moved_before_up (`up_before:1`) | realign, `[tag:prior]`, tag=prior run=prior, retired | PASS |
| up_done_unrecorded (`up_after:1`) | recovery_required/target_live_ungated, Docker unchanged (good runs), kept | GAP: OWNER-ungated |
| restarted_at_health_gate (in the gate's `/ready`) | same as above | GAP: OWNER-ungated |
| restarted_at_verify (`ps_before:3`) | same as above | GAP: OWNER-ungated |
| verified_adopt (polled kill at journal `verified`) | adopt/verified_target_live, no change, retired | PASS |
| verified_target_not_ready_now (same, with `/ready` stalled) | recovery_required/verified_target_not_ready, no change, kept | PASS |
| rb_armed_before_tag (bad, `tag_before:2`) | recovery_required/rollback_armed_target_live, Docker unchanged: **bad runs under the tag** | GAP: OWNER-ungated |
| rb_tag_moved_before_up (`up_before:2`) | finish_rollback, `[up]`, tag=prior run=prior ready, retired | PASS |
| rb_up_done (`up_after:2`) | noop/already_on_prior, retired | PASS |
| rb_in_rollback_health (in the rollback gate's `/ready`) | noop/already_on_prior, retired | PASS |
| rb_at_rollback_verify (`ps_before:3`) | noop/already_on_prior, retired | PASS |
| operator_retag_unarmed (`up_after:1`, then an operator tags prior) | recovery_required/tag_on_prior_rollback_unproven, no change (good runs, tag prior), kept | GAP: OWNER-ungated |
| forged_prior_ref (`up_before:1`, then `prior_ref` is rewritten) | recovery_required/invalid_record_ref, no change; the forged ref never reaches Docker argv | PASS |
| docker_unavailable_defers (dockerd **stopped**) | deferred, no Docker command, no attempt counted, record kept. After dockerd restarts: Docker as before. Next start: realign, retired | PASS |
| second_instance_skips (two agents on one `state_dir`) | instance 2: `skipped_second_instance`, no Docker command, Docker unchanged, record kept. After both are SIGKILLed: the next start takes the lock and realigns | PASS |
| off_mode_tag_ahead / off_mode_target_live (`off`) | no Docker command, no `reconcile` in status, op failed(agent_restart_interrupted), listed, record kept, no lock file | PASS |

### Item 1: crash during recovery, at each reconcile step

In each case below, the upgrade was first crashed at the point shown. The
reconcile was then SIGKILLed at the named step, and the agent restarted with
converge.

The checks on these cases:

- While the reconcile was held, `POST /v1/upgrades/apply` returned 409 naming
  `reconcile.startup`, and status said `in_progress`.
- The write-ahead attempt was durable at every kill (`reconcile_attempts=1`).
- No step was repeated unsafely: after a kill that came after the action, the
  next start saw Docker already on prior and changed nothing (`noop`).
- The interrupted op stayed failed.
- J held after every kill and restart.

| Case | Reconcile killed | Docker at the kill | Next start (both stores) | Verdict |
|---|---|---|---|---|
| rc_after_writeahead | after the write-ahead record, before acting (`ps_before:3`) | unchanged | realign, `[tag:prior]`, retired | PASS |
| kill_in_reconcile_tag | at its retag (`tag_before:1`) | unchanged | realign, retired | PASS |
| rc_after_tag_before_verify | after the retag, before the verify (`ps_before:4`) | tag=prior run=prior | noop/already_on_prior, no command, retired | PASS |
| rc_in_verify_last_read | inside the verify, last read done (`image_after:13`) | tag=prior run=prior | noop/already_on_prior, retired | PASS |
| rc_after_audit_before_retire | after the verify and the audit entry, before the record removal (polled) | tag=prior run=prior | noop/already_on_prior, retired, with a **second** `:reconciled` entry | GAP: OWNER-audit |
| kill_in_reconcile_up | finish_rollback before `compose up` (`up_before:1`) | unchanged (bad runs, tag prior) | finish_rollback, `[up]`, retired | PASS |
| kill_in_reconcile_after_up | `compose up` done, not yet seen (`up_after:1`) | tag=prior run=prior | noop/already_on_prior, retired | PASS |
| rc_in_post_up_probe | inside finish_rollback's readiness probe | tag=prior run=prior | noop/already_on_prior, retired | PASS |
| rc_fr_in_verify_last_read | finish_rollback verify, last read done | tag=prior run=prior | noop/already_on_prior, retired | PASS |
| audit_write_fails_keeps_record | not killed: `audit.jsonl` made immutable (`chattr +i`) mid-reconcile | realigned and verified | realign, record **kept** as `converged_not_retired`, reconcile op failed(recovery_required). Once the log is writable: noop, retired with exactly 1 entry | PASS |

### Item 2: repeated restarts on one record

| Case | Sequence | End state (both stores) | Verdict |
|---|---|---|---|
| repeat_tag_ahead_exhaust | killed at the retag twice (attempts 1, then 2), then 2 full restarts | `recovery_required/reconcile_exhausted` both times, **no Docker command**, attempts stay 2, Docker unchanged (tag good, prior runs) | PASS |
| repeat_rollback_exhaust | killed before finish_rollback's `up` twice, then 2 full restarts | `reconcile_exhausted` both times, no command, attempts 2. **The failed-gate `bad` image keeps running** | GAP: OWNER-ungated |
| repeat_mixed_then_converge | killed in a fact read (attempts stays 0), at the retag (1), in a fact read (1), then a full restart | realign on attempt 2, retired | PASS |
| repeat_rr_stable | killed twice inside the reads of a recovery_required record, then 2 full restarts | `target_live_ungated` every time, no command, attempts 0 | GAP: OWNER-ungated |

The attempt counter persisted across every restart. Kills before the
write-ahead attempt record did not count an attempt. The reconcile never looped
on a mutation: after the cap it issues no Docker command at all.

### Item 3: journal consistency

J held after every one of the kills and restarts above, in both stores. For
each check:

- no record failed to parse, and none was truncated;
- no stray file appeared: temp files were counted, and none was ever treated
  as a record;
- no phase, attempt or start counter went backwards;
- every recorded image id was the real one;
- no record at a safe phase disagreed with Docker;
- no record was retired without its audit entry.

The only audit inconsistency was the OWNER-audit gap described under item 1.

### Item 4: negative controls (`--negative-control`, 2026-11-23)

Each mutant is applied to a copy of `cmd/culvert-maint`. The checked-out source
is never modified, and no mutant is committed.

```diff
# adopt_restarted (reconcile_decision_v2.go)
-	case in.Phase != journal.PhaseVerified:
+	case in.Phase != journal.PhaseVerified && in.Phase != journal.PhaseRestarted: // NEGATIVE CONTROL: adopts an ungated target
# no_write_ahead (startup_reconcile.go, act)
-	if err := s.opts.Journal.Write(*c.rec); err != nil {
+	if err := error(nil); err != nil { // NEGATIVE CONTROL: no write-ahead attempt record
# retire_before_audit (startup_reconcile.go, retire)
-	if err := s.auditReconciled(c, audit.OutcomeSucceeded); err != nil {
-		return s.keepRecord(c, OutcomeConvergedNotRetired)
-	}
 	if err := s.opts.Journal.Remove(c.rec.OpID); err != nil {
 		return s.keepRecord(c, OutcomeConvergedNotRetired)
 	}
+	_ = s.auditReconciled(c, audit.OutcomeSucceeded) // NEGATIVE CONTROL: retired before the audit, audit failure ignored
```

Recorded output, abridged:

```
containerd/mutant:adopt_restarted | restarted_at_health_gate | ... | adopt/verified_target_live ... retired=true | FAIL
  - decision: want recovery_required/target_live_ungated, got adopt/verified_target_live
  - record retired: want false, got true
  - I2 converged = same image, gated, ready: ... got tag=good run=good(running,ready) phase_before=restarted
containerd/mutant:adopt_restarted | restarted_at_verify | (same) | FAIL
containerd/mutant:no_write_ahead | rc_after_writeahead | ... | FAIL
  - k1 attempts after the kill: want 1, got 0
containerd/mutant:no_write_ahead | repeat_tag_ahead_exhaust | ... | FAIL
  - k1 attempts after the kill: want 1, got 0
  - k2 attempts after the kill: want 2, got 0
  - r1 decision: want recovery_required/reconcile_exhausted, got realign/tag_ahead_container_on_prior
containerd/mutant:retire_before_audit | audit_write_fails_keeps_record | ... | FAIL
  - r1 J after the failed audit: ... got 01M84C5NCE7K retired with no `:reconciled` audit entry
  - r1 record retired: want false, got true
  - r1 I7 audit before retire: want >= 1 succeeded, got 0 succeeded
NEGATIVE CONTROL adopt_restarted: caught (2 FAIL row(s))
NEGATIVE CONTROL no_write_ahead: caught (2 FAIL row(s))
NEGATIVE CONTROL retire_before_audit: caught (1 FAIL row(s))
NEGATIVE CONTROL: every mutant was caught -> OK
```

The harness also failed once for a reason in the harness itself, during
development: a restarted agent reused the crashed agent's call log, so the
upgrade's own `pull` was reported as a startup pull. That tripped I1 and
AGT-004. It was fixed before the recorded runs.

## Findings

1. **OWNER-audit: duplicate audit entry (reproducible).** The reconcile's
   `retire` writes the `:reconciled` audit entry and fsyncs it, then removes
   the record. If the agent is killed between those two steps, the record
   survives. The next start reconciles again (`noop`, Docker unchanged),
   writes a **second** `:reconciled` entry and retires the record.

   - Repro: `run.sh --cases '^rc_after_audit_before_retire$'`.
   - AGT-005 holds: there is never a retirement without an audit entry, and
     Docker is not touched again.
   - This is the same at-least-once design that `reportInterrupted` documents
     for the interruption audit.
   - It violates the owner's "never duplicated" requirement. Making it
     exactly-once would need the agent to treat its own audit log as state
     (look up the entry before writing it). That is a design choice, so it was
     **not** fixed here.
2. **OWNER-ungated: an ungated or failed-gate image is left running
   (by design).** Whenever the decision is `recovery_required`, converge changes
   nothing, so an ungated target that was already running keeps running. In
   two cases it is the image that **failed** its gate:
   - `rb_armed_before_tag`: the agent was killed after arming the rollback and
     before its tag;
   - `repeat_rollback_exhaust`: finish_rollback was killed twice before `up`,
     hit the attempt cap, and stopped trying.

   The reconcile never starts such an image (I4 holds everywhere). It reports
   `recovery_required` and leaves the image for an operator, exactly as AGT-900
   states. The `off` mode does the same.
3. **No production defect was found.** Every contract check passed in both
   stores.

## Not covered (and why)

- **The `sudoers` mode and the compose-cli wrapper.** The agent ran as root in
  `docker_group_lab`. The reconcile's `tag` and `up` did not go through
  `sudo -n` and the root-owned wrapper. The argv is the same, but the privilege
  path is not exercised.
- **The real Culvert proxy image and the full production compose file**
  (clamav, the cli profile, `compose_override_file`). The images are fakes that
  serve `/health` and `/ready`.
- **Interrupted standalone `rollbacks.create` records** (mode `image`) and
  **data-rollback records**. These are not driven here.
- **The reconcile deadline (`abandoned`)** and a **kill in the window between
  the verify returning and the audit write**. That window has no Docker call
  and no file write to hold on to. The kill points next to it are covered:
  inside the verify's last read, and after the audit write.
- **Docker unavailable means a stopped daemon.** Without `live-restore`, its
  containers stop and come back through the restart policy. Not covered:
  dockerd restarting mid-reconcile, and a stopped proxy container
  (`container_not_running`).
- **`compose up` that exits 0 without recreating (`ok_stale`).** It was not
  produced, as before.
- **One run per store, on one host and one Docker version.** There are no
  repeated trials. The polled kills depend on timing; a miss would be retried
  and reported.
- **A CI workflow.** None was added. The run needs root and starts private
  daemons. It should work on a GitHub-hosted Ubuntu runner with `sudo`, but it
  has not been tried there.
