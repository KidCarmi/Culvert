# Lifecycle conformance (shadow)

A deterministic, model-based check of the maintenance agent's `upgrades.apply`
lifecycle. **Shadow only: it is not a merge gate and must not be made one
without explicit owner approval of the properties it reports.**

## What it is

Everything is Go, standard library only, in the maintenance agent's module under
`cmd/culvert-maint/internal/lifecyclemodel/`. Every file there carries the build
tag `lifecycle_conformance`.

1. `model.go`, `reconcile.go` — a small explicit-state model of the apply flow:
   stages, write-ahead journal barrier, tag move, `compose up`, inline rollback,
   crash points, and the reference table of the recovery decision.
2. `checker.go` — a breadth-first model checker with state, transition and
   bounded-temporal properties. Counterexamples are shortest traces. A property
   whose precondition is never reached is `VACUOUS`, and a state or time budget
   that runs out is `INCOMPLETE`; neither is a pass.
3. `properties.json` — the properties, embedded into the binary (`go:embed`).
   It stays JSON so a status can be changed without touching code.
4. `vectors.go` — derives every fault path (172), every crash point (147) and
   the full bounded input space of the recovery decision (435,456 inputs, each
   with the expected action **and** reason) from the model. No randomness.
5. `cmd/culvert-maint/internal/server/model_conformance_test.go` — generates
   those vectors in-process and replays them against the **real** server,
   journal, orchestrator and runner. Only the process-exec layer and the health
   HTTP client are faked.
6. `cmd/lifecyclecheck` — the property gate and the Markdown step summary.
7. `cmd/lifecyclemutate` — scheduled mutation campaign (see below).
8. `cmd/culvert-maint/orphan_survival_crash_test.go` — orphan-survival crash
   vectors on the real agent binary (see below).
9. `test/lifecycle-conformance/run.sh` — runs 6, 5 and 8 and combines the result.
10. `baseline.json`, `observed.json` (embedded) — the **reviewed baseline**: every
   property verdict, exercised count and shortest counterexample, the state-space
   size, one readable line per apply and crash vector, a fingerprint of the
   reconcile table, and the real-code observations the model does not predict:
   the result payload's image digests (`upgrade_digest`, `rollback_digest`,
   `final_running_digest`) for every apply vector.
   Regenerated only by `test/lifecycle-conformance/update-baseline.sh`.

## Why the reviewed baseline exists

Every property is `proposed` or `open`, so the gate runs with
`-fail-only-approved`, and a property flipping from PASS to FAIL never changed the
exit code. And because the vectors are derived from `model.go`, a pull request that
edits the implementation **and** the model together keeps every vector green.
Measured on `155df09` (worktree experiments, nothing committed):

| Change | Before the baseline | With the baseline |
|---|---|---|
| Failed rollback no longer reported as `rollback_failed` (code + model) | exit 0; S5 FAIL only in the summary | exit 1: `S5 PASS -> FAIL`, 76 apply vectors listed |
| Post-`up` `TargetImageID` capture removed (code + model) | exit 0; C2 went FAIL → PASS, so the run looked *better* | exit 1: S8 FAIL, `C2 FAIL -> PASS`, state space 5864 → 5792 |
| `restartLeftPrior` branch of `final_running_digest` removed (code only) | exit 0; the model does not predict that field | exit 1: real-code DRIFT, 48 → 58 vectors misreport |
| Reconcile reason `indeterminate_restore_prior` moved from `rollback_to_prior` to `loud_stop` (code + model) | exit 0 | exit 1: reconcile table drift, counts keyed `action/reason` |

The existing unit tests also caught these. S8 restates the model's own capture
rule, so it adds a named failure, not detection power: the crash-vector lines
already pin `target_id`. The baseline exists for the
changes where conformance is the only detector (the 17 conformance-only mutants
below), and so that a reviewer sees a behaviour change as a diff instead of
trusting that a co-edited model is still right.

A second independent review found that a co-change to `upgrade_succeeded` still
passed: the field was compared with the code but not rendered in the baseline line.
Every expectation field is now rendered, and
`TestVectorLines_CoverEveryExpectationField` fails if a field is added without
being rendered. An aborted regeneration restores the reviewed files and prints
the drift it captured, instead of leaving half-written baselines that a re-run
would compare as "nothing to review".

Drift is not a correctness verdict and approves nothing. It means "the modelled
or observed behaviour differs from what was last reviewed".

## What a pass means — and does not mean

| Claim | Supported? |
|---|---|
| The agent's own Go logic behaves as the model says on every modelled path | Yes — executed against the real code |
| Docker behaves as the fake exec layer assumes | **No** — an assumption; validate against real Docker (`test/e2e/maint-agent`) |
| Startup crash recovery works end to end | **No** — the model's agent-restart step is not executed |
| The agent's reports stay true when the in-flight docker command outlives the agent | **Measured on the process-level Docker model only**; findings pinned as `open` (below) |
| Standalone/data rollback, migration, timeouts, concurrency are correct | **No** — not modelled |
| The properties are Culvert's contract | **No** — every property is `proposed` or `open`; none is owner-approved |

The model checker by itself verifies an abstraction. Only the conformance test
touches product code. Do not present either as "the lifecycle is verified".

## Fake-Docker assumptions, checked on real Docker

`test/lifecycle-conformance/docker-probe.sh` reproduces the agent's own argv
against a real daemon. It needs no Docker Hub: it builds a registry from source
and two images `FROM scratch`, pushed as OCI indexes like a real release. It is
manual and never a PR gate. Measured on Docker 29.10.0 / Compose v5.7.1, once
per image store:

| Model outcome | Real Docker (both stores) | Model status |
|---|---|---|
| `ok` (tag moved, `up -d` recreates) | recreated in 10 of 10 trials | holds |
| `ok_stale` (tag moved, `up -d` exits 0 and does not recreate) | **0 of 10** | robustness input only, as stated below |
| unchanged tag, `up -d` | container kept | holds (`same=true` skips the restart) |
| `up_fail_stale` | an unpullable sibling image or a broken override gives exit 1, proxy untouched, **tag already moved** | holds: the AGT-002 case is real |
| `up_fail_recreated` | a sibling port clash gives exit 1, **proxy already recreated** on the target | holds |

**Image identity differs by image store**, and the fake used to model only one
of them:

| | classic store (hosts upgraded from older Docker) | containerd store (fresh Docker 29 default) |
|---|---|---|
| container `.Image` | image **config** digest, distinct from the registry digest | the **registry (index) digest** itself |
| RepoDigests | registry refs only; `[]` for a local tag whose registry ref is gone | adds a synthetic `<local repo>@sha256:<digest>` for every local tag, so never empty |

Every apply and crash vector now runs under both stores. Result: **no
mismatch**. The agent's decisions (outcomes, tag, journal records, reconcile
verdicts) do not depend on the store. Only the reported `final_running_digest`
differs. Under the containerd store, 12 of the 48 misreports disappear, because
the agent reports the synthetic local reference for a prior image that has no
registry digest. The rollback gate does not accept that reference. Both
stores' observations are pinned in `observed.json`; containerd lines carry the
`[containerd]` prefix.

## Known reported items (none blocks)

- **C2 passes since the F1 fix (ADR-0061).** It used to fail only through the
  injected outcome `ok_stale` (`compose up` exits 0 without recreating the
  container although the tag moved; not reproduced on real Docker 29.10 /
  Compose v5.7.1): the journal took `target_image_id` from whatever ran after
  `up`. The restart stage now records it only when the post-`up` capture's
  RepoDigests carry the pinned digest, and the new property S9 states that the
  journal never names a non-target image as the target. S8 was narrowed to the
  case where the target actually runs. The FAIL -> PASS was reviewed as a real
  improvement: the capture is still made, it is only gated on evidence.
- **O1 (open, AGT-900)**: an agent killed between `docker tag` and `compose up`
  leaves the tag ahead. Startup reports it and does not act (ADR-0057).
- **O2 (open)**: after AGT-002 the tag is still left ahead on 22 of 172
  modelled terminal paths (28 before the fix). 14 of them need `ok_stale`,
  which real Docker did not exhibit. The other 8 are real residue: `up` failed
  without recreating and the prior image has no allow-listed registry
  reference (4), or the stack was down before the upgrade (4).
- **Reported running image: resolved (contract AGT-006).** The agent used to
  infer `final_running_digest`, and 48 of 172 apply vectors (84 across both
  image stores) reported an image that was not running. It now reports only an
  image captured after the last `compose up`, otherwise `final_running_state:
  unverified`. The model predicts all three fields for every vector, and the
  misreport list in `observed.json` is empty under both stores.

## Orphan-survival crash vectors

The real-binary crash tests (`startup_crash_recovery_test.go`) kill the agent
**and** the docker command it was waiting on. The kernel re-parents that
command instead, and the runner gives each command its own process group, so
nothing aimed at the agent reaches it. `orphan_survival_crash_test.go` kills
only the agent at each of the 7 kill points with a docker command in flight,
proves from `/proc` that the command is alive and re-parented, restarts the
agent, records its reports, releases the command, and reads the reports again
(and after one more restart). A second flow admits the operator's next
operation while the command is still alive.

- Negative controls in the code: a mutating in-flight command (`tag`,
  `compose up`) must change the model after release, write a completion marker
  in both flows, and a read-only one must not change the model; every report
  read must answer 200 (404 for the operation only after a later operation
  verifiably succeeded and retired the record); at the restart the operation is
  `failed(agent_restart_interrupted)` with exactly one audit entry and is the
  only interrupted entry; the later operation must be the one `/v1/status`
  advises. Every other failure, including a shared rig helper's, is `INVALID`.
  `TestOrphanSurvival_ReapedControl` repeats the vectors with the command
  reaped and requires no divergence.
- Findings are pinned in `orphanExpectations`, every entry `open`. Q3 is pinned
  in two parts: the late mutation after a reported success, and what every
  `/v1/status` signal (interrupted entries, `pinned_tag` absent / true / false)
  shows of it. `TestOrphanClassifier_Later` checks the classifier on synthetic
  observations. A finding is not a failure. Exit 1 requires positive evidence
  of a complete run (one `ORPHAN-COMPLETE` line per flow, 14 + 14, and both
  `ORPHAN-SUMMARY` lines) and every failed subtest explained by its own
  `EXPECTATION MISMATCH` or `A3:` line. Two further guards make that evidence
  positive: every line the suites print must start with a prefix on a closed
  allowlist (`orphanOutputPrefixes` in the test, `ORPHAN_PREFIXES` in `run.sh`;
  the two must match), so any unmarked assertion or shared rig helper message
  fails the run as incomplete; and the per-flow `sanctioned=` counts on the
  `ORPHAN-COMPLETE` lines must add up to the number of `EXPECTATION MISMATCH`
  and `A3:` lines. Anything else non-zero, or any unlisted output, is exit 2.
- What Q1 establishes: the durable report (operation result, audit entry) is
  conservative, since it already says `indeterminate` wherever the orphan can act,
  and a conclusive-looking live read (`running_image`, `pinned_tag`) can change
  after the restart. On this model a durable report cannot be shown stale: it
  says `unchanged` only where the in-flight command changes no tag or container.
- Model artefacts, not findings: the model's `compose up` reads the tag when it
  is released, while a real in-flight `compose up` has already resolved its image.
  So "a rollback admitted meanwhile, then the orphan's `up` lands on the prior
  image" is a property of the model. An orphaned `pull`'s effect on the local
  image store is not represented.
- The model is not Docker. What real Docker, systemd and sudo do at these kill
  points was measured separately; see "Real Docker and systemd" below. In short:
  with the shipped unit no docker command outlives the agent, so the model's
  orphaned CLI does not occur, and `barrier_before_tag`'s late tag move did not
  reproduce. What does survive the agent is `dockerd` finishing the last
  request it was sent.

## Real Docker and systemd: the orphan probe

`orphan-probe/probe.sh` (manual; never a PR gate) runs the real agent, installed
by the real `install.sh`, under a real systemd unit, calling Docker through the
real sudoers file and wrapper, against a real daemon. A proxy on the Docker
socket (`dkproxy.py`) SIGKILLs the agent — only the agent — at an exact Docker
API request of the `restart` stage: before the fixed-tag request, after it, and
after each of the 12 requests `docker compose up -d` makes when it recreates the
proxy. systemd then restarts the agent. The probe optionally runs the
operator's next operation, waits for rest, and compares the agent's reports with
what `dockerd` says when asked directly.

```bash
sudo test/lifecycle-conformance/orphan-probe/probe.sh            # about 45 min
sudo test/lifecycle-conformance/orphan-probe/probe.sh --quick    # smoke run, not evidence
```

Exit 0: every property held. Exit 1: a property was violated. Exit 2:
incomplete (a prerequisite, a trial or a control did not run as intended). It
refuses to run where `culvert/proxy:pinned` already exists.

Properties checked on every trial: no docker command of the dead agent is alive
when the new agent starts; an operation that reports success leaves Docker
healthy on the image it names, and Docker does not change afterwards; when
Docker at rest is not healthy, something reports it (an interrupted record, a
failed operation, or `recovery_required`). "Reports it" is deliberately weak:
an outstanding record counts, whatever its live fields said at the restart. A
trial whose follow-up operation did not run to an end is invalid, and each
group of trials must have the expected count, or the run is incomplete.

Unlike `docker-probe.sh`, this probe has to move the real fixed tag: the agent
under test hard-codes `culvert/proxy:pinned`. Hence the refusal above.

Measured on Ubuntu 24.04, systemd 255, sudo 1.9.15, Docker 29.10.0 (containerd
image store), Compose v5.7.1. One environment; a different systemd, cgroup
layout or Compose version is not covered.

**What the supervisor does.** When the agent dies, systemd sends SIGTERM to
everything left in the unit's control group and does not start the next agent
until the group is empty; a child that ignores SIGTERM held the restart for
`TimeoutStopSec` and was then killed; a child started through `sudo` or
`setsid` did not leave the group. With `KillMode=process` the child was still
alive when the next agent started. That control is what establishes the
property. The per-trial check (is any docker command of the dead agent alive
once the new agent answers?) is taken seconds after the kill, so it can only
catch a slow command: it found none under the shipped unit, and it found the
orphaned `docker compose up` on the real agent with `KillMode=process`, where
the rollback that followed reported success and the system ended with no proxy
container.

**What the daemon does.** A request `dockerd` has received is carried out
whether or not the client is still alive. For the fixed tag that takes
milliseconds, long before the 5 s restart delay, so the agent's first read
after a crash at `barrier_before_tag` already sees the final tag (rollback
after it: correct and stable). A container stop is different: it lasts as long
as the proxy takes to exit, up to `stop_grace_period` (60 s in
`docker-compose.yml`).

**Results (shipped unit, 40 trials + 4).**

| Scenario | Trials | Result |
|---|---|---|
| Crash only, proxy exits at once | 14 | Every state stable and reported: the record is kept and says `indeterminate`. In 4 the proxy is down (crash between compose's stop and start) and stays down until an operator acts |
| Crash, then rollback, proxy exits at once | 14 | 13 correct and stable. 1 fails its health gate and says so (crash between compose's stop and delete: the first `compose up -d` only cleans up; a second rollback succeeds) |
| Crash only, proxy drains for 12 s | 4 | The stop the dead CLI requested completes after the new agent has started: the proxy goes down after the agent reported `running_image: prior`. The record is kept |
| **Crash, then rollback, proxy drains for 12 s and answers 200 meanwhile** | 4 | **2 violations.** The rollback finds the old container still running, changes nothing, passes its health gate, reports success and retires the record. The container then exits: proxy down, no record, nothing reporting it |
| Same, with a proxy that answers `/ready` 503 once it has SIGTERM | 4 | 0 violations: the rollback fails its health gate and keeps the record |
| Crash, then re-apply, proxy drains | 4 | 0 violations |

The violation needs three things together: the agent dies while Compose is
stopping the old proxy container; the proxy takes longer to exit than the
restart delay plus the time to the next operation; and it still answers
`/ready` with 200 while it drains. At the time of measurement Culvert's proxy
did: its listener stays open from SIGTERM until its proxy-server shutdown hook
(up to the 12 s early phase plus later hooks), with nothing changing `/ready`.
That is read from `main_shutdown.go` and `healthcheck.go`; the probe's proxy is
a stand-in, and how long the real proxy takes to exit was not measured.

**Startup convergence as first merged (#2039, `reconcile_on_startup = "converge"`), 22 trials.**
With a proxy that exits at once, all 14 kill points end as intended: realign or
no-op where the container is on the prior image, `recovery_required` where the
stack is down or the target is live. With a draining proxy, 4 of 8 are
violations (the two kill points with a stop in flight, with and without the
`/ready` change): the reconcile sees the old container running the prior
image, realigns the tag, records `converged` and retires the record about 5 s
after the crash; the container then exits. Unlike a rollback this needs no
operator timing, and the realign path makes no readiness probe, so the `/ready`
change does not cover it. Not fixed here; it is evidence for the AGT-900 gate.

**With the fixes together (2026-11-23).** The same probe, with the agent built
from the unit fence, the settle wait, the always-reported `pinned_tag` and (for
the last rows) the corrected startup reconcile, and the proxy's `/ready` change.
Kill points -1, 0, 4, 8, 9, 12; settle and stop grace scaled to 20 s / 15 s
(`ORPHAN_PROBE_SETTLE`, `ORPHAN_PROBE_STOP_GRACE`) so that the relation the
agent relies on (settle > stop grace > the proxy's drain) is the shipped one and
the run stays practical.

| Run | Trials | Violations | What changed |
|---|---|---|---|
| Stand-in proxy, shipped unit | 18 + 2 | 0 | The rollback during a 12 s drain no longer reports success: it waits out the window, the stale stop has finished by then, and it fails its health gate and keeps the record |
| Real Culvert proxy binary (v1 from `main`, v2 with the `/ready` change), shipped unit | 18 | 0 | Same properties with the real proxy, including with a request pending on its admin UI, where its shutdown takes its real 5 s |
| Startup convergence as merged in #2039, stand-in | 10 | 4 | Unchanged: realign, `converged`, record retired, proxy then exits |
| Startup convergence with the correction, stand-in | 10 | 0 | Those four end as `recovery_required` with the record kept |
| Startup convergence with the correction, real proxy binary | 8 | 0 | |

The real proxy binary, alone: SIGTERM to exit takes 0.06 s when idle and 5.0 s
with a request pending on the admin UI; during those 5 s `/ready` answers 200
on `main` and 503 with the change, and `/health` answers 200 in both.

Two things these runs show that are not safety failures and are not fixed here:
- After a crash between Compose's stop and delete, the first
  `docker compose up -d` only cleans up. The rollback fails its health gate,
  keeps the record and leaves the proxy down; a second rollback succeeds.
- After a crash between Compose's delete and rename, `up` starts the
  replacement under Compose's temporary name. It serves the right image and the
  operation's success is correct; the container is not called what
  `container_name` says until the next recreate.

The "real proxy" is the real binary in a minimal image, not the release image's
Alpine layers (Docker Hub was not reachable where this was run).

**Not covered.** A crash of `dockerd` or the host; a proxy that ignores
SIGTERM; Compose versions that recreate in a different order; the classic image
store; multi-service stacks; the real Culvert proxy image (the probe's proxy is
a stand-in with the same three behaviours on SIGTERM).

## Running

```bash
test/lifecycle-conformance/run.sh /tmp/lifecycle-report
```

| Exit | Meaning |
|---|---|
| 0 | Model check complete; all three conformance suites ran and passed; every orphan-survival flow ran to its end and passed; no drift from the reviewed baseline |
| 1 | A conformance vector mismatched the real code, an orphan-survival finding no longer matches its pinned expectation, an owner-**approved** property failed, or the model / real-code observations drifted from `baseline.json` / `observed.json` (`lifecyclecheck` alone exits 3 for drift) |
| 2 | Incomplete: state/time budget hit, a vacuous property (its trigger is unreachable), a malformed properties file, a skipped or missing suite, or an orphan-survival run that is not provably complete or failed for any reason other than a pinned expectation or the reaped control (INVALID, panic, timeout, rig failure, a flow that did not reach its end). Never reported as a pass |

Exit 2 takes precedence over exit 1 and nothing downgrades it: a run with a
failing unapproved property **and** a vacuous property is incomplete.

A failing `proposed` or `open` property is printed with its shortest trace and
does **not** change the exit code: the tool reports on unapproved properties,
it does not define the contract. A **change** in any property's verdict,
exercised count or counterexample is drift, and does.

The pieces can be run on their own from `cmd/culvert-maint`:

```bash
# the checker's own tests
go test -tags lifecycle_conformance -count=1 ./internal/lifecyclemodel/...
# the property gate (exit 0 / 1 / 2 as above, plus 3 = drift from baseline.json;
# the baseline is compared only with -include-proposed, otherwise NOT CHECKED;
# build it rather than `go run` it when the exit code matters: `go run` reports
# every non-zero exit as 1)
go build -tags lifecycle_conformance -o /tmp/lifecyclecheck ./internal/lifecyclemodel/cmd/lifecyclecheck
/tmp/lifecyclecheck -include-proposed -fail-only-approved -report /tmp/lifecycle-report
# the three conformance suites
go test -tags lifecycle_conformance -count=1 -run TestModelConformance ./internal/server/
# the orphan-survival vectors, their reaped control and the classifier test (Linux; builds the agent)
go test -tags lifecycle_conformance -count=1 -run '^TestOrphan(Survival|Classifier)_' -v .
```

`lifecyclecheck` flags: `-include-proposed` (evaluate `proposed` properties as
well as `approved` ones), `-fail-only-approved` (a failing property that is not
`approved` is printed but does not cause exit 1), `-max-states`, `-max-seconds`,
`-report <dir>` (writes `model_check.json`), `-summary <dir>` (prints the step
summary for a report directory), `-write-baseline <file>` (record instead of
compare; refused for an incomplete or vacuous run), `-no-baseline` (skip the
comparison; printed, and the summary says NOT CHECKED).

All of it carries the build tag `lifecycle_conformance`. A plain
`go build ./...`, `go vet ./...` or `go test ./...` neither compiles nor runs
any of it, so no existing gate changes.

## Property status

`cmd/culvert-maint/internal/lifecyclemodel/properties.json` holds a `status`
per property:

- `proposed` — checked and reported; never fails the run.
- `open` — a known open product question (linked to `contracts/registry.yaml`);
  reported only.
- `approved` — fails the run when violated. **Set only by the owner**, in the
  same change that records `owner_approved: true` for the matching registry
  contract. The checker only reads the file (it is compiled in); its SHA-256 is
  printed and recorded in `model_check.json`, and the workflow verifies the run
  left the file untouched.

## When a conformance vector mismatches

A mismatch means the code and the model disagree. Either is legitimate:

- The change is unintended → fix the code.
- The change is intended → update
  `cmd/culvert-maint/internal/lifecyclemodel/model.go` in the same pull request, and say so in the description. The model is a second, independent
  statement of the lifecycle; keeping the two in step is the point.

Then run `test/lifecycle-conformance/update-baseline.sh` and commit the
regenerated `baseline.json` / `observed.json` with the change. The script ends
with a **"behaviour changes to review"** block. Paste it into the pull request.

**Regenerating the baseline is not proof of correctness.** It records whatever
the code and the model now do. The reviewer accepts each drift line explicitly:

- `[REGRESSION CANDIDATE] property X verdict PASS -> FAIL`: the lifecycle no
  longer holds what it held. This needs a reason in the PR, and owner sign-off
  for the security-relevant properties: S2 rollback preservation, S4 journal
  retirement, S7 write-ahead barrier, C1/C2 reconcile, B1/B2 recovery.
- `[VERIFY THE IMPROVEMENT IS REAL] property X verdict FAIL -> PASS`: removing a
  safety capture once turned C2 green, so a run can look better while protecting
  less.
- A vector line whose `op`, `reason`, `running` or `tag` changed is a
  customer-visible outcome change.

No property becomes a blocking contract through this process. Promotion is a
separate owner decision (see "Promotion to a required gate"). Review their diff
line by line: a property verdict that moved, or a vector line whose `op`,
`reason`, `running` or `tag` changed, is the behaviour change in plain words. CI
never regenerates them, and the workflow fails if a run modified either file.

## Workflows

- `.github/workflows/lifecycle-conformance-shadow.yml` — pull requests touching
  `cmd/culvert-maint/**`; under a minute; no secrets, no Docker, no network
  services. Not in the required checks.
- `.github/workflows/lifecycle-mutation-campaign.yml` — weekly and on demand.
  Runs `cmd/lifecyclemutate`, which mutates temp copies of seven lifecycle source files and records which mutants
  the existing tests and the conformance suite each kill. About 1h40m on four
  cores for 350 mutants, hence scheduled only.

Since the observation lock, a mutant that changes the reported
`final_running_digest` is also killed by conformance, so later campaigns are not
directly comparable with the figures below.

Baseline measured before AGT-002, at `ef94311` (350 mutants, 343 compiled): existing tests
killed 260 (75.8%), conformance alone 243 (70.8%), both together 277 (80.8%);
17 mutants were killed only by conformance, mostly journal-phase bookkeeping
that existing tests do not observe mid-flight. The conformance suite does not
replace the existing tests (34 kills are theirs alone).

## Promotion to a required gate

Not before all of:

1. The owner approves or rejects each property.
2. The fake-Docker assumptions are checked against real Docker.
3. Several weeks of shadow runs without a false alarm.
4. The check's name states its scope (`upgrades.apply` only) or the model grows.
