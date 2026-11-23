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
8. `test/lifecycle-conformance/run.sh` — runs 6 and 5 and combines the result.
9. `baseline.json`, `observed.json` (embedded) — the **reviewed baseline**: every
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

## Running

```bash
test/lifecycle-conformance/run.sh /tmp/lifecycle-report
```

| Exit | Meaning |
|---|---|
| 0 | Model check complete; all three conformance suites ran and passed; no drift from the reviewed baseline |
| 1 | A conformance vector mismatched the real code, an owner-**approved** property failed, or the model / real-code observations drifted from `baseline.json` / `observed.json` (`lifecyclecheck` alone exits 3 for drift) |
| 2 | Incomplete: state/time budget hit, a vacuous property (its trigger is unreachable), a malformed properties file, or a skipped or missing suite. Never reported as a pass |

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
