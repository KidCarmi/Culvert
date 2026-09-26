# Security review — CI evidence chain and the stage-6B performance reporter

**Date:** 2026-09-24
**Reviewer role:** Security Regression Engineer (scheduled run)
**Scope reviewed:** `origin/main...claude/epic-bardeen-tsbdjm` — 58 files, +7,522/−93.
CI-REDESIGN stage 6B: the `cmd/cireport` performance reporter (5,169 LOC),
`.github/workflows/ci-perf-report.yml`, the `qa-gate.yml` weekly equivalence
audit, the `pr-fast-gate.yml` `run-name`, the shared OpenAPI conformance
fixture, and the gate/wall test changes. Plus targeted invariant-drift checks
across the product tree (see §7).

---

## 1. Executive summary

The delta is CI/supply-chain code, not data-plane code. It is unusually well
defended: the reporter is a read-only collector that treats everything it
downloads as data, runs only trusted default-branch code, and validates the
provenance of every artifact it reads. Sixteen adversarial probes against it
(§6) found nothing exploitable.

**One finding, and it is not in the new code — it is in what the new code
declined to cover.** This diff introduces `require-success` on the gate
aggregates (the mechanism that makes "a job that never ran" refuse instead of
approve) and wires it to *audit* runs only. The two workflows that
`.github/release-evidence.txt` marks **mandatory** — `qa-gate.yml` and
`security-release-gate.yml` — still passed no requirement on a **main push**,
which is precisely the run release promotion reads. Because each aggregate is
`if: always()`, a main-push run in which every substantive job skipped had one
job succeed, so the *workflow* concluded `success` rather than `skipped` — and
`require-gate.sh`, whose fail-closed branch refuses a workflow-level `skipped`,
had nothing to refuse. A commit against which no test and no security scan had
run could satisfy both mandatory evidence rows and be promoted, signed, to
`latest` and semver.

This is a **pre-existing fail-open, not a regression introduced here** (it is
recorded as a known limitation in `qa_gate_scheduling_test.go` and deferred to
CI-REDESIGN §8). It is fixed in this change because this diff is the first to
carry the mechanism that closes it, and closing it for the two mandatory rows
does not require touching the shared action's default that every other
aggregate depends on.

**Verdict:** no security regression found in the reviewed delta. One
pre-existing protection-mechanism failure in the release evidence chain,
closed fail-closed, with defect gates verified failing against the pre-fix
tree.

---

## 2. Security findings

### CI-SEC-1 — A mandatory release-evidence gate approved a run in which nothing ran

| | |
|---|---|
| **Severity** | **Medium** (High impact × Low likelihood) |
| **CWE** | CWE-693 Protection Mechanism Failure; CWE-754 Improper Check for Unusual or Exceptional Conditions |
| **OWASP** | A08:2021 Software and Data Integrity Failures; CICD-SEC-1 Insufficient Flow Control Mechanisms |
| **Regression risk** | Pre-existing; **not** introduced by this diff |
| **Status** | Fixed in this change |

**Mechanism.** `.github/actions/needs-verdict` reads a `skipped` need as a pass
unless the caller passes `require-success`. That default is load-bearing: on a
pull request every QA and Security job skips on its own `if:`, and the required
check must still report success or branch protection wedges every PR at
"Expected". The aggregates therefore ran with no requirement on *every* event.

The compensating control does not reach this case. `require-gate.sh` refuses a
workflow whose conclusion is `skipped` — but a whole-workflow `skipped`
requires *every* job to skip, and the aggregate is `if: always()`. It runs, it
approves, and GitHub concludes the workflow `success`.

**Preconditions.** A second, unrelated defect or misconfiguration that stops
the substantive jobs from starting on a main push: a path filter added to a
job's `if:`, a mistyped event condition, a `needs:` edge whose producer was
removed, or a cancellation landing after the aggregate was scheduled but before
the jobs started. Not directly attacker-triggerable.

**Exploitability.** Low. An attacker with no repository write access cannot
reach it. An attacker *with* write access has cheaper paths (though those are
reviewed; this one is silent and green, which is the point).

**Likelihood.** Low, but non-negligible: this repository edits these `if:`
conditions frequently — stage 1 alone removed six `needs:` edges, stage 5B
moved the race suite between jobs, and stage 6B (this diff) added a schedule
event and two new job conditions. Each such edit is one typo away from the
precondition.

**Impact.** High. Both mandatory rows fail open simultaneously and silently:
`qa-gate.yml` (the whole `-race` + coverage suite, determinism, coverage
floors, contract and bench gates) and `security-release-gate.yml` (gosec,
govulncheck, trivy fs + image, gitleaks, license check, SBOM, staticcheck,
hadolint). `ci.yml`'s `promote-image` then moves `latest`/`main`/semver onto
that digest and signs it with cosign keyless, and the catalog pipeline signs a
release catalog naming it. The failure is invisible: every surface is green.

**Affected assets.** Published container images and their cosign signatures;
the signed release catalog; every appliance that auto-updates from it.

---

## 3. Risk rating

| Axis | Rating | Basis |
|---|---|---|
| Severity | Medium | High impact, low likelihood, not directly reachable |
| Exploitability | Low | Requires a second defect; no unauthenticated path |
| Impact | High | Both mandatory evidence rows fail open together, silently |
| Detection | **Very poor** | Every check, badge and summary reports green |
| Blast radius | Fleet-wide | Signed artifacts on public release channels |

---

## 4. Regression analysis

**Did this diff cause it?** No. The single-arm `require-success` expression is
introduced here; before it there was no `require-success` at all, so the
main-push behaviour is byte-identical to the pre-diff tree. The diff is the
moment the mechanism became available, not the moment the hole opened.

**Did this diff make it worse?** No. The audit arm is strictly additive and
applies only to `schedule` and `unsharded_audit` dispatches.

**Does the fix change any other behaviour?** No, in the fail-closed direction
only, and the arms are provably disjoint:

* **Pull request** — unchanged. Both aggregates still pass `''`, every job
  still skips, the required check still reports success. Pinned as a CONTROL
  in both new tests, because the cheapest wrong fix (tightening the shared
  action's default) would wedge every PR and would pass every other assertion.
* **Ordinary `workflow_dispatch`** — unchanged (`''`). A dispatch is never
  release evidence: `require-gate.sh` reads only `event=push` runs of `main`.
* **Audit runs** — unchanged. `push` is never an audit event; pinned by
  `TestCIPerf_RequireSuccessArmsAreDisjoint`.
* **Tag push on the Security gate** — matches the *first* arm, which now names
  the suite **and** the nine scans. Strictly stronger; those jobs already run
  on a tag.
* **Healthy main push** — approves exactly as before. All nine QA jobs and all
  nine Security scans run on every non-PR event (`if: github.event_name !=
  'pull_request'`), and none of the nine Security scans carries a `needs:`
  edge, so none can skip in a healthy run.

**The one asymmetry, and why it is deliberate.** `tests-race` is **excluded**
from the Security gate's main-push arm. QA owns the race suite on a main push
(stage 2B), so `tests-race` legitimately skips there; requiring it would refuse
every healthy main push. Pinned explicitly — the test fails if a future edit
adds it to that arm.

**`qa-coverage` is included** in QA's main-push arm even though it skips when
`qa-race` fails: in that scenario `qa-race`'s own `failure` already refuses, so
the requirement adds a second refusal reason to an already-refused run and
never a false one.

---

## 5. Attack scenarios

1. **Silent gate evaporation (the finding).** A maintainer adds a `paths:`
   filter or mistypes an `if:` while editing the gate graph. The next main push
   runs only the two aggregates; both report APPROVED; both workflows conclude
   `success`; `require-release-evidence.sh` finds two green mandatory rows;
   `promote-image` moves `latest` and semver onto the digest and cosign signs
   it; the catalog pipeline signs a catalog naming it. No scan and no test ran.
   Appliances auto-update. *Closed by this change.*

2. **Planted trend report (probed, already defended).** An attacker runs the
   reporter on a branch and uploads a `report.json` claiming healthy timings.
   `untrustedProducer` refuses it on four independent axes (producer workflow
   path, producing event, head branch, and both `repository` and
   `head_repository` full names), and `identityMismatch` re-checks the report's
   self-declared run identity against the live API. *Not reachable.*

3. **Classification spoofing via run title (probed, already defended).**
   `titleAuditRE` reads `audit=true` from a run's `display_title` — which for a
   push is the commit subject and for a PR is the author's title. A commit
   message saying `audit=true` would misclassify the run and could make a stale
   weekly audit look fresh, defeating the trend's only hard failure.
   `classify()` reads the title **only** when `run.Event == "workflow_dispatch"`
   (a dispatch title is the workflow's own `run-name`). *Not reachable.*

4. **Workflow-command / markdown injection into the report (probed, already
   defended).** The runner image and toolchain values are parsed out of job
   logs and pass `imageValueRE = ^[A-Za-z0-9._-]{1,64}$` — anchored, bounded,
   no `:`, no newline — before entering a cohort key, the step summary or a
   `::warning::` line. *Not reachable.*

5. **Token exfiltration via artifact redirect (probed, already defended).** An
   artifact download redirects to presigned storage whose query string *is* the
   credential. `net/http` drops `Authorization` on a cross-host redirect, and
   `redactURLError` strips query, fragment and userinfo from any URL a
   transport error names before it reaches a report or step summary — which
   outlive the signature and are readable by anyone with repository read.
   *Not reachable.*

6. **Pwn-request via `workflow_run` (probed, already defended).**
   `ci-perf-report.yml` triggers on `workflow_run` and holds a token. It checks
   out `github.event.repository.default_branch` (never the PR head) with
   `persist-credentials: false`, holds only `actions: read` + `contents: read`,
   disables the cache (a cache restored here could have been written by a PR
   run), builds with `GOPROXY=off`, skips `pull_request` runs entirely, and
   validates `run_id`/`run_attempt` as numeric in the shell before use.
   *Not reachable.*

7. **Zip-slip / decompression bomb in artifact reading (probed, already
   defended).** `zipMembers` never writes to disk, selects members by
   `path.Base` against an allowlist, refuses a duplicate base name rather than
   resolving it by order, checks the declared `UncompressedSize64` **and**
   bounds the actual read with an `io.LimitReader` (so a lying header does not
   help). The artifact carrying the prebuilt test binary is never downloaded.
   *Not reachable.*

---

## 6. Suggested fix (implemented)

Give each mandatory-evidence aggregate a `require-success` arm for the runs
release gating actually reads. The expression is an ordered ternary; `&&` binds
tighter than `||`, so it reads as `(audit && auditList) || (push && pushList) ||
''`.

**`.github/workflows/qa-gate.yml`** — the aggregate now requires all nine
substantive jobs on `github.event_name == 'push'` (the workflow's push trigger
is `branches: [main]`, which is exactly the run `require-gate.sh` reads).

**`.github/workflows/security-release-gate.yml`** — the owned-suite arm now
names the eight blocking scans alongside `tests-race`, and a new main-push arm
requires the eight alone.

**A near-miss worth recording, because it is the failure mode of this kind of
fix.** The first version of the Security-gate arm listed nine scans, including
`sbom`. `sbom` runs on exactly the same events as the other eight and looks
identical in the job list — but it is *deliberately informational* and is not a
member of the aggregate's `needs:`. `needs-verdict` reads its verdicts out of
the `needs` context, so requiring a non-member is not "missing evidence", it is
evidence that can never arrive: the gate would have refused **every** run and
wedged `main` on the next push. The behavioural tests did not catch it, and
could not have: they build their `needs` payload from the same list, so a
fixture derived from the wrong list agrees with the wrong list. The
structural wall below is what catches it, and it is the more important of the
two additions — a fail-closed change that is wrong in the closed direction is
still an outage.

`extractGuard` (the shared wall helper) used `strings.LastIndex(s, "&&")` to
find the guard boundary. That was correct only while the expression had one
arm — a guard may contain its own `&&`, and a second arm moves the last `&&`
past the guard entirely. It now matches the first parenthesis group by depth,
which is stable under both shapes.

Not done, deliberately: the shared action's **default** is still
skipped-as-pass. Changing it is a policy change to code every gate aggregate in
the repository depends on, it would wedge every PR at "Expected", and it is not
needed to close this finding. It stays a recorded follow-up (CI-REDESIGN §8).

---

## 7. Files

| File | Change |
|---|---|
| `.github/workflows/qa-gate.yml` | main-push `require-success` arm + rationale |
| `.github/workflows/security-release-gate.yml` | scans required on every non-PR event + rationale |
| `ci_perf_report_test.go` | exact-expression pin, arm extraction, two new gates |
| `security_race_ownership_test.go` | depth-matching `extractGuard`, both-arm pin, two new gates |
| `qa_gate_scheduling_test.go` | known-limitation notes corrected (now residual, PR arm only) |

---

## 8. Required tests (implemented, each verified failing against the pre-fix tree)

| Test | Proves |
|---|---|
| `TestCIPerf_MainPushRefusesJobsThatNeverRan` | Drives the REAL `needs-verdict` shell with the value read **out of** `qa-gate.yml`. Green push approves; all-skipped refuses; each of the nine skipped refuses and is named; each absent from `needs` refuses. |
| `TestCIPerf_RequireSuccessArmsAreDisjoint` | No event matches both arms. |
| `TestCIPerf_AuditPredicateIsSingleSourced` | The whole expression is pinned; an emptied or reordered arm fails. |
| `TestSecurityRace_MainPushRefusesScansThatNeverRan` | Same matrix for the nine scans, with `tests-race` skipped as it is on a healthy push. |
| `TestSecurityRace_OwnershipPredicateIsSingleSourced` | Both arms pinned; `tests-race` must **not** appear in the push arm. |
| `TestCIPerf_RequiredJobsAreAllNeeded`, `TestSecurityRace_RequiredJobsAreAllNeeded` | Every job named in every arm is a member of the aggregate's `needs:`. Verified failing against the `sbom` version described in §6 — a requirement that can never be satisfied refuses every run. |
| CONTROL (both files) | A pull request with everything skipped must still **approve** — the cheapest wrong fix fails here. |

Boundary / negative / malformed coverage: empty arm, missing arm, extra arm,
job absent from the `needs` map, job present but `skipped`, and the disjointness
matrix across four events × both input values. Concurrency and authn/authz
tests are N/A — this surface has no runtime concurrency and no principal.

Defect proof performed for both workflows: the pre-fix single-arm expression
was restored and the gates were observed **failing**, then the fix restored and
the gates observed **passing**.

---

## 9. What else was reviewed and why it appears safe

Beyond the delta, the following documented invariants were re-verified against
the current tree; all hold:

* `sanitizeLog` — `strings.ReplaceAll` is still the first statement (the CodeQL
  CWE-117 barrier's position is load-bearing).
* OCSP — no bare `ocsp.ParseResponse` call exists anywhere; only
  `ParseResponseForCert` (the CHAOS-65 (1) binding fix).
* No `http.DefaultClient` on any outbound product path.
* No bare `http.NewRequest` (context-less) in product code.
* `logger.Fatalf` ban holds (only comments name it).
* `internal/upstream` credential sealing: AES-256-GCM, random per-seal nonce,
  AAD binding entry id **and** authority hash, key id checked before unseal,
  every failure a bounded error that never carries ciphertext, and a failed
  read never mints a key.
* `TestWall_AuthenticatedURLIsConstructedOnlyInsideSelectors` passes — the
  authenticated proxy URL is still built in exactly two places.
* The upstream v2 red matrix (R15–R42, including the complete credential sink
  matrix) passes.
* `UIUserInfo` — the admin user API DTO exposes only `TOTPEnabled bool`; the
  TOTP secret and bcrypt hash live on the unexported on-disk record and reach
  no handler.
* Route metadata parity (C1/C1.5/C2/C2c/C4) and `configSurfaces` parity pass.

---

## 10. Residual risk

1. **`needs-verdict`'s default is still skipped-as-pass** for every aggregate
   other than the two mandatory-evidence ones — the Fast and Deep PR Gates in
   particular. Those are PR-scoped and not release evidence, but the same class
   of silent evaporation applies to branch protection. Recorded follow-up
   (CI-REDESIGN §8); tightening the shared action is its own reviewed diff.
2. **The tag path's threat-model limit is unchanged.** `require-gate.sh` is
   checked out from the *tagged* tree, so an attacker who can push an arbitrary
   tag can strip the guard. The only control is the repo ruleset restricting
   `v*` creation to the Actions bot (F3). Unchanged by this work.
3. **`cireport`'s `-repo` flag validates only that the value contains `/`.** A
   malformed value could traverse the API path (`url.ResolveReference`
   normalises `..`, so it stays on the same host and within a read-only token's
   scope). Not reachable — the value comes from `GITHUB_REPOSITORY`, set by
   Actions. Hardening opportunity, not a finding.
4. **The reporter's `trend` is advisory by design** and its regression flags are
   `::warning::` only. A misclassified run degrades advice, never a gate. The
   one hard failure — the audit-freshness verdict — is derived from
   `event=schedule` runs, not from a spoofable title.
5. **`require-success` names jobs by id in a string.** Renaming a job, or
   adding a job that is not a `needs:` member, would make the aggregate demand
   evidence that never arrives and wedge main. `Test*_RequiredJobsAreAllNeeded`
   turns both into a build failure instead.
6. **`sbom` remains unrequired on every event.** It is informational by design
   and outside the aggregate's `needs:`. A missing or malformed SBOM therefore
   still does not block a release. That is the pre-existing owner decision, not
   something this change alters — but it is now explicit rather than incidental.
