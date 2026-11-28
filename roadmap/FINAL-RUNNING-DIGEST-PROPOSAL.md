# Proposal: `final_running_digest` must name the verified running image, or say it cannot

> **Status: owner decision recorded 2026-11-23 (Decision 2 in roadmap/VERIFICATION-PROGRAM.md):** option C is approved; `final_running_digest` stays a registry digest; `final_running_state` and `final_running_image_id` are added. This document is the design record.
> Evidence-backed investigation for the verification program (see roadmap/VERIFICATION-PROGRAM.md); observations pinned by PRs #2020 and #2030.

Revision: `8178c19`. Module `cmd/culvert-maint`. This is a proposal, not an implementation; nothing in
the repository was edited. **[exp]** figures come from throwaway patches to a scratch copy that run the real
conformance suite (method in §6).

**Image stores.** This analysis is of the classic image store. PR #2030 runs every vector under the
containerd store too: there the 12 G7 lines disappear, because containerd RepoDigests are never empty
(the agent reports a synthetic local `culvert/proxy@sha256` reference that the rollback gate would not
accept), and container `.Image` equals the registry digest, so `final_running_image_id` (§3) equals the
digest there. The §4 harness changes apply to both stores.

Owner decision (authoritative): the field reports the ACTUAL, VERIFIED running image. When the agent
cannot establish which image is running, it reports that as unknown. It never guesses.

## 1. How the producer works today

`finalRunningDigests` (`internal/server/inline_rollback.go:168-199`) never looks at Docker. It infers the
answer from accumulator flags. The result map returns `firstOrEmpty` of it (`inline_rollback.go:227`), and
the op-log `report` line prints it (`handlers_upgrade_apply.go:379-384`). Branches:

| Line | Condition | Returns | Evidence behind it |
|---|---|---|---|
| 170-171 | `rollbackSucceeded` | `racc.runningAfterDigests` | rb_verify capture (`rollback_stages.go:124-129`), verified |
| 172-177 | `rollbackRestarted` | rollback **target** digest | none. rb_verify either did not run or contradicted the target |
| 178-182 | `restartLeftPrior` | `priorDigests` | post-failure capture with the same image id (`journal_phases.go:198-208`) |
| 183-188 | `rollbackAttempted` | `pinnedDigest` (target) | none. The comment "pull failed before any restart" is false for an rb `up` failure |
| 189-193 | `upgradeFailedPostRestart` | `pinnedDigest` (target) | none. Ignores the verify capture and a failed post-up capture |
| 195-198 | fall-through | `runningAfterDigests`, else `priorDigests` | verify capture, or capture_before when nothing was mutated |

The field is documented as "what is ACTUALLY running at op end" (`roadmap/D1.6c-inline-auto-rollback-plan.md:222`).
For a failed rollback it is documented as "captured best-effort" (`:238-240`). The code comment says
"best-effort set of digests actually running" (`inline_rollback.go:166-167`). Measured against those
documented meanings, any asserted-but-uncaptured value is a defect.

## 2. Classification of the 48 `observed.json` lines

`observed.json:4-51` holds 48 lines, all with params `prior=*`, `Same=false`. Each line's branch was
confirmed **[exp]** by instrumenting the copy (the line produced by each vector was logged).
Verdict key: (a) wrong although the agent held the truth; (b) asserted without evidence, so unverifiable;
(c) consistent with the field's type (a registry digest) but ambiguous.

| # | Root cause | n | Example (observed.json line) | Branch | Verdict | Agent has the truth? |
|---|---|---|---|---|---|---|
| G1 | Rollback restarted, rb_verify capture contradicts the target, which is still reported | 4 | `:36` up_fail_recreated -> rb ok_stale -> rb_verify=mismatch, rep P / act T | 172-175 | (a) | **Yes.** `racc.runningAfterDigests` is set before the mismatch (`rollback_stages.go:129`). It is copied to acc only on success (`inline_rollback.go:128-131`), and 174 prefers the target anyway |
| G2 | Rollback restarted, rb_health fails, rb_verify skipped (`inline_rollback.go:112`) | 4 | `:4` health_gate=fail -> rb ok_stale -> rb_health=fail, rep P / act T | 172-175 | (b) | **No.** No capture after the rollback `up` |
| G3 | Rollback failed before its `up` (rb_pull fail / rb tag_fail); verify capture shows P | 4 | `:18` ok_stale -> verify=mismatch -> rb_pull=fail, rep T / act P | 183-187 | (a) | **Yes.** Verify capture (`handlers_upgrade_apply.go:418`). No `up` ran afterwards (a tag failure aborts before `up`: `rollback_stages.go:39-40,52-58`) |
| G4 | Rollback `up` failed (up_fail_recreated / up_fail_stale); the target is still asserted | 10 | `:6` health_gate=fail -> rb_restart=up_fail_recreated, rep T / act P | 183-187 | (b), and wrong on all 10 | **No.** An `up` failure is indeterminate (`rollback_stages.go:40-41,46-47`), and nothing is captured afterwards |
| G5 | Post-restart failure, rollback skipped/disabled; verify capture shows P, target reported | 6 | `:30` ok_stale -> verify=mismatch, prior=valid rb=false, rep T / act P | 189-192 | (a) | **Yes.** Verify capture (`handlers_upgrade_apply.go:417-418`; for nodigest, `runningAfterID`) |
| G6 | Stack down before the upgrade; after `up` there is still no container, and the target is asserted | 8 | `:40` restart=up_fail_stale, prior=down, rep T / act none | 189-192 | (b) | **Partly.** The post-up capture (`journal_phases.go:147`) or the realign capture (`:198-201`) FAILED, and that failure is discarded. "No container" cannot be told apart from "capture error" (`runner/capture_running.go:150-152`, untyped error) |
| G7 | Prior image has no RepoDigest, reported as `""` | 12 | `:8` pre_backup=fail, prior=nodigest, rep none / act P; `:44` restart=up_fail_stale, prior=nodigest | 195-198 (8), 178-182 (4) | (c) | **Yes.** The config id is in `priorImageID` (`handlers_upgrade_apply.go:226`), and realign proved it equal (`journal_phases.go:205`). The field cannot carry it |

Totals: 48 = 4+4+4+10+6+8+12. By branch: 172-175 = 8, 183-187 = 14, 189-192 = 14, 195-198 = 8, 178-182 = 4.

**`ok_stale` dependence.** 26 lines need the unobserved `ok_stale` outcome: G1, G2, G3, G5, G4's G/H rows, and
G6's D rows. The other 22 are reachable under real-Docker semantics: G4 rb `up_fail_recreated` (6), G6
down + `up_fail_stale` (4) and G7 (12).

**The list understates the problem.** In the **[exp]** run, 68 vectors have no capture after their last `up`.
In 46 of them the inferred value happens to match the fake world, so they are absent from `observed.json`.
Examples: `health_gate=fail -> rb_health=fail` reports P with no post-rollback capture, and
`verify=capture_fail -> rb_restart=up_fail_stale` reports T. These are (b) as well. Note also that the
vector deduplication (`lifecyclemodel/vectors.go:277-280`) collapses equivalent paths. For example, G7's
pre-restart rows appear only with rb=true.

## 3. Proposed production correction

### Semantics (result payload of `upgrades.apply`)

- `final_running_state` (new string): `verified` (an *evidence capture* established the image) or
  `unverified` (none exists). Later, optionally, `not_running` (a capture proved there is no proxy
  container); that needs a typed runner error, so it is not in phase 1.
- `final_running_digest` (existing, unchanged type): the bare `sha256:` of the evidence capture's first
  RepoDigest. It is `""` when the state is not `verified`, and also when the verified image has no
  RepoDigest.
- `final_running_image_id` (new string): the evidence capture's config digest (`RunningImageID`), or `""`
  when not verified. This is how a nodigest image is represented. The config id must NOT go into
  `final_running_digest`. That field is compared with `upgrade_digest`/`rollback_digest`
  (D1.6c plan `:230,:234`), and a config digest "is NOT directly comparable" to a registry digest
  (`server.go:125-129`). The name matches `/v1/status` `running_image.image_id` (`server.go:129`).
- **Evidence capture**: the most recent successful `CaptureRunningProxyImage` with no `docker compose up`
  invocation after it, whatever that `up`'s exit status. `docker tag`, pull and backup do not recreate the
  container. Assumption: the shipped `cli` service has no `depends_on` (`docker-compose.yml:243-271`), so
  `compose run --rm cli` (`runner/templates_d16b.go:193`) does not touch the proxy.

### Changes

1. Accumulator (`handlers_upgrade_apply.go:175-198`): add `evidence{ok, imageID, digests}`, a `stale` bool,
   `noteCapture(id, digests)` and `noteUp()`.
2. Record every capture the flow already makes (no new Docker calls): `capture_before`
   (`handlers_upgrade_apply.go:219-227`); the restart post-up capture (`journal_phases.go:147`, today id
   only); the realign capture (`journal_phases.go:198`, today compare only); verify
   (`handlers_upgrade_apply.go:411-418`); rb_verify (`rollback_stages.go:124-129`, via an optional hook
   on `rollbackAccumulator` that also passes the image id).
3. Mark a mutation in `tagAndUp` immediately before `ComposeUp` (`rollback_stages.go:61`). Use an optional
   `onUp func()` callback so the shared core stays caller-agnostic. Standalone `POST /v1/rollbacks` passes
   nil, so its behaviour is unchanged.
4. **Recommended (option C):** in the existing `report` stage (`handlers_upgrade_apply.go:373-388`, which runs
   always via ContinueOnError), make one read-only best-effort capture **only when** the evidence is stale
   or missing. If it fails, the state is `unverified`. On operation timeout the context is already dead
   (`ops/orchestrator.go:304-310`), so the state is correctly `unverified`. The stage name and stage list
   stay unchanged. **Option B** is steps 1-3 without step 4.
5. Replace `finalRunningDigests` (`inline_rollback.go:168-199`) with a pure function over the evidence. All
   inferential branches go: 172-177 (target assumed), 178-182 (replaced by the realign capture itself),
   183-193 (`pinnedDigest` assumed), and the 198 fallback. The `report` summary
   (`handlers_upgrade_apply.go:379-384`) prints `final_running=<digest|-> image_id=<id> state=<state>`.
   `restartLeftPrior` stays, because AGT-002's tag realignment uses it.

### Effect per group (**[exp]**, fake world)

| Group | Option B (no new Docker calls) | Option C (B + conditional final capture) |
|---|---|---|
| G1, G3, G5 (14) | verified, correct | verified, correct |
| G7 (12) | verified, digest `""`, image_id = P | same |
| G2, G4 (14) | unverified | verified, correct |
| G6 (8) | unverified | `""` + `unverified` (today); `not_running` with a typed runner error |
| Not listed today (46) | **unverified** (an information regression) | verified, same value as today |
| Misreports / unverified overall | 0 / 68 | 0 / 0 (given that fake captures succeed) |

Recommendation: option C. Option B honours the owner rule, but it reports `unverified` for common
real-Docker outcomes where a single read-only capture settles the question. An example is a rollback
whose health gate failed (`inline_rollback.go:112` skips rb_verify).

## 4. Compatibility analysis

- **Wire shape.** `result` is a free-form `map[string]interface{}` (`internal/ops/ops.go:63`). Two new
  string keys are additive. `final_running_digest` keeps its type and key.
- **Changed values of the existing field:**
  - Corrected values: G1, G3, G5.
  - `""` replaces a value only when no capture can be taken. Under option C this is a real capture failure:
    daemon down, or timeout. Under option B it also covers the 68 stale paths.
  - The value stays `""` for nodigest, but `final_running_image_id` now carries the id.
  - A consumer must read `final_running_state` before treating `""` as meaningful.
- **In-repo consumers.** No production reader exists:
  - The root dispatcher reads only the op `state` (`release_dispatch_exec.go:669-678`) and verifies through
    `/v1/status` repo_digests (`:626-638`).
  - The root `/api/backups/operations/{id}` passes `result` through verbatim (`api/openapi/openapi.yaml:1230-1249`,
    `additionalProperties: true`). It returns 404 for anything that is not a backup op
    (`backups_api.go:434-440`), so upgrade results never leave through the root API.
  - `frontend/src`, `static/` and the CLI have no references. Only tests read it: `inline_rollback_test.go:107`,
    `pinned_tag_consistency_test.go:148,181,226,251,269`, `model_conformance_test.go:452`.
  - **[exp]** With steps 1-4 applied, `go test ./internal/server/` still passes.
- **OpenAPI and versioning.** The agent's `/v1` API is not in `api/openapi/openapi.yaml`, which is what
  `docs/api/API-VERSIONING-POLICY.md:5-6` versions, so the oasdiff gate (`:23-37`) is not triggered. By
  analogy, new optional response fields are MINOR (`:17-19`). The semantic change to an existing field is
  invisible to oasdiff. It needs a CHANGELOG `[Unreleased]` entry (`CHANGELOG.md:8`). That entry must
  correct the AGT-002 note at `CHANGELOG.md:725`, which describes an inferred value. External scripts on
  the agent's UDS socket are an unknown population: flag them in the release note.
- **Prose to update:** `roadmap/D1.6c-inline-auto-rollback-plan.md:222-240,365-370,394-395` ("best-effort"
  becomes verified-or-unverified), `PRODUCTION-FAILURE-MODE-AUDIT.md:125` (F-06),
  `test/lifecycle-conformance/README.md:92-97` (open question answered), `RISK-022…plan.md:208`.
- **Contracts** (`contracts/registry.yaml`). `contractcheck impact` will list AGT-003, because
  `inline_rollback.go` is under its `code` (`:428-445`). It will also list AGT-002, because
  `journal_phases.go` and `rollback_stages.go` are under its `code` (`:401-426`). Neither invariant changes
  (tag placement and target selection are untouched), so no `amended` record is needed, and their
  registered tests must stay green. **Propose a new entry, AGT-006**:
  - Invariant: "An upgrade's reported final running image is one the agent observed after its last
    container recreate attempt; otherwise the result says it is unverified."
  - `status: enforced`, `owner_approved: false` (the workflow forbids setting it: `product-contracts.md`
    step 6); code `inline_rollback.go`, `handlers_upgrade_apply.go`; tests from §5.
- **Conformance baselines:**
  - `observed.json` and its schema (`lifecyclemodel/observed.go:18-23`) gain a second list, e.g.
    `final_running_unverified`. The harness (`model_conformance_test.go:452-458`) stops counting
    `state=unverified` as a misreport. It compares `role(final_running_digest)`, falling back to
    `role(final_running_image_id)` when the digest is `""`; `role()` already maps the config ids,
    `model_conformance_test.go:84-95`.
  - Expected drift: the misreport list goes 48 → 0 under both options. The unverified list is 68 under B
    and 0 under C.
  - `baseline.json`: B causes no drift (**[exp]**: 0 model mismatches; the Cmds are unchanged). C adds a
    trailing `capture` to 38 apply vectors (**[exp]**: 38 MISMATCH lines, Cmds only). For C,
    `vectors.go:commands` (`:126-152`) must emit `capture` for `pcReport` when the model's evidence is stale.
    That needs a new `State` field, so the state-space size drifts too. The crash and reconcile suites are
    unaffected (**[exp]**: pass).
  - The mutation-campaign figures (`README.md:198-205`) stop being comparable.
- **Downgrade / persistence.** Nothing is persisted; journal records (`journal_phases.go:41-50`) untouched.

## 5. Tests to add

Unit tests go in `internal/server`, untagged, so they gate. Use the `startApplyRig`/`modelRig` fakes.
1. Success: `state=verified`, digest equals `upgrade_digest`, and image_id is set.
2. Rollback success: digest equals `rollback_digest`. Extend the checks map at `inline_rollback_test.go:100-108`.
3. G1: rb_verify mismatch reports the captured T, never the target.
4. G3: rb_pull fails after a verify mismatch; reports the verify capture. Extend `TestUpgradeApply_InlineRollback_PullFails`.
5. G4: rb `up` fails after recreating. Under C this is verified P; under B it is `unverified` with digest `""`.
6. G7: prior without RepoDigest. Covers both pre-restart failure and the realign path: `verified`, digest
   `""`, image_id equals the prior config id.
7. G6: stack down and `up` fails: `unverified` and digest `""`. Never the target.
8. C only: the final capture fails, giving `unverified`. An operation timeout during rollback gives `unverified`.
9. Standalone rollback is unchanged: a nil hook, and the existing `handlers_rollback` tests.
10. A table test of the pure evidence function: capture/up sequences in, state/digest/id out.

Conformance:
- Make the harness change from §4 and regenerate `observed.json` (the drift is reviewed).
- For C, update the model and regenerate `baseline.json`.
- Better still, add `FinalState` to `ApplyExpectation` (`vectors.go:48-58`), so the model predicts the
  field and every vector checks it, instead of relying on an observation list.

## 6. Residual risks and uncertainty

- `verified` means the agent observed the image after its own last `up`. An external actor (restart
  policy, OOM, operator) can change it later. A crash-looping container still reports its image.
- RepoDigests are best-effort (`runner/capture_running.go:109-113`). If an image inspect fails, a registry
  image looks like nodigest. That is acceptable, because `image_id` is authoritative.
- With several RepoDigests, `firstOrEmpty` takes element 0. On containerd the local alias sorts first
  (`inline_rollback.go:31-34`), but it carries the same bare digest (per the concurrent harness's model).
- Option C adds at most three read-only commands (`ps`, container/image inspect, existing templates), only on stale paths.
- `not_running` needs a typed "no proxy service" error. Today it is an untyped `errors.New`
  (`capture_running.go:152`). Do not string-match it.
- The `cli`-has-no-`depends_on` assumption holds for the shipped compose file only. Operator overrides
  could differ. To be conservative, also treat `pre_backup` as `noteUp()`; under C that costs one capture.
- The **[exp]** numbers come from the fake Docker world. In it a fault fires once, so the C-stage capture
  always succeeds; on a real host the same outage would also make it fail, giving `unverified`. That is
  correct, but less informative.
- **[exp] method:** HEAD copied to a scratch directory;
  steps 1-3 (B) or 1-4 (C) patched in, emitting `exp_*` keys beside the untouched field and logged by the
  harness. Run with `go test -tags lifecycle_conformance ./internal/server/ -run TestModelConformance` (go1.25.0).
