# Review a Culvert change

Use for an explicit code review or change-readiness assessment. Keep the review proportional to the requested scope; this is not an automatic audit for every question or edit. For architectural advice, also consult the [Engineering Constitution](../../engineering/ENGINEERING-CONSTITUTION.md) as an advisory charter without replacing an authorized implementation task with that role.

A review may read beyond changed lines to establish impact. It does not authorize unrelated edits, posting comments, approving a PR, pushing, merging, publishing, or changing permissions. Report findings in the requested destination and obtain any separately required authorization for external actions.

## Establish the contract and scope

1. Record the requested review scope, base/head revisions, and whether the task is review-only or also permits fixes. Inspect the full diff, including renames/deletions and generated or instruction files. Do not treat unrelated working-tree changes as authored by this task.
2. Read applicable root and scoped guidance. Use the [context index](../README.md) for ownership, current contracts, and selected historical regressions. History explains decisions but may contain superseded locations or claims; consult current sources and errata before turning one into a finding.
3. State the intended behavior and affected invariants from implementation, tests, and the task. Trace root composition/adapters as well as internal engines. Prioritize source code, tests, CI, configuration, deployment, then documentation; identify a conflict instead of choosing the most emphatic prose.

## Investigate consequential failure paths

Follow the changed data or state through callers and lifecycle boundaries. Read the relevant files yourself when a conclusion depends on them; a worker summary alone is not evidence. Select the questions that fit the change:

- Ownership and lifecycle: who constructs and owns mutable state, which instance can observe it, who starts/cancels/joins work, and what happens at shutdown, reload, restart, or partial construction? Internal engines must not regain main's globals or service wiring.
- Concurrency and publication: can an input alias mutate published state, does a snapshot preserve its promised consistency, are lock ordering and cancellation safe, and can a read-only endpoint mutate diagnostic history? Existing immutable views and sharded locks can be intentional; a general mutex preference does not override the local contract.
- Error and durability paths: what happens before/after persistence or commit, on retries or partial failure, and across backup/restore or upgrade? Follow actual production wiring, not just a helper unit test.
- Security and compatibility: identify the reachable caller, trust boundary, auth/role/CSRF enforcement, input normalization, outbound guard, supported wire/persistence format, and observability consequence. Check default, disabled, explicit override, and documented break-glass states rather than assuming every subsystem has one universal posture.
- Verification integrity: do tests exercise the claimed path without skips or vacuous fixtures? Do classifiers trigger the right jobs on both sides of a rename? Do aggregate verdicts reject missing or failed required evidence? Are generated artifacts consistent with their source?

For root adapters, inspect both the adapter and its owned package contract. For example, core IP/rate admission spans `internal/admission` and root startup/snapshot/protocol wiring. MCP execution admission belongs to `internal/mcp/execution`; sharing the word "admission" is not evidence that its lifecycle or fairness rules are the same.

## Validate candidate findings before reporting

For each candidate, establish a concrete input, caller, or state transition that reaches the changed behavior, the violated supported contract, and its user/operator consequence. Identify the smallest useful changed-file location and supporting source/test paths. Compare with the base when needed to distinguish a regression from a pre-existing issue.

Make a separate validation pass that attempts to disprove the candidate: trace guards and callers, look for a deliberate safe exception, inspect existing tests, and run a focused reproducer when practical. For consequential or ambiguous candidates, use an independent reviewer when available and have them verify the raw evidence rather than endorse the first explanation. Give reviewers distinct questions, not duplicate broad audits; there is no fixed reviewer count. The lead resolves disagreements and checks critical evidence. If independent validation or reproduction is unavailable, state the material uncertainty and avoid presenting an unsupported suspicion as a confirmed bug.

Useful safe counterexamples include:

- Root aliases and thin adapters can be the intended composition boundary, not an incomplete extraction. [ADR-0039](../../adr/0039-admission-engine-package.md) explicitly keeps root admission adapters.
- Stale or absent remote admission counts contribute zero while local enforcement continues. That documented local-only degradation is not disabling the limiter. A successful empty broadcast can be fresh and intentionally clear old remote counts; check [`freshness.go`](../../../internal/admission/freshness.go) and its tests.
- Configuration/cluster toggles retain admission accounting. A proposal to reset state for "clean initialization" can be the bug. `ClusterFreshness` derives read-side status; `ObserveClusterFreshness` advances episode history. A read-only endpoint need not advance those episodes.
- Documented startup-only, crypto-material, preview, or break-glass settings may have explicit GUI-parity exceptions. Verify the actual deferral and read-only status surface before reporting a missing UI as a violation.
- A default rule cannot be inferred from an old blanket default-deny statement. [`rewrite_default_action_startup.go`](../../../rewrite_default_action_startup.go) and its tests distinguish empty configurations with zero rules from configurations with rules, and honor explicit settings.
- Report-only diagnostics and intentional C2 fallback states are not enforcement failures merely because they do not reject a request. Check the actual route, middleware, handler-level defenses, and pinned tests before making the security claim.

Do not report linter/formatting noise, preference-only refactors, speculative misuse without a reachable supported scenario, or unrelated pre-existing issues as introduced defects. Surface an independently verified serious pre-existing issue separately if it matters to the requested assessment. Do not suppress a real bug merely because a tool could also detect it.

## Assess verification and readiness

Use [verification.md](verification.md) to evaluate the chosen checks against the affected contracts. Root tests do not cover the separate maintenance module or frontend; ordinary tests do not cover every tagged gate. Inspect actual results and the tested revision. Do not convert "tests were requested," "job started," a skipped prerequisite, or a green focused test into a claim that required CI passed.

For instruction-routing changes, get a fresh independent pass over current-source accuracy, missing root-adapter routes, eagerly loaded history, skill triggers and canonical reads, lost preserved knowledge, and accidental authority expansion. Include a scenario that should trigger guidance and an adjacent safe/unrelated scenario that should not. Distinguish static structural validation from actual Codex, Claude, and hosted-review loading evidence.

## Deliver a useful review

Lead with confirmed actionable findings, ordered by consequence. For each, provide the location, concrete triggering scenario, expected versus observed behavior, impact, and evidence sufficient to check it. Keep the explanation concise and propose a minimal correction only when supported.

If no findings survive validation, say so and identify material verification gaps or residual risks. Keep unresolved questions separate from findings. For a readiness request, report scope assessed, verification performed, current aggregate CI state, and blockers. A favorable assessment is not permission to approve, merge, or publish.
