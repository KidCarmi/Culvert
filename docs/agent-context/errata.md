# Verified conflicts in the preserved guide

Baseline: main `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`. These are
source-backed explanatory corrections, not runtime changes. Original blocks
remain untouched in [the preservation map](preservation-map.json). A new task
must recheck its own revision; historical benchmarks are not current measurements.

## Default policy posture

[Original L174](history/policy-category-feeds.md#claude-main-l174-l174) says the
policy engine defaults to deny whenever no rule matches. That blanket statement
omits startup resolution: an empty configured action defaults to allow with zero
rules and deny with rules; explicit allow/deny is honored. Evidence:
[loader](../../rewrite_default_action_startup.go) and
[all-four-case tests](../../rewrite_default_action_startup_test.go).
Do not change that behavior merely to make the old sentence true.

## Admission locations and terminology

Older [admission history](history/admission-and-connection-limits.md) refers to
`security.go` as the engine. Current [ADR-0039](../adr/0039-admission-engine-package.md),
[package contract](../../internal/admission/doc.go),
[implementation](../../internal/admission/engine.go) and
[root aliases](../../admission.go) establish the current ownership boundary.
`ExportHotDeltas` returns absolute qualifying window counts without reset;
[ownership tests](../../internal/admission/security_admission_ownership_test.go)
and [wire adapter](../../cluster_ratelimit_wire.go) control interpretation,
not the old overview's “delta gossip” shorthand. Root aliases are intentional.

## Timestamp clamp direction

[Original L242](history/admission-and-connection-limits.md#claude-main-l242-l242)
and the code/test comments use “true arrival” alongside sampled/observed time.
Those reference times must be distinguished. In the
[ring implementation](../../internal/admission/engine.go), let `s` be the caller's
pre-lock sample and `r = max(s, previous newest)` the recorded stamp. Then `r >= s`:
expiry is later or equal relative to that sample. Relative to the later actual
lock/append time `a`, the recorded stamp is normally earlier or equal (`r <= a`).
Those two comparisons can coexist; do not label the true-arrival comparison as
reversed merely because the sample-based comparison has the opposite direction.

The phrase “earlier than the caller observed” is still ambiguous if “observed”
means the passed sample. The [window test](../../internal/admission/security_ratelimit_window_test.go)
feeds sampled offsets, checks ordering and the final maximum/empty-at-cutoff
behavior; it does not capture actual append/arrival times or establish a per-entry
arrival-based bound. Preserve the actual ordering/cutoff algorithm and tests.
This PR clarifies the reference frames; it does not change runtime/test comments
or claim a new runtime failure or a newly proved admission bound.

## Configuration versioning exclusions

[Original conventions](history/conventions.md#claude-main-l129-l154) broadly say
config-mutating handlers must audit then snapshot. Current
[surface registry](../../config_surfaces.go) and regression tests explicitly
exclude some mutations, including [password changes](../../auth_password_change_no_versioning_test.go),
[CDR hygiene](../../cdr_hygiene_no_versioning_test.go) and
[CDR revoke](../../cdr_revoke_rpc_no_versioning_test.go).
[Versioning triage](../../roadmap/CONFIG-VERSIONING-TRIAGE.md) supplies rationale
but contains historical inventories; use current source/tests for capture decisions.
A credential mutation must not introduce a restore path to old credentials.

## General advice versus domain exceptions

- Generic RWMutex advice does not supersede immutable views or sharded ownership
  in admission, connlimit, blocklist, logsink or metrics. Follow current owner tests.
- GUI/API parity remains the norm, with recorded startup-only/trust/preview
  exceptions already documented in [the environment source](history/run-and-environment.md).
  Do not erase either the norm or the exceptions.
- Legacy `data-view` UI conventions do not describe the React frontend. Use the
  [migration plan](../design/FRONTEND-MIGRATION-PLAN.md) and actual platform files.
- Project-map counts and “program complete” statements are pinned history. Verify
  ownership and implementation status rather than mechanically updating counts.

## Duplicates and mixed-domain blocks

[Category recovery L181](history/storage-and-durability.md#claude-main-l181-l181)
and [L183](history/storage-and-durability.md#claude-main-l183-l183) overlap but
are not byte-identical; both remain preserved.
[Freshness L182](history/admission-and-connection-limits.md#claude-main-l182-l182)
also owns DP→CP audit-queue loss history. Admission and audit routes both reference
it; one canonical owner is not one exclusive semantic category.
[Performance L238](history/admission-and-connection-limits.md#claude-main-l238-l238)
also spans transport, relay, connection counts and metrics.

## Unmerged appliance branch

PR [#1528](https://github.com/KidCarmi/Culvert/pull/1528), observed head
`72c827b7f59f4e43ff2a813241be9029f58f23a9`, contains additional instructions
and a different toolchain pin. Its guide was inspected but is not imported as
main behavior. See [rebase instructions](migration.md#branch-reconciliation).
