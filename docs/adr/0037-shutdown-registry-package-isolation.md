# ADR-0037: Instance-owned shutdown execution in internal/shutdown

- Status: Proposed for review with the implementation PR (2026-09-30).
- Baseline: `1f7f42c6937847c26f29387dcaae6685e356a9b0`, freshly fetched origin/main.
- Numbering: checked both `docs/adr/` and `docs/support/rfc/`, the shared
  namespace contract test, and the open-PR file inventories.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), a new program;
  ADR-0002 remains complete. Related: ADR-0003 and RUNTIME-OWNERSHIP S5.

## Decision recorded before the move

Extract the ordered hook registry, per-phase watchdog arithmetic, panic containment,
and partition operation from `runtime_shutdown.go` into `internal/shutdown`.
The registry already owns its hook list, mutex and run-once state. Make its grace,
minimum hook slice and diagnostic sink immutable construction dependencies, so
independent registries and tests never change process-global timing or logging.
Use the existing 3-second grace and 1-second minimum as defaults. Partitioned
registries inherit the same settings. Keep one implementation.
The diagnostic sink is a borrowed callback: its caller owns its lifetime and
synchronization when several registries share it. Main supplies its existing
concurrency-safe logger and keeps the same close ordering.

The production owner remains `main`: it constructs the early/late registries,
supplies its logger, registers the real service callbacks and runs the existing
three-phase sequence. Keep phase budgets, service order constants, signal handling,
gRPC force-stop, tunnel drain and persistence closers in main. No persistence or
configuration format changes, new service, background loop, or general DI framework.
Hook contexts and watchdog timers retain their current cancellation ordering.
A hook that ignores cancellation may outlive its watchdog; Go cannot terminate it.
This existing shutdown-only behavior must remain explicit and test fixtures must
release their blocked hooks.

The package exposes construction, Register, RunAll, PartitionAt and a copied
name/order inventory for wiring diagnostics. It must not expose mutable hook
storage or executable callbacks through that inventory. No setters or package
singletons. Default constants are immutable. No root compatibility implementation;
main may retain a type alias and a construction helper, as composition only.

## Test ownership and safeguards

Move registry contract and synthetic watchdog tests with their assertions and names.
Keep real hook registration/order, persisted audit/cluster flush, signals, tunnel
drain, gRPC and container-envelope coverage in main. Split mixed CHAOS-56 files by
behavior, not filename. Replace timing-global fixtures with per-registry options.
Retain fail-fast nil-hook coverage and root production registration coverage.
Add independent concurrent owners, partition configuration propagation, immutable
inventory and bounded hook-completion checks where the old suite lacks them.

The non-root CI lane discovers packages with `go list ./...`; no allowlist edit or
new lane is needed. Compare old/new source and binary test inventories explicitly.
Keep all coverage floors, release protection and determinism/race execution intact.
No wall-clock CI improvement is assumed: root compilation, focused iteration,
root execution and whole-gate timing are separate measurements.

## Alternatives

IP filtering/rate limiting has a larger movable engine, but shares CIDR internals,
cluster singleton state and mixed white-box integration tests; it needs a separate
ownership design. Policy/draft extraction still carries the rule vocabulary,
security load gate and cross-store durability protocol; ADR-0026 gives a single
evaluator but does not dissolve those dependencies. MCP spool KDF dominates CPU in
the recorded profile, but it is already packaged; reducing sealing work or sharing
fixtures is a separate security/isolation decision, not this extraction.
