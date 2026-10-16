# Admission engine guidance

Read the [current admission contract](../../docs/agent-context/domains/admission.md) before changing or reviewing this package. It also applies to root admission/gossip/snapshot adapters; the directory boundary is not the whole dependency boundary. Keep engine ownership here and application composition in main, as [ADR-0039](../../docs/adr/0039-admission-engine-package.md) specifies.

## Conditional review rules

Report a concrete regression introduced by the change, with its reachable scenario and source/test evidence. Use these controls to avoid flagging intended behavior:

- If lifecycle/configuration changes touch ownership, check independent instances and retained local/remote/diagnostic state. Resetting a live limiter during reconfiguration loses its budget. Safe controls: permanent root type aliases are intentional; a zero limiter is supported for disabled admission/diagnostics, while active local admission requires its constructor.
- If remote publication or freshness changes, check transferred-map immutability, map-before-stamp ordering, exact expiry, future stamps and both arming flags. Safe controls: stale/missing/future broadcasts contribute zero while local limiting continues; a successful nil broadcast is fresh and clears counts; a failed RPC retains a still-fresh broadcast.
- If diagnostics change, check that read-only status/metrics do not call the episode observer or latch freshness. Safe control: an unarmed limiter reports no stale alarm while retaining receipt facts/history.
- If a filter/exemption mutator or view changes, check publication before unlock and absence of writer aliases, then preserve raw-string single-IP exemptions and shared CIDR semantics. Safe controls: canonicalized filter singles differ intentionally from exemption singles; rejected mutations that change nothing need no new view; one admin edit may publish once, while list loads use bulk APIs.
- If export/window logic changes, check absolute retained export counts, cutoff equality and upward timestamp clamping. Safe controls: export may discard expired stamps without resetting live counts; lazy growth avoids allocating every client's full configured limit.

Keep white-box tests and benchmarks beside the engine; exercise root integrations for changed composition or wire behavior. Commands and coverage boundaries are in the [verification section](../../docs/agent-context/domains/admission.md#verification), including the mandatory root-plus-admission selection for tagged benchgates. Historic benchmark numbers are not fresh results.
