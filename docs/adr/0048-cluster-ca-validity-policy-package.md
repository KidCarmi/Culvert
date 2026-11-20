# ADR-0048: The cluster CA validity policy is owned by internal/clusterca

- Status: Proposed for review with the implementation PR (IM-013, 2026-11-20).
- Numbering: ADR-0047 is the highest merged. ADR-0040 is reserved by open
  PR #1526. No other open PR adds a file under `docs/adr/` (checked against
  every open PR head on 2026-11-20).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-013.
  Related: ADR-0002 (the cluster/HA row: "extract only a separately mapped
  state machine, not a ConfigSnapshot hub"), ADR-0038 (instance-owned state),
  ADR-0042..0047.

## Context

`cluster_ca_validity.go` (203 lines, package main) held two responsibilities:

1. **A policy.** The CHAOS-50 / register row CA-13 decision rules for the
   control plane's trust root: the validity predicate `clusterCAUsable(cert,
   now)` (strict `NotBefore`, no future-skew tolerance, unlike the inspection
   CA), the `errClusterCAUnusable` / expired / not-yet-valid sentinels, the
   kind classifier and its operator remediation text, the issuer clamp
   `clampNodeCertValidity`, and the shared 30-day renewal window. It took the
   clock as an argument and referenced no root symbol.
2. **Instance reads.** `(*clusterCA).Usable` and `Expiry`, which read the
   instance's certificate under its lock.

Production callers of the policy: `enrollment.go` (`SignCSR` refusal and
clamp, `RotateIfNeeded` window, `Info`), `controlplane_server.go`
(`clusterCAIssuancePrecondition` remediation text) and `healthcheck.go` (kind
for `/healthz`). The `clusterCA` engine itself (key material, rotation,
import, HA replication, persistence) lives in `enrollment.go` and `ha.go`,
which ADR-0002 lists as main-owned and which open PR #1528 edits.

ADR-0002 does not list `cluster_ca_validity.go`. Its cluster/HA row admits a
separately mapped, independently owned piece; a pure trust-decision policy is
that, and it is not a snapshot or composition hub.

## Decision

Move the policy (1) to `internal/clusterca` with 8 exported identifiers:
`Usable`, `ClampNodeValidity`, `UnusableKind`, `Remediation`, `RenewalWindow`,
`ErrUnusable`, `ErrExpired`, `ErrNotYetValid`. Keep (2) and the instance in
main. Root keeps `clusterCAUsable`, `clampNodeCertValidity`,
`clusterCAUnusableKind`, `clusterCAUnusableRemediation`,
`clusterCARenewalWindow` and `errClusterCAUnusable` as one-line bindings
(the error is the same value, so `errors.Is` matches either name), so no
caller and no test changed. The two kind sentinels had no reader outside the
classifier and get no root name.

Lifecycle, in one sentence: main owns the single cluster CA instance and every
call site and passes the certificate and the current time in; the package
holds no mutable state, starts no goroutines and does no I/O or logging.

Unchanged, byte for byte: every error message (operators, health probes and
`[test]` logs read them), the inclusive bounds, the strict `NotBefore`, the
kind strings used as metric/health values, both remediation strings, the
clamp result and its `clampedToIssuer` flag, and the 30-day window.

## Tests

No root test moved: every existing test of this code
(`cluster_ca_chaos_test.go`, `cluster_ca_rotation_restart_chaos_test.go`,
the enrollment and health tests) drives the `clusterCA` instance, the
enrollment RPC, `/healthz`, diagnostics or metrics, so they are integration
tests and stay root. New engine tests: a differential test against frozen
verbatim copies of the root predicate, clamp and remediation strings over a
clock matrix (exact bounds, ±1 ns, sub-second rounding, non-UTC clocks and
bounds); inclusive-bound and no-skew-tolerance pins; the kind table including
re-wrapped errors; and a mutation control showing the oracle comparison
rejects a 5-minute skew tolerance. A boundary test pins no application
imports, no `log`/`os`/`net`/`sync`, no `init`, no package variable except an
`Err*` sentinel built by `errors.New`, and the 8-name cap, with negative
controls for each.

## Consequences

The control plane's trust-root rules are testable without compiling the
application, and the inspection CA (`internal/ca`) and cluster CA policies now
sit side by side as two explicit owners whose one deliberate difference (skew
tolerance) is documented on both. A later move of the `clusterCA` engine out
of `enrollment.go` has a destination package, but that is a separate,
lifecycle-bearing change (rotation, HA replication, key-at-rest, persistence)
that needs its own map and must not overlap #1528.
