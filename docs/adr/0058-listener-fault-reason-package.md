# ADR-0058: The listener fault reason rules are owned by internal/listenfault

- Status: Proposed for review with the implementation PR (IM-026, 2026-11-21).
- Numbering: ADR-0055 is the highest merged. ADR-0056 is reserved by open
  PR #1992 (IM-024), ADR-0057 by open PR #1993 (IM-025) and ADR-0040 by open
  PR #1526. No other open PR adds a numbered file under `docs/adr/` (checked
  against every open PR head on 2026-11-21).
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-026.
  Related: ADR-0002, ADR-0052 (`internal/hostpin`, the same shape: a pure rule
  the owner in main calls through a binding).

## Context

Four listeners in package main turn a bind or serve error into a bounded
reason class before it reaches the health record, the alert detail and the
operator-contract row:

| Listener | Function | File |
|---|---|---|
| Admin UI | `classifyAdminUIListenError` | `admin_ui_health.go` |
| SOCKS5 | `classifySOCKS5BindError` | `socks5_health.go` |
| Scan sidecar | `classifyScanSvcBindError` | `scan_svc_listener.go` |
| Control Plane gRPC | `classifyCPGRPCBindError` | `cp_grpc_health.go` |

Each carried its own copy of two rules:

1. **The errno classes.** `EADDRINUSE` is `port_in_use`; `EACCES` and `EPERM`
   are `permission_denied`; `EADDRNOTAVAIL` is `address_unavailable`; `EMFILE`
   and `ENFILE` are `descriptors_exhausted`. Found with `errors.As` on
   `syscall.Errno`, never by message text.
2. **The timeout rule.** `network_error` requires a `net.Error` whose
   `Timeout()` is true, because `*net.OpError` is a `net.Error` for every bind
   failure.

Three were the same switch written out three times, and the fourth expressed
the same two rules as rows of a table. The copies have already drifted once:
the timeout rule was wrong in the admin UI and SOCKS5 copies and was corrected
in both by hand (CHAOS-66), and the scan-sidecar copy, added later, states in
its comment that converging the copies "is a real improvement and deliberately
NOT done here ... Recorded as the open half."

The copies read no root name. Their only imports are `errors`, `net` and
`syscall`.

The files they sit in are listener health records, which ADR-0002 keeps in
main as probe adapters. That is unchanged: the records, supervisors, alerts,
log lines and remedy texts do not move. No decision is superseded.

## Decision

Move rules 1 and 2 to `internal/listenfault` with three exported functions:

- `ErrnoReason(err) (reason string, ok bool)`: rule 1.
- `TimedOut(err) bool`: rule 2.
- `Reason(err) string`: nil is `none`, then rule 1, then rule 2, then
  `listen_failed`. This is the whole SOCKS5 and scan-sidecar classifier.

Each listener keeps its classifier function, so no call site and no existing
test is edited:

- `classifySOCKS5BindError` and `classifyScanSvcBindError` return
  `listenfault.Reason(err)`.
- `classifyAdminUIListenError` keeps its own order: `ErrnoReason`, then its
  certificate tag, then `TimedOut`.
- `classifyCPGRPCBindError` keeps its ordered table (tags, then errnos, then
  timeout) and the table keeps one row per class, because
  `TestChaos71_CPGRPCReasonTable` walks the rows. The four errno rows now ask
  `ErrnoReason` for the class and the timeout row is `TimedOut`.

Not moved: the stage tags (`errAdminUITLSMaterial`, `errCPGRPCTLSMaterial`,
`errCPGRPCAddressPublish`) and the order in which each listener tests them.
The order differs between the admin UI and the Control Plane and is each
listener's contract (see "Found, not changed").

No class-name constants are exported. The root files, tests, runbooks and the
legacy UI spell the classes as string literals; exporting seven constants
would put the surface at ten names without removing a literal.

Lifecycle, in one sentence: there is none; a supervisor calls a pure function
once per failed attempt and owns everything that follows.

Unchanged: every verdict of all four classifiers; the class vocabulary; the
health records, alert dedup keys, `/metrics` series, log lines and remedy
texts, none of which are in the diff.

## Tests

No existing test is moved or edited. The root classifier tests
(`TestChaos57_ClassifierUsesErrnoNotStrings`,
`TestChaos66_UnrecognisedErrnoIsNotCalledANetworkError`, the SOCKS5 and
scan-sidecar class tables, `TestChaos71_CPGRPCReasonTable`) call the root
functions and stay where the functions are.

New in root: `TestListenerBindReasons_VerdictTableUnchanged` runs all four
classifiers over 2,597 errors (every errno 0..255 in four shapes, each of the
three stage tags wrapping two shapes of each errno, and the timeout and
non-errno shapes). The SHA-256 of the verdicts and the per-listener class
counts were captured by running the same test over the four root functions on
main `ef9431189` before the move.

New in the package:

- A differential test against a frozen copy of the pre-move switch over
  20,492 errors (errnos 0..4095 in five shapes plus twelve fixed shapes),
  which also requires that all seven classes occur.
- Class, first-errno-only, errno-before-timeout and timeout tables, and the
  `*net.OpError` premise check from the root CHAOS-66 gate.
- A concurrent-call test under `-race`.
- A boundary test: no Culvert import; no `net/http`, logging, I/O, clock,
  context or `sync` import; no package variable; no `init`; exported-surface
  cap of 8. Negative controls reject each.

Mutation checks, each of which fails a test: dropping `EPERM`; testing the
timeout before the errno; accepting any `net.Error` as a timeout; returning
`listen_failed` for a nil error; in root, testing the admin UI tag before the
errno, and testing a Control Plane errno row before its tags.

## Found, not changed

`classifyAdminUIListenError` tests the errno before `errAdminUITLSMaterial`.
`tls.LoadX509KeyPair` on an unreadable key file returns `*os.PathError` over
`EACCES`, which `ui.go` wraps under the tag, so the admin UI reports
`permission_denied` for it. The admin UI runbook
(`docs/operator/admin-ui-listener-recovery.md`) files an unreadable
`-tls-cert`/`-tls-key` under `tls_certificate` and gives `permission_denied`
the `CAP_NET_BIND_SERVICE` remedy. The Control Plane classifier had the same
order and was corrected to test tags first (review of #1556). The admin UI
order is preserved here because changing it changes a reported class; the
verdict table pins the current behavior so that a fix shows up as a
deliberate digest change.

## Consequences

Which errno is which class, and what counts as a timeout, are each written
once. A fifth listener calls `listenfault.Reason` and cannot reintroduce the
`net.Error` mistake. The four root classifiers are reduced to what is theirs:
the order of their own stage tags.

Two more rules are still repeated per listener and were left alone:
the doubling bind backoff (`nextCPGRPCBindBackoff`, `nextSOCKS5BindBackoff`,
`nextScanSvcBindBackoff`) and the sleep clamp that keeps a retry from
straddling the unavailability threshold (`clampCPGRPCBindSleep`,
`clampSOCKS5BindSleep`). `socks5_bind.go` is edited by open appliance PRs, so
the ladder cannot be converged without an overlap today.
