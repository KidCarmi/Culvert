# Documentation governance review 2026-11-14

Scope: checked-out `main` at `de0b6d1`, focused on product changes merged since the
2026-11-13 review (`feb11e8..de0b6d1`, 12 non-merge commits). Point-in-time record; not a
source of truth for behavior.

## Finding (High): the Operations Guide said Diagnostics never touches disk or ClamAV

- **Problem.** `docs/OPERATIONS.md` §1 described `/api/diagnostics` as "Side-effect-free:
  reading it never opens files, dials sockets, or pings ClamAV." `8cb5693` added the
  `clamav_scan` row, whose check can start a ClamAV ping. The "never opens files" half was
  already wrong before that commit. The new row itself had no operator documentation outside
  `CHANGELOG.md`.
- **Implementation evidence.**
  - `checkClamAVScan` (`diagnostics_clamav_scan.go`) calls `Scanner.ClamAVStatus`
    (`internal/secscan/secscan.go`). A fresh observation (`clamStatusTTL`, 30 s) is a memory
    read. A stale one starts one single-flight probe and the caller waits up to
    `clamStatusWait` (750 ms), then answers from the previous observation.
  - `summarizeLatestConfigVersionAt` (`diagnostics.go`) runs `os.ReadDir` and reads the latest
    envelope on every call. `configver.Store.Integrity` caches its full scan.
  - `checkPlaintextKeyBackups` (`keyatrest_diagnostics.go`) runs `os.Stat` per candidate.
  - `readRosterDurabilityFacts` → `sharedRosterProbe` (`roster_probe.go`) opens the roster file
    read-only, cached, with a bounded wait.
  - The row is withheld when ClamAV is unconfigured, answering, not yet observed, or when
    `globalRemoteScanner` is enabled (`diagnostics_clamav_scan_test.go`). `/ready` reports the
    same daemon state as a gating `fail` (`healthcheck.go`).
- **Why it matters.** An operator sizing a monitoring poll, or explaining ClamAV connections
  and config-version reads that coincide with Diagnostics reads, was told they cannot happen.
  An operator who sees `clamav_scan` had nothing stating that content is being forwarded
  without an antivirus verdict or when the row clears.
- **Who is affected.** Operators who poll Diagnostics, and operators running ClamAV.
- **Canonical source.** `docs/OPERATIONS.md` §1 "`/api/diagnostics` — operator contract". The
  scan runbook links to it and does not restate it.
- **Change.** The bullet now states the read-only guarantee and lists the bounded I/O. A
  `clamav_scan` entry was added beside the other row descriptions. The `storage_path` sentence
  "no disk I/O happens at request time" is scoped to that row. Step 2 of the triage list in
  `docs/operator/scan-capacity-and-timeouts.md` links to the row. The two contract comments in
  `diagnostics.go` that carried the same claim were corrected (comments only; no code change).
  Effort: small. Risk: low.

## Checks performed

- `e3bb4b6` (CHAOS-119), `2644508` (per-node re-enrollment alert), `4240dd6` (`env_put`) and
  `fd51f5b` (IM-007 extraction) were read for operator-visible changes. Each is recorded in
  `CHANGELOG.md`; no operator page was found that contradicts them.
  `docs/operator/cluster-state-recovery.md` was updated in `4dd2b8a`.

## Not assessed / documentation debt

- `docs/support/ANALYSIS-MODEL-DECISION.md`, `docs/support/COLLECTOR-CONTRACT.md` and
  `docs/adr/0028-supportability-framework-collector-model.md` describe `buildOperatorContract`
  as side-effect-free. They are design records; the support-bundle collector calls the same
  function, so a bundle capture can also start the ClamAV status probe. Not changed here.
- Whether any Diagnostics check other than the four listed performs request-time I/O was not
  exhaustively audited. The new text lists the accesses that were verified and does not claim
  the list is complete.
- Carried: no catalog lists Diagnostics row codes (`upstream_egress`, `upstream_pool_config`,
  `memory_backstop`, `config_versions_integrity`, `ui_tls_fallback_http` remain undocumented).
- Per-option configuration-reference completeness was not re-audited.
