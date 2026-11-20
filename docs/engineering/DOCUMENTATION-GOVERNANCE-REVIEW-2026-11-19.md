# Documentation governance review 2026-11-19

Scope: checked-out `main` at `491b963`, focused on product changes merged since the
2026-11-17 review. Point-in-time record; not a source of truth for behavior.

## Finding (High): no runbook for audit and request log persistence

- **Problem.** `6c1fef1` (audit) and `72962c8` (request log) made a configured log file that
  could not be opened at startup recover by itself, without a restart. The two logs recover
  differently: the audit log writes the entries recorded meanwhile (up to 500) and adds an
  `audit.persistence.auto_open` entry; the request log does not write them. That difference
  appeared only in the CHANGELOG and in the `OperatorAction` text of two Diagnostics rows. No
  operator guide covered the two JSONL files at all: their flags and `config.yaml` keys, the
  single-archive rotation, the `audit_log_persistence` / `request_log_persistence` rows, the
  `/api/stats` fields, or the write-error counters. `siem-feed-delivery.md` covers only the
  syslog copy. `IDENTITY-AND-ACCESS-DEPLOYMENT.md` says only to enable `-audit-log`.
- **Implementation evidence.** `observability_startup.go` (startup open and arming),
  `observability_startup_config.go` (flag-over-key precedence, 100 MB request-log default),
  `audit_persist_retry.go` and `request_log_persist_retry.go` (10 s doubling to 2 min plus
  25% jitter, no attempt limit, log lines), `internal/audit/deferred.go` (`rotateMaxMB = 50`,
  backfill bounded to `MaxRing`), `internal/reqlog/deferred.go` (no backfill),
  `internal/fileutil/rotating.go` (one `.1` archive), `diagnostics.go`
  `checkAuditPersistence` / `checkRequestLogPersistence`, `ui_config.go` (`/api/stats` fields,
  `?source=file`), `storage_health.go` (audit write failures feed `storage_write_failed`),
  `internal/reqlog/persist.go` (first failure logged, rest counted).
- **Why it matters.** A compliance auditor or on-call operator who sees
  `audit_log_persistence: fail` cannot find out from the docs whether entries were lost, how
  many, or where the gap ends in the file. A fault after a successful open shows `ok` on the
  row, and nothing said which counter to alert on.
- **Who is affected.** Operators responsible for audit retention and incident evidence.
- **Canonical source.** The code above. The new page links to `siem-feed-delivery.md` and
  `request-history-recovery.md` and does not repeat what they cover.
- **Change.** New `docs/operator/audit-and-request-log-persistence.md`, plus an index entry in
  `docs/operator/README.md`. Effort: small. Risk: low (documentation only).

## Checks performed

- Environment-variable constants in non-test Go were compared with the tracked Markdown and
  YAML. Every operator-facing variable is documented; the only unmatched names are
  `cmd/feedgen` CI inputs and GitHub Actions variables.
- Admin API routes are covered by the generated `docs/api/API-INVENTORY.md` and OpenAPI bundle
  under the route-coverage gate. Hand-written route documentation was not re-audited.
- Commits since 2026-11-10 that changed `feat`/`fix`/`security` behavior without touching
  operator docs were screened. The audit and request-log changes were selected as the
  operator-visible gap. The others (policy IP-literal matching, scan-cache eviction, CDR,
  install script) were not re-audited in this pass.
- `python3 docs/agent-context/check.py` passes.

## Not assessed / documentation debt

- The `audit_log_persistence` `OperatorAction` says Culvert retries "at least every 2
  minutes". With the 25% jitter the cap is about 2.5 minutes, which the
  `request_log_persistence` row (same schedule) states. This is product text in
  `diagnostics.go` and is left to a code change.
- Carried: no catalog of Diagnostics row codes, and none of the subscribable alert events.
- Carried: the GAP-PKI-05 wording is partly stale (2026-11-16). It is owner-scoped.
