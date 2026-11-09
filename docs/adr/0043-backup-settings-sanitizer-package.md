# ADR-0043: The backup settings sanitizer is owned by internal/upstream/backupstrip

- Status: Proposed for review with the implementation PR (IM-004, 2026-11-09).
- Numbering: ADR-0042 is the highest merged; no open PR touches `docs/adr/`.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-004.
  Related: ADR-0002, ADR-0041, ADR-0042 (extraction pattern).

## Context

`upstream_backup_strip.go` (517 lines, stdlib only, no root dependency) removed
sealed upstream credentials from an `admin_settings.json` body before archiving
and counted entries a restore would boot as requiresReplacement. It has no
state, I/O or logging, but twelve Codex-round regression files compiled the
whole application to test it. Its two callers are `backup.go` (sanitize before
packing) and `restore.go` (dry-run count).

## Decision

Move it to `internal/upstream/backupstrip` with two exported identifiers:
`Strip(body) (sanitized, stripped, err)` and `CountRequiringReplacement(body)`.
The code, comments and refusal messages move unchanged. Main keeps reading the
file, the manifest `credentialsOmitted` assertion, the stderr/audit reporting
and the error wrapping at both call sites. No root alias is kept.

- Tests: 15 engine-only functions moved with names and assertions unchanged
  (r8 x3, r9, r10, r11, r12, r13 BackupStrip, r14 x2, r15-r19, one each). The five
  neighbouring non-sanitizer tests (Normalize/Create/Loader evidence) stay in
  their root files. Existing root backup/restore portability tests still cover
  the real composition.
- Boundary: package variables are limited to a named allowlist of read-only
  error sentinels and key tables; no application import, `os`, `log`, or `init`.
  Negative controls prove the checker detects each.

## Consequences

No behavior, archive-format or fail-closed change. The sanitizer's security
matrix runs with `go test ./internal/upstream/backupstrip` without the
application. Only the sanitizer moved; the settings loader stays in main.
