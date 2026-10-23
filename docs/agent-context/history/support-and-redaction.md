# Preserved source: Support And Redaction

Historical evidence from main `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`, not current architectural authority.
Read the [current task routes](../README.md) and [verified errata](../errata.md) first.
No benchmark, status, location or instruction in these blocks is independently revalidated by moving it here.
Links inside preserved text retain their original spelling and source-root context; use each pinned source link to follow original references.
Do not import this file into startup instructions.

## Topics

- [Supportability framework (CSF, appliance track M0–M5 shipped)](#claude-main-l229-l229)

<a id="claude-main-l229-l229"></a>

## Supportability framework (CSF, appliance track M0–M5 shipped)

[Original lines 229–229](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L229-L229) · `claude-main-L229-L229`

<!-- BEGIN preserved-block: claude-main-L229-L229 -->
- **Supportability framework (CSF, appliance track M0–M5 shipped)**: `internal/support` (collector registry, runner with isolation/timeout/budget/panic-recovery, manifest builder) + `internal/redaction` (fail-closed `Redactor.Struct`, `config_surfaces.go`-backed classification) produce redacted, tamper-evident `csb/1` support bundles — standard or scoped to an `IncidentScope` (`tls`/`upstream`/`policy`/`storage`/`dns`/`cluster`/`scan`), at a bounded capture level (L1–L2), with plain, passphrase-encrypted, or recipient-public-key sealed (true E2E, X25519) export/download and a `case_id`-keyed lifecycle (pending → admin-approved → ready). On-appliance `diagnose cluster`/`diagnose config` verbs report live HA/cluster posture and config-snapshot validity. Admin surface: `/api/support/*` + `/api/diagnose/*` (viewer read-only, operator collect/diagnose/download, admin create/approve/set-capture-level) + the Support SPA panel; recovery one-shot `culvert --support-bundle <out>` needs no running server. The appliance-side M6/M7 slices (secure-upload queue `internal/supportupload` + `support_upload_queue.go`; consent-gated telemetry collection `support_telemetry_*`, no network sender) have since shipped; cloud-side analysis, correlation, and the TAC receiving tier remain design-only — see `docs/support/README.md`. See `docs/operator/support-bundles-and-diagnostics.md` for the operator runbook.
<!-- END preserved-block: claude-main-L229-L229 -->
