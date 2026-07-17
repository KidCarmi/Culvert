# tac-platform — moved

The executable TAC product code that formerly lived here has been **extracted,
with history preserved, to its own repository**:

> **https://github.com/KidCarmi/tac-platform**

This directory is intentionally a pointer stub. Culvert (the on-prem appliance)
does **not** depend on any `tac-platform` internal Go package; the two
communicate only across the versioned wire contracts documented in
[`/CONTRACTS-OWNERSHIP.md`](../CONTRACTS-OWNERSHIP.md).

## What moved here
The deterministic infra-ops spine — operation service, executor, policy engine,
approval, validator/reconciler, audit, provider adapters, `tacctl`, DB
migrations, and the product test suites (unit + PostgreSQL integration + failure
injection) — plus the design/qualification docs that were under
`docs/support/infra-ops/` (now `docs/design/` in the new repo).

## Migration record
See [`/TAC-REPO-EXTRACTION.md`](../TAC-REPO-EXTRACTION.md) for the full
classification, commit mapping, gates, secret-scan result, and rollback plan.
History mapping is in the new repo's `HISTORY-MIGRATION.md`.
