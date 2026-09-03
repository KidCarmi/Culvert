# ADR-0029: Source-side redaction & a data-classification registry for support data

- **Status:** Accepted — implemented (`internal/redaction` shipped as part of appliance track M1–M2; see `docs/support/SUPPORTABILITY-ROADMAP.md`)
- **Date:** 2026-07-12
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (ratified through shipped implementation)
- **Relates to:** ADR-0007 (secret containment — the `NEVER_EXPORT` enforcement), ADR-0028 (bundle framework), `config_surfaces.go` (the existing classification pattern). Full design in `docs/support/REDACTION-MODEL.md`.

## Context

Support data may contain passwords, tokens, TLS/CA private keys, session secrets, IdP/upstream credentials, user identities, and traffic metadata. The audit found **no centralized redaction framework**: `sanitizeLog`/`obs.Sanitize` only neutralize control characters (CWE-117) — they do **not** mask secret *values*; redaction is otherwise a set of siloed, per-call-site accessors (`List()` vs `Entries()`, `URL.Redacted()`, `GetConfig` field-scrub). The only formal classifier is `config_surfaces.go`'s `Sensitive`/`Redacted` flags, and it covers only three config DTOs. A support bundle that reaches into stores directly would bypass all of it. Regex-only scrubbing is insufficient and error-prone for the crown-jewel material.

## Decision

Adopt **structural, source-side redaction with a fail-closed default**, backed by a **data-classification registry** that generalizes the `config_surfaces.go` pattern.

1. **Five ordered `DataClass`es:** `PUBLIC < INTERNAL < SENSITIVE < SECRET < NEVER_EXPORT`. The **default for an unclassified field is `SENSITIVE`** (masked). `SECRET`/`NEVER_EXPORT` are **dropped**, never masked-and-kept.
2. **Redact at the source, inside each collector**, before any value crosses a process/disk/network boundary — never a post-hoc scrub of an assembled blob. The assembled bundle is re-scanned as defense-in-depth only.
3. **Techniques in priority order:** (a) structural unreachability — `internal/secret` handles render `REDACTED` and expose no bytes, so `NEVER_EXPORT` is a compile-time property, not a runtime filter; (b) structured field redaction driven by the registry; (c) reuse of existing redacting accessors; (d) a bounded free-form scrubber (env pairs, auth headers, PEM blocks, seeded live-secret values) as the **last** backstop, never the guarantee.
4. **A `DataClassRegistry` across three domains** — config surfaces (reuse `config_surfaces.go`), persisted `/data` files (new table, unlisted → `SECRET`), and log/stream fields (new table) — each with a **reflection parity wall** (`data_surfaces_test.go`) that fails CI when a collected struct gains an unclassified field.
5. **Per-bundle random salt** for stable-within-bundle masking tokens; salt is `NEVER_EXPORT`.
6. **Evidence + versioning:** every bundle carries a `redaction-report.json` (counts by class, never values) and a `redaction.model_version`, and requires a **pre-export preview**.

## Consequences

**Positive**
- Secret leakage becomes a **fail-closed structural property**, not author discipline. The `TestNoSecretInBundle` golden test (planted canaries of every class, all collectors, all levels/scopes) is the crown-jewel gate.
- New config/collected fields cannot ship without a class — the parity wall names the omission at CI time, exactly as `config_surfaces_test.go` does today.
- "Do not rely only on regexes" is satisfiable: the most sensitive bytes are gone by construction (ADR-0007), regexes only backstop free-form text.

**Negative / cost**
- Two new classification tables + a redaction engine (`internal/redaction`) to maintain, plus the discipline that collectors call the redactor. Mitigated by parity tests and by preferring existing redacting accessors.
- Masking reduces some analytic fidelity; mitigated by stable per-bundle tokens and profile choice.

**Neutral**
- `internal/redaction` is reusable beyond support (a future logging-layer redactor), but its first consumer is the support framework.

## Alternatives considered

1. **Regex scrubbing of an assembled blob.** Rejected: fail-open, brittle, ReDoS-prone, and blind to structure — the exact anti-pattern the prompt forbids.
2. **Extend `config_surfaces.go` only.** Rejected: it covers config DTOs, not `/data` files, logs, or traffic — the majority of bundle content.
3. **Allowlist-only (collect nothing unless explicitly permitted).** Considered and partially adopted: the default-`SENSITIVE` + explicit-class model *is* an allowlist for anything above `INTERNAL`; a pure allowlist for every field was rejected as too rigid for evolving diagnostics, so `PUBLIC`/`INTERNAL` pass by classification, not omission.
