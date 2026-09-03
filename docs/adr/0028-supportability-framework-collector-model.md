# ADR-0028: Supportability Framework — plugin-collector model & the Culvert Support Bundle

- **Status:** Accepted — implemented (appliance track M0–M5 shipped; see `docs/support/SUPPORTABILITY-ROADMAP.md` and the live operator runbook `docs/operator/support-bundles-and-diagnostics.md`)
- **Date:** 2026-07-12
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (ratified through shipped implementation)
- **Relates to:** ADR-0002 (internal decomposition — a new engine `internal/support`), ADR-0007 (secret containment — the `NEVER_EXPORT` enforcement), ADR-0029 (redaction), ADR-0030 (privileged host collection), ADR-0031 (export/consent). Full design in `docs/support/`.

## Context

Culvert has no support/TAC framework. Diagnosing a production failure today requires an engineer to stitch `/api/diagnostics` + `/api/audit` + `/api/config/export` + host SSH, and to hand over a raw backup — which is a **full secret export** (`backup.go` copies `/data` verbatim incl. CA keys, session HMAC, credentials). The product's own gap register already endorses a redacted `GET /api/support-bundle` (GAP-MON-01 / FO-2) but under-specifies it. The codebase has strong primitives — the side-effect-free `OperatorContract` (`diagnostics.go`), the `config_surfaces.go` classification registry, the `internal/secret` boundary, the manifest-based `backup.go` archive, and a shell-free privileged agent — but nothing composes them into a versioned, redacted, explainable artifact.

A naïve implementation ("one big collect function that tars `/data`") would reproduce the backup's secret-leak, couple the framework to a single deployment/runtime, and make one broken step abort the whole thing.

## Decision

Build a **plugin-collector supportability framework** in a new engine `internal/support`, producing a versioned **Culvert Support Bundle (CSB, `csb/1`)**.

1. **Collectors, not a monolith.** Each subsystem owns a small `Collector` that produces exactly one bundle section, with typed metadata (owner, timeout, byte budget, level/runtime/feature gates, declared max data class). The runner executes them concurrently, each isolated with a timeout + panic recovery, so **a broken collector becomes a manifest error entry, never a bundle abort**.
2. **A stable, dual-readable format.** Every CSB carries a machine-readable `manifest.json` (versioned per the three-axis scheme: format / engine / per-section schema) with per-section SHA-256 + integrity hashes + collection-errors, and a human `SUMMARY.md`. Reuse the audited `backup.go` tar/manifest/atomic-write machinery and `internal/backupcrypt` for encryption; **do not** reuse `defaultBackupArtifacts` and **never** ship a raw backup.
3. **Redaction at the source** (ADR-0029), enforced fail-closed, with a mandatory pre-export preview.
4. **Runtime-agnostic by construction.** Collectors declare a runtime capability; the runner gates them. Build for Compose+HA now; OVA/k8s later add only new collectors.
5. **One contract, three front-ends.** `/api/support/*` (route family + `uiRoutes` metadata + RBAC + C2), a `data-view="support"` GUI panel, and `culvert support`/`diagnose` CLI verbs — plus a recovery-mode one-shot that works with the server/GUI down.
6. **A CI parity wall** (`support_registry_test.go`) makes it impossible to add a collector without a unique id/path, a golden schema, a data-class bound, and its mandatory test set.

## Consequences

**Positive**
- TAC gets a single, redacted, integrity-verified, explainable artifact; the endorsed GAP-MON-01 direction is realized and hardened.
- Failure isolation, determinism, and bounded execution are structural, not hoped-for.
- The flat-package + shim conventions are respected (engine in `internal/support`; wiring in `package main`).

**Negative / cost**
- A new engine + route family + SPA panel + CLI surface — meaningful surface area, mitigated by small milestone slices (M1 first) and heavy reuse of existing safe accessors.
- Three version axes to maintain; mitigated by golden-schema + cross-version tests.

**Neutral**
- Adds `<dataDir>/support/` state (bundles, debug watchdog, timeline) under the existing disk-safety/retention discipline.

## Alternatives considered

1. **Extend the raw backup with a redaction pass.** Rejected: retrofitting redaction onto a byte-faithful `/data` copy is fail-open by default and couples diagnostics to the restore surface. Source-side collectors are fail-closed and decoupled.
2. **One monolithic `/api/support-bundle` handler.** Rejected: no failure isolation, no per-subsystem ownership, no runtime gating, and it grows unreviewably. The collector registry mirrors the proven `uiRoutes`/`config_surfaces` registry discipline.
3. **A separate support daemon.** Rejected: a second privileged process is unnecessary attack surface; the proxy hosts application collectors and the existing maintenance agent hosts host collection (ADR-0030).
