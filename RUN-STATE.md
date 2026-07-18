# Culvert Content Factory — Run State

Live operational log for the autonomous content engineer. Updated at every
phase transition. Newest activity at the top of each section.

---

## Session

- **Role:** Autonomous Technical Content Engineer / Product Educator / Docs Architect
- **Branch:** `claude/culvert-content-foundation-5geqkh`
- **Repo revision at start:** `ca60d83` (main merge #817)
- **Toolchain:** Go 1.25.12 (build verified OK — `go build .` exit 0)
- **Control files:** `CONTENT-STANDARD.md`, `CONTENT-BACKLOG.yaml`, `RUN-STATE.md`
- **Content root:** `content/` (docs / youtube / training / evidence)

## Current item

- **H-010** — Policy engine & Zero-Trust authoring. Selecting; next high-pri.

## Recently completed

- **C-003** — Quick start (`content/docs/02-getting-started/quick-start.md`) +
  evidence ledger + **reproduced lab run** (`content/evidence/quick-start-lab-run.md`:
  real `/health` + `/ready` output from the built binary). Readiness gating
  (session_secret, config_snapshot_validator) vs report-only (ca, policy_loaded)
  documented from `healthcheck.go`. Hardened `check-links.sh` (pipefail bug on
  link-less files). Committed.
- **C-002** — Architecture (`content/docs/01-overview/architecture.md`) +
  evidence ledger. Request pipeline **re-verified from `proxy.go:handleRequest`**
  (14-stage order), not mirrored — caught doc-drift (G-05). Committed `ba90a4d`.
- **C-001** — Product overview + evidence ledger. ~55 capability claims verified
  via 3 parallel research agents + direct greps. Two overclaims corrected
  (tamper-evident audit → append-only; CDR → external engine). Committed
  `9176e99`.

## Execution plan

1. **Bootstrap (done):** record revision, read control surfaces, create
   `CONTENT-STANDARD.md`, `CONTENT-BACKLOG.yaml`, `RUN-STATE.md`, content tree,
   verify build.
2. **Loop** per `CONTENT-BACKLOG.yaml` priority order:
   critical (C-001 → C-002 → C-003) → high (H-010…H-015) → medium → low.
3. For each item: Select → Investigate (subagents for independent research) →
   Evidence ledger → Draft → Adversarial review (5 lenses) → Verify → Commit →
   Record.
4. Stop at a defined stop condition; produce `reports/CONTENT-FACTORY-SUMMARY.md`.

## Completed items

- **C-001** — Product overview + claim-evidence ledger (critical).
- **C-002** — Architecture overview + claim-evidence ledger (critical).
- **C-003** — Quick start + evidence ledger + reproduced lab run (critical).

**All critical-priority items complete.** Proceeding to high-priority (H-01x).

## Commits created

- `5a4aa90` docs(content): bootstrap autonomous content foundation scaffolding.
- `9176e99` docs(content): add verified product overview (what is Culvert).
- `ba90a4d` docs(content): add verified architecture overview.
- _(C-003 commit — hash recorded next cycle)_

## Blocked items

_(none yet)_

## Product gaps / uncertainties discovered

- **[G-01] "Tamper-evident audit trail" is an overclaim.** README and
  `docs/architecture.md` describe the audit trail as tamper-evident, but
  `internal/audit/audit.go` implements only a bounded (`MaxRing = 500`),
  append-only JSONL ring with oldest-eviction — **no hash-chain or signature**.
  Content downgrades the claim to "bounded, append-only". _Human decision:_ add
  a hash-chain/signature to justify "tamper-evident", or correct the README.
- **[G-02] `internal/halease` doc comment appears stale.** `halease.go:7` says
  "S1 ships the primitive ONLY — nothing in the runtime consumes it yet," which
  conflicts with CLAUDE.md ("ADR-0005 PROGRAM COMPLETE S0–S5") and the root
  `ha_lease.go`/`ha_failover.go` that consume it. Overview keeps "Supported";
  the HA article (M-023) must confirm the real integration state from code.
- **[G-03] "Rolling upgrades" is partial.** Per-node digest dispatch
  (`release_dispatch_exec.go`) and CP leadership handoff exist, but no
  cluster-wide rolling-upgrade orchestrator was found. Excluded from the
  verified overview table; to be scoped in the distributed article (M-021).
- **[G-04] CDR requires an external engine.** `cdr.go` is a gRPC/mTLS client to
  an external "Sluice" CDR engine; the disarm/reconstruct algorithm is not
  in-binary. Content labels CDR "Supported (companion engine)". Not a defect —
  a deployment prerequisite to document clearly (parallels the ClamAV sidecar).
- **[G-05] `docs/architecture.md` pipeline diagram drift.** The in-repo diagram
  places the plugin middleware chain *before* authentication, but in
  `proxy.go` `handleRequest` the plugin decision runs *after* Stage-1 auth,
  inside `preDispatchBlocked` (`proxy.go:435`). The diagram also omits the
  rate-limit stage and the host-canonicalization (IDNA, fail-closed) gate
  (`proxy.go:850-859`). The website architecture article uses the code-verified
  order. _Human decision:_ update `docs/architecture.md` to match (out of scope
  for content — it is product doc, flagged not edited).

## Verification log

- Bootstrap: `go build -o …/culvert .` → exit 0 (toolchain + module compile OK).
- C-001: `content/tools/check-links.sh` → OK (forward-refs allowlisted in
  `content/.forward-refs`). Markdown structure: 1 H1, balanced fences, no
  trailing whitespace. Corrected claims re-verified against source
  (`internal/audit/audit.go:49` `MaxRing = 500`, no hash-chain;
  decryption-profiles "coming soon"; `metrics.go:332` metric name).
- C-002: link check OK; pipeline order re-read from `proxy.go:handleRequest`
  (`preDispatchBlocked` `:401`, `pluginDecision` `:435`).
- C-003: **reproduced run** of the built binary — `/health` `status:ok`,
  `/ready` HTTP 200 `ready`; readiness gating logic read from
  `healthcheck.go:135-233`; setup gate from `ui_auth.go:371-411`. Link check OK
  after hardening `check-links.sh` (dropped `-e`; `-uo pipefail` + `|| true` so
  a link-less evidence page no longer aborts the run).

## Notes

- Existing `docs/` (116 md files) is internal engineering + operator docs of
  high quality. The `content/` tree is the website/YouTube/training foundation —
  it must add coherent, audience-oriented structure, not mirror source or docs.
- No docs-site tooling (mkdocs/docusaurus) present; content is plain Markdown +
  Mermaid, portable to any site generator later.
