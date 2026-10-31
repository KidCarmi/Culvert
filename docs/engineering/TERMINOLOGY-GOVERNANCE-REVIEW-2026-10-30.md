# Culvert Language & Terminology Governance Review — 2026-10-30

> **Status:** Point-in-time review. **Window:** `5cbbaff..9eb4281` (changes since the 2026-10-29 report).
> Sweep covered SEC-SETUPANCHOR-1 / SEC-AUTHENABLED-1 (`setup_bootstrap_window.go`, `store.go`, `proxy.go`),
> the CHAOS-104/105 cluster-CA log lines and runbook, and the glossary.

## Executive Summary

One Low finding: the glossary's **Setup window** definition still described the setup anchor as "an admin account",
which SEC-SETUPANCHOR-1 changed to "any admitted roster account, whatever its role". Terminology Health Score: 94/100 (unchanged; the drift was definitional, not a naming split).

## Finding 1 — setup anchor definition lags the code (Low)

- **Business concept:** the setup window and what durably closes it.
- **Current names:** "an admin account, or open mode" (glossary); "any ADMITTED record … whatever its role" (`rosterBytesConfigure`).
- **Recommended canonical wording:** "any admin roster account, whatever its role, or open mode". No identifier changes.
- **Why problematic:** a support engineer reading the glossary would conclude a roster of Viewer-only accounts leaves the window open, the opposite of the shipped behavior.
- **Affected code/API/GUI/configuration:** none. **Documentation:** one glossary row. **Migration complexity:** trivial. **Compatibility risk:** none. **PR size:** XS.

## Checked, no change

- "roster", "admitted record", "verifier": used only in code comments and the Go-internal `hasRoster`/`rosterWithoutVerifier`; operator text keeps "admin roster" / "administrator account".
- `ClusterCA:` log prefix, "previous CA", "dual-CA overlap", "rotation": consistent with the runbook `cluster-ca-expiry.md`.
- blocklist/allowlist remain dominant over legacy whitelist/blacklist (previously reviewed; no operator-visible regression).

## Priority

Critical none · High none · Medium none · Low 1 (applied).
