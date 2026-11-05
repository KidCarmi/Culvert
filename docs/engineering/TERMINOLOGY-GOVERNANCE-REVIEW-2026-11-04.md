# Culvert Language & Terminology Governance Review — 2026-11-04

> **Status:** Point-in-time review. **Window:** `110bf9f..2d03196` (admin UI certificate diagnostics, CHAOS-109 feed-ingestion budgets, canonical header-key gate, dependency bumps).

## Executive Summary

One Low finding: the new admin UI certificate diagnostics (`ui_tls_cert_corrupt`, `ui_tls_cert_pending`, `ui_tls_cert_expiry`) told operators to act under "Settings → Network & TLS (Certificates)". No such location exists: the upload lives in the top-level **Certificates** view, panel **Upload Custom Certificate**, **Target: Management UI**. Terminology Health Score: 93/100 (unchanged).

## Finding 1 — navigation name that does not exist in the GUI (Low)

- **Business concept:** where an operator replaces the certificate that secures the admin UI.
- **Current names:** "Settings → Network & TLS (Certificates)" (diagnostic remediation text); "Certificates → Upload Custom Certificate, Target: Management UI" (GUI); "admin UI certificate" / "admin UI TLS certificate" (diagnostic messages).
- **Recommended canonical name:** the GUI wording is authoritative — **Certificates → Upload Custom Certificate (Target: Management UI)**. "Admin UI certificate" stays the prose noun.
- **Why problematic:** the "Network & TLS" panel in Settings only holds External Base URL and Additional TLS SANs. A support engineer or operator following the diagnostic row would not find the upload control.
- **Fix applied:** the three remediation strings in `diagnostics_ui_tls_cert.go` now quote the GUI path. No identifiers, codes, API fields or metrics changed.
- **Affected code:** one file, three strings. **API/GUI/config:** none. **Docs:** none. **Migration complexity:** trivial. **Compatibility risk:** none (free-text `operator_action`). **PR size:** XS.

## Checked, no change

- **Feed-ingestion budgets (CHAOS-109):** "byte budget" (compressed body / expansion) and "entry budget" (entries/lines) are used consistently across `feedsync`, `blocklistfeed`, `threatfeed`, CHANGELOG and the chaos review; "byte budget" elsewhere (cluster snapshot, revocation sync, support bundles) means the same kind of bound.
- **"Admin UI certificate" vs "admin UI TLS certificate":** same concept, differing only by an adjective; no GUI/API/metric surface. Rejected as cosmetic.
- **"Management UI" (GUI target) vs "admin UI" (diagnostics/docs):** a real alias pair, but "Management UI" is a single GUI option label and renaming it or the diagnostics wording is churn; recorded here for the next time that dropdown is touched.

## Priority

Critical none · High none · Medium none · Low 1 (applied).
