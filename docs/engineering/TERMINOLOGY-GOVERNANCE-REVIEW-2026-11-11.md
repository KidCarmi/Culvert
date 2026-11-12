# Culvert Language & Terminology Governance Review — 2026-11-11

> **Status:** Point-in-time review. **Window:** `ac4e223..04aa647` (Root CA provenance and same-key renewal, CDR
> partial-capacity diagnostic, CHAOS-116 ClamAV status probe, catdb single-transaction lookup, admin UI non-ASCII SAN
> handling, go1.27.4).

## Executive Summary

One production-worthy terminology improvement was identified and applied. The new withheld-renewal `cert_expiry`
alert and log line told the operator to upload a replacement CA under "CA Management, custom CA". No GUI surface has
that name. The upload lives at **Certificates → Upload Custom Certificate**, with target **MITM / SSL Inspection
Engine**. The CA Management view has no upload control. The text is unreleased (`40084c0`, no tag contains it), so
there is no migration cost. Two older button names in the same runbook were also corrected to match the GUI.

Terminology Health Score: 93/100 (unchanged; the drift was caught before it shipped).

## Canonical Concepts

| Concept | Canonical name | Surfaces |
|---|---|---|
| Replace the inspection (MITM) CA with an admin-supplied one | **Upload Custom Certificate**, target *MITM / SSL Inspection Engine* | GUI `view-certificates`, `POST /api/certs/upload` `target=mitm`, `root-ca-expiry.md` §5/§6, `cert_expiry` withheld-renewal detail (**this PR**) |
| Who may renew the Root CA | **provenance**: `culvert-managed` / `imported` / unknown | `CULVERT_CA_PROVENANCE`, bundle PEM record, logs, runbook §5 |
| Manual Root CA rotation | **Force Rotate Now** | GUI CA Management, runbook §3 (**this PR**) and §6, `POST /api/ca/rotate` |

## Finding T-1 (Medium): alert action names a GUI location that does not exist

- **Business concept:** how to replace an imported inspection CA that Culvert will not renew.
- **Current names:** "upload it (CA Management, custom CA)" in `ca_health.go` `noteCARenewalWithheld`. This text goes to the
  `cert_expiry` alert detail and to the application log every 24 hours.
- **Recommended canonical name:** "Certificates → Upload Custom Certificate, target MITM / SSL Inspection Engine". These
  are the real nav item, panel title and target option.
- **Why the current naming is a problem:** an operator who follows the alert opens CA Management. That view has Root CA,
  cache, OCSP, mTLS, overlap and HSM panels, but no upload control and no "custom CA" label. The alert fires near a
  trust-anchor expiry, which is exactly when a wrong path is costly. At expiry, inspected HTTPS is refused.
- **Why the new name is better:** it quotes the visible labels word for word, so the alert, the GUI and the runbook all
  name one place. The same rule was applied to the `ui_tls_fallback_http` OperatorAction on 2026-11-10.
- **Affected code:** `ca_health.go` (one string) and `rootca_provenance_test.go` (now pins "Upload Custom Certificate").
- **Affected API / GUI / configuration:** none. Only alert detail and log text change.
- **Affected documentation:** `docs/operator/root-ca-expiry.md` §5 now gives the same GUI path and API call.
- **Migration complexity / compatibility risk:** none. The text is unreleased, and it is free text, not a matched field.
- **Estimated PR size:** XS.

## Finding T-2 (Low): runbook button names disagree with the GUI and with the runbook itself

- **Current names:** §3 says *Force Rotation* and *Download CA*. The GUI buttons are **Force Rotate Now** and
  **Download CA Cert (PEM)**, and §6 of the same runbook already says *Force Rotate Now*.
- **Fix:** §3 now uses the GUI labels. Docs only, XS.

## Candidates considered and rejected

- **Provenance value `imported` vs. GUI "Custom":** `imported` is a persisted bundle record and a startup env value.
  It names *origin* (your PKI issued it), while "Upload Custom Certificate" names the *action*. It also matches the
  existing "Import Custom Cluster CA" / "Import CA" wording. The runbook links the two ("Uploaded by an admin"), and
  renaming a persisted value would add a compatibility cost for no gain in clarity. Kept.
- **Log prefixes `CA:` vs. `SSLCA:` in the CA path:** both prefixes existed before this window (`ca_health.go` vs.
  `rootca_*.go`). The new lines follow their file's existing prefix. Unifying them is a separate, low-value log change.
- **CDR diagnostic states `enabled-reduced` / `enabled-recovering`:** these extend the existing
  `enabled-{healthy,degraded,dark,broken}` family. "Out of rotation" and "tripped circuit breaker" are used together
  with the breaker state in parentheses, and the action cites the real GUI tab (CDR → Instances). Consistent.
- **ClamAV probe metrics `culvert_clamav_status_{probes,probe_coalesced,stale}_total`:** these follow the existing
  `culvert_clamav_*` prefix and *coalesced*/*stale* vocabulary. No collision with *saturated* (T-1, 2026-11-10).
- **Legacy-term sweep:** none of the new lines reintroduce "unauth mode", "whitelist"/"blacklist", "hash cache" or
  "expansion ratio".

## Priority

Critical none · High none · **Medium 1 (T-1, fixed)** · **Low 1 (T-2, fixed)**.

Checks: `go test -run TestCAProvenance -count=1 .` passes on go1.27.4. No wire fields, metrics, configuration keys or GUI labels changed.
