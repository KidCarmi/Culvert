# Documentation governance review 2026-11-16

Scope: checked-out `main` at `51996b9`. Swept operator, enterprise and top-level docs for
admin API paths and `CULVERT_*` variables with no backing code (none found), then audited
inspection-CA rotation guidance against `internal/ca`. Point-in-time record; not a source of
truth for behavior.

## Finding (High): three guides gave the wrong CA-rotation distribution deadline

- **Problem.** `docs/deployment-guide.md` § CA Auto-Rotation said Culvert auto-rotates every
  CA 30 days before expiry and that endpoints must receive the new root "before the old leaf
  certs expire (24h)". `docs/enterprise/TLS-INSPECTION-DEPLOYMENT.md` § 5 ("Distribution
  window") and `docs/enterprise/OPERATIONS-RUNBOOK.md` (Certificate expiry → Recovery) carried
  the same 24-hour window. Both claims are wrong, and they contradict the canonical runbook
  `docs/operator/root-ca-expiry.md` § 5. That runbook is correct, and so is the line just above
  the bad one in TLS-INSPECTION-DEPLOYMENT.
- **Implementation evidence.**
  - `Manager.RotateIfNeeded` (`internal/ca/ca.go`) returns without renewing unless provenance
    is `culvert-managed`. For an imported or unknown CA it calls `RenewalWithheldObserver`
    instead, which becomes a log line and a `cert_expiry` alert in `noteCARenewalWithheld`
    (`ca_health.go`).
  - Renewal reuses the old key and raw subject (`installSelfSignedCA(oldKey,
    oldCert.RawSubject)`), so a client that trusts only the old root keeps validating until the
    old root expires. `TestDualCAOverlap_ClientTrustingOnlyOldRootValidates` and
    `TestDualCAOverlap_SurvivesRestart` (`internal/ca/overlap_trust_test.go`) pin this.
  - The manual rotate path (`InitCA`) generates a new key, so trust breaks at once for clients
    without the new root. The 24 h leaf lifetime (`clampLeafValidity(..., now.Add(24*time.Hour))`)
    has no effect on either deadline: each new connection gets a newly signed leaf.
  - The check runs at startup and then every 24 h (`StartCAAutoRotation`, `ca.go`). The leaf
    cache is reset on install (`installCALocked` → `resetLeafCacheLocked`).
- **Why it matters.** After an automatic renewal, an operator following the old text pushed the
  root as an emergency when about 30 days were available. After a manual rotation the same
  operator believed they had 24 hours when they had none. An operator with an imported CA
  expected an automatic renewal that never happens; at expiry, inspected HTTPS is refused.
- **Who is affected.** Operators running SSL inspection, especially with an imported
  enterprise-PKI CA.
- **Canonical source.** `docs/operator/root-ca-expiry.md` § 5. The edited guides now point to it
  and do not restate the provenance table.
- **Change.** The deployment-guide section was rewritten to cover provenance, same-key renewal,
  the overlap deadline and the manual-rotate caveat. The TLS-inspection and runbook lines were
  corrected. Effort: small. Risk: low (documentation only).

## Not changed / documentation debt

- **GAP-PKI-05 text is partly stale (Medium).** The gap register,
  `TLS-INSPECTION-DEPLOYMENT.md` § 5 and `OPERATIONS-RUNBOOK.md` say `cert_expiry` fires "only
  when rotation occurs". Current code also fires it for a withheld renewal (every round, startup
  included), for an unusable CA (`fireCAUnusableAlert`), and for a rotation that did not persist.
  The check runs at startup (CHAOS-28). What is still missing is an expiry warning that does not
  depend on the rotation loop. Re-scoping a tracked gap belongs to its owner, so it was left out
  of this PR.
- `internal/alerts/store.go` lists 23 events in its "Supported events" header comment. The
  Alerts panel exposes 40 subscribable events (CHAOS-120 commit `542d5e8`). No operator page catalogs alert
  events; the panel is the only place to see the full list.
- Carried: no catalog of Diagnostics row codes. Per-option configuration-reference completeness
  was not re-audited.
