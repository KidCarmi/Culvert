# Documentation governance review 2026-11-21

Scope: checked-out `main` at `ef94311`. Point-in-time record; not a source of truth for
behavior.

## Finding (High): authentication rules (Auth Policy) have no operator documentation

- **Problem.** Stage-1 authentication rules decide which clients skip authentication, which
  get a `407` and which are sent to SSO. They have a GUI panel, an admin API, a global
  default, sixteen Diagnostics codes and three metrics, and no operator guide. The only
  operator-facing text was the kill-switch runbook (2026-11-20), which covers one control.
  The behavior was described only in `roadmap/` specs and code comments. Carried forward
  from the 2026-11-20 review.
- **Implementation evidence.** `authpolicy.go` (`validateAuthRule` and its helpers,
  `authRuleMatchesScratch`, `resolveNoCredAuthOutcome`), `proxy.go` `resolveRequestAuth`
  (arms 3a–3c and the `authRequired` gate), `ui_authpolicy.go` (CRUD, reorder, `ifVersion`,
  `simulateAuthOutcome`), `ui_config.go` `apiDefaultAuthOutcome`, `store.go`
  (`setDefaultAuthOutcomeChecked`, `normalizeDefaultAuthOutcome`), `config_surfaces.go`
  (`policy_rules` cluster-synced and rolled back; `default_auth_outcome` an informational
  mirror; `admin_users` excluded from rollback), `diagnostics.go`,
  `diagnostics_auth_sso.go`, `proxy_portal.go`, `internal/clientclass`, `metrics.go`.
- **Why it matters.** Facts an administrator cannot infer from the GUI: an exemption applies
  only to requests without a `Proxy-Authorization` header; `SSORequired` answers every
  `CONNECT` with `403`; rule writes bypass Require Commit and are live at once; the default
  authentication behavior is stored with the admin roster, is not versioned, is not rolled
  back and is not applied by Data Plane nodes; and a node with nothing that can verify a
  credential under the `Default` setting evaluates no authentication rule at all.
- **Who is affected.** Security administrators writing exemptions and SSO rules; on-call
  staff diagnosing an unexpected `407` or `403`.
- **Canonical source.** The code above. The new page owns authentication rules and the
  default authentication behavior; the kill switch stays in its own page and is linked.
- **Change.** New `docs/operator/authentication-rules.md` and an index entry in
  `docs/operator/README.md`. Effort: medium. Risk: low (documentation only).

## Checks performed

- Every field, status code, audit action, Diagnostics code, log line and metric name in the
  new page was read from the files above at this revision. The no-backend statements agree
  with `TestS3_NoBackend_DefaultInert_ExemptScopedFires` and the kill-switch page §3.
- `python3 docs/agent-context/check.py` passes.

## Not assessed / documentation debt

- **Medium, new:** the `auth_cr_no_credential_provider` Diagnostics message says covered
  requests "would be challenged (407) indefinitely". With the `Default` setting and no
  backend at all, Stage 1 is skipped and they are not challenged. This is product text, not
  documentation, and was left for the owner.
- **Low, new:** `ui_routes_meta.go` lists `POST /api/authpolicy/killswitch`; the handler
  answers `405`. Not confirmed as a defect.
- Not verified, so not documented: how `priority` is assigned when a create omits it, and
  whether `destCountry` narrows an authentication rule.
- Carried: `CULVERT_MCP_LIVE_CREDENTIAL_KEK`; no environment-variable reference; no catalog
  of Diagnostics codes or alert events; GAP-PKI-05 wording. Enterprise guides not re-audited.
