# Documentation governance review 2026-11-20

Scope: checked-out `main` at `0fe4578`. Point-in-time record; not a source of truth for
behavior.

## Finding (High): the Authentication kill switch has no operator documentation

- **Problem.** `CULVERT_AUTHBYPASS_DISABLE` and the Auth Policy runtime toggle
  (`PUT /api/authpolicy/killswitch`) are a break-glass security control. The
  `auth_exempt_kill_switch` Diagnostics row tells the operator to "unset
  `CULVERT_AUTHBYPASS_DISABLE` and restart", but no operator guide, the README environment
  table included, named the variable, its accepted values, or the difference between the two
  layers. It appeared only in `roadmap/` specs, the terminology table and engineering reviews.
  The 2026-11-19 review counted those mentions as documentation; they are design records.
- **Implementation evidence.** `authpolicy.go` (`parseAuthBypassDisable`: `1/true/yes/on`;
  `authBypassDisabled`: read once; `authExemptDisabledRuntime`: in-memory atomic, never
  persisted; resolver skips only `Exempt`), `proxy.go` `resolveRequestAuth` (forces the
  default outcome to `Default`, keeps the gate armed), `ui_authpolicy.go`
  `apiAuthPolicyKillSwitch` (viewer read, admin write, audit `authpolicy.killswitch`, no
  configuration version), `auth_killswitch_diag.go` (four backend states), `ui_routes_meta.go`,
  `authpolicy_killswitch_nobackend_test.go`. The only setter is the admin handler, so the
  toggle is not replicated. `docker-compose.yml` does not pass the variable to the `proxy`
  service.
- **Why it matters.** Three facts an operator needs during an incident were undiscoverable:
  the runtime toggle is lost on restart, so exemptions resume silently; neither layer reaches
  other nodes; and on a gateway with no authentication backend the switch does not make
  formerly exempt clients authenticate. Under the shipped Compose file, setting the variable
  in `.env` does nothing.
- **Who is affected.** Security operators and on-call administrators using Auth Policy
  exemptions.
- **Canonical source.** The code above. The new page owns the kill switch only.
- **Change.** New `docs/operator/authentication-kill-switch.md`, an index entry in
  `docs/operator/README.md`, and one row in the README environment table. Effort: small.
  Risk: low (documentation only).

## Checks performed

- CLI flags named in `README.md`, `docs/*.md`, `docs/operator`, `docs/enterprise` and
  `docs/support` were compared with the flags registered in non-test Go. No documented flag is
  missing from the code.
- `CULVERT_*` names in non-test Go were compared with the same operator-facing documents
  (not `roadmap/` or `docs/engineering/`). Unmatched: `CULVERT_AUTHBYPASS_DISABLE` (this
  finding), `CULVERT_MCP_LIVE_CREDENTIAL_KEK` (below), and `cmd/feedgen` CI inputs.
- `python3 docs/agent-context/check.py` passes.

## Not assessed / documentation debt

- **High, carried forward as new:** Auth Policy itself (Stage-1 rules, the `Exempt`,
  `CredentialRequired` and `SSORequired` outcomes, `defaultAuthOutcome`, the rule warnings and
  the `auth_exempt_*` Diagnostics rows) has no operator guide. The frozen contracts live in
  `roadmap/AUTHENTICATION-POLICY-SPEC.md` and `roadmap/AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md`.
  It needs its own change and a full read of `authpolicy.go`; it was not attempted here.
- **Medium:** `CULVERT_MCP_LIVE_CREDENTIAL_KEK` is named only in ADR-0035 and a security
  review. The MCP live path is gated and not generally available, so it was left.
- **Low:** the README environment table lists 12 of the operator-facing variables; others
  (`CULVERT_KEK`, `CULVERT_BACKUP_PASSPHRASE`, `CULVERT_HA_TOKEN`, the `*_ENCRYPT` family) are
  documented only in their own guides. There is no single environment-variable reference.
- Carried: no catalog of Diagnostics row codes or of subscribable alert events.
- Carried: the GAP-PKI-05 wording is partly stale (2026-11-16). It is owner-scoped.
- Hand-written admin API route documentation, GUI screenshots and the enterprise guides were
  not re-audited in this pass.
