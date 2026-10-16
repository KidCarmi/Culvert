# Admin API and control-plane contract

Applies to route registration, handlers, RBAC, middleware, audit and configuration
mutations, including root `ui*.go`, `cdr_ui.go`, `pac.go`, `diagnostics.go` and
`store.go`. This concise contract retains the original guide's critical rules;
verify the affected behavior in the linked implementation/tests at the task SHA.

## Routing and authorization

- `startUI` composes; it must not register routes directly. Use per-domain
  `register*Routes` and a matching method-aware entry in
  [ui_routes_meta.go](../../../ui_routes_meta.go). A new route needs both.
- Method resolution is specific method → `MethodAny` → soft-fail. Do not use
  `MethodAny` to conceal a method-specific role contract.
- Metadata must not be more permissive than the handler's real requirement.
  Trace dynamic/delegated dispatch, not only a direct `requireRole` call.
- Keep handler-level `requireRole`; C2 is additional defense, not its replacement.
  The handler wins any disagreement; metadata must not widen access.
- Public-route ownership remains in
  [uiAuthMiddleware](../../../ui_middleware.go). `RolePublic` is documentation,
  not a C2 public-route bypass. `RolePublic` stays OUT of `rolePriority` and is
  metadata only on public routes. `HasRole`/non-public enforcement requires both
  supplied and required roles to be enrolled; unknown roles must not gain
  zero-value privileges. Preserve the supported legacy-session path separately.
- The chain remains IP guard → security middleware → auth → C2 metadata → mux.
  HTTP method drives CSRF/body/rate controls; metadata `Mutating` is informational.

## Preserve the exceptions and observability boundaries

- Missing metadata and absent method policy log/count and soft-fail in shadow
  AND enforce mode. Do not turn this migration guidance into a new deny path;
  handler-level authorization is the backstop. Drift is prevented by parity tests.
- The startup-only `CULVERT_C2_ENFORCE` switch selects enforce/shadow; do not add
  runtime mutation. Shadow must not block.
- `AuditExpected` observes missing audit after successful 2xx/3xx requests,
  excluding public/failed/hijacked cases. It never blocks.
- C4 role divergence observes a handler denial after a more-permissive metadata
  decision. It does not alter allow/deny/response or append an admin audit action.
- [Governance](../../../ui_governance.go) is read-only. Distinguish genuine
  missing-metadata drift from warnings caused by unsupported methods or viewers
  probing admin actions; do not page on ordinary client probing as structural drift.
- Configuration versioning has explicit exclusions. Follow the current surface
  registry and regression tests in [conventions](../conventions.md#ui-configuration-and-api-changes),
  not a blanket snapshot-after-every-mutation rule. Password changes must not
  resurrect old credentials through version restore.

## Verification sources

- [D0 tests](../../../d0_rbac_safety_test.go): route/security baseline (locate other
  `d0_*_test.go` suites relevant to the edit).
- [C1](../../../ui_routes_meta_test.go): forward/reverse route-metadata parity.
- [C1.5](../../../ui_routes_meta_audit_test.go) and
  [delegation tests](../../../ui_routes_meta_delegation_test.go): per-method and
  delegated role/mutation parity.
- [C2 and C2c](../../../ui_metadata_enforcement_test.go): enforce/shadow and
  audit observation, including the soft-fail controls.
- [C4](../../../ui_metadata_divergence_test.go): role-divergence observation
  and response invariance.
- [Fail-closed role regression](../../../ui_role_failclosed_test.go): unenrolled
  supplied/required roles, public metadata and the safe legacy-session control.
- [Governance tests](../../../ui_governance_test.go): read-only reporting.
- [Full original contract and pitfalls](../history/admin-control-plane.md#claude-main-l273-l346)
  and [SEC-RBAC history](../history/authentication-and-identity.md#claude-main-l224-l224).

Use [verification](../workflows/verification.md) to choose actual checks. Restore
shared globals and assert unique audit content, not bounded-ring length deltas.
A missing role check or permissive metadata needs a concrete reachable scenario;
intentional soft-fail/observability-only paths are valid review counterexamples.
