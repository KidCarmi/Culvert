# Current implementation conventions

Scope: every change that touches Go, UI or API code. Root `CLAUDE.md` imports
this document eagerly and root `AGENTS.md` makes it mandatory, because the rules
below are the ones CI, golangci-lint and CodeQL enforce — meeting them after a
red check costs a round trip. Derived from the main baseline in
[migration](migration.md), with explicit exceptions below. Current
implementation and executable contracts take precedence over old prose. Original
wording remains in [preserved conventions](history/conventions.md).

## Before you change code

Each rule names the source that defines it; verify there at the task revision.

- **Logging**: `logger.Printf` in package main (the application logger wired in
  [logger.go](../../logger.go); `logFatalf`, never `logger.Fatalf`), not
  `log.Printf`/`fmt.Printf`. Internal owners use injected sinks or
  [internal/obs](../../internal/obs).
- **Untrusted log values**: wrap with `sanitizeLog` and print with `%q`
  ([proxy.go](../../proxy.go) `sanitizeLog`; CWE-117).
- **Outbound requests**: `url.Parse` + scheme check + `isPrivateHost`
  ([security.go](../../security.go), over the `internal/ssrf` seam) inline at the
  call site before any dial, so CodeQL sees the guard.
- **Contextual I/O**: `http.NewRequestWithContext`, `HandshakeContext`,
  `DialContext`; the `noctx` linter in [.golangci.yml](../../.golangci.yml)
  rejects a bare `http.NewRequest`.
- **Admin handlers**: keep the handler-level `requireRole(w, r, RoleAdmin)` /
  `RoleOperator` / `RoleViewer` check ([ui_rbac.go](../../ui_rbac.go); roles in
  [store.go](../../store.go)) even though C2 metadata also gates the route.
- **Configuration mutations**: `auditEvent` first, then
  `saveConfigVersion(actor, action)` ([configversion.go](../../configversion.go)),
  except the recorded exclusions under "UI, configuration and API changes" below.
- **GUI parity**: a new operator setting normally needs the admin API endpoint,
  the `uiRoutes` entry and a UI surface; recorded startup-only/trust/preview
  deferrals are the only exceptions.

## Ownership, toolchain and concurrency

- Domain logic/state/unit tests belong to cohesive internal owners; main keeps
  application wiring and integration. Read the owner's `doc.go`, ADR and boundary
  tests before moving code. Existing root aliases can be intentional boundaries.
- Take the compiler from [go.mod](../../go.mod) `toolchain`, not the minimum
  `go` line. CI and Docker pins must agree; do not set workflow `GOTOOLCHAIN`.
- Match the owner's concurrency contract. Immutable published views, sharded
  locks, RWMutex and atomics are different decisions. Do not replace a proven
  lock-free hot path with a generic RWMutex recommendation.
- [upstream_transport.go](../../upstream_transport.go) owns the shared transport.
  Read through `getUpstreamTransport`; mutate through `swapUpstreamTransport`
  with a new transport/TLS configuration. Never mutate a published transport or
  the update closure's input, including through a local alias.

## Security-sensitive I/O and logging

- In main, use application `logger.Printf`, not `log.Printf`/`fmt.Printf` for
  logging. Internal owners retain explicit injected sinks or `internal/obs`; do
  not add main/singleton dependencies to obtain the application logger. Sanitize untrusted log values with `sanitizeLog` and `%q`. Preserve the leading
  `strings.ReplaceAll` that CodeQL recognizes and existing single-pass behavior.
  See [proxy.go](../../proxy.go) and [internal/obs](../../internal/obs).
- Object-derived log values sometimes require an inline recognized sanitizer
  (`strings.ReplaceAll`, or format then replace) so CodeQL can trace them.
- Before outbound HTTP/dials, preserve scheme/URL validation and the appropriate
  SSRF guard. Existing `isPrivateHost`/inline `url.Parse` patterns matter to
  CodeQL; a wrapper alone is not evidence the destination is safe. Check the
  actual domain boundary: LDAP directory transport is deliberately not the
  generic public-HTTP URL validator (ADR-0027).
- Use contextual I/O: `http.NewRequestWithContext`, `HandshakeContext`,
  `DialContext`. Wrap errors with `fmt.Errorf("context: %w", err)`.
- Keep lint suppressions narrow and explained (`//nolint:errcheck` with reason;
  appropriate gosec suppression for deliberate dynamic cookie Secure or TLS
  behavior). Do not add suppressions to conceal a new insecure path.
- For new internal fields, avoid inadvertent gosec G117 secret-name matches;
  do not blindly rename an existing public JSON/wire/config contract to satisfy
  a naming rule. Preserve compatibility and use the established reviewed pattern.

## UI, configuration and API changes

- New operator configuration normally requires admin API and UI parity. Existing
  reviewed env-only/startup-only trust, deployment or preview exceptions are
  real exceptions. Record and surface such a deferral instead of inventing a
  runtime mutation endpoint for a startup-only/security boundary.
- Use `apiXxx(w, r)`, per-domain `register*Routes` and method-aware `uiRoutes`.
  Keep handler-level `requireRole` checks. Read [admin control plane](domains/admin-control-plane.md)
  before changing routes, auth, audit or persistence behavior.
- Consult [config_surfaces.go](../../config_surfaces.go) and
  [configuration-versioning triage](../../roadmap/CONFIG-VERSIONING-TRIAGE.md)
  for historical rationale, and the current registry/tests for capture decisions.
  Versioned configuration mutations audit first, then
  save the configuration version. Credential/password and approved hygiene
  paths explicitly must NOT create versions: see
  [password regression](../../auth_password_change_no_versioning_test.go),
  [CDR hygiene](../../cdr_hygiene_no_versioning_test.go) and
  [CDR revoke](../../cdr_revoke_rpc_no_versioning_test.go). Never apply the old
  blanket `saveConfigVersion` instruction to these paths.
- Legacy panels in `static/index.html` use `data-view`, navigation and load/render
  functions. The React frontend has its own migration contract; do not apply the
  legacy pattern to new React code. Use the [frontend route](README.md#frontend).

## Go code and test hygiene

- Prefer index-based range over copying large structs. Keep function complexity
  within the repository's configured cyclop threshold (currently 15); extract
  coherent helpers, not a generic shared-state hub.
- White-box tests sit beside their owner. Cross-domain production wiring stays
  at root. Preserve build tags, differential oracles and negative controls.
- The audit ring is bounded. Assert on unique entry content (Action/ObjectID/
  Detail or a unique test discriminator), not length deltas. Repeated shuffled
  runs saturate the ring; a new entry may evict an old one.
- `setupProxyTest` resets state at test START; it does not restore what a test
  changes afterward. A test adding policy rules must register restoration, such
  as `snapshotPolicyStoreForTest(t)` or an established wrapper. Restore rules and
  the corresponding default action together. Read the
  [original pitfalls](history/admin-control-plane.md#claude-main-l273-l346)
  and current test helpers before modifying shared globals.

No convention above authorizes a policy/runtime change, dependency upgrade,
external publication or security-setting change outside the task's scope.
