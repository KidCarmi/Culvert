# ADR-0041: The identity-backend result cache is owned by internal/identcache

- Status: Proposed for review with the implementation PR (#1633, 2026-10-27).
- Numbering: checked `docs/adr/`, `docs/support/rfc/` and the open-PR file
  inventories; ADR-0040 is held by the open #1526, so this takes 0041.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md). Related:
  ADR-0002 (stdlib leaves), ADR-0037 (instance-owned engine, root binding),
  CHAOS-76 (`roadmap/CHAOS-ENGINEERING-REVIEW.md` §54).

## Context

CHAOS-76 gave the three identity-backend result caches on the proxy credential
path one bounded, client-attributed cache: the LDAP directory bind
(`auth_ldap.go`), the legacy RFC 7662 introspection backend (`auth_oidc.go`) and
the IdP-registry introspection provider (`auth_oidc_flow.go`). The first version
put that engine, `identityResultCache[T]`, and its white-box gates in
`package main`. Codex flagged that as a breach of the internal-owner rule in
`AGENTS.md`. The engine owns synchronisation, entry and bucket state, expiry,
compaction and the eviction policy, which is domain logic rather than
application wiring. Its pure tests also had to compile the whole application
test package.

The engine was already close to a leaf. It imported `sync`, `sync/atomic` and
`time`, and it used three things from package main: the cap
(`maxAuthCacheSize`), the victim ordering (`betterAuthCacheVictim`) and a
package-level process-wide eviction total that `/metrics` exports.

## Decision

Move the engine into `internal/identcache` as `Cache[T]`, constructed by `New`
with `Options`. The policy code moves unchanged.

- **The cap and the eviction sink are construction dependencies.**
  `Options.MaxEntries` is the cap. `Options.OnEvict` is called once per
  displacement, under the cache's lock, so it must be cheap and must not
  re-enter. The package holds no globals, no `init`, no logger and no
  persistence. Its only imports are `sync` and `time`. The process-wide total
  stays in package main, because it must outlive any one cache: the IdP
  registry builds a fresh provider, and so a fresh cache, every time a profile
  is edited.
- **The victim ordering moves with the engine** as `BetterVictim`. `store.go`'s
  `betterAuthCacheVictim` delegates to it, so the local credential cache and the
  identity caches share one definition. Merging `store.go`'s `authCacheStore`
  and `internal/authstate.Store` into this engine is NOT part of this decision.
  §54.7 of the register explains why folding a re-`Set`-heavy cache into
  `authstate` would make two latent defects reachable.
- **Main keeps a binding, `identityResultCache[T]`.** It passes
  `maxAuthCacheSize` and the eviction sink, and stays usable as a zero value
  (the engine is built on first use under a `sync.Once`), because backends
  embed it by value and tests build backends as literals. It is composition
  only, with no second engine.
- **Tests split by behaviour, with names unchanged.** The nine engine-only
  CHAOS-76 gates move to `internal/identcache` and run against the production
  cap. Provider, dispatch, `/metrics` and expiry-clamp integration gates stay in
  main. One new root gate pins the binding's cap and sink. New package tests
  cover the boundary, with negative controls, and per-cache ownership.

## Consequences

- `go test ./internal/identcache` runs the policy gates without the
  application. The non-root CI lane finds the package through `go list ./...`,
  so no workflow edit is needed.
- `TestIdentcacheBoundary_*` turns a new import, package variable or `init`
  into a test failure that names this ADR.
- No change to behaviour, wire, persistence or metrics: the cap, the policy,
  the counter name and its never-decreasing contract are unchanged.

## Alternatives

- **Leave it in main.** Rejected: that is the finding.
- **Fold it into `internal/authstate`.** Rejected. Its presence test cannot
  tell a stale bucket position from a live one when a key is re-`Set`. This
  cache re-`Set`s every TTL, which is why it needs the per-record `pos`
  generation marker.
- **Keep the eviction total as a package global in `identcache`.** Rejected:
  that is shared runtime state across independent caches and tests, the thing
  ADR-0037's pilot removed for shutdown timing.
