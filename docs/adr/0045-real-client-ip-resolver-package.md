# ADR-0045: The trusted-proxy client-IP resolver is owned by internal/realclientip

- Status: Proposed for review with the implementation PR (IM-007, 2026-11-14).
- Numbering: ADR-0044 is the highest merged; no open PR touches `docs/adr/`.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-007.
  Related: ADR-0002, ADR-0038 (instance-owned state pattern), ADR-0044.

## Context

`realclientip.go` held the admin-UI trusted-proxy set in two package globals
(`trustedProxyNets`, `trustedProxyNetsMu`) next to the X-Forwarded-For walk
that reads them. Nothing in the file depends on root state. The IM-007 map
asked for an instance owner before the move.

## Decision

Move the set and the walk to `internal/realclientip` as an instance-owned
`Resolver` whose zero value trusts no proxy: `SetTrustedProxies`,
`TrustedProxies`, `ClientIP` (4 exported identifiers). The package has no
package-level variables or `init`, imports no application package, and does no
I/O or logging.

Main keeps the single application instance `clientIPResolver`, persistence in
admin settings (`trusted_proxy_cidrs` plus its saved sentinel), the admin
handler and every call site. `SetTrustedProxyCIDRs`, `ListTrustedProxyCIDRs`
and `realClientIP` remain as one-line wrappers, so no caller changed. The
instance owner and the move land together because the wrappers keep the
caller-visible surface identical; the root file shrinks from two globals to one.

Unchanged: the trust gate (X-Forwarded-For is read only when the direct peer
is in the set), the right-to-left walk over all header fields, canonical IP
output, validation without partial mutation, the error text, and the RWMutex
concurrency contract.

## Tests

`realclientip_test.go` in root is untouched and passes through the wrappers.
The package adds its own table (including a second header field, an
unparseable peer and a bare-IP neighbour), spoof defense, validation, instance
independence, a concurrent set/resolve race test, and a boundary test with
negative controls.

## Consequences

The trust gate can be tested without compiling the application, and a second
Resolver cannot observe the first's trusted set.
