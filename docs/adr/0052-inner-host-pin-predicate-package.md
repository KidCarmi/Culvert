# ADR-0052: The inner-host pin predicate is owned by internal/hostpin

- Status: Proposed for review with the implementation PR (IM-019, 2026-11-20).
- Numbering: ADR-0051 is the highest merged; ADR-0040 is reserved by open
  PR #1526. No other open PR adds a numbered file under `docs/adr/`.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-019.
  Related: ADR-0002, ADR-0003 (`internal/hostutil`), ADR-0042 (`internal/alpnpeek`,
  the same shape: a parse the tunnel code calls, owned outside it).
- Product contract: SWG-002 (`contracts/registry.yaml`). Not amended; one code
  path is added so the contract follows the predicate.

## Context

`inspect_host_pin.go` (368 lines, package main; SEC-TUNHOST-1 and -2) held two
responsibilities:

1. **A decision.** `innerHostPinnedToTunnel` and its two helpers
   (`innerAuthorityAsSent`, `innerAuthorityBracketsValid`): given the inner
   request's Host/:authority and the CONNECT host the tunnel was authorized
   for, are they the same destination. About 240 lines, most of them the
   recorded reasoning for each refusal rule. It reads no root name. Its
   imports are `net`, `strings`, `golang.org/x/net/http/httpguts` and
   `internal/hostutil`.
2. **The gate.** The refusal counter `proxyInnerHostMismatchBlocked` (read by
   `/metrics`), `blockInnerHostMismatch` (counter, `statBlocked`, the
   sanitized log line, the protocol-neutral block), the test reset, and the
   file comment that states why the anchor is the CONNECT authority, what the
   IP-literal scope leaves open and why the answer is a 403.

The decision is the part that has been wrong before. Both recorded defects
were the comparison accepting a value that a helper had repaired while
`net/http` serialized the unrepaired one. Its regression tests do not need the
proxy: they drive `http.ReadRequest` and `Request.Write` directly and compare
against the predicate. They nevertheless compiled and ran inside the root test
binary.

ADR-0002 keeps `proxy.go` and the request path in main. That is unchanged:
`runInspectExchange` (`proxy_tunnel.go`) still makes the call, takes the
refusal branch and owns everything that follows. The file is not on ADR-0002's
list, so there is no decision to supersede.

## Decision

Move the decision (1) to `internal/hostpin` with one exported identifier,
`Pinned(innerHost, tunnelHost string) bool`. The helpers become unexported
`authorityAsSent` and `bracketsValid`. Keep the gate (2) in main.

- **Root keeps `innerHostPinnedToTunnel` as a one-line binding.** The call
  site in `proxy_tunnel.go` and the root tests that use the name are not
  edited. `proxy_tunnel.go` is also edited by open PRs #1528 and #1705, so
  not touching it avoids an overlap.
- **Not folded into `internal/hostutil`.** The predicate must refuse
  spellings `hostutil.StripHostPort` repairs on purpose for its other callers
  (threat feed, DPI, scan exclusion, autoexclude, redaction). A separate
  owner keeps the two rules from being merged by a later cleanup; the moved
  test `TestInnerHostPin_SuffixMatchWouldNotHaveCaught` states the same thing
  for the policy matcher.
- **No options, no instance.** The predicate has no state, clock, logger or
  configuration. The package holds no variable and no `init`.

Lifecycle, in one sentence: there is none; `runInspectExchange` calls a pure
function once per inner request and owns the outcome.

Unchanged: every verdict; the order of the refusals (empty inner host, empty
tunnel host, bracket rule, wire serializability, then the IP-literal scope
skip, then strict IDNA comparison); the counter, its `/metrics` series, the
log line (`sanitizeLog` + `%q` on both hosts and the client address), the 403
body, and the point in `runInspectExchange` where the check runs (before the
round trip and before the header scrub).

## Tests

Moved with names and assertions unchanged (they call only the predicate and
the standard library): `TestInnerHostPinnedToTunnel_Equivalences`,
`TestInnerHostPin_SuffixMatchWouldNotHaveCaught` and the wire oracle
`TestInnerHostPin_WireAgreesWithWhatWasPinned`, with its two helpers.

Stay root, unedited (they drive `runInspectExchange`, the counter or the H1/H2
block responders): the other eight `TestInnerHostPin_*` tests, including the
SWG-002 contract test
`TestInnerHostPin_MismatchIsRefusedBeforeTheUpstreamIsContacted`.

New in the package:

- A verdict table over the cross product of 66 inner and 21 tunnel spellings
  (1,386 pairs). Its SHA-256 and its count of accepted pairs (261) were
  captured by running the same table over the root function on main
  `0fe457878` before the move. Five mutant predicates show the table notices
  a changed rule.
- A fuzz target that runs the wire oracle over arbitrary inner authorities.
- A concurrent-call test under `-race`.
- A boundary test: `internal/hostutil` is the only Culvert import; no
  `net/http`, logging, I/O, clock, context or `sync` imports; no package
  variable; no `init`; exported-surface cap. Negative controls reject each.

Mutation checks against the moved and new tests (each fails): skipping the
bracket rule, comparing the client's bytes instead of the wire's, accepting an
empty inner host, dropping `httpguts.ValidHostHeader`.

## Consequences

The rules that decide whether a decrypted request may leave on an authorized
tunnel can be read, tested and fuzzed in about a second without building the
application. The root file is the gate only (136 lines, mostly its scope
statement). A future per-inner-request policy evaluation, the follow-up the
root comment records for IP- and CIDR-authorized tunnels, would replace the
call in `runInspectExchange`; it would not belong in this package, which
compares and does not consult policy.
