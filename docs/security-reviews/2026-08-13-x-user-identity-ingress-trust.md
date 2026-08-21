# Security review — `X-User-Identity` ingress trust boundary

- **Date:** 2026-08-13
- **Reviewer:** Claude architecture/security review (Policy Learning Foundation Round, F1)
- **Component:** forward-proxy request dispatch (`proxy.go`)
- **Risk register:** RISK-024 (MEDIUM, closed by this change)
- **Change window:** F1 commit (this PR) — independent, bisectable security fix

## Finding

`X-User-Identity` is an **internal** header. The auth layer stamps it from the
resolved identity (`proxy.go`, `handleRequest`) and the egress scrub
`scrubForwardedHeaders` deletes it before any upstream forward. Before this
change, the scrub ran **only** on the three egress sites
(`proxy_http.go:92`, `proxy_tunnel.go:96`, `proxy_tunnel.go:1085`) — there was
**no ingress scrub**.

On the request path, `handleRequest` stamped the header only when the auth
layer produced a non-empty identity, then **read it back** for policy
evaluation:

```
if authenticatedIdentity != "" { r.Header.Set("X-User-Identity", authenticatedIdentity) }
...
identity := r.Header.Get("X-User-Identity")            // ← read-back
match := policyStore.Evaluate(clientIP, identity, ...)
```

On every posture where authentication produces **no** identity, the `Set` is
skipped and nothing deletes an inbound value, so a client-supplied
`X-User-Identity` survived into `policyStore.Evaluate` as the `SourceIdentity`
input and into the log-attribution recorders. The affected identity-free
postures:

- default-`Exempt` (`defaultAuthOutcome = Exempt`, open mode) — `proxy.go` arm 3a'
- scoped-`Exempt` rule match — `proxy.go` arm 3a
- no-backend inert (no local user, no legacy provider, no enabled IdP) — arm 3 default
- `authRequired == false` (the whole Stage-1 block skipped)

The in-code comment asserting the value was "already stripped … safe to use for
policy matching" was incorrect: the strip was egress-only.

Related residual noted in the 2026-07-11 window review: `scrubForwardedHeaders`
touched `r.Header` only, not `r.Trailer`, so a trailered `X-User-Identity` was
unscrubbed on egress as well.

## Classification

- **CWE-290** Authentication Bypass by Spoofing · **CWE-807** Reliance on
  Untrusted Inputs in a Security Decision · OWASP A07.
- **Severity: MEDIUM.** Precondition: the deployment runs an identity-free
  posture (Exempt or no-backend). Authenticated deployments 407 before
  evaluation and were never exposed; `SourceGroup` matching was never exposed
  (groups are IdP-derived, never header-derived); SOCKS5 was never exposed (no
  headers, never calls `Evaluate`).

## Impact / blast radius

1. **Authorization:** an unauthenticated client could satisfy a
   `SourceIdentity`-scoped access rule by asserting that identity — including
   rules an admin scoped more tightly than a group rule — altering
   allow/redirect/block, SSL inspect/bypass, and file-profile outcomes for that
   request.
2. **Forensic attribution:** request-log / SIEM entries could be stamped with a
   client-chosen identity (`proxy_http.go` FILE_BLOCKED / SCAN_BLOCKED /
   POLYGLOT_BLOCKED recorders read the header).
3. **Forward-looking:** it would poison any identity-keyed Learning Mode
   observation evidence — which is why this is remediated as a hard
   prerequisite before any learning code (ADR-0025 §5).

## Fix

`proxy.go`, three coordinated changes (minimal diff, no signature churn):

1. **Ingress scrub, fail-closed:** `r.Header.Del("X-User-Identity")` at the top
   of `handleRequest`, before `resolveRequestAuth`. No downstream branch can
   observe a client value regardless of future control-flow edits.
2. **Remove the load-bearing round-trip:** policy evaluation consumes
   `authenticatedIdentity` (already in scope) directly; the header read-back is
   deleted and the comment corrected.
3. **Trailer hardening:** `scrubForwardedHeaders` also deletes
   `X-Forwarded-For` / `X-Real-IP` / `X-User-Identity` from `r.Trailer` when
   non-nil.

The server-stamped `X-User-Identity` **request header is retained** solely as
transport for the existing plain-HTTP logging consumers in `proxy_http.go`. It
is no longer an authority boundary: with the ingress scrub, the only value that
can appear there is the server-stamped one. This residual header transport is
recorded **technical debt** (RISK-024 residual), to be replaced with explicit
typed identity plumbing when the HTTP forward path is next touched — expected
during Learning Mode observation wiring (M2). No new readers may be added.

## Why it is safe (evidence)

| Property | Evidence (server-side, un-spoofable) |
|---|---|
| No client value reaches auth | `r.Header.Del` runs before `resolveRequestAuth`; auth never consults the header |
| No client value reaches policy eval | `Evaluate` takes `authenticatedIdentity` (the resolved auth-context field), not `r.Header.Get` |
| No client value reaches log attribution | ingress `Del` + conditional re-stamp: the header holds only the server-resolved identity or nothing |
| No identity/topology leak on egress | header + trailer both scrubbed at every forward site |
| Authenticated attribution preserved | regression test asserts a spoofed header alongside real creds logs the REAL identity, not the spoof |

## Tests (each fails on the parent commit, passes after the fix)

`authz_identity_ingress_test.go`:

- `TestIdentityIngress_ExemptSpoofDenied` — Exempt posture, `SourceIdentity`
  rule, spoofed header ⇒ 403, upstream not reached, no identity attribution.
- `TestIdentityIngress_NoBackendSpoofDenied` — no-backend inert posture ⇒ 403,
  upstream not reached, no identity attribution.
- `TestIdentityIngress_AuthenticatedIdentityStillAttributed` — authenticated
  request with a spoofed header alongside real creds ⇒ 200, log carries the
  real identity, never the spoof.
- `TestIdentityIngress_TrailerScrubbed` — trailer keys stripped by
  `scrubForwardedHeaders`.

Parent-commit run recorded three failures (Exempt/no-backend spoof accepted +
200, trailer keys survived); post-fix run is green, and the adjacent
auth/proxy/scrub/inspect suites remain green.

## Residuals

- Server-stamped `X-User-Identity` header transport for HTTP logging (DEBT;
  RISK-024 residual). Typed plumbing deferred to M2.
- No behavior change for authenticated or SOCKS5 traffic.
