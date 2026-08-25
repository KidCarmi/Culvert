# ADR-0033 — MCP admission fairness: two-tier admission (RISK-026)

**Status:** ACCEPTED (architecture = Option C) · operator contract + implementation
**OPEN — product decision required**
**Date:** 2026-08-25 (Shadow-readiness phase)
**Builds on:** `docs/design/mcp/ADR-PROPOSAL-mcp-admission-fairness.md` (analysis of record)
**Related:** ADR-0024, RISK-026 (HIGH, OPEN), OVN-07 (per-connection budget, DONE),
`internal/authstate` (fair-share eviction precedent), `internal/connlimit`

## Context

`runtime.LimitConfig.AdmissionBudget` is documented as a per-source token bucket but has
**zero enforcement call sites** — `runtime.Request` carries no client address, and
admission (`Listener.admit`) runs *before* authentication, so one source can occupy all
`MaxConcurrent` (64) workers and `QueueDepth` (256) queue slots pre-auth at the cost of
only connections. OVN-07 (per-connection budget) and OVN-06 (single credential
validation) reduced adjacent amplifiers but neither is per-source fairness; RISK-026
stays open. The field is recorded `reserved`/unenforced in the Limits anti-drift wall
(`limits_ownership_test.go`), so it creates no false operator confidence today.

The keying strategy cannot be chosen by patch because each is correct for one topology
and wrong for another, and Culvert does not know its own MCP deployment topology:

- **A (per TCP peer, pre-auth):** correct for the default `client_cert_mode: require`
  posture (a listener requiring client certs cannot sit behind a TLS-terminating L7
  proxy, so the peer *is* the client) and for L4 passthrough; **wrong for corporate NAT**
  (one key for a whole fleet ⇒ a legitimate estate silently throttles itself).
- **B (per principal/client/tenant, post-auth):** cannot bound a *pre-auth* flood (the
  actual attack); valuable in addition, never instead.
- **D (declare it external, delete the knob):** the SWG in the same binary does not assume
  a front-end limiter (`connlimit`, `authstate`); an MCP capability that did would be
  *less* defended than the SWG beside it. Rejected as the sole answer; legitimate as an
  interim operator instruction.

## Decision

**Option C — two-tier admission:**

1. **Pre-auth, coarse, per TCP peer** — generous, sized to stop one peer monopolizing
   (not to apportion), keyed on the real `r.RemoteAddr` (IPv6 → /64, IPv4 raw; mirroring
   `authStateClientKey`), **never `X-Forwarded-For`** (MCP has no trusted-proxy contract).
   Bounded table with `internal/authstate` fair-share eviction (a flooding source evicts
   *itself*). **Disabled when the operator declares the listener sits behind a terminating
   proxy.**
2. **Post-auth, per `(tenant, client_id, principal)`** — the real fairness control, where
   identity exists, consulted after `authenticate` and before dispatch.

Node-local only (a fleet-wide budget would need shared state on the request path — out of
scope).

## The remaining human decision (why implementation is not folded into this phase)

Safe implementation of tier 1 REQUIRES a new operator-facing contract, because tier 1
without it reintroduces the NAT-outage it is meant to avoid:

```yaml
mcp:
  gateway:
    network_position: direct | behind_l4 | behind_l7_proxy   # no default is inferred
```

- `direct`/`behind_l4` ⇒ peer is the client ⇒ tier 1 applies.
- `behind_l7_proxy` ⇒ tier 1 **disabled**, and the status surface says so (visibly absent,
  not silently ineffective).
- `client_cert_mode: require` (the default) is **incompatible** with `behind_l7_proxy` and
  must fail validation — removes the most dangerous misconfiguration.

Per the repo's GUI-parity rule, a new config field needs an admin API + UI surface. That
operator-contract + GUI work is a product decision and deserves its own focused PR on the
admission hot path, **not** to be bundled into Shadow-readiness. Implementing tier 1
without `network_position` would be the exact silent-NAT-throttle failure the analysis
rejects — so it is deliberately not done here.

## Implementation plan (when the operator contract is accepted) — unchanged from proposal §5

1. `network_position` in `mcpObserveStartupConfig` + `ListenerConfig` + the mTLS
   incompatibility check; no silent-guess default.
2. `runtime.Request.SourceKey`, derived by the LISTENER from `r.RemoteAddr` only.
3. Bounded per-source token bucket in `admit()` before the queue; `authstate` eviction.
4. Post-auth budget keyed on `(tenant, client_id, principal)` after `authenticate`.
5. Metrics: `culvert_mcp_admission_source_rejected_total`, `..._sources_tracked`,
   `..._source_evictions_total` — hashed key, never a raw address label.
6. Tests: exact-limit N/N+1; concurrent saturation; one source cannot starve another; a
   NAT-shaped fixture (many principals, one peer) is NOT throttled by tier 1; table bound
   under flood; deterministic eviction; HTTP/2 saturation; `behind_l7_proxy` disables
   tier 1 and says so.
7. HA: node-local, explicitly.

## Relevance to Shadow readiness

Admission fairness is a pre-auth availability control; it does not gate Shadow
correctness (Shadow is disabled-by-default and, once activated per the runbook, runs on a
single controlled host with bounded request volume, where monopolization is not the
threat). It is tracked as an exit-criterion signal ("acceptable admission saturation")
but is **not a blocker** for a controlled Shadow activation review. RISK-026 stays OPEN;
this ADR narrows it to a decided architecture plus one bounded operator-contract decision.

## Status for the phase report

`admission fairness` = **PARTIALLY DECIDED**: architecture (Option C two-tier) DECIDED;
the `network_position` operator contract + GUI + implementation OPEN and correctly a
product decision.
</content>
