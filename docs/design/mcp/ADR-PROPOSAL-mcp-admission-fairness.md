# ADR PROPOSAL — MCP admission fairness (RISK-026)

**Status:** PROPOSED. Needs a human architecture decision.
**Raised:** 2026-08-24 backend review (MCP-05b) · investigated 2026-08-24 overnight run
**Owner:** MCP Agent Security Gateway (ADR-0024)
**Risk:** RISK-026 (HIGH, OPEN) — remains open. This document does not close it.

---

## 1. The defect

`runtime.LimitConfig.AdmissionBudget` is documented as *"per-source admission
budget (token bucket size)"*. It is validated, ceiling-checked, exposed as an
accessor — and has **zero enforcement call sites**. There is no per-source
admission of any kind:

```go
func (l *Listener) admit(ctx context.Context) (func(), bool) {
    select { case l.queue <- struct{}{}: default: return nil, false }
    select { case l.sem <- struct{}{}: ... }
}
```

`runtime.Request` carries **no client address at all**, so admission has nothing
to key on. Admission is step 1 — before authentication — so the exhaustion costs
an attacker nothing but connections.

**Consequence:** one source can occupy all `MaxConcurrent` (64) workers and all
`QueueDepth` (256) queue slots, pre-authentication.

## 2. What has already been fixed, and what it does NOT fix

Two adjacent amplifiers were removed in this run. Neither is per-source fairness,
and neither closes RISK-026:

- **OVN-07 — per-connection request budget.** HTTP/2 multiplexing meant one socket
  could carry hundreds of concurrent streams into a 64-worker pool while consuming
  one of 1024 connection slots. Measured: **36 requests from one connection sat in
  a shared queue behind a 4-worker pool**; now zero. This is topology-independent
  and needed no source identity. It bounds one *connection*, not one *source* — an
  attacker simply opens more connections (up to `MaxConns`, 1024).
- **OVN-06 — single credential validation.** Removed a 2× amplification of the
  most expensive attacker-reachable operation (~96 µs of a ~206 µs request). This
  halves the cost of the flood; it does not bound who may mount it.

## 3. Why this needs a decision rather than a patch

Every candidate keying strategy is correct for one deployment topology and wrong
for another, and Culvert does not currently know its own MCP topology.

### Option A — per TCP peer (`r.RemoteAddr`), pre-auth

Key on the real socket peer, normalized: IPv6 collapsed to /64, IPv4 raw. **Never
`X-Forwarded-For`** — MCP has no trusted-proxy contract.

*Evidence that this is nearly implied by the shipped defaults.* The observe
listener's defaults are `client_cert_mode: require`, `sender_constraint: mtls`,
`min_assurance: high` (`mcp_observe_startup_config.go`). **A listener that
requires client certificates cannot sit behind a TLS-terminating L7 proxy** — the
proxy would need the client's private key. So in the DEFAULT posture the TCP peer
*is* the client, by construction.

| Topology | Correct? |
|---|---|
| Direct exposure, `client_cert_mode: require` (the default) | YES — peer is the client |
| L4 load balancer (TCP passthrough / PROXY protocol absent) | YES — source IP preserved |
| Corporate NAT, many distinct mTLS clients | **NO** — one key for a whole fleet; a legitimate estate throttles itself |
| L7 terminating proxy (`client_cert_mode: none`) | **NO** — one key for everything |

- **Spoofability:** none. A TCP peer address is validated by the handshake before
  any request exists.
- **Connection reuse / HTTP/2:** irrelevant — the peer is a property of the socket,
  and OVN-07 already bounds one socket.
- **Memory:** attacker-driven cardinality. Requires a hard cap plus eviction.
  Culvert already has the exact pattern in `internal/authstate` (bounded, evicts
  the oldest entry of the client holding the most, so a flooding source evicts
  *itself*) — reusing it is not a new trust model.

**Verdict: correct for the default posture, wrong for NAT.** The NAT case is the
blocker: it converts an availability control into an availability *outage* for a
legitimate customer, silently.

### Option B — per principal / client / tenant, post-auth

Key on the resolved identity.

**Does not solve the stated problem.** Admission runs *before* authentication, and
that ordering is deliberate: it is what stops an unauthenticated flood reaching
signature verification. A post-auth budget cannot bound pre-auth exhaustion —
which is the entire attack. It is valuable *in addition*, never instead.

### Option C — two-tier (RECOMMENDED)

1. **Pre-auth, coarse, per TCP peer.** Generous — sized to stop one peer
   monopolizing, not to apportion fairly. Explicitly disabled when the operator
   declares the listener is behind a terminating proxy.
2. **Post-auth, per principal/client/tenant.** The real fairness control, where
   identity actually exists.

Handles the NAT case correctly: the coarse tier stays wide enough not to hurt a
NAT'd fleet; the fine tier does the apportioning once identity is known.

**Cost:** a new listener configuration field the operator must set correctly, and
two eviction-bounded tables.

### Option D — declare it an external dependency and delete the knob

State that per-source admission is a deployment-layer concern (L4/L7 rate limiter,
service mesh, WAF) and remove `AdmissionBudget`.

*Is that acceptable for an enterprise security gateway?* Partly. Culvert's own SWG
does **not** take this position — it ships `internal/connlimit` (sharded per-IP
connection limiting) and `internal/authstate` (fair-share eviction under
unauthenticated flood) precisely because it does not assume a limiter in front.
An MCP capability that assumed one would be **less** defended than the SWG in the
same binary, which is hard to justify. Rejected as the sole answer, though it
remains a legitimate *interim operator instruction*.

## 4. Recommendation

**Option C**, with the pre-auth tier keyed on the real TCP peer, reusing the
`internal/authstate` fair-share eviction pattern verbatim, and gated on a new
explicit listener declaration:

```yaml
mcp:
  gateway:
    # How this listener is reached. Governs whether the pre-auth per-peer
    # admission budget is meaningful. No default is inferred: an operator
    # behind a terminating proxy must say so, and one who says nothing gets
    # the safe reading for the default mTLS posture.
    network_position: direct | behind_l4 | behind_l7_proxy
```

- `direct` / `behind_l4` ⇒ the peer is the client; the pre-auth budget applies.
- `behind_l7_proxy` ⇒ the pre-auth budget is **disabled** and the status surface
  says so explicitly, so it is visibly absent rather than silently ineffective.
- `client_cert_mode: require` (the default) is **incompatible** with
  `behind_l7_proxy` and must fail validation — this is checkable in code and
  removes the most dangerous misconfiguration.

## 5. Implementation plan (if accepted)

1. Add `network_position` to `mcpObserveStartupConfig` + `ListenerConfig`, with the
   mTLS incompatibility check. No default that silently guesses.
2. Extend `runtime.Request` with an opaque `SourceKey` derived by the LISTENER from
   `r.RemoteAddr` only — never a header. IPv6 → /64, IPv4 raw, mirroring
   `authStateClientKey` exactly.
3. Add a bounded per-source token bucket keyed on `SourceKey`, consulted in
   `admit()` before the queue. Cap the table; evict the oldest entry of the
   heaviest holder (`internal/authstate` semantics) so a flooding source evicts
   itself rather than legitimate clients.
4. Post-auth tier: a second budget keyed on `(tenant, client_id, principal)`,
   consulted after `authenticate` and before dispatch.
5. Metrics: `culvert_mcp_admission_source_rejected_total`,
   `..._sources_tracked`, `..._source_evictions_total`. No raw address is ever a
   label — the key is hashed for metrics and for evidence.
6. Tests: exact-limit N/N+1; concurrent saturation; one source cannot starve
   another; a NAT-shaped fixture (many principals, one peer) is not throttled by
   the coarse tier; table bound holds under flood; eviction is deterministic;
   `behind_l7_proxy` disables tier 1 and says so on the status surface.
7. HA: the budget is node-local and must stay so. A fleet-wide budget would need
   shared state on the request path — explicitly out of scope.

## 6. Until then

`AdmissionBudget` is now recorded as **`reserved` with no enforcement owner** in
`internal/mcp/runtime/limits_ownership_test.go`, the Limits anti-drift wall. That
wall fails the build if the field is ever silently read, and fails it if a bound
is added without declaring an owner. The knob no longer creates operator
confidence it has not earned: its status is an executable, checked fact.

**RISK-026 stays OPEN.**
