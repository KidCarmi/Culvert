# ADR-0008: Identity-gate the spoofable client-pinned decryption-exclusion evidence

- **Status:** Proposed
- **Date:** 2026-07-13
- **Deciders:** Engineering Advisor (proposed); project maintainer (to ratify — this changes customer-facing behavior)

## Context

The adaptive decryption-exclusion cache (`internal/autoexclude`, `autoexclude_resolve.go`)
promotes a `(profile, host)` to an inspection-bypass only after a **confirm-count** of *distinct
client-evidence tokens* observe the same qualifying inspect failure within a window
(`DefaultConfirmN = 2`). The evidence token is derived by `clientEvidence(identity, clientIP)`:

- the **authenticated identity** when the session is authenticated (`id:<identity>` — strong,
  unspoofable, set server-side), else
- the **client address** (`ip:<ipv4>` raw, or `net6:<ipv6/64>`).

The IPv4 token is deliberately **raw** (not `/24`-bucketed): a `/24` would over-collapse a
legitimate enterprise NAT fleet behind one egress IP into a single evidence token, defeating the
confirm-count for the common case (documented NAT/DHCP limitation).

The production security qualification (roadmap/AUTOEXCLUDE-PRODUCTION-QUALIFICATION.md, finding **F2**)
identified the resulting residual risk:

> For the `client_pinned` reason — which the engine's own comments call **"the spoofable class"**
> because the client fully controls the TLS alert it sends against our forged leaf — the confirm-count
> over **raw IPv4** tokens gives *near-zero* protection against a *deliberate* attacker. `confirmN = 2`
> distinct source IPs is trivially met (two cloud instances, a dual-homed host, any pair of egress
> addresses). An attacker on a broad/unauthenticated fail-open scope can therefore poison arbitrary
> same-scope hosts into a bounded (1h TTL) inspection blind spot by sending a cert-rejection alert
> from two IPs.

The blast radius is bounded by the existing controls — the per-profile fail-open **opt-in**, **scope
isolation** (only same-profile victims), the shorter **1h pinned TTL**, and the loud per-promotion
**audit + alert + metric**. (An *aggregate* burst/rate signal is a separate proposed finding, **F4**,
not part of this decision and not assumed present here.) But the *code-level* barrier for the
spoofable class is effectively the two-IP confirm-count, which is not a barrier against an adversary.
The confirm-count today protects against *accidental* single-endpoint self-poison, not against a
deliberate one on unauthenticated traffic.

This is a **behavior/customer-experience** decision, not a pure hardening fix, which is why it is an
ADR rather than a code change in the F1–F5 hardening sprint: any tightening changes which pinned apps
auto-heal.

## Decision (proposed)

For the **`ReasonClientPinned`** reason only, require **authenticated-identity** evidence: count only
`id:`-prefixed tokens toward its confirm-count, and do not accept IP-only tokens as evidence for that
reason. Concretely, `recordAutoExclude`/`clientEvidence` emit an **empty** token for an IP-only
(unauthenticated) session under `ReasonClientPinned`; the engine already discards `client == ""`
(`autoexclude.go` `Observe`), so such a session contributes nothing toward promotion.

Consequences of the rule:

- A pinned app that breaks inspection **only for unauthenticated traffic** will **no longer
  auto-learn**. The operator's remedy is the **manual SSL Bypass list** (`internal/sslbypass`) — the
  documented, deliberate control for known pinned apps. This is the correct posture for
  un-attributable traffic: an inspection bypass driven purely by attacker-controllable IPs is exactly
  what we do not want to automate.
- The two server-observed reasons (`ReasonClientCertRequired`, `ReasonUnsupportedParams`) are
  **unchanged** — they are not the spoofable class (the origin, not the client, controls those
  signals), so IP evidence remains acceptable for them.

The other two evidence classes stay as-is (raw IPv4 for the NAT-fleet reason; `/64` for IPv6).

## Consequences

- **Positive:** removes the one materially cheap poisoning vector the qualification found. After this,
  poisoning `client_pinned` requires **two distinct authenticated identities** to independently reject
  our leaf for the same host — a far higher bar that a single attacker cannot trivially forge.
- **Negative / customer-visible:** deployments that rely on auto-exclusion for pinned apps on
  **unauthenticated** fail-open segments lose that auto-heal and must add those apps to the manual
  bypass list. This must be called out in release notes and the operator guide.
- **Neutral:** no change to the volatile/node-local/opt-in model, to scope isolation, or to the
  server-observed reasons.

## Alternatives considered

1. **Raise `confirmN` for the pinned class only (e.g. 3–5).** Cheaper to ship and less disruptive
   (unauthenticated pinned apps still auto-heal, just slower). *Rejected as the primary fix* because
   it only raises the number of IPs an attacker needs — a linear cost the attacker pays once — rather
   than removing the spoofable-evidence class. Could be adopted *in addition* as a defense-in-depth
   default.
2. **Subnet-bucket IPv4 evidence (`/24`).** *Rejected* (and previously reverted, commit `e0b93f0`):
   over-collapses a legitimate enterprise NAT fleet into one token, defeating the confirm-count for
   the common case — the exact reason IPv4 is raw today.
3. **Status quo + operator discipline.** Keep the two-IP confirm-count and rely on narrow fail-open
   scopes + the loud per-promotion alerting (plus the proposed F4 burst signal) to detect poisoning
   after the fact. *Rejected as
   sufficient on its own* because it leaves the code-level barrier at "two IPs" and makes safety
   contingent on operator configuration and alert triage rather than on the design. (The alerting is
   still valuable and stays — see F4.)
4. **Make it operator-tunable per profile** (choose IP-vs-identity evidence and `confirmN` per
   decryption profile). The most flexible, but it is a larger config-surface + GUI-parity change
   (tracked separately as qualification finding **F10**). This ADR can be superseded by that work; the
   identity-gate here is a safe default in the meantime.

## Related

- Qualification findings **F2** (this decision) and **F10** (operator-tunable confirm-count/TTL, which
  would generalize it) — `roadmap/AUTOEXCLUDE-PRODUCTION-QUALIFICATION.md`.
- Operator guide: `docs/operator/decryption-auto-exclusions.md` (§ Distinct-client evidence) must be
  updated if this is accepted.
- Separate behavior finding surfaced during the F5 canary work (out of scope here, needs its own
  investigation): a Go client's `HandshakeContext` against a cert-requiring origin does **not** surface
  the `certificate required` string (TLS 1.3 → nil; TLS 1.2 → generic handshake failure), so the
  origin-leg **client-cert live-rescue may not fire** from a client-side handshake error — the rescue
  would need to classify the *post-handshake* alert instead.
