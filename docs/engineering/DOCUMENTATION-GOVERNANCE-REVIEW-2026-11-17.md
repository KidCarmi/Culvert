# Documentation governance review 2026-11-17

Scope: checked-out `main` at `84b1b4c`, focused on product changes merged since the
2026-11-16 review (`51996b9..84b1b4c`, 35 non-merge commits). Point-in-time record; not a
source of truth for behavior.

## Finding (High): two guides said a non-TLS client on an inspect rule is relayed raw

- **Problem.** `af22214` (SEC-INSPECT-PLAINTEXT-1) changed what happens when a client sends
  non-TLS bytes inside a `CONNECT` on an SSL-inspect rule. Two guides still described the old
  behavior:
  - `docs/enterprise/TLS-INSPECTION-DEPLOYMENT.md` § 4 (GAP-PKI-06 callout): "Non-TLS over
    CONNECT (SSH/RDP) falls back to a raw relay automatically."
  - `docs/operator/tunnel-drain-on-shutdown.md` § 1: the `inspect_fallback` class was "a
    non-TLS protocol … found inside a `CONNECT` on an inspect rule, relayed raw", with no
    mention of the inspection mode.
- **Implementation evidence.**
  - Strip-ALPN path (`handleTunnelInspect`, `proxy_tunnel.go`): the upstream TLS handshake
    runs before the first-byte peek, so a non-TLS origin returns `502`. A first byte other
    than `0x16` now closes both legs and records `DECRYPT_FAILED` through
    `clientInspectFailureOutcome(errInspectNonTLSClient, …)`. That error classifies as a
    client-hello protocol failure (`classifyClientFailure`, `decryption_observability.go`).
    `maybeFailOpenClient` is deliberately not called, so the auto-exclusion learner is not fed.
    `TestMITM_NonTLSClientOnInspectRuleIsRefused` pins the refusal.
  - Native-ALPN path (`handleInspectNativeALPN` → `relayPlaintextInspectFallback`,
    `proxy_tunnel_h2.go`) still raw-relays and registers `tunnelClassInspectFallback`. The
    CHANGELOG entry states that this path is unchanged.
  - Strip is the default. `resolveStripALPN` (`decryptprofile_resolve.go`) selects native only
    when a bound profile sets `InspectHTTP2: true` or the rule sets `stripAlpn: false`.
- **Why it matters.** An administrator who reads that SSH/RDP over `CONNECT` "falls back
  automatically" leaves those hosts on an inspect rule. On the default path those sessions
  now fail (`502`, or a refusal logged as `DECRYPT_FAILED`). The documented remedy was absent:
  bypass those hosts. A monitoring engineer reading the drain page expects
  `inspect_fallback` traffic on every inspect rule; on a strip-only deployment the gauge
  stays at zero.
- **Who is affected.** Operators running SSL inspection with non-HTTPS traffic over `CONNECT`,
  and anyone building dashboards on `culvert_tunnels_active{class="inspect_fallback"}`.
- **Canonical source.** The code paths above and the CHANGELOG `[Unreleased]` › Security
  entry. `docs/operator/http2-inspection.md` is canonical for how strip and native are
  selected; the edited lines name the selectors and do not restate that page.
- **Change.** Both sentences were corrected in place (one line each). Effort: small.
  Risk: low (documentation only).

## Checks performed

- Commits since the previous review were read for operator-visible changes:
  - `6c1fef1`: the deferred audit-log open. The `audit_log_persistence` operator action was
    updated in code, and no guide told operators to restart.
  - `184bc41`: the `admin_route_enforcement_shadow` row. No guide claims to list
    Diagnostics rows; see the debt carried below.
  - `a2bada4`/`dfe25e2`/`761ff04`: the HA compose. These are recorded in CHAOS-121 and were
    not re-audited here.
  - `7f07ca8`: the CA key identifier is kept across renewal. This is consistent with
    `root-ca-expiry.md` and the 2026-11-16 correction.
- The tracked Markdown was searched for other raw-relay or SSH/RDP fallback claims outside
  history, security-review and dated-review records. None remain.
- `python3 docs/agent-context/check.py` passes.

## Not assessed / documentation debt

- Carried: no catalog of Diagnostics row codes, and none of the 40 subscribable alert events.
  The new `admin_route_enforcement_shadow` row widens this gap.
- Carried: the GAP-PKI-05 wording is partly stale (2026-11-16). It is owner-scoped.
- `roadmap/ROADMAP.md` still lists "TLS protocol detection … Fall back to raw relay" as done.
  That entry is a dated roadmap record, not operator guidance, so it was left unchanged.
