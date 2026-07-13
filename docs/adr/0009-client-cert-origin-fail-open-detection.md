# ADR-0009: Detect the origin CertificateRequest to make client-cert fail-open functional

- **Status:** Proposed
- **Date:** 2026-07-13
- **Deciders:** Engineering Advisor (proposed); project maintainer (to ratify — this changes runtime behavior on the SSL-inspect bypass path)

## Context

The adaptive decryption-exclusion feature documents three learnable inspect-failures, one of
which — **origin requires a client certificate** (`certificate_required`) — is the *only* reason
allowed to **live-rescue** the triggering session (bypass inspection transparently), per the
operator guide and `classifyOriginInspectFailure` (`autoexclude_resolve.go`).

The F5 classifier-qualification work (canary + fuzz, merged) **empirically discovered that this
path never fires in production.** The strip-inspect path decides based on the error returned by the
proxy's upstream `tls.Client.HandshakeContext` (`proxy_tunnel.go`), and a Go TLS *client* dialing a
cert-requiring origin does not produce a `certificate required` error there:

- **TLS 1.3** (the modern default; `upstreamInspectTLSConfig` caps nothing above `MinVersion
  TLS1.2`): the client completes its handshake and `HandshakeContext` returns **nil** — TLS 1.3
  sends the client Finished before the server validates the (absent) client cert. So the
  `if err != nil { maybeFailOpenOrigin(...) }` branch is **never entered**: no rescue, no learn. The
  proxy proceeds to inspect, sends `200 Connection Established`, and the origin's
  `certificate_required` alert only surfaces **mid-relay**, breaking the tunnel after connect.
- **TLS 1.2**: `HandshakeContext` returns a generic `remote error: tls: handshake failure`, which the
  classifier deliberately drops (origin-controlled/ambiguous) → plain `502`, no rescue, no learn.

Confirmed by `TestClientCertRescue_GapConfirmed` (dials a cert-requiring origin through the exact
`upstreamInspectTLSConfig`). The operator guide has been corrected to state the limitation; this ADR
proposes the fix. The `unsupported-params` and `client-pinned` learn paths are unaffected.

This is a **runtime behavior decision on a security-sensitive path** (it turns on an
inspection-bypass that does not happen today), which is why it is an ADR rather than a silent fix —
mirroring ADR-0008 (F2).

## Decision (proposed)

Detect the origin's **`CertificateRequest`** directly, independent of TLS version and of the
handshake error string, using a `GetClientCertificate` callback on the upstream inspect `tls.Config`:

```go
// in upstreamInspectTLSConfig / ...ForMatch
var originAskedForClientCert atomic.Bool
cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
    originAskedForClientCert.Store(true)
    return &tls.Certificate{}, nil // we have none to present
}
```

The callback fires exactly when the origin sends a `CertificateRequest`, in **both** TLS 1.2 and 1.3,
*before* the strip path has sent the client `200`. The strip path then keys the client-cert fail-open
decision on this flag instead of the (unreliable) handshake error:

- **Handshake failed** (TLS 1.2 path) **and** `originAskedForClientCert` **and** rule is fail-open ⇒
  treat as `client_cert_required`: **learn + live-rescue** via `handleTunnelBypass` (as the docs
  describe), instead of the current generic-`handshake_failure` `502`.
- **Handshake succeeded** (TLS 1.3 path) **and** `originAskedForClientCert` **and** rule is fail-open ⇒
  inspection *will* break on relay, so **rescue now**: close the inspect upstream and
  `handleTunnelBypass` before sending `200`. (Still confirm-count-exempt, and now correctly audited/
  alerted/metered via the merged F1 `recordAutoExcludeRescue`.)
- The **native-ALPN** path (`handleInspectNativeALPN`) sends the `200` before the upstream handshake,
  so it cannot rescue — it becomes **learn-only** there (record the observation so the next session
  self-heals), consistent with its existing learn-only posture.

Fail-close rules are unchanged: the flag is consulted only when `resolveFailOpen(match)` is true.

## Consequences

- **Positive:** the documented, opted-into client-cert fail-open behavior actually works, for both TLS
  versions. Removes this reason's dependence on a brittle Go error string (the F5 concern) — a
  structured callback replaces `strings.Contains(msg, "certificate required")`, which the canary
  showed never matches a real client dial anyway.
- **Security tradeoff (why this needs ratification):** it *increases* inspection bypass for
  cert-requiring origins that today fail/`502`. This only ever happens under an **explicit per-profile
  fail-open opt-in** and within that profile's scope — it delivers the operator's stated intent, it
  does not widen bypass beyond the opt-in, and every rescue is now loud (F1 audit + alert + metric,
  plus the F4 surge signal on bursts). Still, turning a bypass ON is a decision for the maintainer.
- **Cost:** a small change to the two inspect handlers + the upstream config builder; a per-connection
  `atomic.Bool` on the inspect path (negligible). `TestClientCertRescue_GapConfirmed` flips to assert
  rescue=true.

## Alternatives considered

1. **Classify the post-handshake alert (mid-relay).** *Rejected:* on TLS 1.3 the alert surfaces only
   after `200` is sent and relay begins — too late to rescue cleanly, and it would require inspecting
   relay-read errors on the hot path.
2. **Force upstream `MaxVersion: TLS1.2`** so the handshake fails synchronously with a classifiable
   error. *Rejected:* downgrades every inspected origin to TLS 1.2 — a security and compatibility
   regression far worse than the bug.
3. **Document-only + manual bypass list (status quo).** Safe and already shipped as the interim
   remedy, but leaves a documented feature non-functional. This ADR supersedes that as the real fix.
4. **Remove client-cert rescue entirely** (drop the reason from the classifier + docs). Simplest and
   most conservative (never bypass on this signal). Viable if the maintainer decides auto-bypassing
   client-cert origins is not wanted at all — in which case the fix is to *delete* the path rather
   than repair it. This ADR recommends repair (option in the Decision) but records deletion as the
   explicit conservative alternative.

## Related

- F5 (classifier qualification, merged) surfaced this; `TestClientCertRescue_GapConfirmed` pins it.
- `docs/operator/decryption-auto-exclusions.md` — the "Known limitation" note documents current
  reality until this lands.
- ADR-0008 (F2) — same "behavior change on the decryption-exclusion security path ⇒ ADR" discipline.
- `roadmap/AUTOEXCLUDE-PRODUCTION-QUALIFICATION.md` — the production qualification this derives from.
