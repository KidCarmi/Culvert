# ADR-0009: Detect the origin CertificateRequest to make client-cert fail-open functional

- **Status:** Accepted (2026-07-13 — ratified: repair, not deletion) — implemented
- **Date:** 2026-07-13
- **Deciders:** Engineering Advisor (proposed); project maintainer (ratified the repair direction)

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

Confirmed empirically by dialing a cert-requiring origin through the exact `upstreamInspectTLSConfig`
(now pinned by `TestClientCertRescue_DecisionRealHandshakes`, which drives real handshakes rather than
mocked error strings). The `unsupported-params` and `client-pinned` learn paths are unaffected.

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
decision on this flag **together with a proven handshake failure** — never on a successful handshake:

- **Handshake FAILED** **and** `originAskedForClientCert` **and** rule is fail-open **and** the error is
  not a cert-verify failure ⇒ treat as `client_cert_required`: **learn + live-rescue** via
  `handleTunnelBypass` (as the docs describe), instead of the current generic-`handshake_failure`
  `502`. This is the **required-mTLS on TLS 1.2** case: the origin demands a cert we cannot present and
  the handshake genuinely breaks, so inspection provably cannot continue.
- **Handshake SUCCEEDED** (`herr == nil`) ⇒ **never rescue**, even though `originAskedForClientCert` is
  set. A completed handshake means the connection is **inspectable**, and we cannot tell a *required*
  mTLS origin apart from an *optional* one (`tls.RequestClientCert`) at this point — both complete our
  client handshake. Bypassing here would wrongly strip inspection from optional-mTLS origins (the
  reviewer's finding). The two herr==nil shapes this covers:
  - **Optional mTLS** (any version) — the origin merely *requests* a cert and completes anyway; it is
    fully inspectable and MUST stay inspected.
  - **Required mTLS on TLS 1.3** — our client handshake completes locally (client Finished precedes
    the server's cert validation) before the origin rejects, so we cannot prove un-inspectability from
    the handshake result. Safe posture: keep inspecting; if the origin truly breaks on relay, the
    operator adds it to the manual **SSL Bypass** list. This is the accepted residual limitation.
- The **native-ALPN** path (`handleInspectNativeALPN`) sends the `200` before the upstream handshake,
  so it cannot rescue — it stays **learn-only** there, consistent with its existing posture.

Fail-close rules are unchanged: the callback is attached and the flag consulted only when
`resolveFailOpen(match)` is true.

## Consequences

- **Positive:** the documented, opted-into client-cert fail-open behavior actually works for the case
  we can prove — **required mTLS on TLS 1.2**. Removes this reason's dependence on a brittle Go error
  string (the F5 concern) — a structured callback replaces `strings.Contains(msg, "certificate
  required")`, which the canary showed never matches a real client dial anyway.
- **Bounded, not universal (security-first).** Rescue fires ONLY on a proven handshake failure, so it
  can never strip inspection from an **optional-mTLS** origin (which completes the handshake and stays
  inspectable) — the reviewer's false-positive is structurally excluded. The cost is that **required
  mTLS on TLS 1.3** is NOT auto-rescued: at TLS 1.3 our client handshake completes before the origin
  rejects the missing cert, so required and optional are indistinguishable from the handshake result,
  and choosing safety means those origins go to the manual **SSL Bypass** list. Preferring a missed
  rescue over a wrong bypass is the deliberate posture.
- **Security tradeoff (why this needs ratification):** it *increases* inspection bypass for
  TLS-1.2-required-mTLS origins that today `502`. This only ever happens under an **explicit
  per-profile fail-open opt-in** and within that profile's scope — it delivers the operator's stated
  intent, it does not widen bypass beyond the opt-in, and every rescue is now loud (F1 audit + alert +
  metric, plus the F4 surge signal on bursts). Still, turning a bypass ON is a decision for the
  maintainer.
- **Cost:** a small change to the strip inspect handler + the upstream config builder; a per-connection
  `atomic.Bool` on the inspect path (negligible).

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
5. **Rescue on the TLS-1.3 success path too (as originally proposed), distinguishing required from
   optional mTLS with a post-handshake liveness probe.** *Considered and deferred.* To safely rescue
   TLS-1.3 required-mTLS we would need to prove the origin *actually* rejects the missing cert — e.g.
   send a probe request over the completed inspect upstream and rescue only if the origin tears the
   connection down with `certificate_required`. Rejected for now: it adds a blocking round-trip on the
   inspect hot path, races the real client's first bytes, and re-introduces reliance on an
   origin-emitted alert (the exact fragility this ADR set out to remove). The safe, no-probe posture
   (never rescue a successful handshake; manual bypass for TLS-1.3 required mTLS) is preferred until a
   probe design that is off-hot-path and provably non-racy is warranted by real demand.

## Invariants (enforced by tests)

Implemented on the strip path (`handleTunnelInspect`); the decision lives in
`clientCertRescueDecision` and the signal in a fail-open-only `GetClientCertificate`
callback. Each invariant is pinned by a test:

1. **Signal-only callback.** `GetClientCertificate` records `originRequestedClientCert`
   and returns an EMPTY `tls.Certificate` — it never provides/synthesizes a client
   certificate and makes no policy decision.
2. **Decision is the sole gate.** Rescue requires `clientCertRescueDecision(failOpen,
   originAsked, herr)` == true: a concrete fail-open profile **and** the origin-asked
   signal **and** NOT a cert-verify failure. *(TestClientCertRescue_DecisionRealHandshakes)*
3. **Rescue only on a proven handshake failure; a successful handshake is inspectable.**
   Detection works in both TLS 1.2 and 1.3 (the `CertificateRequest` signal fires
   either way), but rescue requires `herr != nil`. The TLS-1.2 required-mTLS case
   (handshake fails) rescues; every herr==nil case — optional mTLS (any version) and
   TLS-1.3 required mTLS (handshake completes locally before the origin rejects) — stays
   inspected, so optional-mTLS origins are never wrongly bypassed. TLS-1.3 required mTLS
   is the accepted residual (manual SSL Bypass list).
   *(TestClientCertRescue_DecisionRealHandshakes: positive_TLS1.2_required + inspectable_{optional_TLS1.2,optional_TLS1.3,required_TLS1.3_success}; TestMITM_ClientCertOrigin_RescuesAndBypasses (TLS1.2); TestMITM_OptionalClientCertOrigin_StaysInspected)*
4. **Strip path only.** The callback + rescue live in `handleTunnelInspect`; the
   native-ALPN path is unchanged (it has already sent the 200).
5. **Fail-close never participates.** The callback is attached ONLY when
   `resolveFailOpen(match)`; a fail-close rule never learns, rescues, or consults the
   mechanism, and the decision re-checks `failOpen` defensively.
   *(TestClientCertRescue_DecisionRealHandshakes/negative_fail_close_never_rescues)*
6. **Cert-verify stays fail-closed.** An untrusted/expired/mismatched origin cert
   aborts before the callback and is excluded by `isOriginCertVerifyErr` (nil-guarded).
   *(…/negative_cert_verify_fails_closed)*
7. **Generic alerts never rescue.** They leave `originAsked` false, so they can never
   reach the rescue branch (they fall through to the existing learn/502 path).
8. **Feature-off is byte-identical.** No fail-open profile ⇒ no callback attached ⇒
   inspection behaves exactly as before.
9. **SSRF-guarded re-dial.** The rescue bypasses via `handleTunnelBypass`, which
   re-runs `isPrivateHost` + the `ssrfControl` connect gate.
   *(TestClientCertRescue_SSRFRedialRejected)*
10. **Observable independent of promotion.** Every rescue emits a
    `decryption.autoexclude.rescue` audit event, the `decryption_autoexclude_rescue`
    alert, the `culvert_decrypt_autoexclude_rescue_total` metric, AND a structured
    `autoexclude_client_cert_rescue` ActionTaken on the TUNNEL_CLOSED feed entry —
    plus it LEARNS (confirm-count) for the next session.
    *(TestMITM_ClientCertOrigin_RescuesAndBypasses, TestClientCertRescue_FeedReasonPlumbing)*

## Related

- F5 (classifier qualification, merged) surfaced this gap empirically.
- `docs/operator/decryption-auto-exclusions.md` — the "How client-certificate origins are detected"
  note documents the shipped mechanism and the TLS-1.3 required-mTLS residual.
- ADR-0008 (F2) — same "behavior change on the decryption-exclusion security path ⇒ ADR" discipline.
- `roadmap/AUTOEXCLUDE-PRODUCTION-QUALIFICATION.md` — the production qualification this derives from.
