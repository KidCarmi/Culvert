# OCSP revocation checking — what it covers, how it fails, how to read it

**Audience:** operators running Culvert with `security.ocsp_check: true` (or the
**OCSP revocation** toggle in the admin UI).
**Related:** `roadmap/CHAOS-ENGINEERING-REVIEW.md` §35 (CHAOS-65),
`docs/operator/root-ca-expiry.md`.

---

## 1. What it covers — read this first

Enabling OCSP does **not** revocation-check the HTTPS traffic your users send
through the proxy. It covers one path:

| Path | Revocation-checked | Why |
|---|---|---|
| `upstream_transport` | **yes** | The shared upstream `*http.Transport`. In practice this means the TLS handshake to an `https://` **parent proxy**, if you have configured one. The plain-HTTP forward path never negotiates TLS to the origin. |
| `ssl_inspect_origin` | **no** | Every inspected HTTPS request. `handleTunnelInspect` / `handleInspectNativeALPN` build their own `tls.Config` (`upstreamInspectTLSConfig`) and the OCSP callbacks are not attached to it. |
| `connect_bypass` | n/a | A bypassed CONNECT tunnel is relayed raw. Culvert never sees the certificate, so there is nothing to check. |

This is recorded as register row **OCSP-8** and is deliberate for now — see §6.
Culvert states it in three places so it cannot be missed:

* a `WARNING` log line at the moment you enable it, from either the config file
  or the admin API;
* the yellow **Coverage** banner on the OCSP panel;
* `culvert_ocsp_path_checked{path="ssl_inspect_origin"} 0` on `/metrics`.

**The practical consequence:** on a node whose OCSP counters are all zero, you
cannot conclude that no revoked certificate was presented. Check
`culvert_ocsp_path_checked` first — all-zero counters are the expected reading
for a deployment with no `https://` parent proxy, because the check never runs.

---

## 2. Posture

Fail **closed**. A handshake is refused unless some responder returns an
**affirmative** verdict — `good` or `revoked` and nothing else. Each of the
following is discarded, not treated as a pass:

| Discarded because | Counter (`reason=` label) |
|---|---|
| the signed response is about a **different certificate** (issuer-chained signature, different serial) — either a genuine response borrowed from another certificate or a faulty responder answering for the wrong serial; the signer's authorization is not re-checked on this path, so it needs investigation rather than proving an attack | `not_for_certificate` |
| the response's **signer is not authorized** for this issuer — no `id-kp-OCSPSigning` on the embedded certificate, or a delegate outside its own validity window (RFC 6960 §4.2.2.2); this is what stops a certificate vouching for its own revocation status | `unauthorized_responder` |
| the response is outside its `ThisUpdate`/`NextUpdate` window | `stale` |
| the responder answered `unknown` — the issuer does not recognise the certificate | `unknown_status` |
| the responder URL was refused before any request (bad scheme, private address) | `responder_blocked` |
| the response could not be parsed for this certificate at all — an HTML error page, truncated DER, a bad signature; an ordinary broken responder, not an attack signal | `malformed` |

When nothing affirmative comes back, the verdict is fail-closed and cached for
**2 minutes** (not the 1-hour verdict TTL), so recovery tracks the responder
rather than the cache. A confirmed `good` or `revoked` is cached for 1 hour,
keyed by the RFC 6960 CertID — issuer name hash, issuer key hash, serial.

`unknown` being a refusal is the one behaviour here that can newly block
traffic. Under the CA/Browser Forum baseline requirements a CA must not answer
`good` for a certificate it never issued, so `unknown` is the answer a
mis-issued or forged certificate draws. If a legitimate upstream trips it, the
`unknown_status` counter names it; the remedy is to fix the responder or the
chain, not to relax the check.

`not_for_certificate` is charged only when a response is demonstrably about
someone else's certificate — the response parses and its signature verifies,
and the serial belongs to a different certificate. Anything that merely fails
to parse, including a multi-status response this check cannot re-examine, is
charged to `malformed` instead, never to this reason.

`unauthorized_responder` is **not** the same kind of signal and the two must
not be read as equivalent (Codex review, PR #1433): the table above lists two
distinct causes and only one of them is hostile. A delegate whose certificate
has simply expired, or was issued without the `id-kp-OCSPSigning` extension,
is an ordinary CA-side misconfiguration — check that delegate's EKU and
validity window before assuming anything else. The case this check exists to
catch is a certificate signing a `good` response about its own serial and
embedding its own leaf as the "responder" — needing no other party at all —
and the counter cannot tell the two apart on its own. Treat a first hit as a
responder-configuration bug to chase down; a rate that persists once the
responder chain checks out clean is the one worth escalating as a possible
bypass attempt.

---

## 3. Bounds

Everything this engine acts on is written by the party being checked — the
responder URLs come out of the peer's own certificate. So:

* **At most 4** AIA responder entries are consulted (`culvert_ocsp_responders_truncated_total`
  counts certificates that carried more; real certificates carry one or two).
* **All of them inside one 5-second envelope**, not 5 seconds each.
* **Redirects are refused.** An OCSP responder has no reason to redirect, and a
  redirect bypasses a URL-level guard.
* **Private-range and non-`http(s)` responder URLs are refused** before any
  request, and the dialer re-checks the resolved address immediately before
  `connect(2)` (DNS rebinding).
* **Concurrent handshakes for one certificate share one query.** Followers wait
  on the leader's result; they never start a second query.

---

## 4. Metrics

Emitted **only when revocation checking is enabled** — a flat zero from a node
that never turned it on is indistinguishable from a broken one.

| Series | Read it as |
|---|---|
| `culvert_ocsp_enabled` | always 1 when any `culvert_ocsp_*` series is present |
| `culvert_ocsp_path_checked{path}` | **the coverage gauge — start here** |
| `culvert_ocsp_revoked_total` | confirmed revocations |
| `culvert_ocsp_fail_closed_total` | handshakes refused for want of a usable verdict |
| `culvert_ocsp_response_rejected_total{reason}` | discarded responses, by cause (§2) |
| `culvert_ocsp_responders_truncated_total` | certificates whose responder list hit the cap |
| `culvert_ocsp_singleflight_joined_total` | handshakes that joined an in-flight query |
| `culvert_ocsp_cache_entries` | cached verdicts |

### Suggested alerting

```promql
# Revocation checking has started refusing traffic. Almost always a responder
# or egress problem, not a wave of revocations — compare against revoked_total.
rate(culvert_ocsp_fail_closed_total[10m]) > 0.1

# A signed response named a different certificate's serial. That is the
# shape of a borrowed-response bypass, but a faulty responder (or an expired /
# no-EKU delegate — signer authorization is not re-checked on this path) can
# produce it too, so investigate before treating it as an attack. Any
# sustained rate here deserves a human. (malformed is excluded on purpose:
# it is the ordinary broken-responder bucket, not an accusation — see §2.)
increase(culvert_ocsp_response_rejected_total{reason="not_for_certificate"}[1h]) > 0

# A response's signer failed RFC 6960 §4.2.2.2 authorization. Usually an
# expired or misconfigured delegate responder certificate — check its EKU
# and validity window first. Only treat this as a possible bypass attempt
# (a certificate vouching for its own revocation status) once that chain
# has been ruled out — see §2.
increase(culvert_ocsp_response_rejected_total{reason="unauthorized_responder"}[1h]) > 0

# Certificates engineered to amplify outbound requests.
increase(culvert_ocsp_responders_truncated_total[1h]) > 0

# The control is on but reaches nothing you care about.
culvert_ocsp_path_checked{path="ssl_inspect_origin"} == 0
```

---

## 5. Diagnosing a fail-closed storm

Symptom: upstream HTTPS connections start failing, `culvert_ocsp_fail_closed_total`
climbing, `culvert_ocsp_revoked_total` flat.

1. **Is it egress?** Responder queries go out **directly** from the Culvert instance —
   they do not traverse a configured parent proxy and do not honour
   `HTTP(S)_PROXY` from the environment. An egress policy that blocks outbound
   port 80 to arbitrary hosts blocks OCSP. Allow the responder hosts named in
   your upstreams' certificates.
2. **Is it the guard?** `culvert_ocsp_response_rejected_total{reason="responder_blocked"}`
   climbing means the responder URL resolves into a private range. That is the
   SSRF guard doing its job; if the responder genuinely is internal (an
   enterprise CA hosting OCSP on the corporate network), this configuration is
   not currently supported — record it and turn the check off rather than
   weakening the guard.

   This counter is deliberately narrow: it moves only for a **demonstrated**
   refusal. A responder whose name simply fails to resolve — a DNS outage, or
   the query budget expiring mid-lookup — does **not** move it, because nothing
   was established about where that host points. Those show up as
   `culvert_ocsp_fail_closed_total` with no rejection reason, which is step 1
   above (reachability), not this step. If you see `responder_blocked` climbing,
   the resolution succeeded and the answer was private.
3. **Is it a delegate responder?** `reason="unauthorized_responder"` climbing
   is almost always a CA-side certificate problem, not an attack: pull the
   responder's own certificate (from the OCSP response, or your CA's docs) and
   check it carries `id-kp-OCSPSigning` and is inside its validity window. A
   renewed or reissued delegate fixes it immediately. Only escalate this as a
   possible bypass attempt if the delegate chain checks out clean and the rate
   persists — see §2.
4. **Is it the clock?** `reason="stale"` climbing with no other symptom is
   usually NTP. Five minutes of skew is tolerated in both directions; more is
   not. Fix the clock; do not widen the tolerance.
5. **Recovery is automatic.** The fail-closed verdict is cached for 2 minutes,
   so connections resume within that window once responders answer again. There
   is nothing to clear by hand.

**Break-glass:** turning the toggle off (admin UI, or `POST /api/ocsp`
`{"enabled": false}`) takes effect immediately for new handshakes. It is
audited as `ocsp.toggle`. It is deliberately **not** on the config-version
rollback surface — a rollback must never silently re-permit traffic to
certificates an admin tightened against.

---

## 6. Why inspected HTTPS is not covered yet

Attaching the callbacks to the inspect path is a one-line change and is not the
hard part. The hard part is that it would make **every inspected HTTPS request**
depend on reaching an external OCSP responder, fail-closed, on networks where
outbound port 80 to arbitrary hosts is exactly what egress policy forbids — the
failure mode being a total HTTPS outage for the fleet, arriving the moment
someone ticks a checkbox that today does almost nothing.

CHAOS-65 made the engine safe enough to be wired there (it previously accepted
borrowed and replayed responses, and could be made to stall a handshake for
~17 minutes). Wiring it is a separate, deliberate decision that needs a soft
posture designed alongside it — observe-only counters first, or
fail-open-and-alert — so that turning it on is reversible in production rather
than a cliff.

**Owner action:** treat "revocation-check inspected HTTPS" as a scoped feature
with a posture decision attached, not as a wiring fix.
