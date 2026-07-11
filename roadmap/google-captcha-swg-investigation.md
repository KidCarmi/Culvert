# Google "Verify you're human" via SWG — Root-Cause Investigation

**Audience:** senior network engineers + SWG developers
**Scope:** Chrome (Win10) → PAC → Culvert forward proxy → Google; `/sorry/index` + reCAPTCHA Enterprise
**Primary evidence:** the attached Chrome NetLog (`chromenetexportlog.json`, Chrome 150.0.7871.102, Win10 19045, 10,187 events) + a full read of the Culvert CONNECT/tunnel data path.

---

## 0. Executive summary — the premise is wrong, and the NetLog proves it

The investigation brief states: *"No TLS interception (no MITM) is enabled. The SWG simply creates a CONNECT tunnel to Google."*

**The NetLog disproves this.** For every Google host that traversed the proxy, Chrome verified a **leaf certificate issued by `O = Culvert, CN = Culvert Root CA`** — not by Google Trust Services. Culvert is terminating TLS and re-signing Google's certificate. **SSL inspection (MITM) is active on the Google path**, whatever the operator believes the config says.

Direct comparison from the capture:

| Host | Path | Cert issuer Chrome verified | Negotiated ALPN |
|---|---|---|---|
| `www.google.com` | via proxy (socket 2222, 2444) | **Culvert Root CA** | **http/1.1** |
| `www.gstatic.com` | via proxy (2286, 2314, 2389, 2392) | **Culvert Root CA** | **http/1.1** |
| `content-autofill.googleapis.com` | via proxy (2306) | **Culvert Root CA** | **http/1.1** |
| `fonts.gstatic.com` | via proxy (2337) | **Culvert Root CA** | **http/1.1** |
| `dns.google` | DIRECT (DoH bootstrap) | Google Trust Services (WR2) | h2 / QUIC |

Only `dns.google` — which goes **DIRECT** (it is the DoH resolver, not proxied) — kept Google's real certificate and negotiated HTTP/2. Everything through Culvert was intercepted and downgraded to HTTP/1.1.

This single fact reorders the entire root-cause matrix. Two capture-proven mechanisms explain the challenge, and they are **the direct consequence of interception**, not of CONNECT mechanics:

1. **TLS-fingerprint mismatch.** Because Culvert terminates and re-originates TLS to Google using Go's `crypto/tls` stack (`tls.Client`, `proxy_tunnel.go:565`), Google no longer sees Chrome's TLS ClientHello (JA3/JA4). It sees **Go's** ClientHello — different cipher ordering, different extension set, no Chrome GREASE pattern, different key-share/PQ behavior. A Go-TLS fingerprint claiming `User-Agent: Chrome` is one of the strongest bot signals Google has, and it is exactly what reCAPTCHA Enterprise / the `/sorry` anti-abuse layer keys on.
2. **HTTP-protocol downgrade.** Real Chrome speaks **HTTP/2 (or HTTP/3)** to Google, always. The capture shows every proxied Google request was **HTTP/1.1** (`HTTP_STREAM_REQUEST_PROTO` = `http/1.1` ×28 through the proxy; `h2` ×1 only for direct `dns.google`). Culvert's MITM client-facing config pins `NextProtos: []string{"http/1.1"}` (`proxy_tunnel.go:473`) and the upstream leg uses `http.ReadRequest`/`req.Write` (HTTP/1.x only, `proxy_tunnel.go:676,715`) with **no ALPN offered upstream** (`upstreamInspectTLSConfig` sets no `NextProtos`, `proxy_tunnel.go:505-520`). So Google sees a "Chrome" that inexplicably negotiates HTTP/1.1. Anomalous → challenge.

A third factor is architectural and always present with any forward proxy:

3. **Shared egress IP + QUIC suppression.** All users egress the single proxy source IP (no `LocalAddr`, `proxy_tunnel.go:347`), and PAC/CONNECT forces Chrome's would-be QUIC/HTTP-3 traffic onto TCP tunnels. This concentrates many TLS sessions on one IP. This is why the problem is *IP-reputation-sensitive* and *worse in Incognito* (no established Google cookie identity to lend the shared IP reputation).

**The single highest-value action is to stop intercepting Google.** With inspection off, Chrome's genuine ClientHello and HTTP/2 reach Google end-to-end, and factors #1 and #2 vanish. What remains is only #3 (IP reputation), which is far less likely to produce a hard `/sorry` block on its own for normal search traffic.

> Note on the "curl returned Google's original cert" observation: that is consistent with selective inspection. Either curl did not match the same policy rule that Chrome's browser traffic matched (Culvert resolves `SSLAction` per policy rule — `resolveSSLAction`, `proxy.go:593`), or curl was not actually routed through the proxy. It does **not** contradict the NetLog; it confirms inspection is rule-scoped, and a rule is matching Google for browser traffic.

---

## 1. Root-cause matrix, ranked by probability

Probabilities are conditioned on the NetLog evidence for *this* environment.

| # | Root cause | Prob. | Why it triggers Google | NetLog verdict |
|---|---|---|---|---|
| **A** | **TLS interception → Go `crypto/tls` fingerprint to Google** | **Very high** | JA3/JA4 mismatch vs. UA-claimed Chrome is a first-order bot signal | **Confirmed active** — Culvert Root CA leafs on all Google hosts |
| **B** | **HTTP/1.1 downgrade to Google (ALPN pinned/absent)** | **Very high** | Chrome never uses H1 to Google; H1 + Chrome UA is anomalous | **Confirmed** — 28× http/1.1 through proxy, 0× h2 |
| **C** | Shared egress IP reputation / large NAT population | High | Many sessions/one IP; datacenter or "dirty" ranges are pre-scored | Consistent — single proxy egress; not directly measurable from client NetLog |
| **D** | QUIC/HTTP-3 suppressed by proxy → all traffic on TCP tunnels | Medium (amplifier) | Loss of H3 removes a signal Google expects from modern Chrome; concentrates load | **Confirmed** — Culvert has zero UDP/QUIC support; Alt-Svc H3 marked "broken" in capture |
| **E** | Incognito cookie discontinuity | Medium (amplifier) | No `NID`/`SID` history to offset a low-rep IP; challenge threshold lower | Consistent — first `/sorry` hit had no prior Google cookies until the 302 set them |
| **F** | Proxy auth (407) re-challenge churn in Incognito | Low (env-dependent) | Extra RTs / retries can look automated | **Not observed** — CONNECTs returned `200`, no `407` in capture |
| **G** | CONNECT upstream pooling / cross-client socket reuse | Very low | If clients shared an upstream socket, session bleed could look scripted | **Ruled out** — strict 1:1 fresh dial per CONNECT (`proxy_tunnel.go:347`) |
| **H** | Retry storms / duplicate GETs / auto-reconnect | Very low | Repeated identical requests look bot-like | **Ruled out** — no dial/CONNECT retry on tunnel path; single `DialContext` |
| **I** | TCP transport anomalies (MSS, window, keepalive, RST vs FIN) | Very low | Extreme deviations *can* feed passive OS/middlebox fingerprinting | Unlikely — Go defaults (NODELAY on, 15s keepalive, graceful FIN); no `SetLinger(0)` |
| **J** | Header injection (Via / XFF / Forwarded / Proxy-Connection) | Very low (this path) | Proxy-disclosing headers can raise suspicion | **N/A on CONNECT** — opaque tunnel, nothing injected; MITM inner path strips hop-by-hop but Google sees Culvert's own H1 request framing |
| **K** | Bandwidth/QoS pacing → timing artifacts | Very low | Regular inter-packet timing can look synthetic | **Ruled out** — no rate/token-bucket wrapping in the data path |

### Why A and B dominate

reCAPTCHA Enterprise and the `/sorry` interstitial fuse many signals, but the ones that flip a normal search query to a hard challenge with **no prior abuse history** are the ones that make a single request look non-human at connection time. A datacenter IP alone usually yields a *soft* score (invisible reCAPTCHA passes, or a one-click checkbox). A **TLS fingerprint that says "not a browser" plus HTTP/1.1 to a host that Chrome only ever reaches over H2/H3** is what produces the immediate, repeatable `/sorry/index` you are seeing — and it appears *only* when traffic traverses the SWG because that is the only point where the fingerprint is rewritten. Removing the PAC removes interception, which is why "DIRECT fixes it immediately."

---

## 2. Debug plan, ordered by priority

### P0 — Confirm/kill interception (minutes; highest leverage)
1. **Prove interception is on** (already proven by NetLog, but reproduce operationally): on the endpoint, `openssl s_client -connect www.google.com:443 -proxy 10.0.0.100:8080 -servername www.google.com </dev/null | openssl x509 -noout -issuer`. If issuer is `Culvert Root CA` → intercepted.
2. **Identify the matching rule.** On the SWG, find the policy rule whose `SSLAction=Inspect` matches Google. Check the URL-category path too (a "Search Engines"/"Web" category rule with Inspect will catch `google.com`). Culvert logs `SSL_INNER ...` lines for every inspected inner request and `SSLInspect: tunnel %q` on open (`proxy_tunnel.go:651,702`) — grep the proxy log for `google.com`.
3. **Bypass Google from inspection** (Smart-Bypass list or a rule with `SSLAction=Bypass`) and retest. `resolveSSLAction` honors the bypass matcher over any Inspect rule (`proxy.go:605`). **Expected result: `/sorry` stops.** This is the disproof/confirmation of the entire hypothesis in one step.

### P1 — If challenges persist after bypass (IP reputation)
4. Capture **SWG → Google** egress and confirm the source IP. Query that IP's reputation (see §3/§8). If the egress is a datacenter/hosting ASN or a heavily-shared NAT, escalate to the mitigations in §8.
5. Compare challenge rate: DIRECT vs. bypassed-through-proxy vs. inspected-through-proxy. Three buckets isolate IP-reputation (bucket 2 vs 1) from fingerprint (bucket 3 vs 2).

### P2 — Instrument for recurrence (see §3)
6. Add per-CONNECT structured tunnel logging + egress-IP/protocol metrics so the next incident is diagnosable without a client-side NetLog.

### P3 — Long-term (see §9)
7. Decide inspection policy for high-sensitivity anti-abuse destinations; consider H2-preserving inspection or a documented no-inspect category for Google/Microsoft/Cloudflare-fronted properties.

---

## 3. Required instrumentation (SWG side)

Culvert already emits a `TUNNEL_CLOSED` request-log entry with bytes/duration for raw tunnels (`store.go` `recordTunnelClose*`). Extend it. **Log one structured event per CONNECT tunnel**, both at open and close:

| Field | Source in Culvert | Why |
|---|---|---|
| `client_ip`, `client_port` | `r.RemoteAddr` | correlate to endpoint |
| `user`/identity | `id.Identity` | per-user challenge rate |
| `dest_host`, `dest_port` | `r.Host` | isolate Google |
| `ssl_action` | `resolveSSLAction` result | **the key field — Inspect vs Bypass per tunnel** |
| `upstream_src_ip`, `upstream_src_port` | `destConn.LocalAddr()` (`proxy_tunnel.go:347`) | **prove which egress IP + detect IPv6 vs IPv4** |
| `upstream_dst_ip` | `destConn.RemoteAddr()` | which Google anycast POP |
| `alpn_offered_upstream` / `negotiated` | `upstreamTLS.ConnectionState().NegotiatedProtocol` (inspect path) | prove H1 downgrade |
| `created_ts`, `close_ts`, `duration_ms` | `time.Now()` at open/close | timing |
| `bytes_sent`, `bytes_recv` | existing counters | volume anomalies |
| `close_reason` | idle-timeout vs EOF vs error | teardown pattern |
| `retry_count` | 0 today (no retries) | future-proof |
| `dial_error` | `502` path (`proxy_tunnel.go:348`) | upstream reachability |

Add a boolean `intercepted` derived from `ssl_action==Inspect`. A dashboard that plots **challenge-adjacent hosts (google.com) by ssl_action** will make the current problem self-evident.

---

## 4. Required packet captures

Two simultaneous captures, time-synced, filtered to one reproduction:

### Client → SWG (on the endpoint or a client-side SPAN)
```
tcpdump -i any -w client_swg.pcap 'host 10.0.0.100 and port 8080'
```
- Confirm the `CONNECT www.google.com:443` request and the `200 Connection Established`.
- Confirm the ClientHello Chrome sends **into the tunnel** carries ALPN `h2,http/1.1` and Chrome's real extension set (JA3). *(NetLog already shows this: SNI `www.google.com`, ALPN `h2,http/1.1`.)*

### SWG → Google (on the proxy host or an egress SPAN)
```
tcpdump -i <egress-if> -w swg_google.pcap 'host www.google.com or net <google-range>'
```
- **This is the decisive capture.** Extract the **ClientHello Culvert sends to Google** and compute JA3/JA4. Compare to Chrome's JA3 from the client capture.
- **Expected under interception:** the two ClientHellos differ — client-side is Chrome's, egress-side is Go's `crypto/tls`. That delta *is* the root cause.
- Confirm the egress ClientHello ALPN is **empty or http/1.1** (not `h2`), and that the negotiated protocol with Google is HTTP/1.1.
- Record the **egress source IP** and confirm whether it is IPv4 or IPv6 (Happy Eyeballs may pick v6; `proxy_tunnel.go:347` sets no address family).

### What to compare, precisely
| Comparison | Intercepted (broken) | Bypassed (correct) |
|---|---|---|
| ClientHello JA3 client-side vs egress-side | **differ** (Chrome vs Go) | **identical** (Chrome end-to-end) |
| SNI | same both sides | same |
| ALPN negotiated with Google | http/1.1 | h2 |
| TLS cert Chrome verifies | Culvert Root CA | Google Trust Services |

Run the capture once with the Google inspect rule ON and once with it Bypassed; the JA3 and ALPN columns flip. That is the proof.

---

## 5. Required code changes

Ordered by impact. Note the biggest fix is **configuration** (bypass Google), not code.

### 5.1 Policy/config (do first, no code)
- Add Google properties (and other anti-abuse-heavy, non-inspectable destinations) to the **Smart-Bypass** list or a dedicated `SSLAction=Bypass` rule. `resolveSSLAction` already lets the bypass matcher override Inspect (`proxy.go:605`). This restores Chrome's genuine TLS + HTTP/2 to Google.

### 5.2 Preserve HTTP/2 through inspection (if inspection of such hosts is truly required — large effort)
The current inspect path is HTTP/1.1-only by construction:
- Client-facing ALPN pinned to `http/1.1` (`proxy_tunnel.go:473`).
- Upstream leg offers no ALPN and parses with `http.ReadRequest` (`proxy_tunnel.go:505-520,676`).

To stop the H1 downgrade signal you would need an **H2-aware MITM**: negotiate `h2` on both legs and proxy HTTP/2 frames (HPACK-aware), or at minimum offer `h2` upstream and relay H2 opaquely when not scanning. This is a significant new engine (documented today as a deferral: *"HTTP/2 inside the tunnel is not parsed... H2 DPI support requires a full HPACK parser,"* `proxy_tunnel.go:664-665`). **Recommendation: do not build this to solve reCAPTCHA — bypass Google instead.** Even a perfect H2 MITM still rewrites the TLS fingerprint (§5.4), so it does not fully solve factor A.

### 5.3 Upstream TLS fingerprint (fundamental limitation)
Culvert dials Google with Go `crypto/tls` (`tls.Client`, `proxy_tunnel.go:565`). Go's ClientHello is **not** Chrome's and cannot be made Chrome's without a fingerprint-shaping TLS library (e.g. a uTLS-style stack). This is the core reason inspection is detectable. **Implication: for destinations that actively fingerprint (Google, Cloudflare-fronted, Akamai bot-manager sites), interception is inherently detectable. Bypass is the correct architecture, not fingerprint spoofing** (which is brittle, an arms race, and arguably adversarial to Google's ToS).

### 5.4 Egress determinism / IPv6 (medium)
- The tunnel dialer sets no `LocalAddr` and no address-family preference (`proxy_tunnel.go:347`). Under Happy Eyeballs, egress may flip IPv4/IPv6 unpredictably, splitting reputation across two IPs. Consider pinning `LocalAddr` (stable, reputation-warmable egress) and/or forcing a single family for anti-abuse destinations, so Google sees one consistent, warmable IP.
- Consider a dedicated egress IP for Google (see §8).

### 5.5 Instrumentation (small, high value)
- Implement the per-CONNECT structured log + metrics from §3/§6. Add `upstream_src_ip`/`negotiated_alpn`/`ssl_action` to `recordTunnelClose*`.

### 5.6 Optional TCP hardening (low value here, tidy)
- The tunnel dialer leaves `KeepAlive` unset (Go default 15s). Fine. No `SetLinger` (graceful FIN — correct). No change needed; called out only to confirm transport is **not** a factor.

---

## 6. Recommended runtime metrics

Expose in the `culvert_*` Prometheus namespace:

- `culvert_tunnel_open_total{ssl_action, dest_class}` — inspected vs bypassed, per destination class (google/other).
- `culvert_tunnel_upstream_alpn_total{protocol}` — count of upstream negotiations by `h2`/`http/1.1`/none. **A spike of `http/1.1` to Google is the alarm.**
- `culvert_tunnel_egress_ip{ip, family}` gauge — which source IP(s) and family are in use. Detects IPv4/IPv6 split.
- `culvert_upstream_dial_errors_total{host}` — 502 rate.
- `culvert_connlimit_rejections_total` — 503s from the per-IP cap (default 1024, disabled) — currently not a factor but worth watching under H3-suppression fan-out.
- `culvert_tunnel_duration_seconds` histogram + `culvert_tunnel_idle_timeouts_total` — teardown pattern.
- **Correlate externally:** challenge rate is not visible to the SWG. Track `/sorry/index` hits via endpoint telemetry or Google Workspace/Cloud reCAPTCHA analytics and overlay against `ssl_action`.

---

## 7. Known behavior (industry corroboration)

- **Google `/sorry/index`** is Google's anti-automated-traffic interstitial. It keys heavily on egress IP reputation *and* client fingerprint (TLS + HTTP semantics + headers). Shared/datacenter IPs and non-browser TLS stacks are the classic triggers. Enterprises routing Search through a proxy commonly see this; Google's guidance is essentially "don't send bot-shaped traffic from shared IPs."
- **reCAPTCHA Enterprise** ingests TLS/HTTP client signals. A `crypto/tls`/`OpenSSL`/`BoringSSL`-non-Chrome fingerprint under a Chrome UA is a well-documented detection vector (JA3/JA4 tooling exists precisely to catch this).
- **Enterprise SWGs (Zscaler, Netskope, Palo Alto, McAfee/Skyhigh, Cisco Umbrella)** all ship **SSL-inspection bypass categories/lists** and explicitly recommend **not decrypting** Google, Microsoft update, banking, and certificate-pinned/anti-bot properties — for exactly this reason (breakage + bot flags + pinning). They also maintain **warmed, dedicated egress IP pools** with good reputation rather than a single shared NAT.
- **Chromium**: over an HTTP `CONNECT` proxy, Chrome cannot use QUIC/HTTP-3 (no UDP through a TCP tunnel) and does not H2-multiplex the tunnel itself; it opens per-origin CONNECTs. Alt-Svc H3 advertisements get marked "broken" (visible in this capture's `altSvcMappings`). So proxying inherently strips H3 — an expected, documented consequence, and an amplifier here.
- **Culvert-specific**: MITM forces client ALPN to `http/1.1` (`proxy_tunnel.go:466-473`) and cannot parse in-tunnel H2 (`proxy_tunnel.go:664-665`) — both are documented limitations that directly produce the H1-downgrade signal.

---

## 8. Short-term mitigations

| Mitigation | Pros | Cons | Recommendation |
|---|---|---|---|
| **Bypass SSL inspection for Google** (Smart-Bypass / `SSLAction=Bypass`) | Restores real Chrome TLS + H2 end-to-end; kills factors A & B; zero infra change; reversible instantly | Loses DPI/file-block/DLP visibility into Google traffic | **Do this first.** Highest leverage, lowest cost. |
| **PAC `DIRECT` for Google** | Fully removes proxy from the path; guaranteed fix | Bypasses *all* SWG controls (logging, policy, threat feed) for Google; may violate egress-control posture; split-tunnel complexity | Use only if bypass-inspection is insufficient and policy allows Google to go direct. |
| **Dedicated, warmed egress IP for Google** | Fixes factor C (IP reputation); keeps traffic through SWG | Requires routing/NAT work; IP must be warmed and kept clean; ongoing reputation management | Do this if challenges persist *after* disabling inspection (i.e., true IP-reputation case). |
| **Separate NAT pools per user population** | Limits blast radius of one bad actor; smaller per-IP session counts | More IPs to manage/monitor; still shared within a pool | Good hygiene; pairs with dedicated egress. |
| **Per-destination bypass rules (Google/MS/banking/pinned)** | Targeted; preserves inspection elsewhere | Requires maintaining a bypass category list | Standard enterprise practice; adopt as policy. |
| **Alternative routing (cloud egress / residential-reputation egress)** | Can dramatically improve reputation | Cost; complexity; potential ToS/geo issues | Only for severe, persistent IP-reputation problems. |

**Do not** pursue TLS-fingerprint spoofing (uTLS mimicry) as a mitigation: brittle, an arms race, and adversarial to Google. Bypass is the sanctioned answer.

---

## 9. Long-term remediation

1. **Codify a "no-decrypt for anti-abuse/pinned destinations" policy.** Ship a maintained bypass category (Google, Microsoft, Apple, banking, Cloudflare/Akamai bot-managed) as a first-class SWG feature with a default list. Document that inspecting these breaks anti-bot and pinning.
2. **Egress-IP reputation program.** Dedicated, warmed egress IP(s) with monitoring (reputation feeds, `/sorry` rate telemetry), per-population NAT segmentation, and a runbook for IP rotation when reputation degrades.
3. **Per-CONNECT observability (from §3/§6)** made permanent, with the `ssl_action` + `upstream_alpn` + `egress_ip` dashboard as a standing panel — so any future recurrence is diagnosable server-side without a client NetLog.
4. **If inspection of H2 destinations is a hard requirement**, invest in an **H2-aware MITM** (HPACK parser, `h2` on both legs) *and* accept that the TLS-fingerprint signal (§5.3) remains — i.e., this does not solve reCAPTCHA and should be justified by DLP needs, not anti-bot.
5. **QUIC/HTTP-3 posture.** Document that PAC/CONNECT proxying suppresses H3, and decide whether a MASQUE/HTTP-3-capable forward path is worth building for latency-sensitive users (large effort; unrelated to the reCAPTCHA fix).

---

## 10. Known forward-proxy anti-patterns (reference)

- **Intercepting (MITM) fingerprinting/anti-bot destinations** — rewrites TLS JA3 to the proxy's TLS stack; the #1 cause here.
- **ALPN downgrade under inspection** (forcing HTTP/1.1) — makes modern browsers look legacy/automated.
- **Single shared egress IP for a large user population** — concentrates reputation; one abuser poisons all.
- **Unpredictable IPv4/IPv6 egress** (Happy Eyeballs with no family pin) — splits/So dilutes reputation across IPs.
- **Cross-client upstream socket reuse on CONNECT** — session bleed; would look scripted. *(Culvert avoids this — 1:1 fresh dial.)*
- **Aggressive dial/CONNECT retries** — duplicate requests look bot-like. *(Culvert avoids this — no retries on the tunnel path.)*
- **RST-on-idle teardown / `SetLinger(0)`** — abnormal connection termination patterns. *(Culvert uses graceful FIN + CloseWrite half-close.)*
- **Injecting disclosing headers** (`Via`, `X-Forwarded-For`, `Forwarded`, leaking `Proxy-Connection`) on forwarded requests. *(N/A on CONNECT; the inspect path strips hop-by-hop but note Google still sees Culvert's own H1 request framing, not Chrome's H2.)*

---

## 11. Recommended architecture

```
                       ┌─────────────────────────────────────────────┐
                       │                 Culvert SWG                  │
   Chrome (PAC)        │                                             │
   ───CONNECT────────► │  Policy: resolveSSLAction(host)             │
                       │     ├── Google / MS / pinned  → BYPASS ──────┼──► direct opaque TCP relay
                       │     │      (Chrome's real TLS + H2/H3-attempt │      (genuine Chrome JA3,
                       │     │       reaches origin end-to-end)        │       Google sees a browser)
                       │     └── everything else       → INSPECT      │
                       │            (H1 MITM, DPI/DLP/file-block)      │
                       │                                             │
                       │  Egress: dedicated, warmed IP(s),           │
                       │          pinned family, per-population NAT ──┼──► Internet
                       └─────────────────────────────────────────────┘
```

- **Bypass anti-abuse/pinned destinations** so their traffic is a faithful 1:1 TCP relay (which Culvert already does correctly — see the CONNECT-bypass audit below).
- **Inspect the rest** for DLP/threat, accepting that inspected traffic is HTTP/1.1 with a proxy TLS fingerprint (fine for ordinary sites, fatal for anti-bot ones).
- **Warmed, dedicated, family-pinned egress** with reputation monitoring underneath both.

---

## Appendix A — CONNECT-bypass data-path audit (what Culvert does when NOT inspecting)

Confirms that once Google is bypassed, Culvert is a clean relay and introduces none of the secondary suspects. All citations from a full read of the data path.

1. **Strict 1:1 mapping, fresh dial per CONNECT.** `(&net.Dialer{Timeout:10s, Control:ssrfControl}).DialContext(ctx, "tcp", r.Host)` (`proxy_tunnel.go:347`); `defer destConn.Close()` ties lifetime to the one request. No pooling, no cross-client reuse. *(Ruled out cause G.)*
2. **No upstream/parent proxy on CONNECT/HTTPS.** The chained-proxy `ProxyFunc` is wired only to the plain-HTTP pooled transport; HTTPS/CONNECT always dials Google directly.
3. **No byte injection.** Client gets exactly `HTTP/1.1 200 Connection Established\r\n\r\n` (`proxy_tunnel.go:378`); tunnel is opaque thereafter. Upstream TCP is opened *before* the ClientHello (dial precedes hijack), so no first-byte stall.
4. **Sockets:** TCP_NODELAY on (Go default), keepalive 15s (default), **graceful FIN** on close, `CloseWrite` half-close propagation (`proxy_tunnel.go:245-247`), hard close both sides only on idle-timeout (default **1h**, `proxy_tunnel.go:174`). No `SetLinger(0)`, no RST. *(Ruled out cause I.)*
5. **No retries** anywhere on dial/CONNECT (`502` on dial error, `proxy_tunnel.go:348`). *(Ruled out cause H.)*
6. **Auth:** per-request 407 logic exists but the capture shows CONNECTs returning `200`, no 407 — auth is not implicated here (cause F not observed). An unauthenticated CONNECT under an SSO rule fails closed with `403`, never a redirect.
7. **No UDP/QUIC support** at all (SOCKS5 UDP-associate rejected; no H3/MASQUE). PAC+CONNECT inherently strips Chrome's H3. *(Amplifier D, confirmed.)*
8. **No header injection on CONNECT** (opaque). `Via` never added. `scrubForwardedHeaders`/`removeHopHeaders` apply only to plain-HTTP and the inspect inner path.
9. **Pooled transport (512/64)** is plain-HTTP-only; CONNECT and inspect both dial fresh. No cross-identity socket sharing to Google on any HTTPS path. *(Ruled out cause G.)*
10. **No bandwidth/QoS pacing** in the relay; straight `io.CopyBuffer` with 128 KB pooled buffers. *(Ruled out cause K.)*
11. **DNS by name, twice** (SSRF pre-check + dial), system resolver, Happy Eyeballs on → possible IPv4/IPv6 egress divergence (`proxy_tunnel.go:347`). Single egress IP (no `LocalAddr`). *(Feeds cause C / the IPv6 note in §5.4.)*

**Conclusion of the audit:** on the *bypass* path Culvert is a faithful, transformation-free relay — Chrome's genuine TLS and HTTP/2 would reach Google unaltered. Every secondary hypothesis (pooling, retries, RST teardown, header injection, QoS timing) is ruled out by code. The problem is not the CONNECT relay; it is that **the Google traffic in this capture was not on the bypass path — it was being inspected.**

---

## Appendix B — Key NetLog evidence index

- Proxy config: `proxySettings.effective.pac_url = http://10.0.0.100:8080/proxy.pac`; PAC resolved `PROXY 10.0.0.100:8080` (29×) and `DIRECT` (32×, e.g. DoH). `badProxies = []`.
- CONNECTs observed: `www.google.com`, `www.gstatic.com`, `content-autofill.googleapis.com`, `fonts.gstatic.com` — all to `10.0.0.100:8080`, all `200 Connection Established` with `X-Request-Id` (Culvert's per-tunnel id, `connlimit.go`).
- **Interception proof:** verified leaf certs for all Google hosts issued by `O = Culvert, CN = Culvert Root CA`; only `dns.google` (DIRECT) kept `Google Trust Services / WR2`.
- **Downgrade proof:** `HTTP_STREAM_REQUEST_PROTO` = `http/1.1` ×28 (proxied) vs `h2` ×1 (direct dns.google). Client-facing ALPN negotiated `http/1.1` on all 8 proxied sockets.
- **The challenge:** `GET /search?q=sadad` → `302` → `Location: /sorry/index?...` (710 ms later) → `429 Too Many Requests` on `/sorry/index` → reCAPTCHA Enterprise (`/recaptcha/enterprise.js`, `anchor`, `bframe`, repeated `payload`/`replaceimage`/`userverify` — an image-challenge loop). Response server headers `Server: gws` / `scaffolding on HTTPServer2`, `Set-Cookie: __Secure-STRP/AEC/NID` on the 302.
- QUIC only to `dns.google` (DoH over HTTP/3, DIRECT). Google Alt-Svc H3 entries present but **marked "broken"** — Chrome tried H3, it failed through the proxy, and it fell back to TCP.
```
```
