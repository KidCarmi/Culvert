# Anti-bot SSL inspection: before, now, and the PAN-OS comparison

**Scope.** How Culvert handles the "inspected traffic trips anti-bot / Google
reCAPTCHA" problem **today** (after the native-HTTP/2 → perf → drain → Decryption
Profile program), how it behaved **before**, and what **PAN-OS** does in the same
situation. Audience: engineers + operators deciding when to inspect vs. bypass.

---

## 0. TL;DR

- **The trigger has two independent halves.** When a forward proxy MITM-inspects
  HTTPS, it changes *two* things the origin can fingerprint: **(A) the TLS
  ClientHello** (JA3/JA4 — the proxy re-originates TLS with its own stack) and
  **(B) the HTTP protocol** (a downgrade to HTTP/1.1 is an anomaly for a
  "Chrome"). Anti-bot systems score both. ([JA3/JA4 + HTTP/2 fingerprinting][ja3])
- **Before:** Culvert always did (B) — it stripped ALPN and forced inspected
  tunnels to HTTP/1.1, and there was *no* way to turn that off. Every inspected
  "Chrome" looked anomalous.
- **Now:** Culvert removes (B) on demand — **native HTTP/2 inspection**, enabled via
  a **Decryption Profile attached to the decryption policy** (opt-in; the profile,
  not the rule, owns the setting), through one protocol-neutral pipeline — and gives
  operators the honest posture for (A): keep identity-preserving / fingerprint-
  sensitive origins on a **no-decrypt exception** (and, roadmap, warmed/dedicated
  egress).
- **PAN-OS does essentially the same thing.** It inspects HTTP/2 **by default** and
  exposes **"Strip ALPN"** as the per-profile downgrade escape hatch ([PAN-OS
  HTTP/2 inspection][panh2]); it routes the un-inspectable/anti-bot cases through
  **decryption exclusions** ([predefined + local cache][panexcl]). **PAN-OS also
  re-originates TLS**, so it *also* changes JA3/JA4 — it does **not** fix half (A)
  either. Nobody "beats" TLS fingerprinting from inside a MITM; the industry answer
  is *don't decrypt that destination*.

The upshot: Culvert now follows an **architectural model aligned with commercial SWG
platforms** — the same "inspect-H2 where you choose, downgrade as the exception,
exclude what you can't safely decrypt" *structure*, with the same honest limit on the
TLS-fingerprint half. This is alignment of the **model**, not a claim of equivalent
maturity across every decryption capability (PAN-OS carries far more: auto-populated
exclusion caches, App-ID-driven policy, HSM-backed keys, etc.).

---

## 1. The problem

A customer put Chrome behind Culvert (PAC → proxy, SSL inspection on to run DLP) and
started hitting Google `/sorry/index` **"verify you're human"** loops — worse in
Incognito, gone when the proxy was removed. See
`roadmap/google-captcha-swg-investigation.md` for the full NetLog investigation.

Root cause (the investigation's finding): the proxy was **actively MITM-inspecting**
(the client chain terminated at Culvert's Root CA), and inspection produced two
anti-bot signals:

| Signal | What the origin sees | Who emits it |
|---|---|---|
| **(A) TLS fingerprint** | ClientHello matches Go's `crypto/tls`, not Chrome — JA3/JA4 mismatch against a "Chrome" User-Agent | any TLS-terminating proxy, inherently |
| **(B) HTTP downgrade** | "Chrome" speaks **HTTP/1.1** to Google, which every real Chrome speaks over **h2** | Culvert specifically (it stripped ALPN) |
| **(C) IP reputation** | shared datacenter/NAT egress IP with a low trust score | the network, not the proxy |

Google's bot defense keys hard on **(A)+(C)**; (B) is an *additional* tell that a
CDN/WAF bot-manager will also score. A protocol fix removes (B). It cannot remove
(A) or (C).

---

## 2. Before

Culvert's MITM had exactly one inspected-tunnel behavior:

- The forged leaf offered **only `http/1.1`** in ALPN, and the upstream leg offered
  **no** ALPN. So an inspected tunnel was **always downgraded to HTTP/1.1**.
- There was **no per-rule control** — no way to say "inspect this as HTTP/2." The
  downgrade was hard-wired.
- Result: every inspected HTTPS flow carried signal (B) on top of the unavoidable
  (A). A "Chrome" that speaks HTTP/1.1 to Google is anomalous, and it was a primary
  cause of the reCAPTCHA loops. The only workaround was to stop inspecting the
  destination entirely (a bypass), losing DLP/visibility.

This is the state the investigation documented, and it is *worse* than the PAN-OS
default (which inspects H2 and only downgrades when told to).

---

## 3. Now (what shipped)

Four increments, each reviewed by an independent panel (commercial-SWG/decryption,
HTTP/2+TLS security, Go runtime, and — added later — a field-CISO voice-of-customer
reviewer):

### 3.1 Native HTTP/2 inspection — removes signal (B) where policy selects it
- Culvert can inspect an HTTPS tunnel **as HTTP/2 end-to-end**: client and origin
  both negotiate `h2`, and Culvert decrypts/inspects/re-encrypts each stream through
  the **same** policy/scan/CDR/file-block pipeline used for HTTP/1.1 (`runInspectExchange`
  — one enforcement path, not a second). `proxy_tunnel_h2.go`, `inspect_h2_alpn.go`.
- **ALPN intersection**, computed per tunnel: peek the client's ALPN (read-only,
  fail-closed) → offer the origin `h2,http/1.1` only when policy *and* the client
  both allow → constrain the forged leaf to what the origin negotiated. Mixed
  quadrants are impossible by construction; an HTTP/1.1-only client is never
  stranded (transparent H1 fallback).
- **Controlled by the Decryption Profile, not by the rule.** Whether a flow is
  inspected as H2 is an attribute of the **Decryption Profile attached to the
  decryption policy** (§3.3) — the policy rule selects *which* traffic and *whether*
  to decrypt; the profile it references decides *how* (including Inspect-as-HTTP/2).
  A rule does not carry its own H2 implementation settings; many rules can share one
  profile. Absent a profile setting ⇒ today's strip/H1 downgrade — an upgrade never
  silently changes inspection behavior.

### 3.2 Performance + resource correctness (so it's safe to leave on)
- Zero-alloc pooled + adaptive-flush response-body copy (`h2CopyBody`); per-stream
  inactivity watchdog; `MaxConcurrentStreams=32`; 1 MiB frame/header caps; Rapid
  Reset (CVE-2023-44487) + CONTINUATION-flood (CVE-2023-45288) mitigated via the
  vendored `x/net`.
- **Graceful GOAWAY-on-shutdown drain** (`proxy_tunnel_h2_drain.go`): inspected H2
  tunnels get a client GOAWAY on shutdown, drain in-flight streams within a bounded
  window, then a hard-close backstop — deterministic teardown, not a SIGKILL cut.

### 3.3 Decryption Profiles — the "how to decrypt" control surface
- A named **`DecryptionProfile`** (`internal/decryptprofile`) is the reusable "how to
  decrypt" object. A **decryption policy rule attaches a profile by name**
  (`PolicyRule.DecryptionProfile`); the profile — not the rule — owns the decryption
  mechanics, and one profile can serve many rules. Managed entirely from the admin
  UI. Fields: **Inspect-as-HTTP/2**, **certificate-verification** posture (strict/
  permissive/skip — folds the old per-rule `TLSSkipVerify`), **fail-close** on
  unsupported TLS (fail-open deferred), **min/max TLS version**, per-stream **stall
  timeout**.
- Every field defaults to **inherit** — a profile changes nothing until an operator
  sets it, and a **dangling/deleted profile is fail-safe at eval**: it falls back to
  the rule's **inline** settings (`StripALPN` / `TLSSkipVerify`), or the strip/verify
  default when there is no inline setting. The invariant that holds is that a bad
  reference can **never disable inspection or newly-skip certificate verification**
  (those decisions are independent of the profile). It does **not**, however, force
  HTTP/1.1: on a rule that still carries a legacy inline `stripAlpn: false`, deleting
  the referenced profile falls back to that inline field and **keeps native H2 on** —
  so during profile deletion/sync failures, check the rule's inline settings rather
  than assuming H2 turned off.
- **Honest positioning is in the product** (rule editor + panel + `docs/operator/
  decryption-profiles.md`): native H2 removes signal (B) but does **not** change the
  TLS fingerprint (A), so Google-class destinations still need Bypass or warmed
  egress.
- Observability: `culvert_inspect_upstream_alpn_total{protocol}` (the H2-vs-H1
  success delta) and `culvert_decrypt_profile_mintls_reject_total{profile}` (makes a
  min-TLS-floor drop attributable, not a silent 502).

### 3.4 The other halves — how (A) and (C) are handled today
- **(A) TLS fingerprint:** *not fixed by inspection* (see §5). It is an inherent
  MITM limitation, addressed only by **not decrypting** the destination.
- **Bypass / no-decrypt is a controlled decryption *exception*, not an anti-bot
  feature.** A **Bypass** rule (`SSLAction: Bypass`, `resolveSSLAction`) or the
  no-decrypt FQDN/pattern list (`internal/sslbypass`) exists to serve, in order of
  intent: **compatibility** (certificate-pinned apps, non-HTTP-over-CONNECT, clients
  that break under interception), **privacy boundaries** (regulated categories —
  banking, health — kept out of inspection by policy), and **applications where
  identity preservation is required** (the client's own TLS/HTTP identity must reach
  the origin unchanged). Fingerprint/anti-bot-sensitive destinations fall into that
  last category — you exclude them *because they need their own identity*, which is
  the same reason you'd exclude any identity-preserving application; anti-bot is a
  symptom, not a new bypass "mode."
- **(C) IP reputation:** out of the proxy's protocol layer; the roadmap item is a
  **warmed/dedicated egress-IP** program (per-destination egress selection).

**Net:** Culvert went from "always downgrade, no choice" to "inspect-as-H2 where you
choose, bypass where you must, and be honest about what inspection can't launder."

---

## 4. If it were Palo Alto — what PAN-OS does

PAN-OS is the reference commercial SWG/NGFW for this exact problem, and Culvert's
model was deliberately aligned with it (aligned in structure, not claiming equivalent maturity).

### 4.1 HTTP/2 inspection — same posture
- PAN-OS **inspects HTTP/2 by default** when SSL decryption (SSL Forward Proxy) is
  enabled — has since PAN-OS 9.0. ([PAN-OS HTTP/2 inspection][panh2],
  [App-ID and HTTP/2][panappid])
- The downgrade is the **exception, exposed as "Strip ALPN"** on the **SSL Forward
  Proxy tab of the Decryption Profile** attached to the Decryption Policy rule.
  Selecting it removes the ALPN extension so the firewall negotiates HTTP/1.1 (or
  classifies the flow as unknown TCP). ([PAN-OS HTTP/2 inspection][panh2])
- This is the same structural choice as Culvert's `DecryptionProfile.InspectHTTP2` / the legacy
  `StripALPN` field: a per-profile toggle, H2 the intended default, strip the
  escape hatch.

### 4.2 Decryption Policy + Decryption Profile — same split
- PAN-OS separates **Decryption Policy** (match criteria: who/where/what → decrypt
  or no-decrypt) from the **Decryption Profile** (how to decrypt: protocol/cipher/
  cert-verification/failure checks). Culvert's **policy rule** (match + `SSLAction`)
  *is* the Decryption Policy layer, and the new **Decryption Profile** is the "how."
- PAN-OS profile "failure checks" (block untrusted/expired cert, block unsupported
  version/cipher, block client-auth) are the same field family Culvert's profile now
  carries (cert-verification + fail-close posture; permissive/fail-open deferred).

### 4.3 What PAN-OS does for the reCAPTCHA/anti-bot case specifically — **decryption exclusions**
- PAN-OS ships a **predefined decryption-exclusion list** of sites that break or
  degrade under decryption (pinned certs, mutual auth), excluded by default; plus a
  **Local SSL Decryption Exclusion Cache** that auto-adds servers whose sessions hit
  an allowed unsupported mode (pinned cert / client-auth / unsupported cipher),
  cached ~12h. ([predefined exclusions + local cache][panexcl], [pinned certs][panpin])
- The operational answer to "Google/reCAPTCHA breaks under decryption" on PAN-OS is
  the **same as Culvert's**: put it on a **no-decrypt / exclusion**. Culvert's
  Bypass rule + `sslbypass` list is the direct analogue; PAN-OS additionally
  *auto-populates* exclusions from the failure cache (a Culvert roadmap item — the
  deferred fail-open posture is the same mechanism).

### 4.4 The fingerprint — PAN-OS has the *same* limit
- A TLS-terminating proxy presents **its own** ClientHello to the origin; the
  origin sees the proxy's JA3/JA4, not the client's. ([TLS-terminating proxy swaps
  the fingerprint][ja3fp]) PAN-OS **re-originates TLS** in SSL Forward Proxy exactly
  as Culvert does, so **PAN-OS also changes the TLS fingerprint** and *also* cannot
  make an inspected "Chrome" look like real Chrome to Google. PAN-OS's answer is the
  same one everyone uses: **exclude the destination from decryption.** It does not —
  and no MITM appliance does — solve the JA3/JA4 half from inside inspection.

---

## 5. Side-by-side

| Dimension | Culvert **before** | Culvert **now** | **PAN-OS** |
|---|---|---|---|
| HTTP/2 under inspection | always downgraded to H1 (no choice) | native H2, opt-in via a Decryption Profile attached to policy | native H2 **by default** |
| Downgrade control | hard-wired on | `Inspect-as-HTTP/2` toggle / `Strip ALPN` | **"Strip ALPN"** per profile |
| "How to decrypt" object | none (per-rule bool only) | **Decryption Profile** (H2, cert-verify, TLS floor/cap, stall) | **Decryption Profile** (protocol, cert, failure checks) |
| Match vs. how split | rule only | policy rule + profile | Decryption Policy + profile |
| Un-decryptable / identity-preserving destination | bypass (all-or-nothing) | **no-decrypt exception** (Bypass rule / `sslbypass`) + honest UI copy | **decryption exclusion** (predefined + local cache) |
| Un-decryptable auto-handling | none | fail-close (fail-open deferred) | **local exclusion cache** auto-adds (12h) |
| TLS fingerprint (JA3/JA4) | changed (unavoidable) | changed (unavoidable) — stated in-product | changed (unavoidable) |
| Egress IP reputation | shared | shared (warmed-egress on roadmap) | shared unless SNAT-designed |

---

## 6. The honest crux — two distinct fingerprints, two distinct answers

The single most important thing to communicate is that "the fingerprint" is really
**two** independent problems with **two** different resolutions:

- **HTTP-protocol-downgrade fingerprint (signal B) — SOLVED by native HTTP/2
  inspection.** The "Chrome-that-speaks-HTTP/1.1" anomaly is a *product* behavior, and
  native H2 removes it. This is a real fix for the class of destinations that score
  the protocol anomaly — CDN/WAF bot-managers that *score* rather than hard-block, and
  business-critical H2 SaaS you must keep under DLP.
- **TLS fingerprint (signal A, JA3/JA4) + egress-IP reputation (signal C) — an
  INHERENT MITM LIMITATION, NOT solved by inspection.** A TLS-terminating proxy
  presents its *own* ClientHello; the origin sees the proxy's JA3/JA4, never the
  client's. This is true of **any** MITM — Culvert and PAN-OS alike. It is addressed
  **only** by a **decryption exception** (don't decrypt the destination) and/or a
  **future egress strategy** (warmed/dedicated egress IP for reputation). No inspection
  setting changes it.

So native H2 is **not** the Google reCAPTCHA cure — Google keys on A + C — and it was
never meant to be. Culvert now states this distinction **in the product**, so the
operator who enables the profile for Google sees the expectation *before* they file
the same ticket twice.

---

## 7. Customer impact — what changes for a security administrator

Enabling native HTTP/2 inspection (by attaching a Decryption Profile with
Inspect-as-HTTP/2 to a decryption policy rule) changes the following, and nothing
else — it does not alter which traffic is decrypted, the DLP/threat pipeline, or the
data an admin sees per request:

| | **Before** (H1 downgrade, no choice) | **After** (native H2 where policy selects it) |
|---|---|---|
| Protocol the origin sees on inspected flows | HTTP/1.1 for every inspected "Chrome" (anomalous) | `h2` when the client and origin both support it (matches a real browser) |
| Soft bot-challenges on scored H2 SaaS | frequent (protocol anomaly counts against the flow) | materially reduced (the protocol anomaly is gone) |
| DLP / scanning / policy on inspected flows | full | full — **unchanged** (same one pipeline) |
| Control granularity | none — all inspected traffic downgraded | a reusable **Decryption Profile** attached per policy; many rules share one |
| Google / hard-fingerprinting destinations | CAPTCHA loops | **unchanged** — still challenge (A + C survive); handle via a no-decrypt exception |
| Compatibility risk | n/a | native path transparently falls back to H1 for H1-only / gRPC / WebSocket origins — no flow is stranded |

**Concrete examples an admin will recognize:**

- **"DLP on a sanctioned HR/ERP SaaS behind a bot-manager was breaking users."**
  Before: keep inspecting and users hit soft challenges, or bypass and lose DLP.
  After: attach an Inspect-as-HTTP/2 profile to that rule → the H1 anomaly disappears,
  challenges drop, DLP stays on. **This is the headline win.**
- **"Google Search throws reCAPTCHA when inspected."** Before *and* after: still
  challenges (TLS fingerprint + IP reputation are untouched). The correct action is
  unchanged — a **no-decrypt exception** for Google (and, later, warmed egress). The
  difference is the product now *tells* the admin this at bind time instead of leaving
  them to discover it.
- **"What do I actually do day one?"** Nothing changes unless you act: no profile ⇒
  identical to before. To adopt, create one profile (a `recommended-h2` on-ramp is
  seeded, unbound), attach it to the specific rules where you want H2, and watch
  `culvert_inspect_upstream_alpn_total{protocol="h2"}` climb to confirm the
  negotiation changed.

## 8. What's left (roadmap, in priority order)

1. **Warmed/dedicated egress-IP** program (`LocalAddr` pin + per-destination egress
   selection) — the only sanctioned lever against the (A)+(C) residual.
2. **Auto-exclusion cache** (aligning further with commercial SWG behavior):
   fail-open posture + a local
   decryption-exclusion cache that auto-adds origins that break under inspection.
3. `permissive` cert-verification (verify-but-allow+log) and the fail-open *action*
   (deferred slice 6).
4. **`:authority` pinning / 421** (shared H1+H2 hardening).

---

## Sources

- [PAN-OS — HTTP/2 Inspection (Strip ALPN on the Decryption Profile)][panh2]
- [PAN-OS — App-ID and HTTP/2 Inspection][panappid]
- [PAN-OS — Local SSL Decryption Exclusion Cache + Predefined Exclusions][panexcl]
- [PAN-OS — Troubleshoot Pinned Certificates][panpin]
- [TLS fingerprinting (JA3/JA4) + HTTP/2 fingerprinting for bot detection][ja3]
- [A TLS-terminating proxy presents its own JA3/JA4][ja3fp]
- Culvert: `roadmap/google-captcha-swg-investigation.md`, `docs/operator/http2-inspection.md`, `docs/operator/decryption-profiles.md`

[panh2]: https://live.paloaltonetworks.com/t5/community-blogs/http-2-inspection/ba-p/337392
[panappid]: https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/app-id/http2
[panexcl]: https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/decryption/decryption-exclusions/local-ssl-decryption-exclusion-cache
[panpin]: https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/decryption/troubleshoot-and-monitor-decryption/decryption-troubleshooting-workflow-examples/troubleshoot-pinned-certificates
[ja3]: https://scrapfly.io/web-scraping-tools/ja3-fingerprint
[ja3fp]: https://wilico.co.jp/en/blog/tls-fingerprint-ja3-ja4-detection
