# Security Regression Review — TLS resumption + shared MITM leaf key (PR #578) and the 2026-07-05 security batch

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-05
> **Baseline:** `origin/main` @ `7e4e67f`
> **Scope reviewed:** the code-bearing changes merged to `main` on 2026-07-05 that touch a
> security-relevant surface — PR #578 (MITM TLS session resumption, single shared forged-leaf key,
> Root-CA-change ticket-key flush), RISK-019 (`realClientIP`), RISK-013/012 (fail-closed host
> canonicalization + two-tier login lockout), and the threat-feed `SyncStatus` persistence fix.
> Documentation-only commits (README/architecture/governance drift-sync) were excluded.

---

## Executive Summary

**No security regressions were found.** The reviewed changes preserve or strengthen the security
posture. The most sensitive change — enabling TLS session resumption on both legs of the
SSL-inspection MITM tunnel and reusing a single forged-leaf private key — is soundly reasoned and
correctly fenced:

- **Upstream leg resumption** is attached **only** to the verifying `tls.Config`; the per-rule
  `tlsSkipVerify` path has **no** `ClientSessionCache`, so an unverified session can never be stored
  or resumed. Sessions are cached only after a successful, verified handshake, so a resumption
  inherits that handshake's verification.
- **Client-facing (forged-leaf) resumption** correctly ends its epoch on any Root-CA change: the
  new `ca.CAChangedObserver` hook fires on `InitCA` (fresh generation, force-rotate, and the
  `RotateIfNeeded` auto-rotation path) and `LoadCustomCA` (admin upload), flushing the shared
  config's session-ticket keys so no client can PSK-resume a session authenticated under the
  previous CA. This is pinned by `TestMITMResumptionEndsOnCAChange`.
- **The single shared forged-leaf key** grants an attacker nothing beyond what the co-located CA
  key already grants, because `signLeaf` signs with `cm.caKey` **directly** (the `KeyProvider`/HSM
  seam is only used for its `Name()`, never for signing). The private-key ↔ certificate consistency
  that `tls.X509KeyPair` used to check is guaranteed by construction (`CreateCertificate` signs the
  template with `leafKey.PublicKey`), so skipping that check is safe.

The RISK-019 / RISK-013 / RISK-012 fixes are net-positive hardening (fail-closed host
canonicalization, unspoofable/trusted-proxy-aware per-IP keying, DoS-resistant lockout) and were
already adversarially reviewed before merge; this pass re-confirmed their core invariants.

One **LOW residual hardening observation** is recorded below (static per-CA-epoch MITM ticket
key). It is **not a regression** — client-facing resumption did not exist prior to PR #578, so no
prior rotation posture was weakened — and it is mitigated within the realistic threat model.

**Verification:** `go build ./...` clean; `internal/ca` `TestSignLeaf*`, and package-`main`
`TestMITM*` / `TestNormalizeHostStrict` / `TestRealClientIP*` pass (`-count=1`).

---

## What was reviewed, and why it appears safe

### 1. Upstream-leg TLS session resumption (`proxy_tunnel.go`, perf F1)

`upstreamInspectTLSConfig` now attaches a shared `ClientSessionCache`
(`tls.NewLRUClientSessionCache(4096)`) — **but only on the verifying branch**:

```go
if tlsSkipVerify {
    return &tls.Config{ ServerName, MinVersion, InsecureSkipVerify: true } // no cache
}
return &tls.Config{ ServerName, MinVersion, RootCAs: upstreamVerifyRoots(), ClientSessionCache: upstreamSessionCache }
```

- **Isolation of the skip-verify path is intact.** The skip-verify config has no
  `ClientSessionCache`, so it neither writes nor reads the shared cache. An unverified session is
  never cached, and a verified connection cannot resume an unverified one. ✔
- **Cache scoping is per-origin.** The stdlib keys the client session cache on `ServerName`, which
  is set to the port-stripped origin host on every verifying config. A ticket minted for origin A
  can only be offered back to A; a foreign server cannot decrypt it and the handshake falls back to
  a full verified one. ✔
- **SSRF / private-host guard is unaffected.** `isPrivateHost` + the `ssrfControl` connect-time
  dialer run at TCP connect, independent of TLS resumption. ✔
- **No OCSP regression.** The inspect upstream leg is a distinct `tls.Config`, not the shared
  `upstreamTransport`; it never carried the OCSP `VerifyConnection` callback, so nothing was
  removed. ✔

**Accepted, documented tradeoff (universal TLS-resumption semantics):** a session cached while the
origin cert was valid can resume without re-checking that cert until the ticket expires (bounded by
ticket lifetime). This is standard for any resumption-enabled client and is called out in the code
comment. Not a Culvert-specific weakening.

### 2. Client-facing (forged-leaf) resumption + CA-epoch fencing (`proxy_tunnel.go` + `ca.go`, perf F2)

The forged-leaf `tls.Config` is hoisted to a single process-wide `mitmClientTLSConfig` so
session-ticket keys stay stable across connections (enabling TLS 1.3 client resumption). The
security-critical addition is the CA-change epoch fence:

- `ca.CAChangedObserver` is a new publish-once hook fired (with `mu` NOT held) at the end of
  `InitCA` and `LoadCustomCA`. `RotateIfNeeded` reaches it via its internal `InitCA` call, so
  **auto-rotation, manual force-rotate, and custom-CA upload all fire it.** ✔
- `rotateMITMTicketKeys` installs a fresh random 32-byte key via `SetSessionTicketKeys`,
  invalidating every outstanding ticket → the next reconnect cannot take the TLS 1.3 PSK path
  (which never re-runs `GetCertificate`) and must full-handshake, re-presenting a leaf signed by
  the **new** CA. ✔
- `MinVersion: tls.VersionTLS12` and `NextProtos: ["http/1.1"]` are preserved on the hoisted
  config — the client-facing posture floor and the ALPN pin that prevents a silent HTTP/2 →
  raw-relay fallback (which would bypass file-blocking/DPI/scanning) are unchanged. ✔
- Concurrency: `tls.Server` does not mutate the passed config, and `SetSessionTicketKeys` /
  ticket-key reads are guarded by the stdlib's internal mutex, so the shared config is safe under
  concurrent handshakes + rotation. ✔
- `rand.Read` failure leaves the existing keys in place (fails toward "old tickets still valid
  until age-expiry") rather than zeroing — no crash, no downgrade. ✔

Pinned by `TestMITMClientResumption` (resumption works within an epoch) and
`TestMITMResumptionEndsOnCAChange` (resumption is severed across a CA change).

### 3. Single shared forged-leaf private key (`internal/ca/ca.go`, perf F3)

`signLeaf` now reuses one lazily-generated P-256 key (`sharedLeafKey`, double-checked locking) for
every forged leaf, and assembles `tls.Certificate` directly from DER instead of round-tripping
through PEM + `tls.X509KeyPair`.

- **No trust change from key sharing.** The leaf key never leaves the proxy. `signLeaf` signs with
  `cm.caKey` **directly** (`x509.CreateCertificate(..., &leafKey.PublicKey, caKey)`); the
  `keyProvider` seam is referenced only for `Name()` (`ca.go:643`, `:854`) and never for signing,
  so the CA key is always in-process. An attacker able to extract the shared leaf key already holds
  the strictly-more-powerful CA key from the same memory. ✔ (The code comment correctly flags the
  one future condition that would change this: wiring leaf signing to an HSM. Not the case today.)
- **Skipping `X509KeyPair`'s key-match check is safe.** The cert embeds `leafKey.PublicKey` by
  construction and `PrivateKey` is that same `leafKey`, so they match; `Leaf` is populated from the
  parsed DER. ✔
- **Chain composition is byte-identical** to the prior behavior: `[leaf, secondaryCA?]`. The
  primary CA was not sent before and is not sent now (it is the client's trust anchor). ✔
- **Survives rotation correctly.** The shared leaf key is independent of the CA and is intentionally
  not cleared on `InitCA`; each forged leaf is re-signed under the current CA, so a CA change still
  produces leaves chaining to the new CA. Combined with the ticket-key flush (§2), a client cannot
  resume an old-CA session. ✔

### 4. RISK-019 — trusted-proxy-aware `realClientIP` (`realclientip.go`, `ui_auth.go`, …)

- **Safe default preserved:** with no trusted-proxy CIDRs configured, `X-Forwarded-For` is
  **never** consulted and the direct peer is returned. ✔
- **Spoof defense sound:** XFF is honored only when the direct peer is itself in the trusted set;
  the right-to-left walk returns the rightmost hop **not** in the trusted set (the real client the
  innermost trusted proxy handed off). A direct attacker's peer is untrusted → their XFF is ignored
  → they cannot forge a victim's IP, evade their own lockout, or bypass the admin-IP allowlist. ✔
- **Header-splitting closed (Codex P1):** `Header.Values("X-Forwarded-For")` is joined across all
  field lines (per RFC 7230 §3.2.2), so a proxy that appends its hop as a *separate* header line no
  longer lets a client-controlled first field win. ✔
- **Key-canonicalization (review F2):** the returned IP is `net.IP.String()` canonical form, so two
  textual spellings of one address cannot fork the lockout/rate-limit key. ✔
- The proxy **data** path (`handleRequest` rate/conn/IP-filter) is deliberately left on the direct
  peer — those are direct client connections, not proxy-fronted admin requests. ✔

Residual (documented, operator responsibility, inherent to any XFF scheme): correctness depends on
the fronting proxy appending/overwriting XFF honestly. The default-off posture makes this opt-in.

### 5. RISK-013 / RISK-012 — fail-closed host canonicalization + two-tier lockout

- `NormalizeHostStrict` returns `ok=false` on IDNA failure; `handleRequest` and the SOCKS5 handler
  reject with `INVALID_HOST` **before** any blocklist/threat/policy/category matcher runs — closing
  the fail-open canonicalization asymmetry on every primary path. Bracketed/bare IPv6 literals are
  accepted explicitly (`net.ParseIP` short-circuit) rather than relying on `idna.ToASCII` leniency,
  so a future `x/net` tightening cannot start 400-ing valid IPv6 destinations. ✔
- The permissive `NormalizeHost` remains only for admin-entered patterns / store keys, where a
  literal-match fallback admits nothing a valid pattern would have blocked. ✔
- Two-tier lockout (pair lock + trusted-IP-bypassed account lock) keys on the **direct peer**
  (unspoofable on a directly-exposed deployment), and the setup endpoint uses the pair-only path so
  the pre-provisioning bootstrap flow cannot be globally locked. ✔

### 6. Threat-feed `SyncStatus` persistence (`internal/threatfeed/threatfeed.go`)

Adds `LastSuccess`/`LastSyncErr` (both `omitempty`, legacy DB back-fills from `LastSync`). No sync
or business logic changed. `LastSyncErr` holds a fetch-error summary (public feed URLs, not
credentials) — no secret-exposure regression. ✔

---

## Risk Rating

| Item | Regression? | Residual severity |
|---|---|---|
| Upstream-leg resumption (F1) | No | LOW (universal resumption semantics, ticket-lifetime-bounded) |
| Client-leg resumption + CA fence (F2) | No | LOW (static per-CA-epoch ticket key — see below) |
| Shared forged-leaf key (F3) | No | Negligible (same-memory threat equivalence) |
| RISK-019 `realClientIP` | No (net hardening) | LOW (XFF trust is operator config) |
| RISK-013/012 host + lockout | No (net hardening) | LOW (documented residuals, already tracked) |
| Threat-feed persistence | No | None |

---

## LOW residual / hardening observation (not a regression)

**Static session-ticket key for the whole CA epoch on the client-facing MITM config.**

Calling `SetSessionTicketKeys` switches the shared `mitmClientTLSConfig` from the stdlib's
auto-managed keys (24 h rotation, ~7-day lifetime) to a **single manually-set key** that stays
fixed until the next Root-CA change. If CA rotation is infrequent (the default rotates only near
expiry, which can be months to years), one ticket-encryption key can be live for the entire epoch —
longer than the stdlib's default key lifetime.

- **Why this is not a regression:** client-facing resumption did **not exist** before PR #578
  (every inspected connection full-handshook), so there was no prior ticket-key rotation posture to
  weaken. This is a *new* capability with a static-per-epoch key, not a downgrade of an existing
  one.
- **Why the residual is LOW / mitigated:**
  - *Threat-model equivalence:* extracting the 32-byte ticket key requires reading proxy process
    memory, at which point the attacker already holds the CA key and the shared leaf key from the
    same address space — full MITM capability regardless of the ticket key.
  - *TLS 1.3 forward secrecy:* per-session ECDHE keeps session **content** forward-secret even if a
    ticket key later leaks; only the resumption PSK is at risk.

**Optional hardening (defense-in-depth, not required):** add a periodic timer (e.g. daily) that
also calls `rotateMITMTicketKeys`, restoring a bounded ticket-key lifetime and matching stdlib
hygiene, while keeping resumption effective within each day. This complements — does not replace —
the CA-change flush. If adopted, pin it with a test asserting the key changes across the interval
and that resumption survives within it.

---

## Regression Analysis

- **Authentication / Authorization:** admin-UI per-IP controls are strengthened (unspoofable keying);
  no auth bypass, default-allow, or missing-deny introduced.
- **TLS / MITM / Cryptography:** verification is inherited by resumption, never bypassed; skip-verify
  stays isolated from the session cache; CA rotation correctly severs the client resumption epoch;
  key reuse carries no marginal trust exposure.
- **Certificate validation / MITM opportunity:** none opened — the only cert-validation change is the
  documented, bounded resumption window shared by all TLS clients.
- **Fail-closed behavior:** host canonicalization moved from fail-open to fail-closed on the request
  path; IP-filter/lockout defaults remain fail-closed.
- **DoS / memory:** lockout is now DoS-resistant; the session caches are bounded LRUs (4096 upstream,
  8×… client cache is per-client in tests, shared config in prod bounded by stdlib).
- **Backward compatibility:** threat-feed and trusted-proxy persistence use `omitempty`/sentinel
  migration that fails toward the safe prior behavior.

---

## Files reviewed

- `proxy_tunnel.go` — `upstreamSessionCache`, `mitmClientTLSConfig`, `rotateMITMTicketKeys`,
  `upstreamInspectTLSConfig`, `handleTunnelInspect` client handshake
- `internal/ca/ca.go` — `CAChangedObserver`, `InitCA`, `LoadCustomCA`, `RotateIfNeeded`,
  `sharedLeafKey`, `signLeaf`
- `ca.go` — `CAChangedObserver` wiring
- `realclientip.go`, `ui_auth.go` — RISK-019 client-IP resolution + adoption
- `internal/hostutil/hostutil.go`, `proxy.go`, `socks5.go`, `security.go` — RISK-013 gate
- `internal/lockout/lockout.go`, `ui_auth.go` — RISK-012 two-tier lockout
- `internal/threatfeed/threatfeed.go` — SyncStatus persistence
- Tests: `proxy_tunnel_tls_resume_test.go`, `internal/ca/ca_test.go`,
  `internal/ca/ca_bench_test.go`

## Required / existing tests (all present and passing)

- `TestMITMClientResumption`, `TestMITMResumptionEndsOnCAChange` — client resumption + CA-epoch fence
- `TestSignLeaf_ValidCert`, `TestSignLeaf_SharedKeyAndChainVerify`, `TestSignLeaf_DualCAOverlapChain`
  — shared-key signing correctness + chain verification
- `TestNormalizeHostStrict` — fail-closed host gate (valid + IPv6 accept, invalid punycode reject)
- `TestRealClientIP_SpoofDefense` — XFF spoof defense

## Residual Risk

Overall residual: **LOW**. One documented hardening opportunity (periodic MITM ticket-key rotation)
that does not weaken the prior posture and is mitigated by same-memory threat-model equivalence and
TLS 1.3 forward secrecy. No code change is required to remove a regression, because none was
introduced.

---

*CWE/OWASP mapping for the classes examined (none found exploitable in this diff):*
CWE-295 (Improper Certificate Validation), CWE-297 (Improper Validation of Cert with Host Mismatch),
CWE-384 (Session Fixation), CWE-290 (Authentication Bypass by Spoofing), CWE-348 (Use of Less
Trusted Source / XFF), CWE-807 (Reliance on Untrusted Inputs in a Security Decision), CWE-441
(Unintended Proxy / SSRF), CWE-1188 (Insecure Default), CWE-522 (Insufficiently Protected
Credentials). OWASP: A05 Security Misconfiguration, A07 Identification & Authentication Failures,
A02 Cryptographic Failures, A10 SSRF.
