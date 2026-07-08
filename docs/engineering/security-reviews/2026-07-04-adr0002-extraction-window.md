# Security Regression Review — ADR-0002 Extraction Window

- **Date:** 2026-07-04
- **Reviewer role:** Security Regression Engineer (standing charter, `docs/engineering/ENGINEERING-CONSTITUTION.md`)
- **Baseline (last reviewed clean point):** `f14ea69`
- **Tip under review:** `a13d472`
- **Scope:** 156 non-test Go files changed (+18,731 / −11,608). The window is dominated
  by ADR-0002 engine extractions (logic moved from `package main` into `internal/…`),
  plus targeted DoS-hardening and fail-closed fixes.

## Verdict

**No security regressions found.** Every security-sensitive surface reviewed is either
byte-faithful to the baseline or strictly tighter. The window additionally lands several
genuine hardening fixes (listed below). No security behavior was changed by this review —
none was required.

## Method

The extraction commits claim to be behavior-preserving; a "behavior-preserving" move is
exactly where a security guard can silently vanish, so each critical surface was reviewed
by comparing both sides of the diff (pre-image via `git show f14ea69:<file>`, post-image
at `a13d472`) rather than trusting the claim. Coverage was fanned out across five
independent focused reviews plus direct inspection of the auth-provider, config
export/import, control-plane, and backup-crypto diffs. Extracted-engine unit tests and the
`package main` proxy/policy/IP-filter suites were run green; `go build ./...` is clean.

## Surfaces reviewed and cleared

### CA / MITM trust engine → `internal/ca` (Slice B)
Faithful move. Preserved: ECDSA P-256 + 128-bit serials from `crypto/rand`; PSCA bundle
KDF (PBKDF2-SHA256, 600 000 iters, 32-byte salt) and AES-256-GCM codec; **anti-downgrade
iteration floor (`< 100 000` rejected)**; GCM tag verification fail-closed; root/leaf cert
constraints (`IsCA`, KeyUsage, ExtKeyUsage, validity); `LoadCustomCA`/`ImportBundle`
rejection of non-CA / non-ECDSA / expired certs; `0600` atomic key-at-rest write
(`fileutil.AtomicWrite`, diffed byte-identical); rotation overlap logic; nil-CA →
handshake fails closed (MITM never silently disabled). One cosmetic magic-detector
boundary delta in `restore.go` traced to both-fail-closed; no real bundle affected.

### Session engine → `internal/session` (+ signing-key race fix)
Faithful move. HMAC-SHA256 verification still uses constant-time `hmac.Equal` (not `==`),
verified before any untrusted cookie content is decoded/parsed. Validation order preserved
(signature → token revocation → decode → expiry → user revocation). TTL clamp
`[15m, 7d]` / 8h default, jti (128-bit `crypto/rand`), revocation (token + user, fail-closed),
and cookie flags (`HttpOnly`, dynamic `Secure`, `SameSite=Lax`) unchanged. The claimed
**signing-key race fix is genuine**: the previously-unguarded `sessionSecret` global (raced
between the DP config-sync writer and the per-request MAC reader) is now behind a
`sync.RWMutex`; no TOCTOU, no empty/old-key acceptance window introduced. All four key
install paths keep their `≥32-byte`/hex validation.

### Backup-envelope crypto → `internal/backupcrypt`
Byte-faithful. AES-256-GCM, PBKDF2-SHA256 `KDFIters = 600_000`, header-as-AAD binding,
`encMinIters = 100_000` anti-downgrade floor, and the single opaque
wrong-passphrase-vs-tamper error all preserved (constants confirmed directly at `a13d472`).

### Request / response processing — `proxy.go`, `socks5.go`
Faithful handler decomposition + new raw-tunnel byte accounting. Hop-by-hop stripping
(`removeHopHeaders`, RFC 7230 `Connection` parsing) intact on every HTTP forward path;
`scrubForwardedHeaders` unchanged and now additionally applied on the **WebSocket** and
**SSL-inspect inner-request** forward paths (closes real `X-User-Identity` leaks — a fix).
Tunnel accounting runs only at close, after authorization; authenticated identity flows
only into the internal `TUNNEL_CLOSED` feed entry, never to client/upstream. SSRF guards
present at every dial (CONNECT bypass, WebSocket, SOCKS5). SOCKS5 RFC 1929 negotiation is a
strict relocation (no-auth only when `!AuthEnabled()`; creds zeroed). Default-deny,
Slowloris read deadlines, and log-injection sanitisation preserved.

### Policy / security helpers — `policy.go`, `security.go`, `internal/ssrf`, `internal/sslbypass`
Default-deny (Zero Trust) preserved; FQDN/category/category-group matching equivalent
(the precomputed `normFQDN` is an optimisation with a safe allocating fallback); GeoIP still
fails closed on cache miss. SSRF backbone relocated byte-identical (private-CIDR table,
fail-closed-on-DNS-error, connect-time TOCTOU `Control` guard). SSL-bypass matcher glob
breadth unchanged; malformed regex rejected at set-time (no fail-open).

### DoS bounds + store/limiter extractions
The new map bounds are **janitor/decay-based, never cap-eviction**, so no flood can evict a
live lockout or rate-limit entry (no auth/rate-limit bypass). Login-lockout, admin-API, and
cluster-enrollment limiters only drop entries already decision-dead (lock expired / window
elapsed). Top-hosts decay feeds the dashboard ranking only — not any gating decision.
Upstream pool keeps the raw `Entries()` vs redacted `List()` split; `configver` on-disk
names are integer-only (`v%d.json`, no traversal from actor/action); audit/reqlog fan-out
and JSON-encoded (injection-safe) persistence preserved.

### Control plane / cluster — `controlplane.go`
The `Enroll` decomposition (`admitEnrollment` + `validateEnrollCSR`) preserves every check
(required fields, per-IP rate limit, duplicate-node rejection, atomic token consume, CSR
CommonName ↔ node_id spoofing guard). New ADR-0005 S3 fencing (`haIssuanceAllowed`) gates CA
issuance and revocation-sync, and the epoch ratchet on `ConfigSnapshot` blocks a fenced-out
zombie CP from rolling a DP's config back — net hardening.

### Auth providers / config import
`auth_ldap`/`auth_oidc`/`auth_oidc_flow`: additive hardening only — loud `tls_skip_verify`
MITM warnings and a new SSRF-safe dial context on OIDC introspection. Config export/import
taxonomy extension is admin-gated, non-secret, and never wipes on absent/empty fields; the
shared `content_scan.json` envelope write is guarded against a mixed old-patterns/new-bypass
persist.

## Genuine hardening landed in this window (not regressions)

1. Session signing-key data race closed (mutex-guarded key).
2. `apiSetupComplete` TOCTOU closed — concurrent bootstrap can no longer provision multiple admin accounts.
3. Security-limiter janitor now always runs (previously gated on IP rate-limiting being enabled → unbounded map growth when off).
4. OIDC introspection transport gains the SSRF-safe dial context (RISK-002).
5. IP filter now **fails closed** on a corrupt/unknown mode (was permissive allow-all).
6. `matchAuthSource` rejects cross-IdP scheme confusion (e.g. `oidc:okta` no longer authorises `saml:okta`) — CWE-287.
7. `X-User-Identity` / private-XFF scrub extended to the WebSocket and SSL-inspect forward paths.
8. Forged-leaf client-facing TLS pins `MinVersion: TLS 1.2`.
9. Loud warnings when LDAP/OIDC `tls_skip_verify` is enabled.

## Residual risk (informational, no action required)

The login-lockout and rate-limiter maps are bounded in **time**, not **size**: an
unauthenticated attacker can hold roughly `(attack-rate × lock/window duration)` entries
live at once. This is strictly better than the permanent per-key leak that existed at the
baseline and is not exploitable as an eviction bypass. A future size cap that evicts only
*counting* (never *locked*) entries could close it fully if memory pressure ever warrants.

## Verification performed

- `go build ./...` — clean.
- Extracted-engine unit tests green: `internal/{session,ca,backupcrypt,lockout,connlimit,blocklist,reqlog,audit,upstream,configver,ssrf,sslbypass,pac,rewrite,threatfeed,blocklistfeed,scanner,secscan,totp}`.
- `package main` suites green for policy/proxy/IP-filter/forwarding/hop-header paths.
