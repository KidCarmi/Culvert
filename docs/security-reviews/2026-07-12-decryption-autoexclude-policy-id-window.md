# Security Regression Review — adaptive decryption auto-exclusion + decryption profiles + policy stable-ID addressing (window 7c64699 → b0dd056)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-12
> **Baseline:** `7c64699` — end of the previous review's window
> (`docs/security-reviews/2026-07-11-h2-inspection-gui-redesign-window.md`)
> **Head:** `b0dd056` (integration branch; `origin/main` still at `8e88a40`, so this
> window has not yet reached the default branch)
> **Scope reviewed:** every code-bearing change merged in the window — 105 files,
> +16,044 / −520 (70 Go files, +8,121 / −337) across 25 first-parent merges
> (PRs #671–#695 and the fast-forwarded #672–#681 fixes): the **adaptive
> decryption-exclusion cache** (`internal/autoexclude` fail-open + auto-learn,
> hot-path glue, admin API, SPA panel), the **per-rule decryption profiles**
> engine (`internal/decryptprofile`, `OnInspectError=="fail-open"`), the
> **policy stable-ID (`?id=`) addressing** for rule update/delete + optimistic
> concurrency + Tier-A rule metadata, the **generic object-references / Where-Used**
> walk (`policy_refs.go`), the **config import dry-run/preview**, the **GeoIP
> host→IP TTL cache** on the policy hot path, the **native-H2 graceful GOAWAY
> drain**, the **DP cert-renewal reconnect + expiry alerting** (CHAOS-12), and the
> **installer image-trust** changes (deploy only published images, seed the pinned
> tag from a locally-loaded image without pulling).
>
> Executed as five parallel deep-review passes (autoexclude fail-open poisoning
> surface; GeoIP hot-path cache; policy ID addressing / authz / precedence; config
> import + decryption profiles; installer trust boundary + H2 drain) plus
> orchestrator spot-checks of the `resolveSSLAction` read path, the SPA XSS surface
> of the new panels, and the DP cert-renewal redial. All findings verified against
> the working tree at `b0dd056`.

---

## Executive summary

**No CRITICAL or HIGH security regressions found in this window.** The two
highest-risk features — a cache that *deliberately disables SSL inspection for a
host* (`autoexclude`) and the per-rule fail-open opt-in (`decryptprofile`) — are
implemented fail-closed and defense-in-depth throughout:

- The auto-exclusion cache **gates both the learn and the read on an explicit
  per-profile fail-open opt-in**, keys every entry by the matched decryption
  profile's stable ID (so one fail-open profile can never create a bypass consumed
  by another), and requires a **confirm-count of distinct client-evidence tokens**
  before promotion. Cert-verification failures (the exfil/poisoning vector) are
  excluded *before* any learnable-reason match, so misclassification can only ever
  fail closed (keep inspecting). Eviction only ever re-enables inspection. The
  engine is bounded (active + pending maps hard-capped) and volatile (never
  persisted, never synced CP→DP, off every config surface).
- A dangling/absent decryption-profile reference resolves to **fail-close
  (inspect)** at every eval seam; the admin write path is RBAC-gated, audited, and
  version-snapshotted; the fail-open field validates against an enum whitelist on
  `Add`/`Update`/`ReplaceAll` and degrades to fail-close on binary downgrade.
- The policy `?id=` edit path **forces the stored rule's current priority onto the
  write**, so a content edit can never silently reorder a security-critical `Deny`
  below an `Allow` — this is strictly *safer* than the priority-keyed path.
  Optimistic concurrency fails closed when armed (`?ifVersion=` mismatch → 409).
- The installer's **cosign trust boundary for the host-root maintenance agent is
  intact and fail-closed** — the "seed from a locally-loaded image" change only
  swaps `pull`→`docker tag`; `verify_pinned_image_signature` still re-derives trust
  from the image's registry `RepoDigest`, so a `docker load`-ed / locally-built
  image has no verifiable digest and the agent install is skipped.
- The native-H2 graceful drain keeps **in-flight streams fully inspected** and
  refuses new streams at the admission fence; nil-guards, atomic/`sync.Map`
  concurrency, and a bounded force-close backstop are all present.
- Every new SPA panel escapes attacker-influenceable strings (the learned host,
  the profile/scope name, the rule comment) through `escHtml` — including HTML
  attributes — so a malicious CONNECT host learned into the exclusion cache cannot
  stored-XSS an admin viewing the panel.

**One genuine (LOW) regression was found and FIXED in this change:** a 59 MB
compiled Go test binary (`Culvert.test`, unstripped, with debug info) was
accidentally committed this window (commit `0fddf38`) and left tracked and
un-gitignored. It contains only test fixtures (no real secrets, verified via a
`strings` scan), so the security impact is repository-hygiene / supply-chain
bloat rather than disclosure. **Fix in this change:** `git rm --cached`,
delete the working-tree copy, and add `*.test` to `.gitignore` so `go test -c`
output can never be committed again.

The remaining items are LOW / by-design-accepted-risk residuals of the opt-in
fail-open feature, or pre-existing classes merely widened this window — tracked
below. No security behavior was otherwise changed.

---

## F1 — [LOW, FIXED here] 59 MB compiled test binary committed and tracked

**CWE:** CWE-1104 (Use of Unmaintained/Unnecessary Artifact) / CWE-668-adjacent
(exposure of resource to the wrong sphere). **OWASP:** A08 Software & Data
Integrity Failures (repository-hygiene facet). **Severity:** Low. **Regression
risk:** introduced *in this window* by `0fddf38` (`perf+ux(decrypt):
qualification cycle …`); no prior tracked binary of this kind.

### Finding

`Culvert.test` — an ELF x86-64 executable, 59,114,518 bytes, dynamically linked,
**not stripped, with `debug_info`** — was committed and is tracked
(`git ls-files` shows it), and it was **not** covered by any `.gitignore` rule.
It is a `go test -c`-style compiled binary of the main package.

- **Impact:** (a) a 59 MB unreviewable binary blob in version control bloats every
  clone and can never be code-reviewed; (b) compiled test binaries embed the full
  package source paths and all test-fixture literals in the symbol table. A
  `strings` scan confirmed the embedded literals are **test fixtures only**
  (`dc=x,dc=com`, `OldPass1234`, `D0Passw0rd!`, `203.0.113.x` documentation IPs,
  `TEST-NET` ranges) — **no real CA passphrase, private key, or production secret**
  — so the disclosure impact is nil in this instance. The durable risk is that the
  *pattern* (committing `go test -c` output) is now in the tree with nothing
  stopping the next one from carrying a build/CI environment.
- **Exploitability / likelihood:** N/A for direct attack; the concern is
  supply-chain integrity and the precedent.

### Fix (in this change)

```
git rm --cached Culvert.test      # untrack
rm -f Culvert.test                # remove the working-tree copy
```

and `.gitignore` gains:

```gitignore
# Go compiled test binaries (`go test -c` / stray `-o *.test` output).
# A 59MB unstripped Culvert.test was accidentally committed once — never again.
*.test
```

`*.test` matches `go test -c` output (files ending `.test`) and does **not** match
Go test *source* files (`*_test.go`), so no real source is newly ignored
(verified: `git ls-files | grep '\.test$'` is empty after the change; the build
and `go test ./internal/autoexclude/` stay green).

### Required tests

Covered by the build itself (`go build ./...` unaffected) plus the existing
`deploy_bundle_contract_test.go` / `.dockerignore` guards for what ships in the
image. A CI guard that fails when any tracked path matches `*.test` or exceeds a
size ceiling would harden this further (recommended, not blocking).

---

## Residual / accepted-risk findings (no code change — documented)

### R1 — [LOW–MEDIUM, by-design accepted risk] `client_pinned` is the most accessible auto-exclusion poisoning vector

**CWE:** CWE-350 (reliance on untrusted client-side signal) / CWE-807.
**OWASP:** A04 Insecure Design. **Severity:** Low–Medium, **within the documented
opt-in fail-open threat model.**

Unlike the origin-leg reasons, `ReasonClientPinned` is entirely client-driven: an
attacker CONNECTs to any real HTTPS host (the upstream handshake succeeds), then
aborts the client-leg handshake against the forged leaf with a `bad certificate` /
`unknown ca` alert. With `confirmN=2` distinct client-evidence tokens inside the
10-minute window, inspection of that host is then disabled for the 1-hour pinned
TTL for everyone matched to that fail-open profile. The in-code comment already
labels this "the spoofable class," and three controls bound it: (a) it requires
**two distinct network positions** — a single NAT egress collapses to one IPv4
token, an IPv6 attacker collapses to one /64 — or two authenticated identities;
(b) it is gated by the **per-profile fail-open opt-in**; (c) it is confined to that
**profile's scope**. A related classifier limitation (R2 below) broadens the learn
set. This is inherent to an opt-in fail-open feature; critical origins belong on
fail-close rules (un-poisonable by construction).

**Recommendation (product/security sign-off, not a code defect):** consider
requiring an *authenticated* client-evidence token specifically for
`ReasonClientPinned` (reject the bare-IP fallback for the spoofable reason),
and/or a higher `confirmN` for that reason; ensure the profile UI warns operators
that enabling fail-open lets clients drive bypass-learning.

### R2 — [LOW, informational] Classifier cannot distinguish a pinned app from a client missing the MITM CA

**CWE:** CWE-1230 (exposure through metadata) / design note. **Severity:** Low.

`classifyClientInspectFailure` matches `bad certificate` / `unknown ca` /
`certificate unknown`. A managed client that simply *lacks the internal CA* in its
trust store emits the **same** alerts as a genuinely pinned app, so under a
fail-open profile an unmanaged/BYOD fleet that never trusted the CA can drive
inspection-bypass learning for arbitrary hosts (still bounded by scope +
confirm-count). Arguably the fail-open intent, but it broadens learning beyond
"pinned apps." **Recommendation:** call this out explicitly in the operator guide.

### R3 — [LOW, informational] A non-promoting live-rescue is log-only (no audit/alert)

**CWE:** CWE-778 (insufficient logging). **Severity:** Low.

`recordAutoExclude` fires the audit-ring entry + `fireAlert` + metric **only on
promotion**. The one confirm-count-exempt path — a single `client_cert_required`
origin failure that live-rescues the current session via `handleTunnelBypass` —
produces only the `SSL_AUTOEXCLUDE_RESCUE` logger line: no audit entry, no alert.
So the security-relevant "*this* session bypassed inspection" event for the first
request is not in the audit ring. The live-rescue re-applies `isPrivateHost` +
`ssrfControl` on its own re-dial (no SSRF regression), and it does not populate the
cache for future sessions without the confirm-count — so the *durable* bypass is
still fully audited. **Recommendation:** emit a distinct audit action for the
rescue itself, not just the promotion.

### R4 — [LOW] GeoIP host→IP TTL cache widens a pre-existing DNS-rebinding/TOCTOU window

**CWE:** CWE-367 (TOCTOU) / CWE-350. **OWASP:** A04. **Severity:** Low.

The GeoIP country decision (`policy.go`, `LookupCached`) and the actual upstream
dial resolve the destination host **independently**. The new `resolvedHostCache`
pins a positive host→IP entry for up to `hostIPCacheTTL = 5m`, so an attacker who
controls their own host's authoritative DNS (fast-flux / low-TTL round-robin) can
have the policy-side resolution observe an allowed-country IP and then serve a
different-country IP to the transport dial for up to 5 minutes — widening a
window that already existed (the two resolutions were always separate) from
per-request to ≤5m and making it more reliable.

**Blast radius is confined to GeoIP country *attribution*.** The cache has exactly
two callers (`geo.LookupFull`, `geo.LookupCached`), feeding only the country
policy match and the dashboard counter. It is **not** on any SSRF-enforcement
path — `isPrivateHost` and the actual dial use a fresh resolution — and it is
**bounded** (`hostIPCacheMaxEntries = 10_000`, ~10% bulk eviction) with correct
`RLock`/`Lock` discipline (`go vet` clean; a `-race` concurrency test exists).
**Fail-closed on miss is preserved:** a miss/negative entry returns `nil` →
`("", false)` → `matchCountry("")` is false → the geo rule does not match.
Negative entries use a shorter `hostIPCacheNegTTL = 30s`. **Recommendation
(optional):** if GeoIP is treated as an enforcement boundary rather than advisory
attribution, cap `hostIPCacheTTL` toward observed DNS TTLs (e.g. ≤60s); otherwise
document country policy as advisory. No change required to keep the fail-closed
contract.

### R5 — [LOW, informational, pre-existing] Client-supplied policy-rule `ID` is kept without a uniqueness check

**CWE:** CWE-706 (incorrectly-resolved reference). **OWASP:** A04. **Severity:**
Low. **Not introduced this window** — but the new `?id=` `DeleteByID`/`UpdateByID`
first-match-wins semantics make it consequential.

`PolicyStore.Add` keeps a non-empty client-supplied `ID` (`if nr.ID == "" { nr.ID
= newRuleID() }`), and neither `validatePolicyRule` (checks duplicate *name* and
*priority*) nor `Add` enforces ID uniqueness. An operator could create two rules
sharing one ULID so a later id-addressed delete/update lands on the wrong rule.
**No privilege escalation** — this requires operator role, which can already
edit/delete any rule directly; impact is an integrity/targeting-confusion edge.
**Recommendation:** have `Add` always generate the ID server-side (ignore any
client-supplied `ID` on create), or add a duplicate-ID check to
`validatePolicyRule`.

---

## What was reviewed and found safe (no finding)

| Surface | Why it's safe (evidence) |
|---|---|
| **Auto-exclusion read path** (`resolveSSLAction`, `proxy.go:637-647`) | Consults the cache **only** when `sslAction==SSLInspect && Rule.DecryptionProfile!="" && FailOpenScope()==ok`. Fail-close rules never populate or consult. Read and learn both resolve scope to the same profile *ID* via the same store → no cross-scope match; rename-safe. |
| **Cert-verify never learns** (`classifyOriginInspectFailure`) | `isOriginCertVerifyErr` is checked first (value-typed `errors.As` targets matching crypto/x509's by-value returns); untrusted/expired/mismatch → `learn=false`. Misclassification fails closed. |
| **Engine bounds** (`internal/autoexclude`) | Active + pending maps hard-capped (`maxEntries`/`maxPending`), batched fail-closed eviction, TTL/window enforced, volatile. Attacker-controllable host cannot grow either map past cap. `-race` tested; clock injected. |
| **Decryption profiles** (`internal/decryptprofile`) | Dangling/absent ref → fail-close (inspect) at every seam; `OnInspectError` enum-whitelisted on `Add`/`Update`/`ReplaceAll`; write path operator-gated + audited + snapshotted; no secret fields (not `Sensitive`); downgrade → fail-close. |
| **Config import dry-run** (`ui_config.go`) | Preview branch is *inside* `apiConfigImport` after `requireRole(RoleAdmin)`; read-only (no store write, no `saveConfigVersion`, no outbound/SSRF, no side effect but an audit append); reflects only counts + values from the admin-uploaded backup, never live secret state. |
| **Policy `?id=` addressing** (`ui_policy.go`, `policy.go`) | New ID handlers are dispatch-only (not routed) behind `requireRole(RoleOperator)`; auth-rule guard preserved; **priority forced from the stored rule** (no reorder via edit); `findByIDCopy` returns copies (no live-ruleset aliasing); metadata stamped server-side (un-spoofable); audit + `saveConfigVersion` on every mutation. |
| **Object-references / Where-Used** (`policy_refs.go`) | `deleteBlockedByReferences` fails **closed** on an unknown object type (409, not silent delete); endpoint is viewer-gated read-only; IdP deliberately excluded (its deletion is already fail-close). |
| **Installer image trust** (`scripts/install.sh`) | Host-root agent trusted only after `verify_pinned_image_signature` cosign-verifies the image's registry `RepoDigest` against the pinned identity; local/`docker load`-ed images have no verifiable digest → agent skipped. Flag-extraction greps use a restricted charset; no `eval`; sudoers rendering hardened (colon-escape). Tag resolver now matches the real `X.Y.Z` shape (improves downgrade resistance). |
| **H2 graceful drain** (`proxy_tunnel_h2*.go`) | In-flight streams stay fully inspected; new streams refused at the admission fence (bare TLS close, fail-closed); nil-guards on every drain hook; `atomic`/`sync.Map` concurrency; bounded 15s force-close backstop prevents an infinite stream from pinning the process; balanced register/unregister + pooled-buffer return. |
| **DP cert renewal reconnect** (`dp_enrollment.go`, `controlplane_client.go`) | Post-renewal `reconnectActive` redials via the existing mTLS `connect`/`buildClientTLS` (no downgrade); connect swaps only after success → a failed redial degrades to the pre-renewal state, never drops the link. Expiry alerting is latched (no alert storm). |
| **SPA new panels** (`static/index.html`) | Learned host, profile/scope name, reason, rule comment all escaped via `escHtml`, including HTML attributes (`data-arg`, `title`); provenance rendered via `textContent`; audit diff JSON escaped. No stored/reflected XSS via a malicious CONNECT host or rule metadata. |
| **Admin surface for the cache** (`apiDecryptionExclusions`) | GET viewer-gated, DELETE (evict/clear) operator-gated, both audited. Evict only ever re-enables inspection (fail-closed direction), so operator authority is appropriate. Volatile → no `saveConfigVersion` by design. |
| **Metrics** (`metrics.go`) | No change to `/metrics` auth posture; the new `{reason,scope}` learn labels are cardinality-capped at 200 with an `_other_` overflow bucket and inline-sanitized for CodeQL. |

---

## Regression analysis

- **Fail-closed direction preserved everywhere.** Every new decision seam
  introduced this window — auto-exclusion learn/read gating, dangling-profile
  resolution, GeoIP cache miss, H2 new-stream admission, config-import preview,
  reference-check-on-delete — errs toward *more* inspection / *less* access on any
  ambiguity. No new default-allow, no new missing-deny.
- **RBAC intact.** All new write handlers keep handler-level `requireRole`
  (operator for policy/profile writes, admin for config import) *plus* the C2
  metadata gate; no route was added without metadata; the auth-rule (admin-only)
  guard survives the new `?id=` dispatch.
- **Secrets containment intact.** The new features add no persisted secret; the
  cache is volatile and off every config surface; the decryption-profile struct
  carries no credential fields; config-import preview reflects no live secret.
- **Backward-compat is fail-safe.** Unknown `OnInspectError` on an old binary →
  fail-close; absent `?ifVersion=` → no weaker-than-before behavior (there was no
  concurrency check before); legacy `unauth_mode` migration remains one-way.

## Residual risk

The material residual risk is **R1** — the opt-in fail-open feature lets a client
with two distinct network positions drive inspection-bypass learning for a host
under a fail-open profile (scope- and confirm-count-bounded, 1h TTL). This is an
accepted, documented property of shipping a PAN-OS-style local decryption-exclusion
cache; the mitigation is operator discipline (keep critical origins on fail-close
rules) plus the optional hardening in R1/R2. **R4** (GeoIP attribution TOCTOU) is a
pre-existing class merely widened to ≤5m and confined to advisory country
attribution — not an enforcement boundary. **R3** (rescue not audited) and **R5**
(client-supplied rule ID) are observability/robustness polish with no
cross-privilege impact. None rises to Medium in the shipped configuration.

---

## Files changed by this review

- `.gitignore` — add `*.test` (prevent recurrence of the committed test binary).
- `Culvert.test` — **removed** (untracked + deleted; F1).
- `docs/security-reviews/2026-07-12-decryption-autoexclude-policy-id-window.md` — this report.
