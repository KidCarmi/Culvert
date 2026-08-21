# Security Regression Review — MCP Agent Security Gateway + signed SaaS feed + source-aware category resolution (window `67ab218` → `3d13f7a`)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-08-04
> **Baseline:** `67ab218` — head of the previous review's window
> (`docs/security-reviews/2026-07-26-m7-telemetry-authsnapshot-scan-sslbypass-window.md`)
> **Head:** `3d13f7a` (`claude/epic-bardeen-8vcbfa`)
> **Scope reviewed:** every code-bearing change in the window — 77 first-parent
> merges (PRs #937–#1040), 604 files, +109,310 / −1,235.
>
> **Method.** The window is dominated by two large new programs plus a set of
> perf/robustness changes to shipping enforcement code. Review was prioritised by
> *live blast radius*, not by diff size:
>
> 1. **Enabled-by-default enforcement code that changed** — policy evaluation,
>    host canonicalization, the proxy request/response paths, the admin-UI auth
>    middleware, session-secret loading, alerting, redaction, persistence.
> 2. **New enabled-by-default surface** — the signed SaaS URL-category feed
>    (F3a/F3b: trust kernel, downloader, activation/floor/recovery, admin API)
>    and the admin category-override engine.
> 3. **New disabled-by-default surface** — the MCP Agent Security Gateway
>    (ADR-0024, PR-3…PR-11, ~55k LOC across 25 subpackages) and its CP→DP
>    signed-snapshot distribution; reviewed for *inertness* first, then for
>    trust-boundary correctness of its crypto/SSRF/authz kernels.
> 4. Dependency bumps, CI/workflow changes and docs-only merges were read for
>    intent and checked for trust-material changes, but not treated as runtime
>    attack surface.

---

## Executive Summary

**One MEDIUM regression was found and reproduced.** It is a *silent* narrowing of
URL-category policy matching introduced by the F3b-4 "source-aware category
resolution" change — a fail-open direction, live by default on every node, in an
enforcement path. Everything else in the window is neutral or security-positive.

The MEDIUM finding (**F-1**) is a contract violation rather than an intended
semantic change: the F3b-4 design explicitly states the pre-activation policy
result must be "byte-identical to today's full-store behavior", and the code does
not achieve that. `matchCategory` now resolves the built-in (SaaS) taxonomy
through an atomic `host → single category` view, but the store it replaced was
`category → host-set` — a host may legitimately be in several categories, and a
per-category suffix walk does not let a nested key shadow an ancestor. Both
properties are lost. Notably, the signed feed's **own producer gate**
(`internal/urlcatfeed/readiness.go`) rejects exactly the two dataset shapes that
trigger this (`multi_category`, `suffix_conflict`) — the same invariant was simply
never applied to the `catStore`-derived embedded baseline that every node runs
today. That gives a small, fail-closed fix (§F-1 *Suggested Fix*).

The window's headline new surfaces were each verified against their own claims:

- **The MCP Agent Security Gateway is genuinely inert.** `initMCPRuntime`
  constructs `mcpruntime.NewRuntime(mcpruntime.Config{})` — there is no config,
  CLI, env or admin path that enables a listener in this build, and the admin API
  says so structurally (`listener_activation: "not_implemented"`,
  `distribution_state: "local_only"`). Its crypto kernels were still reviewed and
  are sound: explicit per-algorithm key-type checks (JWS algorithm confusion
  blocked), canonical-hash-then-`ed25519.Verify` with signature-length validation
  and trust-store key lookup for CP→DP envelopes, and an upstream client whose
  `DialContext` **ignores the address argument entirely** and dials only pinned
  IPs, so a hostile redirect cannot escape the pinned destination.
- **The signed SaaS feed trust kernel is fail-closed with no downgrade path.**
  One scheme (keyless Sigstore), no unsigned fallback, verify-before-parse,
  offline verification against the bundle's integrated Rekor timestamp (never
  wall-clock), a feed-specific pinned identity distinct from the release
  catalog's, strict decode + canonical byte-equality, and full manifest↔artifact
  binding (size, digest, `feed_version`, `generated_at`, counts).
- **The feed downloader is the strongest SSRF posture in the codebase.** Origin
  *and* path pinned, `Proxy: nil` (an ambient `HTTPS_PROXY` cannot redirect the
  fetch around the guards), resolve-once dial-time private-IP rejection (closing
  the DNS-rebinding TOCTOU), manual per-hop redirect revalidation, and an
  independent traversal guard on the manifest-supplied artifact key. The
  admin-settable feed URL cannot be used to pivot: `resolveFeedURL` accepts only
  the official origin or a historical URL, and the **DP re-validates** the
  CP-pushed URL through the same boundary.
- **The one authentication-surface change (`/api/cluster/bootstrap/` moved onto
  `uiAuthMiddleware`'s public allowlist) is correct**, and the prefix-on-uncleaned-path
  bypass primitive it superficially resembles does not apply here (§F-2).

**Findings: 1 MEDIUM, 2 LOW, 3 INFO.** No CRITICAL or HIGH. No authentication or
authorization bypass, no default-allow, no missing signature validation, no secret
exposure, and no fail-open in the TLS, scanning, or trust-verification paths.

**Verification:** `go build ./...` clean at `3d13f7a`. Green at HEAD, `-count=1`:
`internal/{hostutil,urlcatfeed,catoverride,urlcat,alerts,reqlog,fileutil}`; and
under `-race`, the package-`main` governance/parity/policy suites
(`TestC1_*`, `TestC2_*`, `TestC4_*`, `TestD0_*`, `TestConfigSurfaces*`,
`TestSnapshot*`, `TestUIAuthMiddleware*`, `TestSecurity*`, `TestRedact*`,
`TestTraffic*`, `TestPolicy*`, `TestSchedule*`, `TestSaaS*`, `TestFeed*`).
F-1 was reproduced with a purpose-built differential harness (§F-1 *Reproduction*).

---

## Security Findings

### F-1 — MEDIUM — F3b-4 source-aware category resolution silently narrows `matchCategory` (fail-open policy-match loss)

| | |
|---|---|
| **Severity** | MEDIUM |
| **Likelihood** | LOW–MEDIUM (requires a specific admin/legacy data shape; no attacker action) |
| **Regression risk** | **HIGH** — silent, default-on, in an enforcement path, with no log/metric/alert |
| **CWE** | CWE-284 (Improper Access Control), CWE-697 (Incorrect Comparison) |
| **OWASP** | A01:2021 Broken Access Control |
| **Affected assets** | URL-category policy enforcement (allow/deny/inspect decisions keyed on a category) |
| **Status** | OPEN |

#### Files

- `policy.go:1549` — `matchCategory` source-aware branch (the enforcement path)
- `policy.go:1579` — `lookupHostCategory` source-aware branch (admin lookup/observability)
- `internal/urlcat/urlcat.go:407` — `Store.BuiltInHostCategories()` (the lossy bridge)
- `saas_feed_view.go:118` — `(*effectiveCategoryView).LookupHost` (longest-suffix-wins)
- `saas_feed_view.go:144` — `embeddedBaselineEntries()`
- `urlcategories_startup.go:66` — `startSignedFeedLifecycle(...)` (makes the view live by default)
- `saas_feed_lifecycle.go:64` — `rt.recover(ctx)` installs the baseline view at startup

#### What changed

Before F3b-4, `matchCategory(cat, host)` consulted `catStore.MatchesHost`, whose
model is **`category → set of host keys`**, and which walks *every* suffix of the
query host against *that one category's* key set.

After F3b-4, when the signed-feed effective view is installed, the built-in (SaaS)
taxonomy is served **exclusively** from that view, whose model is
**`host key → one category`**, resolved by walking suffixes and **stopping at the
first (longest) matching key**.

Two properties are lost:

1. **Multi-membership.** `BuiltInHostCategories()` flattens the store into a
   `map[string]string`. Its own doc comment concedes the loss — *"Later keys win
   on collision (deterministic; callers hold no ordering contract on duplicate
   host keys across categories)"*. A host in two built-in categories now matches
   only one of them.
2. **Ancestor visibility.** With `example.com → A` and `login.example.com → B`, a
   query for `a.login.example.com` stops at `login.example.com` and returns `B`
   only. `catStore.MatchesHost(A, "a.login.example.com")` returned **true**,
   because the walk was per-category and never shadowed.

Because `matchCategory` compares the view's single answer with
`strings.EqualFold(c, string(cat))`, either shape turns a previously-matching
category into a non-match. The `else if` structure correctly preserves the
fall-through to the UT1/community layer, so this is a *narrowing only* — never a
widening.

#### Why it is live by default

`loadURLCategories` calls `startSignedFeedLifecycle` unconditionally
(`urlcategories_startup.go:66`), and step 3+4 of that lifecycle
(`saas_feed_lifecycle.go:64`) installs the recovered/embedded view. So
`saasEffectiveView.Current() != nil` on every normally-started node — including
nodes that have the signed feed **disabled**, which is the default and the state
of every deployment today (no signed feed has been published yet).

#### Preconditions / exploitability

This is not remotely triggerable; it is a **silent degradation of a configured
control**. The triggering data shape can arise three ways:

1. **Operator edit (most likely).** `PUT /api/urlcat?name=<built-in category>`
   preserves the `BuiltIn` flag (`ui_policy.go:1023`) and requires only
   **`RoleOperator`**. An operator curating built-in category lists who adds a
   host that already exists in another built-in category — or who adds a
   *subdomain* key under a different category than its parent — creates the shape.
2. **Legacy raw-feed residue (upgrade path).** The retired raw SaaS syncer wrote
   feed hosts into `catStore` with `builtIn=true` (`saas_feed.go:58`). Any
   duplicate/nested shape that feed ever produced is persisted in
   `<dataDir>/cat.json` and is picked up verbatim by `BuiltInHostCategories()`
   after upgrade.
3. **A future signed feed** — *not* a risk: the producer's readiness gate
   (`internal/urlcatfeed/readiness.go`, kinds `multi_category` and
   `suffix_conflict`) refuses to publish either shape, and `EvaluateReadiness`
   is the F5 publish gate. The single-valued model is sound **for feed-sourced
   data**; the gap is exactly that the same invariant was never applied to the
   `catStore`-derived baseline.

The compiled seed (`internal/urlcat/default_categories.json`, 21 categories /
625 hosts) contains **zero** duplicates and **zero** cross-category nesting, so a
*fresh, unedited* install is byte-identical today. That is what makes this
dangerous rather than obvious: it will only ever surface on an appliance whose
category lists have been curated or upgraded.

#### Attack scenario

1. An operator maintains a `deny category=file-sharing` rule and a lower-priority
   `allow *` rule for a business unit.
2. The same operator (or a legacy feed merge) puts `drive.example-corp.com` into
   the built-in `collaboration` category, while `example-corp.com` is already in
   the built-in `file-sharing` category.
3. `matchCategory("file-sharing", "drive.example-corp.com")` now returns **false**
   (the longer `collaboration` key shadows the `file-sharing` ancestor).
4. The deny rule no longer matches; evaluation falls through to `allow *`.
5. Traffic that policy was configured to block is allowed, with **no** audit
   entry, log line, metric, or alert recording that a category membership
   disappeared. From the admin UI the rule and the category list both still look
   correct.

#### Reproduction

Reproduced against `3d13f7a` with a differential harness in package `main`
(temporary file, not committed — it asserts a regression and would fail CI):

```go
catStore = urlcat.New([]*urlcat.Entry{
    {Name: "collaboration", Hosts: []string{"drive.google.com"},  BuiltIn: true},
    {Name: "cloud-storage", Hosts: []string{"drive.google.com"},  BuiltIn: true},
    {Name: "corp-portal",   Hosts: []string{"example.com"},       BuiltIn: true},
    {Name: "webmail",       Hosts: []string{"login.example.com"}, BuiltIn: true},
})

saasEffectiveView.Swap(nil)                     // pre-F3b-4 path
preDup  := matchCategory("collaboration", "drive.google.com")
preNest := matchCategory("corp-portal",   "a.login.example.com")

saasEffectiveView.Swap(embeddedBaselineView())  // F3b-4 path (the default)
postDup  := matchCategory("collaboration", "drive.google.com")
postNest := matchCategory("corp-portal",   "a.login.example.com")
```

Observed:

```
pre-view : collaboration/drive.google.com=true   corp-portal/a.login.example.com=true
post-view: collaboration/drive.google.com=false  corp-portal/a.login.example.com=false
```

Both regressions confirmed, and both in the fail-open direction.

#### Suggested fix (safe implementation)

**Do not** blanket-restore ancestor OR-matching in the view. Longest-suffix-wins is
*load-bearing* for the override engine: `catoverride.ComposeView` expresses an
admin recategorization of a subtree by emitting a longer key alongside the feed's
ancestor key (`internal/catoverride/catoverride.go:233`, which suppresses only
keys *covered by* an assert key). OR-matching every ancestor would silently defeat
`Recategorized` overrides.

The minimal, fail-closed fix is to **apply the producer's own readiness invariant
to the baseline bridge**:

1. In `embeddedBaselineEntries()` (or a new
   `catStore.BuiltInHostCategoriesStrict()`), detect the two conflict shapes the
   producer already names — a host assigned to more than one built-in category
   (`multi_category`), and a built-in key whose proper suffix is a built-in key of
   a *different* category (`suffix_conflict`). Reuse the detector shapes in
   `internal/urlcatfeed/readiness.go` so producer and baseline share one
   definition.
2. On **any** conflict, refuse to install a derived view: leave
   `saasEffectiveView` at `nil` so `matchCategory`/`lookupHostCategory` take the
   unchanged `catStore.MatchesHost` path. That is byte-identical to pre-F3b-4
   behavior — the documented contract — and is fail-closed with respect to the
   enforcement decision.
3. Surface the refusal loudly: a degraded row on `/api/saas-feed/status`, a
   counter, and an alert naming the conflicting hosts/categories, with operator
   guidance to de-duplicate before the signed feed can take over. The condition is
   admin-fixable and must not be silent.
4. Once a signed generation activates, the producer gate guarantees the invariant
   for feed data, so the exclusive-serving path is sound and unchanged.

An alternative — making `effectiveCategoryView.entries` multi-valued at the same
key level (`map[string][]string`) with membership checked per level — closes the
duplicate half but **not** the ancestor half (which stays correct-by-design for
overrides), and requires touching `catoverride.ComposeView`, the snapshot parser,
`validateEffectiveComposition`, GC, and the status counters. It is the larger,
riskier change and is not recommended for a fix; option 1–3 is.

#### Required tests

- **Positive:** with a conflict-free built-in taxonomy, the view installs and every
  category match is byte-identical to `catStore.MatchesHost` (differential over the
  full compiled seed × an adversarial host corpus).
- **Negative:** with a duplicate host across two built-in categories, the view is
  **not** installed and both categories still match.
- **Negative:** with a cross-category nested key, the view is not installed and the
  ancestor category still matches.
- **Regression:** the exact `pre`/`post` matrix from the reproduction above, pinned
  as an equivalence assertion (`pre == post` for every cell).
- **Boundary:** conflict detection at the exact-key boundary (`example.com` vs
  `.example.com` vs `xexample.com`), trailing dot, uppercase, IDN/punycode
  (`hostutil.NormalizeHost` is applied on both sides).
- **Malformed input:** empty host, empty category, host with an empty label
  (`a..b.com`), 255-byte host.
- **Concurrency:** `-race` over concurrent `matchCategory` readers against a
  `saasEffectiveView.Swap` (the cutover must stay all-or-nothing).
- **Authorization:** the operator-role `PUT /api/urlcat` path that can create the
  conflict must produce the loud degraded state, not a silent match loss.
- **Post-activation:** a signed generation that passes `EvaluateReadiness`
  installs normally and serves exclusively (the intended F3b-4 behavior is
  preserved).

#### Residual risk

Until fixed: any appliance whose built-in category lists have been operator-edited
or carry legacy raw-feed residue may be silently under-enforcing one or more
category-keyed rules. There is currently **no** signal an operator could use to
detect it — this is the part that makes the finding worth acting on even at
LOW–MEDIUM likelihood. Mitigation until the fix lands: audit
`<dataDir>/cat.json` for duplicate/nested hosts across `built_in: true` entries.

---

### F-2 — LOW — `/api/cluster/bootstrap/` moved onto the unauthenticated allowlist

| | |
|---|---|
| **Severity** | LOW (residual; the change itself is correct) |
| **Likelihood** | LOW |
| **Regression risk** | LOW — reviewed and corrected in-window |
| **CWE** | CWE-598 (Use of GET with sensitive query/path data), CWE-1220 (Insufficient granularity of access control) |
| **OWASP** | A01:2021 |
| **Files** | `ui_middleware.go:232` (`isPublicUIAuthPath`), `bootstrap.go`, `enrollment.go:338` (`TokenExists`), `ui_routes_meta.go:674` |

**Change.** `strings.HasPrefix(path, "/api/cluster/bootstrap/")` was added to
`uiAuthMiddleware`'s public allowlist (`023cbe7`), because a configured Control
Plane returned a bare 401 to the generated one-command DP onboarding `curl` — run
from a brand-new host with no session cookie — before the handler's own token check
could run.

**Verdict: correct, and the obvious bypass primitives do not apply.**

- **Token strength.** 32 bytes from `crypto/rand`, base64url-encoded; the store
  holds only `SHA-256(plaintext)` and looks it up as a **map key**, so there is no
  variable-time comparison of the secret and brute force is infeasible.
  Single-use + TTL are enforced (`TokenExists` checks `Used` and `ExpiresAt`).
- **Path-traversal bypass: not reachable.** The allowlist is a prefix test on the
  *uncleaned* `r.URL.Path`, which is normally a bypass primitive
  (`/api/cluster/bootstrap/../../api/auth/users`). It is safe here only because
  `net/http.ServeMux` calls `cleanPath` **before** dispatch and returns a **301
  redirect** rather than serving the cleaned target; the redirected request
  re-enters the full middleware chain with the clean path and is authenticated
  normally. This is a load-bearing property of the stdlib mux — worth recording so
  a future custom router or a `StripPrefix`-style rewrite in front of the mux does
  not silently turn this into a real bypass.
- **Governance parity.** The `uiRoutes` row was initially left at
  `Public: false` / `RoleViewer` and only "worked" because C2's default role
  fallback happened to equal the declared `MinRole`. This was caught in-window and
  corrected to `Public: true` / `RolePublic` (`b1b7e07`), keeping invariant #5
  (public routes are owned by `uiAuthMiddleware` only) intact. `api/route-classification.yaml`
  was updated in the same commit.
- Outer `uiIPGuardMiddleware` and `securityMiddleware` still apply; both handlers
  are GET-only.

**Residual risk (recorded, not a blocker):**

1. **The enrollment token travels in the URL path.** It therefore lands in
   intermediary access logs, `Referer` headers, shell history, and any TLS-terminating
   reverse proxy in front of the CP. This is pre-existing design, but the audience
   that can now reach the endpoint without credentials is larger. A future revision
   should accept the token in a header (keeping the path form for compatibility
   during a deprecation window).
2. **`AllowCIDR` is not enforced by the bootstrap handlers.** `TokenExists` checks
   only existence, use, and expiry — not the token's source-CIDR restriction. A
   token scoped to a CIDR still yields the bootstrap script, the cluster CA
   fingerprint, and the CP gRPC address to a holder from **any** source IP. The
   enrollment RPC *does* enforce the CIDR, so this is disclosure rather than
   enrollment — but the restriction should be applied here too as defense in depth.

**Required tests (for the residual items):** a token with `AllowCIDR` set must
404/403 the bootstrap script from an out-of-CIDR source while still succeeding
from within it; an expired token, a used token, and a token with a `/` in the
segment must each be rejected; a `%2e%2e`-encoded traversal attempt must produce a
redirect that is then authenticated, never a served admin response.

---

### F-3 — LOW — `readErrTracker` compares against `io.EOF` with `!=` instead of `errors.Is`

| | |
|---|---|
| **Severity** | LOW (availability / correctness; not a security bypass) |
| **CWE** | CWE-754 (Improper Check for Unusual or Exceptional Conditions) |
| **File** | `proxy_http.go:68` |

```go
func (t *readErrTracker) Read(p []byte) (int, error) {
    n, err := t.r.Read(p)
    if err != nil && err != io.EOF {   // ← identity comparison
        t.err = err
    }
    return n, err
}
```

`t.err` is fed to `upstreamAtt.Record(...)`, which trips the upstream pool's
circuit breaker (CHAOS-11). A **wrapped** EOF (`fmt.Errorf("...: %w", io.EOF)`)
from any current or future response-body reader would be charged as a parent-proxy
failure on a perfectly normal end-of-body, ejecting healthy parents under load and
pushing egress to the DIRECT fail-open path. `net/http` returns a bare `io.EOF`
today, so this is latent rather than live.

**Suggested fix:** `if err != nil && !errors.Is(err, io.EOF) { t.err = err }`.

**Required tests:** a body reader returning a wrapped `io.EOF` must **not** charge
the breaker; a reader returning `io.ErrUnexpectedEOF` **must**; a client-side write
failure mid-copy must not charge the breaker (the existing separation-of-concerns
contract); `context.Canceled` must remain uncharged.

---

### F-4 — INFO — `fireAlert` converted from a function to a mutable package-level variable

| | |
|---|---|
| **Severity** | INFO |
| **CWE** | CWE-1051 (Initialization with Hard-Coded / Reassignable Resource) |
| **File** | `alerts.go:45` |

`fireAlert` became `var fireAlert = func(...)` so tests can observe the dispatch
decision rather than webhook delivery (a legitimate de-flaking motive — delivery
passes through a package-global semaphore shared by the whole test binary).

Two consequences worth recording:

1. `init() { alerts.SetSink(fireAlert) }` captures the **original** closure value.
   A test that reassigns `fireAlert` therefore does **not** redirect alerts fired
   through `alerts.Fire` from internal packages — a test-fidelity gap that could
   let a future producer regression pass unnoticed.
2. The variable is written without synchronization. Concurrent reassignment while
   request goroutines call it is a data race; it is test-only today, but the
   product's alerting/audit sink is now reassignable by any code in package `main`.

**Suggested fix:** make it an `atomic.Pointer[func(string, AlertPayload)]` seam (or
a dedicated `alertSinkForTest` hook) and have `alerts.SetSink` route through the
same indirection so both paths observe a reassignment.

---

### F-5 — INFO — admin rollback response echoes raw persistence errors containing absolute paths

**File:** `configversion.go` — `"persist_errors": persistErr.Error()`.

Errors originate in `fileutil.AtomicWrite`, whose messages embed the absolute
target path (`atomic write /data/…: …`). The endpoint is admin-only, so this is an
accepted posture — but it is worth recording alongside CHAOS-45, which
*deliberately* redacts paths to a basename before they reach the viewer-readable
`/api/diagnostics` storage row (`storage_health.go:215`, `redactWritePath`). The
two paths have intentionally different redaction levels; that asymmetry should not
be "fixed" in either direction by accident.

---

### F-6 — INFO (pre-existing, carry-forward) — `/metrics` on the proxy listener is unauthenticated by default

**File:** `metrics.go:432`.

`handleMetrics` gates on a Bearer token only when `metricsToken != ""`, and there
is no default value (`metrics_token` is opt-in via `AdminSettings` / CLI). A client
that can reach the proxy port can read gateway telemetry.

Restated here because the in-window fix `1e87ddd` touched exactly this dispatch:
`routeProxyListenerBuiltin` previously matched `/health`, `/ready` and `/metrics`
**regardless of `r.URL.Host`**, so a client proxying
`GET http://any-origin/metrics` through Culvert received *Culvert's own* metrics
instead of the origin's response. The fix adds the `r.URL.Host == ""` guard that
`/proxy.pac` and `/pac/*` already had, which is correct in both directions — it
stops the forward proxy shadowing an upstream site's own paths **and** removes an
unintended second route to the local metrics endpoint. The direct-to-listener
exposure is unchanged and remains pre-existing.

**Recommendation (unchanged from prior reviews):** ship a generated `metrics_token`
by default, or bind `/metrics` to the admin listener only.

---

## Regression Analysis — verified-safe changes

Each item below was a candidate regression that was checked and cleared.

| Area | Change | Verdict |
|---|---|---|
| **Host canonicalization** | `hostutil` already-canonical fast path (`isCanonicalASCIIHost`) | **Equivalent.** The fast path is entered *after* `strings.ToLower(strings.TrimSuffix(host, "."))`, so the case-sensitive `xn--` test holds by construction and the verbatim return cannot leak uppercase. The ACE test is label-anchored (index 0 and after each `.`) and correctly ignores `xn--` inside a label. IP literals (bare and bracketed) take the same path and return the same bytes. Differential + fuzz tests against the real `idna.ToASCII` are present and green. |
| **Policy schedule** | `matchScheduleAt` / `scheduleTimeMatch` / `parseClockMinutes` | **Equivalent.** Normal range: old `!(cur<start ‖ cur≥end)` ≡ new `cur≥start ∧ cur<end`. Overnight: old `!(cur<start ∧ cur≥end)` ≡ new `cur≥start ∨ cur<end`. `parseClockMinutes` is strict 5-char `HH:MM`, on which minute order is isomorphic to lexicographic order; `24:00`→1440 preserves its position; anything else falls back to the byte-identical legacy comparison. Reading the clock **once per scan** is a consistency improvement (a decision can no longer straddle a minute boundary mid-scan). |
| **Feed trust kernel** | `internal/urlcatfeed/verify.go` | **Sound.** Single keyless scheme, no fallback; verify-before-parse (no manifest field read before its exact bytes verify); offline via `WithTransparencyLog(1)` + `WithIntegratedTimestamps(1)` (never wall-clock, air-gap safe); exact issuer + anchored SAN (`publish-feeds.yml` @ strict `feeds-vX.Y.Z`, no wildcard tail); strict decode + canonical byte-equality + canonical RFC3339 + 30-day validity ceiling; artifact bound to the manifest by size, digest, `feed_version`, `generated_at`, and counts. |
| **Feed downloader** | `saas_feed_download.go` | **Sound.** Origin+path pinned; `Proxy: nil`; resolve-once dial-time `isPrivateIP` guard (DNS-rebinding TOCTOU closed); `CheckRedirect` returns `ErrUseLastResponse` so every hop is revalidated manually against the full contract; no userinfo/port/query/fragment; independent `safeArtifactKey` traversal guard over the signature-verified manifest key. |
| **Feed config authority** | `resolveFeedURL` / `validateOfficialManifestURL` | **Fail-closed.** No generic mirror is accepted, so neither an admin nor a hostile CP can pivot the fetch. The DP re-validates the CP-pushed URL/protocol/refresh via the *same* boundary in `validateConfigSnapshot` — a bad value rejects the **whole** snapshot, never partially applies. |
| **CP→DP snapshot** | new `SaaSFeed*`, `CategoryOverrides`, `MCP*Snapshot` fields | **Sound.** `*bool` presence semantics stop a rolled-back CP from re-enabling a durably-disabled DP; `CategoryOverrides` is nil-skip / non-nil-replace so an explicit clear propagates; host-aggregate cap (`maxSnapCategoryOverrides`) plus `catoverride.Normalize` validation on the DP; MCP envelopes are `kindMeta`/`AppliesOnDP` and carry only a public content hash, an ed25519 signature, and a credential-free reviewed payload. Every new field has a `configSurfaces` row; the parity wall (`TestConfigSurfaces*`, `TestSnapshot*`) is green. |
| **MCP CP→DP signing** | `internal/mcp/cpdp/sign.go` | **Sound.** Content hash recomputed over a canonical form that includes `alg` and `key_id` (a signature cannot be transplanted onto another alg/key); trust-store lookup by key id; signature length validated before `ed25519.Verify` (which panics on a bad key size); domain-separated signing input. |
| **MCP JWS** | `internal/mcp/jose/jose.go` | **Sound.** Algorithm allowlist plus an explicit key-type assertion per algorithm — classic `alg` confusion (RS256↔HS256, EdDSA↔ES256) is blocked with a named error. |
| **MCP upstream client** | `internal/mcp/upstreamclient/transport.go` | **Sound.** `pinnedDial` ignores the dialer's `addr` argument entirely and dials only `pin.AllowedIPs`, re-running `destination.VerifyPeer` per candidate and rejecting a stale pin — so a redirect cannot reach a new destination even though redirects are allowed (bounded). Pinned-identity TLS replaces chain verification with an SPKI pin inside `VerifyConnection` (a correct, narrow use of `InsecureSkipVerify`). Responses are read with a hard bound. |
| **MCP inertness** | `mcp_runtime.go`, `mcp_rollout.go`, `ui_mcp.go` | **Confirmed inert.** `NewRuntime(Config{})`; no config/CLI/env enablement path exists in this build; both rollout states start `Disabled` with empty scopes; `apiMCPConfig` PUT stores node-local config only and returns `listener_activation: "not_implemented"` / `distribution_state: "local_only"`. Admin routes are all metadata-declared and C1/C1.5/C2 parity is green. |
| **Alert gating** | `HasSubscriber` gate on the block, DNS-failure and storage-write producers | **Cannot silence a real alert.** `HasSubscriber`'s predicate (`ev == event ‖ ev == "*"`, enabled hooks only) is byte-identical to `Dispatch`'s. The only divergence is a benign add/remove race of at most one alert at the instant a webhook is created. |
| **Alert persistence** | fsync moved off `mu` via `beginSaveLocked` | **Sound.** Readers (`HasSubscriber`, now on the request path) no longer block on an fsync; out-of-order writers are resolved by a monotonic sequence number so disk converges to the newest snapshot rather than the last finisher. |
| **Request-log persistence** | `internal/reqlog/persist.go` | **Sound and deliberately not a load shedder.** A full queue **blocks** the caller (the pre-change behavior, never worse) and increments `Backpressure()`; no entry is ever dropped, so the durable audit record stays complete. One drain goroutine keeps the file FIFO; `Sync` is timeout-bounded so a wedged sink cannot deadlock shutdown. |
| **Durable-write observability** | `internal/fileutil` observers + `storage_health.go` | **Additive and safe.** Observers are notified *in addition to*, never instead of, the returned error; paths are reduced to a basename (`redactWritePath`) before reaching the viewer-readable diagnostics row; recovery is reported only on **evidence** of a later successful write, never on elapsed silence. |
| **Destination pseudonymization** | pooled keyed HMAC in `traffic_redaction.go` | **Sound.** Each pooled hasher records the key **generation** it was keyed with and is rebuilt on mismatch, so a rotation can never emit a token under a superseded key; clearing the key burns a generation; the fail-closed sentinel is returned when no key is present (never plaintext); scratch is capped so one outsized input cannot pin memory. Token bytes are pinned identical to the reference HMAC by test. |
| **Session secret** | check-raw-then-trim ordering | **Improvement.** A whitespace-only `CULVERT_SESSION_SECRET` now still panics / warns instead of being indistinguishable from unset and silently installing a random key. |
| **Proxy built-in paths** | `r.URL.Host == ""` guard | **Correct** (see F-6). |
| **Config import/export** | SaaS feed + overrides on the export/import/rollback surfaces | **Fail-closed.** A managed data-plane node rejects a feed-carrying import with 409 **before any mutation**; the whole payload is pre-validated through the F3a-1 boundary; import never wipes (absent/empty skips in both modes); overrides are applied leaf-first before policy rules. |
| **Connection limiting** | `Rejected()` counter | Additive counter only; no admission-decision change. |
| **Shutdown** | `shutdownOrderMCPRuntimeStop = 65` | Ordered before the admin-UI and proxy drains; a no-op while disabled. |
| **Readiness** | `appendSaaSFeedHealthCheck` | Report-only by design — the feed never gates readiness, because a valid embedded baseline always exists. Strict probes opt in via `/ready?strict=1`. |
| **Dependencies** | `sigstore-go` 1.2.2→1.3.0, `etcd/server/v3` 3.6.13→3.7.1, `kin-openapi`, `badger`, `klauspost/compress`, `oklog/ulid`, CodeQL/cache/login actions | Version bumps only; no trust material (baked Sigstore root, pinned identities) changed in this window. |

---

## Risk Rating

| ID | Finding | Severity | Likelihood | Regression risk | Status |
|---|---|---|---|---|---|
| F-1 | Source-aware category resolution narrows `matchCategory` | **MEDIUM** | LOW–MED | **HIGH** | OPEN |
| F-2 | Bootstrap dispatch on the unauthenticated allowlist (residuals) | LOW | LOW | LOW | OPEN (residuals) |
| F-3 | `readErrTracker` identity-compares `io.EOF` | LOW | LOW | LOW | OPEN |
| F-4 | `fireAlert` is a mutable package var | INFO | — | LOW | OPEN |
| F-5 | Rollback response echoes absolute paths (admin-only) | INFO | — | — | ACCEPTED |
| F-6 | `/metrics` unauthenticated by default (pre-existing) | INFO | — | — | CARRY-FORWARD |

**Release posture:** nothing in this window blocks release. F-1 should be
scheduled promptly because it is silent, default-on, and fail-open; F-3 is a
one-line change that should ride the same PR.

---

## Residual Risk

1. **F-1 is undetectable in the field today.** There is no counter, log line, or
   status row that would tell an operator a category membership was dropped by the
   baseline flattening. The recommended fix deliberately makes the condition loud
   rather than merely correct.
2. **The MCP program is large and disabled.** Its inertness was verified
   structurally (no enablement surface exists) and its crypto/SSRF kernels were
   reviewed, but ~55k LOC of policy, execution, credential-broker, inspection/DLP
   and event-spool logic has not been exhaustively line-reviewed here. **The PR
   that first ships an enablement surface must be treated as a new
   trust-boundary review**, not an incremental one — in particular the credential
   broker (secret materialization + `secret.NewSealed` ownership transfer), the
   approval/four-eyes state machine, and the Gateway listener's authn path.
3. **The signed feed has no published catalog yet.** The trust kernel, downloader,
   floor/rollback and activation machinery are all live code paths that have never
   run against a real signed generation in production. The first publication is a
   trust event and warrants its own verification pass (identity, floor
   monotonicity across the fleet, and the offline recovery matrix).
4. **F-2's traversal safety depends on `net/http.ServeMux` semantics.** Any future
   custom router, `http.StripPrefix`, or path-rewriting middleware placed in front
   of the admin mux could turn the prefix-on-uncleaned-path allowlist into a real
   authentication bypass. This dependency is now recorded but is not enforced by a
   test.
5. **Category-conflict data may already exist on upgraded appliances.** Even after
   F-1 is fixed, operators should be given a one-time inventory of duplicate /
   nested built-in category hosts so they can de-conflict before the signed feed
   takes ownership of the taxonomy.

---

## Appendix — review coverage

**Reviewed as primary attack surface:** `policy.go`, `proxy_http.go`,
`proxy_tunnel.go`, `pac.go`, `ui_middleware.go`, `ui_routes_meta.go`,
`ui_policy.go`, `ui_config.go`, `ui_mcp.go`, `ui_mcp_rollout.go`, `session.go`,
`store.go`, `alerts.go`, `bootstrap.go`, `enrollment.go`, `configversion.go`,
`config_surfaces.go`, `controlplane_snapshot.go`, `diagnostics.go`,
`storage_health.go`, `traffic_redaction.go`, `healthcheck.go`,
`main.go`/`main_shutdown.go`, `metrics.go`, the `saas_feed_*.go` family,
`mcp_runtime.go` / `mcp_rollout.go` / `mcp_distribution*.go` /
`mcp_scope_readmodel.go` / `mcp_ack_readmodel.go`, `urlcategories_startup*.go`;
`internal/{hostutil,urlcat,urlcatfeed,catoverride,alerts,reqlog,fileutil,redaction,secret,connlimit,upstream}`;
`internal/mcp/{cpdp,jose,upstreamclient,rollout,credentials,inspection}`.

**Reviewed for intent only (not treated as runtime attack surface):** docs-only
merges (`docs/design/mcp/**`, `roadmap/**`, governance terminology reviews), CI
workflow changes, and dependency bumps.
