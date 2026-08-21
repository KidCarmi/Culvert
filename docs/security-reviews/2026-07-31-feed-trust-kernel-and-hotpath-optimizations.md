# Security Regression Review — Feed Trust Kernel & Policy Hot-Path Optimizations

- **Date:** 2026-07-31
- **Reviewer role:** Security Regression Engineer (standing charter, `docs/engineering/ENGINEERING-CONSTITUTION.md`)
- **Baseline (last reviewed clean point):** `addfbd7` (`origin/main`)
- **Tip under review:** `6810fce` (`claude/epic-bardeen-ue8lt2`, 65 commits ahead)
- **Scope:** 66 files changed (+9,029 / −357). Of those, **10 non-test Go files
  (+1,512 / −37)** carry all executable change; the remainder is tests
  (13 files, +2,206 / −4), design documents, CI, and dependency bumps.

## Verdict

**No security regressions found.** Every security-sensitive surface in this window
is either provably byte-faithful to the baseline or strictly tighter. Two changes
that touch live request-path security code (`hostutil.NormalizeHostStrict`,
`policy.matchSchedule`) are pure performance optimizations whose behavioral
equivalence I re-proved independently rather than accepting from the accompanying
tests. One change (`pac.go`) is a genuine hardening fix. The new trust kernel
(`internal/urlcatfeed`) is fail-closed by construction and has **no production
consumer** — it is dormant code.

One **Medium** finding is recorded (SR-1). It is *not* a code defect and requires
no code change: it is an operator-visibility gap around an owner-approved
classification change that can silently invert a `deny` decision to `allow` on
upgrade for specific — and common — policy shapes.

**No security behavior was changed by this review. None was required.**

## Method

The two hot-path optimizations both claim to be behavior-preserving. A
"behavior-preserving" rewrite of a security gate is exactly where a guard silently
vanishes, so neither claim was accepted on the strength of its comment or its
accompanying test. For each, I wrote a **throwaway independent differential
harness** against an oracle reconstructed from the baseline implementation, ran it
over a far wider input space than the shipped tests cover, then deleted the
harness (the shipped tests already pin the property — see "Existing coverage
assessed" below).

Everything else was reviewed by direct reading of both sides of the diff, with
`git show addfbd7:<file>` for pre-images. `go build ./...` is clean and
`go test ./...` is green at the tip.

## Surfaces reviewed and cleared

### `internal/hostutil` — strict host normalization fast path (RISK-013 gate)

`NormalizeHostStrict` gained an `isCanonicalASCIIHost` fast path that returns the
input verbatim when it is pure ASCII with no `xn--` label, skipping
`net.ParseIP` ×2 and `idna.ToASCII`. This function is the fail-closed
canonicalization gate in front of blocklist, threat-feed, policy-FQDN, category,
SSL-bypass, autoexclude, and auth-policy matching — a fast path that widens
acceptance, or that returns a differently-cased or differently-shaped string,
would be a direct policy-evasion primitive.

Two things were checked specifically:

1. **Lowercasing is not skipped.** The fast path returns `host`, not
   `strings.ToLower(ascii)`. This is safe *only* because line 46 lowercases and
   trailing-dot-trims before the fast path runs. Confirmed. Had the fast path
   been placed above that line, `EXAMPLE.COM` would have flowed un-lowercased
   into every downstream exact-match store — a trivial policy bypass. It is not.
2. **The identity claim on `idna.ToASCII` holds.** `idna.ToASCII` uses the
   zero-option `Punycode` profile, under which `mapping`, `validateLabel`,
   `fromPuny`, and `bidirule` are all nil and `verifyDNSLength` is false. The only
   transforming or erroring branches are ACE-decode (gated on the `xn--` prefix)
   and punycode-encode (gated on a non-ASCII label). Excluding both leaves the
   input returned verbatim with a nil error — so no over-long label, empty label,
   underscore, control character, or other malformed shape can be accepted by the
   fast path that the baseline rejected.

**Independent evidence:** a differential harness comparing the shipped
`NormalizeHostStrict` against a reconstruction of the pre-fast-path body over
**200,936 inputs** — every single ASCII byte standalone and in label-adjacent
positions, `xn--` near-misses (`xn`, `xn-`, `xn--`, `xnn--`), empty/doubled/leading/
trailing dots, 300-byte labels, 200-label names, IPv4/IPv6 bare and bracketed
literals, IDN U-labels and A-labels, NUL and DEL bytes, plus 200,000 randomized
strings over a hostile alphabet. **Zero divergence**, with 183,416 inputs taking
the fast path. In particular no input was accepted by the new code that the
baseline rejected (the fail-open direction).

### `policy.go` — schedule matching refactor

`matchSchedule` was split into `matchScheduleAt` + `scheduleDayMatch` +
`scheduleTimeMatch`, the per-rule `fmt.Sprintf` was replaced with integer
minutes-of-day comparison, and `Evaluate` now reads the clock **once per scan**
(lazily, on the first scheduled rule) instead of once per scheduled rule.

- The boolean rewrite is faithful. Baseline normal-range rejected on
  `cur < start || cur >= end`, i.e. matched on `cur >= start && cur < end`;
  overnight rejected on `cur < start && cur >= end`, i.e. matched on
  `cur >= start || cur < end`. Both are reproduced exactly.
- `parseClockMinutes` is strict (`len == 5`, `s[2] == ':'`, four digits) and
  uses unsigned byte arithmetic, so a byte below `'0'` underflows to `> 9` and is
  rejected rather than wrapping. Anything it rejects falls back to
  `scheduleTimeMatchLegacy`, which *is* the baseline lexicographic comparison —
  including its historical quirk that unpadded `"9:00"` sorts above `"17:00"` and
  wraps the window. Legacy-quirk preservation is the correct call here: silently
  "fixing" a malformed schedule would change live allow/deny decisions.
- `Evaluate` now calls `matchScheduleAt` only when `rule.Schedule != nil`;
  baseline `matchSchedule(nil)` returned `true`, so skipping is equivalent.
- The single-clock-read change is a **tightening**: previously a single rule scan
  could straddle a minute boundary and evaluate different rules against different
  minutes. One instant per decision is strictly more consistent.

**Independent evidence:** exhaustive differential against the baseline
lexicographic implementation over **41,616,000 decisions** — 28,900 bound pairs
(hours `00`–`25`, minutes `00/01/30/59/60/99`, plus `24:00`, `9:00`, `0:0`,
`aa:bb`, `1a:00`, `/0:00`, `99:99`, `12:5`, `12:345`, `:`, `12-00`) × all 1,440
minutes of the day. **Zero divergence.**

### `pac.go` — proxy-listener built-in endpoint routing

`/health`, `/ready`, and `/metrics` on the **proxy** listener now require
`r.URL.Host == ""`, matching the guard `/proxy.pac` and `/pac/*` already had.
This is a hardening fix: previously a client proxying
`GET http://origin/metrics` had its request **hijacked** and answered with
Culvert's own metrics instead of being forwarded. That shadowed an upstream
site's own paths and leaked local status to a request that was never addressed to
Culvert. Origin-form health checks (`GET /health` + `Host:` header) set
`r.URL.Host == ""` and are unaffected.

I checked the obvious bypass: a request-target of `//evil.com/metrics`. Go's `net/url` request-target parsing (e.g. `url.ParseRequestURI`) treats this as a path, not an authority, so
`r.URL.Path` becomes `"//evil.com/metrics"` — it matches neither the old nor the new
switch arm and is forwarded. No bypass.

### `internal/urlcatfeed` — Sigstore keyless feed trust kernel (new, dormant)

New package: producer (`generate.go`, `normalize.go`, `readiness.go`) and
verifier (`verify.go`, `jsonstrict.go`, `identity.go`, `schema.go`). Reviewed in
full. **No non-test consumer exists** — the only importer in the tree is
`feeds_identity_test.go`. The kernel is not wired into any runtime path.

Cleared as fail-closed by construction:

- **One scheme, no fallback.** Missing or invalid signature is a rejection, never
  a downgrade to unsigned. There is no unsigned mode and `Protocol` is asserted
  on both sides of the wire.
- **Pinned identity is correct.** `verify.NewShortCertificateIdentity(issuer,
  issuerRegex, sanValue, sanRegex)` is called as `(id.Issuer, "", "",
  id.SANRegex)` — verified against the vendored `sigstore-go@v1.2.2` signature,
  since transposing `sanValue`/`sanRegex` would still compile and would silently
  disable identity pinning. The SAN regex is explicitly `^…$`-anchored and pins
  exact repo + exact workflow file + a strict SemVer `feeds-v*` tag with no
  wildcard tail, so it does not rely on the matcher anchoring for it. The feed
  identity is distinct from the release-catalog identity and is SSOT-pinned
  byte-equal to `feeds_identity.env` by test.
- **Offline verification.** `WithTransparencyLog(1)` + `WithIntegratedTimestamps(1)`;
  no `time.Now()` anywhere in non-test code. Nothing reaches the network at
  verify time.
- **Verify-before-parse is real.** `VerifyEnvelope` touches only the two untrusted
  wrapper fields, verifies over the exact decoded payload bytes, and only then
  parses. `verifyArtifactWithEntity` orders bind (size + SHA-256) → verify →
  parse → cross-check. No manifest or artifact field is exposed before the
  signature over its exact bytes passes.
- **Strict + canonical JSON.** `strictUnmarshal` rejects unknown fields,
  duplicate keys at any depth, and trailing data; `requireCanonical` additionally
  requires signed documents to be byte-identical to their canonical
  serialization, closing field-reordering, whitespace, HTML-escaping, and
  alternate-scalar-encoding malleability. Recursion in `scanValue` is bounded by
  `encoding/json`'s own `maxNestingDepth` (10,000) and inputs are size-capped, so
  it is not a stack-exhaustion vector.
- **Path handling.** `safeRelKey` allows a single `[A-Za-z0-9._-]` segment, no
  separators, no `..`; `artifact_sig_path` must equal `artifact_path + ".sigstore"`;
  `artifact_path` must equal a producer-derived `saas-%08d-<UTCdate>.json`. No
  traversal surface.
- **Timestamps.** `parseCanonicalRFC3339` rejects any same-instant string with a
  numeric offset or fractional seconds, so a signed payload cannot smuggle a
  non-canonical timestamp.
- **Integrity rules re-run on the client side.** The verifier independently
  re-checks sorting, canonical hosts, single-category assignment, and
  ancestor/descendant suffix collisions, and rejects the whole candidate rather
  than picking a winner. Producer-side `NormalizeHost` uses the stricter
  `idna.Lookup` profile (STD3, rejects wildcards, IP literals, bare public
  suffixes) — tighter than the engine's, which is the safe direction.

### CI and dependencies

- `pr-fast-gate.yml` **adds** a gate (`mcp-predicates`); nothing was removed from
  `needs`. The classifier deliberately uses `--no-renames` and a separate `case`
  so a moved document still triggers the job — the "a gate that does not run is a
  green tick" vacuity class is explicitly closed, and the runner uses an explicit
  allowlist that fails (not skips) on a missing predicate.
- Action bumps: `docker/login-action` v4.4.0 → v4.5.1 (SHA-pinned);
  `actions/cache` v4 → v6 (tag-pinned, as it already was — no change in pinning
  posture).
- `go.mod`: all forward bumps (etcd 3.6.13 → 3.7.1, badger 4.9.4 → 4.9.5,
  gorilla/websocket 1.5.1 → 1.5.3, kin-openapi, klauspost/compress, ulid, otel,
  go-systemd, bbolt), Go 1.25.12 → 1.26. `golang.org/x/text` promoted
  indirect → direct (now used by `urlcatfeed` for NFC). **No downgrades**, no
  swapped module paths.

## Security Findings

### SR-1 — Category reassignment can invert `deny` → `allow` on upgrade (Medium)

`internal/urlcat/default_categories.json` was reconciled to a one-host-one-category
model. Measured delta: **32 hosts lost a category membership**, **6 hosts were
dropped entirely**, 2 were replaced with `www.` forms. The change is
owner-approved and documented in detail in `roadmap/FEEDS-SOURCE-RECONCILIATION.md`,
whose §6 correctly records the coverage loss.

The gap is not the decision — it is that §6 frames the consequence as *"narrower,
deterministic classification"* and §3A states *"Security impact: none."* That is
true of the trust model but understates the runtime effect. `matchCategory` does
per-category exact + suffix matching and `Evaluate` is first-match-wins, so for an
existing ruleset the change can flip a decision from **deny to allow** — the one
direction that matters.

- **Attack scenario.** A network with the common SWG posture "deny specific
  categories, allow the rest" — e.g. rule 1 `deny Messaging`, rule 2
  `allow Video Conferencing`. Before upgrade, `teams.microsoft.com` matched rule 1
  and was denied. After upgrade it is only *Video Conferencing*, so rule 1 no
  longer matches, rule 2 does, and the same traffic is now allowed. The control
  disappears silently at upgrade with no admin action and no log of the change.
  The same shape applies to `cloudflare.com` (Security Tools → Cloud
  Infrastructure), `grafana.com` (Dev Tools → Analytics), the CRM↔Marketing
  moves, and the remaining reassignments.
- **Sharpest instance.** `s3.amazonaws.com` was **removed entirely** from Cloud
  Infrastructure. `aws.amazon.com` does not suffix-match it (different registrable
  domain), so S3 is now uncategorized by the shipped dataset. For a secure web
  gateway, S3 is a canonical bulk-exfiltration destination; a deployment that
  relied on a Cloud Infrastructure rule to gate it loses that gate. The *removal
  itself is correct* — `s3.amazonaws.com` is a PSL private suffix and a bare-suffix
  entry over-matches every bucket — but the resulting hole should be called out,
  not just the overblock it fixed.
- **Also narrowed.** `amazon.com` → `www.amazon.com`: the apex and every other
  `*.amazon.com` retail host leave E-Commerce. (This one is a net win — it also
  stops AWS being mis-classified E-Commerce — but it is still a coverage change.)
- **Preconditions.** (1) Upgrade to a build carrying the new embedded dataset;
  (2) a ruleset with a deny on the losing category ordered above an allow that
  covers the host's new category, or above a broad allow; (3) no admin-managed
  `catStore` override for that host.
- **Exploitability / likelihood.** No attacker action is required — the control
  changes on its own at upgrade. Not remotely triggerable. Likelihood **Medium**:
  the "deny some categories over a broad allow" posture is common, and 32 hosts
  is a wide enough net to hit it.
- **Impact.** Medium. Loss of a specific, admin-intended egress control; for the
  S3 case the lost control is DLP-adjacent.
- **Affected assets.** Egress policy enforcement; category-driven DLP controls.
- **Recommended fix — no code change.** (a) Release-note the 32 reassignments and
  6 removals in operator-facing upgrade notes, stated as *"these hosts may change
  allow/deny outcome under existing rules"*, not as "coverage loss"; (b) call out
  `s3.amazonaws.com` explicitly and recommend an FQDN rule (`*.s3.amazonaws.com`)
  for deployments that gated S3 via Cloud Infrastructure; (c) amend
  `FEEDS-SOURCE-RECONCILIATION.md` §6 to state the deny→allow direction.
- **Required tests.** A regression test pinning a curated set of security-relevant
  hosts to *some* category (not a specific one), so a future dataset edit that
  drops a high-risk destination out of classification entirely surfaces in review
  rather than silently. Deliberately not landed here: it constrains active
  curation and is the owner's call.
- **CWE.** CWE-183 (Permissive List of Allowed Inputs) / CWE-863 (Incorrect
  Authorization). **OWASP.** A01:2021 Broken Access Control.
- **Severity.** Medium. **Regression risk of the recommended fix.** None
  (documentation only).

## Regression Analysis

| Surface | Change | Direction | Evidence |
|---|---|---|---|
| `hostutil.NormalizeHostStrict` | fast path added | **Equivalent** | 200,936-input differential, 0 divergence |
| `policy` schedule matching | refactor + int compare | **Equivalent** | 41,616,000-decision exhaustive differential, 0 divergence |
| `policy.Evaluate` clock read | per-rule → per-scan | **Tighter** | one instant per decision; no mid-scan minute straddle |
| `pac.go` built-ins | added `URL.Host == ""` guard | **Tighter** | proxied requests no longer hijacked |
| `internal/urlcatfeed` | new package | **Neutral (dormant)** | no non-test consumer |
| `default_categories.json` | 32 reassigned, 6 dropped | **Looser for some rulesets** | SR-1 |
| CI gates | 1 gate added | **Tighter** | nothing removed from `needs` |
| Dependencies | forward bumps only | **Neutral/tighter** | no downgrades |

### Existing coverage assessed (no gap found)

I checked whether the shipped tests actually pin what they claim, since a
differential test with a weak oracle is worse than none:

- `TestNormalizeHostStrict_EquivalentToPreFastPath` and
  `FuzzNormalizeHostStrict` use a faithful reconstruction of the pre-fast-path
  body as oracle and include an explicit fail-open assertion. Adequate.
- `TestScheduleTimeMatch_OrderEquivalence` uses `scheduleTimeMatchLegacy` — which
  *is* the pre-change implementation — over 73×73 bound pairs at a 17-minute
  stride. My exhaustive sweep found nothing the stride missed. Adequate.

Both properties are therefore already pinned in CI. My harnesses were verification
instruments, not gaps to fill, and were not landed — duplicating existing coverage
would be churn, not defense.

## Residual Risk

1. **`internal/urlcatfeed` has no current-time freshness enforcement and no
   monotonic rollback floor.** `validateManifestTiming` only checks `expires_at >
   generated_at` and a 30-day ceiling — a validly-signed but **expired** manifest
   verifies, and a validly-signed **older** `feed_version` verifies. Producer-side
   `Generate` enforces `FeedVersion > PrevFeedVersion`, but that binds the
   publisher, not an attacker replaying a previously-published artifact. Both are
   documented deferrals to the F3b client slice. **Not exploitable today — nothing
   consumes the verifier.** This is the single most important thing that must land
   *before* F3 wires the kernel to a runtime path; a serve-stale/serve-old
   adversary at the distribution point is exactly the threat the signature alone
   does not address. Recommend the F3 PR be gated on: current-time expiry check,
   a persisted monotonic `feed_version` floor (mirroring
   `release_catalog_state.json`), and negative tests for both.
2. **`actions/cache@v6` is tag-pinned, not SHA-pinned.** Pre-existing posture, not
   a regression in this window, but it is a mutable supply-chain reference in a
   workflow that restores a build tool cache.
3. **SR-1 has no admin-visible signal.** Even with release notes, an operator who
   upgrades without reading them gets no runtime indication that a host left a
   category their rules depend on. A longer-term option is surfacing embedded-
   dataset diffs in the config-version/diff machinery that already exists for
   admin-managed config.
4. **`feeds_identity.env` references `feeds_identity_ssot_test.go`; the actual
   file is `feeds_identity_test.go`.** Cosmetic comment drift, no security effect.
