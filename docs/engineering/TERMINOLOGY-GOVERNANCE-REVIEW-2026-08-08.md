# Culvert Language & Terminology Governance Review — 2026-08-08

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited the tree at `1c24311`, following up on
> `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md` (baseline `d2c5a51`). 25 commits separate the two
> reviews, dominated by two same-day auth-availability security fixes (an attacker-provokable LDAP
> bind gating every user, and an answered-but-rejected credential holding a recovered backend in a
> permanent outage — both CHAOS-47), CHAOS-27 alert-dedup-storm bounding (`internal/alerts/store.go`),
> a QUAL-6.1 MCP Observe "authoritative controls" acceptance-harness expansion
> (`internal/mcpacceptance`), and a `hostutil.StripHostPort` allocation-free perf pass.
> Method: (1) diffed the actual cited lines/identifiers (not just file touches) for every one of the
> nineteen carried-over open findings — T-9, T-11, T-12, T-13, T-16, T-17, T-18, T-21, T-25, T-29
> through T-34, T-36 through T-39 — against every file each depends on: zero of their dependency files
> appear anywhere in this window's 45-file diffstat, so all nineteen are unchanged by construction, not
> just by inspection; (2) three independent sweeps of the full tree (not diff-scoped) across the
> blocklist/allowlist family, the SSL/TLS-inspection/decryption family, and the auth/identity/session
> family, cross-checked against this doc's own backlog to avoid re-litigating tracked items and to
> surface anything the diff-based method structurally cannot catch — drift that has been sitting in the
> tree for longer than one window; (3) read the new QUAL-6.1 authoritative-controls harness and the new
> CHAOS-27 dedup vocabulary end-to-end, both landing in territory adjacent to prior findings (QUAL-6,
> T-39's namespace; the alert plane, T-40's namespace), and found each internally consistent; (4) verified
> every fix in this pass by direct `grep`/`Read` citation before editing (not by trusting sub-agent output
> at face value), then `go build ./...`, `go vet ./...`, `gofmt -l`, and targeted `go test` runs, all clean.
> **Companion change:** two findings fixed same-day — **T-41** (new: "whitelist"/"blacklist" resurfaced
> in comments/test names, including a partial regression of T-2's 2026-07-07 fix into new PR-10-era
> code) and **T-42** (new: T-40's `idp_unreachable`→`identity_backend_unreachable` rename, 2026-08-07,
> covered the wire event, GUI, `diagnostics.go`, and `CLAUDE.md` but missed prose comments in the two
> CHAOS-47 source files themselves). Both are comment/test-name-only, zero wire/API/GUI-string impact,
> and — same reasoning this program has applied since T-35 — the cheapest point to fix is now, before
> either compounds further.

---

## Executive Summary

**All nineteen carried-over findings re-verified unchanged, this time by structural proof rather than
line-by-line diffing.** Every one of the nineteen findings' dependency files (`policy.go`, `config.go`,
`metrics.go`, `ui_policy.go`, `ui_mcp.go`, `mcp_inventory.go`, `configversion.go`,
`cluster_convergence.go`, `saas_feed_download.go`, `support_recipients.go`, `support_tac_trust.go`,
`internal/sealbox`, README/enterprise docs, `internal/mcp/rollout`, QUAL-2/3 config/docs, and the
`exportedAt` export/import surface) is absent from this window's 45-file diffstat. `static/index.html`
*was* touched, but only for the new CHAOS-27 dedup-health line and the already-fixed
`idp_unreachable`→`identity_backend_unreachable` checkbox value — zero new hits for `drifted_tools`,
`review_required_tools`, or "qualification". T-38 and T-39 are therefore unchanged, not merely
re-confirmed.

**Two new findings, both fixed same-day.**

**T-41 — legacy "whitelist"/"blacklist" resurfaced, including a partial regression of a prior fix.**
A full-tree sweep (not diff-scoped, since this class of drift accretes one comment at a time and a
diff-only method would never catch it) found seven live instances of "whitelist"/"blacklist" standing
in for the canonical "exempt list"/"allowlist"/"blocklist" vocabulary used everywhere else for the same
concepts. Two are directly on the T-2 (2026-07-07) rate-limit-exempt-list concept that review already
fixed six instances of: `security.go:203` is a struct-field doc-comment T-2's fix missed (it fixed five
function doc-comments and one line in `configversion.go`, not this one), and `controlplane_snapshot.go:831`
is new PR-10-era code (landed 2026-08-03, four weeks after T-2 shipped) that reused "whitelist" for the
identical concept — a genuine regression of an already-fixed finding. Two more are test comments on the
same concept in files that postdate the T-2 fix
(`configversion_rate_limit_exempt_test.go`, `controlplane_ratelimit_exempt_sync_test.go`). The remaining
three are unrelated concepts using the same deprecated words: a CDR tag-safety test
(`cdr_proxy_test.go`), a PAC host-encoding `#nosec` comment (`pac.go`), and an SSRF-dialer test comment
(`qa_gate_test.go`). All seven are comments or test-only identifiers with zero external references
(verified by grep before each edit) — fixed by renaming to the terms already canonical everywhere else
for each concept.

**T-42 — T-40's identity-backend rename didn't reach its own source-file comments.** T-40
(2026-08-07) correctly renamed the `idp_unreachable` wire alert event, the GUI checkbox value,
`diagnostics.go`'s contract-row comment, and `CLAUDE.md` — the finding's own text says the rename covers
"the wire alert event string and its `HasSubscriber` gate ... the event catalog comment ... the GUI
checkbox's `value` attribute ... `diagnostics.go`'s comment, and CLAUDE.md's CHAOS-47 section." It did
not touch prose *inside* `auth_oidc.go` and `auth_backend_health.go` — the two files that implement the
concept T-40 was renaming. Six comments there still said "IdP" for the CHAOS-47 legacy-backend
cooldown/gate mechanism, in the same files whose neighboring lines already correctly say "identity
backend" post-T-40 — a reader moving down the function would hit both names for the same thing within a
few lines. Two more clearly-generic OIDC-protocol usages ("self-signed dev IdPs", "an IdP may
transiently report active=true") were deliberately left alone: they describe the external OIDC
identity-provider concept generically, not Culvert's specific CHAOS-47-vs-registry distinction, so
renaming them would not have reduced any real ambiguity. One held-out instance
(`auth_backend_health_test.go`'s `TestOIDC_UnreachableIdPFiresAlert` test name and its one comment) is
left as-is: the name is cited by two dated historical reports
(`CHAOS-ENGINEERING-REVIEW-2026-08-03.md`, `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md`), and per this
program's own stop-condition practice a point-in-time snapshot is not retroactively kept in sync —
renaming it would orphan those citations for a comment-only, zero-user-impact instance. Noted below as a
soft finding for a future pass, not queued.

**Terminology Health Score: 8.4 / 10** (held steady — the carried-over backlog is unchanged across a
25-commit window with zero new dependency-file touches, and this window's two dominant new features
(CHAOS-27 dedup, QUAL-6.1 authoritative controls) each shipped with fully self-consistent vocabulary. The
score does not move up despite two same-day fixes because one of them (T-41) is evidence that a
previously "fixed" finding can regress via unrelated new code reusing the old word, which is exactly the
kind of drift a point-in-time score should stay cautious about rather than reward for catching quickly).

---

## Wave 1 — Carried-over findings re-confirmed unchanged (by structural proof)

`git diff d2c5a51..HEAD` (25 commits, 45 files) was checked against the full dependency-file list for
each of the nineteen open findings. None of those files appear in the diff at all — a stronger
guarantee than the usual "touched but the cited lines are untouched" check this program normally runs,
possible this window because the diff is small and none of it lands in tracked territory.

| Finding | Files it depends on | Touched this window? | Collision status |
|---|---|---|---|
| T-9 | export/import + parity-test surface (`exportedAt`) | No | Unchanged |
| T-11 | `policy.go`'s default-action vocabulary, `ui_policy.go` core | No | Unchanged |
| T-12 | Maintenance-Agent `/v1/upgrades/*` wire routes | No | Unchanged |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | No | Unchanged |
| T-16 | ADR numbering (0008–0011) | No | Unchanged |
| T-17 | `decryption_redact_hosts` / `/api/decryption/redaction` | No | Unchanged |
| T-18 | `internal/sealbox.Seal`/`Open` call sites | No | Unchanged |
| T-21 | `cluster_convergence.go`, `configversion.go`'s rollback `cp_version` surface | No | Unchanged |
| T-25 residual | `support_recipients.go` / `support_tac_trust.go` | No | Unchanged |
| T-29 | YAML `rate_limit` (`config.go`/`main.go`) vs. `rate_limit_rpm` (API/wire/metric) | No | Unchanged |
| T-30 | YAML `max_conns_per_ip`/wire `MaxConnsPerIP` vs. `conn_limit_max_per_ip` | No | Unchanged |
| T-31 | `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` | No | Unchanged |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` overloads "snapshot" | No | Unchanged |
| T-33 | MCP `PolicyAction`/`PolicyReason` (`internal/mcp/runtime/policy.go`, `events.go`, `observe.go`) | No | Unchanged |
| T-34 | SaaS feed status field-name split (`saas_feed_download.go`, `ui_policy.go`) | No | Unchanged |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | No | Unchanged |
| T-37 | "Manual feed sync" naming split across blocklist/SaaS/threat feeds | No | Unchanged |
| T-38 | `ui_mcp.go`, `internal/mcp/adminapi/health.go`, `mcp_inventory.go`, `static/index.html` (`drifted_tools`/`review_required_tools`) | `static/index.html` touched (+10/−4), but the diff is CHAOS-27 dedup UI + the already-fixed `idp_unreachable` checkbox value — zero hits for `drifted`/`review_required` | Unchanged |
| T-39 | `internal/mcp/rollout` (Production Qualification), QUAL-2/3 config/docs | No | Unchanged |

## Wave 2 — New territory audited this pass (25 commits since `d2c5a51`)

**CHAOS-27 (`internal/alerts/store.go`, `events.go`, `ui_security.go`, `static/index.html`) holds
discipline end-to-end.** The new dedup-saturation vocabulary — `dedupEvicted`/`DedupEvictionsTotal`/
`DedupTracked` in Go, `dedup_evictions_total`/`dedup_tracked` on the JSON API
(`GET /api/alerts/delivery-history`), `culvert_alert_dedup_evictions_total`/`culvert_alert_dedup_tracked`
on `/metrics`, and the GUI's `dedupEvicted` JS variable rendering the same concept — is internally
consistent across every layer, with no competing name introduced anywhere. This is a clean example of the
pattern this program wants to see from new features, not a finding.

**QUAL-6.1's "authoritative controls" acceptance-harness expansion
(`internal/mcpacceptance/authoritative.go`, `spec.go`, `fixture.go` and their tests, plus
`docs/operator/mcp-observe-acceptance-{runbook,decisions}.md`) introduces no new drift and does not touch
T-39's tracked "qualification" territory.** The package remains, as the 2026-08-07 review already
established, unreachable from the production binary (confirmed again this pass: no file outside
`internal/mcpacceptance` and its `cmd/` counterpart imports it), so its vocabulary is test-tooling
vocabulary, not product language. "Authoritative" is a new adjective in this window
(`authoritative.go`'s `AuthoritativeResult`, the runbook's "Authoritative Controls" section) describing a
stricter acceptance-evidence mode layered on the existing Observe-acceptance vocabulary — it does not
reuse or collide with "qualification," "policy," or any other tracked term, and the runbook update is
explicit that this is additive rigor on the existing harness, not a new business concept needing a name
of its own.

**`internal/hostutil.StripHostPort`'s allocation-free rewrite is a pure performance change** — same
function name, same signature, same semantics, pinned by 30-plus new table-driven cases in
`internal/hostutil/hostutil_striphostport_test.go`. No terminology surface.

**The two same-day CHAOS-47 security fixes (LDAP account-rejection gating, OIDC/LDAP cooldown-clearing)
reuse the exact vocabulary this program's T-40 pass established** — `noteVerifyError`,
`errLDAPAccountRejected`, `recordReachable`/`recordUnavailable`, `authProbeGate` — with no new or
competing terms introduced. The gap they closed was security, not naming; this pass's contribution is
T-42, the residual "IdP" prose these same files still carried from before T-40.

**Full-tree sweeps (blocklist/allowlist, SSL/TLS/decryption, auth/identity/session) surfaced T-41 and
T-42 above and otherwise confirmed the existing backlog's boundaries, with two negative results worth
recording so a future pass doesn't re-litigate them:** the `culvert_decrypt_*` metric prefix vs. the
fully-spelled `decryption`/`decryption-profile` namespace remains a documented, internally consistent
deliberate abbreviation (CLAUDE.md), not drift; and `feedsync.go`'s "blacklists/" is the literal on-disk
directory name inside the third-party UT1 Capitole tarball format (`blacklists/<category>/domains`) —
renaming the comments describing it would misdescribe the actual external artifact, so it is correctly
excluded from T-41 rather than folded into it.

---

## Findings

### T-41 — "Whitelist"/"blacklist" resurfaced in comments and test names, including a regression of T-2 (new — fixed same-day)

- **Business concept A:** the rate-limit exempt list (IP/CIDR entries that bypass the per-IP limiter) —
  the same concept T-2 (2026-07-07) already renamed from "whitelist" to "exempt list" in six locations.
- **Business concept B–D (unrelated, same deprecated words):** CDR tag-safety allowlisting, PAC
  host-character encoding safety, and the SSRF-safe dialer's private-address rejection.
- **Current names / collision:**
  - `security.go:203` — `RateLimiter`'s struct-field comment: `// Whitelist — exempt IPs/CIDRs that
    bypass rate limiting`. This is the same struct T-2 fixed five *method* doc-comments on
    (`IsExempt`, `AddExemption`, `RemoveExemption`, `ReplaceExemptions`, `ListExemptions`); the
    *field*-level comment two lines above `exemptMu`/`exemptNets`/`exemptIPs` was not among them and
    survived untouched.
  - `controlplane_snapshot.go:831` — `// lock-step with the CP whitelist instead of silently leaving DP
    nodes...`, part of the CP→DP `RateLimitExempt` sync path. This code landed 2026-08-03 (PR-10 Leg 3,
    `feat(mcp): PR-10 Leg 3 — CP/DP transport integration`) — four weeks *after* T-2 shipped — and reused
    "whitelist" for the identical exempt-list concept T-2 had already renamed everywhere else. A genuine
    regression: not code that predates the fix, but new code that didn't know about it.
  - `configversion_rate_limit_exempt_test.go:26,29,84,107,131` and
    `controlplane_ratelimit_exempt_sync_test.go:71,87` — seven more "whitelist" instances in test
    doc-comments on the same rate-limit-exempt concept, also postdating T-2.
  - `cdr_proxy_test.go:515-516` — `TestSafeCDRSanitize_TagsAreWhitelisted` / "tags are whitelisted",
    describing CDR metric-tag allowlisting (an unrelated concept, same deprecated word).
  - `pac.go:165` — a `#nosec G705` comment: "host is character-whitelisted above" (PAC host-encoding
    safety, unrelated concept).
  - `qa_gate_test.go:218` — "the dialer must refuse because loopback is blacklisted" (SSRF private-address
    rejection, unrelated concept).
- **Why this is real drift, not cosmetic:** "whitelist"/"blacklist" are deprecated industry terminology
  Culvert has already made a product decision to retire — T-2 fixed six instances of exactly this pattern
  seven weeks ago, `docs/design/PRODUCT-TERMINOLOGY.md:35` documents "Blocklist / Allowlist ... never
  'blacklist/whitelist' (already clean)" as the standing rule, and the live API/GUI/JSON surface for the
  rate-limit exempt list has said "exempt"/"exemption" throughout. The `controlplane_snapshot.go` instance
  is the clearest evidence this needs a durable fix, not a one-time sweep: a rule that isn't enforced
  anywhere mechanical (a lint, a grep in CI) will keep resurfacing one comment at a time as new code
  reaches for the intuitive-but-deprecated word.
- **Why same-day-fixable:** every instance is a comment or a test-only function name, verified by grep to
  have zero external references before editing (`TestSafeCDRSanitize_TagsAreWhitelisted` is not
  referenced anywhere outside its own file). No wire field, API field, GUI string, or persisted config key
  changed. `go build ./...`, `go vet ./...`, `gofmt -l`, and a targeted `go test` run across every touched
  file are clean after the rename.
- **Fix applied:** `security.go:203` → "Exempt list"; `controlplane_snapshot.go:831` → "CP exempt list";
  both test files' six comments → "exempt list"; `cdr_proxy_test.go` → "tags are allowlisted" /
  `TestSafeCDRSanitize_TagsAreAllowlisted`; `pac.go:165` → "character-allowlisted"; `qa_gate_test.go:218`
  → "loopback is a blocked private address". `feedsync.go`'s "blacklists/" was deliberately **not**
  touched — see Wave 2 above.
- **Recommended follow-up (not applied this pass):** consider a CI grep gate (alongside the existing
  gitleaks/lint scans) for `\b(white|black)list` outside `internal/feedsync` and the UT1-vendor context,
  so this class of drift is caught at PR time instead of accumulating for the next point-in-time review to
  find. Left as a recommendation, not a same-day change, since it is a process/CI addition rather than a
  terminology rename.
- **Priority:** was Low-Medium (comment-only, but a proven regression pattern). **Migration risk:** None.
  **Est. PR size:** Trivial (already applied this pass).

### T-42 — T-40's identity-backend rename left "IdP" in its own source files' prose (new — fixed same-day)

- **Business concept:** the CHAOS-47 legacy LDAP-bind/OIDC-introspection proxy-auth backend availability
  mechanism — the same concept T-40 (2026-08-07) renamed from `idp_unreachable` to
  `identity_backend_unreachable` at the wire/GUI/diagnostics/CLAUDE.md layer, specifically to stop it
  colliding with the separate, GUI-prominent "IdP" (federated Identity Provider registry, `auth_idp.go`,
  CHAOS-49) vocabulary CLAUDE.md documents as a different subsystem.
- **Current names / residual collision:** T-40's own fix list (`auth_backend_health.go:172,175`, the seam
  function, `internal/alerts/store.go:28`, the GUI checkbox, `diagnostics.go:409`, CLAUDE.md) did not
  include prose *inside* the two files that implement the CHAOS-47 mechanism itself:
  - `auth_oidc.go:148,204,224,233,235` — five comments describing the same
    cooldown/gate/reachability mechanism T-40's fix already correctly names "identity backend" one
    function away, still said "IdP": "gate arms when the IdP is unreachable", "IdP is in its unreachable
    cooldown", "hold a recovered IdP in a permanent outage", "Could not reach the IdP", "the IdP
    recovers".
  - `auth_backend_health.go:10,42` — the file's own header comment (the canonical description of what
    CHAOS-47 is) said "IdP HTTP 5xx" and "an IdP outage was previously indistinguishable from a
    brute-force spike" — describing the file's own subject matter with the word its sibling file,
    `auth_oidc_flow.go`, uses for the *different*, un-cached IdP-registry path.
  - `diagnostics.go:407` — the `checkIdentityBackend` contract-row doc-comment (one line above the line
    T-40 already fixed) said "an LDAP URL, an IdP host" as its example of what the redacted cause text
    names.
- **Why this is real, not cosmetic:** these are the exact same "identity backend vs. IdP registry"
  ambiguity T-40 was written to close, one layer down — a maintainer reading `auth_oidc.go` top to bottom
  hits "identity backend" (the corrected comment at line 148, this pass) and "IdP" (the neighboring,
  unfixed comments) for the same mechanism within a few lines of each other, which is a worse reading
  experience than either name used consistently.
- **What was deliberately left alone:** `auth_oidc.go:169` ("self-signed dev IdPs only") and `:388` ("An
  IdP may transiently report active=true") describe the external OIDC identity-provider concept
  generically — TLS-verification posture and RFC 7662 introspection-endpoint behavior respectively — not
  Culvert's specific CHAOS-47-vs-registry naming distinction. Renaming these would not reduce any real
  ambiguity, matching this program's standing rule against renames that don't improve clarity.
  `auth_backend_health_test.go`'s `TestOIDC_UnreachableIdPFiresAlert` test name and its one "keeps a down
  IdP from emitting" comment were also left as-is: the name is cited verbatim by two dated historical
  reports (`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-03.md:196`, this doc's own
  `TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-07.md:179`), and this program does not retroactively edit past
  point-in-time snapshots to stay in sync with a rename — recorded as a soft finding below instead of
  queued.
- **Why same-day-fixable:** all seven edits are prose comments with zero wire/API/GUI/persisted-config
  surface, verified before editing by reading each file directly. `go build ./...`, `go vet ./...`, and
  `gofmt -l` are clean; the OIDC/LDAP auth test suites (`TestOIDCAuth_*`, `TestLDAP_*`) all pass unchanged.
- **Fix applied:** `auth_oidc.go`'s five comments and `auth_backend_health.go`'s two header-comment
  instances renamed to "identity backend" (matching the file's own already-correct neighboring prose);
  `diagnostics.go:407`'s example changed to "an OIDC introspection host" (more precise than the generic
  "IdP host" it replaced, and avoids the ambiguity entirely rather than just relabeling it).
- **Priority:** was Low (comment-only, T-40 already closed the load-bearing surface). **Migration risk:**
  None. **Est. PR size:** Trivial (already applied this pass).

---

## Carried over, still open (re-confirmed this pass — see Wave 1 table; zero dependency-file touches this window)

| Finding | Business concept | Status |
|---|---|---|
| T-9 | `exportedAt` → `capturedAt` rename | Open since 07-07. Unchanged. |
| T-11 | `allow`/`deny` default-action vocabulary vs. 4-value `PolicyAction` | Open since 07-16. Unchanged. |
| T-12 | Maintenance-Agent wire API "upgrade" vs. GUI/API "update"/"Dispatch" | Open since 07-16. Unchanged. |
| T-13 residual | README/enterprise-doc "TLS Inspection" vs. in-app "SSL" | Open since 07-24 (soft/low). Unchanged. |
| T-16 | ADR numbering collision: 0008–0011 | Open since 07-19. Unchanged. |
| T-17 | Traffic-log destination-privacy config key/route still says "decryption" | Open since 07-19. Unchanged. |
| T-18 | "Seal" names two unrelated cryptographic operations | Open since 07-19, grew 07-24. Unchanged. |
| T-21 | "Config Version" names two unrelated, independently-incrementing counters | Open since 07-24. Unchanged; still compounded by T-32. |
| T-25 residual | Two disjoint "recipient"/"TAC trust key" registries | Open since 07-24. Unchanged. |
| T-29 | Per-IP rate limit: `rate_limit` (YAML/CLI) vs. `rate_limit_rpm` (API/wire/metric) | Open since 08-01. Unchanged. |
| T-30 | Per-IP connection cap: `max_conns_per_ip`/`MaxConnsPerIP` vs. `conn_limit_max_per_ip` | Open since 08-01. Unchanged. |
| T-31 | ClamAV metric family: `clamav` everywhere except `culvert_clam_scan_errors_total` | Open since 08-01. Unchanged. |
| T-32 | F3b's `SnapshotSHA256`/`snapshot_sha256` reuses the overloaded term "snapshot" | Open since 08-01. Unchanged. |
| T-33 | MCP `PolicyAction`/`PolicyReason` observation fields mix three vocabularies | Open since 08-02. Unchanged; zero production consumers. |
| T-34 | SaaS feed status field-name split across two admin endpoints | Open since 08-02. Unchanged. |
| T-36 | `config.rollback` audit token vs. freeform config-version-history action string | Open since 08-04. Unchanged. |
| T-37 | "Manual feed sync" audit-action naming split across blocklist/SaaS/threat feeds | Open since 08-04. Unchanged. |
| T-38 | `drifted_tools` vs. `review_required_tools` — same count, same API response, two names | Open since 08-06. Unchanged; still a pre-existing tested wire field, dual-emit remains the recommended fix. |
| T-39 | "Qualification" names four unrelated concepts in the same config/admin namespace | Open since 08-06, compounded 08-07. Unchanged this pass — still needs a design decision. |

*T-41 and T-42 are not listed here — both fixed same-day, see Findings.*

## Soft findings — no action recommended

- Carried over unchanged from 07-24 onward: "Bootstrap" covering two unrelated features (no on-screen
  collision yet); the T3 "seed"/`CULVERT_PROXY_SEED_REF` vocabulary (internally consistent).
- Carried over unchanged from 08-03: the `culvert_decrypt_*` metric prefix vs. the fully-spelled
  `decryption`/`decryption-profile` API/audit/alert namespace — internally consistent, documented as a
  deliberate abbreviation in CLAUDE.md.
- Carried over unchanged from 08-06/08-07: `drifted_tools`'s absence from the OpenAPI spec despite being
  a live, tested field; the CDR per-instance circuit-breaker fields' ad hoc `cb`-prefix wire-key
  convention vs. the sibling `internal/upstream.Status` breaker's convention (same concept, no collision,
  just an inconsistent key-naming style worth aligning in a future pass).
- **New this pass:** `feedsync.go`'s "blacklists/" — the literal on-disk directory name inside the
  third-party UT1 Capitole tarball format. Confirmed as accurate description of an external artifact, not
  drift; deliberately excluded from T-41.
- **New this pass:** `auth_backend_health_test.go`'s `TestOIDC_UnreachableIdPFiresAlert` test name and its
  one "down IdP" comment — same T-42 pattern, but the name is cited by two dated historical reports and
  this program does not retroactively edit point-in-time snapshots for a comment-only, zero-user-impact
  rename. Worth folding into a future pass once those citations have aged out of relevance.
- **New this pass:** `internal/hostutil.StripHostPort`'s perf rewrite, the CHAOS-27 dedup vocabulary, the
  two CHAOS-47 security fixes, and the QUAL-6.1 authoritative-controls harness were all checked in detail
  and found clean or already correctly disambiguated — continued positive pattern, not findings.

---

## Recommended Refactoring Plan (priority order)

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| High | T-38 (carried over) | Dual-emit `CapabilityHealth.ReviewRequiredTools`/`review_required_tools` alongside `DriftedTools`/`drifted_tools`; update GUI label; add both fields to the OpenAPI spec | Low (additive) | Small |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-16 (carried over) | Renumber the Supportability-track's colliding ADRs (0008–0011 → 0019–0022) | Low (docs only) | Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-36 (carried over) | Give `saveConfigVersion`'s rollback call a `config.rollback`-prefixed action string alongside the version number | Low | Small |
| Medium | T-37 (carried over) | Rename `security.feeds_sync` → `threatfeed.sync`; update `security_feedsync_audit_test.go`'s three literal assertions | Low | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field | None today; rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low-Medium | T-31 (carried over) | Rename `culvert_clam_scan_errors_total` → `culvert_clamav_scan_errors_total`, dual-emit | Low | Small |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |
| Low (process) | T-41 follow-up (new) | Add a CI grep gate for `\b(white|black)list` outside the UT1-vendor context, so this class stops recurring one comment at a time | Low | Small |

*T-41 and T-42 are omitted from the priority list above except the T-41 process follow-up — both fixed
this pass.*

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass re-confirmed, by structural absence from a 25-commit
diff rather than by line-level inspection, that all nineteen previously-open findings are unchanged. It
found and same-day-fixed two new issues: T-41, evidence that a already-"fixed" finding (T-2) can regress
when unrelated new code reaches for the deprecated word again, and T-42, evidence that a rename can be
complete at the wire/API/GUI layer while leaving the same ambiguity live in the source comments that
implement it. Both are the cheapest kind of finding this program looks for — caught before any consumer
or new contributor could be misled by them, with the same "catch it, the earlier the cheaper" logic
applied since T-35. T-41's regression is also the strongest argument yet for the CI-grep-gate follow-up
recorded in the refactoring plan: a convention with no mechanical enforcement will keep resurfacing
one comment at a time, and a periodic review is a backstop, not a substitute, for catching it at commit
time. No cosmetic or preference-driven renames were proposed.
