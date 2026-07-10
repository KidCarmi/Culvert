# Security Regression Review — policy priority dedup, enrollment CIDR fail-closed, reproducible image (window ea0f2ff → 328c883)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-09
> **Baseline:** `origin/main` @ `ea0f2ff` (end of the previous review's window,
> `docs/security-reviews/2026-07-07-secret-containment-maint-agent-chaos-window.md`)
> **Head:** `origin/main` @ `328c883`
> **Scope reviewed:** every code-bearing change merged in the window — 14 files, +3,239 / −11 —
> grouped into four code clusters plus a documentation cluster: (1) policy-rule duplicate-priority
> validation (`ui_helpers.go`) + the TOCTOU close in `PolicyStore.Add` (`policy.go`), PRs #571/#563;
> (2) the enrollment-token CIDR fail-closed fix (`enrollment.go`, chaos finding HA-9), PR #608;
> (3) the quick-start installer's `maint_toml_string()` trailing-comment fix (`scripts/install.sh`),
> PR #611; (4) the byte-reproducible image build (`Dockerfile` `-buildvcs=false`), PR #569.
> Documentation-only merges (R2 catalog-migration plan + its adversarial review, the standing
> chaos-engineering register, roadmap sign-off amendments — PRs #613/#524 and parts of the above)
> were read for posture commitments but carry no attack surface in this window.

---

## Executive Summary

**No CRITICAL, HIGH, or MEDIUM security regressions were found.** The window is a net security
improvement: a nil-pointer panic in the cluster-enrollment token path (reachable from corrupted
or hand-edited persisted token state) now fails closed instead of crashing the node; duplicate
explicit policy priorities — which produced nondeterministic rule precedence, a policy-evaluation
integrity hazard in a first-match engine — are rejected at validation time and, for the residual
concurrent-add race, deterministically reassigned under the store lock with a warning log; and
the Docker image binary is now byte-reproducible (`-trimpath` + `-buildvcs=false`), strengthening
the supply-chain verification story without weakening any stamp the release pipeline relies on
(`VERSION` is still injected via `-X` ldflag; cosign/SLSA provenance are CI-level and unaffected).

Four LOW/INFO findings are recorded below. None changes a trust decision, none fails open, and
none warrants blocking a release. The one most worth scheduling is **F1**: merge-mode config
import now silently skips imported rules whose explicit priority collides with a live rule —
in a default-deny engine a silently-dropped *deny* rule that was meant to shadow a broader
*allow* leaves traffic allowed while the admin believes it is blocked, and the skip is visible
only in the server log, not in the import API response.

Two regression-sensitive paths were explicitly checked and are **unaffected**:
config-version **rollback** (`configversion.go:229,323` validates restored rules against a `nil`
existing-rule slice, so snapshots that historically contain duplicate priorities still restore
via `ReplaceAll`), and **replace-mode import** (`ui_config.go:665-666` goes straight to
`ReplaceAll`, bypassing the new per-rule check). Re-importing a self-consistent export therefore
still works; the new rejection only bites additive merge-mode collisions.

**Verification:** `go build` clean at HEAD; targeted suites green at `-count=1`:
`policy_priority_dedup_test.go` (store + validator + handler paths),
`TestTokenValidate_*` incl. the new `CorruptedCIDR_FailsClosed`,
`TestDetectConflicts_*` (duplicate-state detection still surfaces legacy dups),
`TestInstallScript_MaintTomlString_*`. A residual sweep found no other `net.ParseCIDR`
call site with a discarded error on attacker-influenceable input (the one remaining
`_`-error site, `internal/ssrf/ssrf.go:57`, parses compile-time reserved-range literals
behind a nil guard).

---

## Security Findings

### F1 — LOW · Merge-mode config import silently skips colliding-priority rules

**File:** `ui_config.go:667-674` (`apiConfigImport`, merge branch) · **Commit window:** PR #571/#563
**CWE:** CWE-778 (Insufficient Logging) / CWE-451 (UI Misrepresentation of Critical Information) · **OWASP:** A09 Security Logging & Monitoring Failures

- **Behavior change:** merge-mode import validates each incoming rule with
  `validatePolicyRule(rule, policyStore.List(), -1)`. With the new duplicate-priority check, an
  imported rule whose explicit priority is already occupied by a live rule is **skipped** (one
  `logger.Printf` line) instead of being added alongside it. The import response remains
  `{"ok": true, "mode": "merge", ...}` with no skip count.
- **Attack/failure scenario:** an admin merge-imports a backup containing a narrow **deny**
  rule (e.g. blocking a newly-malicious host) whose priority slot is taken by an existing broad
  **allow** rule. The deny is dropped; traffic the admin believes is now blocked continues to
  flow. No attacker action is required — this is an operator-integrity failure mode — but an
  attacker who knows the target's rule layout benefits from the shadowed deny.
- **Regression analysis:** partially pre-existing — merge mode already silently skipped
  same-**name** rules (the `rule name already exists` branch) with the same log-only
  visibility. The new check **widens the silently-skipped class** to priority collisions, which
  are far more likely when re-importing an edited export of the same deployment. Note the
  baseline behavior (adding the duplicate) was itself hazardous — nondeterministic precedence —
  so skipping is directionally correct; the gap is *visibility*, not the decision.
- **Preconditions / likelihood:** admin-only endpoint (`requireRole(RoleAdmin)`), merge mode,
  colliding explicit priority. Moderate likelihood in normal operations; low as an attack.
- **Impact:** a policy the admin intended to apply is absent; in the default-deny engine a
  dropped *allow* is fail-safe, a dropped *deny* that shadows an allow is fail-open **relative
  to the admin's intent** (the engine's own default never changes).
- **Recommended fix:** accumulate skipped rule names + reasons in the merge loop and return
  them in the JSON response (`{"ok":true,"skipped":[{"name":...,"reason":...}]}`); include the
  skip count in the `config.import` audit event. Optionally treat priority collisions in merge
  mode as an upsert-by-name opportunity (matching the category-taxonomy merge semantics) rather
  than a skip.
- **Required tests:** merge import with one colliding rule asserts the response lists it;
  merge import with zero collisions asserts `skipped` empty; audit-entry content check per the
  ring-saturation-safe pattern; replace-mode import of the same payload asserts full application.

### F2 — INFO · `PolicyStore.Add` TOCTOU path silently demotes a racing rule to lowest precedence

**File:** `policy.go:388-410` (`Add`, collision branch) · **Commit:** `2a5fbc8`
**CWE:** CWE-367 (TOCTOU, now mitigated — residual note) · **OWASP:** A04 Insecure Design

- **Behavior:** when two concurrent creates pass handler-level validation against the same
  pre-lock snapshot, the second now gets reassigned under the lock to `maxPri+1` instead of
  landing as a duplicate. Rules sort ascending and `Evaluate` is first-match, so `maxPri+1` is
  the **lowest** precedence slot — a racing deny meant to shadow an allow at its requested slot
  ends up evaluated last.
- **Why this is acceptable:** the alternative (duplicate priorities) was strictly worse —
  nondeterministic precedence with no signal at all. The reassignment is deterministic, emits a
  `logWarnf`, and the handler returns and **audits the actual assigned priority**
  (`ui_policy.go:917-924` uses `added.Priority`), so the caller can see the demotion. The
  window is a same-millisecond admin/operator race, not attacker-reachable (both requests are
  authenticated writes).
- **Recommended follow-up (optional):** none required. If policy semantics ever make the
  requested slot load-bearing, change the collision branch to return an error instead —
  that needs an error return plumbed through `Add`'s callers (API create, config import,
  CP snapshot apply), so it is deliberately out of scope for this hardening.

### F3 — INFO · `validatePolicyRule` edit-exclusion is by slot, not by rule identity

**File:** `ui_helpers.go:115-124` · **Commit:** `51d310b`
**CWE:** CWE-697 (Incorrect Comparison — benign here) · **OWASP:** A04

- **Behavior:** the update-path exclusion `existingRules[i].Priority != editPriority` excludes
  *every* rule occupying the caller's current slot, not the specific rule being edited. In a
  legacy degenerate state where two rules already share priority P (still creatable via
  `ReplaceAll` on rollback/import of an old snapshot), editing either rule while keeping P
  validates cleanly even though the duplicate persists.
- **Assessment:** not a regression — it merely refrains from blocking edits to pre-existing
  degenerate state, `DetectConflicts` still surfaces the duplicate (re-pinned by the updated
  `TestDetectConflicts_SamePriorityDiffAction`), and any attempt to *move* onto an occupied
  slot is correctly rejected. No action needed; recorded so the slot-based exclusion isn't
  later mistaken for an identity check.

### F4 — INFO · `maint_toml_string()` truncates values at the first `"` (no TOML escape support)

**File:** `scripts/install.sh:864-882` · **Commit:** `ba06351`
**CWE:** CWE-20 (Improper Input Validation — fail-safe direction) · **OWASP:** A05

- **Behavior:** the rewritten extractor strips everything from the first unescaped-or-not `"`
  onward, so an inline `# comment` after the closing quote no longer leaks into the value (the
  actual bug fixed), and a `#` **inside** the quoted value is now handled correctly. TOML
  basic-string escapes (`\"`) are still unsupported — a value containing an escaped quote is
  truncated at it.
- **Regression analysis:** none. The baseline was broken worse (`FS="="` split values
  containing `=` and kept trailing comments). The failure direction is truncation of a
  root-owned config value (fail-safe: a truncated `proxy_repo` fails the digest-pull allowlist
  rather than widening it), the extracted keys (repo/path identifiers) cannot legitimately
  contain quotes, and the implementation now mirrors `extract_toml_string()` in
  `packaging/culvert-maint/install.sh` — one behavior, two copies. Recorded only so a future
  key whose value can contain `\"` isn't routed through this extractor.

---

## Cluster-by-cluster regression analysis

**1. Policy priority dedup (`ui_helpers.go`, `policy.go`, PRs #571/#563).** Net positive:
duplicate explicit priorities in a first-match engine are a precedence-integrity hazard
(CWE-670 class), now rejected at the three write handlers (`ui_policy.go:912,960`,
`ui_authpolicy.go:125,172`) and race-closed inside `Add`. Checked and clean: rollback restores
degenerate snapshots untouched (`nil` existing-rules argument), replace-mode import bypasses the
check via `ReplaceAll`, update-in-place keeping the same slot is allowed, and the auth-policy
(Stage-1) handlers share the same store so no cross-surface divergence. Residuals are F1–F3.

**2. Enrollment CIDR fail-closed (`enrollment.go:275-281`, PR #608, chaos HA-9).** Strict
improvement. Baseline discarded `net.ParseCIDR`'s error, so a malformed `AllowCIDR` in
persisted token state (`cluster.json` corruption or hand-edit) made `cidr.Contains(ip)` panic
inside `ValidateAndConsumeToken` — a crash-DoS of the enrollment path and, depending on
recovery middleware, a repeatable node-wide availability hit. Now returns a wrapped error with
the mutex correctly released (matches the adjacent deny branch). Fail direction is **closed**:
a corrupted restriction denies enrollment rather than skipping the CIDR check. The new
`TestTokenValidate_CorruptedCIDR_FailsClosed` pins it. Residual sweep found no other
error-discarding `ParseCIDR` on non-constant input.

**3. Installer TOML extractor (`scripts/install.sh`, PR #611).** See F4 — bug fix, fail-safe
direction, contract-tested (`install_script_maint_toml_string_test.go` covers comment,
no-comment, `#`-in-value, and missing-key cases).

**4. Reproducible image (`Dockerfile`, PR #569).** `-buildvcs=false` added alongside the
existing `-trimpath`. Security-relevant question: does dropping the VCS stamp weaken any
verification? No — the stamp was already nondeterministic garbage in this build (the
`.dockerignore`-pruned context made `vcs.modified` depend on context contents), `VERSION` is
still injected explicitly via `-X main.version`, and image signing/provenance (cosign, SLSA)
attest the built artifact independently of Go's buildinfo. Byte-reproducibility is a
supply-chain **gain**: independent rebuilds can now bit-compare the binary against the
published image. The module graph remains pinned (no `go mod tidy` at image build — unchanged).

**5. Documentation cluster (PRs #613/#524 and roadmap commits).** No code. The R2
catalog-migration plan ships with its own adversarial pre-implementation review
(`roadmap/R2-CATALOG-MIGRATION-REVIEW.md`, verdict SHIP-WITH-CHANGES with three P0 design
blockers around the monotonic-floor/ring interaction, `catalog_version` authority, and the
unwired client-side refresher). Those P0s describe **latent defects the migration would
activate**, not regressions in this window; this review concurs with the R2 reviewer that
Phase 1 must not start until they are resolved on paper, and flags for the next window that
any implementation commits against that plan get first-class review here. The
chaos-engineering register's only code change in this window is item 2 above.

---

## Risk rating

| Finding | Severity | Exploitability | Likelihood | Regression risk |
|---|---|---|---|---|
| F1 import skip visibility | LOW | N/A (operator-integrity) | Moderate in ops | New silent-skip class widened |
| F2 race demotion | INFO | Authenticated race only | Very low | Strictly better than baseline |
| F3 slot-based exclusion | INFO | None | N/A | None (documentation) |
| F4 TOML escape gap | INFO | Root-owned file only | Very low | None (fail-safe truncation) |

## Residual risk

- Silent merge-import skips (F1) remain log-only until the response/audit surfacing lands.
- Legacy duplicate-priority states restored via rollback persist by design; `DetectConflicts`
  is the discovery mechanism and the write paths now prevent new ones.
- The R2 migration plan's three P0 design blockers are open by explicit decision (pre-implementation);
  no code in the tree depends on them yet.

## Reviewed and found safe (no finding)

Replace-mode import path; config-version rollback round-trip with duplicate-priority snapshots;
`Add`'s auto-assign (`Priority<=0`) branch (unchanged); lock discipline in both the `Add`
collision branch (already under `ps.mu`) and the enrollment fix (explicit unlock before return);
`p4_test.go`'s move to `ReplaceAll` for degenerate-state injection (test-only, keeps the
conflict detector honest); `enrollment.go:200` token-generation CIDR validation (already
error-checked at baseline — the fix covers the consume side).
