# Security Regression Review — internal/secret containment, maint-agent socket persistence, and the chaos-fix batch (window 7e4e67f → ea0f2ff)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-07
> **Baseline:** `origin/main` @ `7e4e67f` (end of the previous review's window, `docs/security-reviews/2026-07-05-tls-resumption-mitm-leafkey.md`)
> **Head:** `origin/main` @ `ea0f2ff`
> **Scope reviewed:** every code-bearing change merged in the window — 81 files, +4,608 / −1,138 —
> grouped into five clusters: (1) the new `internal/secret` KEK-containment boundary (ADR-0007)
> and the migration of the cluster-CA / DP-node / CDR-client key-at-rest paths onto it, incl. the
> `kek.go` deletion; (2) maintenance-agent socket persistence + installer fixes (sudoers surface);
> (3) the chaos-engineering fix batch (atomic writes, syslog deadline, log rotation, geo-track
> semaphore); (4) threat-feed sync carry-forward, YARA/ClamAV perf rewrites, audit-verb renames,
> config-diff UI rendering; (5) the new appliance-catalog E2E workflow + GitHub Actions bumps.
> Documentation-only commits were read for intent but not treated as attack surface.

---

## Executive Summary

**No CRITICAL, HIGH, or MEDIUM security regressions were found.** The window is a net security
improvement: the KEK boundary is now compiler-enforced with zeroize-on-return and all-verb
redaction, every fixed-`.tmp` persistence path moved to fsync'd atomic writes (closing
power-loss downgrade windows on, among others, the release-catalog monotonic version floor and
the session revocation list), audit-log rotation no longer destroys the just-archived file on
transient reopen failure, and the new sudoers entry for compose-override recreates is a single
fixed-literal line with validator backing.

Six LOW/INFO findings are recorded below. None changes a trust decision, none fails open, and
none warrants blocking a release; each has a small recommended follow-up. The two most worth
scheduling are **F1** (YARA duplicate-string-id semantics changed — a malformed-but-accepted
rule can silently stop matching content it matched at baseline) and **F2** (audit-action verb
renames will silently break downstream SIEM alert rules keyed on the old strings — needs a
release-note migration table).

**Verification:** `go build ./...` clean at HEAD; `go test` green for `internal/secret`,
`internal/threatfeed`, `internal/yara`, `internal/clamav`, `internal/syslog`,
`internal/fileutil`, `internal/session`, `internal/pac`, `internal/scanexcl`, the whole
`cmd/culvert-maint` module, and the package-`main` key-at-rest / release-catalog / client-IP
suites (`-count=1`).

---

## Security Findings

### F1 — LOW · YARA duplicate-string-id semantics flipped last-wins → first-wins

**File:** `internal/yara/yara.go` (~line 884, `parseYARARule`, commit `de31e8a`)
**CWE:** CWE-436 (Interpretation Conflict) · **OWASP:** A04 Insecure Design (detection logic)

- **Regression:** The baseline evaluator built `hit[s.id] = match(...)` per string occurrence,
  so with duplicate ids the **last** definition was effective. The perf rewrite moved dedup to
  parse time and keeps the **first** definition (later dups skipped with a logged warning).
- **Attack scenario:** This lenient engine historically *accepted* duplicate string ids that
  real YARA rejects. A ruleset containing `$s = "benign"` followed by `$s = "malware_marker"`
  with `condition: any of them` detected `malware_marker` at baseline; at HEAD only the first
  `$s` is live, so that payload now passes the scanner. (`all of them` shifts in the opposite,
  over-matching direction.)
- **Preconditions / likelihood:** Requires an existing admin-imported rule file that contains
  duplicate ids — malformed by upstream YARA's standard, so likelihood is low; the skip is
  logged per rule at load.
- **Impact:** Silent detection change on next rule reload for affected rules only.
- **Recommended fix:** On duplicate id, **reject the rule** (fail closed, matching real YARA)
  instead of silently choosing either occurrence; or at minimum surface the warning in the
  admin UI rule-validation response, not only the log.
- **Required tests:** positive (dup-id rule rejected or flagged at `WriteRule` time), negative
  (well-formed rules unaffected), regression (a dup-id rule file present on disk logs+skips
  deterministically), boundary (dup id across sections; 0-string rule with `all of them` stays
  non-matching).

### F2 — LOW · Audit-action verb renames break downstream SIEM alerting keyed on old strings

**Files:** `ui_policy.go`, `ui_authpolicy.go`, `ui_security.go`, `bandwidth.go`,
`nodegroup.go` (commit `4b3ae69`)
**CWE:** CWE-778 (Insufficient Logging — downstream) · **OWASP:** A09 Security Logging &amp; Monitoring Failures

- **Regression:** Audit action strings changed (`policy.delete→policy.remove`,
  `policy.bulk_delete→policy.bulk_remove`, `authpolicy.delete→authpolicy.remove`,
  `nodegroup.delete→nodegroup.remove`, `bandwidth.create→bandwidth.add`,
  `security.yara-delete→security.yara_remove`, `security.yara-reload→security.yara_reload`,
  hyphen→underscore across the security panel actions). Verified **no `auditEvent` call was
  dropped or reordered** — per-file call counts are identical baseline→HEAD and
  `saveConfigVersion` labels moved in lock-step — this is purely a string contract change.
- **Attack scenario:** A SOC rule alerting on `policy.delete` / `security.yara-delete`
  (classic attacker cover actions: deleting the rules that would catch them) silently stops
  firing after upgrade. The events still exist under new names; nothing is lost at the source.
- **Recommended fix:** Ship a release-note migration table (old verb → new verb) and, if the
  syslog/SIEM pipeline supports it, emit a one-time startup log line noting the rename set.
- **Required tests:** a pinned inventory test of the audit-action string set (so future renames
  are a conscious, reviewed act), which would also have made this change reviewable at a glance.

### F3 — LOW · Syslog write deadline can drop SIEM lines a slow-but-alive collector previously received; drop counter not yet observable

**File:** `internal/syslog/syslog.go:128-137,192` (commits `00d064b`/`851555a`/`2e3533b`)
**CWE:** CWE-778 · **OWASP:** A09

- **Regression:** Baseline blocked indefinitely (holding the writer mutex — a proxy-wide stall
  hazard) but eventually **delivered** to a slow collector. HEAD arms a 5-second
  `SetWriteDeadline` per write; a slower drain drops the line and increments an internal
  `drops` counter. The trade (bounded-lossy delivery vs. proxy-wide stall) is deliberate,
  documented in `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-07-05.md`, and net-positive —
  but `Writer.Drops()` is **not wired to Prometheus** (CHAOS-20), so today the telemetry loss
  is operator-invisible.
- **Recommended fix:** Export `culvert_syslog_dropped_total` (and feed staleness, per
  CHAOS-20) so a stalling collector is visible before an incident post-mortem needs the
  missing lines.
- **Required tests:** metric increments when the fake collector stalls &gt; deadline; zero drops
  on a healthy collector; concurrency (drops counted race-free under `-race`).

### F4 — LOW · Maint-agent override-filename validators do not reject `[` / `]` (sudoers fnmatch character class)

**Files:** `cmd/culvert-maint/internal/config/config.go:252`,
`cmd/culvert-maint/internal/runner/runner.go:302`, `packaging/culvert-maint/install.sh`
(metachar case + `reject_unsafe`) — new surface from commit `a2c857a`
**CWE:** CWE-184 (Incomplete Denylist) · **OWASP:** A05 Security Misconfiguration

- **Regression (new surface, not a weakening):** The new two-`-f` sudoers line renders the
  validated `compose_override_file` into `/etc/sudoers.d/culvert-maint`, where sudo matches
  arguments with **fnmatch**. The metacharacter denylist `"\"'|;&amp;$`&lt;&gt;*?(){}"` blocks glob `*`/`?`
  but not `[`/`]`, so a configured `a[ab].yml` would render an entry matching either `aa.yml`
  or `ab.yml`, contradicting the template's "fixed literals — never a wildcard" contract.
- **Preconditions:** the value lives in root-owned `config.toml` (0640 root:culvert-maint);
  an attacker who can write it can already grant themselves more directly. Practical
  exploitability is near-nil — this is contract hygiene, not a live hole.
- **Recommended fix:** add `[` and `]` to all three denylists (config validator, runner
  validator, installer `case` pattern); ideally switch to an allowlist
  (`^[A-Za-z0-9._-]+\.ya?ml$`).
- **Required tests:** malformed-input tests for `[`, `]` at all three validators (agent config
  parse, runner argv build, installer shell function), plus the existing parity test extended
  to pin the shared character set.

### F5 — LOW · Stale "retains no reference" comment / retained zeroized key slice in CDR client config

**File:** `cdr_pool.go:375-377,427-428` vs `cdr.go:178,227-232` (commit `731801e`)
**CWE:** CWE-1116 (Inaccurate Comment) — latent, fail-closed

- The comment claims `NewCDRClient` retains no reference to the key PEM; in fact the client
  stores `cfg` by value and `cfg.ClientKeyPEM` aliases the buffer that `Sealed.WithPlaintext`
  zeroizes on return. Harmless today (the only read happens inside construction while the
  plaintext is live; nothing re-reads it afterwards) and **strictly better than baseline**,
  which kept the live plaintext key for the client's whole lifetime. Any future redial-from-cfg
  code would fail closed with an all-zeros key rather than leak.
- **Recommended fix:** set `clientCfg.ClientKeyPEM = nil` after construction (or correct the
  comment) so the documented invariant is real.
- **Required tests:** a pin that `CDRClient.cfg.ClientKeyPEM` is nil/empty post-construction.

### F6 — LOW (availability direction) · Threat-feed carry-forward retains foreign-source entries indefinitely

**File:** `internal/threatfeed/threatfeed.go:212-262` (commits `0ae8e19`/`851555a`)
**CWE:** CWE-459 (Incomplete Cleanup) — over-blocking, not under-blocking

- Entries whose `Source` is not exactly `urlhaus`/`openphish` (e.g. `cluster-sync` from CP
  snapshots, or legacy source strings in an old on-disk DB) are carried forward on every local
  sync and re-persisted. On a node that stops receiving CP snapshots, CP-removed false
  positives are blocked forever with no age-out. The direction is fail-closed (blocks more,
  never less); the inverse hole — a failed/0-entry fetch wiping the whole threat DB, which
  existed at baseline — is **fixed** by this same change, which is why it ships.
- **Recommended fix (follow-up):** a TTL or last-confirmed timestamp on carried-forward foreign
  entries, aged out after N days without re-confirmation from their source.
- **Required tests:** carry-forward entry expires after TTL; cluster-synced entries survive a
  local sync inside TTL (the existing `sync_carryforward_test.go` pins this half).

---

## Risk Rating

| # | Finding | Severity | Exploitability | Regression? |
|---|---------|----------|----------------|-------------|
| F1 | YARA dup-id first-wins | LOW | Low (requires malformed ruleset already present) | Yes — detection semantics vs baseline |
| F2 | Audit verb renames vs SIEM | LOW | N/A (contract change) | Yes — downstream alerting contract |
| F3 | Syslog 5s deadline drops | LOW | Low (requires stalled-but-alive collector) | Yes — deliberate, documented tradeoff |
| F4 | `[ ]` not in validator denylist | LOW | Near-nil (root-owned input) | New surface, contract gap |
| F5 | Stale zeroization comment | LOW | None (fail-closed latent) | No — improvement with wrong comment |
| F6 | Carry-forward no age-out | LOW | N/A (over-blocking) | Accepted residual of a fail-closed fix |

---

## Regression Analysis — what was reviewed and why it appears safe

### 1. `internal/secret` KEK containment (ADR-0007) — CLEARED
- **Crypto-neutral by construction:** `Seal`/`Open` delegate to the unchanged
  `ca.EncryptBundle`/`ca.DecryptBundle` (AES-256-GCM, PBKDF2-SHA256/600k, fresh salt+nonce per
  call); `git diff` on `ca.go`/`internal/ca` in the window is **empty**. No new envelope format,
  no downgrade acceptance.
- **KEK sourcing is a line-for-line port** of the deleted `kek.go`: 32-byte pin, hex
  validation, 0600 permission gate (rejected, never chmod-"fixed"), env &gt; file precedence,
  race-safe `os.Link` first-generate.
- **Redaction:** value-receiver `Format`/`String`/`GoString` on `Sealed` and `Provider` cover
  all fmt verbs; `json.Marshal` emits `{}`; pinned by `TestSealedRedactsUnderAllVerbs`. (The
  in-window P1 — `59c160b` briefly shipped without a Formatter — was caught and fixed
  in-window by `10d7476` before reaching a release.)
- **Fail-closed preserved:** all three migrated paths (cluster CA `enrollment.go`, DP node,
  CDR client) keep the missing/wrong-KEK = hard error + `auditKeyAtRestUnlockFailed` +
  never-regenerate contract. Zeroize-on-return verified against every consumer for dangling
  references (fresh buffers from `pem.Decode` / parsed keys from `tls.X509KeyPair`).
- **Pre-existing, unchanged (not regressions):** content-driven plaintext fallback
  (`OpenOrPlaintext`) for un-migrated installs; `.plaintext.bak` quarantine file; no KEK-bytes
  zeroization; env KEK visible in `/proc/self/environ`. All byte-identical to baseline design.

### 2. Maintenance agent / sudoers — CLEARED (except F4)
- Exactly **one** new sudoers entry (two-`-f` compose up); no new `env_keep`, no wildcard in
  the template, placeholders rendered from validated values, and the line is deleted entirely
  when no override is configured. Leftover-placeholder guard extended.
- **Socket unchanged:** no diff to socket path, 0660 mode, RuntimeDirectory, or
  `SO_PEERCRED`/`allow_peers` auth. "Persistence" is compose-argument-level only; the proxy
  container keeps its pre-existing read-only mount. No new principal reaches the agent.
- `validatePinnedDigestRef` / `pullAndTagPinned` untouched; the override expands to exactly two
  argv tokens on `compose up` only (pinned by `TestBuildArgv_ComposeOverride`).
- Restart-after-patch (`22de848`) re-validates + atomically re-renders before `systemctl
  restart`; every failure path leaves the old process on the old config.
- `release_dispatch_exec.go` adds only a post-`SUCCEEDED` transport-error classification
  (`agent_unreachable_after_update`); both branches remain terminal-failed — no verification
  logic touched.

### 3. Chaos-fix batch — CLEARED (except F3)
- **`release_catalog_freshness.go` (trust-critical): strictly stronger.** The monotonic
  version-floor write moved to `fileutil.AtomicWrite` (fsync + unique temp), closing the
  power-loss floor-rollback window. Freshness/rollback/fail-closed logic untouched.
- **`internal/session`:** only `SaveRevocations` durability; token validation, TTL, revocation
  matching, and key handling untouched — a torn revocation file can no longer resurrect revoked
  cookies.
- **`proxy.go` geo-track semaphore** bounds only the *dashboard* country counter; the
  fail-closed GeoIP **policy** lookup is a separate call site (`policy.go`) and is untouched.
  No `recover()`, no dispatch reordering.
- **`internal/fileutil/rotating.go`:** rotation/reopen decoupled so a transient reopen failure
  (ENOSPC) no longer deletes the just-archived audit log; `O_APPEND` + stat-seeded size is
  correct in both branches. Durability improvement.
- All other files in the batch are the identical fixed-`.tmp` → `AtomicWrite` migration; no
  error path now skips a save that previously succeeded.

### 4. Threat feed / scanners / UI — CLEARED (except F1, F2, F6)
- **Threat feed cannot block less than baseline:** baseline `Sync` wiped both maps on every
  attempt (a failed fetch destroyed the in-memory *and* on-disk threat DB — the actual
  under-blocking hazard); HEAD strictly retains more, fresh entries win collisions, and the
  0-entry-HTTP-200 wipe hole was closed in-window. `CheckURL` ordering and the
  allowlist-suppresses-domain-ingest-only contract are unchanged.
- **YARA `nocase` correctness:** the lowered buffer is used only for `noCase` literals (the
  only branch that can set it precomputes `literalLower`); regex and case-sensitive literals
  still match original bytes; any/all aggregation equivalent for well-formed rules. Only the
  duplicate-id case changed (F1).
- **ClamAV INSTREAM framing intact:** per-chunk 4-byte BE length + data via `net.Buffers`
  (full drain or error — no short-write corruption), zero-length terminator retained, 64 KiB
  ≤ uint32, deadlines unchanged. Error posture unchanged — the (pre-existing) fail-open on
  scanner error lives in the untouched `internal/secscan` caller and did not move.
- **Config-diff UI rendering (`fmtDiffCell`):** every attacker-influenceable value flows
  through `escHtml` (scalars, list elements, JSON fallback); no DOM-XSS sink added.

### 5. CI / E2E / dependency bumps — CLEARED
- New `appliance-catalog-update-e2e.yml`: top-level `permissions: contents: read`, no
  `pull_request_target`, no secrets, no unpinned asset fetches; the E2E signing key is a
  per-run ephemeral ed25519 pair entering only via the documented operator env into the test
  container — zero writes to any baked trust path; the commits touch no product `.go` files.
- All four GitHub Actions bumps are full-SHA → full-SHA with tag comments, and each pinned SHA
  was verified against the upstream tag via `git ls-remote`.
- The tightened P6 assertion (`503` + `no_catalog`) makes the enforce-mode refusal test
  stronger, not weaker.

---

## Residual Risk

- The pre-existing, unchanged design residuals inventoried above (plaintext-fallback key load
  for un-migrated installs, secscan fail-open on scanner error [CHAOS-10/17], CA-load fail-open
  [CHAOS-06], `Drops()`/feed-staleness metrics gap [CHAOS-20]) remain open and tracked in
  `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-07-05.md`. None moved in this window.
- F1–F6 above are recommended follow-ups; none blocks release. F2 needs a line in the next
  release notes **before** the release ships to avoid silent SIEM alert breakage.

## Verdict

**No security regressions requiring code change in this window.** Two LOW items (F1 YARA
dup-id, F2 SIEM verb migration) should be scheduled as small follow-ups; F3–F6 are hygiene.
