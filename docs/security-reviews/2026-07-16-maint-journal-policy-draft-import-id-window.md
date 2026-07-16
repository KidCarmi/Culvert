# Security Regression Review — maintenance-agent crash-recovery journal + policy drafts + config-import ID addressing (window b0dd056 → d5585d5)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-16
> **Baseline:** `b0dd056` — end of the previous review's window
> (`docs/security-reviews/2026-07-12-decryption-autoexclude-policy-id-window.md`)
> **Head:** `d5585d5` (`origin/main`)
> **Scope reviewed:** every code-bearing change in the window — 51 first-parent
> merges (PRs #696–#757), reviewed as six parallel deep passes plus orchestrator
> spot-checks against the working tree at `d5585d5`.
>
> The window is dominated by: the **Tier-1 RISK-022 maintenance-agent
> crash-recovery journal** (`internal/journal`, `journal_phases`,
> `manifest_digest`, `reconcile_decision`, ops-lifecycle wiring — PRs #748–#757),
> the **policy draft / staged-commit** feature (`policy_draft.go`, +662), the
> **config import upsert-by-ID + dry-run preview** path, the **adaptive
> decryption-exclusion F10 runtime tunables** (`autoexclude_tunables`, surge
> detector, engine `Reconfigure`), the **state-file corruption quarantine**
> (`state_corruption.go`, CHAOS-05/07), **HA `Stop()` latch** race fixes, and the
> **category-group / decryption-profile config-surface** additions.
>
> **A large fraction of this window's diff (native-H2 inspection, the autoexclude
> engine core, GeoIP host→IP cache, policy stable-ID eval) was already reviewed on
> integration branches in the 2026-07-11 and 2026-07-12 reports, now merged to
> main.** This review re-verified those surfaces against the merged tree and
> focuses novel findings on the genuinely-new `b0dd056..d5585d5` delta.

---

## Executive summary

**Verdict: no CRITICAL or HIGH security regressions.** The window is
overwhelmingly net-new resilience hardening (crash-recovery journal, fail-closed
reconcile core, corrupt-state quarantine, HA shutdown-race fixes) plus one
authorization surface (policy drafts) that is correctly fail-closed. The privileged
host boundary — the `culvert-maint` sudoers allowlist, the cosign image-trust gate,
and the socket auth — is byte-identical or strengthened; the destructive
boot-reconciler decision core is a pure function with **no live caller** (the acting
hook remains gated on explicit sign-off).

Five findings are recorded, all operator/admin-gated:

- **F1 — MEDIUM** (integrity / confused-deputy): the config **import** and
  **version-rollback** paths persist a rule's object-reference IDs
  (`DestCategoryGroupID`, `DecryptionProfileID`) **verbatim from the file**, but
  policy evaluation is now **ID-authoritative**. A tampered/hand-authored backup
  can carry a rule that displays one object name while enforcing against a
  different object — silent access widening, invisible in the name-based import
  preview and audit trail. The interactive write path re-derives these IDs
  server-side (`stampObjectRefIDs`); import/rollback do not.
- **F2 — LOW–MEDIUM** (safe-default weakening): merge-mode import now **upserts**
  (overwrites) a live rule that name-collides with a backup rule, where baseline
  skipped-on-duplicate. A merge — historically additive — can now silently
  overwrite/weaken an existing deny rule.
- **F3 — LOW** (info disclosure): the unauthenticated `/ready` endpoint on the
  proxy port now emits `state_file_*` rows whose `Detail` leaks the state-file
  path, parse error, and quarantine path when a state file is corrupt.
- **F4 — LOW** (defense-in-depth reduction): the `culvert-maint` systemd unit
  dropped its seccomp / capability-bounding sandbox options — corrective (those
  options implied `NoNewPrivileges`, which breaks the setuid `sudo` path) but a
  genuine post-compromise kernel-surface widening.
- **F5 — LOW** (defense-in-depth, not reachable): the autoexclude engine
  `Reconfigure`/`New` do not clamp `confirmN` up to the `≥2` floor the way they
  clamp `pinnedTTL`, so the anti-poisoning `confirmN≥2` invariant rests entirely
  on the two outer validation layers (both currently correct).

Two previously-recorded LOWs remain present and **unchanged this window** (noted,
not re-raised): the GeoIP host→IP TTL-cache DNS-rebinding TOCTOU
(`2026-07-12` R4; `geoip.go` untouched here) and the native-H2 ALPN-peek
pre-handshake window lacking a read deadline (`2026-07-11`; `inspect_h2_alpn.go`
untouched here).

---

## Findings

### F1 — [MEDIUM] Config import & rollback trust object-reference IDs verbatim → rule enforces against a different object than its displayed name

- **CWE:** CWE-345 (insufficient verification of data authenticity) / CWE-807
  (reliance on untrusted input in a security decision) — confused-deputy.
- **OWASP:** A08:2021 Software & Data Integrity Failures.
- **Files:**
  - `ui_config.go` `importPolicyRules` (~816) — new upsert-by-ID path this window.
  - `configversion.go` `applyConfigBackup` policy-rule loop (~342).
  - eval side (ID-authoritative): `decryptprofile_resolve.go`
    `resolveDecryptionProfile` (ID-first, name only as fallback);
    `categorygroup.go` / `internal/catgroup` `MatchesCategoryByID`.
  - interactive path that DOES stamp: `ui_policy.go` `stampObjectRefIDs` (1310),
    reached only via `stampRuleMetadataForWrite` in the create/update handlers.

**What changed.** The stable-ID addressing work (prior window) made
`DecryptionProfileID` / `DestCategoryGroupID` the **authoritative** link at eval
time — `resolveDecryptionProfile` returns `GetByID(id)` whenever the ID resolves
and never consults the name. This window rewrote `importPolicyRules` into an
upsert-by-ID/name path (`matchForImport` → `UpdateByID`) that persists each
backup rule's `...ID` fields **verbatim**. Neither `importPolicyRules` nor
`applyConfigBackup` calls `stampObjectRefIDs` (which the interactive handlers use
to discard any client-supplied ID and re-derive it from the submitted name).
`validatePolicyRule` does not check ID↔name consistency.

**Attack scenario.** An admin imports a tampered or hand-authored backup (merge or
replace mode). A rule displays `DecryptionProfile:"strict"` (name) but carries the
ID of a `"skip"` profile; or `DestCategoryGroup:"Malware"` while carrying the ID
of an `"Ads"` group. At evaluation the ID wins: the rule that appears — in the
GUI, the dry-run **import preview**, and the audit log, all of which are
name-based — to enforce strict verification / block malware actually resolves the
other object. A deny/inspect rule silently degrades to allow/skip. The mismatch is
invisible on every name-based surface, defeating the review value of the preview
and the integrity of the audit trail.

- **Preconditions:** `RoleAdmin` import rights (the handler is admin-gated) plus a
  tampered backup file; or a rollback to a snapshot whose IDs no longer match the
  named objects after an out-of-band rename/replace. Internally-generated
  exports/snapshots are self-consistent (they were stamped when written), so a
  clean round-trip is safe — only a tampered/hand-edited file, or a
  rename-then-rollback, bites.
- **Exploitability:** moderate. Not a privilege escalation (an admin can author
  rules directly), but it is a genuine confused-deputy / config-supply-chain
  integrity gap: an admin who imports a backup they believe they reviewed gets
  enforcement that diverges from what every human-readable surface showed them.
- **Impact:** a policy rule whose enforced matching (category / decryption
  behavior) diverges from its displayed identity — potential silent bypass of a
  category-scoped deny or a downgrade from strict TLS verification to skip.
- **Regression risk:** introduced this window. Baseline import was name-based
  (`Add` + `validatePolicyRule` name-uniqueness), with no authoritative ID to
  diverge from.

**Recommended fix (safe implementation).** On **every** rule in
`importPolicyRules` and in `applyConfigBackup`'s rule loop, call
`stampObjectRefIDs(&rule)` to re-derive `DestCategoryGroupID` /
`DecryptionProfileID` from the rule's names server-side — exactly as the
interactive path does — **or** reject (skip + warn) any imported rule whose
`...ID` does not resolve to the object named in the same rule. Prefer re-deriving
from the name, because the name is what the preview and audit display; the ID must
never be the trusted-from-file field for a security decision.

**Required tests.** (1) Import a backup whose rule name says profile A but ID
points at profile B → after import the live rule resolves A (or is skipped),
never B. (2) Same for category groups. (3) Rollback of a snapshot taken before a
profile rename resolves the renamed object by name, not a dangling/misdirected ID.
(4) Clean export→import round-trip is byte-stable (no spurious re-stamp drift).
(5) Negative: a rule whose ID resolves to nothing falls back to the name (existing
fail-safe) rather than failing open.

---

### F2 — [LOW–MEDIUM] Merge-mode import overwrites a name-colliding live rule (was: skip-on-duplicate)

- **CWE:** CWE-436 (interpretation conflict) / safe-default weakening.
- **OWASP:** A08:2021.
- **Files:** `ui_config.go` `importPolicyRules`; `policy.go` `matchForImport`
  (ULID match, then case-insensitive name fallback) → `UpdateByID`.

**What changed.** Baseline merge-import `Add`ed each backup rule and let
`validatePolicyRule`'s name-uniqueness check reject a colliding-name rule (the
live rule was preserved; the import was inert on that rule). This window's
merge-import upserts by identity — match by ULID, then a **case-insensitive name
fallback**, then `UpdateByID`, overwriting the live rule's content.

**Attack scenario.** An admin performs what they believe is an additive merge
import of a partial backup that happens to contain a rule named identically (e.g.
`"Block Malware"`) to a live Deny rule, but with `Action:Allow` or a narrower
match. Baseline: skipped, deny preserved. This window: the live deny is silently
replaced with the weaker rule.

- **Preconditions:** admin import rights + a name collision.
- **Mitigations already present:** the new `?dryRun=true` preview reports the real
  `upsert N: X update, Y add` split, so an attentive admin sees a non-zero update
  count; import stays admin-gated and audited.
- **Regression risk:** introduced this window. Note this is the swing-fix of the
  prior series finding (`2026-07-09` window, F1: merge-mode *silently skipped*
  colliding rules) to the opposite failure mode — it closes the "skipped deny"
  gap but opens an "overwritten deny" one.

**Recommended fix.** If upsert-by-name is intended (invariant #4), surface **which
specific live rules** a merge would overwrite (not just a count) in the preview,
and consider making the name-fallback upsert opt-in (ULID match always upserts;
name-only collision defaults to skip-with-warning unless the operator confirms).

**Required tests.** Merge import of a rule name-colliding with a live deny →
preview lists the exact live rule that would be overwritten; without confirmation
the live deny is preserved.

---

### F3 — [LOW] Unauthenticated `/ready` leaks state-file path + parse error on corruption

- **CWE:** CWE-209 (information exposure through an error message).
- **Files:** `healthcheck.go` `appendStateFileChecks` (88–101); `state_corruption.go`
  `quarantineCorruptStateFile` (`detail` string); wired at `main.go` proxy handler
  (`/ready`, unauthenticated proxy port).

`/ready` is served on the unauthenticated proxy port (any proxied client can hit
it). When a state file (`ui_users.json` / `cluster.json`) is corrupt, the new
`state_file_*` rows expose `Detail` containing the full state-file path, the Go
JSON parse error, and the quarantine path. Only surfaces under an actual corruption
fault; contents are configuration/paths, not secrets or roster data — the endpoint
already discloses `ca` / `clamav` / `policy_loaded` detail strings, so the class is
pre-existing (recorded `2026-07-10` F3), extended here to two more rows.

- **Regression risk:** minor extension of a known, accepted LOW disclosure class.
- **Recommended fix.** On the unauthenticated surface emit a generic status
  (`"state file corrupt — see server logs"`); keep the detailed `Detail` on the
  authenticated `/api/*` health surface only. The full detail already goes to the
  logger and the deferred alert.

---

### F4 — [LOW] `culvert-maint` systemd unit dropped its seccomp / capability sandbox

- **CWE:** CWE-693 (protection-mechanism failure) — defense-in-depth only, **not**
  privilege escalation (the sudoers allowlist, the real boundary, is unchanged).
- **File:** `packaging/systemd/culvert-maint.service`.

The unit removed `PrivateDevices`, `ProtectKernelTunables/Modules/Logs`,
`RestrictNamespaces/Realtime/SUIDSGID`, `LockPersonality`,
`MemoryDenyWriteExecute`, `SystemCallArchitectures=native`, `ProtectClock`,
`ProtectHostname`, and the empty `CapabilityBoundingSet=` clamp. This genuinely
widens the post-compromise kernel surface available to the unprivileged
`culvert-maint` process.

**Why it is corrective, not gratuitous.** For a `User=`-scoped (non-root) service,
that exact option set causes systemd to imply `PR_SET_NO_NEW_PRIVS`; under NNP the
setuid `sudo` escalation the agent depends on fails outright, and an empty
`CapabilityBoundingSet=` leaves setuid-root `sudo` with zero capabilities — the
baseline unit was **non-functional for the production `privilege_mode=sudoers`
path**. The mount-namespace hardening that does **not** imply NNP was kept and in
one case strengthened (`ProtectSystem=full → strict`, plus `ProtectHome`,
`PrivateTmp`, `ProtectControlGroups`, `ProtectProc=invisible`, `ProcSubset=pid`).

- **Recommended fix.** Ship the removed seccomp/cap options as a documented
  lab-only drop-in, and re-add any strictly non-NNP-implying members of the set
  that apply to this workload. Acceptable as-is given the rationale; flagged for
  visibility.

---

### F5 — [LOW] autoexclude engine does not clamp `confirmN` to ≥2 (defense-in-depth; not reachable)

- **CWE:** CWE-1284 (improper validation of a specified quantity).
- **File:** `internal/autoexclude/autoexclude.go` `New` / `Reconfigure`.

`Reconfigure`/`New` defensively clamp `pinnedTTL ≤ ttl` at the engine layer ("last
line of defense if outer validation is bypassed"), but `confirmN` is only floored
to the default when `≤ 0`; a `confirmN = 1` passed directly to `Config` would be
honored and would defeat the distinct-client anti-poisoning guarantee. The engine
comment claims it "guarantees a valid state for ANY caller," which `confirmN` does
not currently satisfy. **Not reachable today:** both real callers
(`admin_settings.go` load, `ui_policy.go` PUT) run `validateAutoExcludeTunables`
(floor 2) before `Reconfigure`, and no code constructs `Config{ConfirmN:1}` (only
`Config{}` and validated `engineConfig()` conversions).

- **Regression risk:** the `Reconfigure` path (F10 runtime tunables) is new this
  window, so the clamp asymmetry is introduced here even though it is not
  exploitable.
- **Recommended fix.** Mirror the `pinnedTTL` treatment:
  `if confirmN < DefaultConfirmN { confirmN = DefaultConfirmN }` inside
  `New`/`Reconfigure`, so the engine self-guarantees the invariant for any future
  caller. Add a unit test pinning that `Config{ConfirmN:1}` resolves to the
  default.

---

## Carried-forward (previously recorded; unchanged this window — not re-raised)

- **GeoIP host→IP TTL-cache DNS-rebinding TOCTOU** — recorded as `2026-07-12` R4
  (LOW). `geoip.go` has **zero changes** this window; `resolveHost` feeds only the
  GeoIP country-attribution facade (lines 176/192), **not** the SSRF guard, so the
  window is bounded to GeoIP-attribution staleness (≤ `hostIPCacheTTL = 5m`), the
  dial uses the transport's own fresh resolution, and unknown still fails closed.
  No change to posture this window.
- **Native-H2 ALPN-peek pre-handshake window has no read deadline** — a bounded
  slow-loris surface (`bufio.Peek` caps at ~4 KiB → fail-closed to `http/1.1`;
  same class as the pre-existing strip-path peek), gated behind the opt-in
  native-H2 rule. `inspect_h2_alpn.go` has **zero changes** this window (landed in
  the `2026-07-11` window). Recommend a short `SetReadDeadline` around the peek +
  both handshakes on both the native and strip paths — carried from the H2 review.

---

## Advisory / INFO (bounded, by-design, or pre-existing — no action required)

- **Upstream `http2.Transport{}` sets no explicit `MaxHeaderListSize` /
  `MaxReadFrameSize`** (`proxy_tunnel_h2.go`). Origin-side memory is transitively
  bounded by the client-facing `MaxConcurrentStreams=32` × scan-buffer ceiling.
  Pinning the upstream caps would mirror the deliberate client-side pinning.
- **Native-H2 per-connection scan-buffer memory = `maxScanBufferBytes × 32`** —
  documented and deliberately capped low; only opt-in native-H2 rules; H1 default
  path unchanged.
- **DP cert renewal replaces `RootCAs` wholesale from `resp.CAPEM`** without
  requiring the rotated CA to chain from the currently-pinned anchor (CWE-295) —
  **pre-existing**, carried over unchanged; exploitable only by an already-CP-
  compromised actor. Optional defense-in-depth.
- **Fail-open `client_cert_required` live-rescue is confirm-count-exempt** for the
  triggering session — the inherent, per-profile opt-in, audited-and-alerted cost
  of fail-open. Cross-client persistent promotion still requires 2 distinct
  tokens. By design, not a defect.

---

## Explicitly verified SAFE / net-new hardening this window

- **Maintenance-agent crash-recovery journal (Tier-1 RISK-022, #748–#757).**
  `internal/journal` validates `op_id` with `ulid.ParseStrict` before it reaches
  any filesystem path (traversal-safe); `List`/`Read` are fail-closed on
  corruption (`ErrCorruptRecord`, no partial list); writes are atomic +
  `fsync(file)` + `fsync(parent)`. The live apply-path write-ahead barrier
  (`restartWithBarrier`, `PhaseRestarting`) aborts **before** the fixed-tag advance
  if the journal can't be written, leaving the safe old-tag state. The
  **`reconcile_decision.go` decision core is a pure, side-effect-free function with
  no non-test caller** — the destructive boot hook (slice E3) is unwired; every
  uncertain branch fails closed (`invalid_record_ref` / `reconcile_exhausted` /
  `no_recovery_target` → loud-stop; `mode=data` → manual, never touches docker).
- **`manifest_digest.go` multi-arch pin is fail-closed** — reads only top-level
  `Descriptor.digest`, selects strictly by host `GOOS/GOARCH`, errors on 0 or >1
  matches; replaced the prior `targetDigests[0]` lexicographic scrape that could
  pin a layer/config blob or the wrong arch.
- **Sudo boundary byte-identical in scope** — the only sudoers change is a
  `--format` quoting portability fix (double-quote → backslash-escaped space); no
  new verb, wildcard, or env-passthrough; the repo-literal + 64-hex digest +
  fixed `culvert/proxy:pinned` retag rules are unchanged. `install.sh` adds
  `sudoers_escape_colon` — net-new injection hardening. The cosign image-trust gate
  (`verify_pinned_image_signature`, anchored `ci.yml` SAN, `--timeout=60s`
  fail-closed) is stricter than baseline; the `CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE`
  break-glass is an install-time admin decision, unreachable by the runtime user.
- **Policy draft / staged-commit (`policy_draft.go`, new)** — commit requires
  `RoleOperator` (same authority as a live write), re-validates the whole candidate
  set per-rule, `baseGenerationStale` fails closed on out-of-band import/rollback,
  `policyVersion` is durable across restart (a stale reloaded draft cannot commit
  over changed running config), and Stage-1 auth rules cannot be created/edited via
  the draft path. Default-deny and first-match determinism intact on the draft
  commit route (`ReplaceAll` keeps its fail-closed `policyRulePersistable` drop).
- **State-file corruption quarantine (`state_corruption.go`, CHAOS-05/07)** —
  corrupt `ui_users.json` / `cluster.json` are renamed aside (same-dir atomic
  `os.Rename`) instead of silently overwritten, protecting the admin roster/TOTP
  and the revoked-DP-cert list from resurrection; read errors (EACCES/EIO)
  deliberately do not quarantine. Strengthens the posture.
- **Autoexclude F10 tunables** — GET viewer / PUT admin; bounds `confirmN∈[2,10]`,
  `maxEntries∈[256,262144]`, cross-field `pinnedTTL≤ttl`; persist-before-apply with
  fail-safe on write error (entries preserved); registered `AdminDurable`-only —
  OFF export/import/rollback/CP→DP. Load path re-validates and keeps engine
  defaults on any invalid persisted value. Learned entries stay volatile.
- **Config-surface walling correct** — `require_commit` is admin-durable-only,
  deliberately off the rollback/cluster surfaces (a rules rollback must not flip
  commit mode); `decryption_profiles` / `category_groups` added to
  export/import/rollback/CP→DP with documented `WireWipeCapable` semantics;
  `config_surfaces_test.go` parity green.
- **Category deletion now reference-checked** (`deleteBlockedByReferences`) — also
  blocks when a policy rule references the category via `DestCategory`, closing a
  prior fail-open ("a Deny rule scoped to it silently stopped blocking").
- **HA `Stop()` latch** joins standby/keepalive goroutines and refuses to promote
  when the context is shutting down (prevents spurious split-brain promotion);
  `SaveUIUsersFile` gains a mutex closing a last-write-wins roster-loss race.
- **Updater removal** (legacy in-binary updater, `-1937`+ lines and the docker-sock
  `updater` sidecar) — clean, no dangling callers, attack-surface reduction; the
  maintenance agent is a stronger replacement (digest-pin + cosign + sudoers
  allowlist vs. the deleted HTTP-URL allowlist).

---

## Risk rating

| # | Finding | Severity | Regression? | Exploit gate |
|---|---|---|---|---|
| F1 | Import/rollback trust object-ref IDs verbatim (ID/name desync) | **MEDIUM** | Yes (this window) | admin import + tampered backup |
| F2 | Merge import overwrites name-colliding live rule | LOW–MEDIUM | Yes (this window) | admin import + name collision |
| F3 | `/ready` leaks state-file path on corruption | LOW | Extends known class | unauth, fault-gated |
| F4 | maint systemd sandbox reduction | LOW | Yes (corrective) | post-compromise foothold |
| F5 | engine `confirmN` not clamped ≥2 | LOW | Yes (not reachable) | not currently reachable |

No CRITICAL/HIGH. The one finding worth scheduling is **F1** (a small, well-scoped
fix: re-stamp object-ref IDs on the import and rollback paths).

---

## Residual risk

After the recorded findings, the residual security risk of this window is **low**.
F1 requires an admin to import a tampered/hand-authored backup — a
config-supply-chain integrity gap rather than a remote or privilege-escalation
vector — and is fully closed by re-deriving object IDs from names on the two
non-interactive write paths. F4 is a bounded, corrective defense-in-depth
reduction on an already-non-root process behind an unchanged sudo allowlist. F5 is
not reachable. The most privileged new surface (the maintenance-agent boot
reconciler) ships its destructive action **unwired**, its decision core proven
pure and fail-closed, awaiting explicit sign-off before it runs `docker` at boot.

## Verification

`go build ./...` clean at `d5585d5`. Targeted suites re-run green during the review:
`internal/autoexclude`, `internal/decryptprofile`, `internal/catgroup`,
`internal/journal`, `cmd/culvert-maint/...`, plus the `package main` policy /
draft / import / config-surface parity tests. This PR adds one documentation
artifact and changes **no product code** (charter: never change security behavior
unless a regression requires it; the F1 fix is recommended for a separate,
reviewed change).
