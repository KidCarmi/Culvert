# ADR-0010: Runtime-tunable auto-exclusion parameters (confirm-count / TTLs / window / cap)

- **Status:** Accepted (2026-07-16) — implemented (F10 PRs #747, #749, #752, #753)
- **Date:** 2026-07-16
- **Deciders:** Engineering Advisor (proposed); project maintainer (ratified — this adds an admin-editable operational control and a persisted setting)

## Context

The adaptive decryption-exclusion cache (`internal/autoexclude`) is governed by five parameters,
today **build-time constants** (`autoexclude.go`):

| Parameter | Constant | Default | Meaning |
|---|---|---|---|
| Confirm-count | `DefaultConfirmN` | `2` | distinct client-evidence tokens required to promote a `(scope,host)` |
| TTL | `DefaultTTL` | `12h` | how long a promoted server-observed exclusion lasts |
| Pinned TTL | `DefaultPinnedTTL` | `1h` | shorter TTL for the spoofable `client_pinned` class |
| Window | `DefaultWindow` | `10m` | rolling window the confirm-count must be met within |
| Max entries | `DefaultMaxEntries` | `4096` | active + pending cap (memory-DoS bound) |

The **engine `Config` is global**: `confirmN`/`ttl`/`pinnedTTL`/`window`/`maxEntries` are single fields
on `Cache`, applied to every scope. `scopeID` keys the active/pending maps for policy isolation, but it
does **not** select tunables — there is no per-scope config path today.

The qualification (`roadmap/AUTOEXCLUDE-PRODUCTION-QUALIFICATION.md`, finding **F10**) flags this as a
**GUI-parity gap** (Supportability 6.5/10): the repo's standing rule is that every operational control
must be adjustable from the admin UI, but these five are frozen at build time — an operator who wants a
stricter confirm-count for a hostile population, or a shorter TTL, must recompile.

**F9a is the hard prerequisite and must land first.** It is proposed in **PR #740** (open, not yet
merged to `main` — this tree still has the plain `var autoExclude = autoexclude.New(...)`). F9a puts the
singleton behind `atomic.Pointer` (`autoExclude()` read / `setAutoExclude()` swap) so the cache can be
reconfigured at runtime without racing the lockless proxy hot path. **This ADR's implementation depends
on that seam and MUST NOT be merged before #740** — otherwise the runtime `Reconfigure` would either not
compile against the plain var or reintroduce the exact race F9a removes.

> **Erratum (accepted, 2026-07 — implementation).** The paragraph above overstates the
> dependency. F9a's `atomic.Pointer` is **not** required to make in-place `Reconfigure`
> race-free: `Reconfigure` mutates the five fields under the cache's own `sync.Mutex`, and
> every hot-path reader (`Contains`/`Observe`/`Remove`) takes that same lock, so the mutex
> alone provides the correctness. F9a's atomic pointer is only needed for the *pointer swap*
> path (`setAutoExclude(New(cfg))`) — a wholesale replacement — not for the in-place apply
> that Option A actually ships. F9a and Option A are therefore **orthogonal**: F9a landed
> first for its own reasons (PR #740) and the F10 series builds on the tree that includes it,
> but the Option-A apply path would be race-free on the plain-var tree too. History is left
> intact above; this note is the correction of record. (Raised by the F10 readiness review.)

## Decision (proposed)

Expose the five parameters as a **single, global, runtime-editable tunable set** — **Option A** — surfaced
through a new admin API + a section in the existing **Decryption Exclusions** panel, persisted for
restart durability, and applied to the live cache through the F9a seam.

**Why global, not per-profile (Option B).** The report's phrase "per-profile fields" is aspirational; the
engine is global and the confirm-count semantics (distinct clients across a `scope+host` within a window)
are naturally a single policy. True per-scope tunables are a materially larger engine change (per-scope
config lookup inside `Observe`/promotion, TTL derivation per entry, subtle multi-profile interactions) for
a control operators rarely need to vary *between* profiles. Option A closes the GUI-parity gap now with a
small, low-risk change; **Option B is recorded as deferred** (below) and Option A does not preclude it —
a future per-profile override can layer on top.

### Apply semantics: in-place reconfigure, preserve learned entries

Changing a tunable must **not** wipe the learned set (that would nuke inspection-coverage state and cause
a coverage blip on every tuning tweak). The engine gains an in-place `Reconfigure(Config)` that updates
the five fields under its existing lock; **already-active exclusions keep their current expiry**, and the
new values apply to **future** promotions/observations. (Contrast with a full `setAutoExclude(New(cfg))`
rebuild, which drops the cache — rejected as the apply path for a routine tuning change; see Alternatives.)
`setAutoExclude` remains for test isolation and any future wholesale swap.

### Persistence & config-surface placement

- The tunable set persists in `admin_settings.json` (restart-durable, `0600`), declared as a new row in
  the `configSurfaces` registry (`config_surfaces.go`) as **admin_settings-durable, OFF export/import and
  OFF version-rollback**. Rationale: these are node-local operational tuning, not policy; and the cache
  they govern is itself volatile and off every config surface. This mirrors how `metrics_token` /
  conn-limit settings are treated (durable, unversioned).
- The **learned entries stay volatile** — unchanged. Only the *parameters* persist.

### Admin surface (GUI-parity)

- `GET /api/decryption-exclusions/tunables` (viewer) → current effective values + the built-in defaults +
  bounds, so the UI can render "current / default / allowed range".
- `PUT /api/decryption-exclusions/tunables` (admin) → validate → persist → `Reconfigure` the live cache →
  `auditEvent`. **No `saveConfigVersion`**: because the tunables are deliberately OFF version-rollback
  (below), snapshotting them would create config-version entries that a rollback cannot actually restore —
  misleading history. This matches the existing off-rollback admin-settings handlers (e.g. the conn-limit
  / upstream-pool durable-but-unversioned settings), which intentionally omit the call. `requireRole`
  admin for write, viewer for read (defense-in-depth alongside C2 metadata).
- A **Tunables** section in the Decryption Exclusions SPA panel: five inputs with the default shown as
  placeholder and inline range hints; a "Reset to defaults" action.

### Validation bounds (fail-safe)

Reject out-of-range input at the API (never let a value disable the guardrails):

| Field | Min | Max | Note |
|---|---|---|---|
| confirmN | 2 | 10 | 1 is rejected — a single-client threshold defeats the anti-poisoning guarantee |
| ttl | 1m | 168h | |
| pinnedTTL | 1m | ttl | pinned TTL ≤ TTL (invariant) |
| window | 10s | 24h | |
| maxEntries | 256 | 262144 | memory-DoS bound stays sane |

A `PUT` is a **full-set replacement**: an omitted or zero field **resets to its default**
(`zero ⇒ default`, `resolveAutoExcludeTunables`); the server validates the merged effective
set. **Reset to defaults** is therefore a `PUT` of `{}`. (A negative value is preserved
through resolution so it fails validation — fail-closed.)

> **Erratum (accepted, implementation).** Two bounds and the PUT semantic were tightened
> from this proposal during implementation, and the table + sentence above reflect what
> shipped (not the original draft): (1) `confirmN` min was raised **1 → 2** (a one-client
> promote defeats anti-poisoning and is not an acceptable production posture); (2) the
> `maxEntries` ceiling was lowered **1048576 → 262144**; (3) the PUT was defined as a
> **full-set replacement with `zero ⇒ default`**, NOT a partial merge — an omitted field
> resets rather than persists. The original draft proposed confirmN-min 1, maxEntries-max
> 1048576, and merge-on-partial-PUT; those are superseded. History is left intact here so
> the change of record is visible.

## Consequences

- **Positive:** closes the F10 GUI-parity gap; operators can tighten the confirm-count / shorten TTLs for
  hostile segments without a rebuild. In-place reconfigure means tuning never blips inspection coverage.
- **Neutral:** no change to the volatile/node-local cache model, scope isolation, the classifier, or the
  ADR-0008/0009 evidence/rescue semantics. Defaults are byte-identical to today when untouched.
- **Cost:** one engine method (`Reconfigure`), a resolver + persistence field, one API endpoint pair, a UI
  section, and a `configSurfaces` registry row + its parity-test wiring.
- **Deferred:** true per-profile overrides (Option B) remain open; this ADR is the global baseline they
  would extend.

## Alternatives considered

1. **Per-profile tunables (Option B).** Add the five fields to `DecryptionProfile` and make the engine
   apply them per-scope. *Deferred, not rejected:* matches the report's literal wording and is the fuller
   feature, but it is a much larger engine change (per-scope config in `Observe`/promotion, per-entry TTL
   derivation, multi-profile interaction surface) + config-surface wiring for a rarely-varied control. Can
   layer on top of Option A later.
2. **Rebuild the cache on every change** (`setAutoExclude(New(cfg))`). *Rejected as the apply path:*
   simplest to wire, but it **drops all learned entries** on a routine tuning change — a surprising
   inspection-coverage blip. In-place `Reconfigure` avoids it. (`setAutoExclude` still exists for tests /
   wholesale swap.)
3. **Env-var only (no UI), matching the CULVERT_* precedent.** *Rejected:* the repo's GUI-parity mandate is
   explicit that operational controls must be adjustable from the web UI; env-only would repeat the F10 gap
   in a new form.
4. **Status quo (build-time constants).** *Rejected:* leaves the documented GUI-parity gap open.

## Invariants (to be enforced by tests when implemented)

1. **Defaults unchanged when untouched.** With no persisted tunables, the cache uses the exact five
   defaults — byte-identical behavior.
2. **Bounds enforced.** Every out-of-range field is rejected with 400; `pinnedTTL ≤ ttl` holds.
3. **In-place reconfigure preserves entries.** `Reconfigure` on a cache with active exclusions keeps them;
   only future promotions see the new confirmN/window.
4. **Persistence round-trips.** A `PUT` survives restart via `admin_settings.json`; the value is OFF
   export/import and OFF rollback (pinned by the `config_surfaces_test.go` parity suite).
5. **Race-free apply.** Reconfigure under concurrent hot-path reads is race-free via the cache's own
   `sync.Mutex` (see Erratum above — the mutex, not F9a's atomic pointer, provides this); verified `-race`.
6. **RBAC + audit.** Read = viewer, write = admin; every write emits an `auditEvent`. NO
   `saveConfigVersion` (consistent with the off-rollback placement — a snapshot rollback can't restore is
   misleading); the `config_surfaces_test.go` parity suite pins the tunables OFF the rollback surface.

## Related

- Qualification finding **F10** (this decision) and **F9a** (prerequisite, PR #740) —
  `roadmap/AUTOEXCLUDE-PRODUCTION-QUALIFICATION.md`.
- Config-surface registry discipline: `config_surfaces.go` / `config_surfaces_test.go` (the row + parity).
- Operator guide `docs/operator/decryption-auto-exclusions.md` (§ Distinct-client evidence) — documents the
  posture as read-only today; to gain a "tuning" subsection when this ships.
- ADR-0008 / ADR-0009 — the same decryption-exclusion security surface; unaffected by this control.
