# Chaos Engineering Review — 2026-10-28

## CHAOS-103 — The second process: two Culvert processes, one `/data`

**Date:** 2026-10-28
**Branch:** `claude/serene-cerf-mkluq9`
**Baseline:** `origin/main` **f31744c** (freshly fetched; `CHAOS-102` is the
highest id anywhere on main, and no open PR held a chaos id at claim time).
**Id allocation:** `CHAOS-103` claimed in a committed placeholder row in
[the register](../../roadmap/CHAOS-ENGINEERING-REVIEW.md) as commit one, before
any code was written, per that file's own convention.
**Method:** evidence-first source review, then an executed fault injection — two
real processes against one data directory on a build of the baseline. Every
behavioural claim below was observed, not inferred; the commands and raw
outcomes are in §9.

---

## 1. Executive summary

Culvert's boot path refuses to start on a data directory left half-restored
(`checkInterruptedRestore`, RISK-005), and its embedded BadgerDB directories are
protected by badger's own directory flock. Nothing covered the rest of the
volume, and nothing covered the *process*: **a second Culvert process opened
against the same `/data` was not detected at all.** Both processes booted, both
served the proxy and the admin UI, both reported `"leader":true,
"write_authority":true` on `/healthz`, and neither logged a single line about
the other.

The register has asked "what happens when the volume is damaged" (§19,
CHAOS-50), "what happens when a store is corrupt" (CHAOS-62, CHAOS-74) and "what
does a listener serve before the posture is installed" (CHAOS-102). It had not
asked **who owns the volume**. The answer was: nobody.

Two consequences, and the second one is not a durability bug.

**The data at rest is last-writer-wins.** Every durable surface on the JSON
state plane is whole-file-replaced through `internal/fileutil`'s
temp-then-rename, and `rename(2)` succeeds regardless of who else holds the
file open. `saveHitCounters` is called *synchronously during boot*
([persistent_admin_state_startup.go:59](../../persistent_admin_state_startup.go)),
so a second process overwrites the live one's counters before it has served a
request; `globalClusterStore.Save()` and the policy-learning flush run from its
**shutdown** hooks ([main_shutdown.go:381,413](../../main_shutdown.go)), so
*stopping* the accidental instance is itself a write of its own stale world onto
the live volume.

**The admin control plane is worse, and it is a security finding.**
`uiAuthMiddleware` injects `RoleAdmin` into every request with no credentials at
all while `cfg.IsConfigured()` is false — the documented, necessary first-run
bootstrap window ([ui_middleware.go:267](../../ui_middleware.go)). That
predicate is **in-memory state read once at boot**
([store.go:1242](../../store.go)). A second process that booted before the
operator ran the wizard therefore holds that window open *for its entire life*.
Observed, end to end:

| step | where | result |
|---|---|---|
| operator completes first-run setup | the real gateway | roster on disk = `[alice]` |
| `GET /api/setup/status` | second process | `needsSetup:true` — still "fresh" |
| `GET /api/auth/users`, no credentials | second process | **200** (the real gateway answers 401) |
| `POST /api/policy`, no credentials | second process | **200** — `Allow` + `SSL Bypass` for `attacker.example` persisted to the live `policy.json`, `modifiedBy:"unknown"` |
| `POST /api/auth/users`, no credentials | second process | **200** — a new admin persisted |
| `POST /api/setup/complete`, no credentials | second process | **200** — roster on disk = `[attacker]`; `alice` erased |
| the real gateway restarts | — | `alice` → **401**; `attacker` → **200, admin**; the attacker's rule is enforced; the default action flipped `allow`→`deny` |

Between the fifth row and the last, the real gateway kept serving `alice` from
memory, so **nothing looked wrong to the operator until a restart they did not
connect to the cause**.

This needs no attacker. A double-start is enough: `compose up` over a stale
manual run, a rolling update whose old and new pods briefly share one
ReadWriteOnce volume on a node, an operator starting "a second instance on
another port, just to test". With local exec it is privilege escalation to
persistent admin of an inline security gateway, and if the second instance's UI
port is reachable (the admin UI binds `:port` and `-ui-allow-ip` defaults to
empty = all), it is reachable without credentials from the network.

**Two fixes shipped**, because the second must hold where the first degrades by
design:

- **`datadir_writer_lock.go` — the second process does not boot.** A
  process-lifetime `flock` on `<dataDir>/.culvert-writer.lock`, taken in main
  immediately after the interrupted-restore refusal. A positively identified
  live holder refuses the boot; **everything else degrades with a notice.**
- **`setup_bootstrap_window.go` — the bootstrap window is decided by the durable
  roster, not by one process's latch.** All five gates that asked
  `!cfg.IsConfigured()` now ask `bootstrapWindowOpen()`, which consults the
  roster file when the in-memory term says "not configured".

**What was already right, and is load-bearing:** the primary proxy listener does
`logFatalf` on a bind failure ([main.go:1294](../../main.go)), which is the only
thing that ever stopped a second process — but it is the *last* statement of
`main`, so every boot-time write had already landed, and it does nothing at all
when the operator gave the second process different ports. The audit log is
honest: both `setup.complete` events appear in `audit.jsonl`, append-only and
uninterleaved. That audit trail was the only evidence this failure left behind,
and nothing alerted on it.

---

## 2. Failure scenarios

### SW-1 — A second process is an unauthenticated admin control plane over the live volume (HIGH) — **FIXED**

- **Current behaviour (pre-fix):** reproduced in full in the table above.
- **Expected:** a process that is not bootstrapping a fresh install grants no
  authority without credentials.
- **Failure mode:** silent privilege escalation plus durable state replacement.
  `cfg.IsConfigured()` is a per-process in-memory predicate
  ([store.go:1242](../../store.go): `c.user != "" || c.provider != nil ||
  c.defaultAuthOutcome == OutcomeExempt || legacyLDAPRetired()`), populated by
  `LoadUIUsersFile` at boot and never re-read. The file's own comment already
  names the stake — *"which the admin middleware treats as unauthenticated
  RoleAdmin for everyone"* — it had simply never been asked what happens when a
  second reader of the same file disagrees.
- **Recovery:** none automatic. The roster replacement is not detectable from
  inside either process, and the operator's own account is gone from disk.
  Manual recovery is the `--reset-password` one-shot or a restore.
- **Fix:** `bootstrapWindowOpen()`
  ([setup_bootstrap_window.go](../../setup_bootstrap_window.go)) at all five
  sites — the middleware grant, `apiAuthLogin`'s `preSetup` bypass,
  `apiAuthStatus`, `apiSetupStatus`'s `needsSetup`, and both of
  `apiSetupComplete`'s checks. The durable term is re-read *inside*
  `setupCompleteMu`, so a roster that became non-empty since this process loaded
  one cannot be replaced by a request that observed the stale latch.

### SW-2 — Nothing detected the second process at all (MEDIUM, and the class) — **FIXED**

- **Current behaviour (pre-fix):** two processes, zero signal. `grep -ci
  'already|another process|in use|second instance|lock'` over both process logs
  returned one incidental line each, neither about the other process.
- **Failure mode:** every surface in §3 is silently last-writer-wins, and the
  operator has no way to learn which process wrote what. `internal/storeguard`
  does see the signal for badger directories and deliberately **degrades** on it
  ("another process holds the store" is on its environmental deny-list) — right
  for a store, and the net effect was that the second process kept booting with
  the rest of the volume unguarded.
- **Fix:** `checkDataDirSingleWriter`
  ([datadir_writer_lock.go](../../datadir_writer_lock.go)), wired in `main`
  immediately after `checkInterruptedRestore`.

### SW-3 — Stopping the accidental instance is itself a write (MEDIUM) — **MITIGATED by SW-2**

`registerLateShutdownHooks` flushes `globalClusterStore.Save()` and the
policy-learning store on a graceful stop ([main_shutdown.go:381,413](../../main_shutdown.go)),
and `saveHitCounters` runs on boot. So the window is not "while both are
running" — the accidental instance writes on the way **in** and on the way
**out**. A controlled run isolated the boot half and found `admin_settings.json`
and `ui_users.json` byte-identical across the second process's boot *and* its
clean shutdown in that configuration (both processes had converged on the same
file contents, so there was nothing to diverge); the write paths are real and
reached, and which fields move depends on which process's in-memory state is
stale, so this is recorded as the reached-and-dangerous surface it is rather
than as a specific measured corruption. Closed by refusing the boot.

### SW-4 — The badger stores were the only protected surface (verified, no change)

Verified rather than assumed: badger flocks its own directories
(`badger/dir_unix.go acquireDirectoryLock`, mirrored by
[internal/storeguard/dirlock_unix.go](../../internal/storeguard/dirlock_unix.go)),
and `storeguard`'s classifier puts "another process holds the store" on the
environmental deny-list so the directory is **never** quarantined out from under
its live owner. That decision is correct and is unchanged here. It is also the
whole reason this finding stayed invisible: the one subsystem that could see a
second process was the one designed not to act on it.

### SW-5 — The proxy bind is the only pre-existing backstop, and it is last (verified, no change)

`runProxyUntilShutdown` is the final statement of `main` and `logFatalf`s on
`ListenAndServe` ([main.go:1294](../../main.go)). Every other listener rebinds
instead: the admin UI retries for the life of the process with a jittered,
interruptible backoff (`serveAdminUIWithRetry`, [ui.go:186](../../ui.go)), as do
SOCKS5 (CHAOS-54/66) and CP gRPC (CHAOS-71). So on identical ports the second
process died — **after** running the entire boot write path — and on different
ports nothing stopped it. The asymmetry is deliberate and stays; it simply
cannot be the single-writer guard.

---

## 3. The write surface a second process reaches

Enumerated from the boot and shutdown paths rather than from a grep, because the
point is *when* the writes happen, not how many there are.

| surface | written by | when |
|---|---|---|
| `hit_counters.json` | `saveHitCounters` | synchronously **on boot** (`persistent_admin_state_startup.go:59`) and on an interval and at shutdown |
| `decryption_profiles.json`, `fileprofiles.json` | seeded defaults | on boot of a volume that lacks them |
| cluster store | `globalClusterStore.Save()` | **shutdown hook** |
| policy-learning store | flush hook | **shutdown hook** |
| `ui_users.json` | any roster mutation, and `apiSetupComplete` | on request (SW-1) |
| `policy.json`, `admin_settings.json`, `config_versions/` | the admin API | on request (SW-1) |
| the process log and the request log | the rotating writers | on rotation — the renamer wins the inode and the other process keeps writing to a file nobody will read |

---

## 4. Risk matrix

| id | likelihood | impact | severity | state |
|---|---|---|---|---|
| SW-1 unauthenticated admin control plane over the live volume | low-moderate (needs a second process; no attacker required) | **critical** — durable policy and roster replacement, operator lockout, persistent admin for an account nobody created | **HIGH** | FIXED |
| SW-2 no detection of a second writer | certain, given a second process | high — every surface in §3 silently last-writer-wins | **MEDIUM** | FIXED |
| SW-3 the accidental instance writes on boot and on stop | certain, given a second process | moderate-high | **MEDIUM** | mitigated by SW-2 |
| SW-4 badger's lock is the only prior protection | — | — | informational | verified |
| SW-5 the proxy bind is the only prior backstop, and it is last | — | — | informational | verified |

---

## 5. Recovery assessment

- **Automatic recovery, pre-fix:** none, for any row. The CP's
  `config_unchanged` sentinel means an unchanged config version is never
  re-applied, so even an enrolled DP node does not re-converge (the same shape
  CHAOS-102 carried as BW-7).
- **Automatic recovery, post-fix:** complete and requires no operator action.
  The `flock` is released by the kernel when its holder dies — SIGKILL, OOM,
  kernel panic and power loss all release it — so there is **no stale lock
  state, no lock file to clean up by hand, and no recovery path to get wrong.**
  Verified: a `SIGKILL`ed gateway's volume booted clean on the next start with
  no refusal and no notice.
- **Manual recovery, post-fix:** the refusal names the remedy (stop the other
  process, or give this one its own `CULVERT_DATA_DIR`) and names the escape
  hatch. A second instance crash-loops until the first exits, which is the
  behaviour every single-writer store an operator already runs has — badger
  itself, etcd, Postgres.

---

## 6. Operational impact

- **The refusal is a posture change and is recorded as one.** A second process
  on one volume now fails to start where it previously started and served. That
  is the intended direction: the brief's *prefer fail closed*, and the
  register's own rule that fail-closed applies when recovery is impossible
  rather than merely hard. Here it is impossible — whichever process writes last
  wins and neither can tell which did.
- **The one deployment this changes:** a rolling update that briefly runs two
  pods on one ReadWriteOnce volume. The new pod now crash-loops until the old
  one exits instead of silently sharing the volume. That is correct, and it is
  also the case in which the silent sharing was most dangerous.
- **`CULVERT_ALLOW_MULTIPLE_WRITERS=1`** overrides the refusal for an operator
  whose storage reports lock state wrongly. It is deliberately an environment
  variable and not a config-file setting: an escape hatch for a false positive
  at 3am is not a supported deployment mode, and making it a persisted setting
  would invite it to become one. It does **not** silence the condition — it
  swaps the refusal for a warning that states what two writers cost, and the
  SW-1 gates still hold (verified in §9).
- **Fail-safe default on the other side:** a volume where the lock file cannot be
  created, or a filesystem that does not implement `flock`, is an *undetermined*
  lock state and boots with a notice. A read-only or permission-denied volume is
  an existing documented degraded mode (CHAOS-05/07) and must not become an
  unbootable gateway. This is `checkInterruptedRestore`'s own doctrine — *"don't
  block boot on a transient FS issue"* — and `storeguard`'s — *"the fail-safe
  default is to leave the disk alone."*

---

## 7. Security impact

SW-1 is the finding. Pre-fix, a second process was an **unauthenticated
RoleAdmin control plane over the live gateway's durable configuration**: policy
(including `Allow` + `SSL Bypass`, i.e. turning inspection off for a chosen
destination), the admin roster, the IdP registry, the config-version series.
Attribution was `actor:"127.0.0.1"` and `modifiedBy:"unknown"` — the audit
record exists but names no principal, because there was none.

The escalation path has two independent entrances and the fix closes both:
`datadir_writer_lock.go` stops the second process existing, and the SW-1 gates
mean a process that *did* start (escape hatch, non-unix build, unobservable lock
state) grants nothing without credentials. An unauthenticated admin grant is not
something to leave resting on one mechanism.

Not changed, deliberately: the first-run bootstrap window itself. It is
necessary — a brand-new install has to be reachable before an admin exists — and
its own hazards are already recorded in `ui_auth.go`. What changed is only
*which state decides whether it is open*.

---

## 8. Data-integrity impact

The §3 surfaces are whole-file replacements, so a divergence is not a torn file
but a *coherent file containing the wrong process's world*. That is the harder
kind to detect: every integrity check passes. `config_versions/` is the sharpest
case — the series is seeded by scanning the directory at boot
(`initConfigVersioning`), so two processes allocate from the same sequence and a
version number stops identifying a configuration. Refusing the second boot is
the only fix that restores the invariant the whole series rests on.

---

## 9. Verification

### Fault injection (executed, baseline f31744c)

Two processes, one `CULVERT_DATA_DIR`, different ports, shared
`-ui-users-file`/`-policy`/`-audit-log`. Pre-fix outcome is the table in §1.
Post-fix, same fixture:

```
### A booted and holds the lock:
-rw------- 1 root root 0 .../data/.culvert-writer.lock
### second process, same /data, different ports:
   exit=1
FATAL: another Culvert process is already using this data directory
(.../data/.culvert-writer.lock). Run one Culvert process per data directory:
stop the other process, or give this one its own volume via CULVERT_DATA_DIR. ...
```

And with the escape hatch set, which is the *degraded-lock* case the SW-1 gates
exist for:

```
DataDir: WARNING — another Culvert process holds the single-writer lock on ...,
but CULVERT_ALLOW_MULTIPLE_WRITERS is set, so this process is starting anyway. ...
   -- B's needsSetup (was true before the fix):  {"needsSetup":false}
   -- unauthenticated GET /api/auth/users on B (was 200):          401
   -- unauthenticated POST /api/policy on B (was 200 + durable write): 401
   -- unauthenticated POST /api/setup/complete on B (was 200):     403
   -- roster on the shared volume:  ['alice']
   -- policy on the shared volume:  []
```

### Regression fixture (executed): the paths the fix must not break

| case | result |
|---|---|
| fresh install **with** a roster file: wizard open → admin API reachable → setup 200 → wizard closed → admin API 401 → login works → survives restart | pass |
| fresh install with **no** roster file configured (in-memory-only roster) | pass |
| open (`unauth`) mode setup, then a restart: `needsSetup:false` from the durable `default_auth_outcome` alone | pass |
| `SIGKILL`ed gateway, immediate restart on the same volume | pass — no refusal, no stale lock, no notice |

### Gates

Ten in `datadir_writer_lock_test.go`, six in `setup_bootstrap_window_test.go`
(one a twelve-case table) and four in `chaos103_second_process_test.go`.

**Pre-fix run** — the durable term removed from `bootstrapWindowOpen`, nothing
else changed:

```
--- FAIL: TestCHAOS103_MiddlewareGrantsNoAuthorityToASecondProcess
--- FAIL: TestCHAOS103_AuthStatusReportsNoSessionInASecondProcess
--- FAIL: TestCHAOS103_LoginMintsNoSessionForAnArbitraryUserInASecondProcess
--- FAIL: TestBootstrapWindow_ClosedByDurableRoster
--- FAIL: TestSetupComplete_RefusesWhenTheDurableRosterIsAlreadySet
--- FAIL: TestSetupStatus_ReportsCompleteFromTheDurableRoster
```

`TestCHAOS103_MiddlewareStillBootstrapsAGenuineFreshInstall` passes in **both**
runs, which is what makes the six above mean "the window closed for the second
process" rather than "the window closed".

### The premise is asserted, not assumed

`chaos103SecondProcess` and `TestBootstrapWindow_ClosedByDurableRoster` both
`t.Fatal` if `cfg.IsConfigured()` is true — if the fixture ever starts loading
the roster, these gates fail loudly instead of passing vacuously.

### The differential oracle, and why it is one-directional

`rosterBytesConfigure` mirrors `loadUIUsersFile`'s acceptance: the envelope form
wins only when it parses **and** carries a non-nil `users` key; a record is
skipped unless its hash decodes as hex; and it configures nothing unless its
effective role, after the same least-privilege clamp the loader applies to a
role this build does not enroll, is admin. `default_auth_outcome` is the second
anchor, because open mode completes setup with no account at all.

`TestBootstrapWindow_AgreesWithTheLoader` asserts the implication in the
**unsafe direction only** —

> `rosterBytesConfigure(bytes)` ⇒ a `Config` that loaded those bytes is `IsConfigured()`

— over twelve roster shapes, against the real loader. Over-claiming would lock
an operator out of a legitimate wizard; under-claiming only leaves a window as
open as it is today, so the test records the conservative direction with
`t.Logf` instead of asserting equality. On the shipped derivation **no case takes
that branch**: the two agree on all twelve. Non-vacuity was checked by breaking
the anchor to accept any record, which turns the viewer-only and
unenrolled-role cases red.

The two quiet mirrors (`envelopeDeclaresExempt`, `effectiveRosterRoleQuiet`)
exist because the real helpers log and increment counters, and this derivation
runs on an admin request: calling them would re-quarantine, double-count the
loader's own report and emit a line per request. The drift risk that creates is
exactly what the oracle holds.

### 9a. The review round: the guard did not arm on a first boot

The first version of the single-writer guard had a hole, found by Codex on
PR #1750 (P2) and reproduced before being accepted:

**On a genuine fresh install whose data root does not exist yet, the lock-file
open returned `ENOENT`, the guard degraded, and the process held nothing for its
whole life — while startup then created the directory, so a second process could
take the lock and boot alongside it.** On a healthy filesystem. Measured with
two real processes against a non-existent `CULVERT_DATA_DIR`: `NO LOCK FILE —
A holds nothing`, then `B alive: YES-BOTH-RUNNING`.

The cause is the guard's own position. It runs before the statement that creates
the root (`initPAC` → `loadPAC`'s `os.MkdirAll(filepath.Dir(cfg.ConfigPath),
0o700)`, [pac_startup.go:23](../../pac_startup.go)), which is exactly where it
has to be to precede the first write — so it had to create the root itself
rather than find it. It now does, with `0o700` to match the statement that
creates it today; `MkdirAll` is a no-op on an existing directory and never
changes its mode, so an operator's `0o750` volume is untouched. A creation that
genuinely fails (read-only volume, no permission, a root that is a file) still
degrades, which is the same fail-safe rule.

**This is the sharper lesson of the round, and it is about the degraded verdict,
not the refusal.** Every case the fail-safe rule was written for — a read-only
volume, a filesystem without `flock` — is a *genuinely* unobservable lock state,
and degrading is right. `ENOENT` on a first boot looks identical at the call
site and is not that case at all: it is a healthy volume the guard simply had
not created yet. A rule of the form *anything I cannot classify, degrade* is
correct only as far as the classifier is; here it silently swallowed the one
condition under which the guard was needed most and reported it in the same
words as a damaged disk. The gate added for it
(`TestDataDirSingleWriter_AcquiresOnAFirstBootWhoseRootDoesNotExistYet`) asserts
the lock is HELD, not merely that nothing refused — a weaker assertion would
have passed against the broken version.

**The fix created an interaction worth pinning.** Acquiring the lock now creates
the data root, and `checkInterruptedRestore` (RISK-005) diagnoses a restore
commit killed mid-rename by precisely that root being ABSENT with a `.bak`
sibling. Running the guard first would create the root, make that refusal a
no-op, and boot the gateway on an empty volume with the operator's real data
stranded in a `.bak` nobody is told about. `main`'s order is already safe —
`checkInterruptedRestore` exits the process before the guard is reached —
verified end to end against the built binary (exit 1 on `interrupted restore
detected`, root still absent afterwards) and pinned by
`TestDataDirSingleWriter_MustNotRunBeforeTheInterruptedRestoreRefusal`, which
asserts both halves so a future reorder of `main` fails a test instead of
destroying the evidence.

### Full-module and lint

Recorded in the PR description for the exact SHA. A passing local run is not a
passing hosted gate.

---

## 10. Residual risk

- **Non-unix builds and filesystems without `flock`** get no single-writer
  verdict, by design. Culvert ships linux/amd64 and linux/arm64; the stub keeps
  a cross-platform vet/build honest. In that state SW-1 is still closed (the
  gates are independent of the lock) but §3's surfaces are not.
- **`flock` is per-inode, so a bind mount of the same directory under two paths
  is caught, and two different directories backing one logical store are not.**
  A second process pointed at a *copy* of the volume is a different failure (two
  divergent gateways) and is out of scope here.
- **`--restore` and the other one-shot commands run BEFORE the guard**, so they
  are not covered: the lock is taken after `handleOneShotCommands` precisely so
  `--list`, `--restore` and `--cleanup-restore-leftovers` keep working on an
  orphaned state directory. A `--restore` aimed at a volume a live gateway owns
  is therefore still unguarded, and it is the most destructive write path in the
  tree. Carried as **SW-6** below rather than fixed, because covering it means
  deciding per one-shot whether a live holder should refuse it, and `--list` must
  not.
- **An IdP-only install.** `IsConfigured()` also counts `c.provider != nil` and
  `legacyLDAPRetired()`. Both are derived from inputs *both* processes read
  identically (config/YAML, a durable retirement sentinel), so neither can
  diverge under a running process the way the roster can — and setup itself can
  only ever be completed through the roster envelope (a user, or `Exempt`), which
  is what the durable anchor reads. An IdP added *after* setup sits on top of an
  already-configured install. So the anchor's narrower terms are sufficient for
  the window, but they are narrower, and that is recorded rather than claimed
  equivalent.
- **One `openat` per request on an unconfigured install.** `bootstrapWindowOpen`
  asks `cfg.IsConfigured()` FIRST, so a configured node does no I/O at all and
  the latch keeps it that way once a durable setup has been observed. While an
  install is genuinely unconfigured, the two public endpoints that read the
  predicate (`/api/auth/status`, `/api/setup/status`) each perform one
  `os.ReadFile` that returns ENOENT. That is cheaper than the HTTP handling
  around it and `/api/setup/complete` is separately rate-limited, so it is not an
  amplification vector — but it is a syscall an unauthenticated caller can drive
  on a first-run node, and it is recorded rather than dismissed.
- **The audit trail remains the only evidence of a pre-fix occurrence.** Two
  `setup.complete` events with different objects, or a `policy.add` with
  `modifiedBy:"unknown"`, are what an operator should look for on a volume that
  may have had two writers. Nothing alerts on either; see SW-7.

---

## 11. Reported, not fixed

- **SW-6 — the one-shot commands are not covered by the single-writer guard.**
  `--restore` replaces the data directory wholesale and runs before the lock is
  taken, so it will still overwrite a volume a live gateway owns. Not fixed
  because the right behaviour differs per one-shot (`--list` must work on any
  volume; `--restore` should probably refuse) and because that is a separate
  decision about the restore plane's ownership rather than part of closing this
  race. **Owner decision.**
- **SW-7 — a second writer fires no alert and records no `/readyz` row.** The
  refusal is loud on stderr and exits non-zero, which an orchestrator sees; the
  *degraded* verdicts are a process-log line only. The established pattern for
  this class is a named log line **plus** an alert **plus** a `/readyz` fail row
  (as `state_file_corrupt` has), and the degraded paths have only the first. Not
  fixed here because the guard runs before the alert plane and `/readyz` exist —
  wiring it would mean carrying the verdict forward into the observability slice,
  which is a change to that slice rather than to this race. **Registered.**
- **BW-6 and BW-7**, carried forward unchanged from
  [the 2026-10-27 sweep](CHAOS-ENGINEERING-REVIEW-2026-10-27.md) §11. BW-6 (a
  corrupt `admin_settings.json` leaves the admission posture at its compiled
  default for the life of the process) is adjacent to this sweep — both are
  "in-memory state decided once at boot, from a file that may say otherwise" —
  but it is a posture decision with a real cost and is not a race. **Owner
  decision.**
- **Feed clients still dial without `ssrf.SafeDialContext`**, and **the open
  half of CHAOS-18**, carried forward. Neither is in scope here.
