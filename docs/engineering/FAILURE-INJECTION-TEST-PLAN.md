# Culvert Failure-Injection Test Plan

> **Owner:** Overnight Failure-Mode Audit · **Status:** Design (tests not yet implemented) · **Date:** 2026-07-11 · **Tree:** `7c64699`
> **Companion:** `PRODUCTION-FAILURE-MODE-AUDIT.md` (findings F-01…F-30).
>
> Deterministic tests for the highest-value failure scenarios. **Design-first:** this plan specifies
> tests, not code. It prefers isolated integration/unit tests with fault-injection seams,
> `t.TempDir()`, fake dependencies, and malformed fixtures over Compose-based tests; Compose recovery
> tests are proposed only where unit/integration scope is genuinely insufficient.
>
> **Reuse the in-tree patterns:** `restore_interrupted_test.go` (boot-guard fixtures),
> `internal/fileutil/rotating_test.go` (disk-full reopen simulation), `controlplane_version_persist_test.go`
> (restart/clock seams), `socks5_connlimit_test.go` (limiter enforcement), `inline_rollback_test.go`
> (stage-parity + fault stages via `SetExecHooksForTest`), `sync_carryforward_test.go` (dependency-failure
> carry-forward). New tests should extend these, not reinvent harnesses.

---

## How to read each entry

- **Target invariant** — the property the test locks in.
- **Failure injected** — the fault.
- **Expected result** — the correct behavior (post-fix, if a fix is pending).
- **Current expected result (code today)** — what the test would observe against HEAD *now* (so the
  test can be written RED against current behavior, or GREEN if the behavior already holds).
- **Level / Harness / Runtime / CI lane / Flakiness** — implementation guidance.

CI lanes per `CLAUDE.md`: **Fast PR Gate** (Lane A, required, `-race`), **Deep PR Gate** (Lane B,
diff-triggered), **nightly/e2e** (`install-lifecycle-e2e.yml`, `proxy-nightly-e2e.yml`).

---

## Tier 1 — highest value (write these first)

### T1 — Fresh-boot default posture is not silently open (F-01)
- **Target invariant:** with no policy rules and no `default_action`, the runtime is either default-deny
  OR the open posture is surfaced as a degraded readiness state + alert (never advisory-log-only).
- **Failure injected:** none — assert the *default* posture. Construct startup with empty policy + empty
  `default_action`; read `defaultPolicyAction()` and `/ready`.
- **Expected result (post-P0-1):** `/ready` reports a `security_posture` degraded row and/or a
  `security_posture_open` alert fires; the open state is machine-detectable.
- **Current expected result:** `defaultPolicyAction()=="allow"` (`rewrite_default_action_startup.go:24`),
  `AuthEnabled()==false`, `/ready` returns 200 with **no** posture row — the test is **RED** today and
  documents the gap.
- **Level:** unit (package `main`). **Harness:** call `loadRewriteAndDefaultAction(cfg,0)` +
  `handleReady` via `httptest`. **Runtime:** <1s. **Lane:** Fast. **Flakiness:** none.

### T2 — Corrupt crown-jewel store quarantines, never overwrites (F-03/F-04)
- **Target invariant:** a present-but-corrupt `ui_users.json` / `cluster.json` is renamed to
  `.corrupt.<ts>` and the boot refuses (or fails closed to a locked admin) — the corrupt file is never
  overwritten with empty state, and revoked certs never revalidate.
- **Failure injected:** write malformed JSON to `ui_users.json` and `cluster.json` in `t.TempDir()`,
  then run the load path.
- **Expected result (post-P0-3):** load returns a fatal/quarantine outcome; original bytes preserved
  under `.corrupt.<ts>`; for `cluster.json`, `IsRevoked(previouslyRevokedCert)` stays true.
- **Current expected result:** load logs + returns empty; a subsequent save overwrites; `IsRevoked`
  returns false — **RED** today (this is exactly the CHAOS-05/07 gap). Write the test RED to pin the
  intended fix.
- **Level:** unit/integration. **Harness:** `t.TempDir()` + direct `LoadUIUsersFile`/`ClusterStore.Load`;
  the pattern mirrors `coldstart_uiusers_test.go` + `coldstart_clusterstore_test.go` but adds the
  corrupt-input case they omit. **Runtime:** <1s. **Lane:** Fast. **Flakiness:** none.

### T3 — Maintenance agent reconciles after death mid-apply (F-05)
- **Target invariant:** after an apply is interrupted (process killed between retag and health-gate),
  a restarted agent detects the in-flight op, reconciles Docker state (running digest vs journal), and
  either resumes or rolls back — it does not leave an unknown partial state.
- **Failure injected:** run `buildUpgradeApplyStages` with `SetExecHooksForTest` faking a "process gone"
  after `tagAndUp`; construct a fresh `ops.Manager` (simulating restart) and call `MarkAllInterrupted()`.
- **Expected result (post-P0-2):** `MarkAllInterrupted()` returns 1 and drives a reconcile that either
  repins the prior digest or completes; the op is queryable post-restart.
- **Current expected result:** `MarkAllInterrupted()` returns 0 (`ops.go:468`); no journal exists; the
  op is gone — **RED**, pins the gap.
- **Level:** integration (`cmd/culvert-maint`). **Harness:** existing `SetExecHooksForTest` +
  `OpenOpLog` + a new journal fixture. **Runtime:** ~2s. **Lane:** Deep (agent-surface path-gated).
  **Flakiness:** low (deterministic fakes; avoid real Docker).

### T4 — Config rollback surfaces partial-disk failure (F-12)
- **Target invariant:** if any store `Save()` fails during `applyConfigBackup`, the rollback API
  returns a partial-apply error/warning (not 200) and fires an alert.
- **Failure injected:** inject a `Save()` that returns `ErrDiskFull` for one store (swap a package-var
  saver seam, or point the data dir at a read-only `t.TempDir()`).
- **Expected result (post-P1-2):** `applyConfigBackup` returns a non-nil error naming the failed store;
  handler responds 5xx/partial; alert emitted.
- **Status: GREEN as of 2026-07-31** (`configversion_rollback_durability_test.go`, CHAOS-45 run).
  `applyConfigBackup` returns an error naming the failing file; the handler answers `500` with
  `status:"rolled_back_not_durable"`, `applied:true`, `durable:false`, `persist_errors`; the
  `storage_write_failed` alert fires through the shared observer. The in-memory apply stays
  unconditional by design (a half-applied running config is worse than a fully-applied
  non-durable one) — `TestApplyConfigBackup_ReportsPersistenceFailure` pins both halves.
- **Level:** unit (package `main`). **Harness:** a target inside a **missing parent directory**
  forces a real `AtomicWrite` ENOENT. Note the original plan's RO-`t.TempDir()` injection does
  **not** work in this repo's CI: containers run as root and root bypasses mode bits, so the
  missing-directory form is the only uid-independent injection. **Runtime:** <1s.
  **Lane:** Fast. **Flakiness:** none.

### T5 — `/ready` degrades on CP-poll failure + cert expiry (F-08)
- **Target invariant:** `handleReady` returns 503 (or a strict variant) when `dpControlPlanePollFailing`
  is set for a sustained window OR the node cert is within the expiry threshold.
- **Failure injected:** set `dpControlPlanePollFailing` and a near-expiry cert fixture; call `handleReady`.
- **Expected result (post-P1-1):** `/ready` 503 with `cp_poll`/`node_cert` fail rows.
- **Current expected result:** `/ready` 200 (neither is a gate) — **RED** (CHAOS-09).
- **Level:** unit. **Harness:** `httptest` + the existing `configSnapshotValidatorOK` seam pattern (add
  a `dpControlPlanePollFailing` seam). **Runtime:** <1s. **Lane:** Fast. **Flakiness:** none.

### T6 — DP cert hot-reload after renewal (F-25)
- **Target invariant:** after `renewDPCert` writes a new cert, the live gRPC client presents the new
  cert without a process restart.
- **Failure injected:** drive a renewal against a fake CP; then force a reconnect and assert the
  presented cert is the renewed one.
- **Expected result (post-P1-1):** the client re-dials/hot-swaps TLS; new cert presented.
- **Current expected result:** old cert presented until `failover()`/restart — **RED** (CHAOS-12).
- **Level:** integration. **Harness:** in-process fake CP gRPC + a `connect()` observation seam (extend
  the `callForTest` hook at `controlplane_client.go:34`). **Runtime:** ~2s. **Lane:** Deep. **Flakiness:**
  low (loopback gRPC; use `resyncCtx(t)`-style cleanup to avoid the RISK-018 goroutine-leak class).

---

## Tier 2 — high value

### T7 — Read-only `/data` is a loud degraded state, not silent (F-19)
- **Target invariant:** an RO data dir at boot produces a fail-closed startup gate or a degraded
  readiness state — not a "successful" boot with silently-failing runtime saves.
- **Failure injected:** `chmod 0500` a `t.TempDir()` data dir (or bind an RO tmpfs) and boot.
- **Expected result (post-P1-3):** `probeStorageWritability` failure gates readiness/boot.
- **Current expected result:** boots "ok"; probe stores `storageStateUnwritable` (advisory) — **RED**
  for the gating property (the probe itself is GREEN, `diagnostics_test.go:483`).
- **Level:** integration. **Harness:** `t.TempDir()` + `os.Chmod`; skip on Windows/root (root bypasses
  mode bits — run in the container CI where the test user is non-root). **Runtime:** <1s. **Lane:** Deep.
  **Flakiness:** medium (root-bypass — guard with a writability self-check + `t.Skip`).

### T8 — Lost/unmounted volume does not silent-fresh-start (F-24)
- **Target invariant:** if a mount-present sentinel indicates prior state but `ui_users.json` and
  `cluster.json` are both absent, boot refuses to silently start fresh.
- **Failure injected:** create a data dir with a `.initialized` sentinel but no store files.
- **Expected result (post-P1-3):** boot refuses with an actionable "expected state missing — is the
  volume mounted?" message.
- **Current expected result:** treated as first boot (empty roster + legacy admin) — **RED**.
- **Level:** unit. **Harness:** `t.TempDir()` fixtures. **Runtime:** <1s. **Lane:** Fast. **Flakiness:** none.

### T9 — Restore refuses/warns on version skew + missing required files (F-18)
- **Target invariant:** restore (a) warns/refuses on a `culvert_version` downgrade, (b) rejects a
  backup missing required Tier-1 artifacts before a full-restore overwrite.
- **Failure injected:** a valid-schema backup with a lower `culvert_version`; a second backup whose
  manifest has zero Tier-1 files.
- **Expected result (post-P1-4):** dry-run flags the skew; full-restore of a Tier-1-empty backup is
  refused.
- **Current expected result:** version skew printed-not-flagged; Tier-1-empty passes validation —
  **RED** (extends `restore_test.go:190` schema-gate coverage).
- **Level:** unit. **Harness:** synthesize manifests (reuse `backup_test.go` builders). **Runtime:** <1s.
  **Lane:** Fast. **Flakiness:** none.

### T10 — Scan-error posture is uniform and counted (F-10)
- **Target invariant:** a ClamAV error and a plain-HTTP body-read error follow the configured
  `scan.on_error` posture (default block), and increment `culvert_scan_errors_total`.
- **Failure injected:** a fake ClamAV client returning an error mid-stream; a body reader returning an
  error mid-read.
- **Expected result (post-P1-5):** with `on_error=block`, both paths block; counter increments.
- **Current expected result (updated 2026-07-26):** plain-HTTP read error now fails **closed** (502)
  and ClamAV errors are counted (`culvert_clam_scan_errors_total`) + alerted (`scan_clam_error`) with
  no clean-verdict caching — shipped with `clam_error_test.go` + `proxy_http_scanfail_test.go`.
  Remaining RED sliver: the `scan.on_error=block` posture for the ClamAV-error path itself.
- **Level:** unit. **Harness:** `internal/secscan` fake clam + `proxy_http`/`proxy_tunnel` `httptest`.
  **Runtime:** <1s. **Lane:** Fast. **Flakiness:** none.

### T11 — Upstream pool fail-mode is selectable + alerted (F-09)
- **Target invariant:** with `fail_mode=closed`, an empty pool blocks egress (not direct); the
  pool-empty transition emits an alert/metric; the circuit breaker trips on real request failures.
- **Failure injected:** mark all upstreams unhealthy; issue a request; also drive real request failures
  through the transport.
- **Expected result (post-P1-5):** `fail_mode=closed` → request refused; breaker opens via
  `RecordFailure` on the transport path; pool-empty alert fires.
- **Current expected result:** `Next()` nil → direct (`upstream.go:296`); breaker never trips (dead
  code); no alert — **RED** (CHAOS-11/22/23).
- **Level:** unit/integration. **Harness:** `internal/upstream` + a fake transport. **Runtime:** <1s.
  **Lane:** Fast. **Flakiness:** none.

### T12 — Auth IdP-outage does not amplify (F-11)
- **Target invariant:** LDAP/OIDC error-path negatives are **not** cached (only genuine wrong-password
  denials); post-dial LDAP ops are deadline-bounded.
- **Failure injected:** a fake IdP that errors (dial/bind/introspect) then recovers; assert a valid
  credential succeeds immediately on recovery (no 5m/2m denial tail).
- **Expected result (post-fix):** error negatives not cached; recovery is immediate.
- **Current expected result:** error negatives cached 5m LDAP / 2m OIDC → valid creds denied post-recovery
  — **RED** (CHAOS-16).
- **Level:** unit. **Harness:** existing `auth_ldap_test.go`/`auth_oidc_test.go` fakes + a clock/TTL seam.
  **Runtime:** <1s (inject TTL). **Lane:** Fast. **Flakiness:** none (do not use real sleeps — inject TTL).

---

## Tier 3 — durability / fault-injection depth (extend existing patterns)

### T13 — Kill-9 mid-write leaves no torn crown-jewel file (F-26)
- **Target invariant:** a process killed during a store write never publishes a torn file; the target
  is either the old or the new complete version.
- **Failure injected:** a subprocess that writes via `AtomicWrite` and is `SIGKILL`ed at a randomized
  point (the one scenario the audit could not statically confirm end-to-end).
- **Expected result:** target file always parses; at most the last unsynced mutation is lost; orphan
  `.tmp.*` may remain (hygiene).
- **Current expected result:** **GREEN** expected (validates the atomic-write claim) — this is a
  *confirmation* test, not a gap test.
- **Level:** integration (subprocess). **Harness:** `os/exec` a small writer built from the tree +
  `syscall.Kill`; loop N randomized kill points. **Runtime:** ~5-10s. **Lane:** Deep or nightly.
  **Flakiness:** medium (timing) — mitigate by asserting only the invariant (parses / old-or-new), not a
  specific outcome per kill point.

### T14 — ENOSPC during store write preserves old data (F-19 sibling)
- **Target invariant:** a write that hits ENOSPC returns an error and leaves the prior file intact.
- **Failure injected:** a small tmpfs (`mount -t tmpfs -o size=1m`) filled to capacity, or a seam that
  makes `f.Write` return ENOSPC.
- **Expected result:** **GREEN** — `AtomicWrite` removes the temp, returns error, target untouched.
- **Level:** integration. **Harness:** extend the `rotating_test.go` disk-full pattern to the generic
  `AtomicWrite`. **Runtime:** <2s. **Lane:** Deep. **Flakiness:** low (tmpfs requires privileges — gate).

### T15 — ENOSPC preflight before upgrade pull (F-20)
- **Target invariant:** the apply path checks free space before `docker pull` and refuses with a clear
  reason when insufficient.
- **Failure injected:** a fake `Statfs`/space probe returning "insufficient."
- **Expected result (post-P2-1):** apply refuses with `ReasonInsufficientDisk` before any pull.
- **Current expected result:** no preflight → opaque `ReasonCommandError` at pull time — **RED**.
- **Level:** unit (`cmd/culvert-maint`). **Harness:** inject a space-probe seam. **Runtime:** <1s.
  **Lane:** Deep. **Flakiness:** none.

### T16 — Shutdown bounded under a wedged RPC (F-15)
- **Target invariant:** SIGTERM completes within the shutdown budget even with an in-flight gRPC stream;
  a second SIGTERM forces immediate exit.
- **Failure injected:** a fake DP stream that never returns during `GracefulStop`.
- **Expected result (post-P2-3):** shutdown races `GracefulStop` vs a timer → `Stop()`; process exits
  within budget; second signal short-circuits.
- **Current expected result:** early phase unbudgeted → hangs; second signal ignored — **RED** (CHAOS-25/36).
- **Level:** integration. **Harness:** in-process CP gRPC + a wedged handler; assert bounded exit via a
  timeout-guarded goroutine. **Runtime:** ~2s. **Lane:** Deep. **Flakiness:** medium (timing — use a
  generous budget and assert "≤ budget", not an exact value).

---

## Tier 4 — Compose-based recovery tests (only where unit scope is insufficient)

These require the real stack; put them in `install-lifecycle-e2e.yml` / a nightly lane, not the PR gate.

### T17 — Host-reboot state survival + crash-loop visibility (F-23)
- **Target invariant:** after `docker compose down/up`, state survives (named volumes); a fatal config
  error produces an observable crash loop that the installer `--wait` catches.
- **Failure injected:** inject a malformed `policy.json` into the volume, `up -d`, observe restart loop.
- **Expected result:** container restarts repeatedly; `docker compose ps` shows `restarting`; installer
  `--wait` fails fast (`install.sh:1139`).
- **Current expected result:** **GREEN** for the mechanism; documents that there is **no in-product
  crash-loop alert** (F-23) — the assertion is "external monitoring is required."
- **Level:** e2e/Compose. **Harness:** `install-lifecycle-e2e.yml` (extend). **Runtime:** minutes.
  **Lane:** nightly. **Flakiness:** medium (Docker timing).

### T18 — Full restore round-trip across a version boundary (F-18)
- **Target invariant:** backup on version X, restore-dry-run on version Y flags the skew; a same-version
  round-trip restores byte-faithfully.
- **Failure injected:** two image tags; backup on one, restore on the other.
- **Expected result (post-P1-4):** cross-version dry-run warns; same-version commits cleanly.
- **Level:** e2e/Compose (`cli` profile). **Runtime:** minutes. **Lane:** nightly. **Flakiness:** low.

---

## Coverage map (test → finding → backlog)

| Test | Finding | Backlog | Lane | Today |
|---|---|---|---|---|
| T1 | F-01 | P0-1 | Fast | RED |
| T2 | F-03/04 | P0-3 | Fast | RED |
| T3 | F-05 | P0-2 | Deep | RED |
| T4 | F-12 | P1-2 | Fast | **GREEN** (2026-07-31) |
| T5 | F-08 | P1-1 | Fast | RED |
| T6 | F-25 | P1-1 | Deep | RED |
| T7 | F-19 | P1-3 | Deep | RED |
| T8 | F-24 | P1-3 | Fast | RED |
| T9 | F-18 | P1-4 | Fast | RED |
| T10 | F-10 | P1-5 | Fast | RED |
| T11 | F-09 | P1-5 | Fast | RED |
| T12 | F-11 | (P1-adjacent) | Fast | RED |
| T13 | F-26 | (confirm) | Deep/nightly | GREEN-expected |
| T14 | F-19 | (confirm) | Deep | GREEN-expected |
| T15 | F-20 | P2-1 | Deep | RED |
| T16 | F-15 | P2-3 | Deep | RED |
| T17 | F-23 | (doc) | nightly | GREEN-mechanism |
| T18 | F-18 | P1-4 | nightly | RED |

**Sequencing recommendation:** land T1/T2/T4/T5/T8/T9/T10/T11 first — they are all Fast-lane, <1s, no
flakiness, and each pins a P0/P1 gap RED so the fix has an acceptance test waiting. T3/T6/T7/T16 (Deep)
follow with the agent/gRPC/RO-fs harnesses. T13/T14/T17 are confirmation/nightly. Writing the RED tests
before the fixes turns every backlog item into a test-driven change.
