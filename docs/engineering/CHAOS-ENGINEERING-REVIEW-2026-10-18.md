# Chaos engineering review — 2026-10-18

Base: `dec66e1` (merged `main`). Branch: `claude/serene-cerf-luo96z`.
Ids claimed: **CHAOS-71** (support durable-write chokepoint) and **CHAOS-72**
(DP→CP backoff double-count), per the id-claiming convention in
[the register](../../roadmap/CHAOS-ENGINEERING-REVIEW.md). 67/68 are recorded
there as allocated to other open sweeps; 70 was the highest merged.

Scope of this sweep: durable persistence, background-worker retry/backoff,
startup ordering and fail-closed posture. Every claim below was verified by
reading the source at this revision; items marked **REPORTED (verified)** are
real but deliberately **not** fixed here, with the reason given.

---

## Executive summary

Culvert's resilience architecture is, on the evidence, strong: feed scheduling,
listener accept loops, CA recovery, HA lease recovery, shutdown hook watchdogs
and DP last-known-good config all have bounded, cancellable, panic-contained
loops with chaos tests pinning their shapes. Section "Correctly handled" lists
the specific code paths.

Two defects were found where an **existing, correct, documented contract had
unenforced call sites** — the most dangerous shape of resilience bug, because
the architecture reads as safe:

1. **CHAOS-71 — six support-domain durable writes bypassed the
   `fileutil.AtomicWrite` chokepoint.** They were hand-rolled
   `os.WriteFile(tmp)` + `os.Rename`: atomic for a *reader*, but **not fsynced**
   and — critically — **invisible to the storage-health plane**. On a full or
   read-only volume these writes failed silently while `storageDegraded()`, the
   `storage_write_failed` alert, the degraded operator-contract row and the
   Prometheus series all kept reporting healthy. This is the same defect class
   `audit_writefail_test.go` already pins for the audit JSONL (register ST-8),
   and the support domain's own sibling (`support_telemetry_config.go:198`)
   already used the chokepoint. **Fixed + tested.**

2. **CHAOS-72 — the DP→CP retry charged every failure twice.** `backoff()`
   incremented `failCount`, which `pollConfig`'s error path had already
   incremented. The documented schedule (`2s, 4s, 8s … 60s`) actually ran
   `4s, 16s, 60s`, hitting the ceiling on the 3rd failure instead of the 6th;
   and the `failCount < 3` guard let **failover fire on the 2nd** consecutive
   failure, contradicting its own "only after 3 consecutive failures" comment.
   A ~10s CP blip during a rolling upgrade moved an entire data-plane fleet off
   a healthy leader. No test pinned either the schedule or the threshold.
   **Fixed + tested.**

Three further verified findings are reported for owner decision rather than
fixed, because each touches startup/lifecycle ownership or a deployment-visible
posture where AGENTS.md reserves the call to the owner.

---

## Failure scenarios

### CHAOS-71 — support durable-write chokepoint bypass (FIXED)

| | |
|---|---|
| **Fault injected** | Disk full / read-only filesystem / power loss / kernel panic |
| **Sites** | `support_upload.go:86`, `support_recipients.go:87`, `support_debug_level.go:137`, `support_upload_queue.go:123`, `support_upload_wire.go:234`, `ui_support.go:614` (+ the bundle commit sequence at `:811-848`) |
| **Current behavior (pre-fix)** | `os.WriteFile(tmp, …)` then `os.Rename`. No `fsync` of the file, no `fsync` of the parent directory, no write-failure observer notification |
| **Expected** | `fileutil.AtomicWrite`: unique temp, chmod, fsync(file), rename, fsync(parent dir), and **every** failure branch notifies the observer (the function's own doc calls this "CHAOS-45") |
| **Failure mode** | Silent loss of support state; on power loss, a committed-but-empty or absent file |
| **Monitoring visibility** | **None.** This is the core of the finding and it does not depend on filesystem semantics: `storage_health.go:116-117` installs the observers on `fileutil`, so a write that never calls `fileutil` cannot degrade health or alert |

The security-relevant instance is `writeBundleState`. `createSupportBundle`
(`ui_support.go:800-808`) deliberately writes the PENDING state **first**,
before the tgz and the manifest, with an inline comment explaining why: an
**absent** state file is grandfathered to READY by `readBundleState`
(`ui_support.go:594-598`), and READY is exactly what the download gate checks
(`ui_support.go:672`). So a bundle whose manifest committed but whose state file
did not is **downloadable without the mandatory redaction-preview approval**,
exporting a bundle's INTERNAL sections with no admin consent.

Being precise about the durability half: state-first ordering is correct and
sufficient for a **process** crash (SIGKILL — the page cache survives and the
kernel still flushes). It is *not* sufficient for power loss or a kernel panic,
because without an fsync barrier the relative durability of the state-file
commit and the manifest commit is a filesystem- and mount-option-dependent
accident the code never asserts. The common ext4 `data=ordered` outcome —
a zero-length state file — happens to fail *closed* (`json.Unmarshal` fails →
PENDING). The fail-**open** outcome requires the state rename to be lost while
the manifest rename survives, which same-directory journal ordering makes
unlikely but nothing in the code guarantees. The fsync barrier is what turns
"unlikely" into "cannot".

`internal/connlimit`-style deliberate exceptions do exist and were respected:
`cdr_health.go:310-325` documents at length why it uses
`fileutil.WriteFileExclusive` with a *predictable* `.tmp` rendezvous rather than
`AtomicWrite` (a private key at a guessable path, plus a cross-boot lookup) —
and it **does** fsync. That is correct and was left alone. The six support sites
had no such rationale and no cross-restart temp lookup.

### CHAOS-72 — DP→CP backoff double-count (FIXED)

| | |
|---|---|
| **Fault injected** | CP unreachable: rolling CP upgrade, ~10s network blip, connection reset |
| **Site** | `controlplane_client.go:84-95` (`backoff`) vs `:249-258` (`pollConfig`) |
| **Current behavior (pre-fix)** | `pollConfig` does `c.failCount++`, then `backoff` does `c.failCount++` again before `delay := 1<<min(failCount,6)`. Single-CP schedule: 4s, 16s, 60s, 60s… Multi-CP: `failCount` is 3 after the **2nd** failure, so `if c.failCount < 3` is already false and `failover()` runs |
| **Expected** | The documented `2s, 4s, 8s … 60s`, and failover only on the 3rd consecutive failure |
| **Failure mode** | Fleet-wide CP churn off a healthy leader on a transient blip; policy/blocklist convergence lag up to 60s on a single-CP appliance |
| **Recovery** | Automatic — `resetBackoff()` is correctly called on success (`:273`, `:410`, `:478`), so there is no permanent-ceiling pinning |

The fix is to delete the duplicate increment: `failCount` is owned by the
caller, and every one of the three `c.backoff(ctx)` call sites is inside
`pollConfig`'s already-charged error path. That single deletion corrects **both**
the schedule and the failover threshold. A `max(failCount, 1)` floor clamp was
added so the one path that reaches `backoff()` with a cleared streak — the
post-`failover()` immediate-retry failure, where `failover()` sets
`failCount = 0` (`:202`) — still honors the documented 2s minimum instead of
backing off 1s.

### REPORTED (verified, not fixed): SOCKS5 accepts before the admission posture is restored

`main.go:254` runs `initSOCKS5(s)`; `main.go:255` runs
`initPersistentAdminState(s)` → `LoadAdminSettings` → `applyAdminSecurity`,
which is what restores the **GUI-persisted** admission posture:
`ipf.SetMode`/`ipf.AddAll`, `rl.Configure`, `connLimiter.Enable`
(`admin_settings.go:425-439`). `startSOCKS5` deliberately blocks until the first
`bind(2)` resolves and then returns (`socks5_bind.go:197-225`), so **the socket
is bound and the accept loop is serving** while main is still on line 255.
`handleSOCKS5` consults exactly those three globals (`socks5.go:422, 430, 436`).

With no `-ip-filter-mode` / YAML `ip_filter_mode` — the normal case when the
operator configured the allowlist in the GUI — `applyAdminSecurity` gates on
`s.IPFilterMode != ""`, so until line 255 completes `ipf`'s mode is `""`, and
`IPFilter.Allowed` returns `true` for every IP
(`internal/admission/engine.go:466-467`). A SOCKS5 client connecting in that
window is admitted from **any** source IP, unrate-limited and uncapped, and
relayed. The window spans `probeStorageWritability` (which creates, writes and
unlinks a probe file), `initConfigVersioning`, three store constructions,
`globalAlertStore.Init`, and two fsynced writes — milliseconds on a healthy
volume, far longer on a slow or contended `/data`.

The HTTP/HTTPS plane has **no** such window: `buildAndStartProxyServer` only
*constructs* the server and the listener opens at `main.go:1231`, after
everything. The asymmetry appears unintentional. CHAOS-66 noted this ordering
only as the reason a fatal bind killed the primary plane; the admission-posture
consequence is not recorded anywhere.

**Not fixed here** because the remedy is to move `initSOCKS5` down beside
`startAdminUI`/`buildAndStartProxyServer`, which changes startup ownership and
when SOCKS5 listener health is first reported — and AGENTS.md is explicit that
"optional-listener failure must not become a new primary data-plane termination
path." Severity is reduced by SOCKS5 being opt-in (`socks5_port: 0` default).

### REPORTED (verified, not fixed): DP's CP-pushed default policy action is overwritten at boot

`initCluster` (`main.go:228`) applies the DP last-good snapshot, including
`setDefaultPolicyAction(snap.DefaultAction)` (`controlplane_snapshot.go:901`),
and seeds `lastVersion` from the cache (`dp_enrollment.go:302`). Twenty lines
later `initRewriteAndDefaultAction` (`main.go:248`) calls
`setDefaultPolicyAction` **unconditionally** from node-local YAML
(`rewrite_default_action_startup.go:33`). It does not self-heal: the first poll
sends `KnownVersion = cachedConfigVersion`, the CP answers `config_unchanged`,
and `fetchAndApply` returns without applying (`controlplane_client.go:306-308`).

This is register row **CHAOS-18**, still OPEN, but that row understates it: it
says later inits overwrite cluster-applied state "until the next 30s poll",
whereas the unchanged sentinel means there is **no** next apply until an
operator bumps the CP config version. The same clobber shape applies to
`policyStore.ReplaceAll`, `bl.ReplaceFeedEntries` and
`catStore.ReplaceAllChecked`, and `ipf` is additionally replaced by a plain
(non-atomic) pointer store at `controlplane_snapshot.go:873` from the poll
goroutine while main is still running `initConnAndRateLimit`.

**Not fixed here**: it is an already-tracked open row whose remedy is a startup
re-ordering plus an `atomic.Pointer` publication change in the cluster domain —
a design decision for that owner, not a drive-by.

Note the errata rule this interacts with: an empty configured default action
allowing with zero rules and denying with rules
(`rewrite_default_action_startup.go:24-33`) is **deliberate** and is not
reported as a defect. It appears here only as the mechanism by which a CP value
is lost.

### REPORTED (verified, not fixed): retry/cancellation gaps in three workers

- **`applyWithRetry` retries with zero delay.** `release_dispatch_exec.go:424-440`
  loops `applyRetries = 2` (3 attempts) with **no sleep, no backoff, no jitter**.
  A restarting maintenance agent refuses the connection in microseconds, so all
  three attempts burn in well under a millisecond and the dispatch lands
  `TerminalFailedNeedsAttn` for a fault that cleared a second later. `WaitOp` in
  the same file (`:592-621`) gets this right with a consecutive-error budget on
  a 2s ticker.
- **threatfeed / feedsync discard the scheduler's context.**
  `internal/threatfeed/threatfeed.go:299` and `internal/feedsync/feedsync.go:283`
  declare `Run: func(context.Context) bool` and **drop the parameter**; the
  fetches then use `http.NewRequestWithContext(context.Background(), …)`
  (`threatfeed.go:930`, `feedsync.go:354`). A stalled feed origin cannot be
  interrupted by `SIGTERM`; the round runs on for up to its HTTP timeout and
  finishes with a durable write that races the store close at shutdown order 120.
  Bounded by the fact that nothing joins these goroutines, so shutdown is not
  *blocked*.
- **Alert retry passes are serial and uncancellable.**
  `internal/alerts/store.go:1062-1093`: the loop itself is correct (ctx, ticker,
  `obs.SafeCall`), but `processRetryQueue` takes no ctx and each delivery builds
  `context.WithTimeout(context.Background(), 5*time.Second)` (`:903`). Against a
  blackholing webhook, up to `retryQueueMax = 500` ready entries deliver
  serially at 5s each ≈ 42 minutes per pass, with ticks dropped meanwhile.

**Not fixed here**: three separate owners (release delivery, feeds,
observability), and each needs its own regression test and a judgment call about
deployment-visible timing.

### REPORTED (verified, needs owner decision, NOT a defect call): feed clients bypass the SSRF dialer

`internal/feedsync/feedsync.go:353` and `internal/threatfeed/threatfeed.go:929`
construct `&http.Client{Timeout: …}` with a **nil Transport**, so they dial via
`http.DefaultTransport` — no `ssrf.SafeDialContext`. The sibling feed clients
*do* guard: `internal/blocklistfeed/blocklistfeed.go:305` and `saas_feed.go:31`.
`conventions.md` requires the appropriate SSRF guard before outbound dials.

This is flagged rather than fixed because adding the guard would **break a
legitimate deployment**: an on-prem or air-gapped category/threat-feed mirror on
a private RFC1918 address is a normal enterprise topology, and `SafeDialContext`
would reject it. Whether these two feeds are deliberately exempt for that reason
is not recorded at either site. Owner decision.

---

## Risk matrix

| Id | Finding | Likelihood | Customer | Security | Data integrity | Visibility | Status |
|---|---|---|---|---|---|---|---|
| CHAOS-71 | Support writes bypass durable chokepoint | **High** (any full/RO volume) | Low | **Medium** (approval-gate bypass on power loss) | **High** | **None → full** | **FIXED** |
| CHAOS-72 | DP→CP failure double-charged | **High** (any CP blip) | Medium (convergence lag) | Low | None | Partial (logs the wrong number) | **FIXED** |
| — | SOCKS5 pre-posture accept window | Low (opt-in; ms window) | Low | **Medium** (unfiltered admit) | None | None | Reported |
| CHAOS-18 | DP default action clobbered at boot | **High** (every restart) | Medium | **Medium** (allow-by-default) | None | None | Open (tracked) |
| — | `applyWithRetry` zero-delay retry | Medium | Medium (manual re-dispatch) | None | None | Good | Reported |
| — | Feed rounds ignore shutdown ctx | Medium | Low | Low | Low (write races store close) | Good | Reported |
| — | Alert retry pass ~42 min | Low | Low | Low (alert latency) | None | Partial | Reported |
| — | Feed clients lack SSRF dialer | Low | — | **Needs decision** | — | — | Owner |

---

## Recovery assessment

- **CHAOS-71, automatic:** `storageDegraded()` now clears only on an **observed**
  successful durable write (`noteStorageWriteSuccess`), which is the correct
  "silence is not recovery" posture — a node is not declared healthy merely
  because nothing tried to write. Routing the support writes through the
  chokepoint enrolls them in both halves of that, so they can both *raise* and
  *clear* the signal.
- **CHAOS-71, manual:** a corrupt support state file still fails closed on read
  (`loadUploadConfigLocked` → zero value disables egress; `readBundleState` →
  PENDING). Operator action is re-entering the setting; no restart needed.
  The one residual is the absent-state grandfather, discussed under residual risk.
- **CHAOS-72, automatic:** fully — `resetBackoff()` on any successful poll.
- **DP boot clobber:** **no automatic recovery** (the `config_unchanged`
  sentinel). Manual: bump the CP config version. This is the most operationally
  surprising item in the sweep.

## Operational impact

Before CHAOS-71, an operator whose `/data` went read-only would see a healthy
`/api/diagnostics` row, no `storage_write_failed` alert and no Prometheus
series, while support-bundle approvals, upload queue state and recipient keys
silently failed to persist. After the fix the existing storage-health plane
covers them with no new surface to learn. Before CHAOS-72, `DataPlane: backing
off …(failure #N)` reported a count that was double the real consecutive-failure
streak, so the logs actively misled anyone diagnosing CP churn.

## Security impact

The material item is the support-bundle approval gate (CHAOS-71). The
mandatory-preview gate is the control that stops a bundle's INTERNAL sections
leaving the appliance without sighted admin consent, and its crash-safety
argument rested on a write ordering that had no durability barrier. The fix
supplies the barrier. Recipient-registry writes (X25519 public keys for
seal-by-name) gain the same durability; note the read path already re-validates
stored keys against the low-order guard, so a tampered file cannot yield a weak
key (`lookupSupportRecipientKey`).

CHAOS-72 has no direct security impact, but premature failover is a
availability-and-trust concern for a fleet.

## Suggested improvements (beyond this PR)

1. **Make the chokepoint enforceable, not conventional.** The repo has
   architecture-test precedent (`support_upload_arch_test.go`). A guard test
   that fails on a new `os.WriteFile(tmp…)` + `os.Rename` pair outside an
   explicit allowlist (`cdr_health.go`, `restore.go`'s directory swap,
   `backup.go`, `saas_feed_genstore.go`, `internal/storeguard`, the mcp spool —
   all of which fsync themselves) would stop this class recurring. Not added
   here: an allowlist needs each exception's owner to confirm it.
2. Re-order `initSOCKS5` after `initPersistentAdminState`.
3. Publish `ipf` via `atomic.Pointer` and start the DP poll loop after the local
   inits (closes the open half of CHAOS-18).
4. Give `applyWithRetry` the bounded backoff `WaitOp` already models.
5. Thread the scheduler ctx into `threatfeed`/`feedsync` rounds.
6. Pass ctx into `processRetryQueue` and bound a pass.

## Required tests

Added in this PR:

- `support_durable_write_chokepoint_test.go`
  - `TestSupportPersistence_RoutesThroughDurableChokepoint` — table over all six
    entry points; asserts each committed path was observed at the chokepoint.
    Fails on any future hand-rolled write.
  - `TestSupportBundleState_WriteFailureReachesStorageHealthPlane` — fault
    injection on the security-relevant path; asserts `storageDegraded()`, exactly
    one `storage_write_failed` alert, and the inherited base-name path-redaction
    contract.
- `controlplane_backoff_schedule_test.go`
  - `TestDPBackoff_ChargesOneFailurePerFailedPoll` — the single-count invariant
    the whole schedule derives from.
  - `TestDPBackoff_SuccessResetsTheStreak` — negative control.
  - `TestDPFailover_NotBeforeThreeConsecutiveFailures` — threshold, asserted on
    `activeIdx` (failover resets the streak).
  - `TestDPBackoff_FloorHoldsWithAClearedStreak` — the 2s floor, and that
    `backoff()` does not mutate the caller's streak.

Still needed (not added): a restart/recovery test that kills the process between
the bundle state write and the manifest commit and asserts the bundle is not
downloadable; backoff regression tests for the three reported worker gaps.

## Residual risk

- **Pre-existing absent-state bundles stay grandfathered.** `readBundleState`
  returning READY for a missing state file is a deliberate
  backward-compatibility choice for bundles created before the gate existed. The
  fsync barrier makes a *new* bundle unable to reach that state, but it does not
  and should not retro-block genuinely pre-gate bundles. Closing that would need
  a dated or versioned marker — an owner decision.
- **Orphan temp files.** `AtomicWrite` uses unique temp names
  (`base + ".tmp.*"`), so a crash mid-write leaves a temp behind rather than
  overwriting a single fixed `.tmp`. Verified harmless to both directory scans
  that matter: `listUploadQueueLocked` requires a strict `.json` suffix
  (`support_upload_queue.go:163`) and `listSupportBundles` reads `manifest.json`
  by exact name (`ui_support.go:536`). Disk accumulation across repeated crashes
  is the same posture every other `AtomicWrite` call site in the repo already has.
- **`ErrReplacedNotSynced` reporting.** On a parent-dir fsync failure the target
  already carries the new content while the caller returns an error (HTTP 500).
  All six support callers read-modify-write **from disk** with no in-memory
  cache, so they are already compliant with that error's documented contract
  (never roll back in-memory state on it) and the operator's retry is idempotent.
- The three reported worker gaps and the two reported ordering/posture items
  remain open by design; each is attributed above.

## Correctly handled — citable resilience paths

Verified at this revision and left alone:

- **`fileutil.AtomicWrite` itself** (`internal/fileutil/fileutil.go:103-150`):
  unique temp, chmod, fsync(file), rename, parent-dir fsync with correct
  `EINVAL`/`ENOTSUP`/`EOPNOTSUPP` tolerance, `ErrReplacedNotSynced` for the
  post-rename case, and observer notification on **every** failure branch.
- **`cdr_health.go:310-355`** — the documented, correct exception: a predictable
  `.tmp` rendezvous for cross-boot staged renewal, via
  `fileutil.WriteFileExclusive` (O_EXCL, 0600, fsync) precisely because
  `os.WriteFile` at a guessable path is unsafe for a private key.
- **HTTP/HTTPS data plane has no fail-open window** — listener opens at
  `main.go:1231`, after every load; ordering documented inline at `:177-184`.
- **`IPFilter` fails closed on a corrupt mode** —
  `internal/admission/engine.go:457-470` denies all on an unknown mode rather
  than coercing to a permissive blocklist.
- **Expired inspection CA fails closed, explicitly not to bypass** —
  `proxy_tunnel.go:326-347`, pinned by `ca_expiry_failclosed_test.go:100-125`.
- **Layer-2 category store degrades instead of exiting** —
  `catdb.OpenResilient` quarantines a damaged store and keeps booting
  (`urlcategories_startup.go:96-131`), gated in a child process by
  `urlcategories_startup_chaos_test.go`.
- **MCP gateway's startup window is fail-closed** — the boot inventory re-seeds
  every tool Quarantined; every load-failure branch materializes no trust
  (`mcp_tooltrust.go:140-181`).
- **`internal/feedsched` is the reference scheduler** — ctx-checked before and
  after each tick, `defer timer.Stop()`, jittered bounded backoff with both floor
  and ceiling clamped to the live interval, and a panicked round **charged as a
  failure** so a systematically panicking body backs off instead of hot-looping.
- **SOCKS5 accept loop** — errno-classified, bounded backoff reset on an observed
  successful accept, `select` on `stopping` so `Stop` never waits out a backoff,
  rate-limited logging, panic-guarded into a DOWN report (the CHAOS-54 EMFILE
  incident).
- **Root-CA recovery and HA lease recovery** — bounded budgets, capped backoff,
  interruptible waits, terminal states that log the security consequence.
- **Shutdown hook watchdog** — buffered `done` so an abandoned hook can never
  block, `entered` handshake, bounded gRPC drain with the force-close issued on
  its own goroutine (CHAOS-56).
- **Audit JSONL write failures already reach the storage-health plane** —
  `storage_health.go:130-135`, the ST-8 precedent this sweep's finding mirrors.

---

## Verification

Tested revision: this branch. Toolchain `go1.26.9` (`go.mod` `toolchain` pin),
`GOTOOLCHAIN=auto`.

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | pass |
| `go mod tidy -diff` | pass (no drift) |
| `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build` | pass |
| `gofmt -l` on changed files | clean |
| New tests, pre-fix | **RED** (6/6 bypasses reported; 0 alerts on the failure case) |
| New tests, post-fix | pass |
| `go test -race -count=1 -run 'TestSupport\|TestStorageWrite\|TestAuditWriteFailure\|TestApiDiagnostics\|TestDPBackoff\|TestDPFailover\|TestDataPlane\|TestControlPlane\|TestCluster\|TestHA' .` | pass (59s) |
| `python3 docs/agent-context/check.py` | pass (static integrity) |
| `TEST_SEED=20260421 go test -count=2 -shuffle=on -timeout=20m ./...` | see PR body for the result of this run |
| `golangci-lint run --new-from-rev=origin/main` | **BLOCKED — not run.** The installed v2.5.0 binary is built with go1.25 and panics type-checking this go1.26 module: `package requires newer Go version go1.26 (application built with go1.25)`. CI installs a matching build. Not worked around, and no gate weakened |

A focused local pass is not aggregate CI approval; `✅ Fast PR Gate` and
`✅ Deep PR Gate` remain the authority for this revision.
