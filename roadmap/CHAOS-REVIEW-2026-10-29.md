# Chaos engineering review — 2026-10-29

Reviewer: Culvert Chaos Engineer (automated round). Base revision `7262622`
(`main`), clean worktree. Scope: the recovery paths of the cluster CA plane and
the background-worker plane, selected by working the open HIGH/MED rows of the
[2026-10-13 backlog](CHAOS-REVIEW-2026-10-13.md) rather than re-sweeping ground
the earlier rounds already closed.

This round is recorded separately for the same reason the previous one was: it
closes two defects and re-states the backlog it did not reach.
[CHAOS-ENGINEERING-REVIEW.md](CHAOS-ENGINEERING-REVIEW.md) stays the index.

Ids claimed: **CHAOS-104** (cluster-CA overlap lost on restart) and
**CHAOS-105** (the last unguarded background rounds). Both were free at
`7262622`.

---

## 1. Executive summary

The prior rounds' verdict still holds: this tree's resilience posture is
unusually strong, and most of what a chaos review would normally find has been
found. Three of the HIGH rows I picked up from the 2026-10-13 backlog were
already closed on main — `L-1` (a fatal CP gRPC bind) by CHAOS-71's
`cp_grpc_bind.go`, `L-2` (the SOCKS5 pre-posture fail-open window) by
CHAOS-102, and `X-2`'s "blocking is wrong" framing turns out to be a
*deliberate, documented* posture in `internal/logsink`: the process log is the
operator's record and must not shed load, the blocking is strictly no worse
than the synchronous write it replaced, and saturation is counted and exposed
through `Backpressure()`. That row needs re-wording, not a fix.

The two defects this round closes are, like the last round's, **inversions**:
in each case the mechanism that exists to make a failure survivable is the one
that made it worse.

1. **CHAOS-104 (HIGH) — the dual-CA overlap that makes a cluster-CA rotation
   survivable did not survive a restart.** `commitImport` demotes the outgoing
   CA into `secondaryCert`/`secondaryPEM`/`secondaryExp` and `AllCACertsPEM`
   publishes it into the Control Plane's mTLS client-CA pool, so a Data Plane
   node that has not renewed keeps verifying for the whole overlap. **None of
   those three fields was on the load path**: `loadFromPEM` restores only
   `cert`/`key`/`certPEM`. A Control Plane restart anywhere inside the overlap
   therefore came back trusting *only* the new CA and refused every node still
   presenting an old-CA certificate — precisely the set `cluster.json` durably
   records as pending renewal. The asymmetry is the whole defect: the
   rotation's **bookkeeping** is durable (`StartCARotation` → `saveLocked`,
   carrying `OldFingerprint` and `OldExpires`) and the outgoing CA's **PEM** is
   durable (`backupCAFiles` → `cluster-ca.crt.bak`, through
   `fileutil.AtomicWrite`); only the binding between them was lost. **Verified
   empirically** — see §2.1. Both entry points open the window and
   `RotateIfNeeded`'s is *unattended*, so no operator need be present when it
   opens.

2. **CHAOS-105 (MED) — five background workers were still outside CHAOS-24's
   per-round panic guard.** Go terminates the process on an unrecovered panic
   in *any* goroutine and all five are `go`-detached, so one bad round was a
   total outage of an in-line security gateway, data plane included. Four of
   the five exist for **observability or housekeeping** — the live-dashboard
   SSE broadcaster (every second, over the widest set of mutable globals in the
   binary), the decryption-coverage trend sampler, the support retention
   janitor and the support upload worker — so a non-essential feature could
   kill the thing it reports on. **Source-verified**, and the containment half
   is now driven behaviourally.

A correction to the inherited record: `D-1` (this round's CHAOS-104) said the
old CA's only on-disk copy "is written by a plain `os.WriteFile` with the error
discarded." The `os.WriteFile` half is **outdated** — `backupCAFiles` was moved
onto `fileutil.AtomicWrite` by the SEC-SECRETWRITE-1 sweep, and its comment
records why. The *discarded error* half was accurate and is fixed here, because
CHAOS-104 makes that file load-bearing for recovery rather than an operator
convenience.

---

## 2. Failure scenarios

### 2.1 CHAOS-104 — Control Plane restart inside the dual-CA overlap

| | |
|---|---|
| **Trigger** | Any process restart (SIGTERM redeploy, OOM, node reboot, HA promotion of a fresh image, `docker compose up -d` after a config edit) between a cluster-CA rotation and the moment the last node renews. |
| **Current behavior (pre-fix)** | `InitOrLoad` → `loadFromPEM` restores the primary only. `AllCACertsPEM` returns one block. `buildServerTLS`/`rebuildCPCertPool` build a client-CA pool holding only the NEW CA. |
| **Failure mode** | Fleet-wide mTLS rejection of every DP whose node certificate is still signed by the outgoing CA. The CP is up and healthy by every surface it has; the DPs fail at the TLS handshake, i.e. before any application-level error can describe why. |
| **Blast radius** | `CARotation.TotalNodes - len(RenewedNodes)` — the number the CP had *already written down* as pending. On a fleet that rotated minutes earlier, that is every node. |
| **Expected behavior** | The overlap is a bounded migration window. A restart inside it must come back with the same trust set it had before, and must refuse to extend trust past the window. |
| **Recovery (pre-fix)** | Not automatic. A DP cannot renew, because renewal itself rides the mTLS channel it has just been refused — the chicken-and-egg. Recovery is per-node re-enrollment with a fresh token, by hand, on every stranded node. |
| **Monitoring visibility (pre-fix)** | None. Nothing logged, no metric, no health row, no alert. `/api/cluster/ca` reports a rotation in progress and the node count pending, which reads as normal progress. |
| **Verification** | **Empirical.** `TestCHAOS104_RestartDuringOverlap_KeepsOldCAInClientPool` mints a node certificate through the production signer, rotates, asserts the pre-restart pool verifies it, then rebuilds the CA and the ClusterStore from the same `/data` and re-verifies. It FAILS on the pre-fix tree at the post-restart assertion. |

**Why the fix needs no new durable state.** Both records already survive; only
their binding was lost. `restoreSecondaryFromRotation` re-derives the secondary
from `cluster.json`'s `CARotation` plus `cluster-ca.crt.bak`. The backup path
is fully predictable, so the durable fingerprint is what makes trusting it
safe: the file is admitted only when its SHA-256 equals the `OldFingerprint`
the rotation itself recorded, it must pass the production `parseAndValidateCACert`
(non-CA, expired and not-yet-valid all refused), and what enters the pool is
**re-encoded from that one verified certificate** rather than the file's bytes,
so extra PEM blocks cannot ride along into a trust anchor set. Trust never
extends past the earlier of the recorded window and the certificate's own
`NotAfter`.

**Fail-closed direction.** Every refusal branch leaves exactly the pre-change
posture (new CA only) — the fix can only ever *add back* trust the authority
recorded, never invent it. What changes is that refusals are no longer silent:
each says what it could not reinstate and how many nodes that strands.

**Lock discipline.** `InitOrLoad` is split into `initPrimary` (owns
`cert`/`key`/`certPEM` under `ca.mu`) and `restoreSecondaryFromRotation`, which
reads the rotation record — taking the ClusterStore's lock — *before* it takes
`ca.mu`, and calls `onRotate` with `ca.mu` released. That is deliberate: this
exact type is where CHAOS-50/51 found two self-deadlocks, both from calling
`rebuildCPCertPool` (which reads `AllCACertsPEM` under `RLock`) while holding
the write lock.

### 2.2 CHAOS-105 — unguarded background-worker rounds

| Worker | Owner | Cadence | What its round touches |
|---|---|---|---|
| SSE dashboard broadcaster | `events.go` `(*sseBroadcaster).run` | 1 s | `tsGet`, `countryTraffic`, `secscan.Counters`, the connection gauges, `statTotal/Blocked/AuthFail` — the widest mutable-global set in the binary |
| Decryption-coverage trend sampler | `decryption_trend.go` | 1 min | `decSessions` snapshot fold |
| Support upload worker | `support_upload_worker.go` | 30 s | the TAC gateway (remote) and on-disk queue entries that may have survived a crash |
| Support debug-level watchdog | `support_debug_level.go` | 30 s | the active auto-stop for an elevated capture level |
| Support retention janitor | `ui_support.go` | 6 h **+ a synchronous boot sweep** | the on-disk bundle store, which can hold a half-written directory from a crash |

**Current behavior (pre-fix):** each round is called bare inside the loop; a
panic in any of them terminates the gateway. The janitor's boot sweep is not
even behind a ticker, so a panic there killed the process *during startup*.

**Expected behavior:** CHAOS-24 already decided this: background rounds go
through `runGuarded`, per **round** and never per goroutine — a `recover` at
the top of the worker would let it *return*, converting a loud crash into a
silent permanent stall with every dashboard still green.

**Honest severity.** I did not find a specific reachable panic in any of the
five rounds; both `Top` implementations are bounds-safe and the sampler's
arithmetic is total. This is a **defense-in-depth consistency gap with a total
blast radius**, which is why it is MED and not HIGH, and why the gate is a
registry plus one behavioural proof rather than five fault injections.

---

## 3. Risk matrix — this round

| ID | Domain | Finding | Likelihood | Impact | Sev | Status |
|----|--------|---------|-----------|--------|-----|--------|
| CHAOS-104 | CA / cluster / startup | Dual-CA overlap lost on restart → fleet-wide mTLS lockout, no signal, manual per-node recovery | Medium (any restart inside the window; the window opens unattended) | Fleet management plane down; data planes keep proxying on last-known config but receive no updates | **HIGH** | **FIXED** |
| CHAOS-104b | CA / storage | A failed `cluster-ca.crt.bak` write was discarded, making the rotation unrecoverable across a restart with nothing said at rotation time | Low | Removes CHAOS-104's recovery | **MED** | **FIXED** |
| CHAOS-105 | Background workers / lifecycle | Five `go`-detached worker rounds outside the per-round panic guard; four of them serve observability or housekeeping | Low (no reachable panic found) | Total process termination | **MED** | **FIXED** |

### 3.1 Inherited rows this round re-classified

| ID (2026-10-13) | Re-classification |
|---|---|
| `D-1` | **This round's CHAOS-104; FIXED.** Its `os.WriteFile` premise was outdated (`backupCAFiles` uses `fileutil.AtomicWrite`); the discarded-error premise was correct and is fixed as CHAOS-104b. |
| `L-6` | **This round's CHAOS-105; FIXED** for all five named workers, boot sweep included. |
| `L-1` | **Already closed on main** by CHAOS-71 (`cp_grpc_bind.go`); the row predates that landing. |
| `L-2` | **Already closed on main** by CHAOS-102 (`fix(socks5): refuse connections until the admission posture is installed`). |
| `X-2` | **Needs re-wording, not a fix.** `internal/logsink`'s blocking is a documented deliberate posture (shock absorber, not load shedder; never worse than the synchronous write it replaced; saturation counted and surfaced via `Backpressure()`). The *memory-ceiling* half of the row — that the stated budget assumes a line cap which only governs pool return, so a queued buffer is the full line length — remains accurate and unaddressed. |

---

## 4. Recovery assessment

| | CHAOS-104 (pre-fix) | CHAOS-104 (post-fix) |
|---|---|---|
| Automatic recovery | None | **Deterministic**, on the next start, from state that already persisted |
| Manual recovery | Per-node re-enrollment with a fresh token, on every stranded node | Not required |
| Detection | None | The restore logs what it reinstated and for how many pending nodes; each refusal names what it could not restore and the blast radius |
| Data integrity | Unaffected (no state is corrupted — trust is merely narrowed) | Unaffected |

For CHAOS-105 the recovery property is the one `runGuarded` was designed for:
the loop keeps its ticker, so a transient fault costs one interval and
self-heals, and a deterministic one costs one interval per round while staying
recorded in the crash pipeline — visible rather than fatal, and never a silent
stall.

---

## 5. Operational impact

- **CHAOS-104** is the difference between an unattended restart and a fleet
  outage with a hand-driven recovery on every node. The operator-facing change
  is one log line on a successful restore and one explicit line per refusal,
  each naming the pending-node count, so the condition is greppable and
  alertable where it was previously invisible.
- **CHAOS-104b** moves the warning to the moment it is actionable — rotation
  time, operator at the console — instead of the next boot.
- **CHAOS-105** converts five "the gateway died and the log ends mid-line"
  incidents into a recorded crash plus a continuing loop.
- No configuration surface changes, so no GUI/API parity obligation is
  incurred. No new persisted file, no wire-format change, no new alert channel.

---

## 6. Security impact

- **CHAOS-104's fix adds a trust-anchor load path, which is the part that
  needed the most care.** It is gated three ways: an in-progress rotation must
  be recorded durably, the backup's SHA-256 must equal the fingerprint that
  rotation recorded, and the certificate must pass the production CA validator.
  The predictable `.bak` name is exactly why the fingerprint check carries the
  decision — a planted or stale backup is refused, and the gates
  `TestCHAOS104_NoRotationRecorded_IgnoresStaleBackup` and
  `TestCHAOS104_BackupFingerprintMismatch_IsRefused` pin both refusals. Only
  one verified certificate is re-encoded into the pool, so a multi-block file
  cannot smuggle a second anchor.
- The restored trust is strictly a **subset** of what the running process
  trusted a moment before the restart, bounded by the earlier of the recorded
  window and the certificate's own validity, and a lapsed window is never
  reinstated (`TestCHAOS104_RestartAfterOverlapExpired_DoesNotRestoreOldCA`).
- **CHAOS-105** has no security surface of its own, but it removes an
  availability lever: before it, a fault in a dashboard round took the
  enforcement plane down with it.

---

## 7. Suggested improvements (prioritized, NOT done here)

1. **A dedicated health/alert signal for a lost overlap (MED).** The refusal
   branches now log, which is the missing signal, but there is no health row,
   metric or alert. Reusing `noteClusterCARotationFailure` would be wrong — it
   means "the CA is not being replaced" and latches
   `clusterCARotationDegraded`, while here the rotation *succeeded*. This wants
   its own row on `/api/cluster/ca` and the diagnostics panel, which is an
   owner decision about surface, not a chaos-round change.
2. **Re-word `X-2` and address its memory half (HIGH).** The blocking is
   deliberate; the unbounded queued-line length is not. The stated
   `queueDepth × maxPooledLine` budget is not what the queue actually holds.
3. **`X-4` scan-path decompression before admission (HIGH)** and **`X-5`
   uncapped DPI scan goroutines (MED)** remain the largest untouched
   exhaustion rows, and `X-5` has its own in-tree solved twin in
   `internal/yara` to copy.
4. **`R-1` — the four DP→CP loops with no backoff (MED).** Still open and
   still needing a posture decision rather than a mechanical fix, for the
   reason the 2026-10-13 round recorded.
5. **A two-file commit for the CA pair.** Both `bootstrapPrimary` and
   `commitImport` record that a crash between the cert and key writes leaves a
   mismatched pair, detected on next boot and failed closed. That posture is
   deliberate and documented; it is listed here only so the gap stays visible.

---

## 8. Suggested PR — what this round changes

Two commits on `claude/serene-cerf-3jzbl2`:

- `fix(cluster-ca): restore the dual-CA overlap after a restart inside a rotation (CHAOS-104)`
  - `enrollment.go`: `InitOrLoad` split into `initPrimary` + the new
    `restoreSecondaryFromRotation`; `adoptPrimaryFromDisk` and
    `bootstrapPrimary` extracted from `initPrimary`; `backupCAFiles` reports a
    backup write that did not land.
  - `cluster_ca_rotation_restart_chaos_test.go`: four gates.
- `fix(workers): guard the last five unguarded background rounds (CHAOS-105)`
  - `events.go`, `decryption_trend.go`, `support_upload_worker.go`,
    `support_debug_level.go`, `ui_support.go`: each round through `runGuarded`
    under its own crash-component id; the janitor's boot sweep too;
    `sseBroadcaster` gains an injectable `round`.
  - `chaos105_worker_guard_test.go`: containment plus the registry.

The extraction in the first commit also removes a **pre-existing** lint
violation: `InitOrLoad` carried `cyclop` 26 against a threshold of 15 on main.
Full-tree `golangci-lint` over the touched files goes from 2 issues to 1, and
the remaining one (`liveFeedWritePrometheus` `funlen`) is untouched code.

---

## 9. Required tests — and what they pin

`cluster_ca_rotation_restart_chaos_test.go` (CHAOS-104):

| Gate | Pins |
|---|---|
| `TestCHAOS104_RestartDuringOverlap_KeepsOldCAInClientPool` | The reproduction. A node certificate minted through the production signer must still verify against the pool a restarted process publishes. **Verified to FAIL pre-fix.** |
| `TestCHAOS104_RestartAfterOverlapExpired_DoesNotRestoreOldCA` | A lapsed window is not reinstated — the overlap is bounded, not a second permanent anchor. |
| `TestCHAOS104_NoRotationRecorded_IgnoresStaleBackup` | With no rotation recorded, a `.bak` from a completed rotation is ignored. |
| `TestCHAOS104_BackupFingerprintMismatch_IsRefused` | A backup that is not the certificate the rotation recorded is refused, so the predictable path cannot re-add a retired anchor. |

`chaos105_worker_guard_test.go` (CHAOS-105):

| Gate | Pins |
|---|---|
| `TestCHAOS105_SSEBroadcastLoop_ContainsAndSurvivesAFailingRound` | Containment end to end through the widest worker: contained, recorded under the right component, the loop keeps ticking, it self-heals on the next round, and it still exits on ctx cancellation. |
| `TestCHAOS105_EveryRegisteredWorkerRoundIsGuarded` | The five-worker registry, at the source level, each under its own component id. |
| `TestCHAOS105_RetentionJanitorBootSweepIsGuarded` | The one round not behind a ticker. |

The registry gate is a source gate deliberately: a reintroduced bare call
cannot be caught behaviourally without injecting a fault into each worker's
production dependencies, and nil-ing the globals those rounds read would panic
any *other* live worker that touches them — the hazard the guard exists to
prevent. This is the technique `cp_grpc_bind_chaos_test.go` already uses for
its `logFatalf` ban.

Checks run for this round are recorded in §10.

---

## 10. Verification performed

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `gofmt -l` on every touched file | clean |
| `go test -run 'TestCHAOS104' -count=1 .` | pass (and verified FAILING pre-fix) |
| `go test -run 'TestCHAOS105' -count=1 .` | pass (and verified FAILING with the guards reverted) |
| `go test -run 'ClusterCA\|Enroll\|CARotation\|Cluster\|ColdStart\|Restore' -count=1 .` | pass |
| `go test -run 'SSE\|Support\|DebugLevel\|DecCoverage\|DecryptionTrend\|Chaos24\|Retention\|Upload' -count=1 .` | pass |
| `golangci-lint run --new-from-rev origin/main` (gate's own command, v2.15.0 installed with the `go.mod` toolchain) | 0 issues |
| Full-tree `golangci-lint run`, compared against the same measurement on `origin/main` | touched files 2 → 1 issue; nothing added, the pre-existing `InitOrLoad` cyclop removed |
| `go test -race -count=1 -timeout=40m ./...` | see the PR body for the result at the pushed SHA |

A passing local check is not a passing hosted gate; the Fast PR Gate's sharded
`-race` run and CodeQL are authoritative.

---

## 11. Residual risk

- **CHAOS-104's restore depends on `cluster-ca.crt.bak` existing.** When it
  does not — the write failed, an operator removed it, a restore-from-backup
  brought `cluster.json` without it — the overlap cannot be reinstated and the
  stranded nodes still need re-enrollment. The fix makes that case *loud* at
  both ends (rotation time and boot) but cannot make it recoverable. A second
  durable copy written under the rotation's own name, rather than a single
  fixed `.bak`, would close it; that is a storage-layout decision.
- **A rotation chain inside one overlap keeps only the most recent outgoing
  CA.** `.bak` holds one certificate and `CARotation` records one
  `OldFingerprint`, so two rotations in quick succession strand the nodes still
  on the first CA. That is the pre-existing in-memory behavior too — the
  secondary slot is singular — so the fix does not narrow it, but it is not
  closed either.
- **CHAOS-105 is a guard, not a cure.** A panicking round is now contained and
  recorded; if it panics deterministically it still never completes its work.
  For these five that degrades a dashboard, a chart, a sweep, an upload and a
  capture-level revert respectively — none is a safety-critical completion like
  the fencing-lease keepalive, which is why none takes the fail-closed
  `panicked` branch.
- **Workers outside the five were not re-swept.** `L-7`'s discarded lifecycle
  handles and `context.Background()`-parented MCP telemetry loops remain open,
  and they are a different failure mode (a missed checkpoint, not a crash).
- The backlog rows in §7 and in the
  [2026-10-13 round](CHAOS-REVIEW-2026-10-13.md) that this round did not reach
  are unchanged and still carry their original verification status. Nothing
  there was re-confirmed by this round except where §3.1 says so.
