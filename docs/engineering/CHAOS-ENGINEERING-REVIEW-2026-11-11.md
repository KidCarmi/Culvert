# Chaos Engineering Review — 2026-11-11

## CHAOS-117 — One `null` in a persisted JSON map kills the Control Plane 30 s after every restart, and the HA leader hands it out

**Scope.** The SIMULATE list's *Configuration corruption*, *Policy corruption*,
*Database corruption*, *Power loss*, *Unexpected restart*, *SIGKILL*, *Split
brain* and *Control Plane unavailable* rows, applied to the **enrolled-node
roster** — the one piece of state that is simultaneously persisted, replicated
to every standby, and read by a detached goroutine whose panic is fatal.

**Status.** Fixed. This round takes CHAOS-116 §8.1 (reproduced, not fixed) and
§8.2 row 2, together, because §8.2a showed they cannot be taken apart: the
panic guard without deferred lock release converts a crash into a permanent
silent deadlock of every cluster operation. The previous review named this "the
sharpest open item in this document and … the next round's". It was.

**Closes.** CHAOS-116 §8.1 in full; §8.2 row 2 (`ClusterStore.StartHeartbeatMonitor`)
and the §8.2a pairing requirement for it. CHAOS-116's residual items 1-5 and the
remaining five rows of §8.2 are untouched and remain open as written; §8.3 and
§8.4 are untouched. New findings reached but not fixed are in §8 below.

---

## 1. Executive summary

Line references to `enrollment.go` in §1-§3 are at the **base** revision
`origin/main` `04aa647`, where the defect is; §4-§5 describe the fix.

`{"nodes":{"dp-1":null}}` is valid JSON. That single fact was a persistent,
self-reinstating denial of service of the Culvert Control Plane.

`ClusterStore.Load` normalised nil **maps** and did not normalise nil map
**values**:

```go
// enrollment.go, pre-fix
if st.Nodes == nil {
    st.Nodes = make(map[string]*EnrolledNode)   // the MAP
}
if st.Tokens == nil {
    st.Tokens = make(map[string]*EnrollToken)
}
...
cs.st = st                                       // a nil *EnrolledNode is published
```

Four facts turn that from a bad record into a fleet outage.

**The quarantine cannot see it.** CHAOS-07 installed a
quarantine-don't-overwrite response for a corrupt `cluster.json`
([state_corruption.go](../../state_corruption.go)), and it is triggered by a
`json.Unmarshal` **failure**. A `null` member parses perfectly, so `Load`
returned `nil`, boot continued, and the probes went green.

**The first consumer to touch it is one whose panic is fatal.**
`checkNodeLiveness` dereferences `node.Status`
([enrollment.go:674-678](../../enrollment.go)) and `tokenExpired` dereferences
`tok.Used` ([enrollment.go:704-709](../../enrollment.go)). Both are reached from
`checkHeartbeats`, which is the round of `StartHeartbeatMonitor`'s **detached,
unguarded** 30 s ticker ([enrollment.go:639-650](../../enrollment.go)), started
on control-plane activation ([cp_grpc_activation.go:168](../../cp_grpc_activation.go)).
Go terminates the process on an unrecovered panic in *any* goroutine. The
gateway does not return an error, degrade, or fail closed — it exits, and every
in-flight tunnel on that node dies with it.

**The poison is on disk, so it is a loop, not an incident.** Nothing repairs
the file. The node restarts, loads the same document, activates the control
plane, and dies again 30 s later. Restart-on-failure supervision makes it
worse, not better: it guarantees the next iteration.

**The HA leader propagates it.** `ImportFullState` carried a copy of the same
one-level-too-shallow defence ([enrollment.go:744-758](../../enrollment.go)) and
then **persisted what it imported** — so a standby that resynced from a leader
holding one null record wrote that record to its own `cluster.json` and
inherited the crash loop, which then outlived the leader that produced it. A
single bad member in one file is sufficient to take down every control plane in
the cluster, in sequence, permanently.

**This is the third instance of a class the repository already tracks twice.**
The top-level nil maps in `Load` are the first; `CARotation.RenewedNodes` is
the second, and its own regression test calls it "a second nil-map class
defect" ([qa_gate_test.go:331](../../qa_gate_test.go)). The class kept
recurring because each ingestion boundary hand-rolled its own normalisation and
the second was never updated when the first was deepened. §4 fixes the class,
not the instance.

**The fix nearly made things worse, and that is the interesting part.** The
obvious response to an unguarded fatal round is `runGuarded`. But
`checkHeartbeats` took `cs.mu` and released it with a plain trailing
`cs.mu.Unlock()`. Today a panic there kills the process, so the lock does not
matter. Add the guard alone and the panic is *contained into a permanently held
`ClusterStore` lock*: every enrollment, heartbeat, revocation and admin cluster
read blocks forever — no crash, no restart, no alert, no recovery path at all.
That is strictly worse than the crash it replaces, and it is exactly the
inversion [internal/obs/guard.go](../../internal/obs/guard.go)'s header warns
about. The guard and the deferred release ship as one change, and §6 pins them
with a test that fails by **detecting and reporting** the stall rather than
hanging.

---

## 2. Failure scenarios

How a `null` member gets into `cluster.json` in the first place, in descending
order of likelihood. None of them requires an attacker.

| # | Scenario | Produces |
|---|---|---|
| 1 | A hand edit or scripted repair of the roster during an incident — `jq`, `sed`, a config-management template with an unset variable | `"dp-1": null` |
| 2 | Restore from a backup/export written by a different Culvert version whose `EnrolledNode` serialisation differed | a member that decodes to nil |
| 3 | An HA leader on any of the above, replicating to every standby | the same member, on every node |
| 4 | A generic JSON tool that normalises an empty object to `null` on round-trip | `"dp-1": null` |

The CHAOS-07 **torn-write** case — power loss mid-write — is NOT a source: F4's
fsynced atomic writes mean a torn file does not parse, which is the quarantined
path. This defect's inputs are the ones that produce *well-formed* JSON, which
is precisely why the existing defence missed it.

Each one then runs the same chain:

```
cluster.json with a null member
  → Load() parses cleanly, publishes a nil *EnrolledNode   (no quarantine, no log, probes green)
  → control-plane activation starts the heartbeat monitor
  → +30 s: checkNodeLiveness dereferences node.Status      → SIGSEGV
  → unrecovered panic in a detached goroutine              → PROCESS EXIT
  → restart → the file is unchanged                        → +30 s → exit
```

and, on an HA pair:

```
leader holds the null member
  → standby syncFromLeader → ImportFullState adopts it     (ha.go:1054)
  → saveLocked() writes it to the standby's own cluster.json
  → the standby is now independently poisoned, permanently
```

---

## 3. Reproduction, before any fix

Run on this tree at base `origin/main` `04aa647`, in package `main`:

| Leg | Entry point | Result |
|---|---|---|
| null node | `Load` then `checkHeartbeats` | `Load` **accepted** the document (`nodes=1`); panic `invalid memory address or nil pointer dereference` at `enrollment.go:676` in `checkNodeLiveness` — the test binary died |
| null token | `Load` then `checkHeartbeats` | panic at `enrollment.go:706` in `tokenExpired`, via `gcExpiredTokens` |
| admin plane | `Load` then `ListNodes` | panic at `enrollment.go:421` (`*n` on a nil pointer) |
| replication | `ImportFullState` then `NodeCounts` | the null member was **persisted to disk**, then panic at `enrollment.go:433` |

The third leg is worth separating from the others: `net/http`'s per-connection
recover means a panic in an admin handler drops that request rather than the
process. The admin API is therefore *degraded*; the heartbeat ticker is
*fatal*. The severity of this defect comes entirely from which goroutine
touches the record first.

---

## 4. The fix — normalise the class, at every boundary

One normaliser, called from both ingestion points
([enrollment.go](../../enrollment.go)):

```go
func normalizeClusterState(st *ClusterState) clusterStateRepair
```

It repairs nil maps, nil map **values**, and `CARotation.RenewedNodes`, and
reports what it dropped. `Load` and `ImportFullState` both route through it;
their duplicated, divergent inline versions are gone, which is the actual
remedy for a class that recurred three times because the duplication let one
copy rot.

**A null record is dropped, not zero-filled.** A zero `*EnrolledNode` has no
`NodeID` and no `CertSerial`, so materialising one would invent a nameless node
in the admin roster and in the CA-rotation node count; a zero `*EnrollToken`
has a zero `ExpiresAt`, which is an already-expired token nothing can consume.
Dropping is also what keeps the security posture: `st.Revoked` is a slice of
**values**, so the revoked-certificate list — the half CHAOS-07 identified as
the security-relevant one, because a dropped revocation means a revoked DP
certificate validates again — is untouched by the repair. A dropped node must
re-enrol. That is an availability cost, paid in exchange for not trusting a
record that proves nothing.

**The file is NOT quarantined.** It parsed, so every *healthy* node and the
whole revocation list in it are intact and usable. Renaming the file aside —
the CHAOS-07 response — would discard all of that good state to punish one bad
member, which on a 200-node cluster trades a one-node repair for a 200-node
re-enrolment. §6's mutation 5 shows what that fix would have cost.

**`/ready` is deliberately unchanged.** The repair records through a new
`noteStateFileEntriesDropped` ([state_corruption.go](../../state_corruption.go))
which, like `noteStateFileUnreadable`, leaves `stateCorruptionByKind` alone. The
degradation is survivable by re-enrolment; refusing to serve a fleet over it is
the wrong trade, and it is the same posture CHAOS-05/07 recorded for its own
non-quarantine case.

---

## 5. The fix — containment, and the trap in it

Three changes that are one change:

1. `StartHeartbeatMonitor`'s round runs under
   `runGuarded(crashComponentClusterHeartbeat, cs.checkHeartbeats)` — per
   **iteration**, never per goroutine. A goroutine-level recover would let the
   loop return, and node liveness would then silently never be evaluated again
   with the process up and every dashboard green.
2. `checkHeartbeats` releases `cs.mu` with `defer`, not a trailing `Unlock`.
   Without this, change 1 converts a crash into a permanent deadlock of every
   cluster operation. `ImportFullState` gets the same treatment, for the same
   reason: it calls `saveLocked` under the lock.
3. The monitor is registered in `chaos105Workers`
   ([chaos105_worker_guard_test.go](../../chaos105_worker_guard_test.go)), so
   the existing AST gate now fails if the guard is ever removed. Note what this
   worker is: not observability, but the **only writer of node liveness**,
   detached, on the control plane.

---

## 6. Verification

Tested revision: this branch, base `origin/main` `04aa647`.
`go env GOVERSION` = `go1.27.4`, matching `go.mod`'s `toolchain go1.27.4`;
`GOTOOLCHAIN=auto`, no workflow override.

**Mutation sweep.** Each mutation was applied to the fixed tree, the gates run,
and the tree restored. All seven are caught, and three reproduce the pre-fix
measurement exactly.

| # | Mutation | Caught by | What it reported |
|---|---|---|---|
| 1 | Remove the nil-VALUE sweep (restore the pre-fix nil-MAP-only defence) | `NullNodeRecordIsDroppedNotPublished` | `the null node record is still in the published map`, then **the test binary died** with a nil deref in `checkNodeLiveness` — the pre-fix behaviour, verbatim |
| 2 | `ImportFullState` stops normalising | `ReplicatedNullRecordIsNotAdoptedOrPersisted` | `the standby adopted a null record from the leader` / `persisted cluster.json still carries a null record for "dp-null" — the next boot reloads the crash loop`, then a nil deref |
| 3 | **Keep the guard, revert the deferred unlock** (the §8.2a trap) | `HeartbeatRoundPanicDoesNotWedgeTheStore` + `ClusterStoreLockReleasesAreDeferred` | `cs.mu is still held after a contained panic: the guard converted a crash into a permanent silent stall of enrollment, heartbeats and every admin cluster read` |
| 4 | Remove the per-round guard | `CHAOS105_EveryRegisteredWorkerRoundIsGuarded` + `HeartbeatMonitorSurvivesAPanickingRound` | `runs its round unguarded: an unrecovered panic in ANY goroutine terminates the gateway` |
| 4b | Recover at the **goroutine** level instead | the same two | `recovers at the GOROUTINE level: the loop would exit on the first panic and node liveness would never be evaluated again` |
| 5 | Quarantine the file instead of dropping the records | `DroppedRecordsAreVisibleToAnOperator` | `the state file was moved or removed … a parseable file with one bad record must stay where it is`; `the dropped-record repair gated /ready`; and the row degraded to `running with an EMPTY cluster store` — the cost of the wrong fix, measured |
| 6 | Let the dropped-record note clobber a worse record | `DroppedRecordRowNeverMasksAWorseOne` | `the dropped-record note overwrote the quarantine record` / `the quarantine record's cause was lost` |
| 7 | Remove the once-latch on the replication alert | `ReplicatedRepairAlertsAtMostOncePerProcess` | `5 resync rounds fired 5 alerts, want 1` |

Mutations 1 and 2 are the ones worth reading twice: the guard's absence is not
reported as a failing assertion but as the **death of the process running the
assertions**, which is what happens to the gateway.

Mutation 3 is the round's thesis. Note how it fails: with a 10 s deadline and
an explicit message, not as a hung test binary. A silent stall must be
*reported* as a silent stall.

**Commands and results.**

- `go vet ./...` — clean. `go mod tidy -diff` — clean.
- `CGO_ENABLED=0 go build -ldflags="-s -w" -o culvert .` — ok;
  `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /dev/null .` — ok.
- `TEST_SEED=20260421 go test ./... -count=1 -timeout=40m` — **119 packages,
  0 failures** (root ok in 522 s) after the one gate noted below.
- `TEST_SEED=20260421 go test -count=2 -shuffle=on -timeout=40m ./...` — the
  Deep determinism command — **117 packages ok, 0 failures**.
- `go test -race -count=2 -shuffle=on -timeout=20m -run 'TestCHAOS117|TestCHAOS105|TestCHAOS07|TestClusterStore|StateFile|Heartbeat|TestHA_|TestChaos' .`
  — ok (779 s).
- `go test -tags benchgate -run 'TestBenchGate_' -count=1 -p 1 -timeout=10m`
  over all nine benchgate-owning packages (root, `internal/admission`,
  `internal/threatfeed`, `internal/catgroup`, `internal/session`,
  `internal/decryptprofile`, `internal/catoverride`, `internal/secscan`,
  `internal/catdb`) — ok, on an otherwise idle machine (root 216 s). This
  change touches no benchmarked path; the run is a control.
- `python3 docs/agent-context/check.py` — passes (run as a control; no
  `AGENTS.md`, `CLAUDE.md` or skill changed).

**Not run, and why.** The frontend tree (`frontend/npm run verify`) and the
`cmd/culvert-maint` module: neither is touched by this change, and neither
consumes `ClusterStore`. `make api-verify` was not run because no route,
OpenAPI operation or `uiRoutes` entry changed — the new diagnostics row is a
VALUE inside the existing `/api/diagnostics` operator-contract array, whose
conformance tests are in the root package and passed in both full runs above.
Hosted CI (`Fast PR Gate`, `Deep PR Gate`) has not run on this revision at the
time of writing; a local pass is not aggregate CI approval, and the sharded
race lanes plus the privileged mount-point regression are only reproducible
there.

**One gate caught a real defect in this round's own test.** The first full-suite
run failed `TestTestFileReadsAreCWDIndependent`
([static_read_wall_test.go](../../static_read_wall_test.go)): the new
`EveryIngestionBoundaryNormalises` gate read `enrollment.go` CWD-relatively,
which another test's concurrent `os.Chdir` can flake. Anchored to
`pkgSourceDir()`. Recorded rather than silently fixed, because the wall working
as designed on a new test is evidence about the wall.

**Lint, measured in both directions** — the repository's own rule, because
`cyclop`, `funlen` and `gocognit` attribute to a function's DECLARATION line,
so `--new-from-rev` cannot see a function made more complex.

- `golangci-lint run --timeout=10m --new-from-rev origin/main` (the gate's own
  command, v2.15.0 installed with the `go.mod` toolchain) — **0 issues**. It
  first reported one: `gocritic badLock` on the lock-availability probe in the
  wedge test. Fixed properly (the probe now defers its own release) rather than
  suppressed.
- Full-tree pass, candidate vs. base: **170 findings on each**, with identical
  per-linter totals (`cyclop: 24`, `gocognit: 24`, `funlen: 8`, `gocritic: 40`,
  …). Seven findings appear on one side only, all of them in files this change
  never touches (`cluster_audit_test.go`, `internal/mcp/**`,
  `internal/redaction/**`, `internal/admission/security_test.go`); that is
  `max-same-issues: 3` in [.golangci.yml](../../.golangci.yml) truncating each
  message class, so which three instances are printed shifts with file
  ordering. No new finding, and no complexity regression on either changed
  function.
- Coverage: none of `enrollment.go`, `state_corruption.go`,
  `cluster_metrics.go` carries a per-file floor in
  [coverage-floor.sh](../../.github/scripts/coverage-floor.sh); the change adds
  covered code and cannot move the 55 % global floor down.

---

## 7. Assessment

**Recovery.** Before: none. The failure was self-reinstating, and restart
supervision guaranteed the next iteration. After: automatic and deterministic —
the bad record is dropped at load, the node boots, and the heartbeat monitor
runs. An HA standby no longer adopts or persists the leader's bad record, so
the blast radius of one damaged file is one node's roster entry.

**Customer impact.** Before: total loss of the control plane, repeating every
30 s, with every in-flight tunnel on that node dropped at each exit; on an HA
pair, both nodes, permanently. After: the affected nodes must re-enrol. Proxy
traffic is unaffected either way, which is why the fleet-wide version of this
could run for a long time before anyone connected the restarts to a JSON file.

**Security.** The repair never drops revocation evidence (`st.Revoked` is a
slice of values; pinned by a test asserting the list survives). A dropped node
record cannot authorise anything — it has no certificate serial — so dropping
it is fail-closed with respect to that node's identity. The one real security
consideration is that the pre-fix behaviour was *itself* a security failure:
an in-line security gateway that exits is a gateway that is not inspecting.

**Operational impact.** Silently losing an enrolled node is its own
operational surprise — the node's next heartbeat is refused and nothing says
why — so the repair is reported on four surfaces: the
`culvert_cluster_state_nil_entries_dropped_total` counter, a sanitised log line
naming the dropped node IDs (token hashes are counted, never named, per the
CL-9 contract), the authenticated `state_file_cluster` diagnostics row
(viewer-safe, path-free, with the re-enrol action), and one
`state_file_corrupt` alert. The replication path latches its alert once per
process: a standby resyncs on a timer, and a persistently damaged leader must
not page on every round.

**Data integrity.** `ImportFullState` no longer writes a record it cannot
evaluate to disk. That is the single most important line of this change: it is
what stopped one file from becoming a cluster.

---

## 8. Also reached this round, NOT fixed

**8.1 `funcSource` reads package sources CWD-relatively.** *(source-verified)*
The shared AST helper
([chaos105_worker_guard_test.go:186-205](../../chaos105_worker_guard_test.go))
does `parser.ParseFile(fset, file, …)` and `os.ReadFile(file)` on a bare name.
`TestTestFileReadsAreCWDIndependent`'s regex only matches string **literals**,
so a variable path passes the wall while carrying the exact flake class the
wall exists to prevent — a concurrent `os.Chdir` makes every CHAOS-105 and
CHAOS-117 source gate fail for the wrong reason. Not fixed here because the
helper belongs to another round's file and the fix (anchor to `pkgSourceDir()`)
should land with that round's own re-verification. This round's new gate is
already anchored.

**8.2 The remaining five unguarded ticker loops from CHAOS-116 §8.2 are still
unguarded**, and each needs its own §8.2a audit before a guard is added:
`startSyslogHealthWatchdog`, `telemetryRuntime.flushLoop`,
`telemetryRuntime.exportLoop`, `runInspectionCARecoveryLoop`,
`runIdPMetadataDegradationWatchdog`. CHAOS-116 §8.2a already names
`syslogFeedState` and `commitSyslogDegradation` as having the same trailing-
`Unlock` shape this round just fixed in `checkHeartbeats` — so the syslog loop
carries the identical trap, with the identical remedy. The registry entry added
here makes `chaos105Workers` a six-worker list, which is still a hand-written
list; §8.2's call for a mechanical discovery gate stands.

**8.3 The same nil-VALUE class may exist in other persisted pointer maps.**
*(reported, not verified)* `ClusterState` was audited exhaustively this round.
Every other persisted struct holding a `map[string]*T` is a candidate for the
same `null`-member defect, and the discriminating question is the same one that
made this instance fatal: does a **detached goroutine** dereference it? That
audit is the natural next round and is a strictly mechanical sweep.

**8.4 `UpdateNodeSeen` and `RegisterNode` still release `cs.mu` with a trailing
`Unlock`.** *(source-verified)* They are not reached from a guarded round
today, so the §8.2a trap does not apply to them and this round deliberately did
not widen its diff. They become a problem the moment any caller of theirs is
placed under a guard, and
`TestCHAOS117_ClusterStoreLockReleasesAreDeferred` is written to be extended
with them when that happens.

---

## 9. Residual risk

1. **The repair is silent to the node that was dropped.** A data plane whose
   record was removed keeps presenting a valid certificate and is refused with
   a generic "not enrolled". The operator surfaces added here tell the *control
   plane's* operator what happened; the DP's own logs do not say why it was
   rejected. Correlating the two is manual.
2. **The dropped-record diagnostics row does not survive a restart.** Unlike a
   quarantine, which leaves a `.corrupt.*` file on disk as a durable signal,
   this repair leaves no artifact: the next boot re-drops the same records,
   re-logs, re-alerts and re-renders the row, but nothing accumulates. That is
   consistent (the condition is still true, so it is still reported) but it
   means an operator cannot tell a first occurrence from the hundredth.
   Writing the dropped members aside — a `.dropped.<unixnano>` sidecar — is the
   obvious improvement and is **not** done here, because it adds a disk write
   to the boot path for a case whose repair is already complete.
3. **One alert per process on the replication path can under-report.** If a
   leader is repaired and then damaged again differently, the second episode
   gets a log line and counter movement but no page. The alternative — an alert
   per resync round — is worse (mutation 7), and the honest middle ground
   (latch on the dropped-record *signature*) was judged more state than the
   signal justifies.
4. **The `/ready` posture is a judgement, not a derivation.** This round keeps
   a node with a repaired roster in service, on the grounds that re-enrolment
   is a survivable degradation and that holding a fleet out of service over one
   bad member is the worse trade. An operator who would rather fail closed on
   *any* roster damage has no switch for that. The decision is recorded, as
   CHAOS-05/07's own refuse-to-boot remainder was.
5. **Guarding the heartbeat round means a node can now stay up while
   repeatedly failing to evaluate liveness.** That is the intended trade —
   a transient fault costs one 30 s interval and self-heals instead of killing
   the gateway — but a *persistent* fault in that round now produces a
   control plane whose node-liveness view is frozen while it reports healthy.
   The crash records (`culvert_crash_records_total{component="cluster_heartbeat"}`)
   are the signal, and no alert rule is shipped on them. Same reasoning as
   CHAOS-116 residual 4: the series is cumulative and the rule belongs with the
   operator's alerting, not in the binary.
