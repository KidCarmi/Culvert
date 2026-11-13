# Chaos Engineering Review — 2026-11-12

## CHAOS-118 — The last five detached background rounds could kill the gateway, and guarding two of them naively would have been worse

**Scope.** The SIMULATE list's *Silent failures*, *Deadlocks*, *Unexpected
restart*, *SIGKILL*, *Broken retries*, *Certificate expired*, *Root CA expired*,
*Syslog unavailable* and *Broken IdP* rows, applied to the **background worker
plane** — the `go`-detached loops whose panic Go answers by terminating the
process.

**Status.** Fixed. This round closes CHAOS-116 §8.2 in full (all five remaining
unguarded rounds), applies the §8.2a pairing audit to each, and closes
CHAOS-116 §8.1, which became this round's responsibility the moment it extended
the registry that depends on it.

**Closes.** CHAOS-117 §8.1 (`funcSource` CWD-anchoring); CHAOS-117 §8.2 (all
five loops, each with its §8.2a audit). CHAOS-117 §8.3 was swept and is
**reported clean** — see §3, which is a result, not a fix. CHAOS-117 §8.4 and
its residual items 1-5 are untouched and remain open as written. New findings
reached but not fixed are in §7.

---

## 1. Executive summary

Line references are at the base revision `origin/main` `3b09cff`.

Go terminates the process on an unrecovered panic in **any** goroutine. Culvert
is an in-line security gateway, so that is not a crashed feature — it is every
in-flight tunnel on the node dropped. CHAOS-24 built the per-round guard for
this, CHAOS-105 applied it to five workers and CHAOS-117 to a sixth. Five
remained, and CHAOS-116 §8.2 had carried them forward unfixed through two
rounds:

| Worker | File | What a panic in one round did |
|---|---|---|
| `startSyslogHealthWatchdog` | `syslog_health.go:947` | killed the gateway from a **detection-only** SIEM health check |
| `runIdPMetadataDegradationWatchdog` | `idp_metadata_health.go:974` | killed the gateway from the enforcer of the IdP metadata staleness ceiling |
| `runInspectionCARecoveryLoop` | `rootca_recovery.go:340` | killed the gateway from the only thing that re-enables SSL inspection after a failed CA load |
| `telemetryRuntime.flushLoop` | `mcp_telemetry.go:367` | killed the gateway from the MCP denial-evidence flush |
| `telemetryRuntime.exportLoop` | `mcp_telemetry.go:383` | killed the gateway from the MCP archive export, once per partition |

The inversion CHAOS-105 recorded is the same one here, and sharper: three of
the five exist for **observability**, so a non-essential reporting feature could
kill the thing it reports on.

**The interesting half of this round is not the guard. It is that adding the
guard to two of them, by itself, would have been strictly worse than the crash.**

CHAOS-117 §8.2a established the rule: a guard placed over a critical section
that releases its lock with a **trailing, non-deferred** `Unlock` contains the
panic into a permanently held mutex — no crash, no restart, no alert, no
recovery path. CHAOS-116 §8.2a had already *named* `syslogFeedState` and
`commitSyslogDegradation` as carrying that shape. They did, and so did two IdP
sweeps nobody had looked at:

| Critical section | Lock | Shape at base | Who else takes that lock |
|---|---|---|---|
| `commitSyslogDegradation` | `syslogHealth.mu` | Lock 733 → trailing Unlock 746/758 | the drop observer on the **logging path**, `/healthz`, diagnostics |
| `syslogFeedState` | `syslogHealth.mu` | Lock 1123 → trailing Unlock 1152 | same |
| `idpMetadataDegradationSweep` | `idpMetadata.mu` | Lock 841 → trailing Unlock 853 | the IdP metadata fetch path, every health surface |
| `idpStaleCeilingSweep` | `idpServedMu` | Lock 893 → trailing Unlock 921 | every IdP metadata publish, and retirement |

Each holds that lock across work it does not control: `syslogFeedState` calls
`settleRetiredSyslogWritersLocked()` (which walks a list and calls a method on
every entry) and `described.Stats()`; `idpStaleCeilingSweep` calls
`sd.expired(now)` per entry.

**And the obvious fix — a function-level `defer` — is also wrong, for a second
reason.** All four functions do work *after* the release that must not hold the
lock. `commitSyslogDegradation` formats operator prose and calls `Dispatch`,
which reaches a **webhook**. `idpStaleCeilingSweep`'s own comment records that
its result is acted on with `idpServedMu` released, because retirement takes the
registry write lock — "holding one subsystem's lock across another's call is the
CHAOS-50 cluster-CA rule". Promoting the release to function scope would hold a
health lock across network I/O and invert exactly that rule.

So each critical section is **scoped** — a closure with a deferred release
inside it — and the released-before-alert boundary is unchanged. §4 covers what
that cost.

**The fifth loop needed the opposite decision, and it is the one place
"keep going" is not the safe answer.** `runInspectionCARecoveryLoop` *branches*
on its round's result: `!attempted` means an operator already fixed the CA by
hand, and `err == nil` means recovery succeeded. **Both exits are terminal.** A
contained panic that inherited the zero values would pick one of them —
silently abandoning the retry budget, or declaring SSL inspection recovered
while it stays disabled and inspect-matched TLS is forwarded **uninspected**. A
panicked attempt is therefore charged as a **failed** attempt and retried on
backoff. This is the explicit caller-inspects-the-verdict case that
`internal/obs/guard.go`'s header reserves.

---

## 2. Failure scenarios

What actually panics one of these rounds, none of which requires an attacker.

| # | Round | Trigger | Current behavior (post-fix) |
|---|---|---|---|
| 1 | syslog watchdog | a nil Writer handle on the retirement list; `r.w.CumulativeStats()` nil-derefs under `syslogHealth.mu` | contained, recorded, next tick re-evaluates |
| 2 | syslog watchdog | a displaced Writer whose `Stats()` faults mid-retirement | contained; lock released; `/healthz` and the logging path keep working |
| 3 | IdP watchdog | a fault in the degradation sweep, the ceiling sweep, a retirement or the alert | contained; both IdP locks released; next tick re-arms recovery |
| 4 | CA recovery | a malformed/truncated CA bundle or passphrase path faulting inside an attempt | charged as a FAILED attempt; retries continue on backoff; give-up log still fires |
| 5 | telemetry flush | a fault committing a denial-aggregate window | contained; window stays uncommitted; next tick retries |
| 6 | telemetry export | a fault reading the encrypted spool or in the archive exporter (data this process does not author) | contained; durable cursor unadvanced; spool intact; next tick retries the same batch |

Scenario 1 is the real nil-VALUE class CHAOS-117 fixed in the cluster roster,
in a list this process builds itself — which is why it is the fault the
regression test injects (§5).

---

## 3. CHAOS-117 §8.3 — swept, and clean

§8.3 asked whether the nil-VALUE class exists in other persisted pointer maps,
with the discriminating question: *does a detached goroutine dereference it?*
The sweep was run over every `map[K]*T` and `[]*T` that is decoded from
on-disk or wire JSON. **Every one is already defended**, and this is reported
with the code path that defends it rather than as an absence of evidence:

| Persisted pointer collection | Defence |
|---|---|
| `ClusterState.Nodes` / `.Tokens` (`enrollment.go:52-53`) | `normalizeClusterState` — CHAOS-117 |
| `persistEnvelope.Sessions` (`internal/policylearn/store.go:47`) | `validateSessionRecord`: `if s == nil \|\| s.ID == "" …` rejects, quarantine path |
| `persistEnvelope.Recommendations` (`store.go:48`) | `decodeEnvelope`: `if r == nil \|\| r.ID == "" …` rejects |
| `Aggregate.Cells` (`internal/policylearn/aggregate.go:88`) | `validateSessionRecord` walks `s.Agg.Cells` and rejects a null cell **by name** |
| `persistedStore.Approvals` (`internal/mcp/tooltrust/store.go:29`) | `buildLoadedIndexLocked`: `if a == nil { return … "nil approval record" }` |
| `ConfigSnapshot.IdPProfiles` (`controlplane_snapshot.go:108`) | `validateIdPProfile` rejects nil; `ReplaceAll`'s `discardCandidateEpisodeLocked` guards nil explicitly — a fix made for this exact reason (Codex round 4: "one `null` in idp_profiles took the node down") |

Two near-misses worth recording, because a sweep that only matched struct
fields would have missed both: `idpMetadata.episodes`
(`map[string]*idpMetadataEpisode`) is a **package-level** pointer map read by a
detached ticker — it is in-memory only, never decoded, and the sweep checks
`ep == nil` anyway; and `idpServed` is `map[string]idpServedDoc`, a **value**
map, so it has no nil-value case at all. `healthcheck.go`'s `Checks` map is
built in-process, and `cmd/rootshard` / `cmd/cireport` are CI tools outside the
gateway.

**The class is closed at every persisted boundary.** What this sweep does *not*
establish is that no in-memory pointer map is dereferenced unguarded by a
detached goroutine; scenario 1 above is precisely such a case, and the answer
to it is the guard, not normalisation.

---

## 4. What the fix cost, and what it did not change

- **No wire, persistence, API, config or metric-name change.** Five new crash
  components appear as label *values* on the existing
  `culvert_crash_records_total{component=...}` series:
  `syslog_health`, `idp_metadata_watchdog`, `inspection_ca_recovery`,
  `mcp_telemetry_flush`, `mcp_telemetry_export`.
- **No lock scope widened.** Every rescoped section holds its lock over exactly
  the statements it held before. `syslogFeedState`'s capture variables moved to
  the enclosing scope precisely so the post-release work is unchanged, and
  CHAOS-81's `TestChaos81_TheLiveCountersAreCapturedUnderTheRetirementLock`
  still proves the counter reads happen **under** the lock (§5).
- **One function was split**: `runIdPMetadataDegradationWatchdog`'s tick body is
  now `idpMetadataDegradationWatchdogRound`, so the detached loop has a single
  guarded call and the round can be driven directly by a test.
- **Two existing gates were corrected, not relaxed**, and both corrections were
  mutation-validated to still catch their original defect (§5).

---

## 5. Verification

Toolchain `go1.27.4` (the `go.mod` `toolchain` pin; `go env GOVERSION` agrees).
Note that `docs/agent-context/workflows/verification.md` still states
`go1.27.3` — stale prose, and the source pin governs per the evidence order.

Run: `go build ./...` clean; `go vet ./...` clean; `go mod tidy -diff` clean;
`python3 docs/agent-context/check.py` exit 0; targeted suites
`-run 'Syslog|syslog|Chaos81'`, `-run 'IdP|Idp|idp|Chaos87|Chaos55'`,
`-run 'CA|RootCA|Telemetry|telemetry|MCP'` and
`-run 'TestCHAOS118|TestCHAOS105|TestCHAOS117'` all pass.

**Every gate was validated by mutation.** A test that passes on the fixed tree
proves nothing until it fails on the broken one:

| Mutation | Gate that caught it |
|---|---|
| A. `commitSyslogDegradation` reverted to trailing `Unlock` | `TestCHAOS118_GuardedRoundCriticalSectionsReleaseDeferred/commitSyslogDegradation` |
| B. `syslogFeedState` reverted to trailing `Unlock` | `TestCHAOS118_SyslogWatchdogRoundPanicDoesNotWedgeTheHealthRecord` — reported the wedge in 20 s |
| C. `idpStaleCeilingSweep` reverted to trailing `Unlock` | `…CriticalSectionsReleaseDeferred/idpStaleCeilingSweep` |
| D. `exportLoop` guard removed | `TestCHAOS105_EveryRegisteredWorkerRoundIsGuarded/exportLoop` **and** the CHAOS-118 equivalent |
| E. CA panic branch drops `attempted = true` | `TestCHAOS118_CARecoveryPanicIsChargedAsAFailedAttempt` |
| F. counter reads moved OUT of `syslogFeedState`'s section | `TestChaos81_TheLiveCountersAreCapturedUnderTheRetirementLock` (after correction) |
| G. `idpStaleCeilingSweep` reverted, probed **behaviourally** | **NOT caught** — recorded deliberately; see §5.2 |

Two findings came out of that process and are the most useful part of this
section.

**5.1 The first version of the lock-wedge test hung the package instead of
reporting.** Mutation B detected the wedge at the 10 s probe and called
`t.Fatalf` — and then `t.Cleanup(resetSyslogHealthForTest)` took the same
wedged global mutex and blocked forever. The run died at the 600 s timeout with
a goroutine dump instead of a diagnosis: the test reproduced the very silent
stall it exists to report. Both probes now return a verdict instead of calling
`t.Fatal`, the caller returns early rather than running assertions that would
block on the same lock, and the global resets go through a deadline-bounded
helper. Mutation B now fails in 20 s naming the lock.

**5.2 The injected fault has to land INSIDE the critical section, and the first
version's did not.** A panic raised after the release cannot distinguish the fix
from the defect — and neither can one contained by a *function-level* `defer`,
because deferred calls still run while a panic unwinds. The §8.2a trap is
specifically a panic between a `Lock` and a **trailing** `Unlock`. The test
therefore injects the real nil-handle fault from scenario 1, which faults inside
`syslogFeedState`'s section.

The IdP side was pushed as far as it goes and then stopped, and **mutation G
records where that is.** The test was first written with the fault in the alert,
which aborts the round before the ceiling sweep ever acquires `idpServedMu` — so
the probe passed whatever that sweep did with its lock. It was then strengthened
to seed *both* halves of the round (an episode past the degradation threshold and
a served document past the staleness ceiling) and to inject the fault in the
**retirement**, which runs after both sweeps, with assertions that each sweep
actually selected something so neither probe can be vacuous. Mutation G then
reverted the sweep to a trailing `Unlock` — and the test still passed, because a
sweep that returns normally runs its trailing `Unlock` on the way out. Neither
IdP sweep has an injectable call inside its critical section (both iterate their
own in-memory state, and `idpStaleCeilingSweep`'s only in-section call is a
method on a **value**), so there is no fault to place there without adding a seam
to production code for a test's benefit. The deferred release in those two
sweeps is therefore pinned by the source gate (mutation C), and the behavioural
test's honest claim is the narrower one: the round as a whole leaks neither lock.
The syslog half has no such gap. This is stated in the test's own comment rather
than papered over.

**5.3 Two existing gates needed correcting, and both are now stricter.**

- `TestChaos81_TheLiveCountersAreCapturedUnderTheRetirementLock` compares the
  **source position** of the counter reads against the position of the `Unlock`
  call. A deferred release sits at the *top* of its section, so the gate read a
  correct refactor as a violation. It now resolves the real **release
  boundary**: for a deferred release, the closing brace of the func that owns
  the defer (the closure); for a bare call, the call itself. Mutation F confirms
  a read moved out of the section is still caught — the gate models Go's
  semantics now instead of approximating them.
- `TestChaos87_WatchdogEnforcesTheCeilingAndReArmsRecovery` scanned the
  watchdog's text for five required calls, which moved into the split-out round.
  It now pins the **whole chain**: the loop must invoke the round, and the round
  must make all five calls. Moving the calls out of the round no longer
  satisfies it, and neither does a loop that stops calling the round.

The full Deep determinism command
(`TEST_SEED=20260421 go test -count=2 -shuffle=on -timeout=20m ./...`) was
launched; its result is recorded in §8. **Not run:** the `-race` coverage
diagnostic, the `benchgate` lane (no gate added or touched), `make api-verify`
(no API change), the frontend tree, and `cmd/culvert-maint` — none is reached by
this diff. A passing local selection is not a passing hosted gate.

---

## 6. Operational, security and data-integrity impact

- **Customer impact:** removes five whole-gateway outage triggers. Before:
  one fault in a reporting round dropped every tunnel on the node. After: one
  interval lost and a counter moves.
- **Security:** the CA decision is the load-bearing one. A panicking recovery
  attempt can no longer be mistaken for a *successful* one, which would have
  left SSL inspection disabled — inspect-matched TLS forwarded uninspected —
  while the loop exited believing it had recovered. The IdP watchdog keeps
  enforcing the metadata staleness ceiling, so an expired document still stops
  being served rather than the enforcer dying.
- **Data integrity:** unchanged by construction. The telemetry export's durable
  cursor still advances only after the archive accepts a whole batch, so a
  contained panic leaves the spool intact and the batch retryable; a contained
  denial flush leaves the window uncommitted for the next tick.
- **Monitoring:** each round reports under its own component on the existing
  `culvert_crash_records_total` series, plus the system-actor audit entry and
  log line the crash plane already emits. No new surface.

---

## 7. Also reached this round, NOT fixed

**7.1 `telemetryRuntime.Close` drains from an unguarded detached goroutine.**
*(source-verified)* `Close` runs `t.mgr.FlushDenialsForce` and
`t.drainPartition` inside its own `go func()`, so a panic there is still
process-fatal — it turns a graceful shutdown into a crash and loses the final
flush. Deliberately out of scope: CHAOS-116 §8.2 named the two ticker loops, the
blast radius is a shutdown that was already terminating, the evidence is already
durable in the encrypted spool, and widening this diff into shutdown ordering
carries its own risk. `drainPartition` would terminate under a guard (it stops
on no cursor progress), so the fix is small; it wants its own round.

**7.2 `chaos105Workers` is now an eleven-worker hand-written list.** CHAOS-116
§8.2's call for a **mechanical** discovery gate — one that finds every
`go`-detached loop in the package and fails if it is not registered — still
stands, and the list growing from six to eleven is the argument for it. A worker
added tomorrow is invisible to every gate in this family until someone
remembers to add a row.

**7.3 The §8.2a audit has no mechanical equivalent either.** This round found
its four trap sites by reading each round's transitive callees for
`Lock`-without-`defer`. That is exactly the shape a linter or an AST wall could
assert over the registry: for every registered worker, no lock acquired in its
round's call graph may be released by a bare trailing `Unlock`. Without it, the
next worker guarded by someone who skips the audit reintroduces the inversion,
and the only gate is a reviewer remembering §8.2a.

**7.4 `UpdateNodeSeen` and `RegisterNode` still release `cs.mu` with a trailing
`Unlock`** (CHAOS-117 §8.4, unchanged). Still not reached from a guarded round,
so the trap still does not apply; still a problem the moment one of their
callers is guarded.

---

## 8. Residual risk

1. **A guarded round can now fail forever while the node reports healthy.**
   This is the intended trade and the same one CHAOS-117 recorded: a transient
   fault costs one interval and self-heals. But a *persistent* fault now
   produces a node whose SIEM health, IdP staleness enforcement or evidence
   export is frozen while `/healthz` stays green. The crash counters are the
   signal and **no alert rule ships on them** — the series is cumulative and the
   rule belongs with the operator's alerting, consistent with CHAOS-116
   residual 4 and CHAOS-117 residual 5. The IdP watchdog is the sharpest case,
   because it is the supervisor that re-arms recovery: a round that panics every
   tick leaves SSO unrecoverable with the process up.
2. **The CA loop's panic branch consumes retry budget.** A round that panics
   deterministically now burns all `sched.budget` attempts on backoff and then
   logs give-up, where before it killed the process and a supervisor restart
   retried from scratch. That is the correct trade for an in-line gateway — the
   node keeps proxying — but an operator who relied on restart-on-failure as the
   recovery mechanism for this specific case gets a node that stays up with SSL
   inspection off instead. The give-up log already says exactly that and names
   the remedy.
3. **The IdP lock-release fix is pinned structurally, not behaviourally.** Per
   §5.2 there is no in-section fault seam in either IdP sweep, so mutation C
   caught the revert through the source gate rather than through an observed
   wedge. A future refactor that keeps the literal `defer idpServedMu.Unlock()`
   text while moving the real release elsewhere would satisfy the gate. The
   syslog half does not have this gap.
4. **§7.2 and §7.3 together mean this family of defects is still found by
   reading, not by CI.** Eleven workers are registered because eleven were
   noticed. The honest statement is that the *known* set is guarded and
   audited, not that the package contains no twelfth detached loop.
5. **The corrected CHAOS-81 gate now depends on resolving a defer's owning
   scope.** It models Go's semantics correctly for the shapes in this file
   (a defer inside a closure, and a defer at function level), and mutation F
   proves it still catches the defect. A more exotic arrangement — a release
   handed to a helper, or a conditional unlock — would defeat it, as it would
   have defeated the original position comparison.
