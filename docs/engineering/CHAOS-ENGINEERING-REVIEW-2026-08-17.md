# Chaos Engineering Review — 2026-08-17

**Domain:** the **boot path under a damaged data volume** — which startup faults
are fatal, whether they should be, and whether the process can even report the
ones that are not. Focused on the Layer-2 community category store
(`internal/catdb`, `urlcategories_startup.go`), the one BadgerDB on the boot
path that the shipped `docker-compose.yml` enables by default.
**Register items:** **ST-12** (recorded 2026-07-04, "catdb corruption-recovery
comment claims Badger truncate-on-corruption but `Open` sets no such option; a
corrupt community DB is fatal via ST-9 coupling") · **ST-9** (fatal startup
loads) · adds **CHAOS-50** and two previously unrecorded defects, one of which
is not recoverable by any caller-side error handling.
**Verdict:** four confirmed defects, all reproduced against `main` before a line
of the fix was written. Three fixed; the fourth is a posture decision recorded
for the owner.

---

## Executive Summary

CHAOS-05/07 settled the boot-path question for corrupt state and wrote the
answer down in `state_corruption.go`:

> boot still proceeds with an empty store, since both degradations are
> survivable … and **refusing to boot could take down a fleet on a single bad
> sector**.

That rule was applied to two JSON files — the admin roster and the cluster
roster — and stopped there. The store most likely to be left damaged by an
unclean kill got the opposite treatment, and it is not a close call:

| | `ui_users.json` | `cluster.json` | **community category store** |
|---|---|---|---|
| What it holds | admin accounts, TOTP secrets | node roster, revoked certs | **a cache of a downloadable feed** |
| Authoritative? | yes | yes | **no** |
| Corrupt at boot ⇒ | quarantine + continue | quarantine + continue | **`logFatalf` — process exits** |

So the appliance refused to boot over the *only* store on the path whose loss
costs nothing, while continuing to boot over the two that hold real state. And
it does so on the default configuration: `docker-compose.yml:152` sets
`-cat-feed-db /data/catfeeddb`, and the same service sets
`restart: unless-stopped`, so the fatal is not a one-off exit — it is an
unattended crash-loop with **no proxy, no admin UI, and no health endpoint**.
Recovery required someone with shell access on the host to know to delete a
directory. Culvert's own GUI-parity rule ("the admin must have full control from
the web interface") cannot be satisfied by an appliance that never starts.

Then the domain turned out to be worse than ST-12 recorded, in a way that no
amount of care at the call site could have fixed.

### `badger.Open` does not always return

A corrupt `.sst` table makes `badger.Open` **panic**, and it panics from a
goroutine badger itself spawns:

```
panic: runtime error: slice bounds out of range [-2779063644:] [recovered]
	panic: runtime error: slice bounds out of range [-2779063644:]
	panic:
	== Recovering from initIndex crash ==
	File Info: [ID: 1, Size: 32843, Zeros: 0]
	== Recovered ==

created by github.com/dgraph-io/badger/v4.newLevelsController in goroutine 21
```

`created by … newLevelsController` is the whole finding. A `recover()` at the
call site is on a different goroutine and never fires — proven live, not
inferred: the gate `TestOpenResilient_SurvivesUncatchableOpenPanicOnNextBoot`
runs a child process whose `defer recover()` wraps the open, and the child dies
with exit status 2 having printed nothing. Changing `logFatalf` to a
`return err` would have fixed **nothing** for this fault. The store had to stop
being handed to badger at all.

### The recorded fix for ST-12 does not exist any more

ST-12 says the code should set badger's truncate option. It cannot: badger v4
removed `Options.Truncate`. What survives is `ErrTruncateNeeded` — the error
badger returns when truncation is required and there is no longer any way to
authorise it. The doc comment on `catdb.Open` promised the opposite
("Truncate is enabled so a crashed container can restart without manual
intervention"), which is the most expensive kind of comment: it tells the next
reader that a failure mode is handled when it is not.

### Findings

| # | Failure mode | Class | Why the existing design did not cover it |
|---|---|---|---|
| FS-1 | A damaged Layer-2 store **exits the process at boot**, permanently | Recovery failure → total outage | The CHAOS-05/07 "keep booting" rule was never applied to this store; there is no declared principle for which boot loads are fatal |
| FS-2 | A corrupt `.sst` **panics out of a badger-spawned goroutine** | Uncatchable crash | No caller-side error handling can contain it; the only defence is not to open the directory |
| FS-3 | `catdb.Open`'s comment claims crash-truncation that badger v4 removed | False resilience claim | ST-12 recorded the option as missing; the option no longer exists to add |
| FS-4 | A degraded Layer-2 store is **invisible** — no metric, no diagnostics row, no alert | Silent failure | Nothing existed, because the store could never *be* degraded: it was fatal |

FS-1 and FS-2 compose into the worst shape in the register's §1 taxonomy — a
fault in an optional, non-authoritative component that takes down the whole
in-line appliance, unattended, with no path back through any interface the
product ships.

### Measured, against `main`

A temporary proof harness (removed before commit; its content is preserved as
the empirical table in `TestClassifyOpenError_EmpiricalBadgerMessages`) injected
each fault into a seeded store and called the production open path. badger
v4.9.6, the exact options `catdb.Open` uses:

| Injected fault | `badger.Open` result |
|---|---|
| `MANIFEST` scrambled | error — `Buffer length: 4294967295 greater than file size: 30. Manifest file might be corrupted` |
| `MANIFEST` truncated to 4 bytes | error — `manifest has bad magic` |
| `MANIFEST` emptied | error — `manifest has bad magic` |
| **`.sst` scrambled** | **PANIC from `newLevelsController`'s goroutine — process dies, exit 2** |
| `.sst` deleted | error — `file does not exist for table 1` |
| `KEYREGISTRY` scrambled | error — `Encryption key mismatch` |
| value log scrambled | opened cleanly (badger tolerates it) |
| directory lock held by a live process | error — `Another process is using this Badger database` |
| path is a regular file (bad mount) | error — `… not a directory` |

And end to end, through the real loader, in a child process:

```
[test] CatFeedDB → cannot open BadgerDB at …/catdb:
       Buffer length: 4294967295 greater than file size: 30. Manifest file might be corrupted
child exit err: exit status 1        ← the gateway did not boot
```

**Not one of those errors is reachable through `errors.Is`.** badger wraps them
with `y.Wrapf`, which implements no `Unwrap`, so `errors.Is(err, badger.ErrTruncateNeeded)`,
`errors.Is(err, y.ErrChecksumMismatch)` and `errors.Is(err, badger.ErrEncryptionKeyMismatch)`
all return false for the faults that produce exactly those conditions. That is
recorded because it constrains the fix: message matching is the only mechanism
available, and a fix that *relies* on it to authorise destroying data would be
building a rename on a string comparison against a third-party library's
wording.

---

## Failure Scenarios

### FS-1 — a damaged store stops the appliance from starting

**Current behaviour (pre-fix).** `loadURLCategories` →
`logFatalf("CatFeedDB → cannot open BadgerDB at %s: %v", …)` → `os.Exit(1)`.
Under `restart: unless-stopped`, the container restarts and exits again,
forever.

**Expected behaviour.** The store is a cache. Every consumer of `communityDB`
already nil-checks it (`policy.go:1592,1621`, `ui_policy.go:947`,
`main_shutdown.go:259`), so a nil store is byte-identical to running without
`-cat-feed-db`. The gateway should boot on Layer 1 and say so.

**Failure mode.** Total outage of an in-line appliance. Every client behind it
loses egress.

**Recovery path.** Pre-fix: manual, and only for someone with a shell on the
host who knows the directory to delete. The admin UI is part of the same
process, so the product's own recovery interface is down.

**Customer impact.** Complete. **Security impact.** No egress inspection, but
also no egress — fail-closed by accident rather than by design.
**Monitoring visibility.** One log line on a process that is exiting.

### FS-2 — the fault badger will not let you catch

**Current behaviour.** A corrupt `.sst` panics from `newLevelsController`'s
goroutine. `recover()` at the call site does not fire. The process dies with
exit 2 before any handler, log line, or metric runs.

**Expected behaviour.** The process must not be *given* a directory a previous
process died inside of.

**Failure mode.** Same as FS-1, plus it is immune to the obvious fix. A reviewer
who changed `logFatalf` to `return err` would reasonably believe the class was
closed; the worst instance of it would be untouched.

**Recovery path.** Pre-fix: none, ever, without shell access.

### FS-3 — a comment that says the failure mode is handled

`catdb.Open`'s doc claimed badger truncates a corrupted value log on open
"so a crashed container can restart without manual intervention". badger v4
removed the option that did that. The comment is the reason ST-12 sat at
severity **L** for six weeks: the register believed a missing option was the
whole gap.

### FS-4 — a degradation nobody can see

Once FS-1 stops being fatal, the store can be *absent* — and an absent Layer-2
tier silently changes policy outcomes (a category rule sourced from the
community feed stops matching, so traffic falls through to the next rule or to
default-deny). With no signal, an operator debugging "why did this allow rule
stop matching?" has nothing to look at.

---

## Risk Matrix

| Risk | Finding | Likelihood | Impact | Priority | State |
|---|---|---|---|---|---|
| R-A | FS-1 fatal boot on a damaged Layer-2 cache | **Medium-High** — `docker kill`, OOM, host power loss, and failing volumes are routine; the store is on by default in the shipped compose file | **Critical** — total outage of an in-line gateway, unattended crash-loop, no GUI recovery | **P0** | **FIXED** |
| R-B | FS-2 uncatchable panic during open | Medium — needs a torn table specifically, but that is what an interrupted compaction produces | **Critical** — same outage, immune to caller-side handling | **P0** | **FIXED** |
| R-C | FS-4 degradation invisible | High (once FS-1 is fixed, every occurrence) | Medium — wrong policy outcomes with no signal | **P1** | **FIXED** |
| R-D | FS-3 false resilience claim | — | Medium — misdirected the register for six weeks | **P2** | **FIXED** |
| R-E | The same panic reaches `internal/logstore` | Low-Medium — opt-in store, but also reachable from the admin API | High | **P1** | **RECORDED** (see Residual Risk) |
| R-F | `categories.json` / blocklist / policy file are fatal-on-corrupt with no quarantine | Low | High | **P2** | **RECORDED** — posture decision, owner call |

---

## Recovery Assessment

| Scenario | Before | After |
|---|---|---|
| Torn `MANIFEST` (unclean kill) | **None.** Permanent crash-loop until an operator with shell access deletes the directory | **Automatic, same boot.** Quarantine → re-create → the syncer refills it |
| Corrupt `.sst` (interrupted compaction) | **None**, and immune to caller-side error handling | **Automatic, next boot.** The poison marker quarantines the directory before badger touches it; `restart: unless-stopped` makes this seconds |
| Volume missing / read-only / full / no permission | **None.** Same crash-loop | **Automatic degradation.** Boots on Layer 1, reports the degradation, self-heals when the volume is fixed and the node restarts |
| A second process holds the store | **None.** Crash-loop | **Degrades and refuses to quarantine** — the live store is never renamed out from under its owner |

Manual recovery is now required for exactly one thing, and it is not urgent:
deleting the quarantined `.corrupt.*` copy to reclaim disk. The number of copies
is bounded at one, and its presence is reported on `/api/diagnostics` and
`/metrics` until it is gone.

**The design decision worth recording** is *why* automatic re-creation is safe
here and would not be elsewhere: this store holds no authoritative state. Its
entire content came from a feed the node can download again, and
`feedsync.Start` already performs an immediate sync when it finds the store
empty (`internal/feedsync/feedsync.go:177`). Re-creating it costs one feed sync.
The same mechanism applied to a store with authoritative content would be data
destruction, which is why the quarantine *moves aside* rather than deletes, and
why extending it to `internal/logstore` is deliberately not done here.

---

## Operational Impact

No new CLI flag, YAML key, environment variable, or admin API field is
introduced, so the GUI-parity rule is satisfied by the surfaces that already
exist. Everything rides existing operator vocabulary:

| Surface | Signal | Change |
|---|---|---|
| `/api/diagnostics` | `category_feed_db` operator-contract row | **new row**; `ok` when unconfigured or clean, `warn` for recovered / unreconciled evidence / unavailable. Never `fail` |
| `/metrics` | `culvert_catfeeddb_available`, `culvert_catfeeddb_recovered`, `culvert_catfeeddb_quarantined_copies` | new |
| Alerts | `state_file_corrupt` | **reused, not renamed.** The event already means "corrupt state quarantined at startup" and the operator action is identical. A second event name for the same action would be the drift CHAOS-49 warned about |
| Logs | `CatFeedDB: … quarantined to … / cannot open the community store at … — continuing with admin-managed categories only (Layer 1)` | new |
| Runbook | `docs/operator/category-store-recovery.md` | new |

**Deliberately NOT wired into `/readyz`.** A node running Layer-1-only
categorisation is fully able to serve traffic — it is exactly the posture of a
node started without `-cat-feed-db`. Failing readiness would pull a healthy
gateway out of a load-balancer rotation over a degraded cache, which is the
availability mistake this whole review is about, committed one layer up.

**The diagnostics row carries no raw cause.** `/api/diagnostics` is a
viewer-role surface with a standing no-sensitive-values guardrail (the CHAOS-28
`root_ca` precedent), so the row names the impact and the action; the store
path and the badger error stay in the logs and the alert. Pinned by
`TestCheckCategoryFeedDB_RowCarriesNoRawCause`.

---

## Security Impact

- **Availability of the appliance is a security property.** An in-line gateway
  that will not start is not "failing closed" in any useful sense — the traffic
  it was inspecting is now being carried by whatever the network does when the
  proxy is gone, and the operator's first instinct under pressure is to route
  around it.
- **The degradation is fail-closed at the policy layer.** A missing Layer 2
  means a community-sourced category does not match, so an *allow* rule keyed on
  one stops matching and traffic falls to default-deny; a *block* rule keyed on
  one stops matching and traffic falls to the next rule and ultimately to
  default-deny. Neither direction opens egress that policy did not already open.
- **No new data-destruction capability.** Recovery renames; it never deletes a
  store it has not first moved aside. The only `RemoveAll` is the prune of a
  *previous* quarantined copy, bounded at one.
- **The rename cannot be aimed at a live store.** Every quarantine is gated on a
  non-blocking exclusive `flock` of the directory — badger's own lock
  (`badger/dir_unix.go`) — so a concurrent boot that is still inside its own
  open vetoes the quarantine. Pinned by
  `TestOpenResilient_NeverQuarantinesAStoreAnotherProcessHolds`, which asserts
  the holder's data survives.
- **The classifier cannot authorise destruction on its own.** The environmental
  deny-list is consulted before the corruption allow-list, and anything
  unrecognised degrades. A badger upgrade that changes its wording therefore
  fails *safe* (no recovery) rather than *open* (an unjustified rename).

## Data Integrity Impact

The only state this change can affect is a store that already cannot be read.
Nothing authoritative is touched: Layer 1 (`categories.json`), the policy store,
the blocklist, and every other data file are untouched by this path. The damaged
copy is preserved on the volume under `<dir>.corrupt.<unixnano>` — the same
naming convention CHAOS-05/07 established — for as long as the operator wants
it.

One accepted trade: a `SIGKILL` that lands *inside* `badger.Open` for an
unrelated reason (an operator killing a container during startup) leaves a
marker, and the next boot quarantines a store that was probably healthy. The
cost is one feed re-sync and one directory of disk, both bounded and both
reported. Making that impossible would require knowing *why* the previous
process died, which the marker cannot tell us — and the alternative default
(assume the store is fine) is the pre-fix behaviour that never recovers.

---

## Suggested Improvements (ranked, and what this PR does)

1. **Stop exiting over a cache** — done (FS-1).
2. **Detect the fault badger will not report** — done (FS-2), via a marker armed
   around every open attempt.
3. **Make the degraded state visible** — done (FS-4).
4. **Fix the comment that misdirected the register** — done (FS-3).
5. **Extend the marker to `internal/logstore`** — *not* done. Same badger call,
   same options, same panic; but the log store holds request history with
   retention/compliance semantics, so "quarantine and re-create" is a posture
   decision about evidence, not a mechanical fix. Recorded as R-E.
6. **Decide the boot-fatality principle for the remaining three loads** — *not*
   done. `categories.json`, the blocklist, and the policy file are all
   fatal-on-corrupt with no quarantine, while `ui_users.json` and `cluster.json`
   quarantine and continue. Recorded as R-F; it needs an owner, not a patch.

## Suggested PR (this PR)

```
internal/catdb/resilient.go        OpenResilient + poison marker + classifier + quarantine
internal/catdb/dirlock_unix.go     flock probe (mirrors badger/dir_unix.go)
internal/catdb/dirlock_other.go    fail-safe stub for non-unix builds
internal/catdb/catdb.go            corrected Open doc (FS-3)
urlcategories_startup.go           loadCommunityFeedDB — degrade, never exit
catfeeddb_health.go                boot-outcome record + category_feed_db contract row
diagnostics.go                     register the row
metrics.go                         three culvert_catfeeddb_* series
docs/operator/category-store-recovery.md
```

---

## Required Tests

All present, and every one of them was checked to **fail** against the pre-fix
behaviour before being accepted.

`internal/catdb/resilient_test.go`:

| Test | Pins |
|---|---|
| `TestOpenResilient_SurvivesUncatchableOpenPanicOnNextBoot` | FS-2 end to end, in child processes: boot 1 dies with `recover()` never firing, the marker survives, boot 2 quarantines and comes up. Verified to fail (`boot 2 did not recover … exit status 2`) with the marker check stubbed out |
| `TestOpenResilient_CorruptManifestQuarantinesAndRecoversInOneBoot` | FS-1 for the returned-error family; evidence is kept, the replacement is empty, the marker is cleared |
| `TestOpenResilient_PoisonMarkerQuarantinesBeforeTouchingTheStore` | the marker acts *before* badger, and clears itself so it cannot re-fire |
| `TestOpenResilient_NeverQuarantinesAStoreAnotherProcessHolds` | **the safety gate** — a live lock holder vetoes the rename and its data survives |
| `TestOpenResilient_EnvironmentalFailureDegradesWithoutQuarantine` | a bad mount degrades and leaves the disk alone |
| `TestOpenResilient_QuarantinedCopiesAreBounded` | four corruption rounds leave at most one copy |
| `TestOpenResilient_ResidualQuarantinesAreReported` | evidence stays visible on the boot *after* the self-heal |
| `TestOpenResilient_CleanOpenLeavesNoTrace` / `_FirstRunCreatesTheStore` | the normal paths are untouched |
| `TestOpenResilient_MarkerIsASiblingNotAChild` | a quarantine cannot carry the marker away with it |
| `TestClassifyOpenError_EmpiricalBadgerMessages` | the full fault → message table above, so a badger upgrade that reworded them fails here |
| `TestClassifyOpenError_EnvironmentalWinsOverCorruption` | the deny-list is evaluated first — a message containing both signals can never authorise a rename |

`urlcategories_startup_chaos_test.go`:

| Test | Pins |
|---|---|
| `TestLoadCommunityFeedDB_DamagedStoreDoesNotKillTheProcess` | FS-1 in a child process, so a regression is observed as the exit it actually is. Verified to fail when `logFatalf` is reinstated |
| `TestLoadCommunityFeedDB_SourceHasNoFatalExit` | the executable negative assertion — `loadCommunityFeedDB` may not contain `logFatalf`/`log.Fatal`/`os.Exit` |
| `TestLoadCommunityFeedDB_EnvironmentalFailureDegradesToLayer1` | nil store, nil syncer, no quarantine, warn row |
| `TestLoadCommunityFeedDB_CorruptStoreSelfHealsAndKeepsServing` | store up, syncer started, evidence kept, warn row with an operator action |
| `TestLoadCommunityFeedDB_HealthyStoreIsQuiet` | no warn noise on a clean node |
| `TestCheckCategoryFeedDB_UnconfiguredIsOK` | most deployments never enable Layer 2 and must not see a row that looks like a problem |
| `TestCheckCategoryFeedDB_UnreconciledQuarantineStaysVisible` | the incident outlives the process that handled it |
| `TestCheckCategoryFeedDB_RowCarriesNoRawCause` | the viewer-role guardrail |
| `TestMetrics_CatFeedDBSeries` | the three series are emitted, including `available 0` on an unconfigured node — an omitted series is not something an alerting rule can key on |

---

## Residual Risk

- **R-E — `internal/logstore` has the same uncatchable panic.** `OpenTTL`
  (`internal/logstore/logstore.go:298`) calls `badger.Open` with the same
  options and the same badger version, so a corrupt table there kills the
  process the same way. Two differences bound it: the store is opt-in
  (`log_store_path` unset by default) and its *error* path is already
  non-fatal. Two differences make it worse: it is reachable from the **admin
  API** (`enableLogStore` via the GUI toggle and `LoadAdminSettings`), so an
  admin can kill the gateway by turning history on, and its content is request
  history with retention semantics — quarantining it silently is an evidence
  decision, not a cache decision. Recorded rather than fixed for exactly that
  reason.
- **R-F — the boot path still has three fatal data-file loads with no declared
  principle.** `catStore.Load` (`urlcategories_startup.go`), the blocklist
  (`blocklist_startup.go:59`) and the policy file (`main.go:724`) all exit on a
  corrupt file, while `ui_users.json` and `cluster.json` quarantine and
  continue — and `categories.json` is the closest analogue to those two, being a
  JSON state file the appliance writes itself. Deciding whether
  "policy-load-bearing" justifies refuse-to-boot (rather than boot-and-deny) is
  an owner call.
- **Recovery from the panic case costs one restart.** The marker cannot act
  until the boot after the crash. Making it zero-crash means probing the store
  in a child process before opening it in-process — genuinely better, and a
  reasonable follow-up, but a larger change than the fault warrants right now.
- **A spurious quarantine is possible.** A kill that lands inside
  `badger.Open` for an unrelated reason leaves a marker and costs one feed
  re-sync on the next boot. Accepted, bounded, reported, and preferable to the
  alternative default of never recovering. Documented in the runbook.
- **The classifier is coupled to badger's wording.** `errors.Is` does not work
  against any of these faults, so message matching is the only mechanism. It
  fails safe — an unrecognised message degrades instead of quarantining — and
  the empirical table is a test, so a wording change surfaces as a red build
  rather than as a store that quietly stops self-healing.
- **A store that keeps getting corrupted keeps getting re-synced.** There is no
  circuit breaker on repeated quarantines; a host with a dying disk will
  re-download the feed on every boot. The `culvert_catfeeddb_quarantined_copies`
  gauge and the diagnostics row are the operator's signal, but nothing in the
  process gives up.

## Deliberately Left Open

Unchanged from the prior review:

- **CHAOS-46** — config rollback vs. admin-settings durability (owner decision).
- **CHAOS-43** — OCSP fail-open when the issuer cert cannot be resolved.
- **CA-13** — cluster-CA rotation logs-and-returns on every failure branch.
- **CA-4's retry half** — a failed rotation still waits a full 24 h.
