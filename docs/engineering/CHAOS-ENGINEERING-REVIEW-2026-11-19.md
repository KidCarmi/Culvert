# Chaos engineering review — 2026-11-19

Reviewer: Culvert Chaos Engineer (automated round). Base revision `491b963`
(`origin/main`), clean worktree at branch point.
[CHAOS-ENGINEERING-REVIEW.md](../../roadmap/CHAOS-ENGINEERING-REVIEW.md) stays
the index.

Id claimed: **CHAOS-124**, in a committed register row as commit one, checked
against `origin/main` rather than the working tree per the register's
2026-09-25 amendment. `CHAOS-123` was the highest id anywhere on `origin/main`
at `491b963`, and none of the ten open PRs (#1958, #1957, #1956, #1955, #1705,
#1549, #1548, #1536, #1528, #1526) is a chaos sweep or claims a chaos id.

Scope: **the freshness of the one body of security intelligence Culvert does
not fetch.** This round takes up the class the 2026-11-18 round (CHAOS-123)
handed forward in its §9.4, in these words:

> Apply the same audit to the remaining optional feeds. This round and
> CHAOS-108 have now each found the same class in a feed loop that the
> `internal/feedsched` doc's enumeration did not cover. The doc counts THREE
> loops; the tree has more.

---

## 1. Executive summary

The audit enumerated every periodic remote fetch in the tree. The four feed
loops are **done**, and this round changes none of them: `internal/feedsync`
exports `culvert_category_feed_last_sync_timestamp_seconds`,
`internal/threatfeed` exports `culvert_threat_feed_last_success_timestamp_seconds`
plus an alert, `internal/saasfeed` carries a nine-state machine with a
readiness row and the `culvert_saasfeed_*` family, and
`internal/blocklistfeed` got its plane last round. §9.4's expectation that the
remaining gap was "a feed loop the doc did not count" is **wrong**, and that is
the finding.

**CHAOS-124 (HIGH) — the fifth body of security intelligence this gateway
enforces is the ClamAV signature database, and it had no freshness surface of
any kind, because there is no loop in this repository to hang one on.**
`freshclam` updates definitions **out of process**, inside the
`clamav/clamav:1.4` container `docker-compose.yml` runs, which Culvert neither
starts, supervises, configures, nor can trigger. Four freshness rounds walked
past it for the same structural reason: every previous round found its gap by
auditing a loop, and this intelligence has no loop here.

**The node already knows the answer and threw it away.** `clamd`'s `VERSION`
reply is `ClamAV 1.4.1/27456/Mon Nov 03 09:21:33 2025`, and
`internal/clamav.parseClamVersion` has always split out that third field as
`DBDate`. `scan_signature_watch.go` asks for it **every five minutes**
(CHAOS-107, so a definition change flushes the verdict cache). At the claim
revision `DBDate` had exactly one consumer in the entire tree —
`secscan.go:844`:

```go
key := v.Engine + "/" + v.DBVersion + "/" + v.DBDate
```

an opaque change detector. **Nothing parsed it into a time.** `grep DBDate`
over all non-test Go returned six declaration/comment lines and that one key.
So no metric, no alert and no health row existed for signature **age**, and no
code path in the product could have computed one.

**The only surface that existed cannot reach the people who watch an SWG.**
`/api/security-scan/status` carries `clamav_version` as a raw string, added with
this recorded intent (`ENGINEERING_LOG.md:241`):

> AV currency is a first-order security signal. Surfacing engine + definition
> date lets an operator confirm freshclam is working without shelling into the
> container.

The intent is right and the delivery stops one step short: a date string on a
role-gated admin panel requires a human to open it, read it and do the
subtraction. An enterprise SWG is watched by Prometheus and Alertmanager, and
that path could not see AV currency in any form.

**Why every liveness surface stays green, by construction.** A stale database
is not a fault — it is a *healthy daemon with old knowledge*:

| Surface | What it actually tests | Stale database |
|---|---|---|
| `checks["clamav"]` (`healthcheck.go:420`) | `ClamAVStatus() == "connected"` — a PING | passes |
| `clamav_scan` diagnostics row | `strings.HasPrefix(status, "unreachable")` | silent |
| `scan_clam_error` alert | mid-request scan **errors** | never fires |
| Compose healthcheck | `clamdscan --ping 3` | passes |
| `culvert_scan_sigdb_invalidations_total` | definition **changes** | frozen — *and frozen on a healthy node too* |

That last row is the round's sharpest point and is the same mechanism twice
before: a last-good value that holds is not a freshness proxy, it is the thing
that makes the outage invisible. WK-5/CHAOS-59 recorded it for the threat feed
("the carry-forward fix was correct and also removed the only signal an
operator had") and CHAOS-123 recorded it for `culvert_blocklist_size`. Here a
node whose updater died three weeks ago and a node that is perfectly current
but has had no update in the last hour export a **byte-identical** value.

**It does not self-heal and a restart does not reveal it.** `clamav-db` is a
persistent volume and `restart: unless-stopped` brings the daemon back with the
same database. CHAOS-123 wrote "a restart reloads the same entries from disk,
so not even a reboot moves it" about the blocklist; the same sentence holds
here by a different route.

**No attacker is required.** `freshclam` stops for mundane reasons: egress to
`database.clamav.net` blocked by the very network policy this gateway is
deployed to enforce, DNS failure inside that container, a full
`/var/lib/clamav`, or an operator setting `CLAMAV_NO_FRESHCLAMD=true` — which
disables the updater outright and leaves a daemon that passes every probe
above. ClamAV's distribution has also historically refused updates to
end-of-life engines, so a pinned image tag ages into a non-updating state with
nothing changing on the customer's side.

**What degrades is specific and is not a cache.** The malware signatures
published since the database stopped moving are exactly the ones this gateway
now fails to detect, and it reports those bodies to users as **clean**.

Fixed here. §10 records what is not.

---

## 2. Failure scenarios

| # | Scenario | Pre-fix behavior | Expected | Post-fix |
|---|---|---|---|---|
| 1 | `freshclam` dies; daemon healthy, definitions 30 days old | Every surface green; `CLEAN` returned for anything only a newer signature catches | Visible and paged | `culvert_clamav_signature_stale 1`, `_age_seconds 2592000`, WARN row, one page (`TestStaleSignaturesAreObservable`) |
| 2 | `CLAMAV_NO_FRESHCLAMD=true` — updater never runs | Indistinguishable from healthy, forever | Same as #1 once past 48 h | Same as #1; runbook names this env var first |
| 3 | Definitions current (3 h old) | Green (correctly) | Green, no row, no page | No stale gauge, no row, no alert (`TestFreshSignaturesAreQuiet`) |
| 4 | Daemon answers `VERSION` with no parseable build date | Age unmeasurable and unreported; nothing said so | Reported as **unknown**, not fresh; no page | `_age_unknown 1`, own WARN row, no alert (`TestUnreadableBuildDateIsUnknownNotFresh`) |
| 5 | ClamAV host clock ahead of this node | Would be a negative age, below every threshold — silently passes | Clamped to 0 **and** flagged | `_future_dated 1`, own row, no page (`TestFutureDatedBuildDateIsFlaggedNotFresh`) |
| 6 | Node stale, then ClamAV host clock jumps forward | — | Episode must survive; skew is not a recovery | Episode held; no second page when clocks agree (`TestFutureDatedReadingDoesNotClearAnEpisode`) |
| 7 | Daemon goes unreachable while stale | Unreachability reported by three other surfaces | Freshness plane must not double-page, must keep last observation | Nothing fired; state retained; `_observation_age_seconds` discloses the frozen reading (`TestStaleAlertClearedOnlyByObservedNewerDatabase`) |
| 8 | Stale node polled 12× (one hour) | — | One page, not 12 | Exactly one (`TestStaleAlertFiresOncePerEpisode`) |
| 9 | Stale, then unreadable reply, then stale again | — | No second page for one unresolved fault | One page (`TestUnknownDateDoesNotClearAnEpisode`) |
| 10 | Recovery, then a later outage | — | Second outage must page | Re-armed; second episode pages (`TestStaleAlertClearedOnlyByObservedNewerDatabase`) |
| 11 | No local ClamAV (disabled, or sidecar mode) | — | Export nothing rather than zeros | Family absent; no row (`TestNoSeriesBeforeAnyObservation`) |
| 12 | `/metrics` scraped repeatedly | — | Must not dial the daemon | Cached observation only; no dial path exists from the writer |

---

## 3. Risk matrix

| Id | Severity | Likelihood | Detectability (pre-fix) | Blast radius |
|---|---|---|---|---|
| CHAOS-124 core — stale definitions unobservable | **HIGH** | **High** — ordinary ops: blocked egress, a disabled updater, an EOL engine | **None** via metrics/alerts; a date string on a role-gated panel | Every user of the node; undetected malware reported clean |
| 124-b — `_sigdb_invalidations_total` read as freshness | MED | Medium — it is the only ClamAV-definition series that existed | Actively misleading (identical on healthy and dead) | An operator believing they have coverage |
| 124-c — unmeasurable date read as fresh | MED | Low–Medium (older/odd daemons, no DB loaded) | None | Silent loss of the check itself |
| 124-d — clock skew clamping to "fresh" | LOW–MED | Low | None | Staleness check silently disabled while skew lasts |

---

## 4. Recovery assessment

**Automatic, and nothing in Culvert needs touching.** The next five-minute poll
observes a newer database, the gauges move, the row clears, the episode ends,
and the verdict cache is flushed so `CLEAN` verdicts computed under the old
definitions are recomputed (the pre-existing CHAOS-107 reconciliation — which is
why an update takes effect for already-seen content too).

**Manual recovery is entirely ClamAV-side**, and the runbook orders the checks
by how these actually fail: updater running at all → container egress and DNS →
engine still supported → disk for the database → forced `freshclam --verbose`.
The row's `OperatorAction` names `freshclam` explicitly because "restart the
proxy" is the operator's wrong instinct here and would report the same thing.

**No recovery path was added for the thing Culvert does not own**, and that is
deliberate: this round adds observation, not a second updater.

---

## 5. Operational impact

- **Five new unlabelled series**, emitted only once an observation has landed,
  so a node without local ClamAV exports none of them. The scrape cost is a
  handful of integers from a cached struct.
- **No new dial anywhere.** `ObserveSignatures` replaces the
  `RefreshSignatures` call the watcher already made and returns the identity it
  used to discard, so a **down** daemon still costs one dial per poll rather
  than two. Every surface (metrics, diagnostics row, alert) reads the cached
  observation; `/metrics` is commonly unauthenticated when `metricsToken` is
  unset, and a scrape that could trigger a `VERSION` dial would let any scraper
  drive traffic at the daemon.
- **One new alert type**, `clamav_signature_stale`, with GUI parity
  (`static/index.html` webhook checkbox) and the registry comment in
  `internal/alerts/store.go`.
- **One new diagnostics row**, report-only and never gating.
- **Noise discipline:** one page per episode (the watcher polls 288×/day), one
  log line at onset then at most one per 6 h, one recovery line naming the
  suppressed count.

---

## 6. Security impact

**The gap was a detection control operating on old knowledge while reporting
success.** That is worse than an outage: an unreachable ClamAV is already
loudly reported as fail-open by three surfaces, so an operator knows scanning
is dark. A stale ClamAV returns a verdict, and the verdict is wrong in exactly
one direction — toward `CLEAN`.

**Posture is unchanged, deliberately.** The plane is report-only: no fail-closed
toggle, no readiness change. A node with stale definitions is a fully serving
gateway — policy, categories, DPI, YARA, CDR, the threat feed and the blocklist
all still apply, and ClamAV still catches everything its database knows.
Blocking traffic, or ejecting the node from a load balancer, because a
third-party updater is behind would convert a degradation into the customer's
outage: the judgement `threatfeed_health.go`, `catfeeddb_health.go` and
`blocklist_feed_health.go` each record independently.

**Information exposure was bounded in both new surfaces.** The metric family is
unlabelled — engine string and database counter stay on the role-gated
`/api/security-scan/status`, because as labels they would churn cardinality on
every definition update, which is several times a day on a *healthy* node, so
the cost would fall entirely on operators who have nothing wrong. The
diagnostics rows are viewer-readable, so they carry no daemon address
(`TestNoRowCarriesTheDaemonAddress`), matching what
`diagnostics_clamav_scan.go` already does with its probe error. The alert
`Detail` carries an age and a build date but not the engine string or raw
reply, which change on every upgrade and would weaken the `event+Detail` dedup
window.

**Fail-safe direction of the unmeasurable states.** An absent or unparseable
build date returns `ok=false` from `DBTime` and is reported as its own state.
Collapsing it to a zero `Time` would make every such daemon the oldest possible
database (paging on every reply shape the parse does not understand);
collapsing it to `time.Now()` would make every one permanently current. Both
are silent failures the caller cannot detect, which is why the decision is the
plane's and why `DBTime`'s boolean is documented as load-bearing.

---

## 7. Data-integrity impact

None. Nothing here writes persistent state, mutates configuration, or creates a
configuration version. The plane's entire state is one in-memory observation
plus two edge-trigger gates, and it is derived from a read-only `VERSION` query
the node already made.

---

## 8. Monitoring, logging and alert quality

**Before:** one raw date string on a role-gated JSON endpoint, and a change
counter that is identical on a healthy and a dead node.

**After**, against the four surfaces the previous rounds settled on as the bar
(metrics / alert / health row / last-success):

| Surface | Present | Note |
|---|---|---|
| `/metrics` | yes | `_timestamp_seconds`, `_age_seconds`, `_stale`, `_age_unknown`, `_future_dated`, `_observation_age_seconds` |
| alert | yes | `clamav_signature_stale`, once per episode, observed-evidence recovery |
| diagnostics row | yes | `clamav_signatures`, three distinct shapes |
| last-success | yes | `_timestamp_seconds` is the build time; `_observation_age_seconds` says how current the reading is |

**The series an operator should page on is `_stale`**, not `_age_seconds`.
`_age_seconds` is 0 both for a database built a minute ago and for one whose
date could not be read, which is why the two measurement gaps have their own
flags and why the runbook calls reading the age alone "the one mistake to
avoid".

**`_observation_age_seconds` exists because an age series can lie by freezing.**
A daemon that stopped answering reports the age its database had at the last
reading, forever. This series is the one that says so, and it is what lets an
operator separate "the database is old" from "my reading of it is old" — the
latter already being covered by three other surfaces, which this plane
deliberately does not duplicate.

---

## 9. Suggested improvements, in priority order

1. **A gate that enumerates every body of security intelligence and asserts
    each has a freshness surface.** CHAOS-123 §9.4 proposed this for *periodic
    remote fetches*; this round shows the right domain is wider than the loops,
    since the gap it found has no loop at all. A test over the intelligence
    inputs (feeds, AV definitions, GeoIP database, YARA rule set, category DB)
    asserting each exports an age or a last-success would end the class instead
    of retiring it one input at a time. Open.
2. **Sidecar signature identity.** The remote `/scan` protocol does not carry
    the sidecar's ClamAV identity, so the process-isolated deployment has no
    freshness signal at all. Needs a protocol field — an owner decision, not a
    rider. Open; see §10.
3. **YARA rule-set age.** Rules change only through Culvert's own admin paths,
    so there is no out-of-process updater to fail — but also no age anywhere,
    and `roadmap/CHAOS-REVIEW-2026-10-31.md:528` already noted "unlike
    `freshclam`, nothing updates those files on a schedule" as lower priority.
    Still open, and correctly lower.
4. **Durable freshness across restarts.** Not applicable here, and worth
    recording as the one place this round is structurally better off than
    CHAOS-123: the build date is a property of the *database on disk in the
    other container*, not of this process's memory, so a Culvert restart
    re-observes the true age within five minutes. CHAOS-123's residual risk
    (freshness resets to "never synced" on every boot) has no analogue.

---

## 10. Residual risk

**Sidecar deployments are not covered.** With body scanning delegated to the
remote scan service, this process holds no local daemon to ask, and the `/scan`
protocol carries a verdict, not a signature identity. `checkClamAVSignatures`
returns nothing in that mode rather than reporting a permanent "unknown" an
operator cannot act on, and the runbook says to monitor the sidecar's ClamAV
directly. Closing it properly means adding the identity to the scan protocol,
which belongs to `internal/secscan`'s owner.

**The plane observes what `clamd` reports, not the files on disk.** A daemon
that has loaded a database and not reloaded it after `freshclam` wrote a newer
one reports the loaded one — which is the honest answer for detection purposes
(the loaded set is what scans run against), but it means "freshclam is working"
and "the daemon is using what freshclam fetched" are two questions and this
plane answers the second. ClamAV's own `SelfCheck` handles the reload; a
divergence between the two would show up here as staleness, which is the
correct report.

**An unzoned build date is interpreted as UTC.** `clamd` formats with localtime
and the reply carries no zone, so a daemon in a non-UTC zone skews the computed
age by its offset — under 15 hours, against a 48-hour threshold, so it cannot
flip a healthy node to stale or the reverse by itself. It is recorded rather
than corrected because there is no field in the reply to correct it from.

**A reply shape the parse does not recognise reports "unknown", not stale.**
That is the fail-safe direction (it does not page), but it means a daemon whose
`VERSION` format this parse cannot read has no staleness check at all, visible
only as `_age_unknown 1` and a WARN row. Five layouts are covered and tested;
an unrecognised sixth degrades to a visible gap rather than a silent pass.

**The 48-hour threshold is absolute, not configurable.** There is no local
interval to take a multiple of, because `freshclam`'s cadence lives in another
container's configuration. An operator wanting tighter alerting uses
`culvert_clamav_signature_age_seconds` directly, which the runbook documents;
changing the constant was deliberately not made an operator setting, since a
new setting would need API and GUI parity for a value upstream's publishing
cadence already determines.

**Nothing pages for the two measurement gaps.** An unreadable or future-dated
date is a WARN row and a gauge, not a page, because paging on an inability to
measure would page on every daemon build the parse does not understand and on
every clock-skew episode. The residual risk is that a *persistent* measurement
gap is something somebody has to read rather than something that reaches them;
the runbook recommends a lower-urgency rule on the two flags for operators who
want it.

---

## 11. Tests

Eighteen new cases. White-box parse tests sit with their owner
(`internal/clamav`); the plane's behavioural gates sit at root beside it.

**`internal/clamav/version_dbtime_chaos124_test.go`** — the parse:
`TestDBTimeParsesObservedLayouts` (four day-padding shapes a real daemon
emits), `TestDBTimeZonedReplyKeepsItsZone`,
`TestDBTimeUnknownIsNotZeroAndNotNow` (five unparseable/absent shapes, pinning
that unknown is neither the epoch nor now).

**`clamav_signature_freshness_chaos124_test.go`** — the plane:

- the shape nothing could see: `TestStaleSignaturesAreObservable`,
  `TestFreshSignaturesAreQuiet` (negative control),
  `TestStalenessThresholdBoundary` (48 h pinned on both sides and at it);
- the unmeasurable shapes: `TestUnreadableBuildDateIsUnknownNotFresh`,
  `TestFutureDatedBuildDateIsFlaggedNotFresh`;
- alert discipline: `TestStaleAlertFiresOncePerEpisode`,
  `TestStaleAlertClearedOnlyByObservedNewerDatabase` (elapsed time, an
  unreachable daemon and a re-armed second episode),
  `TestUnknownDateDoesNotClearAnEpisode`,
  `TestFutureDatedReadingDoesNotClearAnEpisode`;
- containment: `TestNoSeriesBeforeAnyObservation`,
  `TestNoEngineOrVersionOnTheScrapeEndpoint`,
  `TestObservationAgeDistinguishesFrozenReadings`;
- the operator contract: `TestStaleRowNamesFreshclamAndTheConsequence`,
  `TestStaleRowDisclosesAFrozenReading`, `TestUnknownDateGetsItsOwnRow`,
  `TestFutureDatedGetsItsOwnRow`, `TestHealthyAndUnarmedProduceNoRow`,
  `TestNoRowCarriesTheDaemonAddress`.

`TestFutureDatedReadingDoesNotClearAnEpisode` was **verified to be a real
gate**: with the `!snap.FutureDated` guard removed it fails, reporting two
pages for one unresolved fault. The guard was added during this round after
the clearing path was found to treat a clamped-to-zero skew age as evidence of
recovery.

Clock is injected (`clamavSigNow`) and the alert sink is a package-level seam
(`fireClamAVSignatureStaleAlert`), so a 48-hour threshold and
fire-once-per-episode are asserted deterministically with no sleeps and without
racing the process-global alerts sink. Every test that touches the global
record registers `resetClamAVSigHealthForTest` via `t.Cleanup`, per the
repository's global-test-cleanup convention; that reset zeroes fields
individually rather than assigning a fresh struct, for the reason
`resetScanSvcHealthForTest` records.

### Checks run, at `b7d3a0c`

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | pass |
| `go test .` (full root package) | **pass**, 448.9 s |
| `go test ./internal/clamav/ ./internal/secscan/` | pass |
| `golangci-lint run --new-from-rev origin/main` (gate's own command, v2.15.0 via the `go.mod` toolchain) | **0 issues** |
| `golangci-lint run` full tree, branch vs. `origin/main` worktree | **174 issues on both, identical per-linter breakdown** — this change adds none |
| `go run ./cmd/contractcheck impact -base origin/main` | "No contract code paths are touched" |
| `python3 docs/agent-context/check.py` | pass (108 blocks, 490 navigation links, 117 route edges) |

The full-tree lint comparison was run because `cyclop`, `funlen` and `gocognit`
attribute to a function's declaration line, so `--new-from-rev` cannot see a
function made more complex. One finding the gate's own command *did* raise —
`gocognit` 40 on an over-large table-driven row test — was fixed by splitting
it into six focused tests, not suppressed.

**Not run:** the hosted Fast PR Gate and CodeQL, which are the authoritative
gates for the exact SHA; the e2e/browser suites, which this change does not
touch (the only UI change is one webhook-event checkbox); and any runtime
validation against a live `clamd`, which this environment has no daemon for —
the parse is covered by the layout table and the plane by injected
observations.

---

## 12. Suggested PR

Title: `fix(chaos124): observe ClamAV signature-database freshness`

One commit claiming the id, one implementing. Branch
`claude/serene-cerf-mzbtmq`.
