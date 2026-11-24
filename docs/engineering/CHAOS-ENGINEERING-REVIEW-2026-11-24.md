# Chaos engineering review — 2026-11-24

Reviewer: Culvert Chaos Engineer (automated round). Base revision `46b4ffa`
(`origin/main`), clean worktree at branch point.

Id claimed: **CHAOS-127**, in a committed placeholder row as commit one, before
any code, per the register's convention and checked against `origin/main`
rather than the working tree per its 2026-09-25 amendment. `CHAOS-126` was the
highest id anywhere on `origin/main` at `46b4ffa`. Of the open PRs (#2068,
#2067, #2066, #2065, #2063, #2060, #2058, #2054, #2052, #2051, #2048, #2047,
#2046, #2045, #2044, #2041, #2040, #2037, #2036, #2035, #2034, #2033, #2031,
#2029 and the Dependabot set) none is a chaos sweep and none claims a chaos id.

Scope: **the GeoIP country database's freshness plane, and the enumerating
gate that ends this class.** CHAOS-124 §9.1 left that gate explicitly *Open*,
and CHAOS-123 §9.4 proposed it first. This round takes both halves.

---

## 1. Executive summary

Five consecutive rounds found the same defect in a different body of security
intelligence, one body at a time: WK-5/CHAOS-59 (the threat feed had a
last-good value and no recency), CHAOS-108 (a feed loop the `feedsched` doc's
enumeration did not cover), CHAOS-123 (`culvert_blocklist_size` held through a
dead feed), CHAOS-124 (the ClamAV signature database had no age anywhere). Each
closed its own body and handed the class forward. This round closes the sixth
and builds the gate that was supposed to end it.

**CHAOS-127a (HIGH) — the only staleness judgement in the product was a line of
browser JavaScript.** The node already *learns* the answer: `readerBuildTime`
(`internal/geoip/geoip.go:83`) parses the `.mmdb`'s own `BuildEpoch` at load,
and `BuildTime()` is documented *"callers use this to surface staleness to the
operator (there is otherwise no signal that the loaded database predates a
country's IP allocations)"*. That comment is exactly right about the need. It
had **one** consumer — `apiGeoIPConfig` (`ui_security.go:2007`), which emits
`dbAgeDays` — and the judgement lived at `static/index.html:11428` (at the claim revision `46b4ffa`; it is line 11440 after this round added the comment above it):

```js
const stale = g.dbAgeDays > 90;
```

which paints a label amber inside a panel a human has to open. Measured on the
production path with a database built **1096 days ago**, loaded and serving:

| surface | reported |
|---|---|
| `/metrics` | 888 lines, **0** about the database |
| `/ready` | `geoip: ok` |
| `/api/diagnostics` | 51 rows, **0** about staleness |
| `/api/geoip` | `dbAgeDays: 1096` — correct, and read by nobody automated |

An enterprise SWG is watched by Prometheus and Alertmanager, and that path
could not see GeoIP currency in any form.

**CHAOS-127b (MED) — the remedy the product advised could not take effect.**
The GUI said *"stale, consider updating"*. An operator who does exactly that
observes nothing change. `InitGeoDB` is startup-only, and `TryDeferredLoad`
(`internal/geoip/deferred.go`) *"is deliberately NOT a reload"* — it publishes
only while no reader is loaded, so on a working node it is a no-op by
construction. Measured, with a current `.mmdb` written to the configured path:
`ArmDeferredLoad` returned **false**, `TryDeferredLoad` loaded **nothing**, and
the reported build date stayed at the three-year-old value. Nothing anywhere
said a restart was required.

**CHAOS-127c — the class-ending gate, which CHAOS-124 asked for and which
caught an error in its own first draft.** Eight bodies of security
intelligence, each declaring *either* its freshness series *or* a reasoned
exemption, with every declared series checked against the tree. Its first
draft declared `culvert_saas_feed_last_sync_timestamp_seconds` for the signed
SaaS feed; the gate failed, because that series is **retired** and
`urlcat_metrics_test.go` asserts its absence. The signed feed's real freshness
surface is `culvert_saasfeed_expires_in_seconds` — a publisher-stamped expiry,
which is the *strongest* primitive in the family, since staleness is a fact the
origin asserts rather than a threshold the consumer guesses.

**What makes this body different from the other five, and worse.** Every other
body on the list degrades because a *loop* dies — a fetch that stops, a
credential that expires, egress that gets blocked. Here there is no loop. The
file is placed on disk by hand, Culvert opens it once, and nothing in the
product or outside it ever touches it again. Decay is the **default state**, not
a failure mode, and it requires no attacker, no fault and no misconfiguration —
only time, and the absence of a habit.

---

## 2. Failure scenarios

| # | Scenario | Pre-round behavior | Expected |
|---|---|---|---|
| 1 | GeoLite2 installed at deployment, never refreshed; 3 years pass | serves lookups; every probe green; no signal anywhere automated | age and a stale flag on `/metrics`; a diagnostics row |
| 2 | Operator reads the GUI warning and replaces the file | nothing changes; reported age unmoved; no explanation | a row saying a newer file is on disk and a restart will pick it up |
| 3 | `.mmdb` with no `build_epoch` in its metadata | `time.Unix(0,0)` → a ~56-year "age" the product cannot stand behind | reported as *unmeasurable*, never as fresh |
| 4 | `.mmdb` dated in the future (corrupt metadata, or node clock behind) | negative age | reported as *unmeasurable*; small skew tolerated, not escalated |
| 5 | Node with GeoIP not configured (the default) | no series — correct | still no series, so a fleet-wide age rule is not silently satisfied |
| 6 | `destCountry` BLOCK rule against a prefix that changed country since the build | allowed, logged as the *old* country, rule counter normal | unchanged enforcement, but the staleness is now visible |
| 7 | Unauthenticated `/metrics` scrape | n/a | no path, no filename, no file I/O |

Scenario 6 is the one with teeth and is deliberately *not* fixed by this round:
nothing here changes a verdict. What changes is that the operator can see the
condition that makes verdicts untrustworthy.

---

## 3. Risk matrix

| Finding | Likelihood | Impact | Detectability (pre) | Severity |
|---|---|---|---|---|
| 127a — staleness invisible to every automated surface | **Certain** (it is the default state of any deployment that does not refresh by hand) | security control silently fail-open in both directions | none outside a human opening one GUI panel | **HIGH** |
| 127b — advised remedy inert, no restart hint | High (follows directly from acting on 127a's warning) | operator believes the control is fixed when it is not | none | **MED** |
| 127c — class had no gate | Certain (five rounds is the evidence) | the sixth body was found by a round, not by a test; a seventh would be too | n/a | **MED** |

Why 127a is HIGH rather than MED despite being "only observability": the
degradation it hides is an **enforcement** control moving in the fail-open
direction, with no bound on how far it drifts and no event that ever surfaces
it. The gateway is not wrong about anything it can check; it is confidently
right about a world that no longer exists.

---

## 4. Recovery assessment

| | |
|---|---|
| **Automatic recovery** | **None, and none is possible.** There is nothing to retry: no fetch, no schedule, no upstream. This is the one body in the family with no automatic path, and that is a property of the design rather than a gap. |
| **Manual recovery** | Two steps, and the second is the one that gets missed: replace the `.mmdb`, **then restart**. |
| **Why not a live reload** | GEO-1/CHAOS-64 (`internal/geoip/geoip.go`): the pointer swap is atomic, but `Close()` munmaps the backing buffer an in-flight lookup may still be reading — a `SIGSEGV`/`SIGBUS` that `recover()` cannot catch, that `crashguard.go` never sees, and that leaves no log line. Making the reader lifetime safe (hold the read lock across `db.Country`, reference-count, or never close) is a design change with an owner, not a rider on an observability round. |
| **Verification of recovery** | Now observable: `geoip_database_pending_restart` appears between step 1 and step 2 and disappears after it, which is the first time either step has had a confirmation signal. |

---

## 5. Operational impact

**Before:** an operator running Prometheus and Alertmanager — the documented
posture for this product — had no way to learn that a GeoIP database had aged
out. The information existed, in the right form, one HTTP call away, on a
role-gated endpoint nothing scrapes. The one place it was judged was a browser.

**After:** `culvert_geoip_database_stale == 1` is the condition with a
consequence, and `culvert_geoip_database_age_unknown == 1` is the lower-urgency
pair for "the staleness check is not running". Both are documented with the
alerting rules in
[`docs/operator/geoip-database-freshness.md`](../operator/geoip-database-freshness.md),
linked from the operator README beside the ClamAV equivalent.

**The trap in the data, recorded because it is easy to walk into.**
`culvert_geoip_database_age_seconds` reads `0` both for a database built this
morning and for one whose build epoch could not be read. Alerting on
`age_seconds` alone without `age_unknown` is the mistake, and it is the same
shape the ClamAV runbook warns about for its own family.

**No new operator setting.** The 90-day threshold is *kept*, not chosen: it is
what the GUI has always used, and the finding is that the judgement was in the
wrong **process**, not that it was the wrong number. A setting would need admin
API and GUI parity for a value an operator can threshold themselves off the
gauge.

---

## 6. Security impact

A `destCountry` rule is an enforcement decision, and a stale country database
makes it wrong in **both** directions — but the direction that matters is
fail-open. Every prefix that changed country since the build date is classified
as its former owner, so:

- traffic an operator configured to **block** is **allowed**, and
- traffic they configured to **allow** is **blocked**.

Both are silent and both are internally consistent. The request log records the
country Culvert believes. The per-rule hit counters move normally. There is no
error, no exception path and no anomaly to detect, because nothing failed —
the lookup succeeded against old data.

**The series that look like they would catch this do not.** `/metrics` carries
six `culvert_geo_*` series, so a reviewer grepping for GeoIP instrumentation
finds hits and concludes the plane is covered. `_warm_total`,
`_warm_dropped_total`, `_warm_failed_total`, `_warm_saturated` and
`_warm_inflight` all measure how *busy* the resolution path is. The sharpest
instance is `culvert_geo_policy_unresolved_total`, which counts country-scoped
evaluations that did not match because the country was **unknown** — the
failure mode of a *missing* database. A stale database is never unknown: it
resolves briskly and confidently, so this counter sits at **zero** through the
entire degradation it appears to watch.

This is the WK-5/CHAOS-59 and CHAOS-123 shape with a new twist. There, the
misleading signal was a stale last-good value. Here it is a *different question,
answered well* — which is harder to notice, because nothing about the series is
broken.

**No posture change.** No verdict, rule, matcher or loader behaviour changes in
this round. It is report-only by construction.

---

## 7. Shipped

- **`internal/geoip/freshness.go`** — `FileBuildTime(path)`, which reads a
  `.mmdb`'s embedded build epoch **without** publishing it as the live reader.
  It closes the reader it opens and nothing outside the call can hold it, which
  is the same safety argument `publishIfUnloaded` makes. The embedded epoch
  rather than the file's mtime, because mtime is wrong in both directions: a
  `cp -p` or an archive restore preserves it across a real data update, and a
  `touch` changes it across none.
- **`geoip_database_freshness.go`** — the plane:
  `culvert_geoip_database_loaded`, `_age_seconds`,
  `_build_timestamp_seconds`, `_stale`, `_age_unknown`, emitted **only** when a
  database is loaded; the `geoip_database_age` diagnostics row for the stale
  shape and for both unmeasurable shapes; and `geoip_database_pending_restart`.
- **`geoip_database_pending_restart`** — 127b's half. Fires when the file on
  disk carries a **newer** build than the reader being served, i.e. the
  operator has done their half and the node is waiting on a restart. Silent on
  every inconclusive shape (no path, unreadable file, either epoch
  unmeasurable, equal or older on disk), because reporting an unopenable file
  as a pending restart is the opposite of true — and that state already belongs
  to `geoip_database_for_rules` and `/api/geoip`'s `lastError`.
- **The GUI string** now says *"replace the `.mmdb` and restart to pick it
  up"*, and the comment above it records that the threshold is shared with the
  process and gated.
- **The enumerating gate** CHAOS-123 §9.4 proposed and CHAOS-124 §9.1 left
  open: eight bodies, each with exactly one of a freshness surface or a
  reasoned exemption (minimum length enforced, because `"N/A"` passes a gate
  and tells the next reader nothing), every declared series checked against the
  tree so a rename fails here rather than silently stopping a scrape.
- **`docs/operator/geoip-database-freshness.md`**, linked from the operator
  README beside the ClamAV runbook.

### Refused, with reasons

- **No alert.** ClamAV's staleness got one because definitions are
  hours-critical *and* because there is an event to close the episode on: an
  observed newer database. Neither holds here. Age is a monotone function of
  wall-clock time with no event to key an episode on, so a fire-once alert
  could only ever be cleared by a human replacing the file — and a condition
  that clears solely on human action is a ticket, not a page. It would fire
  once per node and sit open for the length of the maintenance. The gauges are
  the surface that was missing.
- **No live reload.** GEO-1, above. This is the correct owner decision to
  leave open, and the pending-restart row is what makes living without it
  bearable.
- **No readiness change and no fail-closed toggle.** A node with an old GeoIP
  database is a fully serving gateway. Ejecting it from a rotation because a
  hand-maintained file is behind converts a slow degradation into the
  customer's outage — the judgement `threatfeed_health.go`,
  `catfeeddb_health.go`, `blocklist_feed_health.go` and
  `clamav_signature_freshness.go` all record for their own planes.
- **No operator setting for the threshold.** See §5.
- **No file I/O at scrape time.** Every series reads the build timestamp
  already in memory. The on-disk comparison runs only on `/api/diagnostics`,
  whose documented side-effect contract already permits bounded read-only file
  access and which is role-gated. `/metrics` is commonly unauthenticated when
  `metricsToken` is unset, and a scrape that mmapped a ~9 MB database would let
  any scraper drive file I/O at this process once per scrape.
- **No API field, and so no OpenAPI/generated-client/committed-dist churn.**
  Moving the GUI's verdict to the backend response would have been tidier and
  would have bought only agreement between two surfaces that already agree on
  90 days, at the cost of dragging three drift gates into a round whose API
  shape is otherwise unchanged. The two are held together by a divergence gate
  that reads the JavaScript instead — which is strictly stronger than a shared
  field would have been, because it fails on a *drift* rather than relying on
  nobody re-deriving the number.
- **YARA rule-set age: still open, and correctly lower.** Recorded as a
  reasoned exemption in the gate rather than silently omitted. CHAOS-124 §9.3's
  argument holds: rules change only through Culvert's own admin API, so there is
  no out-of-process updater whose death would be invisible — which is the
  mechanism every other body on the list fails by. An "age" here would measure
  how long since an operator last edited their own detection content.

---

## 8. Required tests — shipped

`geoip_database_freshness_chaos127_test.go` (13 cases) and
`security_intelligence_freshness_gate_chaos127_test.go` (3 cases), plus
`internal/geoip/freshness_test.go` (3 cases) beside the owner.

| Group | Pins |
|---|---|
| The shape nothing could see | a 1096-day-old loaded database produces `stale=1`, the age series, and a row naming both the consequence and the restart |
| Quiet when healthy | a 3-day-old database: `stale=0`, **zero** rows — a plane that warns on a healthy node gets muted |
| Boundary | one second inside, exactly at, and one second past the threshold |
| Unmeasurable | absent epoch, zero time, future-dated: `age_unknown=1`, `stale=0`, `age_seconds=0`, `loaded=1`, a row distinguishing the two causes, and **never** reported fresh |
| Clock skew | 2 minutes of skew stays measurable and floors the age at 0 rather than going negative |
| Pending restart | fires when disk is newer; **silent** on six inconclusive shapes; never speaks with nothing loaded |
| Containment | no series at all without a database; no file I/O from a scrape (asserted by a seam that fails the test if reached, across four scrape shapes); no path or filename in the scrape body |
| Divergence oracle | reads `static/index.html` and fails if the GUI's threshold and the backend constant drift apart, or if the GUI grows a second judgement |
| Enumerating gate | every body classified; exemptions carry a mechanism, not a label; every declared series exists in the tree; GeoIP is no longer exempt |
| Owner package | `FileBuildTime` round-trips a real `.mmdb` epoch, refuses four unreadable shapes, and — the lifetime property — leaves the published reader and its lookups untouched while reading a *different* database off disk |

### Mutation testing

16 mutations. **15 caught immediately. One caught by nothing**, and it was a
vacuous assertion of exactly the kind these runs exist to find.

**M14 — the stale row's advice dropped the restart requirement, and the gate
passed.** The assertion was
`strings.Contains(strings.ToUpper(row.OperatorAction), "RESTART")`. The action
text references the sibling row by code, and that code is
`geoip_database_pending_restart`, which *contains the substring "restart"*. So
replacing *"and RESTART the proxy — a loaded database is never re-read"* with
*"and update the file"* — deleting every word of the advice this round's second
half exists to add — satisfied the check via an identifier. The gate now strips
the row code first and asserts on what remains, plus that the row says **why**
(`"never re-read"`), which is the part an operator acts on.

That is the general lesson, and it is not new to this round: an assertion that
searches for a *word* inside a string built from identifiers can be satisfied
by the identifiers. A mutation suite can only falsify the properties someone
thought to assert, and this one only found it because the mutation targeted the
prose rather than the logic.

The other fifteen: stale boundary `>`→`>=`; absent-epoch guard removed;
future-skew tolerance removed; emit-with-no-database; pending-restart
`After`→`!Equal`; age floor removed (negative age); `age_unknown` inverted;
stale arm short-circuiting the pending-restart row; pre-epoch timestamp passed
through as negative; empty-path guard removed; **threshold silently changed to
30 days (caught by the divergence oracle, which is the case it exists for)**;
`FutureDated` never set; the two unmeasurable arms swapped so the future case
is unreachable; the pending-restart action repeating the download step; and the
`loaded` gauge reporting measurability instead of presence.

---

## 9. Verification

Commands run at `4f25e3a` on branch `claude/serene-cerf-i3iw7v`:

| Check | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `go test ./ -count=1` (root, full) | **ok**, 477.3 s |
| `go test ./internal/... ./cmd/... -count=1` | **ok**, 133 packages |
| `go test ./ -run TestCHAOS127 -count=1 -race` | ok |
| `go test ./internal/geoip/ -count=1 -race` | ok |
| `golangci-lint run --new-from-rev origin/main` (v2.15.0, installed with the `go.mod` toolchain, the gate's own command) | **0 issues** |
| `golangci-lint run` full tree vs. the **same measurement on the base** | byte-identical aggregates (175 issues, all pre-existing) — required because `cyclop`/`funlen`/`gocognit` attribute to a function's declaration line, which `--new-from-rev` cannot see |
| `go run ./cmd/contractcheck impact -base origin/main` | *"No contract code paths are touched by this change."* |
| `python3 docs/agent-context/check.py` | exit 0 |

One lint finding was raised and fixed during the round: `revive` read
`freshness.go`'s file-level comment as `FileBuildTime`'s doc comment. The file
comment now sits above the imports with a conforming doc comment on the
function.

**Not run, and why:** the hosted Fast PR Gate, CodeQL, the frontend bundle
build and the committed-dist drift gates. This change adds no API field, no
generated-client surface and no frontend source, so the last two have nothing
to compare; the first two are hosted and a local pass is not a merge gate.

---

## 10. Residual risk

**The gate cannot discover a seventh body on its own, and this is the honest
limit of the class-ender.** There is no machine-readable registry of "things
this gateway enforces with externally-sourced data" to diff against.
`supportMetricRegistry` is a deliberately narrow support-health scope whose own
comment forbids it growing, and `internal/feedsched`'s enumeration is the one
CHAOS-123 already found incomplete (*"The doc counts THREE loops; the tree has
more"*). So a new intelligence input added with neither a freshness surface nor
a row in the gate still passes. What changed is that the question is now asked
in one place with the answer for every known body written down — the class is
**gated, not provably closed**, and a count is deliberately not asserted
because a count tells a reader something moved without telling them what (the
failure `AGENTS.md` records for the eager-import allowlist).

**The age is of the database this process LOADED, not of the file on disk.**
That is the right answer for enforcement — the loaded set is what lookups run
against — but it means "the operator's file is current" and "this node is
serving current data" are two questions, and the series answers the second.
`geoip_database_pending_restart` is what connects them, and it lives only on
`/api/diagnostics`; a fleet watched purely by Prometheus sees a stale gauge and
not the fact that the fix is already staged on disk.

**Nothing pages, by design.** §7 records the reasoning. The consequence is that
on a fleet with no `culvert_geoip_database_stale` rule configured, this round
changes nothing an operator will notice. The runbook gives the rule; a round
cannot make anyone deploy it.

**The 90-day threshold is inherited, not derived.** There is no local interval
to take a multiple of, because MaxMind's publishing cadence is not something
this process can read. Twice-weekly publication makes 90 days roughly two dozen
missed releases, which is a defensible place to draw the line and not a
measured one.

**A future-dated database is tolerated for 5 minutes and then declared
unmeasurable rather than stale.** That is the fail-safe direction (it does not
page), but a node whose clock is badly wrong has no staleness check at all,
visible only as `age_unknown 1` and a WARN row. Clock skew as a domain is
CHAOS-84's, and this plane deliberately does not re-report it.

**`uiCfgGeoIPDB` is read without synchronisation**, by the new pending-restart
check as well as by the pre-existing `apiGeoIPConfig`. It is assigned once in
`main` before any listener serves, and this round matches the established
pattern rather than introducing a lock for one reader. Carried forward as an
observation, not a defect: if that global ever becomes runtime-mutable, both
readers need revisiting together.

**Scenario 6 is untouched.** A `destCountry` rule evaluated against a stale
database still returns the wrong country, and nothing in this round changes
that. Making enforcement itself resilient to stale geo data is not an
observability problem and probably has no good answer; what it has now is a
signal.
