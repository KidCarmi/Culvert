# Chaos engineering review — 2026-11-02

Reviewer: Culvert Chaos Engineer (automated round). Base revision `110bf9f`
(`origin/main`), clean worktree at branch point. Recorded separately for the
reason the previous five rounds were:
[CHAOS-ENGINEERING-REVIEW.md](CHAOS-ENGINEERING-REVIEW.md) stays the index.

Id claimed: **CHAOS-109**. Claimed in a committed placeholder row as commit one,
before any code, and checked against `origin/main` rather than the working tree
per the register's 2026-09-25 amendment. `CHAOS-108` was the highest id anywhere
on `origin/main` at `110bf9f`, and no open PR held a chaos id (#1794, #1793,
#1792, #1791, #1790, #1788, #1705, #1549, #1548, #1536, #1528, #1526).

Scope: **the feed-ingestion plane's byte budget.** CHAOS-106 (2026-10-30)
bounded decompression where Culvert expands traffic it is *inspecting*. This
round asks the same question one plane over — how many bytes is a third-party
feed origin allowed to spend inside the gateway process? — and takes up the
class the 2026-11-01 round left open in its §8.3, which recorded that no feed
loop caps its response body and handed the class to "a round that treats all
three". This is that round. It also **corrects** §8.3's severity for one loop.

---

## 1. Executive summary

`internal/feedsync` downloads a 50+ MB gzip tarball from
`raw.githubusercontent.com/NethServer/toulouse-bl-mirror`, expands it
in-process on every node, and builds a `map[string]string` of
domain → category. Before this PR the only bound on how much that origin could
spend was `feedSyncHTTPTimeout`, five minutes. The loop carried two things that
look like bounds. Neither is one.

**CHAOS-109a (HIGH) — the entry cap was charged per archive MEMBER, so an
origin stepped around it by repeating a path.** `maxDomainsPerCategory`
(2,000,000) is commented "caps ingestion to limit memory during bulk build",
but `count` is a local in `parseDomainFile`, reset on every call, and tar
permits the same member path any number of times. Measured: 40 duplicate
`blacklists/malware/domains` members of 50,000 domains each produced **exactly
2,000,000 live map entries** while no single member ever came near the cap. Even
honouring the cap's intent, 41 distinct category names × 2 M is a nominal
ceiling of **82 million** entries — on the order of 10 GiB of heap, so the
"bound" permitted an OOM on any realistic node before it could trip.

**CHAOS-109b (HIGH) — neither the compressed body nor its expansion was bounded
at all, and live-heap amplification is ~50×.** `gzip.NewReader(resp.Body)` had
no `io.LimitReader` on the compressed side and no ceiling on the expanded side.
Measured, and linear:

| compressed | live entries | live heap | amplification |
|---|---|---|---|
| 1.20 MiB | 500,000 | +51.6 MiB | 43× |
| 2.40 MiB | 1,000,000 | +113.0 MiB | 47× |
| 4.80 MiB | 2,000,000 | +262.3 MiB | 55× |
| 9.59 MiB | 4,000,000 | +512.1 MiB | 53× |

So the real pre-fix bound was *whatever the link delivers in five minutes, times
fifty*. On a 100 Mbps link that window carries ~3.5 GiB of gzip, which is ~175
GiB of live-heap demand. The process dies long before the timeout expires.

**CHAOS-109c (HIGH) — the containment this loop advertises cannot see the one
resource that is unbounded.** `schedulerConfig` wraps the round in
`obs.SafeCall` with an explicit promise:

> CHAOS-24: Sync streams and parses a remote gzip tarball (UT1 mirror).
> **Guard the ROUND so a malformed/hostile archive costs one sync window rather
> than terminating an in-line gateway**

`recover()` does not run for a Go out-of-memory — it is a fatal runtime error,
not a panic — so the guard holds for every hostile-archive shape *except* the
only one that was unbounded. The second mechanism does not help either, and
says so itself. `memory_backstop.go`, the GOMEMLIMIT backstop, states in its own
"SCOPE OF PROTECTION (important — do not over-claim)" section:

> It reclaims GARBAGE […] It **CANNOT** reclaim memory that is still
> **REACHABLE**

The domain map is reachable for the entire parse. Measured directly: with a
64 MiB soft limit in force, the parse drove live heap to **237 MiB — 3.7× past
the limit — across 112 GC cycles**, and allocation never stopped. A soft limit
converts this from an OOM into a GC pressure spiral and then an OOM anyway.

**Why it does not self-heal.** The scheduler's `RunNow` is
`func() bool { return fs.db.Stats() == 0 }` — an immediate sync at boot when the
community DB is empty. The `BulkWrite` that would populate it is the *last* step
and is never reached, so `Stats()` stays 0 and the next boot syncs immediately
again. A hostile or merely broken mirror is therefore a **deterministic crash
loop**, not a transient outage, and it takes the whole process with it: the
HTTP/HTTPS/SOCKS5 proxy, the control plane and the admin UI all share it.

**No attacker is required**, though one suffices. The default origin is a
community GitHub mirror Culvert does not control; a repo takeover, a compromised
CDN edge, or an intercepting upstream with a trusted CA is enough. The feed URL
is also caller-settable through `New(db, feedURL, …)`.

**CHAOS-109d (MED) — `internal/blocklistfeed` retained every feed line with no
ceiling of any kind.** `fetchFeedLines` appended each non-empty line to a slice
under a 30-second `httpTimeout` and no byte or line cap. This is the open half
of CHAOS-108 §8.3, and this loop was the one with *neither* protection its
siblings had: `internal/threatfeed` caps accepted lines, `internal/saasfeed`
reads under a 10 MB `io.LimitReader`.

**CHAOS-109e (LOW) — and §8.3 was wrong about `internal/threatfeed`, which this
round corrects.** §8.3 recorded all three loops as unbounded because none used
an `io.LimitReader`. True of the reader, false of the retention:
`maxFeedLines = 500_000` is a real cap, commented "to limit memory usage", so
this loop never had its siblings' heap exposure. Its actual gap is narrower —
the accept loop `continue`s on blank and `#` lines *without charging the
counter*, so a comment-only body is scanned for the full `feedHTTPTimeout` while
the cap never advances. That spends CPU and bandwidth, not heap. It is fixed
here and rated LOW, not carried at the siblings' severity.

All five are fixed. §10 records what is **not** fixed.

---

## 2. Failure scenarios

| # | Scenario | Pre-fix behavior | Expected | Post-fix |
|---|---|---|---|---|
| 1 | Mirror serves a tarball with duplicate member paths | Each member starts a fresh 2 M budget; map grows until the node dies | One aggregate ceiling | `maxDomainsTotal`; measured 40 members × 1,000 offered against a 5,000 cap → 5,000 ingested |
| 2 | Mirror serves a gzip bomb | ~50× live heap, bounded only by 5 min × link speed | Refuse on a declared budget | Compressed and expansion budgets both fail the round |
| 3 | Small body, enormous expansion | Unbounded — the compressed size was not a proxy for the expanded size | Bound both independently | Dual bound, mirroring CHAOS-106 |
| 4 | Archive of members not in `ut1CategoryMap` | Skipped, but `tar.Reader` still streams their payload: full fetch window spent producing zero entries | Charge the work | Charged to the expansion budget |
| 5 | Node boots with an empty community DB into a hostile mirror | `RunNow` syncs at once, dies before `BulkWrite`, `Stats()` stays 0, repeats every restart | Round fails, backs off, node serves | Round fails at the budget; `feedsched` backs off 15 m → 2 h; last-good DB readable |
| 6 | Operator-set blocklist feed URL serves gigabytes | Every line retained; live cost = 30 s × link speed | Refuse | 64 MiB budget fails the round; last-good merged list stays authoritative |
| 7 | Blocklist feed legitimately grows past the line cap | n/a (no cap) | Truncate, do not freeze | Truncates to `maxFeedLines`, logs it, merge adds fewer new hosts and removes none |
| 8 | Threat feed serves only comment lines | Scanned for the full timeout; `maxFeedLines` never advances | Bound the bytes | Byte budget fails the fetch |
| 9 | Legitimate feed well inside every budget | Served | Unchanged | Negative controls assert it byte for byte |

### Reproduction (measured, not inferred)

Each gate was run against the pre-fix behavior restored surgically, one defect
at a time, so no gate is credited to a defect it does not detect:

- **RED-A** — aggregate entry cap removed: `DuplicateMembersCannotExceedTheAggregateCap`
  FAILS with `aggregate cap breached: 40000 entries ingested against a cap of
  5000`. Re-run after the `acceptDomainLine` extraction; still red.
- **RED-B** — compressed budget removed: `CompressedBodyBudgetFailsTheRound`
  FAILS (`an origin that overran the compressed budget was accepted`).
- **RED-C** — expansion budget removed: `DecompressedBudgetFailsTheRound` and
  `SkippedMembersAreChargedToTheExpansionBudget` both FAIL.
- **RED-D** — `boundedReader` replaced by `io.LimitReader`, the obvious fix:
  `OverrunIsRefusedAndNotMergedAsAShortFeed` FAILS with `an origin that overran
  its byte budget was accepted as a 65-line feed`. **This is the most valuable
  gate in the set.** A `LimitReader` reports a spent budget as a clean `io.EOF`;
  `bufio.Scanner` reports that as a complete body. So the obvious fix would have
  had a 65-line prefix of a 5,000-line deny list merged and the round recorded
  healthy — the identical "success meant the transport returned bytes" mistake
  CHAOS-108 fixed one layer up. `boundedReader` exists for exactly this.
- **RED-E** — blocklistfeed budget removed entirely: same gate FAILS, accepting
  all 5,000 lines.
- **RED-F** — threatfeed budget removed: `CommentOnlyBodyIsChargedToTheByteBudget`
  FAILS (`maxFeedLines cannot bound it because no line is ever charged`).

Measurement harnesses for the amplification table and the soft-limit result were
scratch instruments, run against the pre-fix tree and not committed; the
permanent gates assert the bounds, not the measured constants, so a faster
machine cannot turn a gate red.

---

## 3. Risk matrix

| Finding | Likelihood | Impact | Severity | Notes |
|---|---|---|---|---|
| 109b unbounded archive ⇒ gateway OOM, ~50× amplification | MED | **CRITICAL** | **HIGH** | Whole process: proxy, control plane, admin UI |
| 109c crash loop on an empty DB (`RunNow` + unreached `BulkWrite`) | MED | **CRITICAL** | **HIGH** | Not transient; re-arms on every restart |
| 109a per-member cap ⇒ nominal bound was a fiction | MED | HIGH | **HIGH** | 82 M nominal ceiling; duplicate members defeat it outright |
| 109c advertised containment does not cover the live path | HIGH | — | **HIGH** | `recover()` cannot see an OOM; backstop disclaims reachable memory |
| 109d blocklist feed retains every line, no ceiling | MED | HIGH | **MED** | 30 s × link speed; CHAOS-108 §8.3's open half |
| 109e threatfeed comment-only body scanned to the timeout | LOW | LOW | **LOW** | Work bound, not a memory bound; corrects §8.3 |
| No ingest-refusal alert or health row (**open**) | HIGH | MED | MED | §10; owner decision |
| Feed origin is an uncontrolled third party (**open**) | — | HIGH | MED | §10; supply-chain posture, not a code bug |

---

## 4. Recovery assessment

- **Automatic recovery, pre-fix:** none for 109b/109c. The process did not
  recover — it died, and on an empty DB it died again on the next boot. For 109a
  the map simply grew until it did.
- **Automatic recovery, post-fix:** a byte overrun fails the round, is charged
  `failDownload` (the existing bounded reason class, whose own comment already
  reads "the tarball did not arrive intact" — so no reason was added and the
  health and metrics surfaces are unchanged), and `feedsched` retries on the
  established 15 m → 2 h ladder. The last-good BadgerDB stays readable
  throughout, which is the graceful-degradation posture the loop already
  documents.
- **Manual recovery:** "Sync Now" is unchanged, and still deliberately not
  parented to the operator's HTTP request.
- **Deliberate asymmetry, and why.** Byte overruns **refuse**; entry caps
  **truncate**. A feed that sends ten times its documented size is a fault or an
  attack, and refusing keeps the last-good store. An entry count that outgrew
  its ceiling is what a legitimately growing feed looks like, and refusing would
  freeze coverage the first time it happened. Truncation is safe here for a
  reason specific to this store: `BulkWrite` overwrites keys as they arrive and
  **never deletes**, so a short round adds fewer *new* domains and
  un-categorises none. The same argument holds for `blocklistfeed`, whose merge
  is merge-only and persisted. Both are asserted by gates
  (`TruncationKeepsTheRoundSuccessful`, `LineCapTruncatesRatherThanFails`).
- **Residual, pre-existing:** a node that has already been OOM-killed by a
  pre-fix round recovers by restarting onto this build; nothing durable was
  corrupted, because the write that would have persisted a partial import is the
  step that never ran.

## 5. Operational impact

Pre-fix, the operator-visible symptom of a hostile or broken mirror was *the
gateway restarting*, with no log line attributing it to the feed — an OOM kill
leaves nothing behind in the application log, and on an empty DB the loop
re-armed on every boot. That is the worst diagnostic shape available: a
whole-process failure whose cause is a background worker nobody was looking at.

Post-fix, an overrun is one failed round with a named cause
(`compressed feed body exceeded its 536870912-byte budget`), the existing
`consecutiveFailures` counter advances, and the scheduler's ladder is visible in
the log. Truncation logs explicitly that the import is short and that previously
categorised domains are unaffected. The budgets are sized at roughly 10× the
feed's documented size, so no legitimate feed changes behavior; negative-control
gates assert that.

One diagnosability defect was found *by* the first run of these gates and fixed:
`parseTarball` logs-and-continues on a member it cannot parse, so a spent budget
initially reached the operator as `FeedSync: skipping blacklists/malware/domains:
…` — a benign-looking line for the one condition that must fail the round. The
round did still fail on the next tar read, so this was diagnosability rather than
correctness; `errBudgetExceeded` now makes a budget error unswallowable, and
`BudgetOverrunIsNotLoggedAsASkippedMember` holds it.

## 6. Security impact

The community category DB feeds URL categorisation, which operator policy uses
to **block**. The ingestion path for that control accepted an unbounded byte
stream from a third party and expanded it inside the gateway process. The
reachable consequence is availability, and it is total: an OOM kill takes the
proxy data plane down with the feed worker, so a compromised mirror is a
full-gateway denial of service with a 24-hour re-arm and, on an empty DB, an
immediate one. That is a supply-chain exposure on a security control, reachable
without any Culvert vulnerability — an origin outage serving the wrong bytes is
enough.

`internal/blocklistfeed` is a **deny** control and its origin is
operator-configured, so 109d is the same shape with a narrower blast radius.
The RED-D measurement is the security-relevant half: the *obvious* fix would
have merged a prefix of a deny list and called the round healthy, silently
under-blocking while reporting success.

## 7. Data-integrity impact

None durable, pre-fix or post-fix, and the reason is worth recording because it
is load-bearing for the truncate/refuse split above: on this path the durable
write is the last step. A round that dies mid-parse writes nothing, and the
last-good BadgerDB is untouched. Post-fix a refused round is identical in that
respect. A truncated round writes a subset, and because `BulkWrite` overwrites
and never deletes, a subset cannot remove knowledge — it can only fail to add.

## 8. Suggested improvements (ranked)

1. **Shipped here:** compressed, expansion and aggregate-entry budgets on the
   category feed; body and line budgets on the blocklist feed; a body budget on
   the threat feed; `errBudgetExceeded` so an overrun cannot be logged as a
   skipped member.
2. **Open (§10):** an ingest-refusal alert and health row. A feed that refuses
   every round is visible only as `LastError` and a log line.
3. **Open (§10):** the `boundedReader` adapter is now duplicated in three owner
   packages. That is a deliberate choice, not an oversight — a shared package
   for a 15-line adapter is a new package boundary, which `AGENTS.md` routes
   through package-isolation records and an ADR, and inventing one inside a
   bounds fix is the scope creep the register's own rules forbid. Recorded for
   an owner who wants to consolidate it.
4. **Observed, not fixed:** the feed origin itself. The default is a community
   GitHub mirror with no signature, no pinned digest and no publisher
   verification, while `internal/saasfeed` next door consumes a **signed** feed.
   Closing that gap is a feed-provenance change, not a bounds change; it is the
   single highest-value follow-up and is recorded in §10 rather than attempted
   here.

## 9. Verification

Revision verified: `4666d7a` (this branch). Toolchain `go1.27.3` (`go.mod`
`toolchain` line; `go env GOVERSION` = `go1.27.3`).

| Check | Command | Result |
|---|---|---|
| Owner packages, race + determinism | `go test -race -shuffle=on -count=2 ./internal/feedsync ./internal/blocklistfeed ./internal/threatfeed` | PASS |
| The 13 new gates | `go test -count=1 -v -run '…' ./internal/feedsync ./internal/blocklistfeed ./internal/threatfeed` | 13/13 PASS |
| Red differential | RED-A…RED-F above | each FAILS as recorded; RED-A re-run after the extraction |
| Root callers | `go test -count=1 -run 'Feed\|Blocklist\|BlFeed\|Threat\|Category\|FeedSync' .` | PASS |
| Vet | `go vet ./...` | clean |
| Tidy drift | `go mod tidy -diff` | clean |
| Build | `CGO_ENABLED=0 go build -ldflags="-s -w"` | OK |
| Cross-build | `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build` | OK |
| Lint, diff-scoped (the gate's own command) | `golangci-lint run --timeout=10m --new-from-rev origin/main`, v2.15.0 built with `go1.27.3` | **0 issues** |
| Lint, full tree vs base | same binary, `origin/main` in a worktree | base **174**, head **174**, per-linter counts **identical** |
| Guidance checker | `python3 docs/agent-context/check.py` | PASS (exit 0) |

**The full-tree pass earned its place again, and this is the third round in a
row it has.** The diff-scoped run reported 0 issues while the full tree was
175 against a base of 174: one new `nestif` finding inside `parseDomainFile`,
whose *declaration* line is unchanged and which `--new-from-rev` therefore
cannot see — the exact case `conventions.md` describes. Fixed by extracting
`acceptDomainLine`, which also let the function drop its `//nolint:gocognit`
(the gocognit count is unchanged at 24 with the suppression gone, so it now
passes on its own) and applied both caps to the final unterminated line, which
the old duplicated EOF-flush branch checked against neither.

**Not run / not claimed:** the full-module shuffled determinism run
(`-count=2 -shuffle=on ./...`), the sharded race path, coverage floors, the
`benchgate` lane (this change adds no wall-clock gate), the frontend tree and
the `cmd/culvert-maint` module — none owns a contract this change touches. No
hosted Fast/Deep PR Gate verdict for this SHA is claimed. A passing local
selection is not aggregate CI approval, and these bounds have not been exercised
against the live UT1 mirror.

## 10. Residual risk — the open half

**The origin is still unverified, and that is the larger problem.** This PR
bounds how much a third-party mirror can spend. It does nothing about *who that
mirror is*. `defaultUT1FeedURL` points at
`raw.githubusercontent.com/NethServer/toulouse-bl-mirror/master/blacklists.tar.gz`
— a community mirror, fetched over TLS with no signature, no pinned digest and
no publisher check, and its contents become a security control's categorisation
data on every node. The contrast is in-tree: `internal/saasfeed` consumes a
*signed* feed. Bounding the bytes converts "a compromised mirror kills the
gateway" into "a compromised mirror feeds it wrong categories within a budget",
which is a real improvement and is not the same as safety. A provenance change
(signature or pinned digest, with an operator-visible verification state) is the
recommended next round and is deliberately not bundled here.

**There is no alert and no health row for a feed that refuses every round.**
Post-fix the node survives and backs off, but an operator whose mirror has
served an over-budget body for a week learns that only from `LastError` in the
admin API and one log line per attempt. This is the same open half CHAOS-108
recorded for `blocklistfeed`, now extended to a second loop, and it is the same
reason: a new alert type has GUI/API parity consequences — alert registry, UI
surface, documentation — that `conventions.md` routes through the admin control
plane. Recommended shape, for the owner: a `feed_ingest_refused` alert keyed on
consecutive `failDownload` rounds with a budget cause, plus a per-feed
diagnostics row. `threatfeed_health.go:154` already has the pattern.

**The budget values are judgement, not measurement.** 512 MiB compressed, 4 GiB
expanded and 4,000,000 aggregate entries are sized from the code's own "50+ MB"
and from the ~128 B/entry measured here (so ~512 MiB of heap at the ceiling,
the same order as the 410–470 MiB reachable peak `memory_backstop.go` is sized
around). They have not been checked against the live mirror's actual size. A
feed that grows past the entry cap truncates and logs, which is the safe
direction; a feed that grows past the *byte* budgets would start failing rounds,
which is loud but is a self-inflicted outage of category coverage. An owner with
real mirror telemetry should confirm the headroom.

**`boundedReader` is duplicated across three packages** (§8.3) and
`obs.SetSink` has no getter, so the one gate that captures log output restores
the package default rather than a captured previous value — noted at the call
site.
