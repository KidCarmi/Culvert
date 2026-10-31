# Chaos engineering review — 2026-10-31

Reviewer: Culvert Chaos Engineer (automated round). Base revision `8138243`
(`main`), clean worktree. Scope: the **recovery** half of the response-scan
plane — not "what happens when a scanner fails", which four earlier rounds have
swept, but *what happens when the scanners get better.*

Recorded separately for the reason the previous three rounds were:
[CHAOS-ENGINEERING-REVIEW.md](CHAOS-ENGINEERING-REVIEW.md) stays the index.

Id claimed: **CHAOS-107** (the signature-database generation). Claimed in a
committed placeholder row in the register as commit one, before any code, and
checked against `origin/main` rather than the working tree per the register's
2026-09-25 amendment. `CHAOS-106` was the highest id anywhere on `main` and no
open PR held a chaos id, so it was free at `8138243`.

---

## 1. Executive summary

The register has asked, repeatedly and well, what the scan path does when a
scanner is **worse** than expected: slow (§20, CHAOS-52), saturated (§21,
CHAOS-53), unreachable (§20's `clamDark` branch), panicking (§14, CHAOS-25) or
handed a decompression bomb (CHAOS-106). Every one of those rounds ended by
tightening a fail-closed path. This round asked the mirror question, which had
never been asked: **the scan verdict cache is keyed on the content hash alone,
so what happens to a cached `clean` when the signature set that would have
caught it arrives afterwards?**

**CHAOS-107 (HIGH) — nothing happened. The verdict stayed authoritative, the
engine was never consulted again, and the node went on serving content it had
already called clean for the rest of `CacheTTL` — with no counter, no log line
and no alert marking the window.**

The finding is not that a cache existed. It is that **the cache already had an
invalidation discipline, and it covered exactly the half of the signature
surface that arrives through Culvert.** Every YARA rule mutation flushes it, on
every CRUD path, deliberately and with a comment saying why:

> `// Tier 1.1: Clear hash cache so content scanned as clean under old rules`
> `// is re-scanned under the new rule set. Without this, new rules don't`
> `// apply to previously-cached content until the 1-hour TTL expires.`
> — [ui_security.go:961](../ui_security.go) (`apiSecYARAReload`), and again at
> the `yara_write` and `yara_remove` branches.

That reasoning is correct and it is complete for YARA, because a YARA rule
changes only when an admin calls an endpoint. **ClamAV definitions do not
arrive that way.** `freshclam` updates them out-of-process, several times a day,
and they are overwhelmingly the more common way a new detection reaches a
gateway. Nothing in the process asked whether they had changed, so nothing
flushed. The same sentence the Tier 1.1 comment warns about — *"new rules don't
apply to previously-cached content"* — was simply true, permanently, for the
larger engine.

Four facts compose, and the third is what makes it more than a staleness nit:

1. **The cache key carries no provenance.** `hashcache` stores
   `ScanCacheResult{Clean, Reason, Source, ScannedAt}` under the SHA-256 of the
   content ([internal/hashcache/hashcache.go:27](../internal/hashcache/hashcache.go)).
   `ScannedAt` records *when* a verdict was computed; nothing records *what
   computed it*. A verdict from last week's definitions and one from a second
   ago are indistinguishable to `Get`.

2. **The window is operator-configurable, with no upper bound.** `CacheTTL`
   defaults to one hour, and `resolveScanningStartupConfig` applies
   "verbatim parse-ok-wins" semantics — *any* parseable duration wins, unclamped
   ([scanning_startup_config.go:73-78](../scanning_startup_config.go)). A
   deployment that set `cache_ttl: 24h` to spare a busy node some CPU bought a
   24-hour stale-clean window along with it and was never told.

3. **Culvert already knew. It had the signal, parsed, and used it for
   decoration.** `ClamAVVersion()` queries the daemon's `VERSION` and
   `parseClamVersion` splits out `DBVersion` — *"signature database counter,
   e.g. 26982"* — and `DBDate`
   ([internal/clamav/clamav.go:131](../internal/clamav/clamav.go)). The result
   is cached for ten minutes and published on the Security panel as
   `clamav_version` so, in the words of the comment at its only call site,
   *"operators can see whether virus definitions are current"*
   ([security_scan.go:409](../security_scan.go)). That is the whole consumer.
   The node displayed the counter advancing on one panel while continuing to
   serve verdicts from the superseded set, and the two facts were never
   compared.

4. **The blast radius is the cache's own design goal, inverted.** The package
   doc states the benefit plainly: *"The same executable or document delivered
   from multiple hosts is therefore scanned only once per TTL window"*
   ([internal/hashcache/hashcache.go:6-8](../internal/hashcache/hashcache.go)).
   Read as a failure mode, that is the amplifier: one cached clean covers that
   object for **every user on the node, from every host, by exact hash**, for
   the full window. Host-based scan exclusions cannot narrow it and a different
   URL does not re-arm it.

Observed end to end on a build of the baseline, before the fix (§10 has the raw
run). The third row is the one that matters — the node *observed* the new
signature set and still answered from the old verdict:

| step | signature db | verdict | engine invocations |
|---|---|---|---|
| sample first seen | 27000 | **clean** (cached) | 1 |
| `freshclam` lands; daemon now detects the sample | 27001 | — | — |
| `ClamAVVersion()` returns `DBVersion: "27001"`, ok=true | 27001 | — | — |
| same bytes re-requested | 27001 | **clean** (from cache) | **1 — never re-ran** |

What this round changes is small and is the half the Tier 1.1 discipline was
missing: the scanner now records the identity of the signature set its cached
verdicts belong to, reconciles the cache whenever it observes a different one,
and is driven by a poller so the reconciliation does not depend on an operator
having the dashboard open. Same table after the fix: the fourth row becomes
**blocked, `Win.Trojan.Dropper`, 2 engine invocations.**

A deliberate non-change, and it is the fail direction most likely to be
second-guessed in review: **a failed `VERSION` query does not flush.** §6 and
§11 give the argument.

---

## 2. Failure scenarios

### 2.1 `CHAOS-107` — a clean verdict outlives the definitions that produced it

- **Current behavior (baseline `8138243`).** `ScanBody` computes the content
  hash, consults the admin hash allowlist, then returns on a cache hit —
  `Blocked` for a cached threat, `nil` for a cached clean
  ([internal/secscan/secscan.go:1007-1029](../internal/secscan/secscan.go)). The
  entry is valid until `expiresAt`, computed from `CacheTTL` at write time and
  from nothing else. No code path compares a cached verdict against the current
  ClamAV engine or signature database.
- **Expected behavior.** A verdict is evidence about content *under a given
  detection capability*. When the capability changes, verdicts computed under
  the old one stop being evidence. The repository already holds this contract in
  two places: the Tier 1.1 YARA flush, and `cdrHashCache`, whose `Get(hash,
  currentEpoch)` takes the policy generation as a parameter precisely so a
  cached artifact cannot outlive the policy that produced it
  ([cdr_proxy.go:130](../cdr_proxy.go)). The scan verdict cache was the
  outlier.
- **Failure mode.** Silent, and fail-**open** in the only sense that matters: a
  known-bad object is forwarded to clients with a 200 after the node acquired
  the ability to detect it. No fail-closed path is involved, because no path
  ran.
- **Recovery path (before).** Automatic only by TTL expiry — up to the full
  configured `CacheTTL`, unbounded by configuration. Manual: `DELETE
  /api/security-scan/cache` (admin), or `POST /api/security-scan/yara/reload`,
  or a process restart (the cache is in-memory and not persisted). All three
  require an operator who already suspects the problem, and nothing told them
  to.
- **Monitoring visibility (before).** None. `cache_hits` rose on exactly the
  requests that were being mis-served, which reads as healthy efficiency. The
  one place the two facts could have been correlated — the Security panel,
  which shows `clamav_version` *and* `cache_hits`/`cache_size` side by side —
  presented them as unrelated gauges.
- **Window shape.** Widest on the deployments that tuned for performance
  (`cache_ttl` raised), on the busiest nodes (a hot object is exactly the one
  held in cache), and for the most-shared content. It does not degrade
  gracefully with load; it gets worse.

### 2.2 The provenance gap at the first observation (found while fixing 2.1)

The first implementation of the fix recorded the signature identity lazily, on
first observation, and flushed only on a *later* change. Re-running the
injection showed it still served the stale clean — because the first
observation had landed *after* the verdict was already cached, so it baselined
onto an unprovenanced entry and silently adopted it as current.

That is a second, narrower instance of the same class of bug, and it is worth
recording because the obvious fix has it: making the poller's opening tick
precede traffic removes it *in practice* (`initScanning` is main stmt 265,
`initBackgroundServices` stmt 269) while leaving correctness dependent on
winning a startup race. The shipped version does not depend on it — the first
identifiable observation flushes if the cache is already non-empty, since those
entries predate any signature set the node can name — and the ordering is kept
anyway, which is what makes a healthy boot show no flush at all.

### 2.3 Swept in the same pass, and NOT defects

Recorded so a later round does not re-open them:

- **Remote/sidecar mode.** `RemoteScanner` keeps no local verdict cache
  ([scan_remote.go](../scan_remote.go)), so the client node has nothing to
  invalidate. The sidecar node runs the local `globalSecScanner` with its own
  cache, and the poller runs there too, so both deployments are covered by one
  change. The admin JSON deliberately does **not** emit the new counter on the
  remote branch, following the CHAOS-106 precedent: a structurally-zero counter
  merged in blind misreports the node that is actually doing the work.
- **Threat-feed updates do not need this.** `CheckURL`/`CheckDomain` consult the
  feed per request and are not memoised by `hashcache`; the feed's own hash
  checks run inside `scanBodyInner`, so a feed update takes effect on the next
  scan. The verdict cache is a ClamAV/YARA-result cache, not a feed cache.
- **The timeout cooldown is already correct, and is the reason this round's fix
  is shaped the way it is.** `cacheTimeoutCooldown` stores a fail-closed
  refusal under a 30-second lifetime rather than the content TTL, with a comment
  recording what the content TTL cost when it was used: *"a few seconds of
  scanner slowness blocked that exact object, node-wide, for every user, for an
  hour after the fault cleared"*
  ([internal/secscan/secscan.go:1113](../internal/secscan/secscan.go)). The
  same asymmetry — a verdict about the *scanner* must not inherit the lifetime
  of a verdict about the *content* — is the asymmetry this round applies in the
  other direction.
- **`publishVerdict`'s tighten-only rule and the `clamDark` branch** are
  untouched and load-bearing for §6's argument: a "clean" computed while ClamAV
  was unreachable is never cached at all, so a dark window cannot accumulate
  false cleans for a later flush to miss.

---

## 3. Risk matrix — this round

| id | domain | severity | likelihood | detectability before | status |
|---|---|---|---|---|---|
| CHAOS-107 | scan verdict cache vs. ClamAV signature generation | **HIGH** | **certain** — every signature update on every node with body scanning, several times a day | none (no counter, log or alert; `cache_hits` read as healthy) | **fixed this round** |
| CHAOS-107.b | provenance gap at first observation (§2.2) | MEDIUM | low (needs traffic before the poller's opening tick) | none | **fixed this round** |
| — | remote-mode client node | n/a | — | — | not applicable (no local cache) |
| — | threat-feed freshness vs. cache | n/a | — | — | not a defect (not memoised) |

Severity rationale: HIGH, not CRITICAL. It requires the object to have been
seen and called clean *before* the signature landed, it is bounded by
`CacheTTL`, it is per-node and non-persistent (a restart clears it), and the
other engines still run on a cache miss. It is not merely MEDIUM because the
likelihood is not "possible" but **certain and recurring** — signature updates
are routine, not a fault — the window is unbounded by configuration, and it was
completely invisible.

---

## 4. Recovery assessment

| property | before | after |
|---|---|---|
| automatic recovery | TTL expiry only, up to the full configured `CacheTTL` | within one poll interval of the signature change (≤ ~15 min: a 5-minute tick against a 10-minute `VERSION` cache) |
| deterministic | no — depended on when the object was cached | yes — keyed on an observed identity change, not on elapsed time |
| manual recovery | admin cache flush / YARA reload / restart, if an operator suspected it | unchanged, and no longer the only route |
| depends on an operator watching | n/a (nothing happened either way) | **no** — this is why the poller exists; `ClamAVVersion()`'s only other caller is the dashboard payload, so without it a node whose dashboard nobody opens would never notice |
| survives a worker panic | n/a | yes — the round runs under `runGuarded` (CHAOS-105/CHAOS-24), so a bad round costs one interval instead of silently disarming the observer for the life of the process |
| survives scanner reconfiguration | n/a | yes — `Init` drops the recorded identity so the next observation re-baselines rather than comparing a new daemon's counter against the old one's |

---

## 5. Operational impact

- **Steady state: none.** An unchanged signature set is observed and recorded;
  nothing is flushed. Pinned by
  `TestCHAOS107_UnchangedSignatureKeepsCache`, which polls five times and
  asserts the cache and the engine-invocation count are untouched — an observer
  that flushed on every poll would hand the node a full re-scan of its working
  set every interval, which is a worse bug than the one being fixed.
- **On a signature update: one cold cache, once.** The node re-scans objects as
  they are next requested. This is the intended cost and it is the same cost the
  Tier 1.1 YARA flush has always imposed; it is now paid on the ClamAV side too.
  On a node with a large hot set this is a visible CPU bump for one cache-fill
  period, a few times a day, and operators who have tuned `cache_ttl` upward
  will feel it most — which is precisely the population that had the widest
  exposure.
- **Cost of the observation itself:** one `VERSION` command to a local daemon
  per ~10 minutes. The 5-minute tick is deliberately shorter than the scanner's
  10-minute `VERSION` cache so that a tick landing inside the previous window is
  free, which keeps worst-case detection near one window rather than two.
- **New observability.**
  - `culvert_scan_sigdb_invalidations_total` (Prometheus) and
    `stat_scan_sigdb_invalidations` (admin JSON, local mode) — a **recovery**
    counter, not a failure counter. The alert condition is the *absence* of
    movement: flat at zero while the reported signature counter advances is the
    shape the stale-clean window had.
  - A log line naming both identities on every flush, so the transition is
    reconstructible from the process log in a support bundle.
  - `sigdb_generation` and `sigdb_invalidations` in the support bundle's scan
    section, beside the `hash_cache_*` gauges they make interpretable. A support
    bundle is usually opened to answer "why was this object allowed?", and a
    cache hit alone could not answer it; the generation says which definitions
    produced the verdict.
- **No new operator configuration, and none is proposed.** The reconciliation is
  a correctness property, not a policy. §7 argues against making it a toggle.

---

## 6. Security impact

The defect is a **silent fail-open on the recovery path**, which is the class
this register has found hardest to see: every fail-closed gate was working, and
none of them ran.

The posture statement Culvert holds itself to is *default deny, fail closed
when recovery is impossible, graceful degradation otherwise.* CHAOS-107 is not
a breach of the fail-closed rule — it is a case where **recovery was possible
and was not taken.** The node had acquired the ability to detect an object and
declined to use it, because a cache said the question was already answered.

The adversarial reading is worth stating because it is the realistic one. The
exposure is widest exactly where defenders are most interested: a sample in
circulation *before* a signature exists for it is the normal lifecycle of a
malware campaign. Such a sample is fetched, scanned clean, and cached. The
signature then lands — and on every node that already cached it, the signature
does not take effect until the TTL lapses. The defender's view says the node is
protected (the panel shows current definitions) while the cache says otherwise.
Nothing about this requires an attacker to *do* anything to Culvert; it is the
default outcome of ordinary timing.

**The deliberate fail direction, and why it is the safer one.** A failed
`VERSION` query does **not** flush. The security-maximalist reading says flush
on any uncertainty; it is wrong here, for two reasons that are both already
established in this code:

1. Flushing on an observer fault hands any daemon blip a free node-wide cache
   wipe, sending every subsequent body to the very daemon that just failed to
   answer. That is the self-sustaining saturation `scanBodyInner`'s cancellation
   was added to stop (CHAOS-52/53), and it would be remotely triggerable by
   anything that makes ClamAV briefly unresponsive — i.e. the fix would ship a
   DoS amplifier.
2. The dark window cannot accumulate new false cleans anyway: the `clamDark`
   branch already refuses to cache a "clean" computed while ClamAV was
   unreachable. So declining to flush preserves only verdicts computed while the
   daemon was *healthy*, and those remain bounded by `CacheTTL` exactly as
   before.

A failed query is therefore evidence about the observer, not about the
definitions. Only a **positive observation of a different identity** invalidates.
`TestCHAOS107_VersionQueryFailureKeepsCache` pins this, including that recovery
to the *same* set does not flush either.

---

## 7. Suggested improvements (prioritized, NOT done here)

1. **HIGH — give `hashcache` entries first-class provenance.** This round
   reconciles at the cache *level* (flush all on change), which is correct and
   coarse. Stamping each entry with the generation that produced it, as
   `cdrHashCache` already does with its policy epoch, would let `Get` reject a
   stale entry individually and make a flush unnecessary — no re-scan cliff,
   and threat verdicts (which do not become *less* true when definitions
   advance) could be retained across a generation change instead of discarded
   with the cleans. Deliberately not done here: it changes a leaf package's
   stored type and its API, which is a larger review than the fail-open it
   would refine.
2. **MEDIUM — clamp or warn on `CacheTTL`.** Fact 2 above is independent of
   this round's fix: "verbatim parse-ok-wins, unclamped" means a typo
   (`cache_ttl: 24h` for `2.4h`, or a unit slip) silently buys a day-long
   verdict window, and no startup line reports the resolved value as a risk. A
   soft ceiling with a logged warning, or simply logging the resolved TTL beside
   the cache size at startup, is cheap. Needs an owner decision because it
   touches a configuration contract.
3. **MEDIUM — alert on a stalled observer.** The counter makes the recovery
   visible but nothing fires when the observation itself stops succeeding (a
   daemon that answers `PING` but not `VERSION`, or a client without the
   capability). The condition to alert on is "cache non-empty and no successful
   observation in N intervals", which is the state where provenance is unknown
   again.
4. **LOW — surface the generation in the Security panel.** `clamav_version` is
   already shown; showing the generation the *cached verdicts* belong to next to
   it would make the invariant legible to an operator at a glance, and the two
   differing would be self-explanatory. GUI/API parity work, not behavior.
5. **LOW — reconcile on an explicit admin signal too.** An operator who has just
   run `freshclam` by hand should not wait up to a tick. The existing admin cache
   flush already covers it; a documented runbook line is probably the whole fix.

---

## 8. Suggested PR — what this round changes

Branch `claude/serene-cerf-wl0ygz`. Six files, one behavior change.

**Owner-respecting split.** `internal/secscan` owns the reconciliation because
it owns the cache (ADR-0006: *"the cache is handed over here instead of being
poked from outside"*); package main owns only the cadence, which is a
startup/wiring concern.

- `roadmap/CHAOS-ENGINEERING-REVIEW.md` — the `CHAOS-107` placeholder row
  (commit one, before any code) and the round's index entry.
- `internal/secscan/secscan.go` —
  - `Scanner.sigGen` / `sigGenKnown`: the identity of the signature set the
    cached verdicts belong to, and whether one has been observed at all.
  - `signatureGeneration(clamav.Version)`: engine + db counter + db date, with a
    `Raw` fallback; `""` means "cannot tell" and is never recorded, so an
    unparseable reply cannot manufacture a change later.
  - `noteSignatureGenLocked`: maintains the invariant *every verdict in the
    cache was produced under `ss.sigGen`*, without depending on who observes
    first (§2.2). Reports whether a flush is owed; the flush itself happens
    **outside** `ss.mu`, keeping the scanner lock off the cache's lock-ordering
    graph.
  - `ClamAVVersion()`: the enforcement point, because it is where the knowledge
    arrives. Reconciles after a *successful* refresh only; the error branch
    carries the §6 argument as a comment so the fail direction is not
    "corrected" later by someone who reads it as an oversight.
  - `RefreshSignatures()` / `SignatureGeneration()`: the poller's entry point
    and a diagnostic accessor.
  - `Init()`: drops the recorded identity so a reconfigured daemon re-baselines.
  - `statScanSigDBInvalidations` + `SigDBInvalidations()` +
    `CounterSnapshot.SigDBInvalidations`.
- `scan_signature_watch.go` (new) — `startScanSignatureWatch`: immediate opening
  observation, then a 5-minute tick, each round under `runGuarded`
  (CHAOS-105), parented to the lifecycle context. Started unconditionally and
  self-no-ops where there is nothing to observe, so it is not gated on a
  scanning mode that can change after startup.
- `background_services_startup.go` — one `go` line.
- `metrics.go` — `culvert_scan_sigdb_invalidations_total`.
- `security_scan.go` — `stat_scan_sigdb_invalidations` (local mode only; see
  §2.3 for why not the remote branch), **plus** the extraction of
  `secScanStatusMapRemote`. The extraction is not cosmetic and not optional:
  `secScanStatusMap` was ALREADY over the configured `funlen` bound on the base
  (81 > 80) and the new key pushed it to 82. The conventions warn that
  `funlen`/`cyclop`/`gocognit` attribute to a function's DECLARATION line, so
  `--new-from-rev` cannot see a function a change made worse — which is exactly
  what the full-tree comparison in §10 caught. Splitting the self-contained
  remote branch out leaves the tree one finding BELOW the base rather than one
  line further over.
- `support_collectors_posture_b.go` — `sigdb_generation` +
  `sigdb_invalidations`, both `redact:"internal"`.

Not changed: `hashcache`'s stored type or API (see §7.1), `CacheTTL` semantics
(§7.2), the YARA Tier 1.1 flushes, `publishVerdict`'s tighten-only rule, the
`clamDark` branch, and the timeout cooldown.

---

## 9. Required tests — and what they pin

`internal/secscan/secscan_sigdb_generation_test.go`, ten gates. Both directions
are pinned deliberately: a cache that never invalidates is the bug, and a cache
that invalidates too eagerly is a worse one.

| test | pins |
|---|---|
| `SignatureUpdateInvalidatesCleanVerdict` | **the finding.** Clean under 27000, signature update, same bytes → blocked by the new detection, engine invoked a second time, counter +1 |
| `UnchangedSignatureKeepsCache` | five polls of an unchanged set flush nothing and leave the engine count at 1 — the anti-regression for a flush-happy observer |
| `VersionQueryFailureKeepsCache` | the §6 fail direction: a failed `VERSION` neither flushes nor forgets the recorded identity, and recovery to the same set does not flush |
| `BaselineOntoNonEmptyCacheFlushes` | §2.2 — unprovenanced entries are discarded, not adopted |
| `EngineUpgradeInvalidates` | an engine change counts, even with a static db counter |
| `UnidentifiableReplyIsNotAnObservation` | an unparseable reply is not recorded, so the next real one is not read as a change |
| `InitRebaselines` | a reconfigured daemon's counter is not compared against the previous daemon's |
| `NoClamIsNotAnObservation` | the unconditionally-started poller is a clean no-op in remote mode / with no ClamAV, and a zero-value scanner does not panic |
| `ConcurrentObservationsFlushOnce` | the dashboard payload and the poller race on the same change; it is counted once (16 concurrent observers, race-safe fake) |
| `CounterSnapshotAgrees` | the Prometheus series and the admin JSON cannot drift apart |

Still owed, and not written here: an integration test that drives
`startScanSignatureWatch` against a fake clock to assert the cadence and the
`runGuarded` containment of a panicking round. The round behavior is covered at
the scanner level; the *loop* is covered only by inspection.

---

## 10. Verification performed

All at `8138243` + this branch, with the `go.mod` toolchain (`go1.27.3`).

- **Fault injection, before the fix** — a scratch probe against a build of the
  baseline, which is the evidence for §1's table. Raw output:

  ```
  t0  db=27000  verdict=CLEAN  clam_scans=1
  observed version: {Engine:ClamAV 1.0.0 DBVersion:27001 DBDate: Raw:} ok=true
  t1  db=27001  verdict=<nil>  clam_scans=1  cache_size=1
  OBSERVED: content is still served CLEAN under signature db 27001
            (engine ran 1 time(s) total — the second request never reached it)
  ```

  The middle line is the finding: the node had the new signature counter in hand
  and answered from the superseded verdict anyway.

- **The same injection, after the fix** — `t1` becomes
  `verdict=&{true Win.Trojan.Dropper clamav ...}  clam_scans=2`, preceded by the
  flush line
  `SecurityScan: ClamAV signature set changed (... ) — scan verdict cache flushed`.
  The probe was then replaced by the ten gates in §9 (it is not in the diff).

- `go build ./...` — clean. `go vet . ./internal/secscan/` — clean.
- `go test ./internal/secscan/ -run TestCHAOS107` — 10/10 pass.
- `go test -race ./internal/secscan/` — full package, pass (41.4 s).
- `go test ./internal/...` — all packages, exit 0.
- `go test -count=1 -run 'TestDataSurfaces|TestCHAOS106|TestMetrics|Metric' .` —
  pass. Covers the redaction parity wall that gates the new support-bundle
  fields and the CHAOS-106 metrics neighbours.
- `go test -count=1 -run 'Scan|scan|Support|Clam|Hash' .` — pass (14.8 s).
- `gofmt -l` — clean on every touched file.
- Lint: the gate's pinned `golangci-lint v2.15.0`, installed with the `go.mod`
  toolchain (`GOTOOLCHAIN=go1.27.3 go install .../golangci-lint@v2.15.0`), run
  **both** ways the conventions require.
  - `run --new-from-rev origin/main` — **0 issues.**
  - Full tree (`run ./...`), compared against the same measurement taken on
    `origin/main` in a scratch worktree: **170 findings on the branch vs 171 on
    the base.** This is the pass that earned its keep. It is what caught the
    `funlen` regression described in §8 (invisible to `--new-from-rev`, because
    the declaration line did not move) and, after the extraction, a `govet`
    `unreachable` left by the extraction itself. Both were fixed; the net −1 is
    the pre-existing `secScanStatusMap` violation going away.
  - The remaining branch/base set differences are all `gosec`/`gocritic`
    entries in files this change does not touch (`internal/catdb`,
    `internal/mcp/*`, `internal/otlp`, `internal/redaction`,
    `internal/admission`, `internal/alerts`, `internal/mcpacceptance`). They
    shuffle because [.golangci.yml](../.golangci.yml) sets `max-same-issues: 3`:
    removing one instance of a capped class lets a previously-truncated
    instance elsewhere surface. Worth stating explicitly, because a reviewer
    diffing the two lists will see entries appear and should not read them as
    new.
- `python3 docs/agent-context/check.py` — exit 0 (no guidance path is changed by
  this round; run because the register is edited).

**Not run, and why:** the full root-package suite and the hosted aggregate gates
(the root package alone is ~1520 files; CI owns the exact-SHA run). A passing
local check is not a passing hosted review. No cluster, appliance or
end-to-end-with-a-real-ClamAV run was attempted; the ClamAV side is covered
through the injected `VERSION` fake, so the *parse* of a real daemon's reply is
inherited from `parseClamVersion`'s existing tests rather than re-verified here.

---

## 11. Residual risk

- **The re-scan cliff is real and is now load-bearing.** A signature update
  invalidates the whole cache, so a busy node re-scans its hot set over the
  following cache-fill period, a few times a day. That is the correct trade
  against serving known-bad content, and it is the same trade the YARA path has
  always made — but on a node already near its ClamAV concurrency limit it moves
  load onto the saturation plane CHAOS-52/53 bound. §7.1 (per-entry provenance)
  is the improvement that removes the cliff rather than accepting it; until
  then, `stat_clam_saturated` is the counter to watch after a signature update,
  and it is already exported.
- **Detection latency is bounded, not zero.** Up to roughly one `VERSION` window
  plus one tick (~15 min) between the signature landing and the flush. Shrinking
  it means polling more often than the daemon's definitions can change, which
  buys nothing; §7.5 (reconcile on an explicit admin signal) is the better route
  for the operator who just ran `freshclam` by hand.
- **The observation can stall silently.** A daemon that answers `PING` but not
  `VERSION`, or a client without the capability, means no observation ever
  succeeds — the poller no-ops forever and the cache reverts to being
  unprovenanced, bounded only by `CacheTTL` as before. The new counter does not
  catch this (it counts flushes, and there are none); §7.3 is the gap.
- **YARA rules changed on disk out-of-band are still not detected.** The Tier
  1.1 flushes cover the admin CRUD paths; a rule file edited directly on the
  volume takes effect only at the next `LoadDir` (admin reload or restart), and
  this round did not extend the generation concept to the YARA rule set. Lower
  priority because, unlike `freshclam`, nothing updates those files on a
  schedule by default — but it is the same shape, and a deployment that syncs
  rules with an external tool has the same gap.
- **Per-entry generation is still absent** (§7.1), so a threat verdict is
  discarded along with the cleans on every flush. Harmless today (it is
  re-derived on the next scan) and the reason the cliff exists.
- **The loop itself is covered only by inspection** (§9's owed test).
