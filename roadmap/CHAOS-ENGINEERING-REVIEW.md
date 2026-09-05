# Culvert Chaos-Engineering / Failure-Mode Review

**Date:** 2026-07-04
**Scope:** Full failure-domain sweep across the proxy data path, CA/TLS/sessions, cluster/HA
(Control-Plane ↔ Data-Plane), storage/persistence, authentication/identity, and background
workers/feeds/scanning/alerting.
**Method:** Evidence-first source review. Every finding cites `file:line`. No behavior was
inferred without reading the code path. Failure modes were assessed against the project's stated
posture — **default deny, fail closed when recovery is impossible, graceful degradation otherwise.**

This document is a standing register. It records where Culvert already survives failure safely
(and *why*, by code path) and where it does not. The one code change shipped alongside the original
review is a fail-closed fix for a latent nil-deref panic in the enrollment path (Finding HA-9);
everything else is triaged below with a suggested PR and required tests for follow-up.

---

## 0. Revision log

> **⚠️ IDENTIFIER COLLISION — `CHAOS-50` names THREE unrelated sweeps.** Several
> reviews ran concurrently in August 2026 and each took the next free number
> independently, so §17 (the cluster/enrollment CA lifecycle), §18 (the CA
> plane's recovery paths) and §19 (the boot path under a damaged data volume)
> are all stamped `CHAOS-50`, as are ~20 source comments across the three merged
> PRs. **Cite these findings by SECTION number, not by CHAOS id, until this is
> resolved.** This is the SECOND occurrence of the same governance failure:
> `docs/engineering/PRODUCTION-FAILURE-MODE-AUDIT.md` §13 (Governance
> observations) recorded that the
> 2026-07-07 and 2026-07-10 reviews both defined CHAOS-22…27 with different
> meanings, concluding *"the CHAOS series is not a stable registry —
> cross-referencing an ID requires naming the review date"* and recommending a
> single append-only ledger (`TECHNICAL-RISK-REGISTER.md`, 2026-07-11 entry).
> That recommendation was never implemented, and concurrent sweeps have now
> reproduced it. Allocating an id at the START of a sweep, in a committed
> placeholder row, is what would actually prevent it. Renumbering now means
> rewriting identifiers three merged PRs already reference, so it is an OWNER
> decision, not a unilateral edit — recorded here rather than silently "fixed".

**2026-09-05 — CHAOS-58 sweep (the public admin-login endpoint's untrusted username).** The
first sweep in this register to ask what an *unauthenticated caller gets to write*, rather than
what happens when infrastructure fails. `apiAuthLogin` is on the public allowlist and bounded
nothing: the username reached two lockout maps (retained ≥ 10 min), the audit ring, and the
durable audit JSONL — a 50 MB rotating file keeping ONE archive. Inside the endpoint's own
60-POST/min limit, one client commits ~60 MiB/min of chosen bytes and rotates the entire retained
compliance record away in under two minutes. The instrument built for exactly this outcome
(`internal/audit`'s `writeErrors`, CWE-778) cannot see it, because **every one of these writes
succeeds**. Closes AU-14/AU-15; the count axis is recorded open as AU-16. See §25.

**2026-08-24 — CHAOS-55 sweep (the fencing lease's recovery paths).** ADR-0005 built the
fence to answer *may this node write?* and answers it correctly in every direction. What it never
built was the way BACK. The lease has three exits from write authority — denied on promotion,
denied on resume, self-fenced by the keepalive — and shipped a return path for exactly one. The
other two dead-ended silently, and the mechanism is one sentence twice: **an unknown was treated as
a decision.** `ha_lease.go`'s own header states the rule for the other direction ("leadership cannot
be taken while the fence's state is unknown") and the promotion path obeys it exactly; the resume
path broke it in reverse. **HA-7** (registered P1, open since the first sweep): the 45 s resume
budget was spent ONLY on waiting out this node's own ghost lease, and a transport error returned
false on the first attempt — so the boot-order fault, etcd a few seconds behind culvert on a host
reboot, got zero retries. The node then asserted `role=leader, leaseEpoch=0`, and because
`startLeaseKeepalive` no-ops on a zero epoch, **nothing left in the process ever called `Acquire`
again**; `PromoteManually` refuses a node already roled leader, so a human restart was the only
lever. **HA-16**, found in the sweep and worse: with a recorded ex-standby, ANY failed resume
demoted to standby — including an unreachable backend. In a two-node cluster restarting together
the guess is symmetric, neither node can sync (a lease-configured puller rejects a bundle with no
live holder), `lastSyncOK` stays zero, and the freshness gate then refuses every auto-promotion —
**a permanently leaderless cluster from a few seconds of etcd being slow to boot.** Shipped: the
resume budget now covers transport errors; a rate-bounded, jittered, interruptible background
re-acquire loop covers a longer outage; demotion is gated on an AFFIRMATIVE read of a foreign
holder, which is also LATCHED (a node that has seen another leader never silently takes over when
that leader vanishes — that judgement belongs to the freshness gate); and six `culvert_ha_lease_*`
series close **HA-17**, the fact that an unfenced leader was indistinguishable from a healthy one on
the only surface a Prometheus rule can read. **HA-18** (self-fenced ex-leader with no recorded peer)
is recorded, not fixed — it needs a posture decision about what freshness means for a node that
does not sync. 18 gates covering the defects and the arming/latching conditions; every defect gate was verified failing against the pre-fix tree. See rows HA-7/HA-16/HA-17/
HA-18, §23, `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-24.md` and
`docs/operator/ha-lease-recovery.md`.

**2026-08-23 — CHAOS-54 sweep (the SOCKS5 accept loop under listener faults).** The one
hand-rolled accept loop in the data plane retried every non-`net.ErrClosed` accept error
IMMEDIATELY and logged each attempt. Under EMFILE/ENFILE that measured **7.68 million accept
attempts in 300 ms**, one log line each: a pinned core, ~40 MB/s into a 50 MB rotating log that
therefore erased the evidence of the incident within seconds, and — because `internal/logsink`
BLOCKS a producer on a full queue — added latency to every proxied HTTP request on a node whose
SOCKS5 listener nobody was using. The listener also had NO health surface of any kind. Shipped:
net/http-shaped exponential backoff (5 ms → 1 s) with an interruptible sleep, an errno
classification that stops the loop only when the socket itself is gone, rate-limited logging,
and a full observability plane (`socks5_listener` diagnostics row, report-only `/readyz socks5`
row, `/healthz socks5` field, four `culvert_socks5_*` series, `socks5_listener_down` alert). PX-20
was raised by Codex review against the fix itself — a bare `ErrClosed` return reproduced PX-18 in
miniature — and closed in the same PR. See §22 and
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-23.md`.

**2026-08-22 — CHAOS-53 sweep (the remote scan sidecar under failure, slowness and saturation).**

CHAOS-52 §20.5 handed this off: the sidecar "is the other fail-open scanning path, with its own 30 s
per-request timeout and no budget threading; the same findings are structurally likely to repeat
there." They repeat, and they are worse, because of where the documentation points. **Culvert has two
body-scanning back ends and they disagreed about what to do when a scan does not finish in time.**
The local path bounds a scan by `ScanBodyTimeout` (10 s) and fails CLOSED — counted, logged, alerted,
memoised. The remote path bounded one by a PRIVATE 30 s context inside a client with a 60 s timeout —
3x and 6x the budget the same process gives the same decision — and surfaced its expiry as an
ordinary transport error, which the classifier read as a sidecar fault and handled fail-OPEN. `nil`
from a scanner means clean, so *"the sidecar did not answer in time"* and *"the sidecar answered
clean"* were the same value at the call site. That is CHAOS-52's WK-15 defect standing in the other
path, with three aggravations: it is reachable by ordinary QUEUEING (the sidecar fronts the same
ClamAV that saturates at four concurrent scans, so a queue longer than the deadline is the normal
steady state of an under-provisioned scanner, not a failure of one); the CHAOS-52 runbook
RECOMMENDS moving scanning to the sidecar as the remedy for the local path's capacity behaviour, so
the recommended remedy silently swapped a fail-closed control for a fail-open one; and it was
invisible, because not one `culvert_scan_*` series is produced by the remote path and the sidecar's
own failure counter reached only the admin JSON API. **Six further defects sat around it, five silent
by construction.** The worst: any HTTP 200 whose body parsed as JSON was treated as CLEAN — `{}`,
`null`, a load balancer's JSON error page — so scanning was fully off with no counter, no log and no
alert. The most surprising: scan exclusions were never LOADED in remote mode, and because
`scanexcl.Store` learns its persistence path FROM `Load`, `Save()` was a documented no-op — so every
admin edit to the allowlists returned 200, wrote an audit entry and took a config-version snapshot
while persisting nothing, and the lists reverted to empty on the next restart. All fixed; the
fail-open posture for a GENUINELY unreachable sidecar is unchanged and remains the recorded owner
decision, now split out as WK-2b. 17 gates, each verified failing against the pre-fix behavior. See
rows WK-2/WK-2b/WK-19, §21, and `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-22.md`.

**2026-08-21 — CHAOS-52 sweep (the body-scan pipeline under scanner slowness and saturation).**

The register has carried **WK-1** ("ClamAV daemon down → files pass UNSCANNED, fail-open") as an open
High, framed as a POSTURE question about a daemon fault. That framing understated it. **The
fail-open branch is reachable by LOAD, on a completely healthy daemon, with no infrastructure
failure anywhere** — and the mechanism is a private constant three call-frames below the decision it
overrides. `clamav.Client.Scan` caps concurrency at four and, with all four slots busy, waited **5 s
and returned an ordinary error**; the orchestrator classifies any engine error as a fault and takes
the fail-OPEN branch, while its OWN budget (`ScanBodyTimeout`, 10 s — the limit that exists to decide
exactly this) fails CLOSED. So the inner limit always fired first and inverted the outer one's
verdict: five concurrent downloads that keep four scans busy for five seconds cause every subsequent
response to be forwarded without antivirus inspection, *reported as a daemon error*. Inducible on
demand, no privilege needed. A second defect made it self-sustaining: `ScanBody` enforced its
deadline with `time.After` and stopped WAITING without stopping the WORK, so an abandoned scan kept
its ClamAV slot for the client's own 30 s timeout — **3x the budget that had already given up on
it** — measured at **30.006 s against a 150 ms deadline** on the pre-fix tree. Once scans start
timing out, abandoned work crowds out live work and live work falls onto the fail-open path. Two more
defects decided what happens AFTER a timeout, pulling in opposite directions so that the outcome for
identical content came down to a race: the fail-closed refusal was cached under the CONTENT TTL (1 h
default), blocking a legitimate object node-wide for an hour after a five-second stall; unless the
abandoned goroutine finished first and wrote `Clean:true` over it, silently converting a fail-closed
refusal into a cached admission with no counter and no log. That last one is the mistake the code
TWO LINES ABOVE it already knows about — the ClamAV-error branch carries a comment explaining that a
verdict computed while the daemon was dark must never be cached. The reasoning had been applied to
one branch and not its neighbour, the same shape as the 2026-08-19 review's own §13.1. All four
fixed; the unifying rule is stated in the code: **an inner deadline must never preempt an outer one
and invert its posture, and abandoned work must release what it holds.** 12 gates, each verified
failing against the pre-fix behavior. See rows WK-15…WK-18 and
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-21.md`.

**2026-08-19 — CHAOS-50 sweep (the cluster/enrollment CA across its lifecycle).**

CHAOS-28 closed the inspection CA and handed off row **CA-13** as "the same defect class in the
OTHER CA, with a different lifecycle and blast radius." That was right about the class and
understated the radius — and the sweep found something bigger than CA-13 sitting next to it. **The
headline is a CRITICAL self-deadlock that was already known to the codebase and recorded nowhere:**
`clusterCA.ImportCA` held `ca.mu.Lock()` across its post-commit side effects, and two of them read
the cluster CA back through the package global — `onRotate`→`rebuildCPCertPool`→`AllCACertsPEM()`,
and `CurrentConfigSnapshot()`→`CACertFingerprint()` — both taking `ca.mu.RLock()` on the SAME object
(the receiver IS the global in production). `sync.RWMutex` is not reentrant, so the goroutine blocked
**forever while holding the write lock**, queueing every `SignCSR` (enrollment AND unattended
renewal), every fingerprint read (hence all config publication) and every TLS-pool rebuild behind it
until restart. `CleanupSecondary` had the identical shape. Three triggers, two unattended:
`POST /api/cluster/ca` (the documented enterprise custom-CA import), `RotateIfNeeded` 30 days before
expiry, and overlap cleanup ~30 days after any rotation — the last two hang the goroutine that drives
BOTH trust roots, so the inspection CA silently stops rotating too. Proven on `main` with a stack
trace (`sync.RWMutex.RLock` inside `ImportCA` on pointer `0x…480`). It survived because the test
suite works AROUND it: every import test points `globalClusterCA` at a separate empty CA, and
`cluster_ca_keyatrest_test.go` says so outright — *"a pre-existing self-deadlock … out of scope for
this key-encryption PR."* **A known defect parked in a test comment is invisible to the register**,
which is the process lesson here and a new theme (§17.3). Alongside it, six more, all reproduced
against `main` first: an **expired cluster CA kept signing** node certs (the CA-1 analogue —
`x509.CreateCertificate` ignores the parent's window) and, because `Enroll` needs no client cert, the
operator's *re-enroll* recovery returned a cert that was **dead on arrival while reporting success**;
node certs were **not clamped to the issuer**, overclaiming by up to a YEAR (vs the leaf case's 24h),
so every expiry surface in the fleet reported validity that did not exist; a rotation failure reached
`Info()` and **nothing else** — no metric, alert, or probe row, on the CA's *only* recovery path;
there was **no usability or expiry series at all** (`culvert_cluster_ca_rotations_total` counts
successes, so a month of daily failures read as `0`, same as healthy); the cluster CA's **only
rotation driver was gated on the INSPECTION CA being ready**, so an unrelated bundle/passphrase fault
silently disabled a healthy trust root's lifecycle for what is a 10-YEAR certificate; and `ImportCA`
**nil-dereferenced on a first import**, after swapping the CA in, leaving a partially applied trust
change. All seven fixed, 18 gates in `cluster_ca_chaos_test.go`. See §17 and
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-19.md`.

**2026-08-14 — CHAOS-50 / CHAOS-51 sweep (the CA plane's RECOVERY paths — both CAs).**

CHAOS-06 made a Root-CA load failure visible and CHAOS-28 made an EXPIRED CA fail closed.
Neither asked what happens NEXT, and the answer was uniformly nothing: the bundle was read
once at startup, `sslInspectionLoadError` had no clearer anywhere in the non-test tree, and
the one background loop that could heal either CA was skipped whenever the inspection CA was
the thing that failed. Eight defects, all fixed.

**CHAOS-51 is the headline and was not in the register.** `clusterCA.ImportCA` held
`ca.mu.Lock()` across TWO calls that re-enter the same object — `onRotate` →
`rebuildCPCertPool` → `AllCACertsPEM` → `RLock`, and `CurrentConfigSnapshot()` →
`CACertFingerprint` → `RLock` — and `CleanupSecondary` repeated the first. `sync.RWMutex` is
not reentrant, so each **self-deadlocked and left the write lock held for the life of the
process**: every reader of the cluster CA then blocked forever, including `CACertFingerprint`
and therefore EVERY CP→DP ConfigSnapshot. `rebuildCPCertPool` additionally strands
`cpTLSConfig.mu` (it takes that FIRST, then blocks), and that is the mutex
`getCPTLSConfigForClient` takes on every ClientHello — so the CP stops completing TLS
handshakes too, and a reconnecting DP cannot even reach the RPC that would have served it
stale config. Total Control-Plane stall — no enrollment, no config distribution, no cluster
admin API, no new CP TLS session — reachable three ways, two of them unattended:
`POST /api/cluster/ca` (immediately and deterministically on any CP with the gRPC server up,
because that is what wires `onRotate`), `RotateIfNeeded` at cluster-CA expiry−30d, and
`CleanupSecondary` when an overlap window ends. A restart clears the lock but NOT the trigger
for the unattended two, so it is self-reproducing. It was found by accident, in the CONTROL
arm of a harness written to prove something else, and it survived every prior review because
every existing `ImportCA` test calls the method on a LOCAL `clusterCA` value while the re-entrant
reads go through the `globalClusterCA` package variable — a different mutex. The generalisable
lesson: **a test that constructs its own instance of a singleton cannot observe a re-entrancy
defect in that singleton.** Fixed by splitting the mutation (`installLocked`) from the
notification/publication half, which now runs with the lock released; same for
`CleanupSecondary`. Also on those lines: `ImportCA` dereferenced `ca.secondaryCert`
unconditionally, nil-panicking on a FIRST import (row CA-17).

**CHAOS-50** closes the long-open CA-3. (1) `StartCAAutoRotation` was gated on
`certMgr.Ready()` but drives FOUR things — both CAs' `RotateIfNeeded` and both secondary
cleanups — so an inspection-CA fault silently disabled CLUSTER-CA rotation for the process
lifetime, and made every runtime recovery permanent-but-useless (a force-rotated CA that
would never auto-rotate). The gate bought nothing: both `RotateIfNeeded`s already no-op when
their own CA is absent. (2) A failed load was never retried — the faults that actually happen
(volume attaches after the container starts, NFS/EBS hiccup, ownership fixed a minute later,
disk full at first write) all left inspection disabled long after the fault cleared. Now a
BOUNDED campaign (10 attempts, 5 s→5 min backoff, then a terminal log line). The load-bearing
decision: a retry **must never mint**. `LoadOrInitCA` generates a fresh root when the path is
absent, which is right on first boot and catastrophic on a retry — an unmounted volume would
silently swap the fleet's trust anchor for one no client trusts and write it to ephemeral
storage, reproducing the CA-1 symptom from a new cause with the appliance reporting itself
healthy. Recovery re-reads the CONFIGURED bundle only. (3) `sslInspectionLoadError` was
write-only, so `/healthz`, `/readyz?strict=1` and support telemetry stayed red after a REAL
recovery — a probe that outlives its fault, inverting this plane's own
"recovery-on-evidence" rule. (4) An admin-uploaded MITM CA was never persisted (silently lost
on restart). (5) The inspect-matched fail-OPEN bypass had no counter at all, while its
fail-CLOSED twin has had one since CHAOS-28. The fail-open POSTURE is deliberately unchanged
and recorded as **CA-3b** (owner decision): unlike the expired-CA case, refusing here DOES
cost availability that bypassing preserves, so the flip is customer-visible and not a chaos
fix's call. See `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-14.md`.

**2026-08-17 — CHAOS-50 sweep (the boot path under a damaged data volume).**

CHAOS-05/07 settled this question and wrote the answer into `state_corruption.go`
— "refusing to boot could take down a fleet on a single bad sector" — then applied
it to two JSON files and stopped. Row **ST-12** recorded the leftover as a
low-severity doc/behaviour mismatch in `internal/catdb`; it is neither low nor a
doc mismatch. The Layer-2 community category store is the ONLY store on the boot
path that holds no authoritative state (it is a cache of a downloadable feed the
syncer refills automatically) and it was the ONLY one that called `logFatalf` —
so the appliance refused to boot over the one store whose loss costs nothing while
continuing to boot over the admin roster and the revocation list. It is default-ON
in the shipped `docker-compose.yml` (`-cat-feed-db /data/catfeeddb`) on a service
with `restart: unless-stopped`, so a torn MANIFEST after one `docker kill` was an
unattended crash-loop with no proxy, no admin UI, and no health endpoint —
recoverable only by someone with shell access who knew which directory to delete.
Then the domain turned out to be worse than any of that: a corrupt `.sst` does not
make `badger.Open` return an error, it makes it **PANIC from a goroutine badger
itself spawns** (`created by … newLevelsController`), so `recover()` at the call
site never fires — proven live in a child process, and the obvious fix (return the
error instead of exiting) would have left the worst instance untouched. ST-12's
recorded remedy is also unavailable: badger v4 REMOVED `Options.Truncate`, and the
doc comment promising crash-truncation was false. Fixed by `catdb.OpenResilient`:
a marker armed around every open attempt turns "a previous process died inside
badger.Open" into a signal the next boot can act on, the directory is quarantined
(never deleted, `.corrupt.<unixnano>`, bounded at one copy) BEFORE badger touches
it, and every quarantine is gated on a non-blocking `flock` of the directory —
badger's own lock — so a concurrent boot can never rename a live store out from
under its owner. Returned errors are classified against an environmental deny-list
FIRST and a corruption allow-list second, with anything unrecognised degrading:
the fail-safe default is to leave the disk alone. Note for future work in this
area: NONE of these faults are reachable through `errors.Is` — badger wraps them
with `y.Wrapf`, which implements no `Unwrap` — so the empirical fault → message
table is itself a test. Visibility rides existing vocabulary (the `state_file_corrupt`
alert, a new `category_feed_db` diagnostics row, `culvert_catfeeddb_*`), and is
deliberately NOT wired into `/readyz`: Layer-1-only categorisation is a fully
serving node. Three further defects were found in review OF THE FIX and are
recorded in §17 rather than quietly patched, because they are the same class the
sweep is about — a protection that does not hold under the conditions it exists
for: the store lock was probed and RELEASED before the rename (rename(2) ignores
flocks, so the gap let a concurrent boot's live store be renamed underneath it);
a single shared marker path could not survive concurrency (process B correctly
skipped the quarantine and then REMOVED process A's breadcrumb, so an A that
subsequently panicked left nothing for the next boot — the crash loop persisting
through its own remedy); and the recovery was reported BEFORE the outcome was
known, so a quarantine followed by a failed replacement open emitted two alerts
that contradicted each other. See §17 and
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-17.md`.

**2026-08-11 — CHAOS-49 sweep (the multi-IdP registry auth path under IdP failure).**

CHAOS-47 gave the LEGACY identity backends a three-part contract (an infrastructure failure is
never cached as a verdict; an unreachable backend arms a half-open probe gate; both are reported
on the `identity_backend` row) and closed by naming the newer **IdP-registry** path as having
none of it. This sweep confirms that and finds the domain is worse than recorded in three ways
that are not about introspection at all — all three in the **JWKS cache**, the component that
distributes the public keys every ID-token validation depends on. (1) `refresh()` installed
whatever it parsed, so an HTTP **200 carrying no usable keys** — a rate-limiter body, an edge
stub, a full rotation to EC — **WIPED the key cache**, and because the wipe happens on the
SUCCESS path it also destroys the explicit "return the stale key rather than failing" fallback
that exists to survive exactly this: a silent, fleet-wide SSO outage with no log, metric, or
health signal. (2) `resp.StatusCode` was never checked, so a JSON error body behind a 503 took
the same wipe path — a 500 returning HTML was *safer* than a well-behaved JSON 503. (3) The
refetch decision keyed on cache MEMBERSHIP, so an **unknown `kid` re-fetched the JWKS on every
request, forever**; the kid is read from an UNVERIFIED token header, making this an
unauthenticated amplifier (gain = number of configured providers) pointed at the customer's own
IdP — and it fires without an attacker in any 2-IdP estate, because the dispatch loop asks every
provider about every other provider's token. Plus (4) no single-flight: 40 concurrent misses ⇒
40 fetches. And CHAOS-49 as recorded: (5) no introspection result cache — 20 authenticated
requests ⇒ 20 round trips; (6) no probe gate and no health reporting — 11 requests against a
DOWN IdP ⇒ 11 full round trips with `degraded=false`, `gatedDenials=0`, and, because providers
are tried SEQUENTIALLY, up to N × 10 s of serialized dial timeouts per request holding a
goroutine, a connection, and a per-IP slot. All six fixed, each reproduced empirically against
`main` first. The load-bearing decision was to REUSE the CHAOS-47 primitives (`authProbeGate`,
`noteAuthBackend*`, `cacheKey`, `errIntrospectClient`) rather than write a second dialect, so the
new backend lands on the existing `identity_backend` row, metrics, and alert with no new
operator vocabulary and no new config. See
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-11.md`.

**2026-08-09 — CHAOS-28 sweep (the Root CA across its lifecycle).**

The inspection CA is the one control whose failure produces no error anywhere INSIDE the
process. Row **CA-1** was still live on `main`, and worse than recorded: (1) `signLeaf` signed
with an expired CA because `x509.CreateCertificate` does not check the parent's validity and
nothing else did either — verified by running the new gate against the pre-fix engine, where
the sign SUCCEEDED — while `handleTunnel`'s `Ready()` gate (`caCert != nil`) admitted the
session, so every inspected client got a leaf chained to a dead issuer and `/healthz` reported
`ssl_inspection: ready` throughout; (2) leaf `NotAfter` was an unconditional `now+24h`, so
leaves minted in the CA's last day OUTLIVED their issuer; (3) **CA-2** — a rotation whose
`SaveCA` failed still logged and alerted success, so the only recovery path FS-1 has could
silently not persist and mint a different root on every boot; (4) **CA-4** — the rotation loop
made its FIRST check 24h after boot, i.e. never at the moment an operator restarts to recover;
and (5) newly found, unrecorded: `cacheOrder` was appended on every TTL REFRESH while the map
entry was overwritten, so the eviction branch (keyed on map length) never fired and the slice
grew unbounded behind a bounded map — a leak that scales with UPTIME on an ordinary steady
working set. All five fixed. The load-bearing decision was to fail **CLOSED** (502 before the
CONNECT 200) rather than fold expiry into `Ready()`: the one-word fix would have converted an
availability outage into a silent, fleet-wide UNINSPECTED-egress outage — the §1 theme — and is
now blocked by an executable negative assertion. See §16 and
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-09.md`.

**2026-08-07 — CHAOS-27 sweep (the alert plane under an alert storm).**

Row **WK-10** marked webhook delivery resilient, and every bound it cites is real — but all of
them bound *delivery*, and the two defects found here are in front of delivery. (1) The delivery
client was built **per attempt**, so every delivered alert abandoned an `http.Transport` holding
a keep-alive socket with a zero-value `IdleConnTimeout` (= never expires): one FD + two
goroutines leaked per alert, until the *receiver* closed. (2) The Q17 dedup map was unbounded on
an **attacker-controlled key space** (the key embeds the requested host) and fully rescanned
under a process-wide mutex on **every** dispatch — 230,603 ns/op of mutex-held work per alert at
the flood steady state, growing. Both amplify with the security controls working (more blocks →
more alerts), so the alerting plane degraded the gateway hardest while it was under attack, and
FS-1's terminal state is the *proxy* plane running out of descriptors. Both fixed with gates
proven to fail against the pre-fix code. See §15 and
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-07.md`.

**2026-08-06 — CHAOS-25 sweep (HA sync-loop + scanner-goroutine panic containment).**

Closes two of the three paths CHAOS-24 explicitly left unguarded (§12.6): the **HA standby sync
loop** and **`internal/yara`'s per-match goroutine**. Both needed the fail-closed analysis §12.2
demanded rather than a mechanical guard — and the HA one turned out to hold a **split-brain
hazard in the obvious fix**, in the mirror image of the lease-keepalive case. See §14. The MCP
runtime listener remains open and is re-scoped there.

**2026-08-04 — CHAOS-24 sweep (background-worker panic containment).**

Re-verified the standing register against current `main`. Several original findings have since
shipped and are marked **CLOSED** in place below (WK-5 threat-feed stale-erase, ST-5/ST-6 atomic
writes, ST-7 async request log, WK-9 async syslog, PX-3 idle-bounded relays, PX-2 observable
direct-egress fallback). The register's **only remaining Critical item — WK-8 — was still open**,
and this revision closes it. See §12 for the new finding, the split-brain hazard it uncovered in
the *obvious* fix, and what is deliberately left for follow-up.

---

## 1. Executive Summary

Culvert's resilience is **strong on the paths that were explicitly hardened** and **weakest where
a security control degrades silently.** The single most important cross-cutting theme:

> **Silent fail-open degradation.** Several security controls (SSL inspection, ClamAV scanning,
> threat-feed coverage, parent-proxy egress) turn *off* under infrastructure failure while the
> gateway keeps forwarding traffic — with only a log line, no alert, and often no metric. An
> operator watching a dashboard sees green while the control is dark.

The second theme is **background-goroutine fragility**: the long-lived feed/health/broadcast
workers run their loop bodies without `recover()`, so a single panic in any of them takes down an
in-line security appliance.

The third theme is **incomplete adoption of the durable-write primitive**: `fileutil.AtomicWrite`
(fsync + temp + rename + parent-dir fsync) exists and is excellent, but several hot state files
(`admin_settings.json`, `ui_users.json`, audit log) still write through non-atomic, non-fsync'd,
fixed-temp-filename paths — risking silent config/credential loss.

What is genuinely well-built and should be held up as the model for the rest: the **etcd fencing
lease** (split-brain is structurally impossible in lease mode, clock-skew-immune via monotonic
`time.Since` + etcd-as-clock), the **KEK-at-rest** handling (fails closed on every corruption/perm
error, never silently regenerates), the **webhook alert delivery** (bounded queue, bounded retry,
SSRF-guarded, never blocks the producer), and the **async history store** (drops-and-counts under
disk pressure, never stalls the request path).

### Severity tally

| Severity | Count | Headline items |
|----------|-------|----------------|
| Critical | 1 | Background workers have no panic recovery → one panic kills the proxy |
| High | 12 | Silent fail-open on ClamAV / SSL-inspect / threat feed / parent-proxy; expired-CA still signs; admin_settings & ui_users non-atomic writes; stale SSO after IdP delete; no global conn cap; unfenced resumed leader never recovers |
| Medium | 20 | Half-open tunnel leaks, no OCSP/handshake deadlines, syslog blocking on hot path, no ticker jitter, DP max-staleness, etc. |
| Low / Positive | 15+ | Confirmed-resilient paths, documented below with the code that provides the resilience |

---

## 2. Failure Scenarios by Domain

Severity key: **C**ritical / **H**igh / **M**edium / **L**ow / **✓** handled well (positive finding).

### 2.1 Proxy Data Path (HTTP / CONNECT / WebSocket / SOCKS5 / upstream)

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| PX-1 | HTTPS CONNECT, WebSocket, and SOCKS5 dial the origin **directly** — the upstream parent-proxy pool is only wired into the plain-HTTP transport. Parent-proxy chaining silently applies to HTTP only. | GAP | H | `proxy.go:1374,1466`, `socks5.go:320`; pool only via `applyUpstreamProxy`→`getUpstreamTransport()` in `handleHTTP` `proxy.go:928` |
| PX-2 | Circuit breaker / all-upstreams-down **fails open to direct** egress, bypassing the parent-proxy control. | GAP → **PARTLY CLOSED** (CHAOS-11: still fail-open by design, now counted + alerted + surfaced) | H | `internal/upstream/upstream.go:240,267` (`// all upstreams down — fall back to direct`) |
| PX-3 | Raw relays (CONNECT bypass, WebSocket, non-TLS fallback) have **no idle/read deadline** — a half-open peer leaks a goroutine + FD + 128KB pooled buffer indefinitely. Only the SSL-inspect *request loop* arms a deadline. | GAP → **CLOSED** (CHAOS-03 `idleCopyCounted`, `proxy_tunnel.go`) | H | `bidiRelayCounted` `proxy.go:1431,1262`; contrast deadline at `proxy.go:1621` |
| PX-4 | Spawned relay/async goroutines have **no `recover()`** — a panic in any propagates to the runtime and kills the process, dropping every in-flight tunnel. | GAP | M | `go relayCounted(...)` `proxy.go:1290`, inline relays `proxy.go:1565,1747`, `go trackDestinationCountry` `proxy.go:696` |
| PX-5 | SOCKS5 connections **bypass the per-IP connection limiter** entirely. | GAP | M | `handleSOCKS5` `socks5.go:251` never calls `connLimiter.Acquire`; HTTP path does at `proxy.go:627` |
| PX-16 | **The SOCKS5 accept loop retried a failed `Accept` with NO delay, forever.** `net/http.Server.Serve` (every other listener in the process) backs off 5 ms→1 s and stops on a non-temporary error; this loop logged and `continue`d on anything that was not `net.ErrClosed`. EMFILE/ENFILE come straight out of `FD.Accept` without blocking, so a descriptor incident produced **7.68 M attempts / 300 ms**, one log line each — a pinned core, ~40 MB/s into a 50 MB rotating log that erased its own diagnostic history in seconds, and (via `logsink`'s blocking backpressure) added latency to the HTTP data path on a node not using SOCKS5. Self-amplifying: FD exhaustion is the terminal state of WK-11 and PX-6. | NEW → **CLOSED** (CHAOS-54: backoff + errno classification + rate-limited logging; interruptible sleep keeps shutdown prompt) | **H** | was: `socks5.go` `serve`; see §22 |
| PX-17 | **An unrecoverable listener error was retried identically to a transient one.** EBADF/ENOTSOCK on the listening descriptor return instantly and forever, so the "retry" was a pure spin that could never accept anything, on a port that stayed BOUND — clients hung against a black hole instead of getting connection-refused. | NEW → **CLOSED** (CHAOS-54: the loop stops, closes the listener so clients fail fast, and records the service DOWN; transient/unknown errors still retry, which is the fail-safe direction) | M/H | was: `socks5.go` `serve`; now `socks5AcceptFatal` — see §22 |
| PX-18 | **The SOCKS5 listener had NO health surface** — absent from `/healthz`, `/readyz`, `/api/diagnostics` and `/metrics`. A listener spinning on EMFILE and a listener that had stopped accepting entirely were both reported by every probe as a fully healthy node. | NEW → **CLOSED** (CHAOS-54: `socks5_listener` contract row, report-only `/readyz socks5` row, `/healthz socks5` field, `culvert_socks5_{listener_up,accept_errors_total,accept_degraded,accept_backoff_seconds}`, `socks5_listener_down` alert) | M/H | `socks5_health.go` — see §22 |
| PX-20 | **Every `net.ErrClosed` from `Accept` was read as an expected shutdown.** `ErrClosed` says the listener is gone; it does NOT say a shutdown was requested, and `Stop` is only one of the ways a listener can end up closed. Any closure outside the shutdown path therefore terminated the accept loop with EVERY probe still green (`socks5: ready`, `culvert_socks5_listener_up 1`, `ok` contract row) — PX-18 reintroduced in a narrower costume, inside the very change that closed PX-18. Raised by Codex review on the PR, not by the sweep. | NEW → **CLOSED** (CHAOS-54: the loop checks whether `stopping` was actually closed; `Stop` closes it BEFORE `ln.Close()`, so the check is race-free in the direction that matters and errs toward silence, never toward a false page) | M/H | was: `socks5.go` `serve`; see §22.3 |
| PX-19 | **The SOCKS5 accept loop had no panic guard.** `handleSOCKS5` carries `recoverGoroutine`, but a panic in `serve` itself propagated to the runtime and killed the whole proxy process (the PX-4 class, one level up). | NEW → **CLOSED** (CHAOS-54: contained and reported as listener DOWN — the CHAOS-24 objection to recovering in a worker goroutine does not apply when the recovery path is the loudest state the subsystem can produce) | M | was: `socks5.go` `serve`; see §22 |
| PX-6 | **No global connection cap**; per-IP map is unbounded in cardinality; limiter ships **disabled by default**. Distributed flood → FD/memory exhaustion. | GAP | H | `internal/connlimit/connlimit.go:12,67` (default disabled, `Acquire`→true when off) |
| PX-7 | Bandwidth/QoS token buckets are **never enforced on the data path** — `AllowBytes` has no call site in the relays. Configured QoS silently does nothing. | GAP (feature dead) | M | `internal/bandwidth` `AllowBytes` `bandwidth.go:261` — no caller in `proxy.go`/`socks5.go` |
| PX-8 | Shutdown drain only accounts for CONNECT tunnels — WebSocket, non-TLS-fallback, and SOCKS5 relays are invisible to `drainActiveTunnels`, so SIGTERM hard-kills them. | GAP | M | `recordActiveConn` only at `proxy.go:1410,1599`; `drainActiveTunnels` `main.go:1131` |
| PX-9 | Half-open circuit admits **all** concurrent requests, not a single probe → thundering herd on a recovering upstream. | GAP | L/M | `internal/upstream/upstream.go:83` (no single-flight gate) |
| PX-10 | Plain-HTTP `WriteTimeout: 30s` can truncate large/slow legitimate downloads (absolute deadline over `io.Copy`). | GAP | M | `main.go:894`, stream at `proxy.go:1045` |
| PX-11 | SSL-inspect slowloris protection: 60s read deadline + per-`Read` re-arming body-stall detector. | ✓ | — | `proxy.go:1621`, `stallDetectReadCloser` `proxy.go:884`; test `proxy_slowloris_body_test.go` |
| PX-12 | CONNECT/WS stranded-byte handling: hijack-before-200, prebuffer flush before relay (avoids first-byte deadlock). | ✓ | — | `proxy.go:1398-1427` |
| PX-13 | Relay teardown is race-free: `CloseWrite` unblocks peer, buffered `done` chan (cap 2) publishes byte counts via happens-before. | ✓ | — | `proxy.go:1272-1295`, `socks5.go:345-368` |
| PX-14 | Upstream transport swap is atomic (clone-on-write, `atomic.Pointer`); health loop exits on `ctx.Done()`, bounded 5s checks. | ✓ | — | `upstream_transport.go:88-103`, `internal/upstream/upstream.go:329-336` |
| PX-15 | Plain-HTTP request safety: 64MB body cap, 30s client timeout, DNS-fail → 502 + deduped alert. | ✓ | — | `proxy.go:904,932,936`; alert dedup `alerts.go:34` |

### 2.2 CA / Certificates / TLS / Sessions

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| CA-1 | **Expired Root CA keeps signing leaves** — no `time.Now().After(caCert.NotAfter)` guard on the sign path. Every inspected client then sees an opaque expired-issuer TLS error (site-wide inspected-HTTPS outage) with no fast-fail signal. | GAP → **CLOSED** (CHAOS-28: fail-closed 502 at dispatch + `ErrCAUnusable` at the sign path + `culvert_ca_usable`/`_expires_in_seconds` + `ssl_inspection: expired`) | H | was: `internal/ca/ca.go` `signLeaf`; now `internal/ca/validity.go`, `proxy_tunnel.go` `failClosedUnusableCA` — see §16 |
| CA-1b | **Forged leaf `NotAfter` was not clamped to the issuer's** — leaves minted in the CA's final 24h claimed validity past their own issuer, the state that makes an expiry incident hardest to diagnose (leaf looks valid, only the chain fails). | GAP → **CLOSED** (CHAOS-28, `clampLeafValidity`, both ends) | M | was: `internal/ca/ca.go` `signLeaf` `NotAfter: now+24h`; see §16 |
| CA-2 | Rotation `SaveCA` failure (disk full / read-only) is **swallowed** — logged, still returns `true`, still fires the "rotated successfully" alert. New CA lives only in RAM; next restart reloads the old near-expiry bundle. | GAP → **CLOSED** (CHAOS-28, `RotationPersistFailureObserver` + distinct log wording + `culvert_ca_rotation_persist_failures_total` + CA-panel banner) | H | was: `internal/ca/ca.go` `RotateIfNeeded`; see §16 |
| CA-3 | Corrupt bundle / wrong `CULVERT_CA_PASSPHRASE` / expired-at-rest CA at startup → **fail OPEN**: inspection silently disabled, traffic falls through to SSL-bypass (no DPI/CDR/file-blocking). Log line only, no alert, no `ssl_inspection_ready` gauge. | GAP → **CLOSED** (visibility by CHAOS-06; RECOVERY by CHAOS-50: bounded retry campaign that never mints, `noteSSLInspectionRecovered` clears the latch on evidence, `culvert_ca_load_failed` + `culvert_ca_inspect_bypassed_total`, CA-panel fail-open banner. The POSTURE is split out as CA-3b) | H | was: `rootca_startup.go:40-44`; now `rootca_recovery.go`, `ca_metrics.go` `caWriteLoadFailurePrometheus` — see the 2026-08-14 review |
| CA-3b | **Fail-open/fail-closed asymmetry**: an inspect-matched CONNECT with no CA loaded proceeds as an unscanned tunnel, while the same appliance-wide fault found at EXPIRY is refused 502 (CA-1). Opposite postures for one fault class, decided by `caCert != nil`. CHAOS-28's supporting argument ("refusing costs no availability that signing would have preserved") does NOT carry over — this traffic works fine as a tunnel — so the flip is a customer-visible availability decision. | GAP (**owner decision**; window now short + measurable) | H | `handleTunnel` `proxy_tunnel.go:321,347`; counter `noteCAInspectUnavailableBypass` |
| CA-17 | **Cluster-CA install path SELF-DEADLOCKS**: `ImportCA` held `ca.mu.Lock()` across `onRotate`→`rebuildCPCertPool`→`AllCACertsPEM`→`RLock` AND across `CurrentConfigSnapshot()`→`CACertFingerprint`→`RLock`; `CleanupSecondary` repeated the first. Non-reentrant `sync.RWMutex` ⇒ write lock held for the life of the process ⇒ every cluster-CA reader blocks, incl. every CP→DP ConfigSnapshot. Total CP stall; restart does not clear the unattended triggers. Plus a nil-deref on `ca.secondaryCert` on a FIRST import. Invisible to the suite because every prior test used a LOCAL `clusterCA` while the re-entrant reads go through `globalClusterCA`. | NEW → **CLOSED** (CHAOS-51: `installLocked` + post-lock effects; `TestChaos51_*` install the object AS the global and stand up `cpTLSConfig`) | **Critical** | was: `enrollment.go:1128,1185,1201,1223`; see the 2026-08-14 review |
| CA-4 | Auto-rotation loop: **no immediate startup check** (24h blind spot after boot), **no retry/backoff** on failure (waits a fixed 24h). | GAP → **PARTLY CLOSED** (CHAOS-28: the startup blind spot is closed — one guarded round runs before the ticker, sharing the CHAOS-24 guard. Retry/backoff on a FAILED rotation still waits the full 24h) | M/H | `ca.go` `StartCAAutoRotation`; see §16 |
| CA-5 | `cert_expiry` alert only fires **on rotation**, not as an early warning — contract says "fired on startup if ≤30 days" but the only producer is the rotation observer. | GAP (contract mismatch) | M | producer `ca.go:45-53`; contract `internal/alerts/store.go:17` |
| CA-6 | OCSP fails **closed** when a cert lists responders and none answer; `VerifyConnection` re-checks resumed sessions. Caveats: nil-issuer → fail-open; OCSP client has no SSRF guard on the peer-controlled responder URL. | ✓ (+2 caveats) | L/M | `internal/ocsp/ocsp.go:177-181`, `ocsp.go:41-56`; caveats `ocsp.go:139-142,187-206` |
| CA-7 | KEK-at-rest: rejects too-permissive/wrong-size files (never chmod-fixes, never silently regenerates), uses `os.Link` EEXIST to avoid racing mints, fails closed on decrypt error. | ✓ | — | `kek.go:174-239`, `cluster_ca_keyatrest.go:95-181` |
| CA-8 | Session HMAC key is **random per-restart by default** (no env/config secret) → all admin sessions invalidated on every single-node restart. | GAP | M | `session.go:38-49`, `internal/session/session.go:80-86` |
| CA-9 | Session HMAC runtime rotation / cluster sync is race-safe (lock-guarded set/read, hex+len validation before install, redacted on export). | ✓ | — | `internal/session/session.go:51-55,422-429`, `controlplane.go:1848-1862` |
| CA-10 | Clock skew/rollback: sessions use wall-clock `time.Now()`; leaf certs backdate only 5 min (`ca.go:747`) vs the UI cert's 1h — >5 min skew makes fresh leaves "not yet valid" to clients. | GAP | M | `internal/session/session.go:408`, `internal/ca/ca.go:747` vs `internal/uitls/uitls.go:52` |
| CA-11 | Leaf-cert cache has **no single-flight** — N concurrent misses for one host each sign independently; TTL expiry is synchronized (thundering herd). | GAP (re-scoped by CHAOS-28: the perf-F3 shared leaf key removed the dominant per-miss cost — P-256 keygen — so the herd is materially cheaper than when first recorded) | M → L/M | `internal/ca/ca.go` `GetCert` |
| CA-16 | Leaf-cache **`cacheOrder` slice grew on every TTL REFRESH** while the map entry was overwritten. `len(cache)` never changed, so the eviction branch never fired: an unbounded slice behind a bounded map, growing with UPTIME on an ordinary steady working set (W=5,000 hosts ⇒ ~120k strings/day). Invisible to `culvert_cert_cache_size`, which reports the bounded map. | NEW → **CLOSED** (CHAOS-28: append only for an untracked host; behavior-preserving for eviction — duplicate entries always resolved to "already gone") | M | was: `internal/ca/ca.go` `GetCert`; see §16 |
| CA-12 | Upstream & client MITM handshakes inherit only `r.Context()` (no explicit handshake deadline); a slowloris handshake ties up the goroutine. Good: uses `HandshakeContext`, not `Handshake()`. | GAP | M | `proxy.go:1503,1591` |
| CA-13 | Cluster CA rotation mirrors CA-2: every failure branch logs-and-returns with no alert/metric. Silent failure → cluster-wide enrollment break at expiry. | GAP → **CLOSED** (CHAOS-50: `noteClusterCARotationFailure` → `culvert_cluster_ca_rotation_failures_total` + `cert_expiry` alert + `cluster_ca` rows on `/healthz`, `/readyz`, `/api/diagnostics`; degraded state cleared on a LANDED rotation only) | M | was: `enrollment.go` `recordRotationFailure`; now `cluster_ca_health.go` — see §17 |
| CA-17 | **`clusterCA.ImportCA` and `CleanupSecondary` SELF-DEADLOCK.** `ca.mu.Lock()` was held across post-commit side effects that read the CA back through the package global (`onRotate`→`rebuildCPCertPool`→`AllCACertsPEM()`; `CurrentConfigSnapshot()`→`CACertFingerprint()`), both taking `ca.mu.RLock()` on the same object — the receiver IS the global in production. The goroutine blocks forever WHILE HOLDING the write lock, so every `SignCSR` (enrollment + unattended renewal), fingerprint read (⇒ all config publication) and TLS-pool rebuild queues behind it until restart. Triggers: `POST /api/cluster/ca`, `RotateIfNeeded` at −30d, and overlap cleanup at +30d — the latter two hang the goroutine driving BOTH trust roots, so the inspection CA stops rotating too. **Already known and worked around in the test suite** (`cluster_ca_keyatrest_test.go`: *"a pre-existing self-deadlock … out of scope"*), never registered. | NEW → **CLOSED** (CHAOS-50: `commitImport` under the lock, side effects with it released, `importMu` serialises operations; proven pre-fix by stack trace) | **C** | was: `enrollment.go` `ImportCA`/`CleanupSecondary`; see §17.2 |
| CA-18 | **Expired cluster CA kept signing node certs** (CA-1 analogue in the enrollment CA) and node cert `NotAfter` was an unconditional `now+365d`, **not clamped to the issuer** — so a node enrolled anywhere in the CA's final year held a cert overclaiming by up to a YEAR, and every expiry surface (nodes API, DP `checkDPCertExpiry`) reported validity that did not exist. Worse than CA-1: `Enroll` uses `VerifyClientCertIfGiven`, so the operator's *re-enroll* recovery succeeded and returned a certificate that was dead on arrival. | NEW → **CLOSED** (CHAOS-50: `clusterCAUsable` gate in `SignCSR` fails closed with `errClusterCAUnusable`; `clampNodeCertValidity` on both ends; `culvert_cluster_ca_{usable,expires_in_seconds,sign_refused_total,node_certs_clamped_total}`) | **H** | was: `enrollment.go` `SignCSR`; now `cluster_ca_validity.go` — see §17 |
| CA-19 | **The cluster CA's ONLY rotation driver was gated on the INSPECTION CA being ready** (`loadRootCA`: `if certMgr.Ready() { StartCAAutoRotation(…) }`). A corrupt bundle / wrong `CULVERT_CA_PASSPHRASE` / unreadable `-ca-path` silently disabled cluster-CA auto-rotation AND secondary-overlap cleanup on a node whose cluster CA was healthy. Two independent trust roots, one shared failure — and because the cluster CA is a 10-YEAR cert, the consequence surfaces years after the fault that caused it, with nothing left to connect them. | NEW → **CLOSED** (CHAOS-50: loop started unconditionally; both halves are already no-ops when their CA is absent; pinned by `TestChaos50_ClusterRotationSurvivesInspectionCALoadFailure`, verified FAILING pre-fix) | M/H | was: `rootca_startup.go` `loadRootCA`; see §17.5 |
| CA-20 | `ImportCA` **nil-dereferenced `ca.secondaryCert`** on a first-ever import (a node that never ran `InitOrLoad`, e.g. a non-cluster node whose admin posts `/api/cluster/ca`) — and it fired AFTER `ca.cert`/`ca.key` were swapped in, so the panic left the new CA installed with the TLS pool never rebuilt and no rotation tracking: a partially applied trust change. | NEW → **CLOSED** (CHAOS-50: guarded — a first import is a bootstrap, not a rotation) | M | was: `enrollment.go` `ImportCA`; see §17 |
| CA-14 | Revocation persistence uses `os.WriteFile`+rename with **no fsync** (unlike the CA bundle's `AtomicWrite`) — a revoked token can be honored again after crash/disk-full. | GAP | L/M | `internal/session/session.go:272-276`, caller `session.go:106-108` |
| CA-15 | CA loader **accepts a plain-PEM bundle even when a passphrase is set** (magic absent) — a downgrade footgun; logged, not alerted/rejected. | GAP (minor) | L | `internal/ca/ca.go:221-229` |

### 2.3 Cluster / HA / Control-Plane ↔ Data-Plane

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| HA-1 | CP unavailable: DP serves last-good config **indefinitely** — no max-staleness ceiling. A partitioned DP can enforce hours-old policy (stale allowlist / stale revocation view). | GAP (by design) | M | `main.go:1762`, `loadDPLastGoodConfigSnapshot` `controlplane.go:1929`, `fetchAndApply` `controlplane.go:1369-1441` |
| HA-2 | etcd witness unreachable: leadership **lazily denied** (fail-closed) — cluster degrades read-only, not split-brain. Only malformed config is fatal. | ✓ | — | `cluster_startup.go:146-178`, `acquireLeaseForLeadership` `ha_lease.go:75-102` |
| HA-3 | Lease keepalive transport failure & clock skew: self-fence bounded by the etcd-confirmed window; `time.Since(confirmedAt)` monotonic → clock-jump-immune; cross-node absolute time never compared. | ✓ | — | `ha_lease.go:154-186`, `internal/halease/etcd.go:118-128`; tests `ha_lease_test.go:105,139` |
| HA-4 | Split brain **with** the fence: structurally impossible (single `CreateRevision==0` txn; promote re-checks Acquire; term = epoch). | ✓ | — | `ha.go:617-621,634`, `internal/halease/etcd.go:73-92`; test `ha_split_brain_failover_evidence_test.go:172` |
| HA-5 | Split brain **without** the fence (legacy 2-node `--ha-auto-failover`): restarted leader resumes with no peer probe, **no rejoin reconcile**. Documented RISK-001. | GAP (accepted) | H | `cluster_startup.go:101-111`; tests `ha_split_brain_failover_evidence_test.go:220,268` |
| HA-6 | Ghost lease on fast leader restart: `acquireLeaseForResume` distinguishes own-ghost (`Holder==id`, wait ≤45s) from a real denial (immediate false). Since CHAOS-55 it also distinguishes an UNREACHABLE backend (retried inside the same budget) — see HA-7/HA-16. | ✓ | — | `ha_failover.go` `acquireLeaseForResume` / `resumeAcquireRound` |
| HA-7 | **Unfenced resumed leader never re-acquires.** `acquireLeaseForResume` spent its 45s budget ONLY on waiting out its own ghost lease and returned false on the FIRST transport error — the boot-order fault (etcd seconds behind culvert on a host reboot) got zero retries. `ResumeAsLeader` then asserted `role=leader, leaseEpoch=0`, and `startLeaseKeepalive` no-ops on a zero epoch, so nothing in the process ever called `Acquire` again: permanently read-only (no issuance, no revocation sync, no accepted snapshot) until a human restarted it — `PromoteManually` refuses a node already roled `leader`, so a restart was the ONLY lever. | GAP → **CLOSED** (CHAOS-55: the resume budget now covers transport errors; a rate-bounded background re-acquire loop covers a longer outage) | **H** | was: `ha.go` `ResumeAsLeader`, `ha_failover.go` `acquireLeaseForResume`, keepalive no-op `ha_lease.go:111`; see §23 |
| HA-16 | **Leadership given up on an UNKNOWN fence state.** `ResumeAsLeader` demoted to standby on ANY failed resume when `standbyAddr` was recorded — including an unreachable backend, which says nothing about who leads. In a 2-node cluster restarting together the guess is symmetric: each node stands by against the other, neither can sync (`verifyBundleEpoch` rejects a bundle with no live holder), so `lastSyncOK` stays zero and `leaseAutoPromote`'s freshness gate refuses every promotion — a **permanently leaderless cluster** produced by a few seconds of etcd being slow to boot. Exactly the rule `ha_lease.go`'s own header states for the other direction, broken in reverse. | NEW → **CLOSED** (CHAOS-55: demotion gated on an AFFIRMATIVE foreign-holder read; an unknown keeps the read-only leader role and hands the decision to the recovery loop) | **H** | was: `ha.go` `ResumeAsLeader`; see §23 |
| HA-17 | **An unfenced leader was invisible to Prometheus.** `culvert_ha_role 1` is emitted identically by a healthy leader and by one that cannot issue a certificate, accept a revocation or publish a snapshot; `lease_valid` existed only on JSON no alerting rule can read, and `ha_resume_unfenced` fired ONCE at boot (a webhook outage correlated with the restart that caused it hid the state permanently). | NEW → **CLOSED** (CHAOS-55: six `culvert_ha_{write_authority,lease_epoch,unfenced,lease_recovering,lease_reacquire_attempts_total,lease_reacquired_total}` series, emitted only when a fence is armed; `lease_recovering` separates "read-only and working on it" from "read-only and stuck") | **M** | was: `cluster_metrics.go`; see §23 |
| HA-18 | **A self-fenced ex-leader with no recorded ex-standby is a passive standby forever.** `selfFence` demotes and `enterStandbyResync` fails when no standby has ever synced to this leader; the node then has no sync loop, no keepalive and no recovery loop. If the fence was lost to a transient etcd outage nobody else acquired either, so the lease is free on etcd's return and no node in the cluster is asking for it. NOT covered by the CHAOS-55 loop by design: re-acquiring from `role=standby` is a PROMOTION, and its freshness gate is keyed on `lastSyncOK` — structurally wrong for an ex-leader, which does not sync. **Owner question:** should an ex-leader's own last-write time substitute for `lastSyncOK`? Sibling of WK-2b / CA-3b. | NEW (recorded, not fixed) | **M** | `ha_lease.go` `selfFence`, `ha_failover.go` `leaseAutoPromote`; see §23.5 |
| HA-19 | **A free lease proves nobody holds it NOW, not that nobody held it since we last looked.** Raised by Codex review of PR #1223 against the CHAOS-55 recovery loop. A peer can acquire, take config writes, crash, and have its lease expire; if that whole tenure fits between two of our observations we see only "free" and re-acquire as a STALE leader, reverting the peer's writes. Partly closed in the same PR: the poll interval is now capped below the lease TTL (`recoveryPollCeiling`), and because etcd keeps a holder's key for ≥1 TTL after it stops renewing, a completed-and-vanished tenure can no longer pass between two SUCCESSFUL observations. **The residual is a blind period we cannot bound from inside this node:** a partition in which WE cannot reach etcd but a peer CAN. Note the same property already holds for the shipped resume path — an operator-restarted leader acquires a free lease with no proof either — so this is the pre-existing class, now reachable without a restart. Closing it needs either durable evidence of the intervening epoch (etcd's `create_revision` advances on unrelated writes, so epoch gaps carry no information, and a free-lease `Read` returns no watermark) or routing a long-blind recovery through the standby freshness machinery instead of acquiring. That is a safety-vs-availability posture call of the same class as HA-18 — recorded for an owner, not settled here. | NEW (partly closed; residual recorded) | **M** | `ha_lease_recovery.go` `recoveryPollCeiling` / `leaseRecoveryAttempt`; see §23.5 |
| HA-8 | Stale/rolled-back ConfigSnapshot: `dpObserveEpoch` monotonic CAS ratchet + puller-side no-live-holder reject; runs before any mutation. Caveat: in-memory floor re-seeds from last-good on restart. | ✓ | L | `ha_fencing.go:119-137,73-103`, `controlplane.go:1424,1667` |
| HA-9 | **Enrollment token corrupt `AllowCIDR` → nil-deref panic** (`net.ParseCIDR` error discarded, `cidr.Contains` on nil). Otherwise replay/expiry/prefix/CIDR are atomically consumed under lock. **FIXED in this PR.** | GAP → fixed | L | `enrollment.go:273-279` (fix), consume-under-lock `enrollment.go:241-294` |
| HA-10 | DP node lost: heartbeat monitor flips connected→disconnected after 90s (3 missed polls), race-safe persist; nodes warned at 24h, never auto-revoked. | ✓ | L | `enrollment.go:627-646,619-624` |
| HA-11 | CP restart while DPs connected: exponential backoff 2s→64s, failover only after 3 consecutive failures. **No jitter** on the 30s poll ticker → fleet re-sync thundering herd. | ✓ (+jitter gap) | L | `controlplane.go:1249-1260,1354-1367` |
| HA-12 | Rolling update mid-canary: error-budget halt/rollback, explicit drain with clear-on-every-exit, crash recovery maps in-flight → terminal. Soft spot: `updating_cp` recovery **assumes success** without verifying the running image tag. | ✓ (+GAP 12A) | M | `update_cluster.go:761-800,869-951,1011-1076`; optimistic transition `update_cluster.go:1025-1030` |
| HA-13 | HA-aware CP update handoff uses a **fixed 15s sleep**, never confirms the standby actually promoted before taking the leader down → possible leaderless window; reports success regardless. | GAP | M | `update_cluster.go:593-598,706-746` |
| HA-14 | Session HMAC / secrets sync: fenced in-band (good), but `persistDPLastGoodConfigSnapshot` writes the whole snapshot **including `SessionHMAC`** as plaintext JSON (0600) — no envelope encryption like the CA key gets. | GAP (at-rest) | M | `controlplane.go:1979-1997,2058-2061` vs DP node-key encrypt `main.go:1757-1760` |
| HA-15 | Puller "no live holder" reject couples standby replication to a healthy leader lease — a witness outage stalls replication until a holder reappears (intended safety-over-availability; needs a runbook entry). | ✓ (documented) | L | `ha_fencing.go:94-97,83-85` |

### 2.4 Storage / Filesystem / Persistence / Configuration

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| ST-1 | `fileutil.AtomicWrite`: temp + fsync + rename + parent-dir fsync, tolerant of ENOTSUP, cleanup on every error. Adopted by blocklist, threatfeed, sslbypass, configver. | ✓ | — | `internal/fileutil/fileutil.go:19-71` |
| ST-2 | History store (Badger) non-blocking on the hot path: bounded `select … default → drop+count`, batched flush, disk-pressure `minimal` mode drops LOW-priority but keeps security events. | ✓ | — | `internal/logstore/logstore.go:328-401` |
| ST-3 | Config-version retention cap (50) enforced on every `Save`; serialized capture→save prevents stale-under-higher-version; corrupt snapshots → `ErrCorrupt`→HTTP 500, skipped in `List`. | ✓ | — | `internal/configver/configver.go:132-150`, `configversion.go:89-112,159-169` |
| ST-4 | SIGHUP reload fail-safe: bad YAML → "keeping current config"; blocklist swaps maps only after successful open+scan. | ✓ | — | `main.go:979-985,1938-1990`, `internal/blocklist/blocklist.go:188-202` |
| ST-5 | **`admin_settings.json`: concurrent goroutine writers to a fixed `.tmp`, no fsync.** `adminSettingsSave()` launches each save in a goroutine and releases the mutex before writing → interleaved bytes → corrupt JSON → next boot silently reverts **all** admin settings to defaults. | GAP → **CLOSED** (`fileutil.AtomicWrite`, `admin_settings.go:660`) | H | `admin_settings.go:407-421,327-329,132-134` |
| ST-6 | **`ui_users.json`: non-atomic write (no fsync) + fail-open-to-empty roster on corruption.** Power loss mid-save loses the entire admin roster + TOTP secrets + `default_auth_outcome`; loader starts empty with no quarantine → potential admin lockout. | GAP → **CLOSED** (`fileutil.AtomicWrite`, `store.go:887`) | H | `store.go:759-763,691-693`, `auth_startup.go:39-40` |
| ST-7 | Persistent request-log JSONL write is **synchronous + globally serialized** under one mutex on the hot path → slow disk collapses proxy throughput (head-of-line). Disk-*full* is handled (counted, once-logged). | GAP → **CLOSED** (async bounded queue + single drainer, `internal/reqlog/persist.go`) | M | `internal/reqlog/reqlog.go:154-167`, `internal/fileutil/rotating.go:40-61` |
| ST-8 | Audit write **silently drops on I/O failure** (`//nolint:errcheck`, no counter) — compliance "who changed what" vanishes on full/RO disk; `GetPersistent` re-reads the whole file per query. | GAP → **CLOSED (silent-loss half)** — every lost entry counted (`audit.WriteErrors()`), first failure logged, wired into the storage-health plane (degraded contract row + `storage_write_failed` alert), surfaced on `/api/stats`, `/metrics`, `/healthz` and the dashboard. Residual: persistence stays best-effort (an admin change still succeeds over a failing disk) and the `GetPersistent` full-file re-read is untouched — see §13 | M/H | `internal/audit/audit.go` (`countWriteError`, `SetWriteFailureObserver`), `storage_health.go` init |
| ST-9 | Startup `logger.Fatalf` on blocklist/URL-category read errors (any non-`IsNotExist`) → **crash-loop** on permission/EIO faults. | GAP → **PARTLY CLOSED** (CHAOS-50 closed the Layer-2 community-store half — the one load with no defensible reason to be fatal. The three remaining fatal loads — `catStore.Load`, the blocklist, the policy file — are a POSTURE decision recorded as R-F in §19: `ui_users.json` and `cluster.json` quarantine-and-continue on a corrupt file while `categories.json`, their closest analogue, exits) | M | `blocklist_startup.go:59`, `main.go:724`, `urlcategories_startup.go` (catStore.Load); Layer-2 half now `loadCommunityFeedDB` — see §19 |
| ST-10 | Backup is not a consistent cross-file snapshot (inputs read at different instants); residual non-atomic writers (`cdrpolicy.go:195`, `internal/scanexcl/scanexcl.go:93`, `update_cluster.go:193`). | GAP | L/M | backup pack loop `backup.go:~280`; flagged by `cluster_persistence_atomic_test.go:8` |
| ST-11 | RotatingFile keeps one archive; reopen failure after rename leaves logging wedged until restart (bounded-growth design otherwise correct). | ✓ (edge) | L | `internal/fileutil/rotating.go:44-56` |
| ST-12 | catdb corruption-recovery comment claims Badger truncate-on-corruption but `Open` sets no such option; a corrupt community DB is fatal via ST-9 coupling. **Re-scoped by CHAOS-50 and far worse than recorded:** the option does not exist to add (badger v4 REMOVED `Options.Truncate`), the store was default-ON in the shipped compose file behind `restart: unless-stopped` (⇒ unattended crash-loop, no admin UI to recover from), and the worst fault does not return an error at all — a corrupt `.sst` PANICS from a badger-spawned goroutine, so no caller-side `recover()` can contain it. | GAP (doc/behavior) → **CLOSED** (CHAOS-50: `catdb.OpenResilient` — poison marker + flock-gated quarantine + deny-list-first classifier; degrade, never exit) | L → **H** | was: `internal/catdb/catdb.go` `Open`; now `internal/catdb/resilient.go`, `loadCommunityFeedDB` — see §17 |

### 2.5 Authentication / Identity / Sessions

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| AU-1 | Registry OIDC introspection has **no result cache** → one IdP round-trip per request, ×N providers, each 10s timeout. The legacy `OIDCAuth` *does* cache (2-min TTL); the newer registry path dropped it. | GAP | H | `auth_oidc_flow.go:344-363,608-627` (no cache field); loop `proxy.go:209-220`; contrast `auth_oidc.go:210-238` |
| AU-2 | In-flight SSO sessions **survive IdP deletion** — no `RevokeProvider`; cookies are self-contained and keep full access up to TTL (default 8h). User-delete *does* revoke. | GAP | H | `auth_idp.go:319-330`, `ui_auth.go:517-529` vs `ui_auth.go:245` |
| AU-3 | Proxy-path Basic-auth bcrypt is **not rate-limited** — correct-username + N wrong-passwords is a cache miss every time → full ~100ms bcrypt per request → CPU starvation. The `loginLimiter` guards only the admin UI. | GAP | M | `store.go:440-444`, limiter only at `ui_auth.go:48,116`, proxy call `proxy.go:223` |
| AU-4 | Lockout store is bounded + fail-closed, and TOTP failures now feed it. But it is **not persisted** (resets on restart) and **per-node** (attacker gets MaxAttempts per node in a cluster). | ✓ (+2 gaps) | M | `lockout.go:111-126,102-110`; per-node note `roadmap/edge-case-audit.md:138` |
| AU-5 | LDAP proxy auth fails closed, but the 10s timeout covers only the **dial** — `Bind`/`Search` have no per-op deadline, so a server that accepts then stalls hangs the request goroutine. | GAP | M | `auth_ldap.go:128-180` |
| AU-6 | SAML metadata & OIDC discovery fetched **once** at compile — no periodic refresh. IdP SAML signing-cert rotation breaks assertion validation until re-save/restart. (OIDC JWKs *do* auto-refresh every 15 min + serve-stale.) | GAP | M | `auth_saml.go:54-57,249-294`; JWKs OK `auth_oidc_flow.go:129-157` |
| AU-7 | IdP 5xx / network error / expired token all collapse to fail-closed "auth fail" — correct posture, but an IdP outage is indistinguishable from a brute-force spike (no distinct `idp.unreachable` metric). | ✓ (obs gap) | L | `auth_oidc.go:152-162`, `auth_oidc_flow.go:623-636` |
| AU-8 | Auth caches bounded at 5000 with eviction; HMAC-keyed keys (heap-dump safe); cached OK TTL capped at token `exp`. | ✓ | — | `store.go:236,241-258,268-285`, `auth_oidc.go:219-227` |
| AU-9 | Session HMAC key change / per-node divergence logs everyone out (fail-closed) — no rotation grace window; cluster without shared key needs affinity. | GAP | M | `session.go:390-393`, `InitRandomKey` `session.go:80-86` |
| AU-10 | TOTP: 30s step, ±1 window (~90s skew tolerance), replay closed via `counter <= lastCounter`, empty-secret fails closed. | ✓ | — | `totp.go:47-88` |
| AU-11 | Multi-IdP registry: compile is isolated (all-or-nothing staging swap; bad profile dropped, not fatal). But the **request-time provider loop is sequential and unguarded** — one slow IdP adds latency to every request that reaches it. | ✓ compile / GAP request | M | `auth_idp.go:159-165,354-376` vs loop `proxy.go:209-220` |
| AU-12 | All admin-configured IdP URLs dial through `ssrfSafeDialContext`; HTTPS+non-private pre-validated; response bodies `io.LimitReader`-capped. | ✓ | — | `auth_oidc_flow.go:64,300`, `auth_idp.go:556-565` |
| AU-13 | Registry introspection also lacks **negative caching / circuit breaker** — a permanently-invalid token amplifies one IdP call per provider per request forever. | GAP | M | `auth_oidc_flow.go:623-636`; breaker exists unused `internal/upstream/upstream.go:89-96` |
| AU-14 | **The public admin-login endpoint accepted an UNBOUNDED username and copied it verbatim into durable state.** `apiAuthLogin` is on `uiAuthMiddleware`'s public allowlist; nothing between the 1 MiB body cap and the handler limited `body.User`, and every failed attempt wrote it into the two lockout maps (retained ≥ `lockout.Window`), the 500-entry audit ring, and the **durable audit JSONL** — a 50 MB rotating file keeping exactly ONE archive. At the endpoint's own rate limit (60 mutating POSTs/min/IP) one unauthenticated client commits ~60 MiB/min of chosen bytes, rotating the entire 100 MB retained compliance record away in **under two minutes**, with no disk fault and every write SUCCEEDING (so `writeErrors`/`storage_write_failed` never fire). Measured by the gate: **4,195,672 bytes into the audit file from 8 requests.** | NEW → **CLOSED** (CHAOS-58: bounded at the handler; `lockout.MaxUsernameKeyLen` is the structural half; `culvert_login_oversize_rejected_total`) | **H** | was: `ui_auth.go` `apiAuthLogin`; `internal/audit/audit.go:213` (`NewRotatingFile(path, 50)`); see §25 |
| AU-15 | **`internal/lockout` bounded its maps by ENTRY COUNT but not by KEY SIZE.** `Cleanup`'s own doc claims the maps are bounded "against an unbounded-memory DoS" — true on the count axis, and the janitor cannot sweep an entry before its `Window` elapses, so the SIZE axis was the whole exposure: one caller retained (rate × Window × username size) bytes in a leaf package whose stated contract is to be bounded. | NEW → **CLOSED** (CHAOS-58: `boundUsername` applied at every public entry point; consistency pinned so `Check` and `RecordFailure` cannot disagree on the key) | M/H | was: `internal/lockout/lockout.go`; see §25 |

### 2.6 Background Workers / Feeds / Scanning / Alerting

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| WK-1 | **ClamAV daemon down → files pass UNSCANNED (fail-open), no alert/counter.** Contradicts the same file's *timeout* path, which fails **closed**. Two infra-failure modes, opposite postures. **Re-scoped by CHAOS-52 and larger than recorded:** the fail-open branch was reachable by LOAD, not only by a daemon fault (see WK-15), because a private 5 s queue deadline preempted the 10 s fail-closed one. The visibility half closed with CHAOS-10 (counter + `scan_clam_error` + never caching a dark verdict); the LOAD half closed with CHAOS-52. | GAP → **visibility CLOSED** (CHAOS-10), **load-reachability CLOSED** (CHAOS-52); the daemon-DOWN posture is split out as WK-1b | H | `internal/secscan/secscan.go` `scanBodyInner`/`recordClamFailure` |
| WK-1b | **Posture**: a ClamAV daemon that is genuinely DOWN still fails OPEN (counted + alerted). Deliberately asymmetric with saturation, which now fails closed: a down daemon is an operator-visible infrastructure state with its own alert and status surface and refusing all traffic on it is a fleet-wide outage, whereas saturation is transient, self-clearing in seconds, and inducible on demand by whoever wants the gap. Same class as CA-3b. | GAP (**owner decision**; now counted, alerted, and distinguishable from saturation) | H | `internal/secscan/secscan.go` `recordClamFailure` default branch |
| WK-2 | Remote scan sidecar down → fail-open, **but** alerted (`scan_svc_down`) + counted. Posture not admin-selectable; 30s per-request timeout stacks latency when hard-down. **Re-scoped by CHAOS-53 and much larger than recorded:** that 30 s timeout was not merely latency, it was a PRIVATE deadline three times the process's own fail-closed scan budget, and exceeding it surfaced as a transport error → classified as a fault → fail-OPEN. So a merely SLOW sidecar forwarded content unscanned while the local back end blocks for the identical condition (WK-19). The down-sidecar posture is split out as WK-2b. | GAP → **slowness/capacity CLOSED** (CHAOS-53, §21); the sidecar-DOWN posture is split out as WK-2b | H | `internal/secscan/remote.go` `ScanBody`/`scanOnce` |
| WK-2b | **Posture**: a sidecar that is genuinely unreachable/erroring still fails OPEN (counted + alerted). Deliberately asymmetric with slowness and capacity, which now fail closed — exactly the WK-1/WK-1b split, for the same reasons. | GAP (**owner decision**; now counted, gated-alerted, rate-limit logged, and reachable only by an actual fault) | H | `internal/secscan/remote.go` `remoteScanFail` |
| WK-19 | **The remote sidecar had none of the CHAOS-52 protections, and the runbook recommended switching to it.** Six further defects: any HTTP 200 whose body parsed as JSON (`{}`, `null`) was read as CLEAN with no counter/log/alert; NO `culvert_scan_*` series is produced on a sidecar node and `stat_remote_scan_fail` never reached `/metrics`; the fail-open alert fired per request ungated with a raw `err.Error()` (ephemeral port ⇒ un-dedupable key) and logged per request; scan exclusions were never LOADED in remote mode, so `scanexcl.Store` had no path and every admin Save was a silent no-op that returned 200 and was audited as success; the hash allowlist was never consulted and `Result.Hash` came from the SIDECAR; `Status()` decoded an unbounded body on an admin endpoint; and the sidecar's own status blob shadowed this node's `scan_svc_mode`, so a remote node reported "local". | GAP → **CLOSED (CHAOS-53)** | **H** | §21; `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-22.md` |
| WK-3 | GeoIP cache-miss on the policy hot path fails **closed** (country allow-rule cannot match unknown country); `LookupCached` never blocks on DB/DNS. | ✓ | — | `policy.go:831-839`, `geoip.go:84-93`; tests `final_coverage_test.go:203` |
| WK-4 | GeoIP DB missing/corrupt: reader stays nil, feature degrades to "no country data" — safe, but **no staleness/health signal** (MMDBs expire silently). | GAP (obs) → **PARTIALLY CLOSED** (`BuildTime()` reads the `.mmdb`'s own `build_epoch`; `GET /api/geoip` returns `dbBuildDate`/`dbAgeDays`; GeoIP Database panel shows the age, warn-colored past 90 days; load failures surfaced via `lastError`. Residual: no PROACTIVE alert/metric — an operator must open the panel to notice) | M | `internal/geoip/geoip.go` `BuildTime`, `ui_security.go` `apiGeoIPConfig` |
| WK-5 | **Threat-feed timeout → stale-erase.** On partial failure `Sync` unconditionally replaces the maps with only what succeeded, discarding prior good entries; stamps `lastSync=now` even on failure; no backoff, no staleness alert → coverage silently shrinks for up to 6h. | GAP → **CLOSED** (per-source `replacedSources` replacement, `threatfeed.go` `applySync`) | H | `internal/threatfeed/threatfeed.go:150-183` |
| WK-6 | UT1 category feed failures counted but **never alerted**; fixed 24h retry, no backoff. Stale-serve is safe (last-good BadgerDB). | GAP (obs) | M | `internal/feedsync/feedsync.go:192-213,176` |
| WK-7 | Category DB (Badger) corruption: read errors → "not found" (fail-open for category-block, no crash); value-log truncate/replay on restart. **The RUNTIME half is correct and unchanged; the claim about restart was not** — see ST-12/§17: a value log is indeed tolerated, but a torn MANIFEST used to be fatal at boot and a corrupt table panics uncatchably. | ✓ runtime / GAP boot → **boot half CLOSED** (CHAOS-50) | — | `internal/catdb/catdb.go` `Lookup`/`getExact`; boot path `internal/catdb/resilient.go` |
| WK-8 | **Background workers have NO panic recovery.** `threatfeed.Start`, `feedsync.Start`, blocklistfeed scheduler, `startCDRHealthPoller`, `startAlertRetryLoop` all run their loop body with no `recover()`. One panic (bad feed line, nil-map deref, a `.(time.Time)` assertion) **terminates the whole in-line proxy.** | GAP → **CLOSED (CHAOS-24)** | **C** | was: `threatfeed.go:131-145`, `feedsync.go:171-187`, `cdr_health.go:65-80`, `alerts.go:46`→`store.go:511`. Now guarded per ROUND — see §12 |
| WK-9 | Syslog on the hot path: `writeMsg` holds `s.mu` and does a **blocking 5s dial** while locked; TCP writes have **no write deadline** → a slow SIEM can stall proxy goroutines. UDP is non-blocking (acceptable). | GAP → **CLOSED** (async drain goroutine owns the socket, `internal/syslog`) | M | `internal/syslog/syslog.go:117-146,68` |
| WK-10 | Webhook alert delivery: never blocks the producer, 30s dedup, bounded semaphore (10) → enqueue not spawn, bounded retry (3× exp backoff), 500-cap queue drop-on-full, SSRF-guarded, atomic persist. | ✓ **for delivery**; the two bounds MISSING in front of delivery are CHAOS-27 → **CLOSED** (§15) | — | `internal/alerts/store.go` |
| WK-11 | Alert **socket** cost: the delivery client was built per attempt, abandoning an `http.Transport` whose zero-value `IdleConnTimeout` never expires — one FD + two goroutines leaked per delivered alert. The semaphore bounds concurrent deliveries, not cumulative sockets. Terminal state: `accept: too many open files` in the PROXY plane. | GAP → **CLOSED** (CHAOS-27, shared pooled `deliveryClient`) | **H** | was: `internal/alerts/store.go` `deliverAttempt`; see §15 |
| WK-12 | Alert **dedup bookkeeping**: unbounded map on an attacker-controlled key space (key embeds the requested host, same input `topHosts` is capped for), rescanned `O(n)` under a process-wide mutex on every dispatch (230,603 ns/op at the flood steady state, growing). Dedup runs *before* the semaphore and the retry queue, so neither bounds it. | GAP → **CLOSED** (CHAOS-27, 4096 cap + amortised prune + eviction counter) | **H** | was: `internal/alerts/store.go` `dedupSuppressed`; see §15 |
| WK-11 | SSE slow client: non-blocking `select … default → close+evict`, 256-client cap, runs off the request path. | ✓ | — | `internal/sse/sse.go:66-78,46` |
| WK-12 | YARA compile failure loads remaining rules (never disables engine); regex timeout + saturation cap with admin-selectable fail-closed/open posture + alerts. Residual: abandoned regex goroutines are counted but never cancelled (memory held until they finish). | ✓ (+leak caveat) | L/M | `internal/yara/yara.go:98-130,584-602,540` |
| WK-13 | Ticker loops have **no jitter** + immediate sync-on-boot → fleet-wide thundering herd against public feeds (URLhaus/OpenPhish/NethServer mirror) on rollout and every interval. | GAP | M | `threatfeed.go:132-135`, `feedsync.go:173-176`, blocklistfeed 60s / cdr_health 15s |
| WK-15 | **ClamAV's queue wait had its own 5 s deadline, which preempted the orchestrator's 10 s one and INVERTED its posture.** Exceeding the inner limit returned an ordinary error → classified as an engine fault → fail-OPEN, while the outer limit fails CLOSED. Five concurrent scans on a HEALTHY daemon therefore admitted content unscanned, reported as a daemon error. Attacker-inducible, no privilege. | GAP → **CLOSED** (CHAOS-52: `ScanContext` charges the queue wait to the caller's budget; `ErrQueueFull` keeps saturation distinguishable from a fault; `culvert_clam_saturated_total`) | **H** | was: `internal/clamav/clamav.go` `Scan` 5 s `time.After`; now `ScanContext` + `internal/secscan` `recordClamFailure` — see §20 |
| WK-16 | **`ScanBody` stopped WAITING without stopping the WORK.** The abandoned scan goroutine held a ClamAV slot (1 of 4) and a copy of the body until the client's own 30 s timeout — 3x the budget that had already given up on it — unbounded in count and invisible in every surface. Four abandoned scans occupy every slot, pushing live requests onto WK-15's fail-open path: the failure sustains itself under load. Measured 30.006 s against a 150 ms deadline. | GAP → **CLOSED** (CHAOS-52: the budget is a context; cancellation reaches the dial, the conn deadline and a close-watcher; `culvert_scan_inflight`) | **H** | was: `internal/secscan/secscan.go` `ScanBody` `time.After`; now `context.WithTimeout` + `clamav.effectiveDeadline`/`watchCancel` — see §20 |
| WK-17 | **The fail-closed scan-timeout refusal was cached with the CONTENT TTL** (1 h default), so seconds of scanner slowness blocked that exact object node-wide, for every user, for an hour after recovery — manual cache flush the only recourse. The ClamAV-error branch two lines above already refuses to cache for exactly this reason. | GAP → **CLOSED** (CHAOS-52: `hashcache.SetTTL` + `scanTimeoutCooldown` 30 s) | M | was: `internal/secscan/secscan.go` `ScanBody` timeout arm; now `SetTTL` — see §20 |
| WK-18 | **An abandoned scan could overturn the fail-closed verdict.** On finishing, the abandoned goroutine wrote `Clean:true` over the refusal the user had just been served — a cached admission for the rest of the TTL, no counter, no log; whether an object was blocked or served was decided by a race. | GAP → **CLOSED** (CHAOS-52: `publishVerdict` tighten-only — a late BLOCK still publishes, a late CLEAN is discarded and counted; budget enforced from both sides so the `select` coin flip cannot launder an overrun) | **H** | was: `internal/secscan/secscan.go` `scanBodyInner` `cache.Set`; now `publishVerdict`/`noteLateCleanDiscarded` — see §20 |
| WK-14 | Release-catalog autoseed: stage → read-only verify+freshness+rollback → atomic swap with move-aside `.bak` restore-on-failure; fail-closed, no unsigned auto-download. | ✓ | — | `release_autoseed.go:49-122,100-116` |

---

## 3. Risk Matrix (likelihood × impact)

| Risk ID | Finding | Likelihood | Impact | Priority |
|---------|---------|------------|--------|----------|
| R1 | WK-8 background-worker panic kills proxy | Medium | Critical (total outage of an in-line appliance) | **P0** |
| R2 | WK-1 ClamAV down → malware passes unscanned, silent | Medium (AV daemon flaps) | High (security control dark) | **P0** |
| R3 | WK-5 threat-feed stale-erase, silent | High (transient feed outage is routine) | High (coverage shrinks) | **P0** |
| R4 | ST-5 / ST-6 admin_settings / ui_users non-atomic → config/credential loss, admin lockout | Medium (rapid UI edits / power loss) | High | **P1** |
| R5 | CA-1 / CA-2 / CA-3 CA silent fail-open / expired-still-signs | Low-Medium | High (inspection dark / outage) | **P1** |
| R6 | AU-2 stale SSO after IdP delete | Low (deliberate deletes) | High (security: revoked IdP still admits) | **P1** |
| R7 | PX-3 half-open relay leak | Medium (mobile/flaky clients) | Medium-High (FD/goroutine exhaustion) | **P1** |
| R8 | HA-7/HA-16 unfenced or mutually-standby CP never recovers | ~~Low~~ **Medium** (boot ordering, not an exotic fault) | High (indefinite write outage / leaderless cluster, manual fix) | ~~**P1**~~ **CLOSED** (CHAOS-55) |
| R9 | PX-6 no global conn cap / limiter off by default | Medium (flood) | High (FD exhaustion) | **P1** |
| R10 | AU-1 / AU-13 no OIDC introspection cache | High (every request) | Medium (latency + IdP amplification) | **P2** |
| R11 | WK-9 syslog blocking on hot path | Medium (slow SIEM) | Medium (latency) | **P2** |
| R12 | WK-13 / HA-11 no ticker jitter | Medium (rollout) | Medium (self-DDoS / herd) | **P2** |
| R13 | ST-8 silent audit-trail loss | Low | Medium-High (compliance) | **CLOSED (silent-loss half)** — see §13 |
| R14 | HA-9 enrollment nil-deref panic | Low (corrupted state) | Low (RPC-scoped) | **FIXED** |

---

## 4. Recovery Assessment

**Automatic recovery — present and correct:** upstream circuit breaker + health loop (PX-14),
lease keepalive/self-fence and epoch ratchet (HA-3/HA-8), rolling-update crash recovery to terminal
states (HA-12), webhook retry queue (WK-10), catalog autoseed atomic swap + restore (WK-14),
Badger value-log replay (WK-7), SIGHUP last-good fallback (ST-4).

**Automatic recovery — missing (manual intervention required):**
- **HA-7** — an unfenced resumed leader has no background re-acquire; a transient etcd blip during
  a restart becomes an indefinite write outage requiring an operator restart. *Highest-value
  recovery gap.*
- **CA-2 / CA-13** — a failed CA persist/rotation is never retried before the fixed 24h tick, and
  the failure is invisible.
- **WK-5** — a feed that fails during its sync window is not fast-retried; coverage stays degraded
  until the next 6h tick.
- **ST-5 / ST-6 / ST-9** — corrupted state files are not quarantined; recovery is a silent revert
  to defaults (ST-5/6) or a crash-loop (ST-9), both requiring human diagnosis.

**Manual recovery paths that exist:** admin lockout after ui_users loss is recoverable via the
legacy `-user/-pass` flags/env; a wedged rolling update halts to an operator-inspectable state;
config rollback offers versioned snapshots (skipping corrupt ones).

---

## 5. Operational Impact

The dominant operational hazard is **invisible degradation**. An operator cannot act on a control
they cannot see fail. Concretely, add alerts + metrics for:

- `culvert_ssl_inspection_ready` gauge (0 when CA-3 fires) and a `cert_expiry` **early-warning**
  independent of rotation (CA-5).
- `culvert_ca_persist_failures_total` + alert (CA-2, CA-13).
- ClamAV scan-error counter + `scan_svc_down`-style alert (WK-1), matching the remote-scanner path.
- Per-feed `last_success` + staleness alert at >2× interval (WK-5, WK-6).
- GeoIP DB load-failure / age **alert** (WK-4). The age/failure *surfacing* (API + panel) shipped; the proactive alert half is still open.
- `idp.unreachable` distinct from auth-failure (AU-7).
- ~~Audit write-failure counter surfaced on `/healthz` (ST-8), matching reqlog.~~ **Shipped — see §13.**

Add **jitter** to every feed/poll ticker (WK-13, HA-11) to stop fleet self-DDoS on rollout.

---

## 6. Security Impact

Fail-open security controls are the headline:
- **WK-1** (ClamAV) and **CA-3** (SSL inspection) both silently *stop enforcing* under
  infrastructure failure — malware and un-inspected TLS flow with a green dashboard.
- **PX-2** (all-upstreams-down → direct) bypasses a mandatory egress/DLP chokepoint.
- **WK-5** shrinks threat-intel coverage silently.
- **AU-2** lets a deleted/compromised IdP's sessions keep full admin access up to the TTL.
- **AU-3** is a practical CPU-starvation DoS via un-rate-limited bcrypt on the proxy path.
- **CA-14** can resurrect a revoked session token after a crash.

Where the posture is *deliberately* fail-open for availability (PX-2, HA-1, WK-1/WK-2), it should
be an **admin-selectable** `fail_closed | fail_open_with_alert` toggle, not a hard-coded silent
default — mirroring the mature YARA posture model (WK-12).

Genuinely strong security-under-failure: the fencing lease (HA-2/3/4), KEK-at-rest (CA-7), SSRF
guards on all IdP/webhook egress (AU-12, WK-10), and geo fail-closed (WK-3).

---

## 7. Data-Integrity Impact

`fileutil.AtomicWrite` (ST-1) is the correct primitive and is used by the highest-churn stores.
The integrity gaps are the **files not yet migrated onto it**: `admin_settings.json` (ST-5),
`ui_users.json` (ST-6), the session revocation list (CA-14), and the residual `os.WriteFile`
writers (ST-10). The fix is largely mechanical: route every JSON state writer through
`fileutil.AtomicWrite` and hold the writer lock across the serialize+write. Backup consistency
(ST-10) additionally wants a quiesce or config-version snapshot as the atomic unit.

---

## 8. Suggested Improvements (ranked)

1. **P0 — `safeGo(name, fn)` supervisor for every background worker** (WK-8, PX-4): a shared
   wrapper that `recover()`s the loop body, logs + increments a `worker_panics_total{worker}`
   metric, and restarts with backoff. Route all `Start`/poller/relay goroutines through it. This
   single change removes the only *Critical* risk.
2. **P0 — ClamAV error posture** (WK-1): admin-selectable `clamav_on_error: fail_closed |
   fail_open_with_alert`, a `scan_clam_error` counter, and an alert — mirror the remote-scanner and
   YARA models.
3. **P0 — Threat-feed last-good retention** (WK-5): replace a feed's entries only on that feed's
   success; track per-feed `lastSuccess`; alert on staleness; fast-retry with backoff.
4. **P1 — Migrate `admin_settings.json` / `ui_users.json` / revocation list to
   `fileutil.AtomicWrite`** (ST-5, ST-6, CA-14) and hold the writer lock across the write; quarantine
   (`.corrupt`) instead of silent-revert on load failure.
5. **P1 — CA fail-closed observability** (CA-1, CA-2, CA-3, CA-5, CA-13): guard `signLeaf` against
   an expired CA; treat `SaveCA`/rotation failure as a first-class alert + metric; fire an early
   `cert_expiry` warning; expose an `ssl_inspection_ready` gauge; optional `--ca-required`
   fail-closed mode.
6. **P1 — `RevokeProvider(id)`** (AU-2) called from the IdP delete/disable path.
7. **P1 — Idle deadline on all raw relays** (PX-3): re-arming read deadline (reuse the
   `stallDetectReadCloser` pattern) so half-open peers can't leak.
8. **P1 — Background lease re-acquire** (HA-7) whenever `role==leader && lease!=nil &&
   leaseEpoch==0`.
9. **P1 — Global connection cap + enable the per-IP limiter by default + wire it into SOCKS5**
   (PX-5, PX-6).
10. **P2 — Registry OIDC introspection positive+negative cache + circuit breaker** (AU-1, AU-13);
    per-op LDAP deadline (AU-5); jitter on all feed/poll tickers (WK-13, HA-11); async/deadlined
    syslog (WK-9); confirm-before-handoff in `updateCPWithHA` (HA-13); verify running version on
    `updating_cp` recovery (HA-12A); encrypt secret fields of the DP last-good snapshot (HA-14).

---

## 9. Suggested PR (this PR)

This PR ships the review document plus **one contained, verified fail-closed fix**:

- **HA-9 — enrollment `AllowCIDR` nil-deref panic.** `ValidateAndConsumeToken` discarded the
  `net.ParseCIDR` error; a corrupted persisted `AllowCIDR` yielded a nil `*net.IPNet` and
  `cidr.Contains(ip)` panicked inside the enrollment RPC path. Now checks the error and fails
  closed (`enrollment.go`). Regression test `TestTokenValidate_CorruptedCIDR_FailsClosed`
  (`enrollment_test.go`) injects a malformed CIDR into the token map (bypassing the creation-time
  validation that `GenerateToken` already enforces) and asserts an error rather than a panic.

The larger remediations (§8) are intentionally *not* bundled here — each is its own reviewable
change with its own test surface, and several (safeGo, atomic-write migration, CA observability)
touch security-critical paths that warrant isolated review.

---

## 10. Required Tests (for the follow-up remediations)

| Finding | Test |
|---------|------|
| WK-8 / PX-4 | Inject a panicking collaborator into each worker's loop; assert the worker recovers, the ticker keeps running, and the process survives. |
| WK-1 | Fake `ClamScanner.Scan` returns an error; assert `ScanBody` blocks when posture=fail_closed and fires an alert. |
| WK-5 | Stub one feed source to fail; assert prior entries retained and `lastSuccess` not advanced. |
| ST-5 / ST-6 | Fire N concurrent saves; assert the file always parses to one committed state and no `.tmp` leftover; truncate mid-record → assert quarantine, not silent-empty. |
| CA-1 | Seed an expired CA via `SetCAForTest`; assert `GetCert` errors + alert. |
| CA-2 | Point `caPath` at a read-only dir; drive `RotateIfNeeded`; assert a failure alert (not a success alert). |
| AU-2 | Mint a session with `Provider:"idpA"`; delete idpA; assert the cookie now fails to decode. |
| AU-3 | Assert the Nth rapid wrong-password attempt for a valid user is rejected before bcrypt runs. |
| PX-3 | Open a tunnel, half-close the client without FIN; assert goroutine count returns to baseline within the idle window. |
| PX-6 | Global cap K; open K+1 conns across distinct IPs; assert rejection + stable FD count. |
| HA-7 | Resume denied → etcd becomes reachable → assert `WriteAllowed()` becomes true within a bounded time with no operator action. |
| HA-13 | Standby refuses to promote → assert the leader does NOT take itself down and the update aborts. |
| **HA-9** | **`TestTokenValidate_CorruptedCIDR_FailsClosed` — shipped in this PR (green).** |

---

## 11. Residual Risk

Even with §8 fully implemented, these remain by design and should be explicitly owned in the
operator runbook:

- **HA-1 / HA-15** — a long-partitioned DP enforces last-good policy (bounded only by an operator
  staleness ceiling if added); a lease-mode witness outage stalls replication *and* writes until
  etcd returns. This is deliberate safety-over-availability.
- **HA-5** — legacy 2-node `--ha-auto-failover` without a witness can dual-write on a partition
  (RISK-001). The remediation is organizational: steer operators to the fencing lease.
- **CA-10 / AU-9** — NTP is a hard dependency; large clock skew breaks fresh leaves and session
  windows, and a deliberate HMAC rotation is an instant mass-logout with no grace window.
- **AU-4** — per-node, non-persisted lockout means a cluster attacker gets `MaxAttempts` per node;
  gossiping the counters (using the revocation-list gossip as a template) is the fix but is not
  free.
- **PX-2 / WK-1 / WK-2** — where fail-open is chosen for availability, residual malware/egress
  exposure exists during the outage window; the mitigation is the alert + the admin fail-closed
  toggle, not elimination.

The bright spots — the fencing lease, KEK-at-rest, atomic-write foundation, bounded async
history/alert/SSE paths, and geo/OCSP fail-closed posture — show the codebase already knows how to
fail safely. The work ahead is applying that same discipline (alert + metric + fail-closed toggle +
atomic write + panic recovery) uniformly across the paths that still degrade in silence.

---

## 12. CHAOS-24 — Background-worker panic containment (fail-closed)

**Date:** 2026-08-04 · **Closes:** WK-8 / risk **R1**, the register's only Critical item.

### 12.1 Failure scenario

Go terminates the process on an unrecovered panic in **any** goroutine. Culvert is an in-line
security appliance, so a panic in a long-lived background worker is a **total gateway outage** —
every in-flight tunnel dropped — and several of those workers parse **third-party data the
operator does not control** (URLhaus/OpenPhish bodies, the UT1 tarball, operator-configured
blocklist feeds). A malformed feed row was a remote availability trigger.

The M1 crash plane (`crashguard.go`) already covered the proxy plane, the admin plane, and four
detached go-sites (`alert`, `geo`, `socks5`, relay). It did **not** reach the long-lived worker
loops, and `internal/*` leaf packages cannot import `package main` (ADR-0003), so the workers that
live in `internal/` had no way to reach the sink at all.

**Verified unguarded before this change** (zero `recover()` on the loop body):

| Worker | Consequence of the panic |
|--------|--------------------------|
| `internal/threatfeed` sync loop | process death, triggered by feed content |
| `internal/feedsync` UT1 sync loop | process death, triggered by remote tarball content |
| `internal/blocklistfeed` scheduler | process death, triggered by feed content |
| `internal/saasfeed` sync loop | process death |
| `internal/alerts` retry loop | process death; alert re-delivery stops |
| `internal/reqlog` drain goroutine | process death — **and see §12.3** |
| `internal/syslog` drain goroutine | process death over a SIEM write |
| `internal/upstream` health loop | process death; tripped breakers never close |
| `ca.go` CA auto-rotation | process death; CA silently never rotates again |
| `cdr_health.go` poller | process death; health snapshot freezes green |
| `dp_enrollment.go` cert renewal | process death; node's mTLS identity expires |
| `connlimit_startup.go` cleanup | process death; limiter maps grow unbounded |
| `logstore.go` retention janitor | process death; volume fills |
| `metrics.go` counter checkpoint | process death |
| `ha_lease.go` fencing keepalive | process death — **and see §12.2** |

### 12.2 The finding inside the finding: the obvious fix creates a split brain

The reflexive fix — `defer recover()` at the top of each worker goroutine — is **worse than the
bug** on two of these paths, because it converts a loud crash into a *silent permanent stall*
while the process keeps reporting healthy.

On the **fencing-lease keepalive** it is actively dangerous. If that goroutine returns, the node
keeps `role=leader` and `leaseEpoch != 0`, so `WriteAllowed()` stays **true** — but nothing renews
the etcd lease. The lease expires, a standby legitimately acquires it, and two nodes now believe
they hold write authority. Panic containment would have **manufactured the exact split brain
ADR-0005 exists to make impossible.** Swallow-and-retry is unsafe for the same reason: if the
panic is deterministic, every round dies *before* the validity-window check in `leaseRenewOnce`,
so the node holds authority forever on the strength of an ever-staler confirmation.

Adopted semantics: **guard the round, never the goroutine** — and where "keep going" is not the
safe answer, the caller branches on the panic and fails closed. `leaseRenewRound` treats a
panicking round as exactly what it is — a round that did **not** confirm the lease, the same
epistemic state as a transport failure — and charges it against the last etcd-confirmed validity
window (`fenceIfLeaseWindowElapsed`, including `haLeaseWriteMargin`). Containment therefore cannot
extend a node's write authority by even one tick.

### 12.3 Why the request-log drain is the other special case

`reqlog.Add` **blocks** the caller when the queue is full — the JSONL file is the durable audit
record, so a saturated queue parks the producer rather than discarding it. That makes the drain
goroutine load-bearing for the **proxy request path**, not just for logging. If it ever stops
consuming, every request goroutine eventually parks in `Add` and the gateway wedges: no crash, no
restart, no alert, just a proxy that stops answering. A goroutine-level guard there would trade a
recoverable crash for an unrecoverable hang. The guard is per round, and `drainRound`'s named
return keeps its zero value on panic so the loop always continues.

**Keeping the goroutine alive is necessary but not sufficient** (P1 from external review of the
first cut). `bufio.Writer.Flush` clears its buffer only *after* the underlying `Write` returns
(`b.n = 0` is its last statement), so a `Write` that **panics** unwinds with the batch still
buffered. Reusing that writer replays the poisoned bytes on every later flush — with a
deterministic, content-triggered fault the drain goroutine stays alive and healthy-looking while
**nothing ever reaches the durable audit file again.** That is the same silent-permanent-loss class
the guard exists to remove, just relocated. The recovery path therefore **discards** the batch
(`batch.discard`) and charges its records to `WriteErrors`, so the loss is bounded to one batch and
visible instead of unbounded and silent. Pinned by `TestDrain_PoisonedBufferIsDiscarded`, which
fails against the un-discarded version with *0 of 25* post-poison entries reaching the sink.

### 12.4 What shipped

- `internal/obs/guard.go` — `Guard` / `SafeCall` / `SetPanicSink`, mirroring the existing `SetSink`
  seam. `package main` publishes `recordCrash` as the sink (`crashguard.go` `init`), so a leaf
  worker panic lands in the **same** pipeline as a proxy/admin panic:
  `culvert_crash_records_total{component}`, the system-actor audit entry, the bounded redacted
  `lastCrash` record. **No new observability surface was introduced.**
- `crashguard.go` — `runGuarded(component, fn) (panicked bool)` for the `package main` loops. The
  bool exists for the fail-closed callers.
- Per-round guards applied to all 15 workers in the §12.1 table.
- `ha_lease.go` — `leaseRenewRound` + `fenceIfLeaseWindowElapsed` (fail-closed, §12.2).
- `internal/syslog` — guarded locally with a `panics` counter rather than importing `obs`: that
  package's header declares it a stdlib-only leaf, and a panicked line is counted as the drop it
  actually is.
- `dp_enrollment.go` — a panicking renewal round raises the **same operator alert** as a renewal
  error, because operationally it is one: the renewal did not happen. The panic *value* is never
  put in the alert (it can embed attacker-shaped text or a secret); `recordCrash` owns the bounded,
  redacted record.

### 12.5 Tests

| Gate | Test |
|------|------|
| Contained round is recorded, loop survives, panic text scrubbed (CWE-117) | `chaos_worker_panic_test.go` `TestChaos24_RunGuarded_*`, `TestChaos24_ContainedPanicTextIsScrubbedForLogInjection` |
| Leaf-package panic reaches main's crash pipeline (seam wiring) | `TestChaos24_ObsSeamRoutesLeafPanicsIntoTheCrashPipeline` |
| **Split-brain gate** — panicking keepalive self-fences, does not keep write authority | `TestChaos24_LeaseKeepalivePanic_FailsClosed` |
| Fail-closed is not trigger-happy — a panic inside a valid window does not fence | `TestChaos24_LeaseWindowStillValid_PanicDoesNotFence`, `TestChaos24_LeaseFenceRespectsWriteMargin` |
| **Anti-wedge gate** — drain keeps consuming; producers never block | `internal/reqlog/persist_panic_test.go` `TestDrain_*` |
| **Anti-poison gate** — a panicking flush discards its batch instead of replaying it forever | `TestDrain_PoisonedBufferIsDiscarded` |
| Primitive semantics, sink-panic containment, nil-sink cannot silence | `internal/obs/guard_test.go` |

Both regression gates were verified to **fail without the fix**: removing the drain guard
reproduces process death (`panic: simulated sink fault during flush`), and substituting the naive
swallow-and-retry keepalive guard trips the split-brain assertion.

### 12.6 Residual risk

- **Containment is not repair.** A worker whose round panics *every* tick is contained and counted
  but makes no progress — the feed goes stale, the CA does not rotate. The signal is
  `culvert_crash_records_total{component}` being non-zero, which is 0 in a healthy process; an
  alert rule on it is the operator-facing follow-up (not shipped here).
- **Deliberately still unguarded:** the HA standby/leader sync loops (`ha.go`), the MCP runtime
  listener, and `internal/yara`'s per-match goroutine. Each needs its own fail-closed analysis of
  the kind §12.2 required — they are *not* mechanical, and bundling them would have hidden the
  lease change in a large diff. Tracked as CHAOS-25. → **The HA sync loop and the YARA match
  goroutine are now CLOSED (CHAOS-25, §14)** — the HA one did indeed hold a split-brain hazard in
  the obvious fix, in the mirror image of §12.2. The MCP runtime listener remains open as
  **CHAOS-26** (§14.7).
- The `crashThrottleEvery` (1s per component) flood guard means a tight panic loop reports a
  fraction of its rounds to the SIEM. The unthrottled `culvert_crash_records_total` counter is the
  lossless signal, by design (anti-forensics-DoS trade-off inherited from M1).

---

## 13. ST-8 — Silent audit-trail loss on a failing volume

**Date:** 2026-08-05 · **Closes:** ST-8 / risk **R13** (silent-loss half). Found by the standing
security-regression review of the CHAOS-24 window.

### 13.1 Failure scenario

`audit.Add` persisted each admin-action entry to the JSONL file with
`f.Write(b) //nolint:errcheck` and discarded the result. That file is the **durable** compliance
record; the in-memory ring the admin UI renders from holds only the newest `MaxRing` (500) entries
and is wiped on every restart.

So on a full volume, a read-only remount, an EIO, or a failed post-rotation reopen
(`fileutil.RotatingFile.Write` returns the open error), every admin action was recorded **nowhere
durable**, with:

- no counter, no Prometheus series, no `/healthz` annotation,
- no alert (the audit log is an append-only `RotatingFile`, so it never passes through
  `fileutil.AtomicWrite` and the CHAOS-45 durable-write chokepoint observer never saw it),
- no log line,
- and an admin UI that kept rendering entries from the volatile ring, so the operator's own
  evidence said logging was fine.

A `json.Marshal` failure took the same silent path.

**Why this is a security finding, not only an observability one.** The audit trail is the control
that answers "who changed what". An attacker who can fill the data volume — directly, or by
driving request-log/history growth — can switch off durable audit logging, act, and then evict the
volatile 500-entry ring by generating further events or forcing a restart. Nothing in the product
would report the gap. CWE-778 (Insufficient Logging); OWASP **A09:2021 — Security Logging and
Monitoring Failures**.

**Why it surfaced now.** The CHAOS-24 sweep made the request-log drain (`internal/reqlog`,
`WriteErrors`/`Backpressure`) and the syslog drain (`internal/syslog`, `Drops`/`Panics`) count and
surface every lost record. That left the audit log — the most compliance-critical of the three
durable log planes — as the only one still discarding its error, an inconsistency an operator
would reasonably read the other way round.

### 13.2 Fix

Persistence stays **best-effort by design** — a failing disk must not make an admin configuration
change fail, which would turn a storage incident into an administrative lockout — but the loss is
no longer silent:

- `internal/audit` counts every entry that did not reach the file (write error, **short write with
  a nil error** — the truncated-JSON-line case — and the defensive marshal branch), logs only the
  first (a failing disk fails every write; the counter carries the magnitude), and exposes
  `WriteErrors()`. Contract mirrors `internal/reqlog` exactly.
- A `SetWriteFailureObserver` seam lets `package main` route the failure into the existing
  CHAOS-45 storage-health plane (`storage_health.go` init → `noteStorageWriteFailure`): degraded
  operator-contract row, rate-limited log, and the `storage_write_failed` alert, with the same
  path-redaction barrier. The observer is documented as **MUST NOT call `Add`** (unbounded
  recursion on a persistently failing disk); the production observer is audit-free by
  construction, and a panicking observer is contained so audit loss can never take down the admin
  plane it records.
- **The file's line boundary is repaired.** A PARTIAL write (bytes accepted, record incomplete) leaves a fragment with no terminating newline; appending the next record onto it yields one unparseable line that every reader skips, so TWO entries are lost while only the first was counted. `persistEntry` therefore opens a fresh line before the next record, leaving the fragment as its own already-charged invalid line. The pending repair is re-derived from the bytes that actually reached the file, so a zero-byte write hands it back instead of leaking it.
- **The SUCCESS half is wired too** (`SetWriteSuccessObserver` → `noteStorageWriteSuccess`). `storageDegraded()` clears only on an OBSERVED successful write ("silence is not recovery"), so a failure producer without a matching success producer would pin a node degraded forever after one transient blip — reproducible on a node whose only durable writes are audit entries.
- Surfaced on `GET /api/stats` (`auditLogWriteErrors`), `/metrics`
  (`culvert_audit_write_errors_total`), `/healthz` (`auditLogWriteErrors`, present only when
  non-zero so healthy probe bodies are unchanged, and never failing the probe), and the dashboard
  — where audit loss **outranks** request-log loss in the logging posture tile, because those
  entries are already gone for good.

### 13.3 Regression gates

| Property | Test |
|---|---|
| Every lost entry counted; ring still populated | `TestWriteErrors_CountedOnFailingSink` |
| Healthy sink never charges a loss | `TestWriteErrors_ZeroOnHealthySink` |
| Truncated line (short write, nil error) charged | `TestWriteErrors_ShortWriteIsCharged` |
| Unconfigured persistence is not a failure | `TestWriteErrors_NoSinkIsNotAFailure` |
| Observer gets the real path + cause | `TestWriteFailureObserver_ReceivesPathAndError` |
| Nil / panicking observer cannot silence or crash | `TestWriteFailureObserver_NilIsSafe`, `_PanicDoesNotPropagate` |
| Exactly-once accounting under concurrency (`-race`) | `TestWriteErrors_Concurrent` |
| Observer not called under the audit lock (deadlock guard) | `TestWriteErrors_ObserverIsNotCalledUnderTheRingLock` |
| Wiring reaches storage health + alert, path redacted | `TestAuditWriteFailure_ReachesStorageHealthPlane` |
| Healthy persist does not degrade the contract | `TestAuditWriteFailure_HealthyPersistDoesNotDegrade` |
| `/api/stats`, `/metrics`, `/healthz` surfaces | `TestAPIStats_SurfacesAuditWriteErrors`, `TestMetrics_ExposesAuditWriteErrors`, `TestHealthz_AnnotatesAuditWriteErrors` |
| Partial write does not corrupt the NEXT entry (counter stays truthful) | `TestPartialWrite_DoesNotCorruptTheNextEntry` |
| Pending boundary repair survives a zero-byte write | `TestPartialWrite_RepairSurvivesATotallyFailedWrite` |
| Repair is inert on a healthy node (no stray blank line) | `TestHealthyWrites_NeedNoRepair` |
| Success observer fires only on a COMPLETE write (recovery signal) | `TestWriteSuccessObserver_FiresOnlyOnACompleteWrite` |
| Nil / panicking success observer costs no record | `TestWriteSuccessObserver_NilAndPanicAreSafe` |

### 13.4 Residual risk

- **Best-effort persistence is unchanged.** An admin mutation still returns 200 while its audit
  entry is being lost. Making the admin API fail closed on audit-write failure is the stronger
  posture and is *deliberately not* taken here: it converts a storage incident into a total
  administrative outage, and it diverges from the sibling log planes. It should be a separate,
  explicitly opted-in control (`audit.fail_closed`), not a silent behavior change.
- **Rotation still destroys the older archive** (`os.Remove(path+".1")` at the 50 MB cap). Bounded
  by design; a high-churn CP can age entries out of the durable file faster than an operator ships
  them off-box. The SIEM forwarder is the intended durable sink for that case.
- **`GetPersistent` still re-reads the whole file per query** — the unchanged half of ST-8, an
  admin-plane DoS amplifier on a large audit file. Tracked separately.
- The counter is process-lifetime and resets on restart, matching `reqlog`. The alert and the
  degraded contract row are the durable signals.

---

## 14. CHAOS-25 — HA sync-loop and scanner-goroutine panic containment (fail-closed)

**Date:** 2026-08-06 · **Closes:** two of the three paths CHAOS-24 deferred in §12.6 (the HA
standby/leader sync loops, and `internal/yara`'s per-match goroutine). The MCP runtime listener
stays open — re-scoped in §14.6.

### 14.1 Failure scenario

CHAOS-24 guarded 15 background workers per round and stopped, deliberately, at three paths whose
containment semantics were not mechanical. Two of them are on the **critical path of an in-line
appliance** and both process input the operator does not control:

| Path | Input it parses | Consequence of a panic (before this change) |
|---|---|---|
| `standbyLoop` → `tick` → `syncFromLeader` → `applyHABundle` | the **leader-supplied HA state bundle** (cluster state, replicated CA PEM + wrapped key, full ConfigSnapshot) | process death on the standby CP — the node that exists to survive the leader's death |
| `matchRegexWithTimeout`'s match goroutine (`internal/yara`) | **attacker-supplied response bodies** on the SSL-inspected scan path | process death of the gateway, remotely triggerable per request |

The HA bundle is the larger hazard. It is decoded and applied on every 5s tick, so a panic anywhere
under `applyHABundle` — a nil map, a slice index, a type assertion in the config-apply tree — is
**deterministic and repeats forever**: crash, restart, re-enter standby, sync, crash. The standby is
in a crash-loop precisely while its whole reason for existing (being ready when the leader dies) is
unavailable.

### 14.2 The finding inside the finding: the obvious fix is a split brain (again)

§12.2 found that the reflexive `defer recover()` was *worse than the bug* on the lease keepalive.
The HA sync loop has the same shape, and then a second trap behind it.

**Trap 1 — goroutine-level containment kills failover silently.** If `standbyLoop` returns on a
panic, the node keeps `role="standby"` and a live process, but it has stopped replicating **and**
stopped watching the leader. `failCount` freezes, `onMaxFail` is never reached, and the leader can
die with nothing left to notice. HA is gone; `/api/cluster/ha` still says `standby`, `sync_fail_count: 0`.
That is the CHAOS-24 rule (guard the round, never the goroutine) applying unchanged.

**Trap 2 — the natural per-round guard promotes on this node's own fault.** Guard the round and the
obvious next step is to charge a panicking round as a failed sync, exactly as `ha_lease.go` charges
a panicking renew round. **Here that is inverted, and unsafe.** The lease keepalive charges a
panicking round because *failing to confirm* is the fail-closed reading — the round produced no
evidence that the node still holds authority. In the standby loop the streak drives the opposite
transition: it **acquires** authority. Three panicking rounds (15s) would auto-promote a standby
whose only problem is its own parser, against a leader that is alive, healthy, and still serving.
In legacy (`--ha-auto-failover`, no witness) mode nothing else stops it, so the containment would
manufacture a **remotely-triggerable split brain** — strictly worse than the crash it replaced,
because today's crash-loop is at least loud and single-writer.

The rule this PR adopts, stated once:

> **A contained panic is evidence that THIS node is broken, not that the leader is gone.**

So the guard wraps the whole round, which puts the unwind *before* `tick`'s
`setFail(failCount+1)`: the promotion streak is untouched by construction, and `guardedTick`
additionally refuses to report loop-exit on a panicking round. Ordering that matters is pinned by
test, not left to comment. A panic raised *later* — inside `promote()`, after a genuine sync
failure already advanced the streak — keeps that (correct) increment and just leaves the node a
standby, retryable next tick.

In **lease mode** the fence is the backstop: a live leader holds the lease, so `Acquire` denies the
promotion anyway. The rule is still enforced there (`TestChaos25_LeaseModePanicIsAlsoFenced`) as
defense in depth — the node must not even *attempt* leadership on the strength of its own fault.

### 14.3 What "not counting" costs, and how it is paid for

Suppressing the streak means a permanently panicking standby never escalates on its own. Left
there, containment would have traded a loud failure for a silent one — the exact class §13 was
about. It is paid for three ways, all pre-existing planes:

- **Crash plane** — `culvert_crash_records_total{component="ha-standby-sync"}` (and `"ha-promote"`),
  the system-actor audit entry, the bounded redacted `lastCrash`. No new observability surface.
- **Status** — `sync_panics` on `HAStatus` → `GET /api/cluster/ha` → a warn-coloured
  "Sync faults (contained)" row in the HA panel, next to the failure streak it is deliberately
  absent from.
- **Alert** — `ha_sync_panic`, fired **once per streak** and re-armed by the next healthy sync, so
  a later stall is not swallowed by the first. The cumulative counter never resets.

The lease-mode freshness gate composes correctly with no change: a stalled standby's `lastSyncOK`
ages out, and `leaseAutoPromote` already refuses to auto-promote on stale state while leaving
`PromoteManually` as the operator break-glass. That is the intended recovery path when the leader
really is down and this node cannot parse its bundle.

### 14.4 The scanner goroutine

`matchRegexWithTimeout` is a one-shot detached goroutine, not a loop, so there is no "next round" to
keep alive — the guard covers the whole body. The decision that mattered is what to hand the
caller: a contained panic yields **no verdict about the content**, which is exactly the epistemic
state a *timeout* leaves. So it resolves through the same admin-selectable posture
(`fail_closed` ⇒ block, `fail_open_with_alert` ⇒ allow) rather than defaulting to "clean", and it
answers **immediately** instead of letting the parent wait out the full timeout — the panic already
proved the match will never complete, and stalling every scan for the timeout window would turn a
contained fault into a throughput collapse. The deferred `yaraInflight.Add(-1)` still runs, so
containment cannot leak the saturation budget into a permanent degradation (pinned by test).

`internal/yara` already imports `obs`, so the panic lands in the same crash pipeline via the
CHAOS-24 seam. `MatchPanics()` is the local counter; non-zero means some verdicts were decided by
the posture rather than by the rule, which is a **correctness** signal, not only a liveness one.

### 14.5 What shipped

- `ha.go` — `guardedTick` / `guardedSyncOnce` (per-round, streak-preserving, exit-suppressing),
  `notePanicRound` / `clearSyncPanicAlert`, `syncPanics` + `SyncPanics` on `HAStatus`, and a
  `syncFn` seam so a round can be made to panic without standing up a gRPC leader.
- `ha.go` — `promote()`'s `onPromote` hook (CP gRPC server startup, reached from the sync loop, the
  planned handoff, **and** the admin `PromoteManually` API) is guarded and a panic is treated
  exactly like the error it already handles: reset the once-guard, stay standby, stay retryable.
- `internal/yara/yara.go` — per-match containment resolving through the on-timeout posture, plus
  `MatchPanics()` and the `yaraMatchFn` fault-injection seam.
- `internal/alerts/store.go`, `static/index.html` — the `ha_sync_panic` event and the contained-fault
  status row (GUI parity).

### 14.6 Tests

| Gate | Test |
|------|------|
| **Split-brain gate** — panicking rounds never promote, streak untouched | `TestChaos25_PanickingRoundsDoNotPromote` |
| Fence-mode defense in depth — no promote attempt even with a free lease | `TestChaos25_LeaseModePanicIsAlsoFenced` |
| Not trigger-happy — genuine leader silence still fails over | `TestChaos25_GenuineFailuresStillPromote` |
| Suppression is not a latch — panics then a real outage still fails over | `TestChaos25_PanicDoesNotMaskARealOutage` |
| Round contained, loop survives, attributed in the crash plane | `TestChaos25_PanickingRoundContained` |
| Startup try (cold local state, largest bundle) contained | `TestChaos25_ImmediateSyncPanicIsContained` |
| Fire-once alert re-arms; cumulative counter does not reset | `TestChaos25_SuccessRearmsThePanicAlert` |
| `onPromote` panic ⇒ stays standby, guard reset, retry succeeds | `TestChaos25_PromotePanicStaysStandby` |
| Failed/panicking promote keeps the loop alive (see §14.8) | `TestChaos25_FailedPromoteKeepsTheLoopAlive` |
| Scanner: contained panic fails CLOSED by default | `TestChaos25_MatchPanic_FailsClosedByDefault` |
| Scanner: honours the operator's fail-open posture | `TestChaos25_MatchPanic_HonoursFailOpenPosture` |
| Scanner: answers immediately, does not wait out the timeout | `TestChaos25_MatchPanic_AnswersImmediately` |
| Scanner: containment does not leak the saturation budget | `TestChaos25_MatchPanic_ReleasesTheInflightSlot` |
| Scanner: healthy matching byte-identical, charges no panic | `TestChaos25_HealthyMatchIsUnchanged` |

Both regression gates were verified to **fail without the fix**. Substituting the naive
count-the-panic-as-a-failure guard trips the split-brain assertion at round 2
(`contained panic promoted the standby — split brain against a live leader`), and removing the
scanner guard reproduces process death (`panic: simulated fault inside the regex match`, test
binary terminated).

### 14.7 Residual risk

- **Containment is still not repair.** A standby that panics every tick is contained, counted, and
  alerted, but replicates nothing. Its recovery path is an operator promoting it manually (if the
  leader is genuinely down) or fixing the fault. The alert says so explicitly.
- **Suppressing the streak is a deliberate availability trade.** If a standby's apply path breaks
  *and* the leader dies during the same window, no automatic failover happens. That is the intended
  ordering: an un-fenced promotion by a node that cannot parse the cluster's state is the worse
  outcome, and manual promotion remains one API call away.
- **A failed or panicking `promote()` leaves an unkept lease grant.** Pre-existing and already
  documented on the error branch (it expires after its TTL). Worth noting precisely: `WriteAllowed()`
  keys on the grant, not the role, so such a node reports write authority on `/healthz` and
  `diagnose` for the rest of the window. It is **cosmetic, not an authority leak** —
  `haIssuanceAllowed` gates on `Role == "leader"` first, so a standby holding a stale grant issues
  nothing, and the lease's exclusivity means no other node can promote during that window either.
  Zeroing the local epoch on a failed promote would tighten the reporting; it touches fence
  semantics and is deliberately **not** bundled into a panic-containment change (§12.2's own lesson).
- **Still unguarded: the MCP runtime listener** (`internal/mcp/runtime`). Left open on purpose: it
  is disabled-by-default with a different blast radius (its own listener, not the SWG request path),
  it spans 25 subpackages, and ADR-0024's rollout ladder means "contain and continue" has to be
  reconciled with the Observe/Shadow/Canary semantics before a guard is correct. Tracked as
  **CHAOS-26**.
- The `crashThrottleEvery` (1s per component) flood guard still means a tight panic loop reports a
  fraction of its rounds to the SIEM; the unthrottled counter is the lossless signal (inherited
  from M1).

### 14.8 Review follow-up — the silent stall one level up

External review of the first cut (Codex, PR #1066) found the containment could still be defeated
by the caller. `onMaxFail`'s legacy branch reported loop-exit **unconditionally** after calling
`promote()`:

```go
if s.h.autoFailoverEnabled() {
    s.h.promote("leader unreachable")
    return true          // <- regardless of whether promotion happened
}
```

`promote()` is not infallible, and now has two ways to decline: `onPromote` can return an error
(pre-existing) or panic and be contained (added by §14.5). Both reset the once-guard and leave the
node a **standby** — and `return true` then told `standbyLoop` to exit for good. The node stopped
replicating **and** stopped watching the leader while still reporting `role="standby"`: exactly the
Trap-1 silent stall of §14.2, reached one level above the guard that prevents it. The reset
once-guard was never retried, so recovery required an operator restart.

The lease branch immediately above already returns `leaseAutoPromote()` (→ `IsLeader()`), so the
fix is to make the legacy branch report the same fact: `return s.h.IsLeader()`. The loop then keeps
ticking and the next round retries the promotion, matching lease mode.

Worth recording that this was **pre-existing** — an `onPromote` error alone (a CP gRPC port already
in use, say) permanently ended a legacy standby's sync loop before this PR. The panic guard added a
second way in, and the review surfaced both. `TestChaos25_FailedPromoteKeepsTheLoopAlive` drives an
error, then a contained panic, then a success, and fails against the old code at round 2
(`loop exited before a promotion succeeded`).

---

## 15. CHAOS-27 — The alert plane under an alert storm

**Date:** 2026-08-07 · **Closes:** WK-11, WK-12 · **Detail:**
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-07.md`

### 15.1 The shape of the miss

WK-10 is not wrong. Webhook *delivery* is bounded four different ways — a 10-slot concurrency
semaphore, a 3-attempt retry with exponential backoff, a 500-cap drop-on-full retry queue, and
SSRF-guarded egress. What this pass asked is a different question: **what does the alert
subsystem cost the appliance when the thing it reports on is happening at volume?**

Two costs sat *in front of* every one of those bounds, so none of them applied.

### 15.2 WK-11 — one leaked FD + two goroutines per delivered alert

`deliverAttempt` constructed its client, and with it a fresh `http.Transport`, per attempt. On
success the keep-alive connection went back into *that* Transport's idle pool — a pool nothing
holds a reference to afterwards, that net/http does not finalize, and whose **zero-value
`IdleConnTimeout` means "never expire"** (unlike `http.DefaultTransport`, which sets 90s). The
`persistConn` read/write goroutines keep the Transport and the socket alive, so the connection
survives until the **receiver** closes it. Culvert had no timer that would ever reclaim it.

`webhookSem` does not bound this: it caps deliveries *in flight* (10), and says nothing about
the sockets those slots opened over the preceding hour.

The blast radius crosses planes. File descriptors are a process limit, so the alerting
subsystem exhausts the descriptors the **proxy** needs to `accept(2)`. A subsystem whose only
job is to report trouble becomes the cause of a data-plane outage, and the visible symptom
(proxy refusing connections) points the operator at the wrong subsystem.

Fixed with one shared pooled `deliveryClient` (`MaxIdleConns: 32`, `MaxIdleConnsPerHost: 4`,
`IdleConnTimeout: 90s`), matching the pooled-client idiom already used in
`internal/blocklistfeed` and `internal/otlp`. Per-attempt deadlines are unchanged.

**Reuse does not weaken the SSRF guard.** `ssrf.SafeDialContext` runs on every *dial*, and a
pooled connection is by definition one to an address that already passed `ssrf.Control`
immediately before `connect(2)`; reuse cannot reach an address that was never validated. What
it extends is how long a validated-then-rebound host stays reachable on an open socket —
bounded by `IdleConnTimeout`, and strictly better than the pre-fix state where an abandoned
pool's socket had *no* timeout at all.

### 15.3 WK-12 — unbounded dedup map, rescanned per dispatch

The Q17 dedup key is `event + ":" + detail`, and the request-path producers
(`threat_detected`, `policy_block`) put the **requested host** in `Detail`. So a scan across
50,000 hostnames produces 50,000 distinct keys that the window cannot suppress *by
construction* — the same attacker-controlled input that `topHosts` (store.go) is already
hard-capped at 10k for, with the same memory-DoS reasoning, unguarded here.

Worse, the expiry scan ran on **every** dispatch, `O(len(map))`, under the process-wide
`dedupMu`. Producers reach `Dispatch` via `go fireAlert(...)`, so a slow critical section does
not stall the request path directly — it piles up *goroutines* waiting on the mutex instead.

Measured at the flood steady state (`BenchmarkDedupSuppressedUnderFlood`, 4-core):
**230,603 ns/op → 745 ns/op**, ≈310×, and the pre-fix number *grows with the map* while the
post-fix number is flat. 0.23 ms of mutex-held work per alert is ~23% of a core serialized at
only 100 alerts/s.

Fixed with a 4096-key hard cap plus an amortised prune. The two costs are deliberately kept
apart: the `O(len)` expiry scan runs at most once per 256 inserts (`pruneExpiredLocked`), while
the cap is checked every insert but costs `O(entries over cap)` — one deletion at steady state
(`evictOverCapLocked`). Coupling the cap to the scan would have fixed memory while leaving the
CPU failure mode fully intact.

**Eviction fails toward MORE alerts, never fewer.** Dropping a live key costs at most one
duplicate delivery of an alert already firing, still bounded by the semaphore and the retry
queue. Silencing a real security alert to save memory is not on the table for a security
control.

### 15.4 The 2026-07-26 residual, revisited

That review already saw this trigger — a producer emitting unique `Detail` text per request —
and accepted it because *"bounded by the store's 500-cap queue and 10-slot delivery
semaphore."* That reasoning was correct about **delivery** and silently assumed the
bookkeeping in front of delivery inherited the same bounds. It did not. The note still stands
for delivery fan-out; the cost of the dedup pass is now bounded too, and counted.

### 15.5 Observability

Loss must not be silent: `dedup_evictions_total` + `dedup_tracked` on
`GET /api/alerts/webhooks/history`, `culvert_alert_dedup_evictions_total` (counter) +
`culvert_alert_dedup_tracked` (gauge) on `/metrics`, and an amber "dedup window saturated"
state on the webhook health line in Settings. Non-zero evictions are themselves a useful
signal: they are the signature of a scanning wave reaching the alert plane. OpenAPI
`AlertHistory` extended and the bundle regenerated.

WK-11 gets no counter by design — the leak is gone, and a gauge for a state that can no longer
occur is noise.

### 15.6 Regression gates (all verified to FAIL against the pre-fix code)

| Gate | Property |
|---|---|
| `TestChaos27_DeliveryReusesConnections` | N sequential deliveries open ≤2 sockets (pre-fix: 8 for 8) |
| `TestChaos27_DedupMapIsBounded` | 3× cap unique keys leave the map at ≤ cap (pre-fix: 12288), evictions counted |
| `TestChaos27_DedupPruneIsAmortised` | scans ≤ inserts/256 + 1 — the CPU half, invisible to the memory gate |
| `TestChaos27_DedupStillSuppressesDuplicates` | Q17 semantics intact |
| `TestChaos27_DedupPrunesExpiredEntries` | a key past `dedupTTL` fires again — the cap never silences permanently |

The connection-reuse gate builds its client through the **production constructor**
(`newDeliveryTransport`) with a plain dialer substituted, because `ssrf.SafeDialContext`
correctly refuses the loopback address an `httptest.Server` listens on. The pooling
configuration under test is production's; only the dial target differs.

### 15.7 Residual risk

- `maxDedupEntries` / `dedupPruneEvery` are compile-time constants (the `topHosts` precedent).
  Making them tunable would add a config surface, a durability row and a CP→DP question for a
  value nobody has had cause to change. Deliberate deferral.
- Eviction order is random (Go map iteration), not oldest-first. Under a flood every live entry
  is inside the same 30s window, so ordering buys nothing for its cost.
- Dedup is still keyed on `event:detail`, so a producer with unbounded `Detail` cardinality
  still defeats *suppression* by design. The cap bounds the **cost** of that, not the
  behaviour — now with an eviction counter that makes it visible.
- Other per-call `http.Transport` sites were audited: `auth_oidc_flow.go` (once per provider
  construction), `auth_saml.go` (metadata fetch), `internal/supportupload` (per upload), and
  `internal/blocklistfeed` (per fetch, but with a 90s `IdleConnTimeout`, so it self-heals).
  `internal/upstream`'s health check sets `DisableKeepAlives: true` and pools nothing. None is
  on an attacker-driven rate path, so none is a WK-11-class leak; the blocklistfeed shape is
  the one worth converging on the shared-client idiom opportunistically.
- `webhookSem` is package-global, so all Stores in a process share the 10 slots. Production has
  one Store; noted, not a defect.

### 15.8 Review follow-up — the phantom saturation signal

External review of the first cut (Codex, PR #1078) found a case where the two triggers disagree.
The expiry prune is scheduled by **inserts** (`dedupPruneEvery`), but entries expire with **time**
— and a quiet period has no inserts. So a flood that fills the map to the cap and then stops
leaves 4096 entirely stale keys sitting there. The next alert to arrive:

- finds the map over cap, and
- evicts a random key and **charges it to `dedupEvicted`** — even though every entry is dead and
  nothing is saturated. It could also evict the key it had just inserted, letting an immediate
  duplicate through.

That counter is monotonic and drives an amber "dedup window saturated" state in the admin UI, so
one flood followed by silence produced a **permanently sticky, false degradation indicator** —
defeating the exact observability contract §15.5 added it for. Worse than useless: it teaches the
operator to ignore the signal.

Fixed on both axes:

- **Time-based prune trigger** on the over-cap path (`dedupPruneMinInterval`, 1s), so a map full
  of stale keys is reclaimed before its size is read as saturation. Rate-limited, so a *sustained*
  flood — where the scan would find nothing to reclaim — still does not pay `O(len)` per alert
  (measured: 745 → 783 ns/op, still ~295× better than the 230,603 ns/op pre-fix baseline).
- **Expired keys are deleted but never charged** (`evictOverCapLocked` compares each key's stamp
  against `dedupTTL`). Dropping a dead key is reclamation, not saturation. This makes the counter
  exact even inside the ≤1s window between an entry expiring and the next prune reclaiming it,
  rather than merely approximately right.

`evictOverCapLocked` also now skips the key just inserted, so the alert that triggered the
eviction is never the one dropped.

`TestChaos27_QuietPeriodCountsNoPhantomEvictions` drives the exact sequence — fill to cap, let the
window pass, insert one key — and fails against the first cut (`charged 1 eviction(s) against a
map holding only EXPIRED keys`). It asserts three things: no eviction charged, the fresh key
survives, and the stale entries are actually reclaimed.

Worth recording the general shape, because it is the same lesson as §12.2 and §14.8: **a
correctness fix that is scheduled on one clock and validated on another will disagree with itself
at the boundary.** The memory bound was right, the CPU bound was right, and the counter that made
both observable was wrong in precisely the state — quiet after a storm — that an operator is most
likely to be looking at it.

---

## 16. CHAOS-28 — The Root CA across its lifecycle (fail-closed)

**Date:** 2026-08-09 · **Closes:** CA-1, CA-1b, CA-2, CA-16 · **Partly closes:** CA-4 ·
**Re-scopes:** CA-11 · **Hands off:** CA-13
**Full write-up:** `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-09.md`

### 16.1 Why this domain

Every other security control in Culvert fails in a way the process can observe — a dial
fails, a scanner times out, a write returns `ENOSPC`. The inspection CA is the exception:
it expires, and *nothing inside the appliance changes*. The only entity that notices is
the client, which reports it as a per-site certificate warning that reads like a website
problem rather than a gateway problem. That is the definition of a silent failure, on the
component whose failure is the widest.

### 16.2 The five defects

1. **Expired CA kept signing.** `x509.CreateCertificate` does not check the parent's
   `NotBefore`/`NotAfter` — verified empirically by running the new gate against the
   pre-fix engine, where the sign succeeded. `handleTunnel` did not help either: its gate
   is `certMgr.Ready()`, which is `caCert != nil`, so an expired CA is "ready".
2. **Leaf validity was not clamped to the issuer's** (`NotAfter: now+24h`, unconditional).
3. **A rotation that could not persist reported success** (CA-2) — so the only recovery
   path defect 1 has could silently not survive a restart, minting a different root each boot.
   Three sub-defects, all surfaced in PR review: the SUCCESS observer fired even when the save
   failed (two contradictory alerts for one event, plus a false `culvert_ca_rotations_total`
   increment); the warning was keyed on the CUMULATIVE counter, so it latched until process
   restart even after the operator fixed the volume and re-rotated; and the MANUAL
   force-rotate path (`apiCARotate`) had the identical swallowed save — the worse of the two
   sites, since force-rotate is exactly what an operator runs to recover from defect 1.
4. **The rotation loop's first check was 24h after boot** (CA-4) — skipped precisely when
   an operator restarts to recover from the outage.
5. **`cacheOrder` grew on every TTL refresh** (CA-16, previously unrecorded) — an unbounded
   slice behind a bounded map, growing with uptime on an ordinary steady working set.

### 16.3 The decision that mattered: fail closed, not bypass

The tempting fix is one word — fold validity into `Ready()`. That routes an expired CA into
the existing `inspect_unavailable` **bypass** branch and keeps traffic flowing. It also means
that at the instant the CA expires, **the whole fleet silently stops inspecting**: DLP,
ClamAV, YARA, CDR, file-blocking and DPI all dark, at once, with the gateway reporting itself
healthy. That is trading an availability failure for a security-control failure, and it is the
exact §1 theme this register calls its worst.

The same reasoning rules out honouring a decryption profile's `OnInspectError=fail-open`. That
contract is scoped to **per-origin** incompatibility and gated behind a confirm-count of
distinct client evidence for exactly that reason. An expired CA is **host-independent**:
routing it through the learner would promote every host requested during the outage into a
durable bypass — poisoning the entire cache from one appliance-level fault.

So the unusable-CA path **never bypasses, never learns, never rescues**, and the negative
assertion is executable: `TestHandleTunnel_ExpiredCAFailsClosedNotBypass` fails if the session
is ever recorded as any flavour of bypass instead of
`failed`/`no_fail_open_502`/`client_hello`/`certificate`.

Failing closed costs no availability relative to the pre-fix state — a leaf chained to an
expired issuer already fails path validation in every mainstream client. The traffic was dead
either way. What changed is that the appliance now knows, says so, and names the remediation.

### 16.4 Observability added

| Surface | Signal |
|---|---|
| `/metrics` | `culvert_ca_usable`, `culvert_ca_expires_in_seconds` (omitted when no CA — 0 would read as "expires now"), `culvert_ca_sign_refused_total`, `culvert_ca_inspect_blocked_total`, `culvert_ca_rotation_persist_failures_total` |
| `/healthz` | `ssl_inspection: expired` (was `ready` throughout the outage) |
| `/readyz` | `ca` row → `fail`, **report-only** by default (an expired CA is fleet-wide; gating would eject every node at once and take working plain-HTTP/bypass traffic with it). `?strict=1` opts in. Fixed detail string — the surface is unauthenticated on the proxy port |
| Alerts | `cert_expiry`, rate-limited (5 min) on an independent gate from the log line, `HasSubscriber`-gated per the per-request producer contract |
| Admin API / GUI | `GET /api/ca/status` gains `usable` / `unusableReason` / `inspectBlocked` / `signRefused` / `rotationPersistFailures`; the CA panel gains a red outage banner and an amber not-persisted banner |

Recovery is reported on **evidence** (an observed usable verification via
`caInspectionUsable`), never on elapsed time — the `storage_health.go` contract, for the same
reason: a still-expired CA looks exactly like a healthy one if nothing happens to need a leaf.

### 16.5 What is deliberately left

- **CA-13** — cluster-CA rotation still logs-and-returns on every failure branch. Same defect
  class as CA-2 in the *other* CA; different lifecycle and blast radius (enrollment, not
  inspection). Suggested as the next sweep.
- **CA-11** — no single-flight on the leaf cache. Re-scoped down: the perf-F3 shared leaf key
  already removed the dominant per-miss cost (P-256 keygen), so the herd is much cheaper than
  when first recorded.
- **CA-4's retry half** — a rotation that FAILS still waits a full 24h before retrying.
- **Client trust redistribution stays manual.** Rotation restores the appliance's ability to
  inspect; it cannot make clients trust a new root. Nothing in-band can. That is why this
  change invests most heavily in making the condition visible *before* the cliff
  (`culvert_ca_expires_in_seconds`) rather than only at it.

---

## 17. CHAOS-50 — The cluster (enrollment) CA across its lifecycle

**Date:** 2026-08-19 · **Closes:** CA-13, CA-17 (**new, Critical**), CA-18, CA-19, CA-20
**Full write-up:** `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-19.md`

### 17.1 Why this domain

CHAOS-28 hardened the inspection CA and handed off CA-13 as the same defect class in the other
trust root. Culvert has exactly two: the inspection CA authenticates the gateway *to clients*; the
cluster CA authenticates *every node to the control plane*. When the first fails, one security
control degrades and clients see certificate warnings. When the second fails, **the control plane
stops** — config sync, policy distribution, enrollment and cert renewal all run over mTLS anchored
in that root, and Go's path validation checks the validity window of every cert in a chain, roots
included, so no node in the fleet is exempt.

### 17.2 The finding that outranked the sweep: a Critical deadlock, already known

`clusterCA.ImportCA` held `ca.mu.Lock()` across its post-commit side effects. Two of them read the
cluster CA back **through the package global** — and the receiver *is* the global in production:

- `ca.onRotate()` → `rebuildCPCertPool` → `globalClusterCA.AllCACertsPEM()` → `ca.mu.RLock()`
- `globalConfigStore.Update(CurrentConfigSnapshot())` → `globalClusterCA.CACertFingerprint()` → `ca.mu.RLock()`

`sync.RWMutex` is not reentrant. Proven against `main`:

```
panic: test timed out after 25s
goroutine 21 [sync.RWMutex.RLock]:
github.com/KidCarmi/Culvert.(*clusterCA).CACertFingerprint(0x69d1b99a480)
github.com/KidCarmi/Culvert.(*clusterCA).ImportCA(0x69d1b99a480, …)
```

`CleanupSecondary` had the identical shape. The goroutine hangs **while holding the write lock**, so
`SignCSR` (enrollment *and* unattended renewal), `CACertFingerprint` (⇒ all config publication),
`AllCACertsPEM` (⇒ TLS-pool rebuild), `Ready()` and `Info()` all block for the life of the process.
Three triggers, two unattended: the documented `POST /api/cluster/ca` enterprise import;
`RotateIfNeeded` 30 days before expiry; and overlap cleanup ~30 days after any rotation. The last two
hang the goroutine that drives **both** CAs, so the inspection CA silently stops rotating as well.
A restart recovers (the durable writes complete before the deadlock point) — but nothing says what
happened, because a hang produces no panic and `runGuarded` cannot see it.

**Fix:** commit under the lock (`commitImport`), notify with it released; a separate `importMu`
serialises whole operations so concurrent imports cannot interleave while readers stay unblocked.
The struct comment now states the invariant: `mu` is never held across a call that reads the CA back.

### 17.3 The process lesson — a new theme

This defect was **already known**. `cluster_ca_keyatrest_test.go` points `globalClusterCA` at a
separate empty CA before every import test and explains why: *"A pre-existing self-deadlock exists
if globalClusterCA IS the receiver being imported — out of scope for this key-encryption PR."*
Every test that reaches `ImportCA` follows the pattern. The suite was green, the workaround was
honestly documented at the call site — and the defect appeared in no register, risk row, or ADR.

> **A defect the test suite works around is a defect the register never hears about.** A green suite
> is evidence about the tests, not about the system, whenever the tests are shaped to avoid the
> failure. Out-of-scope is a legitimate call; *unrecorded* is not — the finding needed a row, and a
> row is what would have surfaced it in any of the fourteen sweeps since.

The two new gates use the production aliasing deliberately, and assert the side effects actually ran
rather than having been skipped to dodge the lock.

### 17.4 The lifecycle defects, and the recovery that manufactured false evidence

`SignCSR` had no issuer-validity guard (CA-18), so an expired cluster CA kept minting node
identities. The chain that makes this more than hygiene:

1. The CA expires (rotation failing — CA-13, invisible; or never running — CA-19, invisible).
2. Every DP's client cert now chains to a dead root ⇒ `x509: certificate has expired` on every mTLS
   handshake. Config sync stops fleet-wide.
3. The operator re-enrolls — and it **works**. `Enroll` uses `tls.VerifyClientCertIfGiven`, so an
   unenrolled caller needs no client cert; `SignCSR` signed a fresh cert with the dead CA; the RPC
   returned 200; the node persisted it, reconnected, and failed identically.

So the recovery path did not merely fail — **it manufactured evidence that it had worked**, on every
surface at once (`/healthz: ok` with no cluster-CA field, no `/readyz` row, no diagnostics row, no
counter moving, a green *"Active"* in the admin panel). That is the register's §1 theme in its purest
form, and it is why the sign path now fails closed with a named, counted, alerted refusal.

The clamp (also CA-18) is the quieter half and was materially worse than the leaf case CHAOS-28
fixed: a forged leaf overclaimed by ≤24h, a node cert by up to **a year**. `GET /api/cluster/nodes`
and the node's own `checkDPCertExpiry` both reported months of validity while every handshake failed
— *nothing in the fleet was looking at the only date that mattered.* `clusterCARenewalWindow` is one
constant shared by the CA's rotation window and the clamp horizon, so on a healthy fleet the clamp is
unreachable; where it is reachable, the resulting renewal pressure is the visible signal.

### 17.5 One loop, two trust roots (CA-19)

`StartCAAutoRotation` drives both CAs, and its caller started it only `if certMgr.Ready()`. That
reads as a harmless optimisation and was a silent cross-domain kill: an inspection-CA load failure
took down the *cluster* CA's entire lifecycle manager, including secondary-overlap cleanup. The
nastiest part is the time constant — a cluster CA is a 10-year certificate, so the consequence
surfaces years after the fault that caused it, with no log line anywhere mentioning the coupling.
Both halves are already no-ops when their CA is absent, so the loop is now unconditional. **Rule
worth generalising: a driver shared by N subsystems must not have its start condition owned by one
of them.**

### 17.6 Observability added

| Surface | Signal |
|---|---|
| `/metrics` | `culvert_cluster_ca_usable`, `culvert_cluster_ca_expires_in_seconds` (omitted when absent — 0 would read as "expires now"), `culvert_cluster_ca_sign_refused_total`, `culvert_cluster_ca_node_certs_clamped_total`, `culvert_cluster_ca_rotation_failures_total` |
| `/healthz` | `cluster_ca`: `ready` / `expired` / `rotation_failing` / `disabled` |
| `/readyz` | `cluster_ca` row, **report-only** (an expired cluster CA is fleet-wide by construction; gating would eject every node at once and take working proxy traffic with it). `?strict=1` opts in. Fails only on the CURRENT outage — a failing ROTATION is not a readiness failure, since such a node still enrolls, renews and syncs; it is a dated problem, so it lives on `/healthz`, diagnostics, the alert and the counter instead of on the surface a load balancer uses to eject nodes. Fixed detail — unauthenticated surface, pinned to contain no digits and no path |
| Alerts | `cert_expiry` with `Host: culvert-cluster-ca` — the EXISTING event, deliberately: a new name would be silently unsubscribed on every already-configured webhook |
| `/api/diagnostics` | `cluster_ca` row (fail on unusable, fail on rotation-degraded, warn on the clamp shoulder, absent without a cluster CA) |
| Admin API / GUI | `GET /api/cluster/ca` gains `usable` / `unusableReason` / `expiresInDays` / `signRefused` / `nodeCertsClamped` / `rotationFailures` / `rotationDegraded`; the Cluster CA panel gains an outage banner, a clamp-shoulder banner, and an honest status (`EXPIRED (enrollment blocked)` instead of a green *Active*) |

Recovery is reported on **evidence** on both axes (`clusterCAUsableNow`, a landed rotation), never on
elapsed time. The reason is sharper here than in CHAOS-28: **on a settled fleet nothing needs a
certificate for weeks**, so a still-expired CA is indistinguishable from a healthy one — a
time-based heuristic would report recovery almost immediately and be wrong every time.

### 17.7 What is deliberately left

- **`RotateIfNeeded` still waits a full 24h after a FAILED attempt** — the cluster-CA twin of CA-4's
  open retry/backoff half. Bounded by the 30-day window (~30 attempts before expiry).
- **`ImportCA` is still not a two-file commit.** A crash between the cert and key writes leaves a
  mismatched pair, detected and failed closed at next startup by `loadFromPEM`. Pre-existing.
- **No days-remaining early-warning alert.** Rotation is automatic at 30 days, so the actionable
  signal is "rotation is failing", which now alerts; operators wanting a days-based page have the
  gauge. A threshold alert is a reasonable follow-up.
- **Client-side trust still cannot be repaired in band.** A DP whose cert already expired must
  re-enroll — which is why this change invests most in making the slide visible rather than the cliff.
- **`ImportCASilent` (HA replication) records no rotation observation**, by design: a standby
  replicating leader state has not rotated anything.

### 17.8 Review follow-up — two defects in the fix itself

Both real, both the sweep's own mistake made while fixing it.

**(1) `culvert_cluster_ca_usable 0` on every node WITHOUT a cluster CA.** `Usable()` errors when no
CA is loaded, so the unconditional gauge read `0` on every standalone appliance and data-plane node —
indistinguishable from an expired CA — while the shipped runbook recommends `== 0` as its paging rule
and promises these rules do not fire outside a cluster. The series beside it
(`culvert_cluster_ca_expires_in_seconds`) already had the correct guard, with a comment explaining
why. Applied to one gauge, missed on its neighbour. Both gauges are now omitted when no CA exists;
the counters stay at `0` so `rate()`/`increase()` work from the first scrape.

**(2) The `NotBefore` skew tolerance issued certs this node's own verifier rejects.** The first cut
copied the inspection CA's 5-minute `caClockSkewTolerance`. Inside that window `Usable()` said yes,
`SignCSR` succeeded, and the clamp pinned the leaf's `NotBefore` to the CA's — so the CP handed out a
certificate its OWN x509 verifier rejects, since it checks DP client certs against that same CA on
that same clock. The exact failure this sweep removes, in miniature (milder: bounded by the skew,
self-clearing, covered by the DP's reconnect backoff). `NotBefore` is now STRICT; clock rollback
lands in the same branch and the same verdict is correct for it.

> **Rule worth generalising:** a tolerance is only sound where the two parties it reconciles are
> genuinely distinct. The inspection CA's tolerance absorbs disagreement between two MACHINES; here
> the rejecting verifier is co-located with the signer, so the same constant turns "absorb
> disagreement" into "disagree with yourself." A constant copied across a boundary needs its
> justification re-derived, not just its value.

## 18. CHAOS-50 / CHAOS-51 — The CA plane's recovery paths (both CAs)

**Date:** 2026-08-14 · **Rows:** CA-3 (closed), CA-3b (new, owner decision),
CA-17 (new, closed) · **Full review:**
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-14.md`

### 18.1 CHAOS-51 — the cluster CA install path self-deadlocked

`sync.RWMutex` is not reentrant. `clusterCA.ImportCA` held `ca.mu.Lock()` across two
calls that come straight back into the same object, and `CleanupSecondary` repeated
the first:

```
ca.onRotate()           → rebuildCPCertPool()  → ca.AllCACertsPEM()  → ca.mu.RLock()
CurrentConfigSnapshot() → globalClusterCA.CACertFingerprint()        → ca.mu.RLock()
```

Each self-deadlocked *and* stranded the write lock for the life of the process, so every
cluster-CA reader blocked forever — `CACertFingerprint` included, hence **every CP→DP
`ConfigSnapshot`**. `rebuildCPCertPool` takes `cpTLSConfig.mu` *before* it blocks, so that
mutex is stranded too, and it is the one `getCPTLSConfigForClient` takes on every
ClientHello: the CP also stops completing TLS handshakes, so a reconnecting DP cannot even
reach the RPC that would have served it stale config.

**Reachable three ways, two unattended:** `POST /api/cluster/ca` (immediately and
deterministically on any CP whose gRPC server is up — that is what wires `onRotate`),
`RotateIfNeeded` at cluster-CA expiry−30d, and `CleanupSecondary` at the end of an overlap
window. A restart clears the lock but not the last two triggers, so the node re-deadlocks:
**self-reproducing and non-recoverable.**

**Why the suite never saw it.** Every prior `ImportCA` test calls the method on a **local**
`clusterCA` value, while the re-entrant reads go through the `globalClusterCA` package
variable — a different mutex — and `rebuildCPCertPool` returns early when
`cpTLSConfig.cfg == nil`, which it always is in a unit test. The generalisable rule:
**a test that constructs its own instance of a singleton cannot observe a re-entrancy defect
in that singleton.** The new gates install the object under test *as* the global and stand up
`cpTLSConfig`, and bound every call on a child goroutine so a regression reports instead of
wedging CI.

**Fix.** `installLocked` does validation, backup, overlap bookkeeping, persistence and the
state swap under the lock and returns a `clusterCAImportEffects`; `ImportCA` then runs
`onRotate`, `StartCARotation`, the config publish and the counter with the lock released.
`CleanupSecondary` captures `onRotate` under the lock and calls it after unlocking.
`StartCARotation` fires only when a previous CA existed — `ca.secondaryCert` was
dereferenced unconditionally, a nil panic on a FIRST import (reachable when `onRotate` is
unwired; otherwise the deadlock at the preceding line wins).

**Keep the rule:** nothing called between `ca.mu.Lock()` and its `Unlock` may reach
`globalClusterCA`, `CurrentConfigSnapshot`, or the CP TLS pool.

### 18.2 CHAOS-50 — a failed Root-CA load had no way back

CHAOS-06 made the failure visible; CHAOS-28 made an *expired* CA fail closed. Neither asked
what happens next, and the answer was nothing.

1. **The auto-rotation loop was gated on `certMgr.Ready()`** but drives four things — both
   CAs' `RotateIfNeeded` and both secondary cleanups. An inspection-CA fault therefore
   silently disabled **cluster-CA** rotation for the process lifetime, and left every runtime
   recovery with a CA that would never auto-rotate. The gate bought nothing: both
   `RotateIfNeeded`s already no-op when their own CA is absent. Now unconditional.
2. **No retry.** The bundle was read once. The faults that actually happen are transient
   (volume attaches after the container starts, NFS/EBS hiccup, ownership fixed a minute
   later, disk full at first write) and all of them left inspection disabled long after the
   fault cleared. Now a **bounded** campaign: `caLoadRetryBudget` 10 attempts,
   `caLoadRetryInitial` 5 s → `caLoadRetryMax` 5 min, then a terminal log line.
3. **A retry must never MINT.** `LoadOrInitCA` generates a fresh root when the path is
   absent — right on first boot, catastrophic on a retry: an unmounted volume would silently
   swap the fleet's trust anchor for one no client trusts and write it to ephemeral storage,
   reproducing the CA-1 symptom from a new cause with the appliance reporting itself healthy.
   `attemptInspectionCARecovery` matches the action to the fault (no path ⇒ `InitCA`; CA
   already loaded ⇒ `SaveCA`, the durability half; otherwise ⇒ `LoadCA` on the configured
   bundle only).
4. **`sslInspectionLoadError` was write-only** — `/healthz`, `/readyz?strict=1` and support
   telemetry stayed red after a *real* recovery, a probe that outlives its fault and an
   inversion of this plane's own recovery-on-evidence rule. `noteSSLInspectionRecovered`
   clears it, called from the retry loop, from `apiCARotate` **after** the persist check, and
   from the MITM `apiCertsUpload` — which now **persists** the uploaded CA (it was memory-only
   and silently lost on restart).
5. **The fail-OPEN direction had no counter**, while its fail-CLOSED twin has had one since
   CHAOS-28. Now `culvert_ca_inspect_bypassed_total` + a rate-limited log + `/api/ca/status`
   + a CA-panel banner.

### 18.3 What is deliberately left

- **CA-3b — the posture.** An inspect-matched CONNECT with no CA loaded still bypasses, while
  the same appliance-wide fault at *expiry* is refused 502. CHAOS-28's supporting argument
  ("refusing costs no availability that signing would have preserved") does **not** carry
  over: that traffic was already dead, this traffic works fine as a tunnel. The flip is a
  customer-visible availability decision and belongs to the owner. This work makes the window
  short (retry) and measurable (counter) so the decision can be taken on data.
- **The retry schedule is not configurable** (GUI-parity cost for a value nobody has asked to
  change).
- **CA-13** — still open; this sweep went to `enrollment.go` for the deadlock and did not
  widen into the rotation-observability half.

### 18.4 Review follow-ups (raised against the fix, fixed in the same PR)

Both are the SAME SHAPE as the bug this sweep is about — a multi-step operation whose steps
are individually atomic and jointly not — so they are recorded rather than deferred.

- **FS-9 / row CA-18 — automatic and manual Root-CA recovery could overwrite each other.**
  Installing a CA is read/generate → install → persist → clear-the-latch. The retry loop and
  the admin force-rotate both perform it and nothing serialized them: a retry could read the
  OLD bundle, the admin could install AND persist a NEW one, and the retry would then install
  its buffered old CA on top. The API reports `persisted:true` — true, ON DISK — while the
  LIVE process signs with the superseded root, so every client the operator just provisioned
  with the new root rejects every leaf until a restart. Not remote: the retry window is
  ~25 min and force-rotate is the documented manual recovery, so these are the two actors an
  operator runs during the same incident. Fixed with `caMutationMu` (an OUTER lock across
  install + persist + latch-clear in all three paths); the "already fixed by hand?" check
  moved INSIDE the lock, because outside it that was a check-then-act with the same gap.
  Pinned by `TestChaos50_ManualRecoveryIsNotOverwrittenByRetry`.
- **FS-10 / row CA-19 — the cluster-CA publish phase could interleave.** Releasing `ca.mu`
  before the publish is what removes the deadlock, but on its own it lets a second import land
  between the state swap and the publish: two imports can run `StartCARotation` out of order
  (persisted rotation record describes the OLDER CA) or a cleanup can clear a newer import's
  record. Fixed with `clusterCA.installMu`, an OPERATION-level lock spanning `installLocked` +
  the publish, taken by `ImportCA` and `CleanupSecondary`. The two locks are not
  interchangeable: `mu` guards the fields and must not be held across the publish; `installMu`
  orders the operations and is never taken by anything the publish reaches. Lock order
  `installMu` → `mu`, never the reverse, so the CHAOS-51 cycle is not reintroduced. Pinned by
  `TestChaos51_ConcurrentImportsKeepRotationRecordConsistent`.

## 19. CHAOS-50 — The boot path under a damaged data volume

**Date:** 2026-08-17 · **Register rows touched:** ST-12 (re-scoped L → H, CLOSED),
ST-9 (partly closed), WK-7 (boot half closed) ·
**Full write-up:** `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-17.md` ·
**Runbook:** `docs/operator/category-store-recovery.md`

### 19.1 The asymmetry

CHAOS-05/07 already decided what a corrupt state file does at boot, and recorded
the reasoning in `state_corruption.go`: quarantine the evidence, keep booting,
because *"refusing to boot could take down a fleet on a single bad sector."* It
was applied to `ui_users.json` and `cluster.json` and nowhere else.

| | `ui_users.json` | `cluster.json` | community category store |
|---|---|---|---|
| Holds | admin accounts, TOTP secrets | node roster, revoked certs | **a cache of a downloadable feed** |
| Authoritative | yes | yes | **no** |
| Corrupt at boot | quarantine + continue | quarantine + continue | **`logFatalf` → exit(1)** |

The appliance refused to boot over the one store whose loss costs nothing, and
kept booting over the two that hold real state. `docker-compose.yml:152` sets
`-cat-feed-db /data/catfeeddb` and the same service sets
`restart: unless-stopped`, so this is the DEFAULT deployment and the fatal is an
unattended crash-loop: no proxy, no admin UI, no health endpoint, and no path
back through any interface the product ships.

### 19.2 The fault the obvious fix does not reach

A corrupt `.sst` does not make `badger.Open` return an error. It panics, from a
goroutine badger itself spawns:

```
panic: runtime error: slice bounds out of range [-2779063644:] [recovered]
	…
created by github.com/dgraph-io/badger/v4.newLevelsController in goroutine 21
```

`recover()` at the call site is on a different goroutine and never fires —
proven live in a child process whose `defer recover()` wraps the open and which
still dies with exit status 2 having printed nothing. Changing `logFatalf` to
`return err` would have closed the *recorded* gap and left the worst instance of
it untouched. **The store had to stop being handed to badger at all.**

ST-12's recorded remedy is also gone: badger v4 REMOVED `Options.Truncate`. The
doc comment on `catdb.Open` promising crash-truncation was simply false, and it
is why the row sat at severity L for six weeks.

### 19.3 The empirical table (badger v4.9.6, the options `catdb.Open` uses)

| Injected fault | Result |
|---|---|
| `MANIFEST` scrambled | error — `Manifest file might be corrupted` |
| `MANIFEST` truncated / emptied | error — `manifest has bad magic` |
| **`.sst` scrambled** | **PANIC, uncatchable, exit 2** |
| `.sst` deleted | error — `file does not exist for table 1` |
| `KEYREGISTRY` scrambled | error — `Encryption key mismatch` |
| value log scrambled | opens cleanly (badger tolerates it) |
| dir lock held | error — `Another process is using this Badger database` |
| path is a regular file | error — `… not a directory` |

**None of these are reachable through `errors.Is`.** badger wraps them with
`y.Wrapf`, which implements no `Unwrap`, so `errors.Is` against
`ErrTruncateNeeded` / `y.ErrChecksumMismatch` / `ErrEncryptionKeyMismatch`
returns false for the faults that produce exactly those conditions. Message
matching is the only mechanism available — which is why the table is itself a
test (`TestClassifyOpenError_EmpiricalBadgerMessages`) and why it is never
allowed to authorise a rename on its own.

### 19.4 The fix — `catdb.OpenResilient`

1. **A per-attempt, flock-OWNED poison marker** (a SIBLING of the store, so a
   quarantine cannot carry it away) is armed around every open attempt and
   cleared however the attempt returns. A marker whose flock can be TAKEN
   belongs to a process that is gone — the kernel releases flocks on death — so
   it means exactly one thing: that process entered `badger.Open` and never came
   back out. That is the only signal available for the panic, and it also covers
   SIGKILL/OOM. It is per-attempt and flock-owned rather than a single shared
   path because a shared one cannot survive concurrency: a second process
   booting while the first was still inside `Open` would clear the first's
   breadcrumb, and if the first then panicked the next boot would walk into the
   corrupt store again — the crash loop persisting through the very mechanism
   meant to break it. A live opener's marker is never touched, and a SKIPPED
   quarantine leaves the breadcrumbs for the next boot.
2. **Quarantine before badger, not after.** On a poison marker the directory is
   moved aside (`.corrupt.<unixnano>`, the CHAOS-05/07 convention, **never
   deleted**, pruned to one copy) before badger is touched.
3. **Every quarantine holds the store lock ACROSS THE RENAME.** A non-blocking
   exclusive `flock` of the DIRECTORY — badger's own lock, `badger/dir_unix.go`
   — is taken and held until the move is done. Probing and releasing first would
   leave a window in which another process acquires the lock and starts opening
   a store that is about to be renamed underneath it: `rename(2)` does not
   consult flocks. The invariant is carried by the TYPE — `quarantineDir` takes
   the `*heldLock` as a required argument and refuses a nil or already-released
   one (`errStoreLockNotHeld`) — so a refactor back to probe-then-let-go cannot
   silently reopen it. Pinned by
   `TestOpenResilient_NeverQuarantinesAStoreAnotherProcessHolds` (the holder's
   data survives AND its breadcrumb is left alone) and
   `TestQuarantineDir_RefusesWithoutAHeldLock`.
4. **Returned errors: deny-list first.** Environmental faults (lock held, not a
   directory, EACCES, EROFS, ENOSPC, EMFILE, EIO) are matched BEFORE the
   corruption allow-list, and anything unrecognised degrades. A rename fixes
   none of them and on the lock case is destructive. Fail-safe default: leave
   the disk alone.
5. **Never fatal.** `loadCommunityFeedDB` degrades to `communityDB = nil`, which
   every consumer already nil-guards (`policy.go:1592,1621`, `ui_policy.go:947`,
   `main_shutdown.go:259`) — byte-identical to running without `-cat-feed-db`.
6. **One outcome, one account.** The result is reported only after it is known.
   A quarantine that succeeded followed by a replacement that would not open
   (volume went full or read-only in between) is a FAILURE, not a recovery;
   reporting the quarantine first queued "re-created empty, the feed re-syncs
   automatically" and then contradicted it. `reportCatFeedDBUnavailable` folds
   the quarantine in as CONTEXT so the operator learns the fault is with the
   replacement store.

Automatic re-creation is safe **only because this store holds no authoritative
state**: `feedsync.Start` performs an immediate sync when it finds the store
empty (`internal/feedsync/feedsync.go:177`), so recovery costs one feed sync.
The same mechanism on a store with authoritative content would be data
destruction — which is why the quarantine moves aside rather than deletes, and
why it is deliberately NOT extended to `internal/logstore` here.

### 19.5 Visibility

No new flag, YAML key, env var, or API field — the GUI-parity rule is satisfied
by surfaces that already exist:

| Surface | Signal |
|---|---|
| `/api/diagnostics` | new `category_feed_db` row — `ok` when unconfigured or clean; `warn` for recovered / unreconciled evidence / unavailable; **never `fail`** |
| `/metrics` | `culvert_catfeeddb_available`, `_recovered`, `_quarantined_copies` |
| Alerts | **reuses** `state_file_corrupt` — the event already means "corrupt state quarantined at startup" and the operator action is identical (the CHAOS-49 lesson: do not invent a second dialect) |
| Logs | quarantine detail via `sanitizeLog` + `%q`; degrade line names Layer-1-only |

**Deliberately not on `/readyz`.** A node on Layer-1-only categorisation is
fully able to serve — the posture of any node without `-cat-feed-db`. Failing
readiness would pull a healthy gateway out of rotation over a degraded cache,
which is this review's own mistake committed one layer up. The diagnostics row
also carries no raw path or badger error (the CHAOS-28 viewer-role guardrail),
pinned by `TestCheckCategoryFeedDB_RowCarriesNoRawCause`.

### 19.6 What is deliberately left

- **R-E — `internal/logstore` has the same uncatchable panic.** `OpenTTL`
  (`internal/logstore/logstore.go:298`) calls `badger.Open` with the same options
  and version. Bounded by being opt-in and already non-fatal on ERROR; made worse
  by being reachable from the **admin API** (`enableLogStore` via the GUI toggle
  and `LoadAdminSettings`), so an admin can kill the gateway by turning history
  on. Not fixed here because its content is request history with retention
  semantics: quarantining it silently is an evidence decision, not a cache
  decision. **Next sweep candidate.**
- **R-F — three fatal boot loads remain with no declared principle.**
  `catStore.Load`, `blocklist_startup.go:59`, `main.go:724`. `categories.json` is
  the closest analogue to the two files CHAOS-05/07 chose to quarantine, and it
  exits instead. Whether "policy-load-bearing" justifies refuse-to-boot rather
  than boot-and-deny is an owner call, not a patch.

  **This is not a new finding, and that is the point.** The 2026-07-11 audit
  already inventoried the class as **F-23 "Crash loop on fatal config"**
  (`docs/engineering/PRODUCTION-FAILURE-MODE-AUDIT.md` §4, the failure-mode
  matrix), noting `restart: unless-stopped` ⇒ *"indefinite crash loop"* with
  *"no self-alert after day-1"*, and ranking it among the top availability
  killers (§15). Its `Mode` column reads `CLOSED` in the sense that table uses —
  fail-CLOSED, i.e. the process dies rather than passing traffic — **not**
  "resolved"; the audit is an inventory, not a tracker, and nothing claimed a fix.

  **R-F is a SUBSET of F-23, not the remainder of it.** F-23 lists five entries,
  and one of them covers two distinct loads:

  | F-23 entry | Load | Status |
  |---|---|---|
  | `urlcategories_startup.go:22,46` | `:46` — Layer-2 community store | **CLOSED by CHAOS-50** |
  | `urlcategories_startup.go:22,46` | `:22` — `catStore.Load`, Layer 1 | R-F |
  | `blocklist_startup.go:59` | blocklist | R-F |
  | bad policy (`main.go:690`, now `:724`) | policy file | R-F |
  | `cluster_startup.go:44` | malformed HA lease | **not R-F** |
  | `main.go:993` / `ui.go:118` | port-bind | **not R-F** |

  So CHAOS-50 closed ONE load — half of a single F-23 entry — a month after the
  audit named it, having rediscovered it independently. R-F is the three
  remaining **data-file** loads, which share the question this sweep answered for
  Layer 2: is refuse-to-boot right for a file that failed to parse? The HA-lease
  and port-bind entries are deliberately outside R-F — they are not data-file
  loads and their postures are separate arguments (a port-bind failure has a
  strong case for staying fatal). Anyone picking this up should start from F-23's
  list rather than re-deriving it a third time, but should scope R-F to the three
  rows above.
- **Panic recovery costs one restart.** The marker cannot act until the boot
  after the crash. Zero-crash recovery means probing the store in a child process
  first — better, and a reasonable follow-up, but larger than the fault warrants.
- **A spurious quarantine is possible** when a kill lands inside `badger.Open`
  for an unrelated reason: one feed re-sync, one bounded directory, both
  reported. Accepted, and preferable to a default that never recovers.
- **No circuit breaker on repeated quarantines.** A dying disk will re-download
  the feed on every boot; `culvert_catfeeddb_quarantined_copies` and the
  diagnostics row are the operator's signal, but nothing in the process gives up.

---

## 20. CHAOS-52 — The body-scan pipeline under scanner slowness and saturation

**Full write-up:** `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-21.md`.
**Id allocated at the start of the sweep**, per the governance note in §0 — this is the first sweep
to do so.

### 20.1 Why this domain

WK-1 has been an open High since the first sweep, framed as a posture question about a ClamAV daemon
that is *down*. Every review since has re-read it as "should fail-open be fail-closed?" and left it
as an owner decision. Nobody asked the prior question: **what else reaches that branch?**

The answer is: ordinary load. `clamav.Client.Scan` caps concurrency at four and, with the slots busy,
waited five seconds and returned an error — and to `scanBodyInner`, an error from the engine is a
fault, so it takes the fail-OPEN path. The orchestrator's own ten-second budget, which exists to
decide precisely the case "the scan did not finish in time" and decides it fail-CLOSED, never got to
run. **The inner limit always fired first and inverted the outer one.**

That is a security control switched off by capacity, on healthy infrastructure, by anyone who can
send four large requests.

### 20.2 The four defects

1. **WK-15 — the inner deadline inverted the outer one.** Fixed by making the queue wait charge to
   the CALLER's context (`ScanContext`). Exceeding the budget is now the outer, fail-closed
   decision. `ErrQueueFull` keeps "at capacity" distinguishable from "daemon faulted" — different
   counter, different log line, and no `scan_clam_error` alert for the one that is not a fault
   (pre-fix, one busy period alerted repeatedly against a perfectly healthy daemon, *while* the node
   was at its busiest — the same backwards-under-load shape the `HasSubscriber` rule exists to
   prevent).
2. **WK-16 — abandoned work held the scarce resource.** `ScanBody` stopped waiting without stopping
   the work; the goroutine kept its ClamAV slot to the client's 30 s timeout, 3x the budget that had
   already abandoned it. Four of those occupy every slot, so live requests take WK-15's fail-open
   path and load keeps the system there. Fixed by making the budget a context that actually reaches
   the dial, the connection deadline (`effectiveDeadline` takes the earlier of caller and client),
   and a watcher that closes the connection on cancel. Abandonment is now bounded in TIME by the
   budget, hence in COUNT by arrival-rate × budget, and it is visible (`culvert_scan_inflight`).
3. **WK-17 — the refusal outlived the fault.** The fail-closed `"scan timeout"` entry went into the
   hash cache with the CONTENT TTL. A five-second stall blocked that object for an hour, node-wide,
   after recovery. Fixed with `hashcache.SetTTL` and a 30 s cooldown — keeping the useful half (a
   burst of requests for one hot object must not each start a doomed 10 s scan, which is what fills
   the queue in the first place) without the hour.
4. **WK-18 — the abandoned scan could overturn the fail-closed verdict.** It wrote `Clean:true` over
   the refusal, converting a fail-closed decision into a cached admission, silently. Fixed with a
   tighten-only rule: a late BLOCK still publishes (and upgrades the placeholder to the real threat
   name); a late CLEAN is discarded and counted. The budget is additionally enforced from inside
   `scanBodyInner`, because `ScanBody`'s `select` can see a finished scan and an expired deadline as
   simultaneously ready and pick either — without that, an overrun could be laundered into a clean
   verdict by winning a coin flip.

### 20.3 The process lesson

WK-17 and WK-18 sit within twenty lines of a comment stating the correct rule for the *neighbouring*
branch: the ClamAV-error path already refuses to cache a verdict computed while the daemon was dark,
*"otherwise the same content stays admitted by hash long after ClamAV recovers."* The reasoning was
right and was applied to exactly one branch.

This is the third occurrence of that shape (2026-08-19 §13.1, the omitted gauge next to the one that
got it right; CHAOS-28's paired persist observers). Stated generally:

> **When a branch is given a special rule because of what it computed under failure, check every
> sibling branch that computes under the same failure.** The reasoning is almost never specific to
> the branch that happened to be reviewed.

### 20.4 Operator runbook

`docs/operator/scan-capacity-and-timeouts.md` — the new signals, suggested paging rules, triage for
"users report intermittent 403 scan timeout", how to add scanning capacity, and the posture table
(including why saturation fails closed while a down daemon does not).

### 20.5 What is deliberately left

- **`clamMaxConcurrent` is still a hardcoded 4, and is now availability-critical.** Failing closed
  under saturation turns a silent bypass into a visible refusal — the right direction — but a node
  with genuinely insufficient scanning capacity now blocks where it used to admit. No knob was
  added: a setting whose only use is widening a security bypass deserves a design decision, not a
  side effect of a chaos fix. Raising it, or making it configurable with GUI parity, is the natural
  follow-up.
- **WK-1b** (daemon genuinely down → still fail-open) is unchanged and remains an owner decision,
  now counted, alerted, and separable from saturation.
- **YARA is not cancellable** — `YARAMatcher.Match` has no context, so the YARA leg of an abandoned
  scan still runs to its own internal bounds. Harmless now (tighten-only), but the CPU is spent.
- **The remote scan sidecar was not touched** (WK-2). It is the other fail-open scanning path, with
  its own 30 s per-request timeout and no budget threading; the same findings are structurally
  likely to repeat there. Separate sweep.

### 20.6 Review follow-up — two defects in the fix itself

Found by automated review of the first cut; both real, both the same mistake §20.3 names.

1. **Only the deadline arm of `ScanBody`'s select did the timeout accounting.** Once `scanBodyInner`
   gained its own budget check, the WORKER arm could deliver a timeout-sourced result too — and with
   a budget-aware ClamAV client the connection deadline and `ctx.Done()` become ready at the SAME
   instant, so which arm wins is a coin flip. On roughly half of all timeouts `statScanTimeout` did
   not increment and, worse, **no cooldown was written** — so the next request for that hot object
   immediately launched another doomed scan. The stampede guard was unreliable in exactly the regime
   it exists for. Both arms now route through one `noteScanTimeout`.
2. **The cooldown write could downgrade a confirmed threat verdict.** A late block (from the
   abandoned goroutine, or a concurrent scan of the same hash) landing between the deadline and the
   write was replaced by a generic 30 s entry — after which the object depends on the next scan
   succeeding, and the engine-error path is fail-OPEN. `publishVerdict`'s tighten-only rule, not
   carried across to the branch beside it: **the literal mistake §20.3 names, committed in the change
   that names it.** Fixed with `hashcache.SetTTLUnless` (test and write atomic under the cache lock —
   a caller-side `Get`-then-`Set` would leave open the very window being closed).

---

## 21. CHAOS-53 — The remote scan sidecar under failure, slowness and saturation

**Full write-up:** `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-22.md`.
**Id allocated at the start of the sweep**, per §0.

### 21.1 Why this domain

§20.5 nominated it: the sidecar is the OTHER fail-open scanning path, and CHAOS-52's findings were
judged "structurally likely to repeat there." The judgement was right. What it did not anticipate is
that the same sweep's operator runbook (`docs/operator/scan-capacity-and-timeouts.md`, "Adding
scanning capacity") recommends **moving scanning to the sidecar** as the remedy for the local path's
new fail-closed-under-saturation behaviour — so following the documentation moved an operator from a
path with a budget, cancellation, timeout accounting, a cooldown, a tighten-only cache rule and an
in-flight gauge, to a path with none of them.

### 21.2 The posture inversion (RS-1)

`RemoteScanner.ScanBody` opened `context.WithTimeout(context.Background(), 30*time.Second)` inside an
`http.Client{Timeout: 60 * time.Second}` — 3x and 6x `ScanBodyTimeout` — and handled `client.Do`'s
error with one classification: fault → `remoteScanFail` → `return nil`. A `nil` from a scanner means
CLEAN, so at the call site "the sidecar did not answer in time" and "the sidecar answered clean" were
the same value. The local path spends 130 lines of comment explaining why that exact condition must
BLOCK.

The condition is not exotic. The sidecar is an HTTP front end to the same ClamAV whose concurrency
cap is four; CHAOS-52 measured five concurrent downloads holding all four slots. A queue longer than
the client's deadline is the normal steady state of an under-provisioned scanner.

Fixed by giving both back ends ONE budget: the remote scan runs under `scanBodyTimeout()` — same
value, same test seam — and an overrun returns the local path's own refusal (`Source: "timeout"`),
increments the same `statScanTimeout`, and therefore lights up the same `culvert_scan_timeout_total`,
the same `scan_timeout` alert in `proxy_tunnel.go`, and the same 403. Sidecar-reported capacity
(HTTP 429) is classified as capacity, counted separately, and refused the same way — the CHAOS-52
saturation rule, transposed.

### 21.3 The five silent ones

- **A 200 without an affirmative verdict was CLEAN.** `ScanResponse` unmarshals from `{}` and `null`
  without error, so any 200 with a JSON body admitted the content — an ingress error envelope, a
  health endpoint reached by a mistyped port, a maintenance page. Scanning off, no counter, no log,
  no alert. A verdict must now be `Blocked` or `Clean`; anything else is a counted fault. The shipped
  sidecar sets `Clean` explicitly, so a correct deployment is byte-identical.
- **No metric.** Every `culvert_scan_*` series is produced by `Scanner`, which a remote-mode node
  never initialises, and `statRemoteScanFail` reached only `/api/security-scan/status`. Now
  `culvert_remote_scan_{fail,saturated}_total` + `culvert_remote_scan_inflight`, with
  `culvert_scan_timeout_total` covering both back ends.
- **Scan exclusions were never LOADED in remote mode.** Worse than a stale allowlist:
  `scanexcl.Store` learns its persistence path FROM `Load`, and `Save()` is a documented no-op
  without one — so every admin edit returned 200, wrote an audit entry and took a config-version
  snapshot while persisting nothing, and the lists reverted to empty on the next restart. The HOST
  list is on the request path in remote mode too, so it was being ignored outright as well.
- **The hash allowlist was not consulted, and `Result.Hash` came from the SIDECAR** — the value that
  then names objects in the operator's allowlist and cache-evict surfaces. Now computed locally from
  the bytes actually scanned, and consulted before the round trip.
- **The status blob shadowed this node's identity.** `secScanStatusMap` merged the sidecar's
  `/status` — which IS the sidecar's own `secScanStatusMap`, carrying `"scan_svc_mode": "local"` —
  over the map it had just built, so a proxy in remote mode reported mode `local` to its own admin UI.

### 21.4 The alert that amplified the fault (RS-5)

`remoteScanFail` ran `go alerts.Fire(...)` and `obs.Printf` unconditionally, once per proxied
response, for as long as the sidecar was unwell — the contract CLAUDE.md states and
`fireDNSFailureAlert` documents, violated by the other producer whose rate is set by a FAULT rather
than by the operator. The dedup key made it worse: `Dispatch` dedups on `event + ":" + Detail`, and
Detail was `"transport error: " + err.Error()`, which for a reset embeds the EPHEMERAL LOCAL PORT. A
sidecar resetting connections therefore produced a distinct key per request, unsuppressable by
construction, and the fan-out lands in the 500-entry retry queue — where a scanner fault can evict
REAL threat alerts. CHAOS-27 identified this key-cardinality class for the host-in-detail producers
and bounded the map; this producer was never converted.

Now: bounded reason classes in the alert (so dedup works), the full cause in a `degradedLogAllowed`
line, the counter carrying the magnitude, and a new `alerts.HasSubscriber` seam
(`internal/alerts/alerts.go`) that **fails toward delivery** when no probe is installed, so a missing
wire-up can never silence a real alert.

### 21.5 The process lesson

CHAOS-52 §20.3's rule, one level up. The sibling here is not a branch but a BACK END:

> **A second implementation of a security decision is a second posture until proven otherwise.** When
> a control has two back ends, the invariant belongs to the CONTROL, not to the implementation that
> happened to be reviewed — and the deployment the docs recommend is the one to check first.

### 21.6 What is deliberately left

- **A genuinely unreachable sidecar still fails OPEN** (WK-2b). Unchanged owner decision, now
  counted, gated-alerted, and reachable only by an actual fault.
- **No circuit breaker and no periodic health probe.** Each request pays one budget to rediscover a
  dead sidecar. `internal/upstream`'s breaker plus a `remote_scan` operator-contract row is the
  natural next slice.
- **No hash cache on the remote path.** Identical objects are re-shipped every time — which is
  precisely the stampede that saturates the sidecar. Not fixed here: memoising a sidecar-sourced
  verdict needs a decision about TTL and about whether it may be memoised at all.
- **No `MaxConnsPerHost`.** N concurrent requests open N connections to the component that is already
  the bottleneck. Bounding it is the right direction; choosing the number is a capacity decision, and
  the per-request budget now bounds the damage.
- **The sidecar's `/scan` has no authentication.** Documented as loopback/private-network, enforced
  nowhere. Out of scope; recorded.

---

## 22. CHAOS-54 — The SOCKS5 accept loop under listener faults

**Date:** 2026-08-23 · **Register rows:** PX-16, PX-17, PX-18, PX-19 ·
**Full report:** `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-23.md`

### 22.1 Why this domain

SOCKS5 is named in the failure-domain list and had never been swept. It is also
the only listener in the process whose accept loop is written by hand: the proxy
port, the admin UI, the PAC endpoint and the MCP gateway all run under
`net/http.Server.Serve`, and the control plane runs under gRPC. Both of those
apply an exponential accept backoff and stop on a non-temporary error. This one
did neither.

That asymmetry is the whole finding, and it is the §21 process lesson repeating
one level up: *a second implementation of a behaviour is a second posture until
proven otherwise.* There, the second implementation was a scan back end. Here it
is a listener.

### 22.2 The defect (PX-16)

```go
conn, err := s.ln.Accept()
if err != nil {
    if errors.Is(err, net.ErrClosed) { return }
    logger.Printf("SOCKS5 accept error: %v", err)
    continue                      // ← immediately, forever
}
```

`accept(2)` returns EMFILE when the process is out of descriptors and ENFILE
when the system is. Go's `internal/poll.FD.Accept` retries only EINTR and
ECONNABORTED and waits only on EAGAIN; EMFILE/ENFILE are returned to the caller
straight away and do not block. So the loop above spins at the speed of a
syscall.

Measured with a listener returning EMFILE, on the same box in the same run:

| loop | accept attempts in 300 ms |
|---|---|
| pre-fix (log-and-retry) | **7,681,156** |
| with backoff | **6** |

The cost is not the syscalls. It is what rides on them:

1. **A pinned core** for the duration of the fault.
2. **The log flood erases its own diagnosis.** One `logger.Printf` per attempt
   is roughly 40 MB/s into a `fileutil.RotatingFile` capped at 50 MB with ONE
   archive — the entire 100 MB of retained process log, including whatever
   exhausted the descriptors, is overwritten in about two seconds.
3. **It reaches the HTTP data path.** `internal/logsink` is a shock absorber,
   not a load shedder: a full queue BLOCKS the caller. `handleRequest` writes
   one POLICY_* line per proxied request through that same sink, so a fault in
   an optional, disabled-by-default subsystem adds latency to every request on
   the primary path.

And the trigger is not exotic. FD exhaustion is the *terminal state* of two
already-registered failures — WK-11 (one leaked socket + two goroutines per
delivered alert, whose recorded end state is literally `accept: too many open
files` in the proxy plane) and PX-6 (no global connection cap, limiter disabled
by default). This loop converts a recoverable resource incident into a
self-amplifying one that destroys the evidence of its own cause.

### 22.3 The three that came with it

**PX-17 — one posture for two opposite faults.** EMFILE clears on its own;
EBADF on the listening descriptor never does. The loop treated them identically,
so an unrecoverable socket error was a pure spin *and* the port stayed BOUND —
clients hung against a listener that would never accept, which is
operationally worse than connection-refused because nothing fails fast.

**PX-18 — no health surface at all.** Not `/healthz`, not `/readyz`, not
`/api/diagnostics`, not `/metrics`. A listener spinning on EMFILE and a listener
that had stopped accepting entirely were both reported by every probe as a
completely healthy node. This is the register's §1 theme verbatim.

**PX-19 — no panic guard on the loop.** `handleSOCKS5` has `recoverGoroutine`;
`serve` itself did not, so a panic there killed the whole proxy process.

**PX-20 — and the fix reproduced PX-18 on its way past it.** Raised by Codex
review on the PR, against the first version of this change: the loop returned
silently on any `net.ErrClosed`, but `ErrClosed` only says the listener is gone,
not that a shutdown was requested. Any closure outside the shutdown path ended
the loop with every probe still reporting a healthy node. Worth recording as its
own row rather than folding into the fix, because it shows how easy this failure
mode is to reproduce even while deliberately closing it. The loop now asks
whether `Stop` actually ran — `Stop` closes `stopping` BEFORE `ln.Close()`, so
an in-progress shutdown is always visible by the time `Accept` returns, and the
check errs toward silence rather than a false page.

### 22.4 What shipped

- **Backoff** with net/http's exact schedule (5 ms doubling to a 1 s ceiling),
  reset on an OBSERVED successful accept. The shape is copied rather than
  invented because it is the schedule every other listener in this process
  already follows.
- **The sleep is interruptible.** `Stop` closes a `stopping` channel BEFORE it
  closes the listener, so shutdown never waits out a backoff inside the 2 s
  `socks5-listener-stop` budget. Measured worst case over four trials at the
  ceiling: 107 µs.
- **`socks5AcceptFatal`** — an errno classification (`errors.As`, not string
  matching) that stops the loop, closes the listener and reports DOWN only for
  EBADF/ENOTSOCK/EINVAL/EFAULT/ENOTCONN. **An unrecognised error is NOT fatal:**
  backed off to one syscall per second, retrying an unknown error costs nothing,
  while misclassifying a transient fault as fatal is a customer-visible outage.
  That is the fail-safe direction here, and it does not violate the
  "avoid infinite retries" rule because the retry is never silent — see below.
- **Rate-limited logging**: the first error of an episode immediately, then at
  most one line per 30 s, then one recovery line naming what was suppressed.
  Signal in the log, magnitude in the counter.
- **Degradation is a DURATION, not a count.** The backoff ceiling is reached in
  ~1.3 s; paging on that would page on every transient spike. Thirty seconds of
  uninterrupted failure is no longer a transient.
- **Recovery on evidence only.** Elapsed time never clears the degraded state —
  an accept loop that stopped failing because nobody is dialling it has not
  recovered (the `ca_health.go` / `storage_health.go` rule).
- **Observability**: `socks5_listener` operator-contract row, report-only
  `/readyz socks5` row (absent when SOCKS5 is unconfigured), `/healthz socks5`
  field, `culvert_socks5_{listener_up,accept_errors_total,accept_degraded,accept_backoff_seconds}`
  (emitted only when configured — `up 0` on a node that never had SOCKS5 is
  indistinguishable from a dead listener), and a fire-once-per-episode
  `socks5_listener_down` alert with a BOUNDED reason class in the Detail.
- **Degraded and down carry SEPARATE fire-once latches.** Raised in review of
  this fix: a single shared latch swallowed the page for a dead listener
  whenever it had already been degraded — silencing the more urgent of two
  states that point at opposite actions. This is `storage_health.go`'s
  "two failures must not share a rate gate" rule in a different costume.

Gates: `socks5_accept_chaos_test.go` (18), green under `-race` and under the
`-count=2 -shuffle=on` determinism gate.

### 22.5 What is deliberately left

- **PX-1 / PX-5 / PX-6 / PX-7 / PX-8 are untouched.** SOCKS5 still dials the
  origin directly (no parent-proxy chaining), there is still no global
  connection cap, QoS is still not enforced on the data path, and in-flight
  SOCKS5 handlers are still not drained on `Stop`. Each is its own change.
  PX-8 picked up a supporting data point here: the first draft of the
  healthy-path gate dialled the real listener, and the `handleSOCKS5` goroutine
  it spawned outlived `Stop` and raced the next test's `setupProxyTest` over the
  `ipf`/`rl`/`connLimiter` globals — caught by the race detector on the full
  suite, and already predicted verbatim by a comment in
  `socks5_shutdown_test.go`. That is a test-harness symptom of the production
  property: after `Stop` returns, handlers are still running against live
  shared state and nothing waits for them.
- **SOCKS5 still does not consult the policy engine.** `handleSOCKS5` applies
  the IP filter, rate limiter, per-IP connection limiter, blocklist, plugin
  chain and SSRF guard, but never `Evaluate` — so category, GeoIP and schedule
  rules, and the default-deny posture, do not apply to it. That is a
  security-posture question, not a resilience one, and it is far too large to
  fold into a chaos fix. Recorded here as the next sweep's headline candidate.
- **The listener cannot be rebound at runtime.** A DOWN listener needs a
  restart. Re-binding would need an owner decision about port reuse and about
  what a half-rebound listener means for the shutdown sequence.

### 22.6 The process lesson

§21 stated it for back ends. The generalisation this sweep confirms:

> **Every hand-rolled equivalent of a stdlib server loop is a place where the
> stdlib's hard-won failure handling was silently opted out of.** `net/http`'s
> accept backoff exists because someone hit exactly this; a loop that reproduces
> the happy path without it has reproduced the shape, not the behaviour. When a
> subsystem is the only one of its kind in a process, ask what the others do
> that it does not.

---

## 23. CHAOS-55 — The fencing lease's recovery paths

**Date:** 2026-08-24 · **Register rows:** HA-7, HA-16, HA-17, HA-18 ·
**Full report:** `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-24.md` ·
**Runbook:** `docs/operator/ha-lease-recovery.md`

### 23.1 Why this domain

HA-7 has sat in this register as an open **P1** since the first sweep, with the
remediation already written down (§8 item 8) and the test already specified
(§10). It was scored *Low* likelihood. That scoring was wrong, and the reason it
was wrong is the finding: the trigger is not an exotic etcd failure, it is
**boot ordering**. On a host reboot the container runtime starts culvert and
etcd concurrently, and a few seconds of `connection refused` was enough.

### 23.2 HA-7 — a budget spent on the wrong fault

```go
if err != nil || st.Holder != id {
    return false        // "real denial (other holder) or unknown backend state"
}
```

The comment names the conflation and then acts on both halves identically. A
foreign holder is a **decision** — retrying it means waiting for a live leader
to die. An unreachable backend is an **absence of one**. `haResumeGhostWait`
(45 s) was therefore spent exclusively on the denial shape that is not a fault.

And the fail-closed choice made here bought nothing: `ResumeAsLeader` takes the
leader role anyway, `WriteAllowed()` is false, `startLeaseKeepalive` no-ops on a
zero epoch, and no code path remains that will ever call `Acquire` again. The
node cannot issue a certificate, accept a revocation, or publish a snapshot a DP
will take. `PromoteManually` refuses a node whose role is already `leader`, so
the operator's only lever was a restart.

### 23.3 HA-16 — leadership given up on an unknown

Where the ex-standby's address WAS recorded, the demotion fired on any failed
resume. In a two-node cluster restarting together, both nodes make the mirror
guess:

| | node A (persisted leader) | node B (persisted standby) |
|---|---|---|
| resume | acquire fails: etcd not up yet | — |
| role | **standby**, syncing from B | **standby**, syncing from A |
| sync | rejected — no live lease holder | rejected, same |
| `lastSyncOK` | zero | zero |
| `leaseAutoPromote` | refused: *"no successful state sync yet"* | refused, same |

Two healthy processes, an etcd that has been up for hours, and no leader.
Nothing is red.

### 23.4 What shipped

- **The resume budget now covers transport errors.** `resumeAcquireRound`
  classifies each round (`granted / foreign / ownGhost / unknown /
  raceRetryable`) and the retryable ones retry. This alone covers the common
  boot-order case with no read-only window at all.
- **…but under its OWN, much shorter budget** (`haResumeUnreachableWait`, 5 s,
  vs the ghost path's 45 s). `ResumeAsLeader` runs inside `initCluster`, which
  `main.go` orders BEFORE the root CA, the policy engine, the proxy listener and
  the admin UI — so time blocked here is time the **secure web gateway data
  plane is not serving**. Reusing the 45 s ghost budget would have fixed a
  control-plane write outage by buying a data-plane availability outage, and the
  fence governs control-plane writes and nothing on the data path. The resume
  absorbs the short race it exists for and hands anything longer to the
  background loop, which costs the boot nothing. Pinned from both ends
  (`ResumeAbsorbsAShortBackendOutage` / `ResumeDoesNotBlockBootOnALongOutage`).
  The ghost budget stays 45 s — that wait is for a condition with a known,
  self-clearing expiry, and it is pre-existing behaviour.
- **A background re-acquire loop** for a longer outage. Bounded in RATE, never
  in ATTEMPTS (1 s → 30 s, ±20 % jitter): giving up would reinstate the dead
  end. That does not violate "avoid infinite retries" for the same reason
  CHAOS-54's accept loop does not — the retry is never silent (first failure
  logged immediately, then ≤1 line/60 s, then a recovery line naming the
  suppressed count; magnitude in a counter). The jitter is load-bearing: a fleet
  restarts together after a site-wide power event, so a fixed cadence aims a
  synchronised herd at the recovering etcd (the WK-13 shape).
- **The sleep is interruptible** (CHAOS-54's rule): `Stop` closes the recovery
  channel, so shutdown never waits out a 30 s backoff. Pinned over 8 trials —
  where `Stop` lands inside a sleep is uniform, so one trial passes a broken
  build most of the time.
- **Read before acquire, and demote only on an affirmative foreign holder.**
  `Acquire` is denied while anyone else holds the lease, so the loop cannot take
  leadership from a live peer — but quietly retrying until that peer *dies* and
  then taking over would make a node of unknown state age authoritative. That is
  exactly `haPromoteFreshnessWindow`'s judgement, so recovery routes to it
  rather than around it: an observed foreign holder is **LATCHED**, the loop
  exits, and this process never acquires again.
- **The latched disposition mirrors the shipped S4/S2 decision** rather than
  inventing a third stance — resync from the recorded ex-standby when the
  material exists, otherwise keep the read-only leader role plus a CRITICAL
  alert.
- **Panic containment lands the OPPOSITE way from `leaseRenewRound`**, and the
  contrast is the point. Containing a keepalive panic is dangerous because it
  would let a node keep authority it is no longer confirming (§12). Here the
  node has NO authority to extend, so containing a panicking round and backing
  off is strictly fail-closed; crashing a node that is already degraded helps
  nobody. Reported via the crash plane and charged to the attempt counter.
- **Six metrics** (HA-17), emitted only when a fence is armed:
  `culvert_ha_{write_authority,lease_epoch,unfenced,lease_recovering,lease_reacquire_attempts_total,lease_reacquired_total}`,
  plus `lease_recovering` on `/healthz` and `/api/cluster/ha`.
  `culvert_ha_unfenced` is deliberately NOT `!WriteAllowed()` — a standby has no
  write authority either and that is healthy; the gauge fires only for a node
  that believes it is the leader and cannot write. The alertable pair is
  `unfenced=1 AND recovering=0`: read-only and no longer trying.

Gates: `ha_lease_recovery_chaos_test.go` (18). Every DEFECT gate was verified
failing against the pre-fix tree; the arming, latching and jitter gates pin new
behaviour and have no pre-fix counterpart.

### 23.5 What is deliberately left

- **HA-18 — a self-fenced ex-leader with no recorded ex-standby stays a passive
  standby forever.** Not covered by the recovery loop by design: re-acquiring
  from `role=standby` is a PROMOTION, and the freshness gate that governs
  promotions is keyed on `lastSyncOK` — structurally wrong for an ex-leader,
  which does not sync, so the gate would refuse the one node whose state is by
  definition the freshest in the cluster. Whether an ex-leader's own last-write
  time may substitute is a posture decision with split-brain implications, so it
  is recorded for an owner rather than settled in a chaos fix.
- **`WriteAllowed()` is silently false whenever `leaseValidFor <=
  haLeaseWriteMargin`.** The config path is already covered (`haLeaseMinTTLSec`
  = 3 s, fatal below), but the value trusted at runtime comes from the BACKEND,
  so a backend reporting a shorter validity than configured reproduces it: a
  leader that acquires, renews successfully forever, logs only success, and can
  never write. Now detectable as `culvert_ha_write_authority 0` with
  `culvert_ha_lease_epoch != 0` — otherwise impossible, and worth an operator
  rule. Not otherwise changed.
- **HA-19 — a free lease is not proof that the fence never moved.** Raised by
  Codex review against this PR. The loop's poll interval is now capped below the
  lease TTL, and since etcd keeps a holder's key for at least one full TTL after
  it stops renewing, a peer tenure that begins and ends between two SUCCESSFUL
  observations is no longer possible. What remains is a blind period this node
  cannot bound: a partition where we cannot reach etcd but a peer can. Worth
  keeping in proportion — the SHIPPED resume path has the same property (an
  operator-restarted leader acquires a free lease with no proof either), so the
  class is pre-existing and the change makes it reachable without a restart
  rather than creating it. The two candidate closures are durable evidence of an
  intervening epoch (not available: `create_revision` advances on unrelated
  writes, and a free-lease `Read` carries no watermark) or routing a long-blind
  recovery through the standby freshness machinery instead of acquiring. Same
  posture class as HA-18, recorded for an owner.
- **`Fake` and `Etcd` disagree about `Read` on a FREE lease** — `Fake` preserves
  an epoch watermark, `Etcd` returns a zero `Status{}` because it deletes the
  key on expiry. Nothing consumes it today, but the conformance suite claims the
  two agree.

### 23.6 The process lesson

§21 stated it for back ends, §22 for listeners. This sweep generalises it to
**decisions**:

> A subsystem that is careful about what it may CONCLUDE from an unknown in one
> direction is not automatically careful in the other. `ha_lease.go` documents
> "leadership cannot be taken while the fence's state is unknown" and enforces
> it exactly — while, forty lines away, leadership was GIVEN UP on the same
> unknown, and the node then stopped asking. When a component states a rule
> about uncertainty, check every branch that consumes it, not only the one the
> rule was written for.

---

## 24. CHAOS-56 — The shutdown sequence under a hook that does not return

**Date:** 2026-08-25 · **Domain:** system shutdown (SIGTERM → exit) ·
**Status:** shipped · **Gates:** `shutdown_chaos_test.go` (14)

### 24.1 Why this domain

Every previous sweep in this register examined a subsystem while the process
was *running*. This one examines the ten seconds in which it stops — the path
every restart, every `docker compose down`, every maintenance-agent upgrade and
every node reboot takes, on every node in the fleet, several times a week.

It is also the path with the sharpest asymmetry in this codebase. Culvert's
per-request sinks were deliberately made ASYNCHRONOUS by the performance work
recorded in §§ above — `internal/logsink` for the process log, `internal/reqlog`
for the JSONL request log, `internal/syslog` for the SIEM feed. Each of those
packages documents the same residual in its own header: *an abrupt process
death can lose the in-flight batch*. Each also names the mitigation — the
orderly shutdown path flushes. So the correctness of three durability contracts
was delegated, by design, to the shutdown sequence completing.

The sequence had no bound of its own.

### 24.2 The shape of the miss

`runShutdownSequence` (main_shutdown.go) ran two registries: an EARLY phase
under `context.Background()` and a LATE phase under a 30s `context.WithTimeout`.
The split is deliberate and its rationale is sound — the early hooks pre-dated
the budget and stopping HA before gRPC before the lifecycle context is the
correct order. What was missing is that neither phase was actually bounded.

**The early phase was documented as unbounded.** The wiring test said so
explicitly, in a test named
`TestRunShutdownSequence_EarlyCtxHasNoDeadline_LateCtxDoes`, whose comment
records it as *"the test the user explicitly asked for"*. A defect can be
pinned by a passing test as easily as a fix can.

**The late phase's ctx was ADVISORY.** `shutdownRegistry.RunAll` looped over
hooks calling `h.stop(ctx)` synchronously and never consulted `ctx` itself, and
most of the hooks cannot consult it either — `syslog.Close`, `communityDB.Close`,
`logstore.Close`, `reqlog.Close`, `audit.Close` and `logCloser.Close` take no
context at all, and `drainActiveTunnels` took one and ignored it, running its
own 15s timer that its comment describes as *"independent of the parent ctx"*.

So the "30s budget" bounded exactly the four hooks that happened to observe it,
and the two numbers an operator would reach for both described something that
did not exist. `docker-compose.yml`'s `stop_grace_period` comment says the
proxy needs time for *"up to a 15s tunnel-drain window inside the ~30s
late-phase budget"*. The drain was not inside it. Nothing was.

### 24.3 SD-1 — the unbounded hook, and where it actually is

The early phase's second hook is `StopControlPlaneGRPC` → `srv.GracefulStop()`.

The first hypothesis was the obvious one: a half-open DP connection (host
power-lost, path blackholed) never acks the GOAWAY ping, so the transport is
never removed and `GracefulStop` waits out the kernel's TCP retransmit budget.
**That hypothesis was wrong, and measuring it is what found the real one.** A
probe against grpc-go v1.83.1 — a raw socket that speaks the HTTP/2 client
preface and then goes silent — returned in **6.005s**, because
`outgoingGoAwayHandler` arms a 5s timer on the ping ack and then sends the
second GOAWAY regardless.

Reading that function for the constant showed what it does next:

```go
if len(t.activeStreams) == 0 {
    retErr = errors.New("second GOAWAY written and no active streams left to process")
}
```

The transport is closed only when there are **no active streams**. With a live
stream the connection is left open and *no timer is armed at all* — and
`GracefulStop` blocks in `for len(s.conns) != 0 { s.cv.Wait() }` until it goes.

So the unbounded case is not the dead peer. It is the **stream that never
finishes**, and Culvert has two ordinary routes to one, neither of which
surfaces an error that would abort it:

- **A handler that does not return.** `Enroll` and `RenewCert` sign a CSR and
  persist it; `PushAuditEvents` appends to a `fileutil.RotatingFile`. On a
  wedged volume — the hung-NFS and slow-filesystem faults the storage work in
  §12/§13 is built around — the handler blocks inside `write(2)`.
- **A response the peer stops reading.** `GetConfig` returns up to a 128 MiB
  `ConfigSnapshot`. A DP that freezes mid-read leaves the CP blocked on HTTP/2
  flow control over a TCP zero window, and the kernel's persist timer retries
  that *indefinitely* rather than ever erroring out.

One wedged DP therefore held the Control Plane's SIGTERM open with no bound,
in the phase explicitly documented as having none.

### 24.4 What the stall actually costs

The compose file's 60s `stop_grace_period` then expires and Docker sends
SIGKILL. Everything after the stalled hook is skipped:

| Skipped | Consequence |
|---|---|
| `cluster-store-flush` | `LastSeen`/`Status` since the last 10th heartbeat lost (CL-2's whole purpose) |
| `request-log-close` | The queued tail of the durable request log — the compliance record — is dropped |
| `community-db-close` | An unclean badger close, i.e. exactly the torn `MANIFEST` that CHAOS-50 (§19) had to build a boot-path quarantine for |
| `log-closer` | The in-flight log batch — **including every line explaining why shutdown stalled** |

The last row is what makes this a *silent* failure rather than a loud one. The
async sink was the right performance decision and its residual was correctly
documented; the consequence nobody drew is that when the flush is the thing
that fails, the evidence is destroyed by the same event. An operator sees a
container that took 60s to stop and a log that ends mid-sentence.

And §19 closes the loop the wrong way round: the recovery path CHAOS-50 built
for a damaged category store is reachable *from Culvert's own shutdown*, not
just from `docker kill`. A hung shutdown manufactures the corruption the
previous sweep had to learn to survive.

### 24.5 The three that came with it

**SD-2 — the late budget was additive, not enclosing.** Worst case was 30s
(a `proxySrv.Shutdown` riding its ctx to expiry) **plus** the drain's
independent 15s **plus** the closers, against a documented envelope of 30s.

**SD-3 — a second signal did nothing.** `signal.Notify` takes SIGINT/SIGTERM
away from the Go runtime's default terminate behaviour, and after `<-quit`
nothing read the channel again. An impatient operator's second Ctrl-C, or an
orchestrator escalating, landed in a 1-deep buffer and was never observed. The
only escalation left was SIGKILL — precisely the outcome an escalation exists
to avoid, and the one that costs the durable flushes.

**SD-4 — a hook panic killed the sequence.** `RunAll`'s contract says *"All
hooks run even if one returns an error"*, which was only ever true for
*errors*. A panic (badger's `Close` can panic — §19 documents that its `Open`
panics from a goroutine the caller cannot recover) unwound the loop and took
the process down mid-shutdown, before the flushes and before the log flush that
would have named it.

### 24.6 What shipped

A **three-phase reserve model**, because the hooks fall into two classes with
opposite failure costs and one budget cannot serve both:

- **DRAIN hooks** (stop accepting, let in-flight work finish) are best-effort;
  abandoning one costs a client retry.
- **FLUSH hooks** (durable closes) are what make the next boot clean;
  abandoning one costs durability or a store the next boot must quarantine.

`shutdownFlushBoundary` (105) splits the late registry via
`shutdownRegistry.partitionAt`, and the flush reserve is carved out **up
front** and measured from the start of the flush phase — so a drain that
overran its own share still cannot spend it.

1. **Every phase carries a real deadline.** Early 12s, drain the remainder,
   flush 10s reserved, inside a 45s Total.
2. **Every hook runs under a watchdog** bounded by its phase deadline plus one
   shared `shutdownHookGrace` (3s) — a per-PHASE overrun, not a per-hook one,
   so the envelope is `Total + 2×grace` = **51s**, inside the 60s compose
   grace. A hook past it is abandoned and **named in a log line emitted at the
   point of abandonment**, not from the aggregated error at the end of the
   phase — the last flush hook closes the log sink, so a phase-end line on the
   flush phase would be enqueued into a channel nobody drains.
3. **Panics are contained.** This lands the same way as CHAOS-55's recovery
   loop and the opposite way from CHAOS-24's HA keepalive, for the reason
   recorded there: containment is dangerous when it would extend authority the
   node is no longer confirming, and a shutdown hook holds none.
4. **`StopControlPlaneGRPC` is bounded** — `GracefulStop` on its own goroutine
   under `cpGRPCGracefulStopBudget` (8s, sized above the measured 6.0s idle
   drain so a merely-unresponsive fleet still completes gracefully), then a
   force-close issued on ANOTHER goroutine (see below — a synchronous one
   deadlocks). Force-closing is safe by construction: an interrupted unary RPC
   is retried by the caller's own sync loop, the same path a mid-flight CP
   restart already exercises.
5. **The tunnel drain honours its phase deadline**, clamping its 15s ceiling to
   whatever the drain phase has left and reaching the SAME force-close backstop
   on either bound — so the compose comment now describes something enforced.
6. **A second SIGTERM/SIGINT exits immediately**, flushing the log sink first,
   with status **1** so an orchestrator cannot read a forced teardown as a
   clean stop.

**The fix's own defect, TWICE, caught by its own gate both times.** grpc-go's
`stop(graceful bool)` — the shared body behind `Stop` and `GracefulStop` — is
hostile to being raced, in two distinct ways, and the obvious wrapper walks
into both.

*Draft one* joined the abandoned `GracefulStop` goroutine after `Stop()`, on the
reasoning that closing every connection must unblock it. It does not:
`stop(graceful=true)` finishes with `s.handlersWG.Wait()`, so it does not return
until every HANDLER has returned — and the handler that has not returned is
exactly the fault being escaped. The join reintroduced the unbounded wait one
level down, and the gate failed on it immediately.

*Draft two* dropped the join but still called `srv.Stop()` SYNCHRONOUSLY. That
`handlersWG.Wait()` runs while **holding `s.mu`** — `stop` takes the lock with
`defer s.mu.Unlock()` before the conns wait, and `s.cv.Wait()` releases it only
for the duration of the wait. So when the last connection is removed both stops
wake and contend for the mutex: if the GRACEFUL one wins, it takes `s.mu`, parks
forever in `handlersWG.Wait()`, and the synchronous `Stop()` blocks on that
mutex with no bound — the original fault, reconstructed inside its own fix. Which
one wins is pure timing. **It passed every targeted run and the full suite, and
failed only under `-race`**, where the instrumentation shifted the race. The
force-close is now issued on its own goroutine and the function returns.

Two things follow. First, the gate's tolerance is part of the gate: a generous
"returns eventually" bound would have made draft two a FLAKE rather than a
failure, and a flaky gate gets muted. It now requires the return to land close
to the budget. Second, this is the argument that the hook-level watchdog and the
gRPC-level bound are not redundant — the watchdog is the only HARD bound on this
hook. `gracefulStopBounded` guarantees the sequence keeps moving; the watchdog
guarantees the phase does. What the bounded stop actually promises is narrower
than "the server is stopped", and §24.6's wording says so: the LISTENERS are
closed (grpc-go closes them before the conns wait, so GracefulStop shut the door
before it parked) and the transport force-close is best-effort and asynchronous.

### 24.6b Review follow-ups — two defects in the fix, raised by Codex

**P1 — the reserve was not recursive, and the wrong rationale was written down.**
The first shipped shape gave the WHOLE PHASE one watchdog deadline, and the
rationale recorded for it was: *a stalled hook is abandoned, and the flush hooks
are safe because they have their own reserved phase.* That is wrong, and it is
wrong in exactly the way this section is about. The flush reserve protects the
flush hooks from a stuck DRAIN. It does nothing to protect them from EACH OTHER.
With one deadline per phase, `syslog-close` or `community-db-close` stalling on
a wedged volume — precisely the fault the reserve exists for — burned the entire
reserve plus the grace, and `request-log-close`, `audit-log-close` and
`log-closer` were each started and then abandoned against a deadline already in
the past. Those three are the durable compliance record, the audit FD, and the
log flush holding the evidence: SD-2b reproduced one level down, inside the fix
for SD-2b.

The reserve principle is therefore applied recursively (`hookBudget`): a phase
reserves for its flush hooks, and within a phase each hook may take what is left
MINUS `shutdownHookMinSlice` for every hook still behind it. Nothing is taken
from the healthy case — a hook that returns quickly hands its unused share
straight to the next, so a legitimately slow close still gets almost the whole
phase when its neighbours are fast (pinned as a control by
`EveryHookGetsItsMinimumSlice`). The hook now also RECEIVES the deadline the
watchdog enforces, so a ctx-aware hook winds down instead of being abandoned.

The gate for it needed a second pass too, and for a reason worth recording: an
ABANDONED hook keeps running after the sequence returns, so a gate that asserted
on a slice the hooks appended to was both racy and a FALSE PASS — the abandoned
closers appended late and the assertion saw them. The property is *what completed
BEFORE the sequence returned*, so the gate collects completions on a buffered
channel and reads it immediately after. Against the pre-fix shape it now reports
`closers that completed before shutdown returned = []`.

**P2 — a completed shutdown could report as a forced one.** The escalation
watcher selected on `done` and `quit`. Go picks UNIFORMLY among ready cases, so
when a second signal was pending at the instant `stopEscalation` ran, the watcher
took the signal branch half the time and exited 1 on a shutdown that had
COMPLETED — the opposite of the escalation's purpose, on the exit status an
orchestrator reads. The decision is now re-checked (`shouldEscalate`).

Both findings share the shape of the two `gracefulStopBounded` drafts above: a
race whose losing side is invisible at speed. Neither was reachable by any
existing gate. And the P2 gate is deliberately NOT a scheduler race — the tie
cannot be scheduled from a test, so a gate for it could only be probabilistic,
which this repo mutes (CHAOS-54's rejected scaling gates). Splitting the decision
into its own function makes it pin deterministically instead.

### 24.7 Gates

`shutdown_chaos_test.go`, 17 tests. Every defect gate was verified failing
against its pre-fix shape by reintroducing that shape in the current tree:

| Gate | Pre-fix result |
|---|---|
| `EarlyPhaseHookCannotStallTheSequence` | sequence never returned |
| `StuckDrainCannotSpendTheFlushReserve` | both flush hooks abandoned at 0s |
| `TunnelDrainHonoursThePhaseDeadline` | drain took 15.0007s against a 150ms deadline |
| `HookPanicDoesNotAbortTheSequence` | process panicked out of the test |

`BareGracefulStopIsUnboundedOnAWedgedStream` is the **defect proof** for SD-1
and runs permanently: it asserts that the unpatched call does NOT return within
8s (well past grpc-go's only bound), so if a future grpc-go bounds the
active-stream case, the gate says so rather than letting the bounded wrapper's
test quietly prove less than it claims.

Three CONTROLS keep the gates honest — a watchdog that abandoned everything, or
a drain clamped to nothing, would pass the defect gates while being far worse
than the defect: `HealthyHooksAreNotAbandonedEarly`,
`TunnelDrainStillWaitsWhenItHasBudget`, `GracefulStopReturnsPromptlyWhenIdle`.

`EnvelopeFitsTheContainerStopGrace` is a **cross-artifact** gate: it parses
`stop_grace_period` out of `docker-compose.yml` and requires the worst-case
envelope to fit inside it. The two numbers live in different files in different
languages, which is exactly how they drift.

`TestRunShutdownSequence_EarlyCtxHasNoDeadline_LateCtxDoes` was **inverted**
into `TestRunShutdownSequence_EveryPhaseCarriesADeadline`. It had been pinning
the defect. The budget-SCOPING property it genuinely protected — that the early
phase does not share the late phase's clock — is preserved and still asserted.

### 24.8 What is deliberately left

- **SD-5 — no unclean-shutdown breadcrumb.** A marker file written at boot and
  removed on a clean stop would let the NEXT boot report that the previous one
  was killed. That is the one signal a SIGKILL cannot destroy, and everything
  else here is invisible after the fact. Not shipped: it adds a boot-path write
  with its own failure modes (read-only volume, full disk) to a change whose
  whole point is bounding, and it deserves the same care CHAOS-50's flock-owned
  poison marker got. Recorded for an owner.
- **No shutdown metrics.** `/metrics` is scraped on an interval and a process
  that is exiting will not be scraped again, so a `culvert_shutdown_*` series
  would describe a shutdown nobody can read. The log line is the record — which
  is only true because the envelope now guarantees the flush.
- **`HAState.Stop()`'s `wg.Wait()` is still an unbounded join**, now covered by
  the early phase's watchdog rather than by its own bound. The loops it joins
  already plumb interruption (`standbyLoop` ties a derived ctx to `stopCh`
  specifically so `Stop` "must not wait out a dial"), so an inner bound would
  be belt-and-braces. Recorded, not fixed.
- **The two durable flushes at orders 55 and 67** (cluster store,
  policy-learning) sit in the DRAIN partition, not the flush reserve. Moving
  them would change a documented ordering constraint (CL-2 requires the cluster
  flush after the gRPC stop and the heartbeat monitor). They run FIRST in the
  drain phase, before any hook that can meaningfully block, and the watchdog
  means an earlier hook cannot starve them. Accepted.
- **In-flight tunnels are cut, not migrated.** Draining a node before a restart
  remains the operator's job.

### 24.9 The process lesson

§21 stated it for back ends, §22 for listeners, §23 for decisions. This sweep
adds one about **documented residuals**:

> When a component documents a residual risk and names the mechanism that
> mitigates it, that mechanism has silently acquired a correctness requirement
> it was never designed to meet. Three packages here independently concluded
> "an abrupt death can lose the in-flight batch — the orderly path flushes."
> Each was right in isolation. None of them checked whether the orderly path
> was guaranteed to reach the flush, and it was not: it was bounded only by the
> container's patience, and the fault that exhausts that patience is the same
> class of fault — a wedged volume — that makes the flush matter.

There is a second, smaller lesson in how SD-1 was found. The plausible
mechanism (half-open TCP, ~15-minute retransmit budget) was written into the
first draft of the fix as its rationale, and it was wrong — the idle case is
bounded at 6s. Measuring it, rather than shipping the plausible story, is what
surfaced the active-stream case, which is both unbounded and reachable by
faults this codebase already has runbooks for.

---

## 25. CHAOS-58 — The public admin-login endpoint's untrusted username

**Date:** 2026-09-05 · **Domain:** authentication / audit / persistence ·
**Status:** shipped · **Closes:** AU-14, AU-15 ·
**Gates:** `login_input_bounds_test.go` (8) + `internal/lockout/lockout_keybound_test.go` (8) ·
**Runbook:** `docs/operator/admin-login-input-bounds.md`

### 25.1 Why this domain

Every sweep in this register so far has asked what happens when *infrastructure*
fails: a volume wedges, a listener returns EMFILE, etcd is slow to boot, a hook
does not return. This one asks a different question, and it is the question an
in-line appliance answers worst:

> What does an unauthenticated caller get to write, and how long does it live?

Culvert's admin plane has exactly three routes on `uiAuthMiddleware`'s public
allowlist that accept a body: `/api/setup/complete`, `/api/auth/logout`, and
`/api/auth/login`. The first validates its username at 1–64 characters and keys
its rate limiter on a FIXED sentinel (`setupKey`). The proxy-side credential
path validated its own at `maxUsernameLen` (256) years ago
(`proxy_portal.go:145`). The admin login endpoint — the one an attacker
actually finds first, because it is what the UI posts to — validated nothing.

### 25.2 The shape of the miss

`apiAuthLogin` decoded `body.User` and, from that point on, treated it as an
identifier. It reached, in order:

1. `loginLimiter.Check(clientIP, body.User)` — a map probe;
2. on failure, `loginLimiter.RecordFailure(clientIP, body.User)` — which CREATES
   an entry in **both** tiers, keyed on `ip + "\x00" + user` and on `user`;
3. `auditEvent(r, "auth.login.fail", body.User, …)` — the 500-entry in-memory
   ring **and** the durable JSONL;
4. on a lockout trip, `fireAlert("auth_lockout", AlertPayload{Actor: body.User})`.

None of those four is wrong on its own. What made them a defect together is that
the only things in front of the handler are `securityMiddleware`'s **1 MiB body
cap** and the **60-mutating-POSTs-per-minute** per-IP API limiter, and the value
they admit is retained by every one of the four:

- the lockout entries cannot be swept before `lockout.Window` (10 min) elapses —
  `Cleanup` deliberately refuses to remove an entry inside its accumulating
  window, because a future `RecordFailure` would reset it anyway;
- the audit JSONL is a `fileutil.RotatingFile(path, 50)` keeping **one** archive
  (`rotating.go` removes the previous `.1` before renaming), so the entire
  retained compliance record is 100 MB.

So one unauthenticated client, from one IP, inside the endpoint's own published
rate limit, commits **~60 MiB/minute** of bytes it chooses into a 100 MB durable
record and parks on the order of a **gigabyte** of heap for ten minutes at a
time. The gate measures the first half directly: **4,195,672 bytes reached the
audit file from eight requests.**

### 25.3 Why this is a security finding, not a capacity one

`internal/audit`'s own header already names this outcome as the thing its
write-error counter exists to make visible:

> *"An attacker who can fill the volume could therefore switch off durable audit
> logging and then act with the record surviving only in a 500-entry buffer they
> can evict by generating further events (CWE-778, OWASP A09:2021)."*

That analysis is correct and the counter is the right instrument — for the fault
it was written for. It does not fire here, and the reason is the interesting
part: **every one of these writes SUCCEEDS.** There is no full disk, no EIO, no
read-only remount. `writeErrors` stays zero, `storage_write_failed` never
dispatches, the `audit_log_persistence` contract row stays green, and the
durable record is destroyed anyway — by ordinary, successful, in-budget
appends. The health plane was watching the volume; the loss came through the
front door.

The consequence is evidence destruction that an attacker can perform **before**
the activity they want unrecorded: two minutes of oversize login POSTs rotate
away every prior admin action, and sustaining them keeps the window rolling.

### 25.4 The fix, and the two places it lives

**At the entry point (`login_input_bounds.go` → `apiAuthLogin`).**
`rejectOversizeLoginUser` refuses a username longer than `maxUsernameLen` (256 —
the constant the proxy-auth path already uses for exactly this question) and
returns **before** the limiter, the credential check and the alert. A rejected
attempt therefore creates no limiter entry and leaves no attacker-sized bytes
anywhere. 400 rather than 401 is deliberate: the length of a submitted username
is not a secret and is not a credential oracle, since no local account can carry
a name this long (both `apiSetupComplete` and the user-creation API cap at 64).

**In the leaf (`internal/lockout`).** `Cleanup`'s doc claimed the maps were
bounded against an unbounded-memory DoS; on the entry-count axis they were, and
on the key-size axis they were not. `boundUsername` clamps to
`MaxUsernameKeyLen` at **every** public entry point. The clamp is worth less
than the handler bound and is not a substitute for it — it is what stops a
future caller from reintroducing the exposure by forgetting.

Applying it at *every* entry point is the load-bearing detail. A clamp on
`RecordFailure` alone would have passed a byte-size assertion while splitting one
attacker's failures across two counters — a fix that shrinks the maps and
quietly weakens the lock. `TestOversizeUsername_CheckAndRecordAgree` is the
control for exactly that, and `TestBoundedNames_BehaviourUnchanged` is the
control that the clamp cannot be the reason an ordinary lockout stops working.

**The attempt is still audited.** `auth.login.rejected` is written with a
truncated, self-describing actor (`…[truncated, N bytes]`) and the observed
length in the detail. Bounding the bytes must not delete the evidence that the
admin plane is being probed — and the entry is O(1), at the same rate the
ordinary `auth.login.fail` entry would have been written, so it adds no ring
eviction capacity that the endpoint did not already have.

**The rejection is on a metrics surface.** `culvert_login_oversize_rejected_total`
is the operator's only signal: the caller gets a 400 and nothing else in the
process changes. The log line is rate-limited to one per minute (onset
immediately, magnitude in the counter) for the reason §22 gives — a mitigation
for a write-amplification defect must not be one itself.

### 25.5 Deliberately not done

- **No byte cap inside `internal/audit`.** The obvious "make the sink
  structurally safe" move is wrong here: the sink cannot distinguish attacker
  bytes from a legitimate `auditEventDiff` before/after payload, and whole
  policy objects are marshalled into those fields on purpose. A cap there would
  destroy real compliance evidence to fix an input-validation defect. The bound
  belongs where the untrusted value enters.
- **No hard entry-count cap on the lockout maps.** Evicting at a cap would
  evict a REAL lock, which is a security trade-off, not housekeeping. The count
  axis stays bounded by the janitor plus the per-IP API limiter; the residual is
  recorded below rather than traded away silently.
- **No new lockout tier for oversize input.** An oversize name can never match a
  local account, so this is not a credential-guessing channel a lock would have
  to close, and the 60/min limiter already bounds the attempt rate.

### 25.6 Residual risk

- **AU-16 (count axis, open).** The lockout maps are still bounded only by
  (attempt rate × `Window`). A distributed source with many IPs, each inside its
  own 60/min budget, still grows both maps linearly — now at ≤ 256 bytes per
  key instead of ≤ 1 MiB, so the exposure is reduced by ~4000× but not
  eliminated. Capping it correctly means deciding which real lock to evict; that
  is an owner decision.
- **Ring eviction is unchanged and remains accepted.** 500 ordinary failed
  logins still roll the in-memory audit ring. That is pre-existing, is what the
  durable JSONL exists to survive, and is now actually survivable because the
  JSONL can no longer be rotated away from the same endpoint.
- **The 300 ms anti-brute-force sleep still holds a request goroutine** per
  failed attempt. Bounded by the same 60/min limiter; not touched here.

### 25.7 The process lesson

§21 stated it for back ends, §22 for listeners, §23 for decisions, §24 for
documented residuals. This sweep adds one about **health planes**:

> A health signal watches a mechanism, not an outcome. `internal/audit` counts
> writes that FAIL, because the analysis that produced it modelled the loss as a
> failing volume. The same outcome — the compliance record destroyed, remotely,
> by an unauthenticated caller — arrives through writes that all succeed, and
> every instrument stays green. When a component names the outcome it is
> protecting against, check whether the instrument it built can see that outcome
> arrive by any other road.
