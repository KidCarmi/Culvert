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
>
> **The request-history sweep (§31) collided FOUR TIMES and renumbered itself
> every time, while still unmerged.** It first took `CHAOS-57` alongside the
> hijacked-tunnel sweep (§25); §25 merged first, so it kept the id and this one
> moved to `CHAOS-59` (`CHAOS-58` having gone to §26). Within the same day the
> intelligence-feed sweep (§27) landed on `CHAOS-59` too, so it moved to
> `CHAOS-60` — the next day the GeoIP sweep (§28) merged holding `CHAOS-60`, so
> it moved to `CHAOS-61` — the day after that the cluster rate-limit sweep
> (§30) merged holding `CHAOS-61`, so it moved to `CHAOS-62` — and within the
> hour the request-history sweep (§31) merged holding `CHAOS-62`, so it moved
> once more, to **`CHAOS-63`**. That last one is the sharpest instance: this
> sweep's move ONTO `CHAOS-62` and §31's were made independently, minutes
> apart, from the same merged tree — which is exactly why "take the next free
> id" cannot be the tie-break (see the §32 revision-log entry).
> Counting the other sweeps' own collisions (the intelligence-feed sweep's two,
> and §30's, whose revision-log entry records that it was itself numbered "at
> the THIRD attempt" after running as `CHAOS-57` and then `CHAOS-60`), that is
> **at least ten occurrences across six sweeps in about seventy-six hours**.
> The pattern is not bad luck, it is the default, and it is getting more
> frequent as more sweeps run concurrently.
>
> **An id that has to be rewritten four times is itself the evidence.** Each
> renumber was individually cheap and correct, and the sequence is still pure
> waste: every one of them touched ~15 files, invalidated the PR description's
> gate names, and bought nothing a committed placeholder row would not have
> bought for free on day one. Do not read the convention below as a solution —
> it is the bandage. The fix is allocation.
>
> **Two sweeps have now independently converged on the same fix while colliding
> with each other**, which is the strongest argument available that the
> convention is not enough: §30's own entry reaches the identical conclusion
> from the other side of the same collision. The next sweep to open should
> claim its id in a committed placeholder row in this file as its FIRST commit,
> before any code is written — that is the whole remedy, and it costs one line.
>
> Both sweeps independently arrived at the same rule, which is the one to
> follow until the durable fix exists: **an id is rewritable for free right up
> until its first merge, and needs owner sign-off the moment after — so the
> sweep that is still an open PR renumbers ITSELF, and does not leave the
> collision for a later owner decision.** That is the whole difference between
> these cases and the `CHAOS-50` one above, where all three had already merged.
>
> Three further cautions this episode produced, all learned the expensive way.
> **A merge-conflict resolver is not a substitute for allocating the id**: the
> automatic main-merges renumbered the SECTION heading each time and left the
> `CHAOS-` id colliding, so the document silently ended up with two §-numbers
> claiming one id. **"Keep both sides" is wrong for a line that is a LIST, not
> an entry**: one of these merges resolved `CLAUDE.md`'s `internal/` package
> inventory — a single line naming every package — by keeping both versions,
> leaving the file with two contradictory inventories (`66 packages` and `67
> packages`) that no test reads and no build rejects. It survived two further
> merges, and the later reader (this sweep) then "fixed" the stale half by
> editing the OTHER line, which looked right and left the contradiction intact.
> A conflict in an enumerating line needs the two sides UNIONED, never stacked.
> And **the only reason any of this was caught is that all four sweeps happened
> to edit THIS file** — sweeps touching disjoint code merge cleanly and collide
> in silence. The durable fix is still the one recorded above (allocate the id
> in a committed placeholder row at the START of a sweep), and at six
> occurrences it is well past overdue.

**2026-09-12 — CHAOS-66 sweep (the SOCKS5 listener's BIND). Id claimed in this
row before the implementation commit**, per the convention above; `CHAOS-66` was
free (65 was the highest merged) and did not move. The sweep closes the row §33
left open in as many words: *"`startSOCKS5`'s BIND failure is still fatal — an
occupied SOCKS5 port takes down HTTP proxying."* It does, and worse than the
sentence suggests — `initSOCKS5` runs BEFORE `startAdminUI` and
`buildAndStartProxyServer`, so an OPTIONAL, off-by-default listener that cannot
get its port kills the PRIMARY data plane, the management plane and the health
endpoints before any of them exist. Reproduced against the real binary: exit 1,
`proxy http_code=000`, zero admin-UI log lines; under `restart: unless-stopped`
an unattended crash loop recoverable only with shell access. The triggers are
routine (a draining predecessor holding the port, a privileged port after
`CAP_NET_BIND_SERVICE` was dropped, an interface not yet up) and none is visible
to `validatePortCollisions`, which compares Culvert's own three ports to each
other only. Fixed by a supervisor owning bind → serve → rebind, borrowing
CHAOS-54/55/57's mechanism wholesale rather than inventing a second dialect;
`socks5Server` is byte-identical, so §22's 18 accept-loop gates are untouched.
Two consequences worth the reader's attention: an observed bind now CLEARS the
accept plane's `down` (§22 recorded it as terminal, correct only while nothing
re-opened the socket) and the `down` row stopped telling operators to restart
the node, which after this change would cost a production outage to achieve what
happens on its own. A second, smaller finding rode along: `network_error` in
`classifyAdminUIListenError` was unreachable-by-accident in the other direction
— `*net.OpError` satisfies `net.Error` unconditionally, so every unrecognised
errno was reported as a network fault and `listen_failed` could only be reached
by an error the net package had NOT produced; the shipped gate passed exactly
that one shape. Both classifiers now require `Timeout()`. See §36 and
`docs/operator/socks5-listener-health.md`.

**2026-09-11 — CHAOS-65 sweep (the OCSP revocation path). FIRST SWEEP TO CLAIM
ITS ID BEFORE WRITING CODE.** The id was committed as a placeholder row in this
file as commit one, which is the remedy the header above reaches twice
independently after ten collisions. It cost one line and the id never moved.
The finding: every input this engine acts on is written by **the party being
checked** — the responder URLs come out of the peer's own AIA extension, so the
peer picks which responder is asked, how many, and therefore what comes back —
and nothing in the pipeline treated that as hostile. Seven defects, six closed.
The sharpest is a **complete revocation bypass performed by the certificate's
own subject**: `ParseResponse` with a nil certificate takes `Responses[0]` and
never compares the serial, so a genuine CA-signed `good` about any other
certificate of the same issuer — obtained by asking that CA about any live cert
and keeping the bytes — was accepted as this one's verdict, and a revoked
certificate went through. Alongside it: no freshness check at all on a protocol
that carries no nonce over plaintext HTTP (replay), `unknown` treated as a pass
while *unreachable* failed closed, a verdict cache keyed on the serial alone
(cross-issuer confusion, both directions), the peer-controlled responder URL
reached with `http.DefaultClient` and no guard (SSRF, redirects followed), and
an unbounded responder walk under a **per-responder** timeout that let one
certificate park a request goroutine for ~17 minutes while aiming 200 outbound
POSTs wherever it named. The seventh is the reason the other six survived
unnoticed: the control is wired only to the shared upstream transport, so on a
Secure Web Gateway it runs on the `https://`-parent-proxy handshake and never
on inspected HTTPS — enabled, logged, panelled, and consulted by almost
nothing. That one is **reported, not wired**: closing it fail-closed would make
every inspected HTTPS request depend on outbound port 80 to arbitrary responder
hosts, a fleet-wide outage one checkbox away. Governance note: row **CA-6**
recorded the SSRF caveat in July and scored the row **✓ (+2 caveats), L/M** —
the evidence column named the property that makes all seven reachable, and the
verdict looked past it. Re-scored **H** and split. See §35, rows CA-6/CA-6b and
OCSP-1…OCSP-10, and `docs/operator/ocsp-revocation-checking.md`.

**2026-09-02 — CHAOS-58 sweep (the directory that accepts and then stops answering).**
CHAOS-47 solved the *unreachable* directory: fail closed, arm a provider-wide cooldown, deny
without dialing, recover on evidence. This sweep asked which faults can actually ARM that
machinery, and the answer is the finding: **the cooldown is armed by an error that RETURNS**, so
every mitigation it built sits downstream of a value a hung call never produces. `LDAPAuth.verify`
dialed with a 10 s dialer timeout and then ran up to four blocking operations with no deadline of
any kind — go-ldap defaults to `requestTimeout: 0`, which arms no timer at all, so `Bind` and
`Search` wait on a bare channel receive. A directory that completes the TCP handshake and then goes
silent (overloaded server, firewall dropping established flows, half-open socket after a peer
reboot, hung VM) blocked the **request goroutine forever** — no error, no counter, no log, no health
movement — pinning a goroutine, a socket, an FD and a per-IP connection slot per authenticating
request, permanently. FD exhaustion is the recorded terminal state of PX-6/WK-11 and the entry point
to CHAOS-54's SOCKS5 findings, so the fault feeds an amplifier this register already documents. The
asymmetry that hid it: the ADMIN directory-test endpoint already called `conn.SetTimeout`; the
per-request production path did not — the bounded path is the one clicked occasionally, the
unbounded one is the one every request takes. Shipped: ONE 10 s end-to-end envelope, deliberately
the same budget this process already gives one OIDC introspection (the CHAOS-53 "both back ends
share one budget" rule, applied to the credential back ends), enforced in two NON-redundant layers —
a per-message timeout, plus a connection watchdog for the post-StartTLS `tls.Handshake()` that
go-ldap runs on the raw socket outside its own timer, verified against the library and kept as a
permanent defect proof. No new metric, no new alert, no new operator vocabulary: a stall now
produces exactly what a down directory produces. 9 gates; all six defect gates verified failing
against the pre-fix tree. See rows AU-5 (re-scored M→H) and AU-14, §25, and
`docs/operator/ldap-directory-stalls.md`.
**2026-09-03 — CHAOS-59 sweep (the intelligence-feed plane under origin outage).**
*(Numbered CHAOS-59/§27 on merge, at the SECOND attempt. This sweep ran concurrently with two
others and collided with both: it first took `CHAOS-57`/`§25` alongside the hijacked-tunnel sweep
(§25), renumbered to `CHAOS-58`/`§26`, and within hours collided AGAIN with the directory-stall
sweep (§26) that took the same id. That is the THIRD and FOURTH occurrences of the collision this
section's header warns about, both on one PR, in one afternoon. The pattern is now unambiguous:
concurrent sweeps in this repository collide by default, and the only reason either was caught is
that all three happened to edit THIS file — sweeps touching disjoint code merge cleanly and collide
silently. The second collision also shows the failure surviving its own remedy: the automatic
main-merge renumbered the SECTION (§26→§27) and left the `CHAOS-` id colliding, so a
merge-conflict resolver is not a substitute for allocating the id. Each time, the already-merged
sweep kept the id and this one moved — renumbering an id that merged PRs reference stays the owner
decision the header records. The header's own recommendation — allocate the id at the START of a
sweep in a committed placeholder row — would have prevented all four, and is now overdue rather
than advisable.)*
Culvert ships THREE periodic feed schedulers and only the newest one — the signed SaaS
feed's `saasFeedScheduler` — backs off, jitters, or reports. The two older loops
(`internal/threatfeed`, `internal/feedsync`) were bare `time.NewTicker`s with the round's
outcome discarded, and the consequences compound in three directions. **Cadence:** a ticker
has no notion of failure, so a failed round waited a FULL interval — six hours for threat
intel, twenty-four for categories — and the triggering fault is a DNS blip or a 503, not an
exotic one. **Cold start:** `Start` syncs immediately when the on-disk DB is empty, so a
fresh or re-imaged node whose FIRST round failed enforced with an EMPTY threat database — not
stale intelligence, none — for up to six hours, with every probe reporting a healthy node.
**Fleet:** a ticker fires at a fixed offset from process start, so nodes that boot together
sync together forever, against public third-party origins shared by every deployment (one of
them a 50+ MB tarball on `raw.githubusercontent.com`); the ordinary answer is rate-limiting
of the customer's egress IP, which PRODUCES the failure the absent backoff then holds the
fleet at. And none of it was visible: **the carry-forward that closed WK-5's stale-erase half
also consumed the only detector**, because it holds `culvert_threat_feed_entries` at its
last-good value by design — so a feed dead for three weeks exported metrics byte-identical to
one that synced ten minutes ago, and the sole surviving difference reached one role-gated
admin JSON field nothing scrapes. Shipped: `internal/feedsched` (one shared cadence engine —
bounded backoff whose ceiling is CLAMPED below the interval, stable per-node ±10% jitter,
interruptible waits, a panicking round charged as a failed one), both legacy loops migrated
onto it, and a staleness plane (five `culvert_threat_feed_*` series emitted only when
configured, a `threat_feed` contract row, a fire-once `threat_feed_stale` alert on a BOUNDED
reason class, recovery on observed evidence only). Deliberately NOT added: a `/readyz` row or
a fail-closed toggle — a stale deny-list is a fully serving gateway, and blocking traffic
because a third-party feed is unreachable converts a provider's outage into the customer's.
35 gates, the cadence ones failing against the bare-ticker shape by construction, with four
CONTROLS (an immediate retry, a ceiling above the interval, and an always-firing alert each
pass a defect gate while being worse than the defect). See rows WK-5/WK-5b/WK-5c/WK-6/WK-13b,
§27, and `docs/operator/threat-feed-freshness.md`.
> **⚠️ `CHAOS-57`, THEN `CHAOS-58`, THEN `CHAOS-59` were each CLAIMED TWICE by
> the same open PR — the renumber lost the race three times running, because
> "take the next free id" is a rule every concurrent sweep computes identically.**
> Two sweeps ran concurrently in September 2026 and each took 57:
> §25 (the hijacked-tunnel plane on the way out, merged via #1288) and the GeoIP
> resolution chain (PR #1339). The collision surfaced as a merge conflict in
> this file — both appended a `## 25. CHAOS-57` at the same position — which is
> the FOURTH occurrence of the governance failure recorded above, and the first
> one caught before both halves were merged.
>
> **That is exactly why it could be fixed rather than recorded.** The rule the
> `CHAOS-50` note states — renumbering is an owner decision once merged PRs
> reference the id — turns on whether the identifier has escaped. Here one had
> and one had not: §25 was merged and keeps `CHAOS-57`; the GeoIP sweep was
> still an open PR, so it took the next free id (`CHAOS-58`) and renumbered to
> §26, along with every source comment, `CLAUDE.md` note, operator runbook and
> register row that cited it. Nothing merged was rewritten.
>
> The asymmetry is the lesson, not the fix: the cheap moment to resolve a
> collision is while one side is still unmerged, and the only reason this one
> was noticed then is that both sweeps happened to append to the same file at
> the same offset. Two sweeps touching disjoint files would have collided
> silently and merged clean. The START-of-sweep placeholder row recommended
> above remains unimplemented and remains the actual prevention.

> **It then happened AGAIN, to the renumber itself, within hours.** The GeoIP
> sweep was moved to `CHAOS-58` on 2026-09-10; by the next merge of `main` that
> id was taken too — §26, the directory that accepts and then stops answering,
> merged via #1286 while this PR was still open. So the sweep moved a second
> time, to **`CHAOS-59` / §27**, by the identical rule: `main` holds the id, the
> open PR yields. That rule is stable and cheap to apply. **It is also not a
> fix, and the second collision is the proof.**
>
> The mechanism is a RACE, not a mistake, and renumbering runs the race again.
> An id is chosen when a sweep is written and validated only when it merges, so
> every sweep open across another sweep's merge is exposed, and an open PR that
> renumbers is exposed AGAIN for as long as it stays open — a PR that lives
> across N merges of sweep work can be renumbered N times, each time touching
> every source comment, gate name, register row and doc that cites it. The cost
> is not the edit; it is that the identifier in a merged commit message, a
> review thread, or someone's notes now names a different sweep.
>
> **And then a THIRD time — which finally shows WHY the rule cannot converge.**
> The GeoIP sweep took `CHAOS-59` / §27 on 2026-09-10; by the next merge of
> `main`, that id was taken too — §27, the intelligence-feed plane under origin
> outage. So the sweep moved a third time, to **`CHAOS-60` / §28**, same rule,
> same afternoon, third application.
>
> Read the intelligence-feed sweep's own revision-log entry above and the
> mechanism stops looking like bad luck: **it walked the identical path.** It
> took `CHAOS-57`, collided with the hijacked-tunnel sweep and moved to
> `CHAOS-58`, collided with the directory-stall sweep and moved to `CHAOS-59` —
> and landed on the number the GeoIP sweep had just moved to for exactly the
> same two reasons. Two sweeps, renumbering independently, in the same window,
> produced the same sequence and collided at every step of it.
>
> That is the part worth keeping. **"Take the next free id" is not a
> tie-breaker; it is a shared deterministic function of the same input.** Every
> concurrent sweep computes "next free" against the same `main`, so they all
> compute the SAME answer, and a collision does not disperse them — it moves
> them together. The remedy behaves like the fault, which is why applying it
> three times produced three collisions rather than converging. Nothing here
> was done wrong; the rule cannot succeed against a concurrent peer running it.
>
> All three collisions were caught only because every side appended a heading to
> THIS file at the same offset, so git surfaced them as a conflict. Nothing
> checks the id itself. Two sweeps whose write-ups land in different sections —
> or whose source comments collide but whose documents do not — merge clean and
> silently share an id, which is exactly how `CHAOS-50` came to name three
> sweeps.
>
> The placeholder row is still the prevention, and it now has a third piece of
> evidence behind it — the strongest, because it is the one that shows the
> current rule is not merely expensive but non-convergent: **allocate the id in
> a committed row on `main` BEFORE the sweep is written**, so the claim is
> visible to every concurrent sweep at the moment it picks a number, the
> allocation is serialised by `main` rather than recomputed independently by
> each PR, and a duplicate is a merge conflict on one line instead of a rename
> across a dozen files. A cheap approximation while that is unimplemented:
> prefer citing a sweep by SECTION and title, and treat the `CHAOS-nn` id as a
> label that may move until the sweep merges.

**2026-09-01 — CHAOS-57 sweep (the hijacked-tunnel plane on the way out).** CHAOS-56 bounded
the shutdown sequence end to end and made the drain honour its phase deadline. It did not ask the
prior question: **does the drain see what it is draining?** It does not. `drainActiveTunnels` waits
on ONE number, `activeConns`, and **four of Culvert's seven hijacked-tunnel classes never touched
it** — both non-TLS inspect fallbacks (strip and native), WebSocket, and SOCKS5. A hijacked conn is
invisible to `http.Server.Shutdown` by construction, and `socks5Server.Stop` waits only for the
ACCEPT LOOP while every session runs in a detached `go handleSOCKS5(conn)` — a deferral that file's
own header records ("In-flight SOCKS5 tunnels are NOT drained… tracked for Phase 2"). So for those
four classes nothing waited and nothing closed them: they ran until process exit and the kernel
reset them. **PX-8**, registered since the first sweep. Three consequences, all silent. (1) **One
fault, two postures** — a CONNECT tunnel gets 15 s of grace on SIGTERM; a WebSocket or an
SSH-over-SOCKS5 session on the same node at the same instant gets none, decided by which
`recordActiveConn` call site the code path happened to pass. (2) **The accounting for every severed
tunnel is lost** — `recordTunnelClose*` runs only after both relay goroutines drain, so every
graceful shutdown dropped the bytes and duration of every in-flight raw tunnel from the request log,
the JSONL export, the SIEM feed and the dashboard totals; across a rolling fleet upgrade that is
systematic, not incidental. (3) **The drain's own log line undercounts** — "Draining 0 active
tunnel(s)" on a node severing hundreds of sessions, and `activeConns` is the dashboard field an
operator sizes FD budgets from. **The finding inside the finding is why counting alone would have
been the WRONG fix**: long-lived is what WebSocket and SOCKS5 are FOR, so a drain that waits on them
with no way to END the wait hits its deadline on every shutdown, turning an instant restart into a
guaranteed 15 s one across a fleet — and severs them anyway. The wait only earns its cost if it ends
in a deterministic teardown, which is the argument PR3d already made for inspected H2. Shipped: a
per-class registry holding both legs of every hijacked tunnel, a drain-deadline force-close backstop
covering all five classes (so each relay's `io.Copy` returns and its accounting is written), a
bounded settle clamped to the phase budget that keeps that accounting ahead of the FLUSH hooks
instead of leaving the ordering to luck, and `culvert_tunnels_active{class}` +
`culvert_tunnel_drain_forced_total`. A **PX-4 residual** was found alongside and closed:
`relayPlaintextInspectFallback` was the ONE relay goroutine in the tree with no panic guard, so a
panic there killed an in-line security appliance and dropped every other in-flight tunnel with it.
15 gates; every defect gate verified failing against its reintroduced pre-fix shape, plus controls
for the two cheapest wrong fixes (force-close at drain START — which passes every defect gate while
being strictly worse than the defect — and a non-idempotent release, whose negative gauge restores
the original blindness by accident). See rows PX-4/PX-8, §25 and
`docs/operator/tunnel-drain-on-shutdown.md`.
**2026-09-07 — CHAOS-60 sweep (the GeoIP resolution chain under a failing resolver).**
This sweep started from a row in this document that said a path was SAFE. Row
WK-3 recorded that `geo.LookupCached` — the accessor the per-request policy path
uses for country-scoped rules — "never blocks on DB/DNS", marked ✓, citing
`geoip.go:84-93`. Those lines are now the body of a function that did not exist
when the row was written. **GEO-1**: the accessor called `resolveHost`, which on
a cache miss called `net.LookupHost` — no context, no deadline, no way to
abandon — inside the request goroutine, holding the client connection and its
per-IP slot for the system resolver's full budget (10–40 s on a blackholed
resolver). The same file already said so 380 lines earlier, in the comment
explaining why `Evaluate` releases its lock before the scan; two comments, one
saying the geo check cannot block and one explaining the locking discipline
required because it can. There was no single-flight either, and the negative
entry that suppresses the next lookup is only written when a lookup RETURNS — so
in exactly the window where lookups do not return, nothing suppresses the next
one, and the proxy amplifies client request rate 1:1 into queries at an
already-failing resolver (measured pre-fix: 50 concurrent misses for one host →
50 resolver invocations). **GEO-2**, found in the sweep and worse: after the
resolution, the country half is read from a cache that on the request path had
exactly ONE populator — `trackDestinationCountry`, a best-effort dashboard
sampler that runs on the ALLOW branch only and drops its work when its 256-slot
pool is full. Country-scoped policy ENFORCEMENT therefore depended on a
telemetry goroutine having won a semaphore slot on an earlier request; saturate
the sampler and every country rule silently stops matching, with the rule's hit
counter reading exactly like "no traffic matched this rule". Shipped: a
genuinely cache-only accessor that fails closed and arms a bounded (64,
drop-on-full), single-flighted, off-path warm; the warm fills BOTH caches, so
enforcement owns its own populator; and six `culvert_geo_*` series, of which
`culvert_geo_policy_unresolved_total` is the first signal an operator has ever
had that a geo rule is evaluating against an unknown country. The first-request
window is unchanged and recorded as an owner decision (WK-3c). See §28.
**2026-09-06 — CHAOS-57 sweep (credential verification as an unbounded, unauthenticated CPU sink).**
The register carried **AU-3** as an open Medium — *"correct-username + N wrong-passwords is a cache
miss every time"* — which described an attack requiring a valid username and categorised the
consequence as latency. Both halves understated it. **The cheap branch is the WRONG-username branch
and the consequence is a gateway-wide outage.** `verifyAuthWithSnapshot` ran an unconditional bcrypt
against a fixed dummy hash whenever the username did not match — RISK-008's timing equaliser, which
exists for a good reason — but it sat BEFORE the result cache and never populated it, so a flood of
distinct usernames was a guaranteed miss every time. No credential, no valid username, no knowledge
of the deployment. And nothing stood in front of it: the per-IP connection limiter, the request rate
limiter (`-rate-limit`, default 0) and the IP filter all ship DISABLED, and nothing capped
concurrency. Measured on the 4-core reference box: **79.6 ms of exclusive CPU per ~200-byte request
(51,631x a cached auth); 66 req/s — about 13 KB/s on the wire — consumed 100% of all four cores; other
CPU work degraded 15.6x under 64 attacker connections.** Two amplifiers sat beside it: the result
cache evicted **one arbitrary LIVE entry** at capacity, so a flood displaced honest users' cached
positives (measured: gone by a 2x-capacity flood, after which the victim paid a full bcrypt on every
request — the attacker's amplification landing on legitimate traffic, the `internal/authstate`
finding standing unchanged one subsystem over), and its expired-entry scan is O(cache) under the
process-wide mutex at 64 µs per insertion. **The finding inside the fix:** gating only the branch
that reaches the real hash — the obvious fix, and the one written first — makes "over budget" fast
for a wrong username and slow for a wrong password, handing back exactly the username-enumeration
oracle RISK-008 removed. The admission decision is therefore taken BEFORE the username is compared
and cannot depend on it; the gate that pins this was verified failing against that asymmetric shape.
Shipped: `internal/authcost` (global ceiling of GOMAXPROCS/2, per-client ceiling of 1, bounded wait
with a BOUNDED queue — an unbounded one would trade CPU exhaustion for goroutine exhaustion), the
`internal/authstate` fair-eviction policy ported to the result cache, and a full observability plane
(eight series, a `credential_verification` contract row, a rate-limited log pair, and a
fire-once-per-episode `auth_verify_saturated` alert with evidence-based recovery). Bounds are
CONSTANTS by design — a knob here could only widen a DoS window — with an order of magnitude of
headroom over real demand. 34 gates; eleven defect gates verified failing against the shape each replaces. A SECOND finding inside the fix, caught in self-review and fixed on the branch: moving the cache lookup ahead of the username comparison made a latent NON-INJECTIVE cache key (`user + ":" + pass`) reachable with a caller-chosen username — an AUTHENTICATION BYPASS whenever the configured password contains a colon. `cacheKey` is now length-framed. **AU-3e**, a
PRE-EXISTING username-enumeration oracle reached by repetition (wrong-username negatives are not
cached, correct-username ones are), is recorded and deliberately NOT fixed here: closing it changes a
security control's behaviour and deserves its own review. See rows AU-3/AU-3a/AU-3c/AU-3d/AU-3e, §25,
and `docs/operator/credential-verification-cost.md`.
**2026-09-08 — CHAOS-61 sweep (the Data Plane's outbound cluster state under a Control
Plane outage).**
*(Numbered CHAOS-61/§30 on merge, at the THIRD attempt. This sweep ran as `CHAOS-57`/§25 and
collided with the hijacked-tunnel sweep, which merged first and kept the id; an intervening
main-merge moved the SECTION to §27 and left the `CHAOS-` id colliding, so the tree carried TWO
different sweeps stamped `CHAOS-57` — two `## ` sections here and two Architecture Notes in
`CLAUDE.md`. Renumbered to `CHAOS-60`/§28 — and within a day collided AGAIN, with the GeoIP
resolution sweep that took `CHAOS-60` concurrently and merged first; that merge once more moved
the SECTION (§28→§29) and left the id colliding, so two sweeps shared `CHAOS-60` and, in the same
package, a `TestChaos60_` test-name prefix. Those are the FIFTH and SIXTH occurrences of the
collision this section's header warns about, the second and third time a section-only renumber let
the id survive its own remedy, and the second time it happened to THIS sweep specifically — a
renumber is not a fix, because the next free id is exactly what every other concurrent sweep is
also taking. Resolved both times by this section's established precedent: the already-merged sweep
keeps the id and this one moved. The header's standing recommendation — allocate the id at the
START of a sweep, in a committed placeholder row — would have prevented all six, and this sweep
having to move twice is the clearest evidence yet that renumbering-on-merge cannot converge. A
FOURTH main-merge then moved this section again, §29→§30, ahead of the credential-verification
sweep that landed at §29 — this time with no id collision at all, because the id was already
unique. That is the distinction the six collisions kept obscuring: a SECTION number is positional
and every concurrent merge can change it, so it is not a handle anything may cite, while the
`CHAOS-` id is stable the moment it is allocated. Cross-references should name the id; the three
`§29` references this sweep had to fix on that merge are what a positional handle costs.)*
Register row **HA-1** records the deliberate posture for a DP that loses its
Control Plane — it keeps serving its last-known-good CONFIG — and that posture was reasoned about
carefully. This sweep asked the adjacent question the row does not cover: what happens to the DP's
other outbound cluster state, the per-tick loops that are not config sync at all. The same posture
had been applied to data where it is not correct. **CL-20:** `clusterCounts.Apply` is reached from
exactly one place, the gossip loop's SUCCESS branch, so a failed `SyncRateLimits` left the Control
Plane's last per-IP broadcast FROZEN in memory and `AllowClusterAware` kept adding it to every
local count for the rest of the process lifetime. An IP whose cluster-wide total happened to be at
the limit when the CP went away — an ordinary NAT or corporate egress address, exactly the kind
that gets hot — was thereafter denied on that node with a local count of ZERO: a total blackhole
for that client, on a healthy proxy, cleared only by the CP returning or a restart, and
indistinguishable in the log from a client genuinely sending too fast. The fix is arithmetic
rather than posture — `RemoteCounts` means "the total in the CURRENT window", so past one window
every timestamp it counted has aged out and its correct contribution is zero — and **the Control
Plane had been applying that exact reasoning in the other direction all along**
(`ClusterTotalsExcluding` prunes a node that has not reported for two minutes, so a dead DP's
counts stop suppressing fleet traffic). The rule existed on one side of the link and not the
other, and the side that lacked it is the one that decides allow/deny on live traffic.
**CL-21:** the DP→CP audit push queue is correctly bounded at 1000 and correctly keeps the newest —
but dropped with no counter, no metric and no log line, three hundred lines below this same
package's documented contract for the durable path ("count EVERY failure, log only the FIRST"),
and because `Requeue` prepends the events that just failed to send, the first thing discarded is
the OLDEST unsent history: the beginning of whatever happened during the outage. Shipped: broadcast
expiry derived from the live limiter window (with a negative age — clock rollback — failing toward
the local decision, a disagreement between the enforcement and reporting paths that the sweep's own
gate caught inside the first version of the fix), a freshness health plane armed only on a
clustered node, counted audit-push drops, and 17 gates with every defect gate verified failing
against the pre-fix tree. No new alert event: a stale broadcast is always the CP link, which
already alerts. See rows CL-20/CL-21, §30 (CHAOS-61), and
`docs/operator/cluster-rate-limit-freshness.md`.
**2026-08-29 — CHAOS-62 sweep (the request-history store under a damaged data volume).**
§19.6 opened row **R-E** and marked it *"next sweep candidate"*: `internal/logstore` calls
`badger.Open` with the same uncatchable-panic exposure CHAOS-50 had just fixed for the category
store — a corrupt `.sst` panics from a goroutine badger spawns, so no `recover()` at any call site
contains it. Re-measured against THIS store's options (encryption on, 128 MiB value log) it
reproduces exactly. **Both clauses of the deferral inverted on re-derivation.** *"Quarantining it
silently is an evidence decision"* argues FOR the fix: the CHAOS-05/07 contract MOVES ASIDE, never
deletes, so the evidence survives either way — what the deferral preserved was a crash-looping
appliance whose history is equally unreadable and whose entire service is down as well. And
*"bounded by being opt-in"* is backwards: opt-in means DURABLE in `admin_settings.json`, so one
unclean kill becomes an **unattended crash loop** with no admin UI left to turn the setting back
off, and it means reachable from the **LIVE ADMIN API**, so the toggle kills a gateway carrying
production traffic rather than merely failing a boot. The clause meant to bound the severity was
the mechanism that raised it. **Two further defects.** **LS-3:** on a KEYED store badger reports a
changed passphrase, a lost salt and real KEYREGISTRY damage with the SAME error, and CHAOS-50's
classifier lists that message as corruption on the explicit rationale *"this store is never opened
with a key"* — so reusing it unmodified would have moved a HEALTHY store aside over an ordinary
config change. That is why the classifier is now a per-store `Policy` that can only ever SUBTRACT.
**LS-4:** `EncKey` minted and WROTE a fresh salt over an existing encrypted store whenever the
sidecar was unreadable — destroying, on the READ path, the only value that could decrypt it, and
leaving an error indistinguishable from a passphrase change so the operator's remedy became
"purge". The codebase had already adopted that exact rule elsewhere (SEC-WHSIGN-1, *"a failed
decrypt never mints a key"*); nothing was checking whether anywhere else did the same thing.
Shipped: `internal/storeguard` (the CHAOS-50 engine extracted verbatim — a second copy would have
duplicated the empirical badger message table that is pinned by a test precisely so an upgrade
which rewords a message fails the build), `catdb` reduced to a thin adapter with its 21 recovery gates
unchanged and green, `logstore.OpenResilientTTL`, the `EncKey` refusal, and a full health plane
(`request_history` row, three `culvert_logstore_*` series, the existing `state_file_corrupt`
alert). 37 new gates; every defect gate verified failing against the reintroduced pre-fix shape, plus
a permanent defect proof that the bare open still panics uncatchably. R-E CLOSED. See §25 and
`docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-29.md`.
**2026-09-05 — CHAOS-63 sweep (the public admin-login endpoint's untrusted username).**
*(Numbered CHAOS-63/§32 on merge, at the SIXTH attempt. This sweep took `CHAOS-58`/`§25`, collided
with the directory-stall sweep and moved to `CHAOS-59`/`§27`; collided with the intelligence-feed
sweep and moved to `CHAOS-60`/`§28`; collided with the GeoIP sweep — which was itself renumbering
for the third time in the same window — and moved to `CHAOS-61`/`§30`; collided AGAIN, with the
DP-outbound-cluster-state sweep, which had reached `CHAOS-61` at its OWN third attempt (see its
entry above), and moved to `CHAOS-62`/`§31`; collided a FIFTH time, with the request-history-store
sweep, which had taken `CHAOS-62` independently and merged minutes later, and moved here. Five
renumberings on ONE PR, spanning ~38 hours. Same rule each time, the one §27 records: the
already-merged sweep keeps the id, the unmerged one moves.
**What these rounds add to the §27 analysis is a boundary on the remedy, not more evidence of the
fault.** Round two already showed a renumbering cannot prevent the next collision. Round three
shows the stronger thing: BOTH sweeps in that collision were mid-renumbering, so the two remedies
raced each other — the GeoIP sweep moved onto `CHAOS-60` while this one was moving onto the same
id, and neither could have observed the other, because until a merge lands there is nothing to
observe. Renumbering is a reconciliation, and two reconciliations against an unallocated namespace
do not converge; they take turns. That is why the placeholder row §27 calls overdue is not an
improvement to the current practice but a replacement for it: allocation has to happen BEFORE the
work, in a committed artifact, or the only mechanism available is discovery-after-the-fact.
**Round four sharpens that from a tendency into a mechanism.** Both sweeps in this collision had
ALREADY renumbered three times each, and both independently arrived at `CHAOS-61` — because
"the next free id" is a PURE FUNCTION of the merged tree, so every sweep renumbering in the same
window necessarily computes the SAME answer. Renumbering to the next free id is therefore not a
tie-break at all: between two concurrent sweeps it is a guarantee of collision, and the guarantee
does not weaken as the namespace grows. Round three showed the two remedies racing; round four
shows they were never racing toward different answers. A tie-break has to consume something the
other party cannot also take — which is what a committed allocation is, and what a recomputation
can never be.
**Round five is that prediction confirmed inside the hour, and it is the reason this entry is
worth keeping rather than trimming.** The round-four fix — moving to `CHAOS-62` — was itself
computed from the merged tree and pushed; the request-history-store sweep had computed the SAME
id from the SAME tree, independently, and merged minutes later. So the remedy for the fourth
collision CAUSED the fifth, exactly as the paragraph above says it must. Note what this rules
out: the failure is not haste, not inattention, and not a missing check — no amount of looking
harder at the tree before renumbering can help, because the tree is precisely what both parties
agree on. The bug is that the allocation step has no side effect until a merge lands, so two
correct actors reading correct state produce the same answer; the only repair is to make
allocation WRITE something, before the work, that the other actor must observe.
Two secondary observations from these rounds. The automatic main-merge renumbers the SECTION
heading and leaves the `CHAOS-` id colliding, so the resolver looks like it handled the conflict
while the identifier people search by stays duplicated (§27 saw this too — it reproduces every
time). And round one collided on the REGISTER as well (both sweeps took `AU-14`), which is the
worse half: a duplicate section heading is visible on sight, a duplicate register row is not.
The residual cost is unchanged and is not the edit — it is that `CHAOS-58`, `CHAOS-59`,
`CHAOS-60` and `CHAOS-61` each name a different sweep in this PR's commit messages, review threads
and notifications than they name in the merged tree.)*
The
first sweep in this register to ask what an *unauthenticated caller gets to write*, rather than
what happens when infrastructure fails. `apiAuthLogin` is on the public allowlist and bounded
nothing: the username reached two lockout maps (retained ≥ 10 min), the audit ring, and the
durable audit JSONL — a 50 MB rotating file keeping ONE archive. Inside the endpoint's own
60-POST/min limit, one client commits ~60 MiB/min of chosen bytes and rotates the entire retained
compliance record away in under two minutes. The instrument built for exactly this outcome
(`internal/audit`'s `writeErrors`, CWE-778) cannot see it, because **every one of these writes
succeeds**. Closes AU-15/AU-16; the count axis is recorded open as AU-17. The sweep also found and MEASURED the
same class on the **proxy data path** — `sanitizeLog(r.Host)` bounds nothing and the proxy server sets
no `MaxHeaderBytes`, so one request with a 200 KB host writes 204,899 bytes to the process log and a
204,812-byte `Host` field to the request log, on a port every client can reach. Recorded OPEN as
**PX-21** rather than bundled: rejecting an over-long host is probably the right fix and is a
data-plane behaviour change that needs its own review. See §31.
**2026-09-09 — CHAOS-57 sweep (the admin UI listener, and which plane may kill which).**
Every earlier sweep asked whether a subsystem survives its own failure. This one asked what
a failing subsystem takes with it, and found the *least* critical listener in the process
holding a lever over the *most* critical one. `startUI` spawned a detached listen goroutine
whose ONLY error branch was `logFatalf` — `os.Exit(1)` — so **every way the ADMIN UI's
listener could fail terminated the PROXY DATA PLANE with it**, asynchronously, against a
process that had already announced itself as serving. Two triggers, both reproduced against
the real binary and both routine operations: an occupied admin port (`validatePortCollisions`
checks only Culvert's own three ports against each other, never the host) and an unreadable
custom UI certificate (the pair is read at listen time, so any rotation that momentarily
breaks it was a boot that ended in exit 1). Under `restart: unless-stopped` each becomes an
unattended crash loop — no proxy, no admin UI, no health endpoint — which is exactly the
outcome §19 closed for the category store, reached from the opposite direction. The defence
that "exiting fails closed" does not survive contact: **process death picks no posture at
all**, it delegates the choice to the topology — an explicit-proxy fleet loses all egress, a
PAC fleet with a DIRECT fallback goes UNFILTERED. The codebase already knew the answer in two
places, one of them inside the same function (a `selfSignedTLS()` failure degrades to HTTP
rather than exiting; CHAOS-54 gave the SOCKS5 listener a gentler death than the admin UI had).
Shipped: no listen path is fatal; an explicit bind so recovery can be declared on OBSERVED
evidence; a rate-bounded, jittered, interruptible rebind loop; the certificate re-read on
every attempt (so a rotation self-heals with no restart); the success log moved to AFTER the
bind (it used to claim a listener that did not exist); and a full observability plane on the
PROXY port — because the admin port's own `/healthz` cannot report that the admin port is
unreachable. The `/ready` row is REPORT-ONLY by design and pinned as a control: failing it
would eject a healthy gateway from the load balancer over its management plane. 15 gates; the
defect gates were verified failing against the reintroduced pre-fix shape, where `logFatalf`
kills the TEST BINARY mid-run and takes the package with it — so the defect cannot be
reintroduced and kept green. **SOCKS5-BIND** (an occupied SOCKS5 port still takes down HTTP
proxying) is recorded, not fixed: it is the same class one plane over, but a posture decision
rather than a mechanical extension. See rows AP-1…AP-4/SOCKS5-BIND, §25, and
`docs/operator/admin-ui-listener-recovery.md`.
**2026-09-04 — CHAOS-64 sweep (destination-host DNS resolution on the policy path).** The
sweep took the one failure domain the register had never entered: **DNS**, listed in the original
scope and never swept, because it looks like somebody else's dependency. It is not — a
`DestCountry` policy rule puts the customer's resolver on the critical path of every request that
misses one process-wide cache, on the REQUEST goroutine, inside the policy scan. `policy.go`'s own
comment names the hazard ("the scan can block → `geo.LookupCached` → DNS on an uncached
DestCountry host") and the code drops the evaluation lock because of it, which is the right fix for
the *lock* and no fix at all for the *request*. Behind that call sat `net.LookupHost` with **no
deadline, no single-flight, no concurrency bound and no counter**. Three defects, each reproduced
against the pre-fix tree: a wedged resolver held the request goroutine for the OS budget (5 s ×
attempts × nameservers) while it owned a client connection and a per-IP connection-limiter slot;
**200 concurrent requests for ONE host produced 200 resolver invocations**, so a brownout amplified
by request rate straight back at the resolver that was already failing (the WK-13 herd, aimed at
the customer's own DNS); and an expired entry was DISCARDED, so the first expiry during an outage
took every popular host cold inside the same five-minute window. That third one is the security
half and it is the register's §1 theme reached through a new door: a `DestCountry` rule that cannot
determine a country does not match, a rule that does not match is SKIPPED, and evaluation continues
to lower-priority rules — so **a "block sanctioned countries" rule silently stops enforcing while a
broad allow rule beneath it takes over.** Geo blocking goes dark because DNS is slow, and nothing
on this path counted, logged or alerted it. Shipped: a 2 s deadline via a context-aware seam;
single-flight (concurrent callers inherit the leader's answer AND its deadline, never start a
second lookup); a bounded resolver pool that SHEDS a distinct-host flood instead of queueing it,
without caching the shed result; stale-while-revalidate with a one-hour ceiling, so **a host
resolved in the last hour never blocks a request and never goes dark**, plus the guard that keeps a
failed refresh from overwriting the servable answer it was supposed to renew; and the missing
health plane — six `culvert_dns_resolve_*` series, a `dns_resolution` contract row, and a
fire-once page on the EXISTING `dns_failure` event. NXDOMAIN is counted but excluded from
degradation: the hostname is client-chosen, so counting it would let any client fabricate the page.
The same sweep bounded `fireDNSFailureAlert`'s Detail, which was a raw `err.Error()` — a
`*net.DNSError` embeds the queried hostname, so every failure minted a distinct dedup key the 30 s
window could not suppress, and the fan-out evicted real threat alerts from the 500-entry retry
queue (WK-12/RS-5, remotely triggerable). Deliberately NOT changed and recorded as residual: the
fall-through posture itself (making an unknown country match a block rule would deny every
destination this node cannot resolve — a bounded security gap traded for an unbounded availability
one), and the cgo resolver's uncancellable `getaddrinfo` (the deadline releases the request
goroutine; the OS thread is bounded by Go's own 500-thread cap). Gates:
`dns_resolve_chaos_test.go` (23, incl. two CONTROLS — a resolver that simply stopped resolving
would pass every defect gate while being far worse than the defect). See §28 and
`docs/operator/dns-resolution-health.md`.

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
| PX-4 | Spawned relay/async goroutines have **no `recover()`** — a panic in any propagates to the runtime and kills the process, dropping every in-flight tunnel. **CHAOS-57 found the last one:** `relayPlaintextInspectFallback` (the native-ALPN non-TLS fallback) was the ONE relay goroutine in the tree still unguarded — every other raw relay had carried a guard since CHAOS-24, so this branch was the odd one out rather than a known gap. Containing it is strictly fail-closed (a relay goroutine holds no authority the recovery could extend — the CHAOS-24 objection does not apply) and it closes BOTH legs, since the peer relay may be parked in a deadline-less Write that only a close can end. | GAP → **relays CLOSED** (CHAOS-24 + CHAOS-57); `go trackDestinationCountry` remains an unguarded async spawn | M | `relayCounted` + the strip-path/`rawRelay`/`socks5Relay` inline relays; last gap `proxy_tunnel_h2.go` `relayPlaintextInspectFallback`; residual `go trackDestinationCountry` `proxy.go:951` |
| PX-5 | SOCKS5 connections **bypass the per-IP connection limiter** entirely. | GAP | M | `handleSOCKS5` `socks5.go:251` never calls `connLimiter.Acquire`; HTTP path does at `proxy.go:627` |
| PX-16 | **The SOCKS5 accept loop retried a failed `Accept` with NO delay, forever.** `net/http.Server.Serve` (every other listener in the process) backs off 5 ms→1 s and stops on a non-temporary error; this loop logged and `continue`d on anything that was not `net.ErrClosed`. EMFILE/ENFILE come straight out of `FD.Accept` without blocking, so a descriptor incident produced **7.68 M attempts / 300 ms**, one log line each — a pinned core, ~40 MB/s into a 50 MB rotating log that erased its own diagnostic history in seconds, and (via `logsink`'s blocking backpressure) added latency to the HTTP data path on a node not using SOCKS5. Self-amplifying: FD exhaustion is the terminal state of WK-11 and PX-6. | NEW → **CLOSED** (CHAOS-54: backoff + errno classification + rate-limited logging; interruptible sleep keeps shutdown prompt) | **H** | was: `socks5.go` `serve`; see §22 |
| PX-17 | **An unrecoverable listener error was retried identically to a transient one.** EBADF/ENOTSOCK on the listening descriptor return instantly and forever, so the "retry" was a pure spin that could never accept anything, on a port that stayed BOUND — clients hung against a black hole instead of getting connection-refused. | NEW → **CLOSED** (CHAOS-54: the loop stops, closes the listener so clients fail fast, and records the service DOWN; transient/unknown errors still retry, which is the fail-safe direction) | M/H | was: `socks5.go` `serve`; now `socks5AcceptFatal` — see §22 |
| PX-18 | **The SOCKS5 listener had NO health surface** — absent from `/healthz`, `/readyz`, `/api/diagnostics` and `/metrics`. A listener spinning on EMFILE and a listener that had stopped accepting entirely were both reported by every probe as a fully healthy node. | NEW → **CLOSED** (CHAOS-54: `socks5_listener` contract row, report-only `/readyz socks5` row, `/healthz socks5` field, `culvert_socks5_{listener_up,accept_errors_total,accept_degraded,accept_backoff_seconds}`, `socks5_listener_down` alert) | M/H | `socks5_health.go` — see §22 |
| PX-20 | **Every `net.ErrClosed` from `Accept` was read as an expected shutdown.** `ErrClosed` says the listener is gone; it does NOT say a shutdown was requested, and `Stop` is only one of the ways a listener can end up closed. Any closure outside the shutdown path therefore terminated the accept loop with EVERY probe still green (`socks5: ready`, `culvert_socks5_listener_up 1`, `ok` contract row) — PX-18 reintroduced in a narrower costume, inside the very change that closed PX-18. Raised by Codex review on the PR, not by the sweep. | NEW → **CLOSED** (CHAOS-54: the loop checks whether `stopping` was actually closed; `Stop` closes it BEFORE `ln.Close()`, so the check is race-free in the direction that matters and errs toward silence, never toward a false page) | M/H | was: `socks5.go` `serve`; see §22.3 |
| PX-21 | **The same unbounded-untrusted-value class as AU-15, on the PROXY data path, and it is NOT fixed.** `handleRequest` writes `sanitizeLog(r.Host)` into the POLICY_* process-log line and `r.Host` verbatim into the request-log entry. `sanitizeLog` neutralises control characters but bounds NOTHING, and the proxy `http.Server` sets no `MaxHeaderBytes`, so net/http admits a request line plus headers up to ~1 MiB. **Measured on the default-deny path: one request with a 200 KB host wrote 204,899 bytes to the process log and a 204,812-byte `Host` field to the request log.** Both sinks are rotating files with one archive, and the proxy port is reachable by every client on the network — a far broader audience than the admin login endpoint, with the process log holding the diagnostics for every other incident (the §22 amplification lesson). | **NEW, OPEN** | **H** | `proxy.go:689,728` (`sanitizeLog(r.Host)`), `recordRequestAuthURI` `proxy.go:688`; reproduction in §32.6 |
| PX-19 | **The SOCKS5 accept loop had no panic guard.** `handleSOCKS5` carries `recoverGoroutine`, but a panic in `serve` itself propagated to the runtime and killed the whole proxy process (the PX-4 class, one level up). | NEW → **CLOSED** (CHAOS-54: contained and reported as listener DOWN — the CHAOS-24 objection to recovering in a worker goroutine does not apply when the recovery path is the loudest state the subsystem can produce) | M | was: `socks5.go` `serve`; see §22 |
| PX-6 | **No global connection cap**; per-IP map is unbounded in cardinality; limiter ships **disabled by default**. Distributed flood → FD/memory exhaustion. | GAP | H | `internal/connlimit/connlimit.go:12,67` (default disabled, `Acquire`→true when off) |
| PX-7 | Bandwidth/QoS token buckets are **never enforced on the data path** — `AllowBytes` has no call site in the relays. Configured QoS silently does nothing. | GAP (feature dead) | M | `internal/bandwidth` `AllowBytes` `bandwidth.go:261` — no caller in `proxy.go`/`socks5.go` |
| PX-8 | Shutdown drain only accounts for CONNECT tunnels — WebSocket, both non-TLS inspect fallbacks, and SOCKS5 relays are invisible to `drainActiveTunnels`, so SIGTERM hard-kills them. **Re-scoped by CHAOS-57 and larger than recorded:** the invisibility also silently DESTROYED each severed tunnel's `TUNNEL_CLOSED` byte/duration accounting (written only after both relays drain), and `activeConns` — the drain's log line and the dashboard's `activeConns` field — undercounted by four whole classes. Counting alone would have been the wrong fix: the classes are long-lived by design, so a drain that waits with no way to END the wait costs a guaranteed 15 s per node and severs them anyway. | GAP → **CLOSED** (CHAOS-57: per-class registry owning the `activeConns` accounting, drain-deadline force-close backstop across all five classes, budget-clamped settle so the accounting lands ahead of the FLUSH hooks, `culvert_tunnels_active{class}` + `culvert_tunnel_drain_forced_total`) | M | was: `recordActiveConn` at the CONNECT sites only; now `proxy_tunnel_drain.go`, `drainActiveTunnels` `main_shutdown.go` — see §25 |
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
| CA-6 | OCSP fails **closed** when a cert lists responders and none answer; `VerifyConnection` re-checks resumed sessions. Caveats: nil-issuer → fail-open; OCSP client has no SSRF guard on the peer-controlled responder URL. | ~~✓ (+2 caveats)~~ → **RE-SCORED by CHAOS-65**: the fail-closed half was right; the ✓ was not. The "caveat" was one of **seven** defects in the same pipeline, six of them closed in §35 and the seventh (CA-6b) open. **The row's own evidence pointed at the finding and the verdict looked past it** — *"no SSRF guard on the peer-controlled responder URL"* names the property (the peer controls the input) that makes all seven reachable, and the row still reads ✓ because the one question asked was "does it fail closed?". A control can fail closed on the path you tested and be bypassable on the path you did not. | ~~L/M~~ → **H** | `internal/ocsp/ocsp.go`; see §35 |
| CA-6b | **OCSP is not consulted on the path that handshakes.** `ConfigureTLSConfigOCSP` has two call sites, both targeting `upstreamOpTLSCfg` behind the shared upstream transport — which for a forward proxy means an `https://` PARENT PROXY handshake and nothing else. Every inspected HTTPS request goes through `upstreamInspectTLSConfig`, which builds its own `tls.Config` with no OCSP callbacks. So on the one path where this appliance validates an origin certificate on a client's behalf, revocation is not checked, while the startup banner, the admin panel and the API all report "enabled" and every counter reads zero — "working perfectly" and "never consulted" are the same scrape. | NEW → **REPORTED, not closed** (CHAOS-65 / OCSP-8: `culvert_ocsp_path_checked{path}`, `coverage` on `/api/ocsp`, a WARNING from both enable paths, a panel banner, and a structural gate pinning the claim to the code. Wiring it fail-closed would make every inspected HTTPS request depend on outbound port 80 to arbitrary responder hosts — a fleet-wide outage one checkbox away — so it is an owner posture decision with a soft mode attached) | **H** | `ocsp_coverage.go`, `proxy_tunnel.go:627`; see §35 |
| OCSP-1 | **A signed OCSP response was not bound to the certificate under test.** `ParseResponse(bytes, issuer)` is `ParseResponseForCert(bytes, nil, issuer)`, which takes `Responses[0]` and never compares the serial. The peer names the responder in its own AIA extension, so it also chooses the reply: a genuine CA-signed `good` about any OTHER certificate of the same issuer — obtained by asking that CA about any live cert and keeping the bytes — was accepted as this certificate's verdict. A **revoked certificate is accepted**, by its own subject, with no network position required. | NEW → **CLOSED** (CHAOS-65: `ParseResponseForCert(respBytes, leaf, issuer)`; `culvert_ocsp_response_rejected_total{reason="not_for_certificate"}` + a red panel banner, because a non-zero rate means something is answering with borrowed responses) | **C** | was: `internal/ocsp/ocsp.go` `queryOCSP`; see §35 |
| OCSP-2 | **No freshness validation.** `ThisUpdate`/`NextUpdate` were parsed and never read, the request carries no nonce (`CreateRequest(leaf, issuer, nil)`), and OCSP rides plaintext HTTP — so a `good` captured before revocation replayed forever. Fixing OCSP-1 does not close it: a pre-revocation response for the CORRECT certificate binds perfectly. | NEW → **CLOSED** (CHAOS-65: `responseFresh`, 5-min skew tolerated in BOTH directions — a clock rollback is a fault, not an attack — plus a 24h ceiling when `NextUpdate` is absent) | **H** | was: `internal/ocsp/ocsp.go` `queryOCSP`; see §35 |
| OCSP-3 | **`unknown` was a pass while "unreachable" failed closed** — two postures for one question. A CA must not answer `good` for a certificate it never issued (CA/B Forum BRs), so `unknown` is precisely the answer a mis-issued or forged certificate draws. | NEW → **CLOSED** (CHAOS-65: a verdict is `Good` or `Revoked` or it is not a verdict — CHAOS-53's rule; discarded under `reason="unknown_status"`, then the EXISTING fail-closed path, no new posture) | M/H | was: `internal/ocsp/ocsp.go` `checkResponders`; see §35 |
| OCSP-4 | **Verdict cache keyed on the serial alone.** A serial is unique only within an issuer — which is why RFC 6960's CertID carries the issuer name and key hashes with it. The dangerous direction admits a genuinely REVOKED certificate from a different CA off another CA's cached `good`, with no responder query at all. Sequential serials are the norm in enterprise PKI (ADCS). | NEW → **CLOSED** (CHAOS-65: `certKey` = SHA-256 over issuer subject + issuer SPKI + serial) | **H** | was: `internal/ocsp/ocsp.go` `cacheResult`/`checkCached`; see §35 |
| OCSP-5 | **The responder URL was an unguarded SSRF sink** (the CA-6 caveat, six weeks unaddressed): `http.DefaultClient.Do` against a URL from the peer's certificate — no scheme allow-list, no `isPrivateHost`, no SSRF dialer, and `DefaultClient` follows up to ten redirects, so even a URL-level guard would have been bypassed by a `302`. Any operator of any destination this gateway reaches could name an internal address and have the proxy POST to it from inside the trust boundary. | NEW/known → **CLOSED** (CHAOS-65: inline scheme + `ssrf.PrivateHost` at the call site per repo convention, `ssrf.SafeDialContext` under it to close the rebinding window, redirects refused outright, a dedicated client so `HTTP(S)_PROXY` and the shared pool are out of the path) | **H** | was: `internal/ocsp/ocsp.go` `queryOCSP`; see §35 |
| OCSP-6 | **Unbounded responder fan-out inside a TLS handshake.** `leaf.OCSPServer` walked in full under a PER-RESPONDER 5 s timeout, on the request goroutine, holding the client conn, an FD and a per-IP `connlimit` slot: 200 blackholed responders ⇒ ~17 minutes parked AND 200 outbound POSTs at hosts the attacker named. Fan-out and targets both peer-written. CHAOS-58's finding one subsystem over. | NEW → **CLOSED** (CHAOS-65: `maxResponders` 4 inside ONE `queryBudget` 5 s envelope — deliberately the old per-responder value, so the ordinary one-responder certificate is unchanged and only the worst case shrinks; `culvert_ocsp_responders_truncated_total`) | **H** | was: `internal/ocsp/ocsp.go` `checkResponders`; see §35 |
| OCSP-7 | **No single-flight**: N concurrent handshakes to one host each launched their own query (measured 24 → 24), amplifying client request rate 1:1 onto a responder that is by hypothesis already the slow dependency. The herd `hostIPCache` and `jwksCache` already collapse. | NEW → **CLOSED** (CHAOS-65: leader/follower per CertID, no follower timer, leader publishes on every exit path INCLUDING a panic, flight defaults are the fail-closed verdict) | M | was: `internal/ocsp/ocsp.go` `VerifyPeerCertificate`; see §35 |
| OCSP-9 | **No OCSP stapling.** Culvert never requests or consumes `tls.ConnectionState.OCSPResponse` — the deployment shape that makes revocation checking cheap, private and egress-free, and the natural companion to closing CA-6b. | NEW (recorded, not in scope) | M | `proxy_tunnel.go` `upstreamInspectTLSConfig`; see §35 |
| OCSP-10 | **No CRL fallback, and a certificate with no AIA responder is accepted unchecked.** The admin panel is titled "OCSP / CRL Revocation"; only OCSP exists. Unchanged by CHAOS-65. | NEW (recorded) | L/M | `internal/ocsp/ocsp.go` `checkResponders` (`len(responders) == 0` ⇒ pass); see §35 |
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
| AU-3 | Proxy-path Basic-auth bcrypt is **not rate-limited** — correct-username + N wrong-passwords is a cache miss every time → full ~100ms bcrypt per request → CPU starvation. The `loginLimiter` guards only the admin UI. **Understated: the WRONG-username branch is worse (AU-3a) and needs no valid username at all.** | GAP → **CLOSED** (CHAOS-57, §25: `internal/authcost` bounds concurrency globally + per client, fail-closed) | M → **C** | `store.go` `verifyAuthFrom`, `internal/authcost`, `auth_cost_health.go` |
| AU-3a | The wrong-username branch runs an unconditional bcrypt against the dummy hash (RISK-008 timing equaliser), is reached BEFORE the result cache, and never populates it — so a flood of DISTINCT usernames is a guaranteed miss every time. Measured **79.6 ms of exclusive CPU per ~200-byte request (51,631x a cached auth)**; **66 req/s (~13 KB/s) consumed 100% of a 4-core box** and degraded other CPU work **15.6x**. Unauthenticated, remotely triggerable, and in the DEFAULT posture nothing stands in front of it — the connection limiter, rate limiter and IP filter all ship disabled. | GAP → **CLOSED** (CHAOS-57) | **C** | `store.go:521` (pre-fix), gates `TestChaos57_WrongUsernamePathIsGoverned`, `..._ConcurrentVerificationsAreBounded` |
| AU-3c | The auth result cache evicted **one arbitrary LIVE entry** at capacity (a Go map range stopping at the first key), so a flood of distinct passwords under a known username displaced OTHER clients' cached positives. Measured: an honest client's cached credential survived a 1x-capacity flood and was reliably gone by 2x — after which that user paid a full ~80 ms bcrypt on EVERY request. The attacker's amplification lands on legitimate traffic. Same class as the `internal/authstate` finding. | GAP → **CLOSED** (CHAOS-57: `internal/authstate`'s fair-eviction policy ported — oldest entry of the largest holder, deterministic) | H | `store.go` `evictOneLocked`, gate `TestChaos57_FloodCannotDisplaceAnHonestClientsCachedResult` |
| AU-3d | The at-capacity expired-entry scan is O(cache) whenever nothing has expired — precisely the state a flood keeps it in — and runs holding the process-wide auth mutex. Measured **64 µs per insertion** at the 5,000-entry cap. | GAP → **CLOSED** (CHAOS-57: bucket-indexed eviction, no full scan) | L/M | `store.go` `set` (pre-fix) |
| AU-3e | **Username-enumeration timing oracle, PRE-EXISTING and deliberately NOT closed by CHAOS-57.** A negative result for the CORRECT username is cached; one for a wrong username is not (the branch returns before the cache). So repeating the SAME wrong (user, pass) pair twice is ~1.5 µs the second time for a valid username and ~80 ms for an invalid one — which is the oracle RISK-008's dummy-compare equalisation exists to prevent, reachable by repetition rather than by a single request. Closing it means caching wrong-username negatives, a behaviour change to a security control that deserves its own review. CHAOS-57 verifies only that it does not WIDEN it (`TestChaos57_AdmissionDecisionIsUsernameIndependent`). | GAP | M | `store.go` `verifyAuthFrom` — cache write is on the username-match branch only |
| AU-4 | Lockout store is bounded + fail-closed, and TOTP failures now feed it. But it is **not persisted** (resets on restart) and **per-node** (attacker gets MaxAttempts per node in a cluster). | ✓ (+2 gaps) | M | `lockout.go:111-126,102-110`; per-node note `roadmap/edge-case-audit.md:138` |
| AU-5 | LDAP proxy auth fails closed, but the 10s timeout covers only the **dial** — `Bind`/`Search` have no per-op deadline, so a server that accepts then stalls hangs the request goroutine. | GAP → **CLOSED** (CHAOS-58 §26: one 10s round-trip envelope, two non-redundant layers; re-scored **H** on discovery — the stall is unbounded, not slow, and it made the CHAOS-47 cooldown structurally unreachable) | ~~M~~ H | `auth_ldap.go` `verify`; gates `auth_ldap_stall_chaos_test.go` (9) |
| AU-14 | The CHAOS-47 provider-wide cooldown is armed only by an error that RETURNS, so any identity-backend fault that HANGS is invisible to it by construction. Closed for LDAP by CHAOS-58; the OIDC leg is bounded by `http.Client{Timeout}` on every call, and SAML is browser-mediated. Recorded so the next backend added to the credential chain inherits the rule rather than rediscovering it. | GAP → **CLOSED for the shipped backends** (CHAOS-58 §26) | M | `auth_backend_health.go` `authProbeGate`; `noteVerifyError` `auth_ldap.go` |
| AU-6 | SAML metadata & OIDC discovery fetched **once** at compile — no periodic refresh. IdP SAML signing-cert rotation breaks assertion validation until re-save/restart. (OIDC JWKs *do* auto-refresh every 15 min + serve-stale.) | GAP | M | `auth_saml.go:54-57,249-294`; JWKs OK `auth_oidc_flow.go:129-157` |
| AU-7 | IdP 5xx / network error / expired token all collapse to fail-closed "auth fail" — correct posture, but an IdP outage is indistinguishable from a brute-force spike (no distinct `idp.unreachable` metric). | ✓ (obs gap) | L | `auth_oidc.go:152-162`, `auth_oidc_flow.go:623-636` |
| AU-8 | Auth caches bounded at 5000 with eviction; HMAC-keyed keys (heap-dump safe); cached OK TTL capped at token `exp`. | ✓ | — | `store.go:236,241-258,268-285`, `auth_oidc.go:219-227` |
| AU-9 | Session HMAC key change / per-node divergence logs everyone out (fail-closed) — no rotation grace window; cluster without shared key needs affinity. | GAP | M | `session.go:390-393`, `InitRandomKey` `session.go:80-86` |
| AU-10 | TOTP: 30s step, ±1 window (~90s skew tolerance), replay closed via `counter <= lastCounter`, empty-secret fails closed. | ✓ | — | `totp.go:47-88` |
| AU-11 | Multi-IdP registry: compile is isolated (all-or-nothing staging swap; bad profile dropped, not fatal). But the **request-time provider loop is sequential and unguarded** — one slow IdP adds latency to every request that reaches it. | ✓ compile / GAP request | M | `auth_idp.go:159-165,354-376` vs loop `proxy.go:209-220` |
| AU-12 | All admin-configured IdP URLs dial through `ssrfSafeDialContext`; HTTPS+non-private pre-validated; response bodies `io.LimitReader`-capped. | ✓ | — | `auth_oidc_flow.go:64,300`, `auth_idp.go:556-565` |
| AU-13 | Registry introspection also lacks **negative caching / circuit breaker** — a permanently-invalid token amplifies one IdP call per provider per request forever. | GAP | M | `auth_oidc_flow.go:623-636`; breaker exists unused `internal/upstream/upstream.go:89-96` |
| AU-15 | **The public admin-login endpoint accepted an UNBOUNDED username and copied it verbatim into durable state.** `apiAuthLogin` is on `uiAuthMiddleware`'s public allowlist; nothing between the 1 MiB body cap and the handler limited `body.User`, and every failed attempt wrote it into the two lockout maps (retained ≥ `lockout.Window`), the 500-entry audit ring, and the **durable audit JSONL** — a 50 MB rotating file keeping exactly ONE archive. At the endpoint's own rate limit (60 mutating POSTs/min/IP) one unauthenticated client commits ~60 MiB/min of chosen bytes, rotating the entire 100 MB retained compliance record away in **under two minutes**, with no disk fault and every write SUCCEEDING (so `writeErrors`/`storage_write_failed` never fire). Measured by the gate: **4,195,672 bytes into the audit file from 8 requests.** | NEW → **CLOSED** (CHAOS-63: bounded at the handler; `lockout.MaxUsernameKeyLen` is the structural half; `culvert_login_oversize_rejected_total`) | **H** | was: `ui_auth.go` `apiAuthLogin`; `internal/audit/audit.go:213` (`NewRotatingFile(path, 50)`); see §32 |
| AU-16 | **`internal/lockout` bounded its maps by ENTRY COUNT but not by KEY SIZE.** `Cleanup`'s own doc claims the maps are bounded "against an unbounded-memory DoS" — true on the count axis, and the janitor cannot sweep an entry before its `Window` elapses, so the SIZE axis was the whole exposure: one caller retained (rate × Window × username size) bytes in a leaf package whose stated contract is to be bounded. | NEW → **CLOSED** (CHAOS-63: `boundUsername` applied at every public entry point; consistency pinned so `Check` and `RecordFailure` cannot disagree on the key) | M/H | was: `internal/lockout/lockout.go`; see §32 |

### 2.6 Background Workers / Feeds / Scanning / Alerting

| # | Scenario | Verdict | Sev | Evidence |
|---|----------|---------|-----|----------|
| WK-1 | **ClamAV daemon down → files pass UNSCANNED (fail-open), no alert/counter.** Contradicts the same file's *timeout* path, which fails **closed**. Two infra-failure modes, opposite postures. **Re-scoped by CHAOS-52 and larger than recorded:** the fail-open branch was reachable by LOAD, not only by a daemon fault (see WK-15), because a private 5 s queue deadline preempted the 10 s fail-closed one. The visibility half closed with CHAOS-10 (counter + `scan_clam_error` + never caching a dark verdict); the LOAD half closed with CHAOS-52. | GAP → **visibility CLOSED** (CHAOS-10), **load-reachability CLOSED** (CHAOS-52); the daemon-DOWN posture is split out as WK-1b | H | `internal/secscan/secscan.go` `scanBodyInner`/`recordClamFailure` |
| WK-1b | **Posture**: a ClamAV daemon that is genuinely DOWN still fails OPEN (counted + alerted). Deliberately asymmetric with saturation, which now fails closed: a down daemon is an operator-visible infrastructure state with its own alert and status surface and refusing all traffic on it is a fleet-wide outage, whereas saturation is transient, self-clearing in seconds, and inducible on demand by whoever wants the gap. Same class as CA-3b. | GAP (**owner decision**; now counted, alerted, and distinguishable from saturation) | H | `internal/secscan/secscan.go` `recordClamFailure` default branch |
| WK-2 | Remote scan sidecar down → fail-open, **but** alerted (`scan_svc_down`) + counted. Posture not admin-selectable; 30s per-request timeout stacks latency when hard-down. **Re-scoped by CHAOS-53 and much larger than recorded:** that 30 s timeout was not merely latency, it was a PRIVATE deadline three times the process's own fail-closed scan budget, and exceeding it surfaced as a transport error → classified as a fault → fail-OPEN. So a merely SLOW sidecar forwarded content unscanned while the local back end blocks for the identical condition (WK-19). The down-sidecar posture is split out as WK-2b. | GAP → **slowness/capacity CLOSED** (CHAOS-53, §21); the sidecar-DOWN posture is split out as WK-2b | H | `internal/secscan/remote.go` `ScanBody`/`scanOnce` |
| WK-2b | **Posture**: a sidecar that is genuinely unreachable/erroring still fails OPEN (counted + alerted). Deliberately asymmetric with slowness and capacity, which now fail closed — exactly the WK-1/WK-1b split, for the same reasons. | GAP (**owner decision**; now counted, gated-alerted, rate-limit logged, and reachable only by an actual fault) | H | `internal/secscan/remote.go` `remoteScanFail` |
| WK-19 | **The remote sidecar had none of the CHAOS-52 protections, and the runbook recommended switching to it.** Six further defects: any HTTP 200 whose body parsed as JSON (`{}`, `null`) was read as CLEAN with no counter/log/alert; NO `culvert_scan_*` series is produced on a sidecar node and `stat_remote_scan_fail` never reached `/metrics`; the fail-open alert fired per request ungated with a raw `err.Error()` (ephemeral port ⇒ un-dedupable key) and logged per request; scan exclusions were never LOADED in remote mode, so `scanexcl.Store` had no path and every admin Save was a silent no-op that returned 200 and was audited as success; the hash allowlist was never consulted and `Result.Hash` came from the SIDECAR; `Status()` decoded an unbounded body on an admin endpoint; and the sidecar's own status blob shadowed this node's `scan_svc_mode`, so a remote node reported "local". | GAP → **CLOSED (CHAOS-53)** | **H** | §21; `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-22.md` |
| WK-3 | GeoIP cache-miss on the policy hot path fails **closed** (country allow-rule cannot match unknown country); `LookupCached` never blocks on DB/DNS. **The fail-closed half was and is true. The "never blocks" half STOPPED being true** and this row went on asserting it: the host→IP cache added in front of the engine made the common path fast without removing the blocking `net.LookupHost` from the MISS path, so the accessor the request goroutine calls performed an uncancellable resolution inside policy evaluation. Re-scoped by CHAOS-60 (§28) as GEO-1, with GEO-2 alongside it. | ✓ fail-closed / GAP no-block → **CLOSED (CHAOS-60)** | **H** | §28; `geoip.go` `LookupCached`/`resolveHostCached`, `geoip_resolve_health.go` |
| WK-3b | **Country-scoped ENFORCEMENT was fed by a best-effort dashboard sampler.** On the request path the only populator of the IP→country cache that `matchDestNorm` reads was `trackDestinationCountry` — telemetry, ALLOW-branch only, drop-on-full at 256. A saturated sampler, or a first request that was blocked, left the country permanently unknown and every country-scoped rule silently non-matching. | GAP → **CLOSED (CHAOS-60)**; the enforcement path now owns its own bounded warmer | **H** | §28; `proxy.go` `trackDestinationCountry`, `geoip_resolve_health.go` `warmGeoHost` |
| WK-3c | **Posture**: a country-scoped rule still does not match on the FIRST request to a host whose country is not yet cached — fail-closed for an allow-rule (user-visible block), fall-through for a deny-rule. Unchanged by CHAOS-60, which only makes the window converge in one request instead of depending on a sampler. Closing it means deciding what "unknown country" MEANS in policy, which is a product decision. | GAP (**owner decision**; now counted as `culvert_geo_policy_unresolved_total`) | M | §28.5; `policy.go` `matchDestNorm` |
| WK-4 | GeoIP DB missing/corrupt: reader stays nil, feature degrades to "no country data" — safe, but **no staleness/health signal** (MMDBs expire silently). | GAP (obs) → **PARTIALLY CLOSED** (`BuildTime()` reads the `.mmdb`'s own `build_epoch`; `GET /api/geoip` returns `dbBuildDate`/`dbAgeDays`; GeoIP Database panel shows the age, warn-colored past 90 days; load failures surfaced via `lastError`. Residual: no PROACTIVE alert/metric — an operator must open the panel to notice) | M | `internal/geoip/geoip.go` `BuildTime`, `ui_security.go` `apiGeoIPConfig` |
| WK-5 | **Threat-feed timeout → stale-erase.** On partial failure `Sync` unconditionally replaces the maps with only what succeeded, discarding prior good entries; stamps `lastSync=now` even on failure; no backoff, no staleness alert → coverage silently shrinks for up to 6h. | GAP → **CLOSED** (stale-erase: per-source `replacedSources` replacement, `threatfeed.go` `applySync`. Backoff + staleness alert: CHAOS-59, §27) | H | `internal/threatfeed/threatfeed.go` `applySync`; `threatfeed_health.go` |
| WK-5b | **The carry-forward fix removed the only signal.** `culvert_threat_feed_entries` is held at its last-good value by design, so after WK-5's fix a node whose feed has not synced in three weeks exported metrics byte-identical to one that synced ten minutes ago; the only surviving difference reached ONE role-gated admin JSON field no alerting rule scrapes. | GAP → **CLOSED (CHAOS-59)** — five `culvert_threat_feed_*` freshness series, `threat_feed` contract row, fire-once `threat_feed_stale` alert | **H** | §27; `threatfeed_health.go` |
| WK-5c | **A feed round that fails at COLD START leaves the node with no coverage at all.** `Start` syncs immediately when the on-disk DB is empty (fresh install, re-image, replaced volume); pre-fix a failed first round was not retried for 6h, so the node enforced with an EMPTY threat database while every probe reported healthy. | GAP → **CLOSED (CHAOS-59)** — backoff ladder + a distinct never-synced alert/row at a 30-min grace rather than 2× the interval | **H** | §27; `threatfeed_health.go` `checkThreatFeed` |
| WK-6 | UT1 category feed failures counted but **never alerted**; fixed 24h retry, no backoff. Stale-serve is safe (last-good BadgerDB). | GAP → **retry/backoff/jitter CLOSED (CHAOS-59)**; the alert half stays open by owner decision (last-good BadgerDB keeps serving; category staleness is not a security control) | M | `internal/feedsync/feedsync.go` `Start`/`syncRound`, §25 |
| WK-13b | **No jitter on either legacy feed ticker** (the WK-13 herd finding, instantiated). `time.NewTicker` fires at a fixed offset from process start, so a fleet that boots together fetches from the same third-party origins forever — and the origins are public/shared (abuse.ch, openphish.com, a raw.githubusercontent.com mirror of a 50+ MB tarball). Rate-limiting of the customer's egress IP is the ordinary answer, which then produces the failure the absent backoff held the fleet at. | GAP → **CLOSED (CHAOS-59)** — stable per-node ±10% jitter on both, via `internal/feedsched` | M | §27; `internal/feedsched/feedsched.go` `StableJitter` |
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
| AU-3 | **DONE** (CHAOS-57): 19 root gates in `auth_cost_chaos_test.go` + 15 engine gates in `internal/authcost`. Eleven defect gates verified failing against the shape each replaces, including the asymmetric-gate variant that reintroduces the RISK-008 oracle, the non-injective cache key (an authentication bypass), and the immediate per-client refusal that denied a workstation's own parallel connections. |
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
  it spans 27 subpackages, and ADR-0024's rollout ladder means "contain and continue" has to be
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

  > **CLOSED by CHAOS-62 (2026-08-29) — and both bounding clauses above were
  > WRONG.** "Quarantining it silently is an evidence decision" argues FOR the
  > fix: the CHAOS-05/07 contract moves aside and never deletes, so the evidence
  > survives either way; what this deferral preserved was a crash loop whose
  > history is equally unreadable and whose whole service is down too. And
  > "bounded by being opt-in" is backwards — opt-in means DURABLE in
  > `admin_settings.json` (so the crash loop is self-latching, with no admin UI
  > left to turn the setting off) and reachable from the LIVE admin API (so it
  > is a runtime kill of a gateway carrying traffic, not a boot failure). See
  > §25. The severity was Critical, not the bounded case recorded here.
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

## 25. CHAOS-57 — The hijacked-tunnel plane on the way out

**Sweep date:** 2026-09-01 · **Register rows:** PX-8 (closed), PX-4 (relays closed)
· **Runbook:** `docs/operator/tunnel-drain-on-shutdown.md`

### 25.1 Why this domain

§24 (CHAOS-56) bounded the shutdown sequence end to end and made the tunnel
drain honour its phase deadline instead of adding a private 15 s window on top
of it. It answered *how long may the drain take?* It never asked the prior
question:

> **Does the drain see what it is draining?**

It does not. `drainActiveTunnels` waits on ONE number — `activeConns`
(geoip.go) — and Culvert has seven hijacked-tunnel classes. Four of them never
touched that number:

| class | counted before? | force-closed before? |
|---|---|---|
| CONNECT bypass | yes | no |
| CONNECT inspect (strip, H1) | yes | no |
| CONNECT inspect (native ALPN) | yes | only if it negotiated h2 |
| CONNECT inspect non-TLS fallback (strip) | **no** | no |
| CONNECT inspect non-TLS fallback (native) | **no** | no |
| WebSocket | **no** | no |
| SOCKS5 | **no** | no |

Two mechanisms produce the blind spots, and neither is a bug in isolation. A
hijacked conn is invisible to `http.Server.Shutdown` **by construction** —
net/http stops tracking a conn the moment it is hijacked, which is the whole
point of hijacking. And `socks5Server.Stop` waits only for the ACCEPT LOOP,
because every session runs in a detached `go handleSOCKS5(conn)`; that file's
own header records the deferral verbatim:

> *"In-flight SOCKS5 tunnels are NOT drained — that is explicitly out of scope
> for P1.5 (tracked for Phase 2)."* — `socks5_shutdown_test.go`

Phase 2 never came. So for four classes **nothing in the shutdown sequence
waited, and nothing closed them**: they ran until the process exited and the
kernel reset them.

### 25.2 Three consequences, all silent

**(1) One fault, two postures.** A CONNECT tunnel gets a 15 s grace on SIGTERM.
A WebSocket or an SSH-over-SOCKS5 session on the same node, at the same instant,
under the same signal, gets none. Nothing decides this deliberately — it is
decided by which `recordActiveConn` call site the code path happened to pass
through. That is the §16.3 theme (opposite postures for one fault class,
decided by an incidental predicate) reappearing in the data plane.

**(2) The accounting for every severed tunnel is destroyed.**
`recordTunnelClose*` — the `TUNNEL_CLOSED` request-log entry carrying
`BytesSent`/`BytesRecv`/`DurationMs`, and the `recordTunnelBytes` fold into the
global byte counters — runs **after** both relay goroutines drain. A tunnel
killed by process exit never reaches it. So every graceful shutdown dropped the
bytes and duration of every in-flight WebSocket and SOCKS5 session from the
request log, the JSONL export, the SIEM feed and the dashboard totals, with no
counter saying so. On a rolling fleet upgrade this is systematic, not
incidental: the loss is proportional to how many long-lived sessions the fleet
carries, which is exactly the deployments that care about the numbers.

**(3) The drain's own evidence undercounts.** `Draining %d active tunnel(s)` is
what an operator reads to confirm a node left cleanly; with four classes
uncounted it reports 0 — and returns immediately — on a node severing hundreds
of live sessions. `activeConns` is also the dashboard's `activeConns` field, so
an operator sizing FD or connection budgets from it was reading a number that
excluded SOCKS5 and WebSocket entirely.

### 25.3 The finding inside the finding: counting alone is the WRONG fix

The obvious change is four `recordActiveConn` calls. It is wrong, and it is
wrong in a way the defect gates would not have caught.

Adding the calls makes the drain **wait** on those classes — but nothing would
END that wait. Long-lived is what WebSocket and SOCKS5 are FOR: SSH sessions,
IMAP IDLE, push channels, database tunnels. They do not go quiet inside 15 s. So
the drain would hit its deadline on **every** shutdown of a node carrying any
such session, converting an instant restart into a guaranteed 15 s one across a
rolling fleet upgrade — and then sever them anyway, because nothing closed them.
The operator would have paid `N × 15 s` of maintenance window and received
nothing.

The wait is only worth its cost if it ends in a **deterministic teardown**. That
is the same argument PR3d already made for inspected H2, which is why the fix
mirrors `forceCloseH2InspectTunnels` rather than inventing a second mechanism:
the registry holds both legs of every hijacked tunnel, and the drain deadline
hard-closes them. Each relay's `io.Copy` returns, its parent runs
`recordTunnelClose*`, and the accounting lands in the request-log queue while
the FLUSH hooks (order ≥ 110) are still ahead of us. **Force-closing is never
worse than the SIGKILL it replaces** — that abandons the same conns AND the
accounting.

### 25.4 What shipped

1. **`proxy_tunnel_drain.go` — a per-class registry.**
   `registerDrainableTunnel(class, conns...) func()` OWNS the `activeConns`
   accounting for its class (a caller must not also call `recordActiveConn`, or
   the drain would wait on a count that never reaches zero). Release is
   idempotent via `sync.Once`.

2. **The map key is the ENTRY pointer, never a conn.** Two tunnels can
   legitimately hold the same conn value — the strip-path fallback registers
   `rawClient` while the inspect path registers the `tls.Conn` wrapping it — and
   a conn-keyed registry lets one release evict the other's registration, so the
   surviving tunnel would never be force-closed. Verified: the conn-keyed shape
   evicts *both*.

3. **All five classes wired**, including the two the drain could already see
   (`connect_bypass`, `connect_inspect`) which were counted but held by no
   registry, so the drain waited on them with no way to end the wait. A native
   tunnel that negotiates h2 appears in both registries; that is deliberate and
   not double-counting — this registry owns the single `activeConns` increment
   while `culvert_h2_inspect_active` measures the GOAWAY-capable subset, both
   backstops fire at the same deadline, and a second `Close` is a no-op.

4. **The backstop closes conns, not contexts.** `idleCopyCounted` sits in
   `io.CopyBuffer`, which returns only on a read/write error, and the peer
   direction may be parked in a deadline-less Write that nothing but a close can
   end — the same reason every relay's panic path closes BOTH legs. Entries are
   left in the map: the relay's own release removes them, and deleting here
   would race a concurrent release into double-decrementing the gauge.

5. **A budget-clamped settle** (`tunnelForceCloseSettle`, 2 s ceiling). Without
   it the ordering between "the relay writes its entry" and "the flush hooks
   run" is only probabilistic — the relays need microseconds and the intervening
   hooks take milliseconds, so it *works* — and this section exists because
   probabilistic shutdown ordering is what CHAOS-56 removed everywhere else. It
   is a CEILING clamped to whatever the phase has left, so it can never overrun
   the deadline or borrow from the flush reserve. **On the `ctx.Done()` branch
   the settle is SKIPPED**: the budget is already spent, and lingering would
   take time from the hooks behind us. Losing the accounting there is exactly
   the pre-change behaviour — never worse.

6. **PX-4 residual closed.** `relayPlaintextInspectFallback` was the ONE relay
   goroutine in the tree with no panic guard; every other raw relay
   (`relayCounted`, the strip-path fallback, `rawRelay`, `socks5Relay`) has
   carried one since CHAOS-24, so this branch was the odd one out rather than a
   known gap. A panic there propagated to the runtime and killed an in-line
   security appliance, dropping every OTHER in-flight tunnel with it.

7. **Observability.** `culvert_tunnels_active{class}` (five classes) and
   `culvert_tunnel_drain_forced_total`. The class label matters at exactly the
   moment it is read: when the drain times out, WHICH kind of session is holding
   the node decides the remedy. The class names are a monitoring contract and
   are pinned by test.

### 25.5 Gates

`proxy_tunnel_drain_chaos_test.go` — 15. Every DEFECT gate was verified failing
against its reintroduced pre-fix shape:

| gate | pre-fix failure |
|---|---|
| `SOCKS5TunnelIsVisibleToTheDrain` | `activeConns = 0` with a live relay |
| `WebSocketTunnelIsVisibleToTheDrain` | `activeConns = 0` on a real 101 through the real proxy |
| `SeveredTunnelStillRecordsItsAccounting` | no `TUNNEL_CLOSED` entry; relay still parked in `io.Copy` |
| `DrainWaitsForAHijackedTunnel` | drain returns instantly |
| `DrainDeadlineForceClosesEveryClass` | `forced_total = 0`, want 5 |
| `NativeInspectFallbackRelayContainsAPanic` | the test binary itself panics — the production failure mode |
| `RegistryKeysOnTheEntryNotTheConn` | conn-keyed registry evicts both registrations |
| `SettleIsClampedToTheBudget` | settle runs its full 2 s past a spent deadline |
| `ReleaseIsIdempotent` | `activeConns = -2` |

Plus CONTROLS, because the two cheapest wrong fixes pass every defect gate:
`ControlGraceIsRealNotImmediateForceClose` (force-closing at drain START
satisfies all of them while being **strictly worse than the defect** — a session
that would have finished inside the window is killed; verified failing against
that shape) and `ControlDrainStillReturnsImmediatelyWithNoTunnels` (seeing four
more classes must not make a quiet node pay the window on every restart). A
non-idempotent release is its own control: a negative gauge makes
`active <= 0` true forever, restoring the original blindness by accident.

### 25.6 What is deliberately left

- ~~**New tunnels are not fenced during the drain.**~~ **This was recorded as a
  residual and the reasoning given for it was WRONG.** The original note claimed
  the raw classes need no fence "because their listeners are already closed by
  the time the drain runs and the drain's per-tick loop picks up any late
  registrant." Codex review of PR #1288 showed that is false for SOCKS5, and
  §25.8 records it — the fence shipped in the same PR.
- **`go trackDestinationCountry` remains an unguarded async spawn** (PX-4
  residual). It is not a relay and holds no conn; recorded rather than swept in
  with a tunnel change.
- **Tunnels are still cut, not migrated.** Draining a node before a restart
  remains the operator's job — CHAOS-57 makes the cut deterministic, accounted
  and observable, not avoidable.
- **The settle can legitimately time out.** `activeConns` is a SUPERSET of what
  either backstop can force-close (a native-ALPN tunnel mid-handshake is counted
  but held by neither registry), so it is best-effort by construction and
  bounded by its own ceiling.

### 25.7 The process lesson

§24 was about documented residuals whose named mitigation had silently acquired
a correctness requirement. This sweep adds one about **counters as interfaces**:

> A drain, a health check and a dashboard that all read one counter have all
> inherited that counter's blind spots — and a blind spot in a counter is
> invisible in exactly the way a blind spot in a check is not. Nobody audits a
> number for what it is *not* counting. `activeConns` was correct for every
> call site that incremented it; the defect lived entirely in the sites that
> did not, and it reached three consumers with three different consequences
> (no grace, lost accounting, a false gauge) without any of them being wrong.

### 25.8 Review follow-up — the defect surviving inside its own fix

Raised by Codex review against PR #1288 and fixed in the same PR. It is the
sharpest kind of finding this series produces: **the fix was correct for every
tunnel the drain could see, and PX-8 survived in the window where the drain
could not see one yet.**

`handleSOCKS5` sets a 30 s negotiation deadline, dials with a 10 s timeout, and
only then calls `socks5Relay` — which is where CHAOS-57 registers the tunnel. So
a connection accepted moments before `Stop` can register **up to ~40 s after the
listener closed.** And `socks5Server.Stop` waits only for the ACCEPT LOOP,
because each session is a detached `go handleSOCKS5(conn)`, so nothing in the
sequence is waiting for that handler.

The consequence is not a race the drain narrowly loses — it is a drain that has
already finished. `drainActiveTunnels` returns IMMEDIATELY when
`activeConns <= 0`, and that is exactly the state of a node whose SOCKS5 sessions
are all still negotiating. So the drain returns instantly, the force-close
backstop runs against an empty registry, the flush hooks complete — and only
*then* does the handler send `0x00 success` and establish a long-lived tunnel
that nothing will close and nothing will account for. PX-8, inside the change
that closed PX-8.

**Why SOCKS5 and not the HTTP classes.** This is the distinction the original
residual note missed:

> `proxySrv.Shutdown` (order 90) waits for every in-flight request, so a CONNECT
> or WebSocket either completes or hijacks-and-registers before the drain at
> order 100 looks. **The HTTP paths have a synchronization barrier before the
> drain. SOCKS5 has none at all.**

**The fix is to refuse, not to register earlier.** Codex offered both. Registering
at handler entry would make the drain wait on sessions that may never become
tunnels, and would redefine `culvert_tunnels_active` from *live tunnels* to
*attempts* — a monitoring contract change to fix a shutdown bug. Refusing is
protocol-correct (SOCKS5 reply `0x01`, general server failure) and strictly
kinder to the client: it learns the request failed and retries, on a fleet
against another node, instead of being handed a success reply and a tunnel that
dies seconds later with no record it existed. A node that is shutting down should
not be minting new long-lived tunnels.

`fenceTunnelEstablishment` is a shutdown hook at **order 94**, and the ordering is
the correctness argument, not a detail: after the listeners stop (80/90) so a
session that can still be drained is never refused needlessly, and before the
drain (100) so nothing establishes behind its back. The check sits after the dial
and immediately before the success reply, so the unavoidable check-to-register
window is microseconds rather than spanning a 10 s dial. Pinned by
`TestChaos57_FenceIsOrderedBetweenTheListenersAndTheDrain`, which fails if the
fence is moved to either side of its bracket.

The control matters as much as the gate here: a fence stuck raised refuses every
SOCKS5 session on a healthy node — a total protocol outage, far worse than the
window it closes — so `ControlFenceIsDownDuringNormalOperation` pins that it is
down in normal operation and that the test reset clears it (the PR3d
fence-pollution class), and `ControlFencedSOCKS5StillEstablishesWhenNotDraining`
drives the real establishment path to prove an unfenced session still relays and
still records its accounting.

**The process lesson**, and it is the second time this sweep produced one about
documentation rather than code: §25.6 recorded this as a deliberate residual
*with a stated reason*, and the reason was false. A "deliberately left" entry
carries more authority than an unexamined gap — it tells the next reader the
question was asked and answered — so a wrong one is worse than silence. The
entry has been struck rather than quietly deleted, so the record shows the claim
was made and refuted.
## 26. CHAOS-58 — The directory that accepts and then stops answering

**Date:** 2026-09-02 · **Domain:** authentication / LDAP + Active Directory ·
**Status:** shipped · **Gates:** `auth_ldap_stall_chaos_test.go` (9) ·
**Closes:** AU-5 (re-scored M→H), AU-14 (new)

### 26.1 Why this domain

CHAOS-47 gave the identity backends a posture for an unreachable directory and
built the machinery to make it cheap: fail closed, arm a provider-wide cooldown,
deny without dialing, recover on observed evidence. CHAOS-49 extended the same
primitives to the IdP registry rather than inventing a second dialect. Between
them the *unreachable directory* is a solved problem in this codebase, with one
health row, one metric family and one alert.

This sweep asked a narrower question: **which faults can arm that machinery?**

The answer is one sentence, and it is the finding. `authProbeGate` is armed from
`noteVerifyError`, which runs on the error `verify()` returns. So the cooldown
can only see a fault that **returns**. Every mitigation CHAOS-47 built is
downstream of a value that a hung call never produces.

### 26.2 The fault

`LDAPAuth.verify` dialed with a 10 s dialer timeout and then ran up to four
blocking operations — StartTLS, service bind, user search, user bind — with no
deadline of any kind. go-ldap's `Conn` defaults to `requestTimeout: 0`, and its
message loop arms a timer only `if requestTimeout > 0`, so **no timer existed at
all**. `Bind` and `Search` wait on `<-msgCtx.responses`, a bare channel receive.

A directory that completes the TCP handshake and then goes silent therefore
blocked the **request goroutine forever**. Not slowly — permanently, with no
error, no counter, no log line and no health-surface movement.

That fault is ordinary, not exotic: an overloaded directory, a firewall that
drops established flows without a reset, a half-open socket after a peer reboot,
a hung VM, a storage stall on the directory host. In every one of them the dial
**succeeds**, which is precisely why bounding the dial answered the wrong
question.

The blast radius is per request, not per outage. `verify()` is reached from the
proxy's per-request credential loop (`proxy.go`, via
`LDAPIdPProvider.ResolveIdentity` and `Config.VerifyAuth`), so every
cache-missing authentication pinned a goroutine, a socket, an FD, the client's
connection and a per-IP connection-limiter slot, permanently. FD exhaustion is
the recorded terminal state of PX-6 and WK-11, and CHAOS-54 measured what an
FD-exhausted node then does to the SOCKS5 accept loop — so this fault feeds an
amplifier this register already documents rather than staying contained.

**Reproduced before it was fixed** (a listener that accepts and never writes):
`Verify` was still blocked when the gate gave up, and the six defect gates were
each verified failing against the pre-fix tree.

### 26.3 The asymmetry that made it easy to miss

The correct pattern was already in the tree, one call away. The **admin
directory-test** endpoint (`ui_auth_ldap.go`) calls `conn.SetTimeout(8s)`
immediately after dialing. The **per-request production path** did not.

So the bounded path is the one an admin clicks occasionally, and the unbounded
path is the one every proxied request takes. That is the inversion worth
recording: a safe pattern existing in the repository is not the same as it
being applied where the load is.

### 26.4 The second layer, and why it is not belt-and-braces

Adding `SetTimeout` is the obvious fix and it is **not sufficient**.
`Conn.StartTLS` waits for the extended response through the message loop — which
the timer covers — and then runs `tls.Client(l.conn, config).Handshake()` on the
**raw socket**, outside the message loop and outside the timer. A directory that
ACKs StartTLS and then never negotiates TLS hangs with `SetTimeout` armed.

This was verified directly against the library, not assumed, and the check is
kept as a permanent **defect proof**
(`TestChaos58_SetTimeoutDoesNotBoundStartTLSHandshake`): it asserts that go-ldap
still behaves this way, so a future library release that fixes it fails the
build rather than leaving a backstop silently guarding nothing — the role
`BareGracefulStopIsUnboundedOnAWedgedStream` plays for CHAOS-56.

The second layer is therefore a whole-envelope watchdog that **closes the
connection**. Closing is what unblocks a deadline-less read — the same reason
`idleCopyCounted` hard-closes both conns on idle (CHAOS-03) instead of trusting
a deadline the blocked goroutine cannot observe. Two properties of go-ldap make
it safe and were read rather than assumed: `Close` is idempotent via
`setClosing`, and `messageMutex` is released before every network wait
(`sendMessageWithFlags` unlocks before sending; the StartTLS handshake runs with
it released), so a timer-goroutine close cannot deadlock the operation it is
rescuing.

The same gap exists on the admin test path — which set the per-message timeout
and was therefore *more* obviously bounded while carrying the one stage that
timeout cannot reach, on an endpoint that actuates an admin-supplied address on
demand. It gets the same watchdog under its own, deliberately generous, envelope
(a diagnostic should report a slow directory rather than clip it; its job is to
guarantee the handler goroutine is released at all).

### 26.5 The budget

One directory round trip is bounded **end to end at 10 s** — an envelope, not a
per-step allowance, so the historical 10 s dial timeout becomes the ceiling for
the whole flow rather than for its first step. Summing four per-operation
budgets would have produced a ~42 s worst case on a per-request path, which is
not a bound anyone would act on.

10 s is deliberately the **same** budget this process already gives one identity
resolution against an OIDC IdP (`http.Client{Timeout: 10s}`, `auth_oidc.go` /
`auth_oidc_flow.go`). Two identity backends answering the same question on the
same request path must not disagree about how long that decision may take —
CHAOS-53's rule for the two body-scan back ends, applied to the two credential
back ends. It is a constant for the same reason the JWKS stale ceiling is: a
per-deployment knob whose only use is widening it re-opens the fault.

The bound is unreachable on a functioning deployment — roughly 50x a healthy WAN
round trip, with authoritative answers cached for 5 minutes.

### 26.6 What changes for the operator

Nothing new to learn, which is the design goal. A stalled directory now produces
exactly what a down one produces: an `ErrorNetwork` the existing classifier
already reads as unreachable, so it arms the same cooldown, moves the same
`identity_backend` diagnostics row, increments the same
`culvert_auth_backend_*` series, and fires the same
`identity_backend_unreachable` alert. One additional rate-limited log line names
the backend and the budget, with a **bounded reason class only** — no directory
address and no server-supplied diagnostic on a per-request path (the WK-12/RS-5
rule).

The outage therefore becomes self-limiting: one probe per 3 s cooldown instead
of one permanently hung goroutine per request, recovering on observed evidence
with no restart.

Runbook: `docs/operator/ldap-directory-stalls.md`.

### 26.7 Gates

Nine, in three groups — the controls exist because a bound that fired on a
healthy directory would pass every defect gate while being strictly worse than
the defect it replaced.

| Group | Gate | Pins |
|---|---|---|
| Defect | `StalledDirectoryReleasesTheRequestGoroutine` | the call returns inside its envelope, fail-closed |
| Defect | `StalledDirectoryArmsTheUnreachableCooldown` | the fault is now visible to CHAOS-47 at all |
| Defect | `ArmedCooldownDeniesAStalledDirectoryWithoutDialing` | the outage is self-limiting, not re-paid per request |
| Defect | `StartTLSHandshakeStallIsBounded` | layer 2 is load-bearing (remove the watchdog and it hangs) |
| Defect | `AdminDirectoryTestIsBoundedOnAStartTLSStall` | the admin handler goroutine is released too |
| Defect | `ConcurrentStallsDoNotAccumulateGoroutines` | 12 concurrent stalls all return and unwind |
| Proof | `SetTimeoutDoesNotBoundStartTLSHandshake` | the library assumption layer 2 exists for |
| Control | `PromptDirectoryIsNeitherClippedNorGated` | a healthy directory is not clipped, and its deny does not arm the gate |
| Control | `WatchdogStopsWhenTheRoundTripCompletes` | a cancelled watchdog never closes a live connection |

All six defect gates were verified failing against the pre-fix shape; the proof
and both controls pass in both trees, which is what makes them controls.

### 26.8 Deliberately left

- **AU-3** (proxy-path bcrypt is not rate-limited) and **AU-11** (the credential
  provider loop is sequential, so N providers serialise their budgets on one
  request) are untouched and remain open. AU-11's worst case is now bounded
  rather than infinite, which lowers its severity without closing it.
- **The fail-closed posture is unchanged.** A directory that cannot answer
  denies; it never becomes an implicit allow.
- **No new metric.** A stall is an unreachable backend, and it now lands on the
  series that already means that. A second name for one operator action is the
  thing CHAOS-47's `identity_backend` naming note warns against.

### 26.9 The general rule this sweep produces

> A cooldown, breaker, or health gate armed by a returned error is blind to
> every fault that hangs. Bounding the call is what makes the mitigation
> reachable — the mitigation is not the bound.

Recorded as **AU-14** so the next backend added to the credential chain inherits
it instead of rediscovering it. The shipped backends satisfy it today: OIDC by
`http.Client{Timeout}` on every call, SAML because it is browser-mediated, and
LDAP as of this sweep.

---

## 27. CHAOS-59 — The intelligence-feed plane under origin outage

**Date:** 2026-09-03
**Scope:** the two legacy periodic feed loops — `internal/threatfeed`
(URLhaus + OpenPhish) and `internal/feedsync` (the UT1 community category
tarball) — under an unreachable, slow, rate-limiting or erroring third-party
origin, on a single node and across a fleet.
**Registry rows:** WK-5 (reopened and closed), WK-5b, WK-5c, WK-6 (partially),
WK-13b.

### 27.1 The finding in one sentence

**Culvert ships three periodic feed schedulers, and only the newest one backs
off, jitters, or reports** — so a transient outage at a public feed origin
froze threat intelligence for a full sync interval, a fleet-wide restart aimed
a synchronised fetch storm at that same origin, and neither condition was
visible on any surface an alerting rule can read.

### 27.2 Why it was invisible, and why that is this sweep's fault

The register has carried **WK-5** since the first sweep: a partially-failed
sync unconditionally replaced the lookup tables with only what had succeeded,
wiping the rest of the threat database in memory and — because `Sync` persists
immediately after — on disk. That was closed by the per-source carry-forward in
`applySync`, and the fix is correct.

It also **removed the only signal an operator had.**

Before carry-forward, a feed outage was catastrophic but LOUD in the one place
a Prometheus rule can read: `culvert_threat_feed_entries` collapsed toward
zero. After it, the entry count is held at its last-good value *by design*. A
node whose feed has not fetched successfully in three weeks and a node that
synced ten minutes ago export **byte-identical metrics**. The only surviving
difference — `threat_feed_sync_ok` — reached exactly one role-gated admin JSON
blob (`security_scan.go`), which nothing scrapes and no rule alerts on.

This is the §1 silent-degradation theme in a form worth naming, because it is
not a missing feature. It is a *fix that consumed its own detector*:

> A fix that converts a loud failure into a safe one inherits the obligation to
> replace the signal it silenced. Carry-forward made the failure survivable and
> simultaneously made it unobservable, and the second half was never done.

Freshness is the whole value of this control. A URLhaus entry is useful because
it was added hours ago; yesterday's list does not contain today's campaign.
"Serving last-known-good intelligence" is the right behaviour and an
indefinitely acceptable *state* only if someone is told.

### 27.3 The cadence defect (WK-5, WK-6)

Both loops were `time.NewTicker(syncInterval)` with the round's outcome
discarded:

```go
ticker := time.NewTicker(tf.syncInterval)   // 6h  (threatfeed)
for { select { case <-ticker.C: obs.SafeCall("threatfeed", tf.Sync) } }
```

A `time.Ticker` has no notion of failure, so **a failed round waits a full
interval** — six hours for threat intel, **twenty-four** for categories. The
fault that triggers it is not exotic: a DNS blip, a 503 from the provider, a
restarted upstream proxy, or a few seconds of packet loss on the customer's own
egress path. One such second bought six hours of frozen intelligence.

The evidence that this was understood and simply not applied here is in the
tree: `saas_feed_scheduler.go`, the *newest* feed loop, already implements
bounded exponential backoff, stable ±10% jitter, injectable clock/timer seams
and fake-clock tests. Two older loops never got it.

### 27.4 The severe shape: a cold start into an outage (WK-5c)

`Start` runs an immediate sync when the on-disk DB is empty — a fresh install,
a re-imaged node, a replaced data volume, or a node whose category store was
quarantined by §19's boot-path recovery.

If **that** round fails, the node is not serving stale intelligence. It is
serving **none**: an empty threat database, for up to six hours, while
`/health`, `/ready`, `/metrics` and the dashboard all report a completely
healthy gateway. Policy, category, DPI, AV and CDR are untouched, so this is a
coverage hole rather than an outage — but it is a security control that is
fully dark and silently so, and it is reachable by the single most ordinary
operational event there is: bringing up a new node.

Combined with §26.5, a rolling upgrade performed during a provider incident
brings the *whole fleet* up in this state simultaneously.

### 27.5 The fleet shape: a self-inflicted herd (WK-13b)

`time.NewTicker` fires at a fixed offset from process start. Nodes that boot
together — a rolling upgrade, a compose restart, a hypervisor recovering a rack
— therefore sync together, **forever**, with no mechanism that could ever
spread them.

The origins are the aggravating factor. They are public, third-party, shared by
every Culvert deployment, and one of them serves a 50+ MB tarball from
`raw.githubusercontent.com`. The ordinary answer to a synchronised fleet
hammering such an endpoint is rate-limiting or blocking of the customer's
egress IP — which **produces** a feed failure. And the missing backoff then
held every node in the fleet at that failure for a full interval, at which
point they retried in lockstep again.

That is a closed loop in which the scheduler manufactures the outage it cannot
recover from promptly. Neither half is dangerous alone; together they are the
finding.

### 27.6 What shipped

**`internal/feedsched`** — one shared cadence engine, deliberately shaped like
the `saasFeedScheduler` that already existed rather than invented:

- delay after a clean round = the configured interval, offset by a per-node
  jitter fraction **drawn once** (stable within a node, spread across a fleet;
  re-rolling per tick would let nodes drift back into phase and would make the
  cadence untestable);
- delay after a failed round = bounded exponential backoff from `BackoffMin`,
  doubling, clamped at `BackoffMax`, reset by the first success;
- **Both the retry FLOOR and the CEILING are clamped to the live interval.** A
  ceiling above the interval would mean a failing feed attempts *less* often
  than a healthy one — the recovery mechanism becoming an extra delay. A caller
  cannot express that shape. Clamping the ceiling ALONE is not sufficient, and
  the first version shipped in this PR got it wrong (Codex review): with an
  interval shorter than `BackoffMin` — an admin running `-feed-sync-interval
  1m` against the 5 m floor — the ceiling clamped down to 1 m and was then
  raised straight back to the floor, so a failed round waited **five times
  longer** than a healthy one. That is the bare-ticker regression this whole
  section exists to remove, reintroduced inside its own fix, and the original
  gate missed it because it used an interval comfortably above the floor. The
  invariant is one sentence and it has to hold at every interval: *a retry is
  never later than the configured cadence.*
- the wait is interruptible: ctx cancellation returns from inside a backoff, so
  shutdown never waits one out;
- a **panicking round is a failed round**, contained at the iteration per
  `internal/obs`'s rule, so a hostile feed body backs off instead of either
  killing an in-line gateway or hot-looping.

Retries are unbounded in COUNT and bounded in RATE. That does not violate
"avoid infinite retries" for the reason §23 recorded: the retry is never silent
(every failure is counted, classified and — past the threshold — alerted), and
a feed that *stopped* retrying would be strictly worse, freezing intelligence
permanently on one transient error.

**Threat feed:** 6 h interval, retries 5 min → 1 h. **Category feed:** 24 h
interval, retries 15 min → 2 h.

**`threatfeed_health.go`** — the staleness plane, in the shape
`storage_health.go` / `ca_health.go` / `socks5_health.go` already use, with no
new operator vocabulary:

- five `culvert_threat_feed_*` series (`last_success_timestamp_seconds`,
  `stale_seconds`, `sync_ok`, `sync_failures_total`,
  `consecutive_sync_failures`), emitted **only when the feed is configured** —
  the §22 rule, since `sync_ok 0` on a node that never ran the feed is
  indistinguishable from a broken one and the paging rule is `== 0`;
- the `threat_feed` operator-contract row;
- a `threat_feed_stale` alert, **fire-once per episode**, cleared only by an
  OBSERVED clean round, and **also evaluated once at startup** for the
  warm-but-already-stale database (a node that was powered off, or one whose
  feed has been failing across restarts). Without that startup pass the alert
  waited on a failed round, and the first round is a full jittered interval
  away — so nothing fired for the window in which the gateway was enforcing
  against stale intelligence, and nothing fired at all if that round then
  succeeded. It routes through `deferStartupAlert` because the webhook store is
  loaded by a LATER startup slice: firing directly would fan out to an empty
  subscriber list and vanish, which is precisely the failure that queue exists
  to prevent. The never-synced branch is deliberately excluded from the startup
  pass — at boot its age is ~0, and a node that has simply not finished its
  first sync is not a fault.

`culvert_threat_feed_sync_ok` derives from the **persisted** `lastSyncErr`, not
from the in-memory consecutive-failure count. The count is deliberately not
persisted (the true run length across restarts is unknowable), so a gauge keyed
on it reported a green `1` after a restart from a database written by a failed
sync — for hours, until the next scheduled round (Codex review). Deriving it
from the persisted error also makes `/metrics` and the admin API's
`threat_feed_sync_ok` agree by construction rather than by coincidence.

Failures are classified into a **bounded reason class** (`urlhaus`,
`openphish`, `urlhaus+openphish`, sorted so it is stable). The verbose summary
stays on the role-gated admin API and in the rate-limited log, because
`Dispatch` dedups on `event + ":" + Detail` and the summary embeds the feed URL
and — for a transport failure — the ephemeral local port, so a raw detail would
defeat the dedup window by construction and evict real threat alerts from the
500-entry retry queue (the WK-12/RS-5 defect).

### 27.7 Rejected alternatives, recorded

- **No `/readyz` row and no `/healthz` failure.** A node with stale threat
  intelligence is a fully serving gateway; failing readiness would pull healthy
  gateways out of rotation over a degraded cache. Same judgement §19 records
  for the community category store, for the same reason.
- **No fail-closed toggle.** Blocking traffic because a third-party feed is
  unreachable converts a provider's outage into the customer's. The threat feed
  is an additive deny-list on top of default-deny policy, not the control that
  decides whether a request is allowed. This is the deliberate asymmetry with
  WK-1b/WK-2b: those govern a scanner's verdict on content in flight; this
  governs how fresh a deny-list is.
- **Staleness at 2× the interval, not 1×.** One missed window is exactly the
  transient the new backoff exists to absorb — the ladder reaches its 1 h
  ceiling long before 2 × 6 h elapses, so by the time this fires the feed has
  failed a dozen bounded retries. But the **never-synced** case is measured
  from process start against a 30-minute grace instead, because it is the
  severe shape (§26.4) and its usual cause is a deploy-time misconfiguration an
  operator should hear about in minutes.
- **The category feed gets the cadence fix but not an alert.** Its last-good
  BadgerDB keeps serving and category staleness is not a security control;
  adding a second staleness dialect for it would be operator noise. Recorded as
  the open half of WK-6.

### 27.8 Gates

`internal/feedsched/feedsched_test.go` (11), `internal/threatfeed/sync_cadence_test.go` (10),
`internal/feedsync/sync_cadence_test.go` (5), `threatfeed_health_test.go` (13).

The cadence defect gates fail against the bare-ticker shape **by
construction**: a `time.NewTicker(interval)` returns the interval after a
failed round, and the gates require a strictly smaller delay. That was
**verified empirically, not asserted** — reintroducing the pre-fix shape
(`NextDelay` returning the interval regardless of outcome) fails six gates
across all three packages (`TestNextDelay_SuccessUsesInterval_FailureBacksOff`,
`TestNextDelay_SuccessResetsBackoff`, `TestRun_ImmediateRoundThenBackoffOnFailure`,
`TestRun_PanickingRoundIsContainedAndChargedAsFailure`, and
`TestScheduler_FailedRoundRetriesLongBeforeTheInterval` in both feed packages),
while every CONTROL correctly still passes — which is what makes the controls
controls rather than more defect gates. The staleness-plane gates have no
pre-fix counterpart to fail against: those surfaces did not exist. Four CONTROLS
guard the direction of the fix, because each defect gate has a trivially worse
way to pass:

- `TestRetryRateIsBounded` / `TestRetryBoundsAreSaneRelativeToTheInterval` — a
  scheduler that retried *immediately* satisfies "a failure is retried before
  the next interval" while being a hot loop against a third-party origin.
- `TestBackoffCeilingIsClampedToInterval` — a ceiling above the interval turns
  recovery into an extra delay.
- `TestThreatFeedStale_HealthyFeedNeverAlerts` — an alert that fired on every
  round passes every staleness gate while being useless.
- `TestScheduler_ColdStartArmsAnImmediateRound` also pins the *other* half: a
  warm feed must NOT re-fetch at boot, or a fleet restart stampedes the origins
  regardless of jitter.

Four gates pin defects **introduced and caught inside this work**, which is
worth recording as a pattern rather than as embarrassment — three of the four
are the section's own findings reappearing one level down:

- `TestApplySync_CarriedForwardEntriesAreCounted` — counting entries before the
  carry-forward merge reported a partially-failed sync as a nearly-emptied
  feed, precisely the false alarm carry-forward exists to prevent.
- `TestBackoffNeverExceedsAnIntervalShorterThanTheFloor` — the floor-clamp
  defect above: §26.3's "a failed round waits longer than a healthy one",
  rebuilt inside the fix for it.
- `TestThreatFeedSyncOK_SurvivesARestartFromAFailedSync` — a freshness gauge
  that reads healthy while the feed is known to be failing: §26.2's "the
  detector says fine", rebuilt inside the detector.
- `TestThreatFeedStale_EvaluatedAtStartupForAWarmButStaleDatabase` — an alert
  that cannot fire in the window it exists for, with a CONTROL (a fresh install
  and a node that synced ten minutes ago must both stay silent) so an alert
  firing on every boot cannot pass it.

### 27.9 Residual risk

- **The main-side `saasFeedScheduler` is a third instance of this engine** and
  was not migrated onto `internal/feedsched`. It is already correct — it is the
  shape the package copies — and it additionally owns a config-change wakeup
  bound to its runtime. Migrating it is a refactor, not a chaos fix, and
  bundling it here would have mixed the two. Recorded as a follow-up.
- **A DP with no direct feed egress reports never-synced forever.** Such a node
  receives coverage through the CP's config snapshot (`cluster-sync` entries,
  which local syncs never replace), so the state is correct but the alert is
  noise on those nodes. The runbook says to suppress it there; a per-node
  "feed egress not expected" declaration is not modelled.
- **Feed content trust is unchanged.** These are unsigned plaintext lists over
  TLS; a compromised or hijacked origin can add entries (over-blocking) or
  withhold them (under-blocking). Signing is out of scope here and is the
  problem the signed SaaS feed solves for its own path.
- **No age ceiling on carried-forward entries.** A permanently-failing feed
  serves its last-known-good list indefinitely. That is the fail-safe direction
  (over-blocking, and a stale entry is still a real past threat), and it is now
  visible rather than silent — but nothing expires it.

### 27.10 The process lesson

§21 stated it for back ends, §22 for listeners, §23 for decisions, §24 for
documented residuals. This sweep adds one about **fixes**:

> Making a failure safe is not the same as making it observed, and a fix that
> converts a loud failure into a quiet one has *taken on a debt*. Carry-forward
> was the correct remedy for the stale-erase defect, and it silenced the entry
> count — the one signal that had made the defect visible. Two sweeps later the
> register still recorded WK-5 as closed. It was half closed: the failure could
> no longer hurt you, and it could no longer be seen.

The corollary is a review question worth asking of every degradation fix in
this register: *what signal did the old, worse behaviour emit, and what emits
it now?*
## 28. CHAOS-60 — The GeoIP resolution chain under a slow or unavailable resolver

**Date:** 2026-09-07
**Scope:** `geo.LookupCached` (the per-request policy accessor), `resolveHost`,
`internal/geoip`'s IP→country cache, and the destination-country tracker.
**Shipped:** `geoip.go` (single-flight + a genuinely cache-only accessor),
`geoip_resolve_health.go` (bounded warmer + health plane), `policy.go`
(unresolved-country counter, two corrected comments), `metrics.go` (six series),
`geoip_resolve_chaos_test.go` (15 gates).

### 28.1 Why this domain

Every earlier sweep in this register found its defect on a path that was
already *suspected*: a CA that expires, a lease that cannot be re-acquired, a
hook that does not return. This one started from the opposite end — a row in
this document that said a path was **safe**.

Row WK-3 read: *"GeoIP cache-miss on the policy hot path fails closed;
`LookupCached` never blocks on DB/DNS."* Marked ✓. It cited `geoip.go:84-93`.
Those lines are now the body of `hostIPCache.get`, a function that did not
exist when the row was written. The citation had drifted, and so had the claim.

### 28.2 GEO-1 — the accessor named "Cached" took an uncancellable DNS round trip

`matchDestNorm` (policy.go) evaluates a country-scoped rule with:

```go
// Geo-IP country check — cache-only to avoid blocking the request goroutine.
code, cached := geo.LookupCached(host)
```

`LookupCached` called `resolveHost(host)`, and `resolveHost` on a cache miss
called `lookupPublicHostIP` → `net.LookupHost`. `net.LookupHost` takes **no
context**. It runs to the system resolver's own budget — `resolv.conf`
`timeout` × `attempts` × nameservers, commonly 10–40 s on a blackholed
resolver — and there is no way to abandon it.

That ran **inside the request goroutine**, during policy evaluation, which
happens before the plain-HTTP path's `upstreamRequestTimeout` is armed and on
the CONNECT path has no overall budget at all. For the duration the request
holds its goroutine, the client's TCP connection, its per-IP connection slot
(`internal/connlimit`), and a resolver descriptor.

The same file said so, 380 lines earlier, in `Evaluate`:

```go
// the scan can block (matchDestNorm → geo.LookupCached → DNS on an uncached
// DestCountry host; …), so the lock must NOT be held across it
```

Two comments in one file, one saying the geo check cannot block and one
explaining the locking discipline required *because* it can. Both were written
in good faith; the second is the one that was true.

There was no single-flight either — the code said so explicitly
(*"Concurrent misses for the same host may resolve in parallel; last write
wins, which is benign"*). It is benign for correctness and not for load: the
negative entry that stops the next lookup is only written when a lookup
**returns**, so during exactly the window where lookups do not return, nothing
suppresses the next one. A proxy is therefore a 1:1 amplifier of client
request rate into DNS query rate (×2 for the A/AAAA pair Go issues), aimed at
a resolver that is by hypothesis already failing. A reconnect storm against a
single host — one of this document's own simulate-list entries — is the worst
case, and it is the case a caching layer looks like it should have covered.

Measured against the pre-fix tree by `TestChaos57_ConcurrentMissesResolveOnce`:
**50 concurrent misses for one host → 50 resolver invocations.**

### 28.3 GEO-2 — enforcement was fed by a telemetry sampler

The blocking resolution is only half the chain. After it, `LookupCached` calls
`geoip.LookupCachedByIP`, which — correctly, and as documented — *never*
performs a database lookup. So the country half still had to be populated by
someone.

On the request path, exactly one thing populated it: `trackDestinationCountry`
(proxy.go), whose own doc comment reads *"Dashboard stats are best-effort:
when the tracker pool is saturated the sample is dropped rather than queued."*
It runs on the **allow** branch only, after the policy decision, behind a
256-slot drop-on-full semaphore.

So the enforcement of a country-scoped policy rule depended on a
dashboard-statistics goroutine having won a semaphore slot on an earlier
request. Three consequences, none of them visible:

1. Under enough concurrency to saturate that pool the samples are dropped, the
   country stays unknown, and **every country-scoped rule silently stops
   matching** — the rule's hit counter stays at zero while the traffic it
   describes flows.
2. If the first request to a host is BLOCKED, the tracker never runs at all,
   so nothing on the enforcement path ever learns that host's country.
3. The one signal an operator could have read — the rule's hit count — reads
   identically to "no traffic matched this rule", which is the reading an
   operator will reach for first.

This is the §21/§22 theme in a new costume: a security control wired to a
lossy path, where the loss is the designed behaviour of the path and a
correctness requirement of the control.

### 28.4 What shipped

**The accessor is genuinely cache-only.** `resolveHostCached` answers from an
IP literal or a live cache entry and never touches the resolver. A miss returns
`("", false)` — the fail-closed answer the call site already documented — and
arms a warm. The distinction between *"unknown, nothing cached"* and
*"resolved to nothing usable"* is now explicit in the return, because only the
first is worth warming; a negative-cached host is governed by its TTL, not by
the request rate (`TestChaos57_NegativeCachedHostDoesNotWarm`).

**The warm is BOUNDED, and deliberately not by a deadline.** `geoWarmSem`
(64, drop-on-full) is the bound. A context deadline was considered and
rejected: under the cgo resolver a cancelled lookup returns to the caller while
the OS thread stays blocked in `getaddrinfo`, so a deadline would release the
semaphore slot without releasing the thread — turning a bounded goroutine pool
into an unbounded thread pool, which is worse than the fault it treats. Holding
the slot for the **true** duration of the call is what makes the bound real.
A queue was rejected for the reason drop-on-full is used everywhere else here:
it converts a resolver outage into unbounded memory and unbounded staleness.

**Misses are single-flighted, and the host is claimed BEFORE a pool slot is
taken.** `hostIPCache.begin`/`finish` elect one leader per host; every
concurrent caller waits on its result (the jwksCache shape from
`auth_oidc_flow.go`). The warmer takes that claim **synchronously**, before it
consumes a slot or spawns anything, so N concurrent callers for one host cost
exactly one slot and the other N−1 return having touched nothing. The ordering
is not incidental — see §28.8, where getting it wrong re-entered this
document's own finding.

**The warm fills BOTH caches.** It calls `geoip.LookupByIP`, not just the
resolver, so the enforcement path now owns its own populator and no longer
depends on `trackDestinationCountry` having run. That is the GEO-2 fix, and it
is why the warm also fires on the *country-half* miss (host→IP cached, IP never
geolocated) — the shape that was otherwise permanently undecidable on a node
whose sampler is saturated.

**The release is bound to the channel the slot came from.** `warmGeoHost`
captures `sem` rather than re-reading the global, so a goroutine outliving a
swap cannot return a slot to a channel it never took one from. This was found
by the gates themselves: the first draft read the global on release, and two
saturation gates passed or failed on goroutine timing.

**It is observable.** Six series, emitted **only when a GeoIP database is
loaded** — the socks5/cluster_ca rule, because a flat `0` on a node that has no
GeoIP is indistinguishable from a node whose geo rules have stopped enforcing,
and every paging rule here is `> 0`:

| Series | Reads |
|---|---|
| `culvert_geo_warm_total` | warms started off the request path |
| `culvert_geo_warm_dropped_total` | warms refused — the pool was saturated |
| `culvert_geo_warm_failed_total` | warms that found no usable public address |
| `culvert_geo_warm_saturated` | 1 while warms are being dropped |
| `culvert_geo_warm_inflight` | warm goroutines running |
| `culvert_geo_policy_unresolved_total` | **country-rule evaluations that did not match because the country was unknown** |

The last one is the security-relevant one and the one that did not exist in any
form before: it is the operator's only way to see a geo rule evaluating against
an unknown country. A low rate is expected (one per host per cache lifetime,
the warm being off-path); a rate that tracks request rate means enforcement is
not converging, and it will be accompanied by `warm_dropped_total` climbing.
Saturation onset is logged immediately, then rate-limited to one line per
minute, then one recovery line naming the suppressed count — signal in the log,
magnitude in the counter (socks5_health.go's discipline). Recovery clears on
**observed evidence** (a warm that actually got a slot), never on elapsed time.

No new alert event was added: the operator vocabulary is unchanged and the
metrics carry the state. Recorded as a deliberate choice, not an oversight.

### 28.5 What is deliberately left

- **WK-3c — the first-request window is an OWNER DECISION.** A country-scoped
  rule still does not match on the first request to a host whose country is not
  yet cached. For an allow-rule that is fail-closed (a user-visible block that
  clears on retry); for a deny-rule it is traffic falling through to a
  lower-priority rule. CHAOS-60 does not change this in either direction — it
  makes the window converge in **one request** instead of depending on whether
  a dashboard sampler won a slot, and it makes the window **countable**.

  The evidence for whoever decides: `geoip.LookupByIP` is an **mmap read of a
  local file**, not I/O that can block, so performing it inline on the policy
  path is affordable and would close the window entirely for any host whose
  address is already cached. That is not shipped here because it changes when a
  rule first matches — a policy-semantics change, not a resilience fix, and this
  register's rule is that a security posture is never flipped unilaterally. The
  fuller version of the same decision is what "unknown country" should MEAN in
  policy (today: "does not match"; the alternative is an explicit deny-on-unknown
  option per rule), which is a product decision.

- **`LookupFull` still blocks**, by design. Its two callers are bounded some
  other way — the destination-country tracker (256, drop-on-full) and node
  enrollment (admin-rate) — and both may block. The contract is now written
  down on `resolveHost` itself, so a future caller has to opt into it knowingly.

- **A private-only or unresolvable host re-warms once per negative TTL**
  (30 s). On an estate with many internal hostnames that is a steady low rate of
  warms that can never succeed. It is bounded by the semaphore and counted by
  `warm_failed_total`; a per-host suppression window was judged not worth the
  state.

- **The MaxMind database itself is still unmonitored proactively** — WK-4's
  residual, untouched here.

### 28.6 Gates

`geoip_resolve_chaos_test.go` (15). **Five defect gates were verified failing
against the reintroduced pre-fix shape**, with the numbers quoted above:

| Gate | Pre-fix result |
|---|---|
| `LookupCachedNeverBlocksOnDNS` | blocked 2.0006 s against a 2 s resolver |
| `ConcurrentMissesResolveOnce` | 50 concurrent misses → 50 resolver invocations |
| `WarmConvergesWithoutTheDashboardSampler` | no warm armed |
| `WarmFiresWhenOnlyTheCountryHalfIsMissing` | no warm armed |
| `WarmIsBoundedAndDropsWhenSaturated` | no warm armed |

`PreFixShapeBlocksOnDNS` is a permanent **defect proof**: it rebuilds the
pre-fix body inline and requires it to still block, so the primary gate can
never quietly start proving less than it claims (the
`BareGracefulStopIsUnboundedOnAWedgedStream` pattern from §24).

Two **controls**, because the gates above are all satisfiable by a warmer that
does nothing: `ControlWarmerActuallyResolves` requires the warm to perform the
resolution and the engine lookup and populate the cache;
`ControlDisabledGeoIPDoesNothing` pins the shipped default — with no `.mmdb`
loaded, no resolution, no goroutine, no counter movement. A sixth gate,
`MetricsAppearOnlyWhenGeoIPIsLoaded`, pins both halves of the exposition rule.

One gate is against a defect **introduced by the fix and caught inside it**.
`APanickingLeaderStillPublishes`: the single-flight's leader owns the slot, and
the first draft published after the call rather than in a `defer`. A leader
that returns without publishing strands every current follower *and* leaves the
slot occupied, so every LATER caller for that hostname becomes a permanently
blocked follower — one panic in the resolver seam would take that host out for
the life of the process, which is a strictly worse failure than the unbounded
block being fixed. Verified failing against the non-deferred shape
("the follower was stranded by a leader that returned without publishing").

Every bounded wait in the file is bounded *for a reason*: the first draft used
bare channel receives, and against the pre-fix tree three gates hung to the
package timeout instead of failing with a message. A gate that hangs tells a
future reader nothing.

### 28.7 The process lesson

§24 was about documented residuals. This one is about **documented safety**:

> A register row that records a path as safe is a claim with a shelf life, and
> nothing in the build checks it. The row here was accurate when written and was
> invalidated by an ordinary, well-executed performance change that put a cache
> in front of the blocking call without removing it — a change that made the
> defect *less* likely to be observed, which is precisely why the claim survived.
> The line-number citations drifted at the same time and in the same direction:
> the row still pointed at real code, so it still looked checked.

The practical consequence for this register: when a sweep confirms a ✓ row,
it should confirm it against the code, not against the row. Two of the three
sweeps' worth of confidence in this path came from re-reading the row.

### 28.8 Review follow-up — the fix re-entered its own finding

Codex raised a **P1** against the first version of this change, and it was
right. The finding is worth recording in full because it is the same shape as
GEO-2, one level down.

`warmGeoHost` began with:

```go
if resolvedHostCache.resolving(key) { return }   // (A) pre-CHECK
select { case sem <- struct{}{}: default: drop } // (B) take a slot
go func() { … resolveHost(key) … }()             // (C) the claim is registered HERE
```

The claim is registered by `begin`, which runs inside `resolveHost` — in the
**goroutine**, at (C). So (A) is a pre-check against a claim that does not
exist yet, and the window between (A) and (C) is a goroutine scheduling round.
Concurrent policy evaluations for one uncached hostname — precisely the
reconnect-storm shape this change exists to survive — all pass (A), all consume
a slot at (B), and all but one park as **followers holding those slots** for
the resolver's full delay.

One popular destination could therefore drain the whole 64-slot pool, and every
*unrelated* host's warm would be dropped and its country rule left unresolved.
That is the GEO-2 degradation — country rules silently not enforcing because a
bounded pool ran out — re-entered through the fix for GEO-2.

The fix is an ordering one: `begin` is now called **synchronously in the
caller**, before any slot is taken. A non-leader returns immediately having
touched nothing; a leader that then cannot get a slot **hands the claim back**
(`finish` with a nil result, deliberately *without* a cache write — nothing was
learned, and a negative entry would suppress the retry for a full TTL over a
transient pool shortage). `finish` was made idempotent with a `sync.Once` so
every hand-back path can call it unconditionally, which is what turns "a claim
is never stranded" from a proof about ordering into a local property.

**The gate that missed it is the more instructive part.**
`WarmSkipsAHostAlreadyBeingResolved` claimed the single-flight, and passed — it
pre-claimed the slot synchronously in the test and so only ever exercised the
*post*-registration state, never the window. The first replacement gate missed
it too, for a different reason: with all callers spawned as goroutines, the
leader usually wins the race to register, so a single trial passes a broken
build most of the time. It is now a **many-trial** gate (60 trials × 32
concurrent callers, the `TestChaos54_StopIsPromptDuringAcceptBackoff`
precedent) — the invariant asserted per trial is exact (one host, at most one
held slot) and only the trial count is statistical. Against the pre-fix shape
it fails at trial 6: *"32 concurrent warms for ONE host held 2/8 pool slots."*

A second, smaller defect surfaced on the way: under `-race`, a warm goroutine
outlives the test body that armed it, and `defer restore()` runs **before** any
`t.Cleanup` — so the resolver seam was being restored while a live warm was
still reading it. Production never reassigns those vars, so this is harness-only,
but `stubResolver` now waits for in-flight warms before restoring: a seam must
outlive its users.
## 29. CHAOS-57 — Credential verification as an unbounded, unauthenticated CPU sink

**Date:** 2026-09-06
**Scope:** the per-request proxy-authentication path for local accounts —
`Config.verifyAuthFrom` (store.go), its two data-plane callers
(`resolveRequestAuth` in proxy.go, `socks5Negotiate` in socks5.go), and the
verification result cache.

### 29.1 Why this domain

The register has carried **AU-3** as an open Medium since the first sweep,
framed as *"correct-username + N wrong-passwords is a cache miss every time →
full ~100 ms bcrypt per request"*. That framing was too narrow in the one
direction that mattered: it described an attack that requires knowing a valid
username, and it categorised the consequence as latency.

**The cheap branch is the wrong-username branch, and the consequence is a
gateway-wide outage.**

`verifyAuthWithSnapshot` ran an unconditional `bcrypt.CompareHashAndPassword`
against a fixed dummy hash whenever the presented username did not match. That
comparison exists for a good reason — RISK-008 equalises the wrong-username and
wrong-password paths so neither is distinguishable by timing — but it sat
**before** the result cache and never populated it, so a flood of *distinct*
usernames was a guaranteed cache miss every single time. No valid username, no
credential, no knowledge of the deployment.

And nothing stood in front of it. The three front-door limiters that could have
capped the arrival rate — the per-IP connection limiter, the request rate
limiter (`-rate-limit`, default **0 = off**) and the IP filter — **all ship
disabled**. Nothing capped concurrency either, so N simultaneous requests put N
goroutines into bcrypt at once and the scheduler shared every core between them.

### 29.2 The measurements

Taken on the reference 4-core box against the pre-fix tree. The probe that
produced them is preserved as the defect gates.

| | |
|---|---|
| one wrong-username attempt | **79.6 ms of exclusive CPU** |
| one cached successful authentication | 1.5 µs |
| **amplification** | **51,631×** |
| sustained attempt rate at full saturation | **66/s** |
| bytes on the wire to achieve that | **~13 KB/s** |
| degradation to other CPU work, 64 attacker connections | **15.6×** |

So roughly **thirteen kilobytes per second from one unauthenticated source
consumes an entire four-core gateway**, and everything else the appliance must
do per request — TLS handshakes, DPI scanning, policy evaluation, relay copying
— competes for what is left. That is a remotely triggerable denial of service
against the data plane, in the shipped default configuration.

The arithmetic generalises without needing a benchmark: one request buys ~80 ms
of a core, so **12.5 × GOMAXPROCS requests per second saturates the machine**.

### 29.3 Two amplifiers found alongside it

**AU-3c — the cache evicted a random victim.** At capacity the cache scanned
for an expired entry and, finding none, dropped *an arbitrary one* — a Go map
range that stops at the first key, i.e. a uniformly random **live** entry. A
flood of distinct passwords under a known username therefore displaced other
clients' cached positives. Measured: an honest user's cached credential
survived a flood of 1× the cache capacity and was **reliably gone by 2×**,
after which that user paid a full ~80 ms bcrypt on *every* request. The
attacker's amplification lands on legitimate traffic. This is precisely the
finding `internal/authstate` closed for the login-state stores, standing
unchanged one subsystem over.

**AU-3d — the scan is O(cache) under the process-wide mutex.** The
expired-entry scan walks the whole 5,000-entry map whenever nothing has
expired, which is exactly the state a flood keeps it in. Measured **64 µs per
insertion**, serialised against every other authentication in the process.

### 29.4 The finding inside the fix

The obvious fix — gate the branch that runs the expensive comparison — **is a
security regression**, and it is subtle enough that it was written first.

RISK-008's dummy comparison exists so that a wrong username and a wrong
password take the same time. A governor consulted only on the branch that
reaches the real hash makes "over budget" **fast for a wrong username and slow
for a wrong password**, handing back exactly the username-enumeration oracle
the equalisation removed. The bound would have been bought with the
vulnerability it was protecting.

So the rule is: **the admission decision is taken before the username is
compared, and does not depend on it.** The code reads as *answer for free if you
can, then buy permission to spend 80 ms, then look at the credential*:

1. **Cache first, unconditionally** — ahead of the username comparison. This
   changes no verdict (entries are only ever stored for the configured
   username, so a wrong username was always a miss and still is) and costs the
   same one HMAC + one map probe either way, but it means a client riding a
   warm cache never consumes a slot. Without it, a legitimate high-rate
   deployment would be throttled by a bound on work it is not doing.
2. **Admission second**, username-independent.
3. **Refusal is a deny** — fail closed.
4. **The slot is held across both branches**, released by `defer` so a panic
   inside bcrypt cannot leak it.

`TestChaos57_AdmissionDecisionIsUsernameIndependent` is written to fail against
the asymmetric shape, and was verified doing so.

### 29.4b The second finding inside the fix — an authentication BYPASS

Raised against this change during self-review, before it left the branch, and
it is the more serious of the two.

Moving the cache lookup ahead of the username comparison (§25.4 step 1) is
necessary — without it a client riding a warm cache would consume a
verification slot, and the governor would throttle work it is not doing. But
the pre-existing key derivation hashed `user + ":" + pass`, which is **not
injective** once either field can contain the separator:

```
("admin",   "a:b")  ->  "admin:a:b"
("admin:a", "b")    ->  "admin:a:b"     <- same key, different credential
```

That was **latent and unreachable** while the cache was consulted only *after*
the presented username had been confirmed equal to the configured one: every
reachable key then shared the same `user + ":"` prefix, so distinct passwords
gave distinct keys. Moving the lookup earlier makes the ambiguity reachable
with a **caller-chosen username**, and it is then an authentication bypass —
with a colon anywhere in the configured password, an attacker presents a
re-split of the same concatenation, hits the cached POSITIVE, and is
authenticated with a caller-controlled subject:

```
configured:  user="admin"    pass="a:b"
presented:   user="admin:a"  pass="b"     -> cache hit, ok=true, Sub="admin:a"
```

Reproduced end to end against the branch before it was fixed. Passwords
containing a colon are entirely ordinary, so this needed no unusual
configuration.

`cacheKey` now **length-frames** each field, making the encoding injective, so
no two distinct `(user, pass)` pairs can share a key regardless of separator
placement. The derivation is process-local (the HMAC key is random per start)
and the cache is memory-only, so changing the encoding invalidates nothing that
outlives a restart. Pinned by `TestChaos57_CacheKeyIsInjective` (unit) and
`TestChaos57_ReSplitCredentialCannotAuthenticate` (end to end); both were
verified failing against the concatenation-based key.

**The lesson is about the shape of the change, not the bug.** Reordering two
steps changed the *reachable input domain* of a hash that was only ever safe
because of the ordering — and nothing in the original code recorded that
dependency, because at the time it was not a dependency but a coincidence. A
reordering is not a refactor when a downstream invariant is holding the old
order up.

### 29.4c The third finding inside the fix — the governor denying service itself

Found by CI, not by the local suite, and it is the most instructive of the
three because the fix was behaving exactly as designed and the design was
wrong.

The per-client rule originally REFUSED a client already at its cap, immediately.
That reads as obviously correct — "one source, one slot" — until you ask what a
single ordinary client actually does. A browser opens six to eight parallel
connections. When their cached verification results expire together, all of them
present the same credential at the same moment, and all but one were **denied**:

```
6 concurrent VALID authentications from one workstation
  -> 1 admitted, 5 refused (reason: per_client)
```

Measured on the real authentication path. No attacker, no flood, no load —
just a workstation behaving normally. **A control built to stop an attacker
denying service was denying it unprompted**, which is precisely the failure the
CONTROL gates in this file exist to catch; they missed it because they only
exercised the *cached* path, where the governor is never consulted.

It surfaced as a `Deep · determinism` failure on CI and not locally, and that
difference is the tell: whether a client's parallel requests overlap enough to
collide depends on machine load, so the same code passed a quiet box twice
(non-race and race) and failed a loaded runner.

**The fix is that a client at its cap WAITS for its own earlier verification
rather than being refused.** Fairness is untouched — the cap still bounds how
many slots one source holds *at any instant*, which is the whole property — and
only the excess changes: serialised behind its predecessor (~80 ms each)
instead of rejected. Parked waiters are counted against the SAME bounded
waiter budget as the global queue, so the goroutine bound this engine insists
on is unchanged; and the wait is bounded, so a burst deeper than roughly
`maxWait / verification cost` (about a dozen from one client) still ends in a
refusal, which is stated in the runbook rather than implied away.

The wakeup is a close-and-replace generation channel read under the same mutex
that releases the reservation, so a release can never be missed by a caller
about to park.

Gates: `TestClientAtItsCapWaitsRatherThanBeingRefused` and
`TestWaitingDoesNotWidenThePerClientCap` (engine, the pair — one proves waiting
happens, the other proves the cap still binds while a caller waits), plus
`TestChaos57_OneWorkstationsParallelRequestsAreNotDenied` end to end through the
real authentication path. The end-to-end gate uses a long wait budget
deliberately: the property is "none of them is refused", and tying it to how
long bcrypt happens to take on a given build would make it fail under `-race`
for a reason unrelated to the property.

**The lesson:** "one source, one slot" is a correct fairness rule and an
incorrect *admission* rule. Fairness is about what a client may HOLD; admission
is about what happens to the rest. Conflating them turned a bound into a denial.

### 29.4d The fourth finding inside the fix — the alert that could never fire

Raised by Codex review against the observability plane, as a P1, and correct.

The refusal episode was cleared by any FAST-PATH admission. The reasoning
behind that was sound as far as it went — a queued admission proves nothing, a
fast one proves a slot was free — but it stops one step short: **a slot being
free at an instant is not evidence that refusals have stopped**, and during a
sustained flood the two coexist by construction. Every in-flight bcrypt
eventually releases its slot, so some arrival wins the fast path roughly once
per comparison while its siblings continue to be refused.

The consequence is that the whole observability plane failed at its one job:

- the episode restarted every ~80 ms and so could **never** reach
  `authCostDegradedAfter`,
- the `credential_verification` contract row flapped between "refusing" and
  "recovered",
- an `AUTH_VERIFY_RECOVERED` line was emitted per comparison — a log flood
  produced by the flood-detection code,
- and `auth_verify_saturated` **would never have fired for the primary attack
  this governor exists to expose.**

Recovery now requires BOTH halves of the evidence: a fast-path admission AND no
refusal for `authCostRecoveryQuiet` (5 s — comfortably longer than the 1 s wait
budget, so a client timing out once a second keeps the episode alive, and far
short of the 30 s degradation threshold, so a real recovery is still reported
promptly).

This is not a retreat to "recovery on elapsed time", the rule `ca_health.go` and
`storage_health.go` exist to enforce. Elapsed time alone still clears nothing —
an admission is still required, so a gateway nobody is authenticating against
stays reported as refusing rather than being declared healthy by silence. The
window supplies the half of the evidence that was missing, it does not replace
the half that was there.

Gates: `TestChaos57_RefusalEpisodeSurvivesInterleavedFastAdmissions` (drives the
exact refuse/admit interleaving a flood produces, and then checks the episode
can still age into Degraded — the state the alert keys on) and the extended
`TestChaos57_RecoveryRequiresObservedCapacity`. Both verified failing against
the pre-fix shape.

**The lesson, and it is the same one as §25.4c in a different costume:** the
evidence has to match the claim. "A slot was free" and "refusals have stopped"
are different propositions, and the recovery signal was keyed on the one that
was easy to observe rather than the one it was asserting.

### 29.5 What shipped

**`internal/authcost`** — the admission governor. Two bounds and one fairness
rule, all fail-closed:

- **A global ceiling** of `GOMAXPROCS/2` (floored at 1) concurrent
  verifications. Half, not all: the gateway's real work has to keep running
  while somebody authenticates, and a ceiling equal to GOMAXPROCS bounds the
  fault without preventing the outage. This is the bound that holds against a
  **distributed** flood, where no per-client rule can help.
- **A per-client ceiling of 1.** Without it the global ceiling contains the CPU
  but not the outage: one source occupies every slot and denies everyone else.
  A legitimate workstation authenticates serially and never notices.
- **A bounded wait (1 s) with a bounded queue (8 × the ceiling).** A legitimate
  synchronised burst is absorbed rather than refused, because graceful
  degradation is the house preference — but the queue is capped, because an
  unbounded one converts a CPU-exhaustion vector into a goroutine-and-memory
  one. **Trading one exhaustion for another is not a fix**, so both are bounded
  explicitly.

The bounds are **constants**, deliberately: the only use for a knob here would
be to widen a denial-of-service window. Headroom is large and checkable —
successful results are cached for 5 minutes, so the sustained uncached rate is
`active users / 300 s` (~1.7/s for 500 users) against a ceiling of ~25/s on
four cores. The governor bites under attack, not under load.

**Fair cache eviction.** `internal/authstate`'s policy ported verbatim in
spirit: entries are attributed to a client key and eviction always takes the
**oldest entry of the client holding the most** (ties broken by oldest entry,
then by client key, so the victim never depends on map order). A flooding
source evicts *itself* until it is no longer the largest holder; a client
holding one entry is untouchable until every other client is down to one too.
The bucket index also removes the O(cache) scan. The compaction condition is on
`len(keys)`, not on the un-consumed window — the same trap `internal/authstate`
documents, where a window-based test never fires under a sustained flood and
the backing array grows with total request count.

**Observability**, in the existing vocabulary: eight
`culvert_auth_verify_*` / `culvert_auth_cache_evictions_total` series, a
`credential_verification` operator-contract row (counts and bounds only — the
client key is admin-scoped), a rate-limited `AUTH_VERIFY_REFUSED` /
`AUTH_VERIFY_RECOVERED` log pair, and a fire-once-per-episode
`auth_verify_saturated` alert. Recovery clears on **observed evidence** — a
fast-path admission, meaning capacity genuinely exists — never on elapsed time
and never on a merely-queued admission: a flood that stops *sending* looks
identical to capacity returning.

This matters more than usual because a refusal denies a request whose
credential was never checked. Silent, its symptom would be *"users
intermittently get 407"* against a healthy directory and a healthy proxy, with
nothing anywhere saying why.

### 29.6 Gates

34 in total: 15 in `internal/authcost/authcost_test.go`, 19 in
`auth_cost_chaos_test.go`. **Eleven defect gates were verified failing against
the shape each replaces** — including the asymmetric-gate variant of §25.4,
both halves of the §25.4b bypass, and the immediate-refusal shape of §25.4c
(the engine's own first form, which the parallel-connection gate was
reproduced against before it was changed) and both halves of the §25.4d
recovery defect.

The controls are load-bearing, because several defect gates would also pass
against a "fix" that simply broke authentication:

- `TestChaos57_CachedVerificationsDoNotConsumeTheGovernor` — a warm cache must
  not be throttled, or the fix is a self-inflicted outage.
- `TestChaos57_UnderBudgetBothBranchesStillEqualise` — under budget both
  branches must *still* run a comparison. A "fix" that skipped bcrypt on the
  wrong-username branch to save CPU would pass the oracle gate while
  reintroducing the oracle in the opposite direction.
- `TestChaos57_CacheStaysBounded` — a policy that never evicted would pass the
  displacement gate while turning the cache into an unbounded map.
- `TestChaos57_ExternalProvidersBypassTheGovernor` — LDAP/OIDC run no bcrypt;
  charging them a slot would bound the wrong resource and let a slow directory
  starve local authentication.
- `TestChaos57_VerdictsAreUnchanged` — the governor changes no verdict.

### 29.7 What is deliberately left

- **AU-3e — a pre-existing username-enumeration oracle, reported not fixed.** A
  negative result for the *correct* username is cached; one for a wrong
  username is not. Repeating the same wrong pair twice is therefore ~1.5 µs for
  a valid username and ~80 ms for an invalid one — the RISK-008 oracle reached
  by repetition rather than by a single request. Closing it means caching
  wrong-username negatives, which is a behaviour change to a security control
  and deserves its own review rather than riding along in an availability fix.
  CHAOS-57 verifies only that it does not *widen* it.
- **The admin UI login path is untouched.** `VerifyUIUser` also runs bcrypt (two
  comparisons, in fact) but is bounded by the brute-force lockout
  (`loginLimiter`), which the proxy path never had.
- **Per-client parked waiters share one budget** (§25.4c). Callers waiting on
  their own client budget are counted against the same bounded waiter pool as
  the global queue, and are not additionally capped per client — so one source
  with many concurrent requests can occupy that pool and leave others unable to
  QUEUE for a slot. It costs them no capacity (the fast path still admits
  whenever a slot is genuinely free, and the flooding source still holds at
  most its cap), so the fairness claim holds: a flood can take the queue, not
  the slots. It is also strictly better than the shape it replaced, where those
  requests were refused outright. Capping parked waiters per client would close
  it; not done, because it adds a second bound to ration a wait that is already
  bounded twice.
- **The front-door limiters still ship disabled** (PX-6 remains open). The
  governor bounds the *cost* of the flood; it does not stop the flood arriving.
  The runbook says so explicitly and points at the three limiters.
- **No configuration surface**, and therefore no GUI-parity obligation — the
  bounds are constants derived from `GOMAXPROCS`. This is the recorded
  deferral class of `jwksStaleMaxAge` and the M1-3 release thresholds: a knob
  whose only use is widening a trust or availability window is not a feature.

### 29.7b The cost that is actually paid: restart and mass reconnect

The verification cache is memory-only, so a restart empties it and every active
client's next request is an uncached verification arriving at once — the "mass
reconnect storm" scenario. This is the one case where the governor legitimately
refuses valid credentials, and it is worth stating plainly rather than
discovering.

The queue absorbs the first arrivals; the rest get a `407` and retry.
Authentication drains at the ceiling rate (~25/s on four cores), so a
1,000-client fleet re-authenticates over roughly 40–80 seconds with some clients
seeing a retried 407.

**That is strictly better than the behaviour it replaces**, and the comparison
is the justification for the whole posture: pre-fix, the same 1,000 clients put
1,000 goroutines into bcrypt simultaneously — ~40 seconds during which every
core was consumed and **the proxy served nobody**, including clients that were
already authenticated and only wanted to browse. The governor trades *slower
authentication for some* against *the data plane keeps working for everyone*.

The residual is real and recorded: a non-browser client that does not retry a
`407` will see a hard failure during that window. The runbook names the three
remedies (stagger restarts, move authentication to an IdP — which this control
does not govern at all — or add cores) and, more importantly, says that a
DECAYING post-restart spike is not an incident while a sustained one is.

### 29.8 The process lesson

AU-3 sat open at **Medium** for the whole review series because its register
row described the attack that needs a valid username. The variant that needs
nothing at all was one branch away in the same function, and it is Critical.
The row was not wrong about what it described; it was wrong about being the
worst case.

The general shape — *an expensive operation reachable before authentication
completes* — is worth sweeping for directly rather than finding one instance at
a time. bcrypt is the obvious one because its cost is deliberate and
documented. The same question should be asked of every cryptographic
verification on an unauthenticated path.

See rows AU-3/AU-3a/AU-3c/AU-3d/AU-3e, `internal/authcost` (package comment),
`auth_cost_health.go`, and `docs/operator/credential-verification-cost.md`.

## 30. CHAOS-61 — The Data Plane's outbound cluster state under a Control Plane outage

**Date:** 2026-09-08 · **Domain:** DP→CP gossip (`controlplane_client.go`), the
distributed rate limiter (`security.go`), the DP→CP audit push queue
(`internal/audit`).

### 30.1 Why this domain

Register row **HA-1** records the deliberate posture for a DP that loses its
Control Plane: it keeps serving its last-known-good *config*. That posture was
reasoned about for configuration and reasoned about carefully. This sweep asked
the adjacent question the row does not cover — what happens to the DP's other
outbound cluster state, the per-tick loops that are not config sync at all
(`rateLimitGossipLoop`, `revocationSyncLoop`, `auditPushLoop`, `metricsLoop`) —
and found the same posture applied to data where it is **not** correct, in one
case with a customer-visible, permanently self-sustaining denial.

### 30.2 CL-20 — a rate-limit broadcast that never expired

Cluster rate limiting is gossip: each DP reports hot IPs, the CP aggregates the
fleet, and the DP adds the returned per-IP remote total to its own local count:

```go
localCount := len(b.timestamps)
remoteCount := clusterCounts.Get(ip)
if localCount+remoteCount >= limit { return false }
```

`clusterCounts.Apply` is reached from exactly one place — the gossip loop's
SUCCESS branch. A failed `SyncRateLimits` logs and `continue`s. So the moment
the CP became unreachable the last broadcast **froze in the map and was
enforced for the rest of the process lifetime**.

The reachable worst case needs no attacker and no unusual configuration: an IP
whose cluster-wide total was at or above `limit` at the instant of the outage —
an ordinary NAT or corporate egress address, which is exactly the kind of IP
that gets hot — is thereafter denied on this node with `localCount = 0`. **A
total blackhole for that client, on a healthy proxy, cleared only by the CP
returning or a process restart.** The quieter half is worse to diagnose: any
non-zero frozen remote count permanently shrinks the node's local allowance for
that IP.

It was also unfalsifiable from the outside. `RATE_LIMITED <ip>` is logged per
request and names only the IP; nothing distinguished "this client is sending
too fast" from "this node is enforcing an hour-old number from a Control Plane
that has been gone since Tuesday".

**The fix is arithmetic, not posture, and that matters.** `RemoteCounts` is
defined as the total *in the current window*: a broadcast received at `T`
describes timestamps in `[T-W, T]`, so at `now > T+W` every timestamp it
counted has aged out and its contribution to the current window is exactly
zero. Serving the frozen value is not a conservative choice — it is a wrong
answer. `clusterCountStore` therefore stamps every applied broadcast and
`FreshCount(ip, now, maxAge)` returns 0 past the window; there is deliberately
no unconditional `Get` left, so the frozen-count path cannot be reintroduced by
a future caller.

**The Control Plane already applied this exact reasoning in the other
direction.** `rateLimitAggregator.ClusterTotalsExcluding` prunes any node that
has not reported for two minutes, precisely so a dead DP's counts stop
suppressing fleet traffic. The rule existed on one side of the link and not the
other — and the side that lacked it is the one that makes the allow/deny call
on live traffic. That asymmetry, not the missing expiry itself, is the finding:
**a staleness rule that is only half-applied is a staleness rule nobody
reviewed as a pair.**

Two implementation details are load-bearing:

1. **The max-age is DERIVED from the live limiter** (`clusterRemoteCountMaxAge(rl.Window())`),
   not a second constant. A hardcoded minute would silently disagree with any
   operator who configured a different window, in the permissive direction.
2. **A NEGATIVE age is stale, not fresh.** `age >= maxAge` alone reads a
   future stamp (clock rollback between the stamp and the read) as brand new
   and honours the broadcast for however far back the clock went. This was
   caught by the sweep's own gate, against the first version of the fix: the
   enforcement path and the reporting path had reached opposite verdicts on the
   same condition. Two answers to one question is the defect; both now fail
   toward the local decision, where every other failure on this path lands.

Freshness is **evaluated, never latched** (`clusterRateLimitFreshness()` derives
it from the stamp on every read), so recovery needs no clearing path and a
gossip loop that wedges entirely still reports the truth to `/metrics` — the
`ca_health.go` `Usable()` discipline.

### 30.3 CL-21 — the DP→CP audit push queue dropped silently

`internal/audit` bounds the DP push queue at 1000 entries and trims to the
newest. The bound is correct — a DP that cannot reach its CP must not grow it
without limit. The silence was not: there was **no counter, no metric and no
log line**, three hundred lines below this package's own documented contract
for the durable JSONL path ("count EVERY failure, log only the FIRST").

Which entries are lost makes it worse rather than better. `Requeue` prepends
the events that just failed to send, and the trim keeps the newest — so the
first thing discarded is the **oldest unsent history**, the beginning of
whatever happened during the outage. That is the half an investigation needs
most, and losing it with no marker is CWE-778 in the same shape the
durable-write counter exists to prevent. The local JSONL file on the node is
unaffected; what acquires a hole is the CENTRALIZED trail, which is the surface
an operator actually watches in a cluster.

Both writers now go through one `trimPendingLocked` chokepoint so neither can
drop without charging `PendingDrops()`; surfaced as
`culvert_audit_cluster_push_drops_total` and, when non-zero,
`auditClusterPushDrops` on `/healthz`.

### 30.4 What shipped

* Broadcast expiry at the rate-limit window, derived from the live limiter,
  with the negative-age case failing toward local.
* A freshness health plane: `culvert_cluster_ratelimit_{remote_stale,broadcast_age_seconds,stale_episodes_total}`
  (emitted ONLY on a node where cluster rate limiting is armed — CHAOS-54's
  rule), five read-only fields on `GET /api/cluster/rate-limits`, a Cluster-panel
  banner, and one log line per TRANSITION in each direction (the gossip loop
  ticks every 5s; a per-tick line would report an hour-long outage 720 times).
* Counted audit push-queue drops with the package's first-failure-only log.
* 17 gates in `cluster_ratelimit_freshness_chaos_test.go`. Every DEFECT gate was
  verified failing against the pre-fix shape.

**No new alert event.** A stale broadcast is always caused by the CP link,
which already alerts and already carries a `cp_poll` row on `/ready`. A second
event name for one root cause is two pages for one action.

**The control gates are the point.** The cheapest way to pass every defect gate
is to stop consulting remote counts at all — which would silently delete the
distributed rate limiter. `TestChaos61_FreshBroadcastStillSuppresses` and
`TestChaos61_BroadcastAppliesForTheWholeWindow` pin the healthy path from both
sides, so a fix that passes by deleting the feature fails.

### 30.4b Review follow-up — a defect in the fix itself (Codex, PR #1346)

The freshness plane's emission rule is stated in its own header — a 0/1 gauge on
a node that never had the feature is indistinguishable from a broken one, so
emit only when ARMED — and the first version broke it in the same file. `Armed`
checked only `clusterRateLimitEnabled`, but `rateLimitGossipLoop` sets that flag
UNCONDITIONALLY when it starts and then skips every RPC while `rl.Enabled()` is
false. That is the DEFAULT posture: `Configure` enables the limiter only for a
limit > 0, so on a Data Plane with no rate limit configured no broadcast can
ever be applied — and every freshness surface reported a permanent,
un-clearable degradation on a node that is not rate limiting at all: gauge
pinned at 1, an episode counted, a warning logged, the panel banner shown.

The condition was applied to *"is gossip running"* but not to *"is anything
being decided"*. `Armed` now requires BOTH halves of what the request path
itself requires — the gossip loop running (so `AllowAuto` dispatches to the
cluster-aware path) AND `rl.Enabled()` (`AllowClusterAware` returns true
immediately when the limiter is off, before `FreshCount` is ever reached) — and
an un-armed node is never `Stale`, because staleness is a statement about
ENFORCEMENT, not about the age of a value nobody reads. `Applied` and `Age`
stay honest there, so suppressing the ALARM does not blank the FACTS.

Three gates, each verified failing against the pre-fix condition:
`LimiterOffIsNeverReportedStale`, `LimiterOffStillReportsWhatArrived`, and
`ArmedNeedsBothHalves` — the last being the control that suppressing the false
alarm did not also silence the real one.

The lesson is narrower than the finding: **a health surface's armed condition
must be the same predicate as the code path it reports on.** The request path
needs two facts to consult a remote count; the reporter checked one, and a
false alarm on the default posture is the kind of noise that trains operators
to ignore the gauge before the real outage arrives.

### 30.5 What is deliberately left

* **HA-1 itself is unchanged.** Config staleness is a posture decision with a
  recorded owner; this sweep touched only data whose own definition makes it
  expire.
* **None of the four auxiliary DP loops back off** (`revocationSyncLoop` 3s,
  `rateLimitGossipLoop` 5s, `auditPushLoop` 10s, `metricsLoop`). Against a
  down CP each retries at a fixed cadence with a fixed log line, and none
  jitters — WK-13/HA-11's herd shape, registered P2, and now with a second
  instance recorded here. Only the config poll (`pollConfig`) backs off.
* **`pollConfig` double-counts a failure.** It increments `failCount` and then
  calls `backoff`, which increments it again — so the delay reaches its ceiling
  in three failures rather than six, and the "3 consecutive failures" failover
  threshold fires after two. Cosmetic; recorded rather than changed inside a
  sweep about something else.
* **A partitioned fleet still under-counts.** Nodes that reach the CP see totals
  excluding those that cannot. Inherent to gossip aggregation.

### 30.6 The process lesson

> A staleness rule applied on one side of a link and not the other is not half
> a rule — it is an unreviewed asymmetry. The Control Plane pruned dead Data
> Planes for exactly the reason the Data Plane needed to expire a dead Control
> Plane's broadcast, and the code that did it sits in the same repository, two
> files away, with a comment explaining why. What was missing was ever asking
> the question in both directions at once.

Runbook: `docs/operator/cluster-rate-limit-freshness.md`.
## 31. CHAOS-62 — The request-history store under a damaged data volume

**Date:** 2026-08-29 · **Domain:** storage / persistence (`internal/logstore`) ·
**Status:** shipped · **Gates:** `internal/storeguard/storeguard_test.go` (19),
`internal/logstore/{resilient,enckey}_chaos_test.go` (13),
`logstore_chaos_test.go` (5) · **Register rows:** R-E (CLOSED), LS-3, LS-4

### 31.1 Why this domain

§19.6 opened row **R-E** and marked it *"next sweep candidate"*: `logstore.OpenTTL`
calls `badger.Open` with the same version and the same uncatchable-panic
exposure that CHAOS-50 had just fixed for the community category store. It was
deferred with a two-clause bound — *"bounded by being opt-in and already
non-fatal on ERROR"* and *"its content is request history with retention
semantics, [so] quarantining it silently is an evidence decision, not a cache
decision."*

Re-deriving both clauses from the wiring inverted them, which is §25.4.

### 31.2 The panic, re-measured for THIS store

CHAOS-50's table was measured with `catdb.Open`'s options. This store's differ —
encryption on, 128 MiB value log — so the premise was re-measured rather than
inherited. It reproduces exactly (badger v4.9.6):

```
panic: ... [recovered, repanicked]
  table.(*Table).initBiggestAndSmallest ← table.OpenTable
created by github.com/dgraph-io/badger/v4.newLevelsController in goroutine 21
```

A `recover()` in the frame directly above `OpenTTL` never fires: the panic is
raised on a goroutine badger spawns. This is kept as a permanent DEFECT PROOF
(`TestChaos62_BareOpenTTLPanicIsUncatchableAtTheCallSite`) so a future badger
change cannot let the recovery gate quietly prove less than it claims.

The same run also produced the table that forced `storeguard.Policy` to exist —
on a KEYED store, three conditions are indistinguishable:

| Injected condition | Error | Is the data intact? |
|---|---|---|
| passphrase changed | `saved logs use a different encryption key` | **yes** |
| `.salt` sidecar truncated | `saved logs use a different encryption key` | **yes** |
| KEYREGISTRY scrambled | `saved logs use a different encryption key` | no |
| `MANIFEST` scrambled | `manifest has bad magic` | no |

CHAOS-50's classifier lists `encryption key mismatch` as CORRUPTION, on the
stated rationale *"this store is never opened with a key"* — correct for that
store, false for this one. Reusing it unmodified would have moved a **healthy**
history store aside over an ordinary passphrase change: data loss caused by the
recovery mechanism (**LS-3**).

### 31.3 What made this worse than the category store

Two things, both from the wiring rather than the engine.

**It is reachable at RUNTIME.** `enableLogStore` is called from `ui_config.go`'s
history toggle, so a damaged store kills a gateway carrying production traffic
the moment an admin flips a switch — no restart, no warning, and no error the
handler could return, because the process is gone.

**It LATCHES.** The toggle is durable in `admin_settings.json` and re-applied by
`LoadAdminSettings` on every boot. Under the shipped compose file's
`restart: unless-stopped`, one unclean kill that damages a table becomes an
**unattended crash loop** — no proxy, no admin UI, no health endpoint, and no
way to turn the setting back off, because that requires the admin UI the setting
prevents from starting. The category store needed a CLI flag to reach that
state; this one gets there from an admin's saved preference.

### 31.4 The deferral's own reasoning, inverted

- *"Quarantining it silently is an evidence decision"* — true, and it argues FOR
  the fix. The CHAOS-05/07 contract **moves aside, never deletes**; the evidence
  survives either way. What the deferral preserved was the alternative: a
  crash-looping appliance whose history is equally unreadable and whose entire
  service is down as well.
- *"Bounded by being opt-in"* — opt-in means DURABLE (the latch) and reachable
  from the LIVE ADMIN API (the runtime kill). The clause meant to bound the
  severity was the mechanism that raised it.

### 31.5 LS-4 — the read path destroyed the key

Found by asking the obvious next question of the key path rather than the
corruption path. `EncKey` minted and **wrote** a fresh 32-byte salt whenever the
sidecar was unreadable or the wrong length — including next to an existing
encrypted store. The key is a pure function of `(passphrase, salt)`, so the
overwrite replaced the only value that could ever decrypt it; the resulting
error is indistinguishable from a passphrase change, so the operator's remedy
became *purge*, destroying history that was intact until the read ran. Reachable
by exactly the fault this store must survive — a torn sidecar after an unclean
kill (verified: `salt regenerated by EncKey: true`).

**This codebase had already written the rule down.** `internal/alerts`
(SEC-WHSIGN-1): *a failed decrypt never mints a key; creation happens on first
encrypt.* Nothing was checking whether anywhere else did the same thing. The
rule now holds here: mint only when there is no store to be locked out of,
otherwise `ErrSaltUnusable` with the sidecar untouched — so restoring one 32-byte
file recovers the whole history, a path that previously did not exist.

### 31.6 What shipped

`internal/storeguard` — the CHAOS-50 engine extracted verbatim and made
store-agnostic. A second COPY was rejected: the badger message table is
empirical and pinned by a test *precisely* so an upgrade that rewords a message
fails the build rather than silently switching recovery off; two copies is how
that protection rots. `catdb.OpenResilient` is now a thin adapter with an EMPTY
policy, and its 21 recovery gates run unchanged against the extracted engine —
21 test functions, 97 assertions, identical before and after, the only edits
being identifier renames. That is the evidence the extraction is
behaviour-preserving.

`storeguard.Policy` can only ever **SUBTRACT**. There is deliberately no field
for ADDING corruption signals: widening destruction from a call site is how a
shared safety mechanism becomes an unsafe one.

Plus `logstore.OpenResilientTTL` (exempting encryption errors both structurally
and textually), the `EncKey` fix, the `request_history` contract row, three
`culvert_logstore_*` series, the existing `state_file_corrupt` alert, and a
distinct 409 for the salt case naming its own reversible remedy. **Not** wired
into `/readyz` — a node with history degraded is fully able to serve.

### 31.6b Review follow-up — a defect in the mechanism itself (LS-5)

Raised by Codex against the extraction and **verified in both directions before
fixing**. Discovery used `filepath.Glob(base + suffix + "*")`, so a glob
metacharacter in the operator-configurable store path silently broke the
mechanism:

| Store path | `filepath.Glob` result | Consequence |
|---|---|---|
| `/data/hist[1]` | `[]` — reads `[1]` as a character class and looks for `hist1.opening.*` | the store's OWN poison marker is undiscoverable, so the next start hands badger the corrupt directory again — **the crash loop survives its own remedy** |
| `/data/hist?` | matches `histX.opening.999` | a **healthy** store is quarantined on a NEIGHBOUR's evidence |

The first row is the exact failure this package exists to prevent, reached
through the package itself. It is inherited from CHAOS-50 — the shipped catdb
code has it today — and is fixed here for both stores.

Escaping the metacharacters would close only the first row and is
platform-specific (Go's glob does not honour backslash escapes on Windows).
Discovery is now a prefix match over the parent directory (`siblings`), which
has no pattern semantics at all, so the class is gone rather than patched.
Gates: `TestDiscovery_IsNotFooledByGlobMetacharactersInThePath` (4 paths),
`TestDiscovery_DoesNotClaimANeighboursMarker`, both verified failing against the
glob implementation.

A second Codex finding (P2) corrected the health record: a runtime enable that
fails to open returns BEFORE `adminSettingsSave`, so the persisted setting stays
off — a record asserting `Enabled: true` reported a configuration that was never
written. The field is now `SaveRequested` ("an open was attempted"), which is
true on both the boot and admin paths, and the contract row no longer claims the
feature is enabled.

### 31.7 What is deliberately left

- **Real KEYREGISTRY damage does not self-heal.** It is indistinguishable from
  the two benign conditions, and of the four postures the only unacceptable one
  is destroying intact history over a config change. Degrades loudly; the
  operator purges. Recorded owner-visible trade.
- **Recovery still costs one process death** for the panic case (inherited from
  CHAOS-50 — the marker cannot act until the run after the crash).
- **No circuit breaker on repeated quarantines**; the metric and the row are the
  signal.
- **Nothing backs up the `.salt` sidecar**, which is correctly excluded from
  archives as key material. An operator who loses it with no backup still loses
  the history. Whether the appliance should hold a second copy under the KEK is
  a key-custody decision, not a patch — for an owner.
- **No third unguarded BadgerDB open remains** in the tree; `catdb` and
  `logstore` were the two.

See `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-29.md` and
`docs/operator/request-history-recovery.md`.
## 32. CHAOS-63 — The public admin-login endpoint's untrusted username

**Date:** 2026-09-05 · **Domain:** authentication / audit / persistence ·
**Status:** shipped · **Closes:** AU-15, AU-16 ·
**Gates:** `login_input_bounds_test.go` (10) + `internal/lockout/lockout_keybound_test.go` (9) ·
**Runbook:** `docs/operator/admin-login-input-bounds.md`

### 32.1 Why this domain

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

Note the handler-vs-store split that §32.4 turns on: those 1–64 caps live in the
API *handlers*. Neither `cfg.SetAuth` nor `cfg.SetUIUser` bounds a username, and
`validateAuthStartupCredentials` validates only the password — so `-user` /
`auth.user` and `--reset-password` can persist an admin whose name is longer
than any of these limits.

### 32.2 The shape of the miss

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

### 32.3 Why this is a security finding, not a capacity one

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

### 32.4 The fix, and the two places it lives

**At the entry point (`login_input_bounds.go` → `apiAuthLogin`).**
`rejectOversizeLoginUser` refuses a username longer than `maxUsernameLen` (256 —
the constant the proxy-auth path already uses for exactly this question) and
returns **before** the limiter, the credential check and the alert. A rejected
attempt therefore creates no limiter entry and leaves no attacker-sized bytes
anywhere. 400 rather than 401 is deliberate: the length of a submitted username
is not a secret and is not a credential oracle for a name that exists nowhere.

**A CONFIGURED account is never refused, however long its name**, and the first
draft of this change got that wrong. It asserted that no local account could
carry such a name because `apiSetupComplete` and the user-creation API cap at
64 — but those are handlers, not the stores (see §32.1), so an over-long
username can already be a valid persisted admin and the guard would have locked
that operator out of their own admin UI on upgrade: a hardening change turned
into an outage for the one person who has to fix it. Raised by Codex review on
PR #1320, against exactly the claim the code comment made. The guard now
consults `cfg.LoginNameConfigured`, a non-retaining probe whose resolution MUST
stay identical to `VerifyUIUser`'s (roster **or** legacy single user — the
existing `UIUserExists` checks only the roster and would have missed the legacy
case). `warnOversizeConfiguredUsernames` reports such an account once at boot,
deliberately as a WARNING and never fatally: the stores never bounded the name,
so failing the boot would brick an appliance whose config was legal when it was
written.

The narrow cost is that, for names past the bound only, a 400 rather than a 401
says "no such account" — and an attacker must already have guessed the exact
over-long name to learn anything from it. That is a far better trade than
refusing a real admin's login.

That exemption has a consequence in the leaf, and it is why the clamp there is
**injective**: a configured over-long name now reaches the limiter, so a plain
truncation would let an attacker who knew that admin's first 256 bytes submit an
ordinary ≤256-byte name clamping to the SAME key and drive the tier-2 account
lock against them — lockout-as-DoS, precisely what the two-tier design
(RISK-012) exists to prevent. `boundUsername` appends a SHA-256 digest of the
whole name to a rune-safe prefix, which keeps the key bounded and distinct
names distinct (`TestBoundUsername_IsInjective`, verified failing against a
plain truncation).

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

### 32.5 Deliberately not done

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

### 32.6 Residual risk

- **PX-21 (NEW, open, and larger than the finding this sweep fixed).** The
  identical class — an unbounded untrusted value copied into a rotating sink —
  is live on the **proxy data path**, which every client on the network can
  reach. `handleRequest` logs `sanitizeLog(r.Host)`; `sanitizeLog` neutralises
  control characters and bounds nothing, and the proxy `http.Server` sets no
  `MaxHeaderBytes`, so net/http admits ~1 MiB of request line plus headers.
  Measured with a throwaway probe against `handleRequest` on the default-deny
  path (200 KB host, `GET http://<host>/`):

  ```
  status=403  process-log bytes=204899  (host was 204812 bytes)
  reqlog newest entry: host len=204812  status="POLICY_DEFAULT_DENY"
  ```

  This is deliberately **recorded rather than fixed here**. It is a different
  domain with a different fix shape and a real design decision the owner should
  make, not a reviewer: RFC 1035 caps a hostname at 253 bytes, so *rejecting*
  an over-long host outright is defensible and probably correct — but that
  changes data-plane behaviour and has to answer for IPv6 literals, non-DNS
  authorities and the CONNECT form before it ships. Truncating only at the log
  call sites is the smaller, safer move and does not close the request-log
  field. Bundling either into an admin-auth fix would have shipped a data-path
  behaviour change under a security-hardening title.

- **AU-17 (count axis, open).** The lockout maps are still bounded only by
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

### 32.7 The process lesson

§21 stated it for back ends, §22 for listeners, §23 for decisions, §24 for
documented residuals. This sweep adds one about **health planes**:

> A health signal watches a mechanism, not an outcome. `internal/audit` counts
> writes that FAIL, because the analysis that produced it modelled the loss as a
> failing volume. The same outcome — the compliance record destroyed, remotely,
> by an unauthenticated caller — arrives through writes that all succeed, and
> every instrument stays green. When a component names the outcome it is
> protecting against, check whether the instrument it built can see that outcome
> arrive by any other road.
## 33. CHAOS-57 — The admin UI listener, and which plane is allowed to kill which

**Date:** 2026-09-09 · **Domain:** admin/control plane ↔ proxy data plane coupling ·
**Status:** shipped · **Gates:** `admin_ui_listener_chaos_test.go` (15)
**Id allocated at the START of the sweep**, per the governance note in §0.

### 33.1 Why this domain

Every sweep in this register so far has asked *does this subsystem survive its
own failure?* This one asks a different question: **when a subsystem fails, what
else does it take with it?**

Culvert runs several listeners in one process — the proxy port, the admin UI,
SOCKS5, the control-plane gRPC server, optionally the MCP gateway. They are
separate planes with different jobs and wildly different criticality, and they
share one address space and one exit status. That sharing is not itself a
defect; every appliance does it. The defect is when the *least* critical plane
holds a lever over the *most* critical one.

It does. The admin UI held the biggest lever there is.

### 33.2 The finding

`startUI` (ui.go) spawned a detached listen goroutine whose ONLY error branch
was `logFatalf` — which `os.Exit(1)`s the process:

```go
go func() {
    if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
        logFatalf("UI server error: %v", err)   // ← kills the whole appliance
    }
}()
```

Three of those, one per TLS mode. So **every way the admin UI's listener could
fail terminated the proxy data plane with it.**

This inverts the dependency the product is built on. The admin UI is the plane
you manage enforcement *from*; it may degrade without the enforcement plane
going with it, never the reverse. And `startUI` is called from the init block
BEFORE the proxy listener starts and returns as soon as the goroutine is
spawned, so the failure lands asynchronously against a process that is already
announcing itself as up.

**Both triggers were reproduced against the real binary.**

*Trigger 1 — the admin port is occupied.* A predecessor container still
draining, a host-network service on 9090, an operator collision.
`validatePortCollisions` (main.go) checks only Culvert's own three ports against
EACH OTHER; nothing on the host is visible to it. Observed log, verbatim, in
this order:

```
UIHTTP: http://localhost:19090          ← claims the UI is listening
Proxy:  http://localhost:18080          ← the data plane announces itself
UI server error: listen tcp :19090: bind: address already in use   → exit 1
```

Note the first line. The success message was printed *before* the bind was
attempted, so the process log actively claimed the admin UI was listening on a
port it never acquired — and then the appliance died over it.

*Trigger 2 — the custom UI certificate cannot be loaded.*
`ListenAndServeTLS` reads `-tls-cert`/`-tls-key` at call time, so a rotation
that briefly truncates, replaces or re-permissions those files (certbot,
cert-manager, a Docker secret whose mount is not ready yet) is a boot that ends
in `UI TLS error: tls: failed to find any PEM data in certificate input` and
exit 1.

Both are ROUTINE operational events, and under `restart: unless-stopped`
(docker-compose.yml) each becomes an unattended crash loop: no proxy, no admin
UI, no health endpoint, recoverable only with shell access. That is precisely
the outcome §19 closed for the category store, arrived at from the opposite
direction — §19 reached it from a damaged data file, this sweep from a busy TCP
port.

### 33.3 Why "it exits, so it fails closed" is wrong

The obvious defence of the old behaviour is that exiting is the safe direction.
It is not, and this is the part worth recording.

**Process death picks no posture at all — it delegates the choice to the network
topology.** An explicit-proxy fleet loses all egress: a total business outage
from an admin-plane fault. A PAC/WPAD fleet with a `DIRECT` fallback, or a
transparent deployment that bypasses a dead next hop, sends traffic straight out
**unfiltered** — a fail-OPEN security outcome reached by a mechanism that looks
like fail-closed. Whichever one a given customer gets is a property of their
network, not of any decision Culvert made.

The counter-argument that *does* have force is DX: a hard failure on first boot
is honest about a misconfiguration, whereas a silently-degraded appliance could
ship to production unmanageable. That argument is answered by making the
degradation impossible to miss (§25.5) rather than by keeping the exit — because
the exit's cost is paid by every *later* boot too, when the appliance is carrying
production traffic and the fault is transient.

### 33.4 The codebase already knew

Two precedents, one of them inside the very function that carries the defect:

- **In `startUI` itself**, a `selfSignedTLS()` failure does NOT exit. It degrades
  to plain HTTP and records `uiTLSFallbackActive` for the operator. One of the
  four failure modes in this function was already handled correctly.
- **CHAOS-54 (§22)** made exactly this call for a listener: a SOCKS5 accept loop
  that hits an unrecoverable socket error closes the listener, records DOWN, and
  the process keeps serving. The *least* critical listener in the process already
  had the *gentlest* failure posture, while the admin UI had the most violent one.

So the fix borrows wholesale rather than inventing a second dialect.

### 33.5 What shipped

`serveAdminUIWithRetry` / `adminUIServeOnce` (ui.go) + `admin_ui_health.go`.

1. **No listen path is fatal.** The bind is performed EXPLICITLY (`net.Listen`)
   rather than through `ListenAndServe`, so the loop can distinguish a successful
   bind from a serve that ended — which is what makes evidence-based recovery
   implementable here at all.
2. **Rate-bounded, never count-bounded retry** (1 s → 30 s ceiling, ±20 % jitter,
   interruptible). Unbounded attempts are deliberate, on CHAOS-55's reasoning:
   the terminal state of "give up" is an appliance nobody can manage, which is
   the outcome being removed. "Avoid infinite retries" is satisfied the way §22
   and §23 satisfy it — the retry is never SILENT.
3. **The certificate is re-read on every attempt**, so a rotation that
   momentarily breaks the pair self-heals with no restart.
4. **The success log moved after the bind.** The pre-change line claimed a
   listener that did not exist.
5. **Recovery on OBSERVED evidence only** — a listener that actually bound.
   Elapsed time never clears the state; a retry loop that has stopped failing
   because it stopped attempting looks identical to a bound one.
6. **Full observability, on the PROXY port** — `/health admin_ui`, a
   report-only `/ready admin_ui` row, five `culvert_admin_ui_*` series, the
   `admin_ui_listener` contract row, and a fire-once `admin_ui_unavailable`
   alert whose text states that traffic is unaffected. The surface choice is the
   point: **the admin port's own `/healthz` cannot report that the admin port is
   unreachable** — a probe that dies with the plane it measures reports nothing.
7. **The readiness row is REPORT-ONLY and that is load-bearing.** A node whose
   admin UI cannot bind is proxying perfectly; gating the default verdict would
   eject a healthy gateway from the load balancer over its management plane —
   converting a management outage into the traffic outage the change exists to
   prevent. Pinned as a control test.
8. **The pair is validated BEFORE the listener is bound.**
   `http.Server.ServeTLS` returns a certificate error WITHOUT closing the
   listener it was handed, so a bind-first loop would leak one socket per attempt
   against a persistently bad certificate — turning a recoverable config fault
   into the descriptor exhaustion §22 spent its whole sweep on. Pinned by a
   50-attempt FD-count gate.

Verified end to end against the real binary: with the port held, the appliance
stays up, `/health` reports `admin_ui: degraded`, and the proxy answers 200
throughout; when the port frees at T+13 s the listener rebinds on its own and
`/health` reports `admin_ui: ready` at T+22 s with a recovery line naming the 3
suppressed log lines — no restart.

### 33.6 Deliberately not done

- **The other fatal listeners are NOT changed.** `runProxyUntilShutdown`'s
  `logFatalf("Proxy error")` is CORRECT: the proxy *is* the product, and a
  gateway that cannot serve should exit loudly rather than linger as a black
  hole. `startSOCKS5`'s bind failure stays fatal too, and that one is a genuine
  open question rather than a settled answer — see SOCKS5-BIND below.
- **No admin-UI-down entry in the audit ring.** The admin plane being down is a
  systems event, not an admin action, and the audit ring is 500 entries shared
  with security events (the §13 anti-forensics rule).
- **No `culvert_admin_ui_never_bound` series.** `_up` plus `_binds_total == 0`
  already distinguishes "never came up" from "fell over", and the contract row
  states it in words.

### 33.7 Register rows

| Row | Finding | Status |
|---|---|---|
| **AP-1** | Admin UI listen/serve failure calls `logFatalf`, terminating the proxy data plane. Reachable by an occupied port or an unreadable custom certificate; a crash loop under `restart: unless-stopped`. | **CLOSED** (§25) |
| **AP-2** | The admin UI success log line was emitted BEFORE the bind was attempted, so the process log claimed a listener that never existed. | **CLOSED** (§25) |
| **AP-3** | No health/metrics/diagnostics surface reported the admin plane's reachability, and the only surface that carried admin-plane posture was on the admin port itself. | **CLOSED** (§25) |
| **AP-4** | The custom UI certificate was read exactly once, at boot, so a rotation that momentarily broke the pair required a restart. | **CLOSED** (§25) |
| **SOCKS5-BIND** | `startSOCKS5` bind failure is still fatal, so an occupied SOCKS5 port takes down HTTP/HTTPS proxying too. Same class as AP-1, one plane over. Not fixed here: §22 deliberately settled the RUNTIME posture for this listener and left the BOOT posture alone, and changing it is a posture decision (is a SOCKS5 port that cannot bind a misconfiguration to refuse, or a subsystem to degrade?) rather than a mechanical extension. | **OPEN** (Medium) |
| **R-F** | Three data-file boot loads still `logFatalf` on any error: `catStore.Load` (Layer-1 URL categories), `blocklist_startup.go`, and the policy-file load in `main.go`. Scoped by §19 and unchanged by this sweep — the question there is about authoritative *state*, not about plane coupling. | **OPEN** (carried from §19) |

### 33.8 The lesson this sweep adds

§21 stated its rule for back ends, §22 for listeners, §23 for decisions, §24 for
documented residuals. This one is about **blast radius**:

> A process that hosts several planes has, by construction, given every one of
> them the ability to end all the others. Which planes are *allowed* to exercise
> that is a design decision — and it is almost never made explicitly, because
> the mechanism (`os.Exit` on a startup error) is idiomatic, local, and looks
> obviously correct at the call site. The question "what else dies when this
> line runs?" has no local answer, so it does not get asked. Here the answer was
> "the entire reason the product exists", written in a goroutine three lines
> long, about a port number.

And a second, sharper one about the shape of the argument: *exiting is not a
posture.* Fail-closed and fail-open are properties of what the system does to
traffic, and a process that is gone does not act on traffic at all — the
surrounding network does, differently for each customer. Any component that
reaches for `os.Exit` as a safety measure should be made to say which of the two
outcomes it is choosing, in terms of packets, for a named deployment topology.
## 34. CHAOS-64 — Destination-host DNS resolution on the policy path

> Same finding as §28, reached from the other end. §28 entered through the
> GeoIP accessor and fixed the WARM path (cache-only accessor + bounded,
> single-flighted off-path warmer); this sweep entered through the resolver
> itself and added the DEADLINE, the process-wide resolver POOL with shedding,
> stale-while-revalidate, and the `dns_resolution` health plane. Both shipped;
> the implementations were reconciled onto one `hostIPCache` (one flight type,
> one leader path) when this sweep landed. Read §28 first.

**Date:** 2026-09-04 · **Domain:** DNS (never previously swept) · **Code:**
`geoip.go`, `dns_health.go`, `alerts.go` · **Runbook:**
`docs/operator/dns-resolution-health.md`

> **Renumbered SEVEN TIMES before merge — CHAOS-57 → CHAOS-58 → CHAOS-59 →
> CHAOS-60 → CHAOS-61 → CHAOS-62 → CHAOS-63 → CHAOS-64.** This sweep collided
> with a concurrently-developed sweep on `main` on seven merges inside eight
> days, and
> lost the id every time for the same reason. Each rename picked the next id that
> was free *at that instant*, and each time another in-flight branch merged that
> id first.
>
> | # | Date | Collided with | Which had taken | This sweep became |
> |---|---|---|---|---|
> | 1 | 2026-09-04 | §25 the hijacked-tunnel plane | `CHAOS-57` | `CHAOS-58` / §26 |
> | 2 | 2026-09-10 | §26 the LDAP directory that stalls | `CHAOS-58` | `CHAOS-59` / §27 |
> | 3 | 2026-09-10 | §27 the intelligence-feed plane | `CHAOS-59` | `CHAOS-60` / §28 |
> | 4 | 2026-09-11 | §28 the GeoIP resolution chain | `CHAOS-60` | `CHAOS-61` / §29 |
> | 5 | 2026-09-11 | §30 the DP outbound cluster state | `CHAOS-61` | `CHAOS-62` / §31 |
> | 6 | 2026-09-11 | §31 the request-history store | `CHAOS-62` | `CHAOS-63` / §32 |
> | 7 | 2026-09-11 | §32 the admin-login username bound | `CHAOS-63` | `CHAOS-64` / §33 |
>
> The first was already the THIRD occurrence of the class the header records for
> `CHAOS-50`. Collisions 2 and 3 landed on the same day, hours apart, against two
> different branches. Collisions 4, 5, 6 and 7 all landed on the same day,
> hours apart, against four more.
>
> **The section has ALSO moved THREE times without a rename** — §29 → §30 → §31
> between collisions 4 and 5, and §33 → §34 after collision 7, when the admin-UI
> listener sweep merged ahead of it. Each time an unrelated newly-merged sweep was
> inserted ahead of it, displacing the section while leaving the id alone. Column five
> records what each RENAME produced at the time, so rows 4 and 5 keep their
> then-current locations and the displacements are not rows. The current location
> is §34, and every pointer outside the register (`CLAUDE.md`, the runbook,
> `internal/geoip/geoip.go`) was repointed with it each time. **A section move and
> an id collision are different events and the table must not conflate them** —
> the first costs a pointer sweep, the second costs a rename of every gate,
> metric and comment naming the sweep.
>
> **Collisions 6 and 7 each arrived as a displacement AND a rename in ONE
> merge**, where the first five had kept the two events separate. The
> request-history-store sweep was inserted ahead of this section AND had taken
> the id this section was holding, so a single fetch delivered both a
> displacement (§31 → §32) and a rename (`CHAOS-62` → `CHAOS-63`). The
> distinction above still holds and is worth more, not less, for having been
> collapsed once: the displacement cost a pointer sweep of three files, the
> collision cost 62 identifier renames across ten. Nothing about either merge
> announced which of the two had happened — both surfaced as the same
> conflict-free fast-forward, and the duplicate id was visible only to a
> `uniq -d` over the section headers.
>
> **Collision 7 is the one that closes the argument.** It landed on the same day
> as collisions 4, 5 and 6, against a sweep whose own commit message reads
> *"renumber to CHAOS-63/§32 — the fifth collision, caused by the fourth fix"* —
> so a sweep renaming itself to escape a collision took the id this sweep had
> renamed itself into hours earlier, and both were racing the same free-id
> scan. That is the mechanism stated as plainly as it can be: when two branches
> both pick "the next free id" against `main`, the winner is decided by merge
> order, which neither can observe. There is no version of renaming-at-merge
> that survives this; only allocation does.
>
> **Collision 4 is the one the previous note predicted in writing, and it is the
> sharpest case of all**: §28 is the sibling half of THIS finding — the same
> subsystem reached through the GeoIP accessor rather than the resolver — and it
> was developed on THIS BRANCH and merged to `main` ahead of this section. So the
> id was taken by a sweep sharing this sweep's own `hostIPCache`, and the pair was
> reconciled onto one flight type while still answering to one name. For a
> window, §28 and this section (then §29) both read `CHAOS-60` with
> `(second sweep)` appended to
> distinguish them — a parenthetical is not an identifier, and that is the same
> half-fix (correct the SECTION, leave the ID) recorded for collisions 1–3.
>
> **The rule applied all seven times, and it is not "last one loses".** The header
> states renumbering is an owner decision *because* "identifiers three merged PRs
> already reference" would have to be rewritten. That reason is **asymmetric**:
> the MERGED side is referenced by merged code, gates and register rows, so it
> keeps the id; the UNMERGED side has every reference inside one branch, where
> changing them costs nothing. Renumbering the unmerged side is therefore not a
> unilateral edit of shared history — it is the only moment at which the collision
> is free to remove, and after merge it would be permanent. The other side's
> references were left untouched in every pass, so `metrics.go` now carries one
> line from §25, one from §28 and one from here, `CLAUDE.md` carries §26's, §27's
> and §28's bullets beside this sweep's, and `geoip.go` carries both halves of the
> §28/§34 pair.
>
> **Each of the seven merges was resolved by someone who fixed the duplicate
> SECTION number and left the duplicate ID in place**, which is why the collision
> survived to recur: a section renumber makes the register read correctly while
> two sweeps still answer to one name, and collisions 2–7 were found only because
> a later merge conflict forced someone to look again. Collision 6 did not even
> produce a conflict — the merge was a clean fast-forward, and the duplicate would
> have merged silently had this branch not re-run the `uniq -d` check by habit.
>
> **The prevention the header has named since `CHAOS-50` is now overdue, and this
> sweep is the whole argument for it**: allocate the id in a committed placeholder
> row at the START of a sweep. Renaming at merge time provably cannot work — the
> id a rename picks is validated against `main` at the instant of the rename and
> nothing reserves it afterwards, so the rename is itself a race. One branch lost
> the id SEVEN times in eight days; catching each one was luck, not process.
> Each revision of this note has predicted the next occurrence in writing and each
> prediction has been met within the day — *"expect a fourth"* was followed by a
> fourth from a sibling sweep on this very branch, the note that recorded the
> fourth was overtaken by a fifth before it merged, and the note that recorded the
> fifth — which said in these words that *"a sixth is not a prediction about luck;
> it is what this process produces by construction"* — was overtaken by a sixth
> the same day, before a reviewer had read it. **Owner action: add the
> placeholder-allocation row.** The argument no longer needs a prediction to rest
> on: the sentence claiming the process generates collisions by construction was
> itself invalidated by one, which is as direct a demonstration as the register
> can offer.
>
> **`CHAOS-57` is now stamped on THREE merged sections, and no branch can resolve
> any of them.** §25 (the hijacked-tunnel plane, 2026-09-04), §29 (credential
> verification, 2026-09-11) and §33 (the admin-UI listener, 2026-09-11) all carry
> it. Every one is merged, so the asymmetry that resolved collisions 1–7 does not
> apply: no side is free to move, and whichever is renumbered rewrites identifiers
> that merged PRs already reference.
>
> It is also the collision that reached the CODE. All three sweeps name their gates
> `TestChaos57_*` in the same `package main`, and the tree compiles only because
> every suffix happens to differ — with two sweeps that was luck, with three it is
> luck being asked to hold across a widening surface, and a future gate named for
> any of them can now fail to build for a reason that has nothing to do with its
> subject. **This section records the fact and renumbers nothing**: choosing which
> merged sweep moves is exactly the owner decision the header reserves, and doing
> it from an unrelated branch would edit three other sweeps' merged history.
>
> The progression is the argument. When this note first recorded the duplicate it
> was a pair and the claim was that the process had produced something no branch
> could resolve cheaply. Within the same day it became a triple — without anyone
> making a mistake, because each sweep independently picked an id that was free
> when it looked. **Renaming at merge cannot converge; only allocation can.**

### 34.1 Reachability

Two conditions, both ordinary in an enterprise deployment:

1. A MaxMind database is loaded (`geoip.Enabled()`).
2. At least one enabled access rule carries a `DestCountry`.

Geo-scoped policy is a headline SWG feature, so this is a normal posture, not an
exotic one. Under it, `matchDestNorm` (policy.go:1608) calls
`geo.LookupCached(host)` once per such rule per request, on the **request
goroutine**, and that needs an IP address before it can ask for a country.

`policy.go:1221` already names the hazard:

> the scan can block (matchDestNorm → geo.LookupCached → DNS on an uncached
> DestCountry host) … so the lock must NOT be held across it

That comment is correct and the mitigation it describes — releasing the
evaluation lock before the scan — is the right fix for the *lock*. It is not a
fix for the *request*, which still blocks.

### 34.2 The three defects

Each was reproduced against the pre-fix tree before any code was written.

**D1 — no deadline.** `lookupHostFn` was `net.LookupHost`: no context, no
timeout. The only bound was the operating system's, and `resolv.conf` ships
`timeout:5 attempts:2` per nameserver. Measured: `resolveHost` had not returned
after 1.5 s against a wedged resolver and would not until the resolver did. That
goroutine holds a client connection, a per-IP `internal/connlimit` slot, and its
place in the policy scan.

**D2 — no single-flight.** The pre-fix comment stated the position explicitly —
*"Concurrent misses for the same host may resolve in parallel; last write wins,
which is benign (both hold live answers)"* — and it is benign for correctness
and not for load. Measured: **200 resolver invocations for 200 concurrent
requests to one host.** During a resolver brownout that is one blocked goroutine
per request AND one query per request, fired at the resolver that is already
failing. It is also what made the negative cache useless as a shock absorber: a
negative entry is written only when a resolution *completes*, so during an
outage every request kept missing for the full length of the outage.

**D3 — no stale serving, and the security consequence.** An expired entry was
discarded outright. Because the TTL is uniform (5 min) and entries are created
by traffic, the whole working set expires within one window — so the first
expiry during a resolver outage takes every popular host cold at the same
moment. `LookupCached` then returns `("", false)`, and:

```go
if countrySet {
    code, cached := geo.LookupCached(host)
    if !cached || !matchCountry(rule.DestCountry, code) {
        return false          // rule does not match
    }
}
```

A rule that does not match is **skipped**, and `evalAccessRules` continues to
lower-priority rules. The in-code comment calls this fail-closed, and for an
*allow* rule it is. For a *block* rule it is the exact opposite: a "block
sanctioned countries" rule stops matching and a broad allow rule beneath it
takes over. **Geo blocking silently stops enforcing because DNS is slow.**

And none of it was visible. No counter, no log line, no alert, no health row on
this path — every probe stayed green.

### 34.3 What shipped

| Property | Mechanism | Why this shape |
|---|---|---|
| Bounded in time | `dnsResolveTimeout` 2 s on a context-aware seam | The budget is what a client pays for a cache miss. A resolver that has not answered in 2 s is not about to make the request fast. |
| Bounded per host | single-flight; followers inherit the leader's answer **and its deadline** | A timer on the follower would be worse than useless — it would release it to start a *second* lookup, which is the herd being collapsed. |
| Bounded in total | 64-slot pool; saturation SHEDS, never queues | Single-flight collapses a herd on one host and does nothing across many, and the hostname is attacker-controlled. A queue would only relocate the pileup. |
| Never blocks for a known host | stale-while-revalidate, ceiling `hostIPCacheStaleMax` 1 h | The address is used only for country attribution — the real connection is dialled through the transport's own resolution — and an IP's country changes on a timescale of months. The alternative to a stale answer here is not a fresher one, it is **no** answer. |
| The refresh cannot make it worse | a negative result never overwrites a still-servable positive | A failed refresh writes a negative, and a negative is served as FRESH for its TTL — so without this guard the refresh introduced by the fix would itself take geo dark for exactly the window the stale answer existed to cover. |
| Shed is not a fact about the host | shed results are not cached | Saturation is a statement about this node's load; caching it would suppress a legitimate destination for a full TTL. |
| Followers can never hang | `finishFlight` is DEFERRED on every leader path | Otherwise a panic inside the resolution leaves followers blocked forever on a flight nobody completes — a bounded resolver fault converted into a permanent request-plane hang no upstream `recover()` can undo. |

Observability, all reusing existing operator vocabulary: six
`culvert_dns_resolve_*` series, the `dns_resolution` operator-contract row, and
a fire-once-per-episode page on the **existing** `dns_failure` event (a new
event name would be silently unsubscribed on every already-configured webhook —
the cluster-CA `cert_expiry` precedent).

Two discipline points carried from the earlier sweeps:

- **Degradation is a DURATION (60 s), and NXDOMAIN never counts toward it.** An
  authoritative "this name does not exist" is a resolver working perfectly, and
  a gateway sees a steady stream of them from typos and malware beaconing to
  sinkholed C2. Any count-based threshold pages on healthy traffic — and
  because the hostname is **client-chosen**, it would let any client fabricate
  the page on demand.
- **Recovery is on OBSERVED evidence only.** One successful resolution clears
  the episode; elapsed time never does. A gateway whose resolution failures stop
  because traffic stopped has not recovered.

### 34.4 The alert-plane defect found alongside

`fireDNSFailureAlert` passed the raw `err.Error()` as the alert Detail.
`Store.Dispatch` dedups on `event + ":" + Detail`, and a `*net.DNSError`'s text
embeds the **queried hostname** and the resolver address — so every failure
minted a distinct dedup key that the 30 s window could not suppress by
construction, and the fan-out landed in the 500-entry retry queue where it
evicts real threat alerts. That is WK-12/RS-5, and here it is remotely
triggerable: the hostname is chosen by the client, so any client could both
fabricate unbounded alert volume and write arbitrary strings into an operator's
alert pipeline. Detail is now a bounded reason class; the full error was already
logged at each of the four dial sites, so nothing is lost.

### 34.5 Gates

`dns_resolve_chaos_test.go` (23). D1/D2/D3 were each reproduced against the
pre-fix tree with the equivalent assertion before the fix was written. Two
**CONTROLS** are included for the CHAOS-56 reason: a resolver that always shed,
or always served stale, or never refreshed, would pass every defect gate above
while being far worse than the defect — so the suite proves the mechanism still
resolves (`Control_HealthyResolutionStillWorks`) and still tells the truth about
a genuinely unresolvable host (`Control_UnresolvableHostStillFailsAndIsCounted`).

`geoip_hostcache_test.go`'s `TestResolveHost_TTLExpiry` was **inverted**: it
pinned the synchronous-re-resolve-on-expiry behaviour, which is the defect. It
now pins stale-serving, with `TestResolveHost_StaleCeilingForcesResolution`
pinning the other end of the window.

### 34.5a Review finding — stale serving is for POSITIVE entries only

Codex review of PR #1312 (P1), verified and fixed before merge.

The first implementation classified ANY entry past its TTL as stale-servable,
negative entries included. A negative entry's stale value is `nil`, so the
`resolveHost` stale branch returned nil immediately and left the repair entirely
to the asynchronous refresh.

That inverts the stated rationale for stale serving. Serving stale is justified
because *"the alternative to a stale answer is not a fresher one, it is NO
answer"* — true of an address, false of a negative, whose stale value **is** no
answer. So it bought nothing and cost the exact thing the change exists to
prevent: a host that failed to resolve ONCE kept returning nil on the
synchronous path for up to `hostIPCacheStaleMax`, leaving a country-scoped DENY
rule dark for an **hour** after DNS recovered instead of the 30 s the negative
TTL promises. Worse, `refreshAsync` SHEDS when the resolver pool is saturated,
so under sustained load the bypass could persist for the full window. And it was
a REGRESSION against the pre-CHAOS-64 behaviour, which re-resolved synchronously
the moment the negative TTL lapsed.

Fixed by restricting the stale state to `e.ip != nil`. An expired negative is a
MISS and takes the bounded, single-flighted blocking path, picking up a
recovered resolver on the very next request. Pinned by
`TestChaos58_ExpiredNegativeEntryIsNotStaleServed` and
`TestChaos58_ExpiredNegativeStillReResolvesWhenTheResolverPoolIsSaturated`, both
verified failing against the reintroduced pre-fix shape.

**The lesson worth keeping:** a mechanism justified by one case (a usable
address) was applied to every case, and the sibling case turned it into the
defect it was built to remove. A degradation path needs its rationale checked
against each state it can be in, not only the one that motivated it.

### 34.6 Residual risk (owner decisions, recorded not fixed)

- **DNS-1 — the fall-through posture is unchanged.** An unresolvable destination
  still cannot match a geo rule in either direction. Making an unknown country
  match a *block* rule would deny every destination this node cannot resolve —
  a bounded security gap traded for an unbounded availability one. The
  mitigation is the one-hour stale window (which removes the gap entirely for
  any recently-seen destination), the alert and the metric. Operators needing
  hard geo enforcement during a DNS outage should express it as an explicit deny
  rule rather than relying on fall-through. **An admin-selectable
  `geo_on_unresolvable: skip | deny` toggle is the natural next step** and is the
  same shape the register already recommends for WK-1/PX-2.
- **DNS-2 — the cgo resolver's `getaddrinfo` is uncancellable.** The deadline
  reliably releases the request goroutine; the OS thread behind it is bounded
  only by the Go runtime's own 500-thread cap on cgo lookups. The pure-Go
  resolver honours the deadline fully.
- **DNS-3 — the four dial sites still resolve without a Culvert-side bound.**
  They run under a 10 s `net.Dialer` timeout, which bounds the dial including
  resolution, so the unbounded case does not exist there; but they have no
  single-flight either, so a brownout still produces one resolver query per
  request on the dial path. That is inherent to dialling (each request really
  does need its own connection) and is recorded rather than changed.

### 34.7 GEO-1 — a latent process-kill armed by a comment (recorded, not fixed)

Found while sweeping the domain adjacent to CHAOS-64 and **not reachable in the
current tree**, but recorded because of how it is armed.

`internal/geoip.InitGeoDB` claimed:

> Call once at startup. **Subsequent calls replace the open reader atomically.**

The pointer swap is atomic. The *close* is not safe, and the difference between
those two is an error versus a process kill:

```go
// geoCache.lookup
geoDBMu.RLock()
db := geoDB
geoDBMu.RUnlock()      // ← lock released
...
record, err := db.Country(ip)   // ← reader used here, unprotected
```

```go
// InitGeoDB
geoDB = r
geoDBMu.Unlock()
if old != nil { _ = old.Close() }   // ← immediately
```

`geoip2.Reader.Close` delegates to maxminddb's, which **`munmap`s the backing
buffer** (`reader_mmap.go:55`). An in-flight lookup holding the old reader
therefore reads unmapped memory: a **SIGSEGV/SIGBUS, which `recover()` cannot
catch**, which `crashguard.go` never sees, and which leaves no log line. A total
gateway outage with no evidence — the worst failure shape in the register,
strictly worse than the panics CHAOS-24 was built to contain, because
containment is not available at all.

**Reachability today: none.** `loadGeoIP` (`geoip_startup.go`) is the only
production caller and runs from `initGeoIP` (`main.go:198`) during startup,
before the proxy listener serves. There is no SIGHUP path, no admin reload, and
no CP→DP snapshot field for the GeoIP database.

**Why it is recorded rather than fixed.** The danger is not the code, it is the
comment: a runtime GeoIP reload is a natural next feature (CLAUDE.md mandates a
GUI surface for every config option, and the register's WK-4 already asks for
GeoIP staleness surfacing, which invites "so let me reload it"), and the comment
told whoever adds it that the swap was already safe. Building reference counting
for a path with no caller is the wrong trade. What shipped is the correction: the
doc comment now states the hazard, names the three acceptable remedies (hold the
read lock across `db.Country`, reference-count the reader, or never close the old
one — a leaked mapping is strictly cheaper than a crash), and requires one of
them **before** any reload path is added.

**Owner action:** treat "add a GeoIP reload" as blocked on the reader-lifetime
fix, not as a standalone feature.

---

## 35. CHAOS-65 — The OCSP revocation path

**Date:** 2026-09-11 · **Domain:** Certificates / revocation (never previously
swept) · **Code:** `internal/ocsp/ocsp.go`, `ocsp_coverage.go`,
`ocsp_metrics.go`, `ui_security.go`, `mtls_ocsp_startup.go` · **Runbook:**
`docs/operator/ocsp-revocation-checking.md`

> **Id claimed in a committed placeholder row BEFORE any code was written** —
> the remedy the revision log at the head of this file reaches twice,
> independently, after at least ten collisions across six sweeps. This is the
> first sweep to follow it. It cost one commit and one line, and the id has
> been stable since. Every subsequent sweep should do the same.

### Executive summary

The revocation check was reachable, enabled by an ordinary config flag, and
wrong in six ways at once — and the reason they had all survived is the
seventh: **it is wired to a path that almost never handshakes.**

Every input this engine acts on is chosen by **the party being checked**. The
responder URLs come out of the peer's own AIA extension, so the peer picks
which responder is asked, how many are asked, and therefore which bytes come
back. Nothing in the pipeline treated that input as hostile. The sharpest
consequence is a complete revocation bypass performed by the certificate's own
subject, with no network position required.

### The row that already said it

Register row **CA-6**, written in the original 2026-07-04 sweep, reads:

> OCSP fails **closed** when a cert lists responders and none answer;
> `VerifyConnection` re-checks resumed sessions. Caveats: nil-issuer →
> fail-open; **OCSP client has no SSRF guard on the peer-controlled responder
> URL.** — Verdict **✓ (+2 caveats)**, severity **L/M**

The evidence column pointed straight at the finding and the verdict looked past
it. *"Peer-controlled responder URL"* names the exact property — the input is
written by the party being checked — that makes all seven defects reachable;
it was filed as a caveat on a row scored ✓ because the one question asked was
*"does it fail closed?"*, and on the path that was examined, it does.

**The lesson is not "someone missed an SSRF bug".** It is that a control can
fail closed on the path you test and be bypassable on the path you did not, and
that "✓ with caveats" is where a finding goes to stop being looked at. Two
cheap habits would have caught it: score the row by its WEAKEST property rather
than its strongest, and — when a caveat says an input is attacker-controlled —
re-ask every other question in the row with that assumption. CA-6 has been
re-scored to **H** and split, with CA-6b carrying the coverage gap.

### Failure scenarios

**OCSP-1 — a response was not BOUND to the certificate under test. (Critical.)**
`queryOCSP` called `cryptoocsp.ParseResponse(respBytes, issuer)`, which is
`ParseResponseForCert(bytes, nil, issuer)`; with a nil certificate the library
takes `basicResp.TBSResponseData.Responses[0]` and **never compares the
serial** (`x/crypto@v0.56.0/ocsp/ocsp.go:509-528`). The signature *is* verified
against the issuer, so the response must be genuinely CA-signed — which is a far
lower bar than it sounds, because a genuine CA-signed `good` response about any
*other* certificate of the same issuer is obtained by asking that CA about any
live certificate and keeping the bytes. The peer names the responder, so the peer
serves that reply, and a **revoked certificate is accepted**. RFC 6960 defines
CertID with the issuer hashes precisely so a response can be bound to a request;
the binding was simply not performed.

**OCSP-2 — no freshness validation. (High.)** `ThisUpdate` and `NextUpdate` were
parsed and never read. OCSP here rides plaintext HTTP and `CreateRequest(leaf,
issuer, nil)` sends no nonce, so a response is replayable by anyone on the path —
and, again, by the peer itself. A `good` captured before the certificate was
revoked stayed authoritative forever. Fixing OCSP-1 alone does not close this:
a pre-revocation response for the *correct* certificate binds perfectly.

**OCSP-3 — `unknown` was a pass. (Medium-High.)** `checkResponders` set
`anyResponded = true` for any parsed response and returned revoked only for
`Status == Revoked`, so `unknown` admitted the connection — while a responder
that could not be *reached* failed closed. Two postures for one question. Under
the CA/Browser Forum baseline requirements a CA must not answer `good` for a
certificate it never issued, which makes `unknown` exactly the answer a
mis-issued or forged certificate draws: the one case where accepting is worst.

**OCSP-4 — the verdict cache was keyed on the serial alone. (High.)**
`cacheResult(serialHex, …)`. A serial is unique only *within* an issuer. The
harmless direction blocks a good certificate; the dangerous one admits a
genuinely **revoked** certificate from a different CA off another CA's cached
`good`, with no responder query at all. Random 128-bit serials from public CAs
make accidental collision negligible, but sequential serials are the norm in
enterprise PKI (ADCS), and a Culvert deployment with two internal CAs in its
trust store is ordinary, not exotic.

**OCSP-5 — the responder URL was an unguarded SSRF sink. (High.)**
`http.DefaultClient.Do(httpReq)` against a URL read from the peer's certificate:
no scheme allow-list, no `isPrivateHost`, no SSRF-controlled dialer, and
`DefaultClient` follows up to ten redirects, so even a URL-level guard would
have been bypassed by a `302`. Any operator of any destination this gateway
reaches could name `http://169.254.169.254/…` or an internal admin endpoint and
have the proxy POST to it from inside the trust boundary. CLAUDE.md states the
convention this path never followed, in as many words: *"inline `url.Parse` +
scheme check + `isPrivateHost()` before outbound HTTP requests."*

**OCSP-6 — the fan-out was unbounded, and so was the stall. (High.)**
`leaf.OCSPServer` was walked in full with a **per-responder** 5 s timeout.
`VerifyPeerCertificate` runs on the request goroutine inside a TLS handshake,
holding the client connection, an FD and a per-IP `connlimit` slot. A
certificate listing 200 blackholed responders parks that goroutine for ~17
minutes *and* aims 200 outbound POSTs at whatever hosts it names — an outbound
amplifier whose fan-out and targets are both written by the attacker. This is
CHAOS-58's finding in a different subsystem: a per-step allowance is not a
bound.

**OCSP-7 — no single-flight. (Medium.)** Concurrent handshakes to one host all
miss the same cold entry, and each launched its own query, so the gateway
amplified client request rate 1:1 into load on a responder that is by
hypothesis already the slow dependency. Measured pre-fix: 24 concurrent
handshakes → 24 responder queries. The same herd `hostIPCache` (§28/§34) and
`jwksCache` (CHAOS-49) already collapse.

**OCSP-8 — the control is not on the path that handshakes. (High; REPORTED,
not closed.)** `ConfigureTLSConfigOCSP` has exactly two call sites
(`mtls_ocsp_startup.go`, the `/api/ocsp` toggle) and both target
`upstreamOpTLSCfg`, the operator TLS template behind the shared upstream
`*http.Transport`. That transport carries the plain-HTTP forward path — which
never negotiates TLS to an origin — and a TLS connection to an `https://`
**parent proxy** if one is configured. Every inspected HTTPS request takes a
different path: `handleTunnelInspect` and `handleInspectNativeALPN` build their
own `tls.Config` in `upstreamInspectTLSConfig` (`proxy_tunnel.go:627`), and
nothing attaches the callbacks to it. So on the single path where this
appliance terminates and validates an origin certificate on a client's behalf,
revocation is not checked — while the log says "enabled", the panel says
"enabled", and the counters read zero.

**Zero counters are the problem, not the symptom.** "Found nothing wrong" and
"never consulted" render identically, and until this sweep there was no
`/metrics` exposition at all — the only OCSP surface was a role-gated admin
JSON blob nothing scrapes. That is the exact sentence §27 had to write about
the threat feed.

### What shipped

The engine, in `internal/ocsp`:

1. **`ParseResponseForCert(respBytes, leaf, issuer)`** — a response is a verdict
   only when it is about *this* certificate.
2. **`responseFresh`** — `ThisUpdate` not in the future, inside `NextUpdate`,
   and a 24 h ceiling when `NextUpdate` is absent (RFC 6960 §2.4 permits
   omitting it, which without a ceiling is an unbounded replay window). Skew is
   tolerated 5 min in **both** directions, reusing `caClockSkewTolerance`'s
   value rather than inventing a second one: a clock rollback is a fault, not
   an attack, and must not take revocation checking down.
3. **A verdict is AFFIRMATIVE or it is not a verdict** — `Good` or `Revoked`.
   `unknown`, an unbindable response and a stale one are each discarded under
   their own counter, and the existing fail-closed path with its existing
   2-minute `indeterminateTTL` and its existing counter handles the remainder.
   No new posture, no second dialect: CHAOS-53's rule for the scan sidecar.
4. **`certKey` = RFC 6960's CertID fields** (SHA-256 over issuer subject,
   issuer SPKI, plus the serial).
5. **SSRF**: scheme allow-list + `ssrf.PrivateHost` inline at the call site
   (so CodeQL sees the guard, per repo convention), a dedicated client whose
   `DialContext` is `ssrf.SafeDialContext` — closing the rebinding window the
   pre-flight lookup leaves open — and `CheckRedirect` refusing outright.
   Deliberately **not** `http.DefaultClient`: it shares the process-wide default
   transport, follows redirects, and honours `HTTP(S)_PROXY` from the
   environment, none of which is wanted for a request whose URL the peer chose.
   The consequence — responder queries are direct and do not traverse a parent
   proxy — is a behaviour change, recorded in the runbook rather than left to be
   discovered.
6. **One envelope, `maxResponders` 4 inside `queryBudget` 5 s.** The budget is
   deliberately the *old per-responder* timeout, so the ordinary one-responder
   certificate is unchanged and only the worst case shrinks.
7. **Single-flight per certificate**, leader/follower, no follower timer (a
   follower timeout releases it to start exactly the query being collapsed —
   §34's rule). The leader publishes on **every** exit path including a panic,
   and the flight's defaults are the **fail-closed** verdict, so a leader that
   dies leaves its followers denied rather than admitted.

The visibility, in package main: `ocspCoverage()` with a structural gate
comparing each claim against the `tls.Config` the named path actually builds; a
`WARNING` from both enable paths; `culvert_ocsp_*` including the
`culvert_ocsp_path_checked{path}` coverage gauge; `coverage`,
`uncheckedEnforcingPaths` and the four rejection counters on `GET /api/ocsp`;
two banners on the OCSP panel.

**Emitted only when enabled** — the standing rule (`socks5_health.go`,
`cluster_ca_health.go`, `dns_health.go`): a flat zero from every appliance that
never turned the feature on is indistinguishable from a broken one, and trains
operators to ignore the series.

### Why OCSP-8 was reported rather than wired

Attaching the callbacks to `upstreamInspectTLSConfig` is one line. It would also
make **every inspected HTTPS request** depend on reaching an external OCSP
responder, **fail-closed**, on networks where outbound port 80 to arbitrary
hosts is exactly what egress policy forbids. The failure mode is a total HTTPS
outage for the fleet, arriving the moment an operator ticks a checkbox that
today does almost nothing — a posture change with a blast radius the flag's
wording warns nobody about, and reachable from the **live admin API**, so it is
a runtime kill of a gateway carrying traffic rather than a boot decision. (That
is the shape §31's own deferral note got wrong in the other direction, and it
is worth not repeating from either side.)

The engine had to be safe before anything could be wired to it, and now is.
Wiring is a scoped feature with a posture decision attached — observe-only
counters first, or fail-open-and-alert — so that enabling it is reversible in
production instead of a cliff.

### Risk matrix

| Row | Finding | Likelihood | Impact | Status |
|---|---|---|---|---|
| **OCSP-1** | A signed response about another certificate of the same issuer is accepted as this one's verdict | Low-Medium (needs an attacker who wants it; trivial once wanted) | **Critical** — complete revocation bypass by the certificate's own subject | **CLOSED** |
| **OCSP-2** | Pre-revocation response replays forever (no nonce, no freshness check) | Medium | High | **CLOSED** |
| **OCSP-3** | `unknown` treated as a pass while "unreachable" fails closed | Medium | Medium-High | **CLOSED** |
| **OCSP-4** | Verdict cache keyed on serial alone ⇒ cross-issuer confusion, both directions | Medium in enterprise PKI | High | **CLOSED** |
| **OCSP-5** | Responder URL is an unguarded SSRF sink; redirects followed | Medium | High | **CLOSED** |
| **OCSP-6** | Unbounded responder fan-out ⇒ ~17 min handshake stall + outbound amplifier | Low-Medium | High | **CLOSED** |
| **OCSP-7** | No single-flight ⇒ 1:1 amplification onto a failing responder | High whenever it runs | Medium | **CLOSED** |
| **OCSP-1b** | The response was bound to the certificate; the SIGNER was never bound to an authority. A peer signs a `good` about its own serial with its own leaf key and embeds that leaf as the responder — no `id-kp-OCSPSigning` check. Defeats OCSP-1 and is easier than it | Low-Medium | **Critical** — revocation bypass needing no other party at all | **CLOSED** (Codex review) |
| **OCSP-2b** | Freshness checked at receipt, then discarded: a confirmed verdict cached for the full hour regardless of `NextUpdate`. OCSP-2's replay window reopened in the cache | Medium | High | **CLOSED** (Codex review) |
| **OCSP-3b** | Every parse failure charged the "borrowed response" accusation, so a broken responder's HTML 502 raised a standing claim of attack | High (any broken responder) | Medium (false positive on a trust surface) | **CLOSED** (Codex review) |
| **OCSP-7b** | `resolve` opened a flight without re-checking the cache — a late arrival queried again for a verdict already cached | Medium | Low-Medium | **CLOSED** (Codex review) |
| **OCSP-11** | Bounding the responder loop also made the FIRST Good win, so the peer's own AIA ordering decides the verdict; a later Revoked was never consulted | Medium (replication lag alone reaches it) | **High** — a security posture moved as a side effect of a cost change | **CLOSED** (Codex review) |
| **OCSP-12** | A dial-time SSRF refusal (DNS rebinding) was charged to nothing, so the guard's own success was invisible on the surface built to expose it | Low-Medium | Medium | **CLOSED** (Codex review) |
| **OCSP-13** | The cache honoured the ASSERTION's deadline (OCSP-2b) but never the SIGNER's: a delegate expiring in seconds could sign a `good` valid for a day, and the cached verdict outlived the authority it rested on | Low-Medium (a CA rotating a delegated responder) | Medium | **CLOSED** (Codex review) |
| **OCSP-14** | The SSRF pre-flight has THREE outcomes and the call site read two: a DNS failure charged the `responder_blocked` ACCUSATION, whose runbook tells the operator the responder resolved privately | High (any DNS outage) | Medium (false accusation on a trust surface) | **CLOSED** (Codex review) |
| **OCSP-8** | Revocation not checked on inspected HTTPS; control reports itself healthy | **Certain** (it is the default wiring) | High (security control dark) | **OPEN — owner posture decision, now visible on three surfaces** |

### Recovery assessment

Automatic in every closed row. A fail-closed verdict is cached on the 2-minute
`indeterminateTTL`, so connections resume within that window once responders
answer again — there is nothing to clear by hand, and the CHAOS-04 amplification
this TTL exists to prevent is unchanged. The break-glass is the existing toggle,
audited as `ocsp.toggle`, deliberately off the config-version rollback surface.

### Residual risk

- **OCSP-8 is open by design** and is the dominant residual: on a Secure Web
  Gateway, "revocation checking is on" currently means "for the parent-proxy
  handshake". It is now stated in the log, the panel, the API and a metric, but
  it is still the gap.
- **Responder queries are direct.** They do not traverse a configured parent
  proxy and no longer honour `HTTP(S)_PROXY`. An egress-restricted deployment
  must allow the responder hosts; an internally-hosted enterprise responder is
  refused by the SSRF guard and is, for now, unsupported. Recorded rather than
  weakened — the alternative is re-opening OCSP-5.
- **No stapling.** Culvert never asks for or consumes a stapled OCSP response
  (`tls.ConnectionState.OCSPResponse`), which is the deployment shape that makes
  revocation checking cheap, private and egress-free — and is the natural
  companion to closing OCSP-8. Not in scope here; recorded as **OCSP-9**.
- **No CRL fallback.** The panel is titled "OCSP / CRL Revocation"; only OCSP
  exists. A certificate with no AIA responder is accepted without a check —
  unchanged by this sweep, recorded as **OCSP-10**.
- **`maxResponders` = 4 is a constant**, like every other bound in this file
  whose only use would be widening an attack window.

### The review round: binding a response is only half of it

Codex reviewed the shipped engine and found four more, each reproduced against
the tree that had just fixed OCSP-1. **The first defeats that fix outright, and
it is the more important finding of the two.**

**OCSP-1b — the RESPONSE was bound; the SIGNER was not. (Critical.)**
`ParseResponseForCert` verifies an embedded responder certificate by asking one
question — did the ISSUER sign it? — and never asks RFC 6960 §4.2.2.2's: does it
carry `id-kp-OCSPSigning`? **The peer's own leaf is, by definition, a
certificate the issuer signed, and the peer holds its private key.** So the peer
signs a fresh `good` about its OWN serial, embeds its own leaf as the responder
certificate, and serves it from the responder URL in its own AIA. A revoked
certificate is accepted — needing no response from anyone else at all, which
makes it *strictly easier* than the borrowed-response vector OCSP-1 closed.

**The lesson is the one this sweep had already written down and then only half
applied.** OCSP-1's own reasoning was "the peer picks the responder, so the peer
picks the answer" — and the fix asked only *which certificate is this response
about?* while leaving *who was allowed to say so?* unasked. Binding an assertion
to its subject is worth nothing until the signer is also bound to an authority.
Now only two signers are authorized: the issuer itself, and a delegate it signed
that carries the OCSP-signing EKU and is inside its own validity window.
`ExtKeyUsageAny` is deliberately refused — honouring it would re-admit every
ordinary leaf the issuer ever signed, which is the whole attack. Delegated
responders are ordinary, so refusing every embedded certificate is not the fix;
that shape is pinned as a CONTROL.

**OCSP-2b — freshness was checked at receipt and then thrown away. (High.)**
Every confirmed verdict was cached for the fixed 1 h `cacheTTL`, so a `good`
whose `NextUpdate` was a minute out kept admitting the certificate for another
59 minutes after the responder stopped vouching for it: **the replay window
OCSP-2 closed on the wire, reopened in the cache.** Same shape as OCSP-1b — a
rule enforced at one layer and not carried to the next. The TTL is now the
earlier of `cacheTTL` and the response's own deadline, and a verdict already at
its deadline is not cached at all.

**OCSP-3b — the accusation counter cried wolf at a 502. (Medium.)** Every
`ParseResponseForCert` error charged `notForCertTotal`, whose metric help and
red panel banner both read *"something is answering with borrowed responses"*.
An HTML error page from a broken responder therefore raised a standing claim of
attack — on a surface whose whole job is to be believed, and against this
register's own rule about false positives on such surfaces. The accusation is
now charged only when it is demonstrable (the response parses, its signature
verifies against the issuer, and the serial is someone else's); everything else
is `malformed`. Note *why* a second parse is needed rather than a string match:
the library checks the serial BEFORE it verifies any signature, so its
serial-mismatch error on its own proves nothing about who signed.

**OCSP-11 — a security posture moved as a side effect of a cost change.
(High.)** The pre-CHAOS-65 loop walked every responder and returned revoked if
ANY of them said so. The rewrite added a `case Good: return` to save queries, so
the FIRST responder decides — and **the peer writes the AIA list and its
ORDER**, which hands the verdict back to the party being checked. That is this
sweep's own finding, reintroduced by this sweep, inside the change that bounded
the loop. It also accepts a certificate during ordinary responder replication
lag. Restored: a Good is remembered (with the EARLIEST deadline among the Good
answers, for the cache) and the loop continues; only Revoked short-circuits.
**A cost change must not quietly move a security posture** — and the way to
notice is to diff the CONTROL FLOW of the thing being sped up against what it
replaced, not just its outputs on the happy path.

**OCSP-12 — the guard fired and nothing counted it. (Medium.)** A responder host
that answers public to the pre-flight `ssrf.PrivateHost` check and private to
the dial is exactly what `ssrf.SafeDialContext` exists to catch, and it does —
but its `ErrBlocked` arrived at the generic transport branch, so the
DNS-rebinding attack moved neither `responderBlockedTotal` nor
`culvert_ocsp_response_rejected_total{reason="responder_blocked"}`. The
defence worked and was invisible on the surface built to expose it. Same family
as OCSP-3b: the counters have to say what actually happened.

**OCSP-7b — the single-flight had a hole on the late arrival. (Low-Medium.)**
`resolve` opened a flight without re-checking the cache, so a handshake
descheduled while the leader finished would start a redundant query for a
verdict already cached — defeating the collapsing during exactly the cold-cache
burst it exists for.

**OCSP-14 — a DNS outage was reported as an SSRF refusal. (Medium.)**
`ssrf.PrivateHostContext` has three outcomes — allowed, refused-as-private, and
could-not-determine (DNS failure, or this query's own budget expiring
mid-lookup) — and the call site treated any error as the middle one. So an
ordinary resolver outage inflated
`culvert_ocsp_response_rejected_total{reason="responder_blocked"}`, whose
runbook states the responder resolved into a private range and sends the
operator down an entirely different remediation.

Neither branch of the guard wrapped a sentinel, so the caller could not have
distinguished them: the fix is at both layers. `ErrBlocked` — previously
documented as the connect-time `Control` sentinel — now wraps the pre-flight
refusal too, so ONE identity means "we refused this destination as private" at
whichever layer decided it, and the resolution-failure branch deliberately does
NOT wrap it. The OCSP call site charges the counter only on
`errors.Is(err, ssrf.ErrBlocked)`; a resolution failure is an unreachable
responder, already accounted by the fail-closed path, and takes no
`response_rejected_total` reason because no response existed to reject.

**This is the second time in this sweep that an accusation counter was charged
for something it could not demonstrate** — OCSP-3b was the same defect on
`not_for_certificate`, where any parse failure raised a standing claim of
attack. Both were introduced by the same reflex: the error path was treated as
one thing because it arrives as one value. The rule the register keeps from
this: *a counter an operator is told to act on must be charged only from
evidence that supports the specific claim its runbook makes* — and when a guard
can fail for more than one reason, the caller needs the guard to say which, not
a best guess at the call site.

**OCSP-13 — the cache outlived its SIGNER, after being taught to respect its
ASSERTION. (Medium.)** OCSP-2b made `cacheResult` honour the response's own
`NextUpdate`. Two checks bound a verdict at parse time, though, and only one of
them was carried down: `responseFresh` bounds the assertion, `responderAuthorized`
bounds the signer. `responseValidUntil` never looked at `resp.Certificate`, so a
delegated responder valid for another thirty seconds could sign a `good` whose
`NextUpdate` was a day out — the handshake that parsed it cached the verdict, and
later handshakes kept admitting the certificate for the rest of the cache TTL
while a re-parse of those identical bytes would have refused them as an
unauthorized responder.

The cap now mirrors `responderAuthorized`'s branch structure exactly, so the
cache expires at precisely the instant a re-parse would begin rejecting.

**This is the third instance of one pattern in a single sweep**, which is the
part worth carrying forward. OCSP-1 bound the response to its subject; OCSP-1b
bound the signer to an authority; OCSP-2b carried the assertion's deadline into
the cache; OCSP-13 carried the signer's. Each time the rule was enforced where it
was first noticed and not at the next layer down, and each time the gap was found
by someone else rather than by the sweep that wrote the rule. *A check that runs
at parse time governs a value that outlives the parse* — so for every new
validity rule, ask what caches the result and for how long, in the same change.

### Two defects the fix itself introduced

Both found in an adversarial re-read of the diff, before merge, and both worth
recording because each is a general trap rather than a slip.

**The guard became the unbounded call.** `ssrf.PrivateHost` resolves under
`context.Background()`. Reaching for it from a TLS handshake on the request
goroutine makes the SSRF pre-check the thing that blocks for the system
resolver's full budget — on a hostname written by the peer. That is §34's fault
re-imported through the fix for OCSP-5, and strictly worse than what it
replaced. `internal/ssrf` gains `PrivateHostContext`; `PrivateHost` delegates
with a background context, so every existing caller is byte-identical. **The
general trap: a guard added to a hot path is code on the hot path, and inherits
every bound the path already required.**

**The single-flight collapsed the REFUSALS along with the queries.** Followers
inherited the leader's fail-closed verdict without charging
`fail_closed_total`, so a fail-closed storm under-reported itself by however
many handshakes happened to arrive concurrently — worst exactly when the storm
is worst, and that counter is what the runbook tells an operator to alert on.
The pre-existing cached-fail-closed path already charges every hit for this
reason, which is what made the inconsistency findable. `revokedTotal` is
deliberately *not* charged there: it counts responder CONFIRMATIONS, and the
cached confirmed-revocation path does not charge it either. **The general trap:
deduplicating work is not deduplicating events — ask, per counter, whether it
measures the work or the outcome.**

### Gates

`internal/ocsp/ocsp_chaos_test.go` — 8 defect gates, **each verified failing
against the pre-fix tree**, plus 2 gates for the self-review defects above
(each mutation-checked against the shape it replaces), 7 gates for the two Codex
rounds (each verified failing against the tree that shipped the original fix)
and 6 controls (a checker that refused everything
would pass all eight while being a fleet-wide HTTPS outage: a healthy `good` is
still accepted and still cached, a genuine revocation still blocks and still
counts as a revocation rather than a fail-close, and a disabled checker still
queries nothing). `ocsp_coverage_test.go` — 4 gates pinning the AGREEMENT
between the coverage claim and the `tls.Config` each named path builds, in both
directions, plus the emit-only-when-enabled rule; the agreement gate was
mutation-checked by flipping the claim and confirming the failure.

---

## 36. CHAOS-66 — The SOCKS5 listener's BIND, and which plane may kill which

**Date:** 2026-09-12
**Scope:** `startSOCKS5` / `initSOCKS5` / the SOCKS5 listener lifecycle, and the
classifier it shares with the admin UI listener.
**Status:** Shipped. Closes the register row CHAOS-57 (§33) left open:
*"`startSOCKS5`'s BIND failure is still fatal — an occupied SOCKS5 port takes
down HTTP proxying."*

### The finding

`startSOCKS5` bound its listener with exactly one error branch:

```go
ln, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", port))
if err != nil {
        logFatalf("SOCKS5 listen error: %v", err)   // ← os.Exit(1)
}
```

So every way the OPTIONAL SOCKS5 listener could fail to bind terminated the
whole appliance. And it did so from `initSOCKS5`, which `main.go` runs at line
239 — **before `startAdminUI` and before `buildAndStartProxyServer`** — so the
HTTP/HTTPS proxy and the admin UI never start at all.

This is §33's finding one plane over, and it lands strictly harder. There the
MANAGEMENT plane killed the DATA plane. Here a **secondary, opt-in data plane**
— SOCKS5 is off by default (`-socks5-port 0`) — kills the **primary** data
plane, the management plane and the health endpoints, before any of them exist.

### Reproduction (real binary, not reasoned about)

Port 11080 held by an unrelated process:

```
$ ./culvert -port 18080 -ui-port 19090 -socks5-port 11080
...
SOCKS5 listen error: listen tcp :11080: bind: address already in use
EXIT CODE: 1

$ curl -x http://127.0.0.1:18080 http://example.com
proxy http_code=000                    ← the HTTP proxy port never listened
$ grep -c 'UIHTTP\|Admin UI' boot.log
0                                      ← startAdminUI never ran
```

Three routine triggers, none of them visible to the one check that looks like it
should catch them — `validatePortCollisions` compares Culvert's own three ports
to EACH OTHER only, and nothing else on the host is in its field of view:

- **`port_in_use` (EADDRINUSE)** — a predecessor container still draining, a
  host-network service, an operator collision, a second Culvert instance.
- **`permission_denied` (EACCES/EPERM)** — a privileged SOCKS5 port on a
  deployment that dropped `CAP_NET_BIND_SERVICE` or stopped running as root.
- **`address_unavailable` (EADDRNOTAVAIL)** — binding before the interface the
  address lives on is up: an ordinary host-boot race.

Under `restart: unless-stopped` (three services in the shipped
`docker-compose.yml`) each becomes an unattended **crash loop**: no proxy, no
admin UI, no `/health`, no `/ready`, recoverable only with shell access. That is
the terminal state §19 closed for the category store and §33 for the admin UI,
reached this time from a subsystem the customer may not even be using.

**"It exits, so it fails closed" is wrong here and must not be re-argued.**
§33 states the reason: process death picks NO posture, it delegates the choice
to the topology. An explicit-proxy fleet loses all egress; a PAC/WPAD fleet with
a `DIRECT` fallback, or a transparent deployment that bypasses a dead next hop,
goes **unfiltered**.

### The fix

A `socks5Supervisor` (`socks5_bind.go`) owns bind → serve → rebind.
`socks5Server` — the unit §22's 18 accept-loop gates construct directly from a
pre-bound listener — is **byte-identical**, which is what lets this change add a
lifecycle without disturbing the semantics those gates pin.

Five rules, all borrowed from CHAOS-54/55/57 rather than invented as a second
dialect:

1. **No bind path is fatal.** `startSOCKS5` always returns a live handle.
2. **Retry is RATE-bounded, never COUNT-bounded** (1 s doubling to 30 s, ±20%
   jitter). The terminal state of "give up" is a configured service that is gone
   until someone restarts the appliance — the outcome this change removes.
   *"Avoid infinite retries"* is satisfied the CHAOS-54/55 way: the retry is
   never SILENT (onset logged immediately, then ≤1 line/60 s, then a recovery
   line naming the suppressed count, magnitude in a counter).
3. **Recovery is declared on OBSERVED evidence only** — a listener that actually
   bound. Elapsed time never clears the state, because a loop that stopped
   failing because it stopped attempting looks identical to a bound one.
4. **The sleep is INTERRUPTIBLE**, so the 2 s `socks5-listener-stop` shutdown
   budget is never spent waiting out a 30 s backoff.
5. **Reason classes are BOUNDED**, matched with `errors.As` on `syscall.Errno`,
   never by string. The raw error reaches the rate-limited log and nowhere else:
   an unbounded reason gives the alert dedup key one value per failure (the
   WK-12/RS-5 defect) and would put the listener address on a viewer-role
   surface.

Three further decisions worth recording because each had a plausible
alternative:

**`noteSOCKS5Configured` moved BEFORE the first bind attempt.** It gates every
SOCKS5 surface, so leaving it after a successful bind means a listener that has
NEVER come up reports *"SOCKS5 listener not configured"* — byte-identical to the
ordinary appliance that never asked for SOCKS5, on precisely the node where an
operator is trying to find out why SOCKS5 is unreachable. This is the same
reasoning CHAOS-54 applied one step later when it moved the call ahead of the
accept loop.

**An observed bind now CLEARS the accept plane's `down`.** §22 recorded `down`
as terminal for the process, which was correct when nothing re-opened the
socket. Something does now, and a fresh socket is exactly the recovery for an
unrecoverable one. Had it not been cleared, a listener that recovered would keep
reporting a fail row, a `listener_up 0` gauge and a page until the node
restarted — reporting an outage that is over. The `down` row's operator action
moved with it: it used to read *"Restart this node to rebind the SOCKS5
listener"*, which after this change would be advice that costs a production
outage to achieve what already happens on its own.

**The backoff is never reset inside the loop**, exactly as
`serveAdminUIWithRetry` does it. Resetting on every successful bind would let a
socket that dies immediately after each bind settle into a steady
one-bind-per-floor cadence forever; letting it escalate monotonically to the
ceiling bounds that pathological case at one attempt per 30 s. The cost — a
listener that recovers after a long outage and only later loses its socket
rebinds at the escalated rate rather than the floor — is bounded by the ceiling
and strictly better than the pre-change behaviour, which never rebound at all.

### A second, smaller finding: `network_error` was unreachable-by-accident

`classifyAdminUIListenError` (shipped in §33) ends:

```go
var ne net.Error
if errors.As(err, &ne) { return "network_error" }
return "listen_failed"
```

Every bind failure arrives as `*net.OpError`, which satisfies `net.Error`
**unconditionally** (verified: `Timeout()` is false for a bind `EINVAL`). So the
branch swallowed every unrecognised errno into a class naming the wrong
subsystem — sending an operator down a network-troubleshooting path for a socket
or permission fault — and made `listen_failed` unreachable for any error the net
package produced. The original gate passed only a bare `errors.New`, which is
the one shape that *does* reach `listen_failed`, so the branch looked correct.

Both classifiers now require `ne.Timeout()`. The lesson is the §35 one in a
different costume: *a table-driven classifier gate proves only as much as the
shapes it feeds in* — and the shape that mattered here is the one the production
path actually produces.

### Verification

The fix was verified against the real binary, not only in test. With the port
held at boot:

```
proxy http_code=403        ← the proxy is serving and enforcing policy
adminui http_code=200      ← the admin UI is serving
/health: {"status":"ok", ..., "socks5":"degraded", "admin_ui":"ready"}
ERROR SOCKS5 listener on port 11080 could not bind (port_in_use): ... —
  retrying in 878ms; the HTTP/HTTPS proxy data plane and the admin UI are unaffected
```

…and after releasing the port, with **no restart**:

```
SOCKS5: listener on port 11080 bound and accepting again (4 suppressed bind-failure log line(s))
SOCKS5 OK 127.0.0.1 -> "104.20.23.154:80"
```

Note the jitter (878 ms against a 1 s floor) and the rate gate (one line, four
suppressed, across 31 s) are both visible in the real run.

### Surfaces

All reuse existing operator vocabulary; **no new alert event**, because a new
name would be silently unsubscribed on every configured webhook (the §27 rule).
`socks5_listener_down` now carries the bind case too, with a Detail that states
explicitly that the rest of the appliance is serving — the single most important
fact for whoever it pages, since before this change the condition meant the
whole gateway was gone.

- `/api/diagnostics` — the existing `socks5_listener` row, with bind branches
  ahead of the accept branches (a listener with no socket at all is a more
  fundamental state, and while unbound the accept-plane fields describe the
  PREVIOUS socket).
- `/readyz` — the existing report-only `socks5` row. Report-only stays
  load-bearing: a node whose SOCKS5 listener cannot bind proxies HTTP/HTTPS
  perfectly, and failing the default verdict would eject a healthy gateway over
  an optional subsystem. Fixed detail strings — `/readyz` is unauthenticated.
- `/healthz` — the existing `socks5` field; the enum is unchanged
  (`disabled`/`ready`/`degraded`/`down`), so no dashboard or probe changes.
- `/metrics` — `culvert_socks5_unavailable`, `_bind_failures_total`,
  `_binds_total`, `_bind_backoff_seconds`, emitted **only when configured** (the
  CHAOS-54 rule: a flat 0 from every appliance that never enabled SOCKS5 is
  indistinguishable from a broken listener, and the paging rule is `== 0`).
  `culvert_socks5_listener_up` extends symmetrically — 0 when the accept loop
  stopped OR the bind has failed past the threshold; a listener merely retrying
  stays 1, so an ordinary redeploy does not page.

### Gates

`socks5_bind_chaos_test.go` — 20 gates. "Verified failing against the pre-fix
shape" has a stronger meaning than usual here: the pre-fix shape calls
`os.Exit(1)`, which kills the TEST BINARY mid-run and takes the whole package
with it, so the defect cannot be reintroduced and kept green (the §33 property).

Six mutations were each applied to the fixed tree and confirmed to fail their
gate: a non-interruptible backoff sleep; `adopt` ignoring a concurrent `Stop`;
`configured` recorded only after a successful bind; a rebind that does not clear
the accept-plane `down`; unavailability keyed on a COUNT instead of a DURATION;
and the reverted classifier narrowing.

**One gate was found vacuous and replaced, which is worth recording.** The
adopt/Stop race was first gated end-to-end — start the supervisor, `Stop`
immediately, assert the port is free — and it passed against the broken build,
because the loop exits at its top `stopRequested` check before ever reaching the
bind, so the window was never entered. The window is real (`go s.run()` can be
scheduled onto another P and be inside `lc.Listen` while the caller is already
in `Stop`) but is microseconds wide and cannot be scheduled from a test, and a
gate that can flake gets muted. It is now pinned as a UNIT on `adopt`'s
invariant — `Stop` sets `stopped` under the same lock BEFORE it reads `cur` —
which catches the mutation deterministically; the end-to-end version was kept,
renamed to what it actually proves.

Two CONTROLS, because the cheapest way to pass every "it did not exit"
assertion is to delete the fatal and report the listener healthy — strictly
WORSE than the defect, trading a loud crash loop for a SOCKS5 service that is
silently absent forever on a node whose every probe reads green:
`ControlUnboundListenerIsNeverReportedReady` (every surface must say so, in both
the transient and the sustained state) and `ControlHealthyBindIsSilent` (the
fault plane must not tax the healthy plane — no alert, no warn row, no counter
movement, and the listener genuinely accepts).

A STRUCTURAL wall (`TheSOCKS5ListenerPathHasNoFatal`) scans the three listener
sources for `logFatalf`/`log.Fatal`, with a not-vacuous line-count check.
Behavioural coverage cannot name this reintroduction — a returning `logFatalf`
kills the test binary rather than failing an assertion, so the signal would be
an unexplained package-wide crash. It deliberately does NOT cover `main.go`'s
`logFatalf("Proxy error")`, which is correct and must stay: the proxy IS the
product, and a gateway that cannot serve must exit loudly rather than linger as
a black hole. **That asymmetry — an optional listener degrades, the primary one
does not — is the whole finding.**

### Residual risk / deliberately left

- **The other boot-path fatals are untouched** (register row R-F): `catStore`
  (`urlcategories_startup.go`), the blocklist file (`blocklist_startup.go`) and
  the policy file (`main.go`) still `logFatalf` on a load error that is not
  `IsNotExist`. These are POLICY-load-bearing — a gateway that silently starts
  with no policy is a worse failure than one that refuses to start — so the
  posture is defensible, unlike a listener's. It deserves its own sweep with an
  owner decision on each, not a drive-by change inside this one.
- **`startUI`'s sibling faults** are already closed by §33; the CP gRPC bind
  (`cluster_startup.go`) remains fatal and is the closest unexamined analogue —
  recorded, not changed here (one concern per change).
- **SOCKS5 still never consults the policy engine** (no category/GeoIP/schedule
  rules, no default-deny) — §22's residual, unchanged.
- A listener that binds successfully and whose socket dies instantly on every
  accept will cycle at the 30 s ceiling indefinitely. It is rate-bounded, loudly
  reported (`down`, alert, gauge at zero) and strictly better than the previous
  terminal state, but it is a cycle rather than a convergence.
