# Security Regression Review — 2026-11-19

**Scope.** `348a2cf…491b963` — the window since the 2026-11-18 review: 14 merged
pull requests (#1941–#1954), 31 non-merge commits, 89 files, +8,302/−688.
Reviewed at `491b96306bc27d64d77c63ebcf39c756623243ba`, which is also
`origin/main`.

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `348a2cf`?** Every verdict is measured against that
revision. Where a finding is pre-existing rather than newly introduced, it says
so.

**Headline.** This window is predominantly hardening, and it closed every
behavioural finding the 2026-11-18 review raised. Its largest single change is a
*new* control — the CHAOS-123 blocklist-feed freshness plane — and the one
material defect is in that control's own paging path: the once-per-episode latch
was consumed by an alert that was never dispatched, so a node in the **default
posture** (no webhooks configured) burns its single page before any subscriber
exists and never pages again for a deny list that has stopped refreshing
(Finding A). A second, much narrower defect was introduced by the CDR pool
re-dial: a withdrawn pool member's connection is closed while the member is
still published, and `pick` has no way to skip it (Finding B). Both are fixed
here, each proven by reverting the fix and watching the new gate fail. A
pre-existing credential echo in `bootstrap-resolve`'s refusal — the exact class
this window's own `fa8c906` fixed for the main binary, never propagated to that
FlagSet — is also fixed (Finding C).

| Change | Security surface |
|---|---|
| `liveVictimLocked` (hashcache) | Eviction no longer makes the fail-closed scan-timeout cooldown the standing victim. **Closes 2026-11-18 Finding A** |
| `store_savelock_test.go` → `List` | The "no persistence under `mu`" probe is no longer blind. **Closes 2026-11-18 Finding B** |
| `Store.Update` URL preservation | A URL-less PUT no longer blanks the destination while keeping the subscription live. **Closes 2026-11-18 Finding C** |
| `runner.go` `.`/`..` rejection | `culvert-maint`'s `ComposeFile` acceptance set matches the installer's. **Closes 2026-11-18 Finding F** |
| `observability_startup.go` | Four `%v`/`%s` sinks on operator paths and OS error bytes gained `sanitizeLog` + `%q`. **Closes a pre-existing CWE-117** |
| `auth_oidc.go` + `config.example.yaml` | Comment/doc only: records that `requiredScope`/`requiredAudience` are credential-path only. **Documents 2026-11-18 Finding E; no behaviour change** |
| CHAOS-123 freshness plane | A stale/never-synced remote blocklist feed now has a WARN row, Prometheus gauges and an alert. **New detection for a deny control — and the source of Finding A** |
| `canonicalDestLiteral` (policy) | An IP-literal destination rule is matched by ADDRESS, not spelling. **Hardening — closes a Block/Drop bypass** |
| `cdr_pool_reconcile.go` | An enrolled Sluice whose bundle was unreadable at pool build re-dials without a restart. **Availability of a security control — and the source of Finding B** |
| `noteCDRFailOpenPassthrough` | A recent unsanitized CDR passthrough is now a diagnostics row. **New visibility over an existing fail-open posture** |
| `fireScanTimeoutAlert` | The `scan_timeout` producer is `HasSubscriber`-gated. **Neutral for enforcement; removes work from a degraded node** |
| `redactArgValuesWith` (fa8c906) | A dash-leading flag value is redacted from the CHAOS-122 refusal. **Hardening — and the sibling the `bootstrap-resolve` copy never got (Finding C)** |
| `env_put` lock decision (install.sh) | A sibling creating the lock mid-check no longer silently skips a secret write. **Fail-safe direction** |
| `internal/mcp/evidenceview`, `internal/mcp/shadowmetrics` | IM-009 / IM-011 package extractions. **Behaviour-preserving; proven byte-identical** |
| `trafficStatus.ts` | Traffic rows carry severity and meaning for scan/file/threat/CDR/decrypt statuses. **Operator-facing accuracy — `CDR_ERROR` corrected mid-window** |

**Method.** Four independent investigations ran in parallel over the CDR plane,
the CHAOS-123 freshness plane, the secrets/alerts/install/argv surfaces, and the
MCP extractions plus the admin and frontend surfaces. The policy engine, the
scan-cache fix, the OIDC change and the proxy request path were reviewed
directly. Every finding below was re-derived from source by the reviewer — no
finding rests on a worker summary — and all three fixes are proven
differentially.

---

## No regression found in

- **The IP-literal destination fix (`3bcc9de` + `d67943f`).** This is a
  tightening: a `Block`/`Drop` rule on `192.0.2.7` previously did not match
  `[::ffff:192.0.2.7]`, and one on `2001:db8::1` did not match `2001:db8:0::1`
  or the bracketed form `r.Host` carries on a port-less request, so the request
  took a lower rule or the default action and was forwarded to the address the
  rule named. `canonicalDestLiteral` (`policy_destliteral.go:31`) is applied to
  **both** sides of the FQDN comparison — the published pattern in `sortLocked`
  (`policy.go:1426`) and the request host via `hostCatScratch.fqdnHost`
  (`policy_hostcat.go:115`). I verified the completeness of the spelling
  coverage end to end: `handleRequest` strips the port with `net.SplitHostPort`
  (`proxy.go:1681-1683`), which also removes IPv6 brackets, so the port-carrying
  form reaches `Evaluate` bare; the port-less bracketed form is unbracketed
  inside `canonicalDestLiteral`; and `::ffff:` forms are `Unmap()`ed. Zoned
  addresses are deliberately left alone, matching `sourceLiteralPrefix` on the
  source side.
  The first cut of this change *was* over-broad — it rewrote the host for the
  whole Stage-2 scan, so a custom category listing `2001:db8:0::1` stopped
  matching the request spelling it that way — and `d67943f` corrected the scope
  to the FQDN predicate alone before the window closed. I checked the hazard
  that correction introduces: `fqdnHost` memoizes per scratch, so a scratch
  reused across hosts would return a stale canonical host and mis-match. Every
  construction site builds a fresh scratch bound to one host
  (`policy.go:1709`, `:2491`, `:2709`, `:2727`, `cdrpolicy.go:491`,
  `authpolicy.go:585`); there is no `sync.Pool`, and `authMatchScratch.hostCat`
  assigns a whole fresh value, which clears `fqdnHostSet`. The prefilter takes
  the same canonical host as the check it filters for (`policy.go:1726`).
- **The scan-cache eviction fix (2026-11-18 Finding A).** `liveVictimLocked`
  (`internal/hashcache/hashcache.go:361`) returns the heap root when the root
  carries the full configured lifetime, and otherwise prefers the
  earliest-expiring full-lifetime entry within a bounded 8-slot scan, falling
  back to the root when none is found. I checked the classification predicate
  for drift: `c.ttl` is assigned only in `New` (`:121`) and has no setter, so an
  entry's `lifetime >= c.ttl` verdict cannot change under it at runtime.
  Termination and the bound are preserved — a victim is always returned, so the
  cache never grows past `maxSize`. Uniform-TTL behaviour is unchanged, as
  claimed. The enforcement side is untouched: `internal/secscan`'s only change
  this window is a test, and it pins that a cooldown hit is still the
  fail-closed `timeout` verdict served without an engine call
  (`scan_saturation_chaos_test.go:552`), so evicting a cooldown costs a
  stampede, never an allow.
- **The `scan_timeout` producer gate (`b14d87f`).** The `go` keyword moved
  *inside* `fireScanTimeoutAlert` (`alerts.go:131-141`), so the only new work on
  the request path is `HasSubscriber`, which is `as.subs.Load()` plus a map read
  on an immutable published view (`internal/alerts/store.go:695-701`) — no lock
  a slow fsync could hold. Enforcement is independent of the gate at both call
  sites: `statBlocked`, `recordRequestAuthURI(..., "SCAN_BLOCKED", ...)`, the
  log line and the 403 all sit outside it (`proxy_http.go:394-401`,
  `proxy_tunnel.go:1592-1598`). `fireAlert`/`Dispatch` is the sole consumer of
  the event — the identically-named `culvert_scan_timeout_total` metric is
  produced on a separate path — so no consumer lost the signal.
- **The CDR fail-open posture.** The only change inside the enforcement branch
  is `noteCDRFailOpenPassthrough()` added to the existing `cfg.CDRFailOpen()`
  arm (`cdr_proxy.go:701`); the decision and the `cdrPass` outcome are
  unchanged. The window therefore adds visibility over an existing posture
  rather than changing it. The monotonic rewrite of the window measurement is
  fail-safe in every direction I enumerated: a forward wall-clock step no longer
  ages the row out early, a backward step is no longer clamped to "just now",
  and a zero stamp cannot coexist with a non-zero counter because both are
  written in the same branch.
- **The CDR re-dial's authentication parity and bootstrap guard.** The re-dial
  calls the same `dialEnrolledInstance` the pool build calls
  (`cdr_pool_reconcile.go:180` vs `buildCDRPoolFromRegistry`, `cdr_pool.go:364`) — there is no second dial
  implementation — so the mTLS and server-pin requirements are identical, and
  `loadCDRCertBundle` returns an error on any unreadable path, so no pool entry
  is ever created with empty credentials. The bootstrap arm is gated on
  `cdrBootstrapRedialArmed && len(live) == 0 && Endpoint != "" &&
  ServerFingerprint != "" && CertsDir != ""` (`cdr_pool_reconcile.go:253`). I traced that flag's full
  lifecycle: it is cleared at the top of **every** build and set only when that
  same build was an empty-registry build that failed completely
  (`cdrstore.go:547-552`), and cleared on every teardown (`:613`). So the
  re-dial can only retry a bootstrap the most recent pool build itself attempted
  — it never introduces one where the build did not try it — and an admin
  delete cannot switch it on.
- **The freshness plane cannot touch enforcement.** Every function in
  `blocklist_feed_health.go` is observational (`note*`, `evaluate*`, `state`,
  `accumulate*`, `check*`, `writePrometheus`); it reads `blFeedSyncer.Feeds()`
  and writes only its own health record. Nothing in the window deletes, expires
  or clears blocklist entries — the "clear/reset" vocabulary in the diff is
  entirely about the alert-episode latch and the health counters — so a stale
  feed keeps enforcing everything it had already imported.
- **The staleness bound cannot be inflated into silence.** `blocklistFeedStaleAfter`
  is `max(2*interval, MaxHealthyGap(interval, N) + TickInterval)`
  (`blocklist_feed_health.go:535`), and the floor binds only while
  `2*interval < TickInterval + 2*N*httpTimeout`. For hour-scale intervals the
  documented 2× threshold is intact regardless of feed count (24 h at 1 feed and
  at 100 feeds both give 48 h), so adding feeds cannot dilute the detector for
  realistic configurations. The per-fetch bound is deliberately static so "a
  stalled scheduler cannot widen its own freshness bound"
  (`internal/blocklistfeed/blocklistfeed.go:241-245`). A zero or negative
  interval is clamped in `SetFeed` and leaves the auto-sync set entirely.
  "Never synced" is fail-closed: past a 15-minute grace it counts as stale
  (`blocklist_feed_health.go:489-500`).
- **The dropped feed-status mutator.** `SeedFeedStatusForTest` existed in
  non-test code only between `cd565f4` and `0ad6ee0`, and its callers were all
  in `_test.go` files — no handler, no `uiRoutes` entry, no MCP tool. Its
  removal is correct hardening against a latent boundary violation, not the
  closure of a live privilege path. At HEAD the only exported writers set
  existence and interval or perform a real guarded fetch; there is no way to
  advance `lastSync` without a successful round.
- **The feed fetch's SSRF guard and caps.** `git diff 348a2cf..HEAD --
  internal/blocklistfeed/blocklistfeed.go` filtered for the guard and cap
  identifiers is empty: `fetchFeedLines` still does `url.Parse` → explicit
  `http`/`https` scheme check → inline `ssrf.PrivateHost` before any dial,
  `http.NewRequestWithContext`, `ssrf.SafeDialContext`, a re-check on every
  redirect with `maxRedirects = 5`, and the 64 MiB body budget and 1,000,000
  line cap are byte-identical.
- **IM-009 and IM-011 are behaviour-preserving.** Both extractions were checked
  against 348a2cf by lifting the pre-window implementation into a standalone
  package and comparing marshalled output: byte-identical across six evidence
  postures and across eleven metric outcomes including hostile unknown outcome
  strings carrying a quote and a newline. No role check, redaction or cap was
  lost: `apiMCPRolloutEvidence` keeps its `requireRole(w, r, RoleViewer)` and
  GET-only dispatch (`ui_mcp_rollout.go:169-177`), and all nine handlers in that
  file retain their original roles with no Admin→Operator relaxation. The
  shadow-metrics label set remains entirely literal, so there is no
  untrusted-cardinality path; the never-armed nil gate survives on both read
  paths. The evidenceview move also *removed* an aliasing hazard, replacing a
  shared package-level slice with a per-call copy.
- **The `trafficStatus.ts` severity map.** Every status was checked against the
  backend site that stamps it. No status meaning "delivered unsanitized" or
  "not scanned" is presented as benign: the two fail-open-shaped statuses
  (`CDR_ERROR`, `DECRYPT_FAILED`) are both `warn` with prose that claims no
  delivery, and `37151e2` corrected `CDR_ERROR` mid-window from "it was
  delivered unmodified" to "passed on to inspection", which is what
  `cdr_proxy.go:477-483` actually does. `SCAN_BLOCKED` is correctly `critical`,
  including its scan-timeout arm, which is fail-closed. No raw-HTML sink was
  added — `dangerouslySetInnerHTML`/`innerHTML` has zero hits outside
  `frontend/src/test/` — so attacker-controlled hosts, URLs and filenames remain
  JSX text children.
- **The eslint / typescript-eslint bump (`5367030`).** All 33 changed lockfile
  entries are `dev: true`, and the root `dependencies` object is byte-identical
  to 348a2cf. No runtime dependency moved and no security default changed. The
  `frontend/dist` change in this window is attributable to the two frontend
  source commits and is consistent with them.
- **`env_put`'s lock decision (`eaa685b`).** The truth table of the new
  single-observation test is identical to the old compound test; the only
  behavioural delta is that a case previously raced into *skipping* a secret
  write now performs it, which is the safe direction for `CULVERT_HA_TOKEN`. The
  whole write path, including `chmod 600` inside the `flock` critical section,
  is byte-identical to 348a2cf.
- **Convention sweep over the whole window.** No `requireRole`, `auditEvent`,
  `saveConfigVersion`, `isPrivateHost` or `url.Parse` call was removed; no bare
  `http.NewRequest` was added; no `log.Printf`/`fmt.Printf` entered package
  main. Every added log call either carries only counts and durations or wraps
  its untrusted value in `sanitizeLog` with `%q`
  (`cdr_pool_reconcile.go:121-122`, `:141-142`, `observability_startup.go` ×4).

---

## Finding A — MEDIUM: an undelivered stale alert consumed the episode, so a later subscriber is never paged

`SEC-BLFEED-STALE-LATCH-1`. **Newly introduced** by the CHAOS-123 freshness
plane in this window (`cd565f4`).

**Defect.** `evaluateBlocklistFeedStaleness` latched first and fired afterwards:

```go
blocklistFeedHealth.mu.Lock()
alertNow := !blocklistFeedHealth.alerted
blocklistFeedHealth.alerted = true     // consumed unconditionally
blocklistFeedHealth.mu.Unlock()
if !alertNow { return }
fireBlocklistFeedStaleAlert(blocklistFeedAlertDetail(snap))
```

while the sink it calls drops the alert when nothing subscribes:

```go
var fireBlocklistFeedStaleAlert = func(detail string) {
	if !alertStore().HasSubscriber("blocklist_feed_stale") { return }   // dropped
	go fireAlert("blocklist_feed_stale", ...)
}
```

The latch is cleared only by an **observed** clean sync
(`noteBlocklistFeedRoundRecovered`), a feed removal (`noteBlocklistFeedsRemoved`)
or a process restart — never by elapsed time, deliberately. So an episode spent
on an alert that reached nobody is spent for the life of the process.

**Attack scenario / failure scenario.** This needs no attacker; the trigger is
the shipped default.

1. An appliance boots with an auto-synced remote blocklist feed whose origin is
   unreachable (DNS gone, mirror retired, egress ACL changed, credential in the
   feed URL rotated).
2. No alert webhook is configured — the default posture, and the reason the sink
   has a `HasSubscriber` gate at all.
3. The 15-minute never-synced grace elapses. The next failed round calls
   `evaluateBlocklistFeedStaleness`, which sets `alerted = true` and then drops
   the alert.
4. The operator later adds a `blocklist_feed_stale` webhook — the documented way
   to be paged for this condition.
5. The feed stays dead for weeks. **No page is ever sent.** The latch is set,
   and only a clean sync (which cannot happen) or a restart clears it.

**Preconditions.** An auto-synced remote feed that is stale or has never synced,
and no `blocklist_feed_stale` subscriber at the moment the first stale
evaluation runs. Both are default/ordinary states.

**Exploitability.** Not attacker-triggered in the usual sense, but
attacker-*favourable* and reachable by an adversary who can keep the feed origin
unreachable (BGP/DNS interference, or simply an abandoned origin): the gateway
keeps enforcing a frozen denylist while the operator's paging surface stays
silent. No authentication or privilege is required to benefit from it.

**Likelihood.** High for the "node boots broken before webhooks are configured"
ordering, which is the normal install sequence: the installer brings the
appliance up and the operator configures alerting afterwards.

**Impact.** Loss of the push-notification surface for a **deny control's**
freshness. Degraded, not dark: the `blocklist_feed` WARN row
(`checkBlocklistFeeds`) and the `culvert_blocklist_feed_stale` /
`_stale_seconds` gauges are derived on read and stay correct, so a pull-based
monitor still sees it. What is lost is precisely the surface the feature added
for operators who are not watching a dashboard. Destinations added to the feed
since its last good sync are not blocked, and nobody is told.

**Affected assets.** Remote blocklist feed freshness; the
`blocklist_feed_stale` alert contract; operator trust in the paging surface for
threat-intel staleness.

**Fix applied.** The episode is consumed only by a **dispatched** alert. The sink
now reports delivery, and the decision stays inside the lock so concurrent
failed rounds still page at most once per episode:

```go
blocklistFeedHealth.mu.Lock()
defer blocklistFeedHealth.mu.Unlock()
if blocklistFeedHealth.alerted { return }
if fireBlocklistFeedStaleAlert(detail) {
	blocklistFeedHealth.alerted = true
}
```

Nothing blocking runs under the lock: the sink only probes the lock-free
subscription index and hands off to a goroutine. The detail string is rendered
before the lock because `blocklistFeedState` takes the same mutex.

**Safe implementation notes.** Latching on delivery rather than on the attempt
cannot *suppress* an alert, only permit one that was previously swallowed, so the
fail direction is toward more pages. The alternative — probing `HasSubscriber`
outside the lock and then latching — would reopen a double-page window between
two failed feeds in one round.

**CWE.** CWE-778 (Insufficient Logging), CWE-390 (Detection of Error Condition
Without Action). **OWASP.** A09:2021 Security Logging and Monitoring Failures.

**Severity.** Medium. **Regression risk of the fix.** Low; the only behavioural
change is that an undelivered alert no longer burns the episode.

**Files.** `blocklist_feed_health.go`.

---

## Finding B — LOW: a withdrawn CDR pool member is closed before it is unpublished

`SEC-CDR-REDIAL-CLOSE-ORDER-1`. **Newly introduced** by the CDR pool re-dial in
this window (`7ec0839`).

**Defect.** `reconcileCDRPool` publishes the members it dialled, then
re-validates them and withdraws any whose authority disappeared in between. The
post-publish pass called `dropInvalidRedialed`, which closed each withdrawn
member's connection **while that member was still in the published pool**
(`cdr_pool_reconcile.go:298`, pre-fix); only afterwards did `cdrPool.replace(trimmed)`
unpublish it.

This matters because nothing filters a closed client out of selection.
`cdrClientPool.pick` selects on breaker state alone (`cdr_pool.go:176-195`), and
`CDRClient.closedAt` is **written by `Close` and read by nothing** — `grep
closedAt` returns exactly two hits, both writes (`cdr.go:135`, `:191`). So a
published-but-closed client is still selectable.

At 348a2cf the only publisher was `initCDRClient` → `cdrPool.replace`, which
swaps first and closes non-carried clients afterwards: a reachable client was
never closed. The inversion is therefore new.

**Attack scenario / failure scenario.** CDR is enabled with at least one
enrolled instance whose credential bundle was unreadable when the pool was
built (the condition the re-dial exists to recover from). The bundle becomes
readable, so a health-poller round dials the instance in. In the interval
between the publish and the post-publish re-validation, an admin issues
`DELETE /api/cdr/instances?name=X` or a revoke-prune removes that entry. The
re-validation withdraws the member and closes its connection while it is still
in the pool. A concurrent `PickReserved` hands that dead connection to a
sanitize RPC, which fails. Under `fail_mode: open` the document it was drawn for
**passes CDR unsanitized**; under `fail_mode: closed` it is refused.

**Preconditions.** A re-dial actually publishing a member, *and* a concurrent
admin delete/revoke of that same instance landing inside a window of
microseconds, *and* a document in flight that draws that client. All three.

**Exploitability.** Very low. The window is not attacker-controlled — it is
bounded by two map lookups — and reaching it requires admin credentials to
perform the concurrent delete.

**Likelihood.** Very low.

**Impact.** One document per occurrence bypasses CDR sanitization under an
explicitly configured fail-open posture (and that passthrough *is* counted and,
since this same window, surfaced on the operator contract). Under fail-closed,
one document is refused.

**Affected assets.** CDR sanitization of a single in-flight document; CDR pool
integrity.

**Fix applied.** `dropInvalidRedialed` gained an explicit `closeDropped`
parameter that states whether the pass owns the teardown of what it drops —
which is exactly "are these clients still unpublished?". The pre-publish pass
passes `true` (nothing else would close them); the post-publish pass passes
`false` and lets `cdrPool.replace` do the closing, which it already does for
exactly the clients not carried over, *after* the swap.

**Safe implementation notes.** No client is leaked: `replace` closes every old
client not present in the new set, and the withdrawn members are by construction
absent from `trimmed`. The pre-publish pass is unchanged.

**CWE.** CWE-672 (Operation on a Resource after Expiration or Release),
CWE-362 (Race Condition). **OWASP.** A04:2021 Insecure Design.

**Severity.** Low. **Regression risk of the fix.** Low; teardown still happens,
one step later and through the path that already owned it.

**Files.** `cdr_pool_reconcile.go`.

---

## Finding C — LOW–MEDIUM: `bootstrap-resolve`'s refusal echoes credential-bearing flag values

**Pre-existing**, not introduced by this window. Fixed here because it is the
precise sibling of this window's own `fa8c906`, which gave the main binary's
CHAOS-122 refusal position-based value redaction and was never propagated to
this FlagSet.

**Defect.** `runBootstrapResolve` refuses an argv with a positional tail and
printed the whole discarded tail verbatim:

```go
sanitizeLog(strings.Join(fs.Args(), " "))
```

`sanitizeLog` is the CWE-117 barrier — it neutralizes newlines — but it does
**not** redact values. That FlagSet owns `--catalog-url`, `--proxy-repo`,
`--data-dir` and `--out` (`bootstrap_resolve.go:104-114`), and a catalog origin
is an operator-supplied URL that can carry userinfo credentials — a class this
repository explicitly recognizes elsewhere ("the URL routinely embeds a token",
`blocklist_feed_health.go:195`).

**Attack scenario / failure scenario.** An operator (or an orchestrator
template) invokes
`culvert bootstrap-resolve STRAY --catalog-url https://user:TOKEN@mirror/catalog.json`.
The stray token makes Go's flag package discard every following flag, so the
subcommand refuses — and prints the tail, credential included, to stderr.
`scripts/install.sh` collects that stderr into the install log, where it
persists at whatever permissions the log has and is routinely attached to
support bundles and pasted into tickets.

**Preconditions.** A `bootstrap-resolve` invocation with a stray positional
token *and* a credential-bearing `--catalog-url`. The refusal itself is the
documented CHAOS-122 behaviour; the typo is the trigger.

**Exploitability.** Not remotely triggerable. The exposure is local-log and
downstream-disclosure: a mirror credential reaching a file and a support bundle
that are not treated as secret material.

**Likelihood.** Low–moderate — exactly the operator-typo path CHAOS-122 was
written to catch, so the refusal is reached in practice.

**Impact.** Disclosure of a release-catalog mirror credential.

**Affected assets.** Release-catalog mirror credentials; installer logs and
support bundles.

**Fix applied.** The refusal now echoes only `fs.Arg(0)` and the flag **names**,
routing the tail through the existing, tested
`redactArgValuesWith(fs.Args()[1:], boolFlagIn(fs))`. That helper identifies a
value by **position**, so a dash-leading secret is redacted too, and an unknown
flag name is treated as taking a value — ambiguity redacts rather than prints.
The `--data-dir` name still appears, which is what tells the operator the
anti-rollback floor was among the discarded flags.

**CWE.** CWE-532 (Insertion of Sensitive Information into Log File),
CWE-214 (Invocation of Process Using Visible Sensitive Information).
**OWASP.** A09:2021.

**Severity.** Low–Medium. **Regression risk of the fix.** Low; over-redaction is
the fail-safe direction, and the diagnostic keeps every flag name.

**Files.** `bootstrap_resolve.go`.

---

## Reported, not fixed

These are real but out of this window's authority to change unattended, or are
governance rather than defects. Each is stated with its direction of risk.

- **`cdrPruneRevokedInstance` can activate the CERTLESS bootstrap client.**
  `cdrPruneRevokedInstance` (`cdr_ui.go:1066-1081`) removes the registry entry and
  then, when a pool is still live, calls `initCDRClient` (`:1076`), so `buildCDRPoolFromRegistry` takes its empty-registry branch and
  `bootstrapPoolFromConfig` dials the config-level bootstrap client — which,
  with `cdr.certs_dir` unset, is the **no-client-auth** `NewCDRClient` path
  (`cdr_pool.go:511-512`, server-pin only). This is the genuine "last instance
  removed → implicit client activated" hole; `237d7a7` closed the *reconcile*
  path only (and the reconcile arm additionally requires `CertsDir != ""`, so it
  can never produce the certless client). **Entirely pre-window** — verified against
  `348a2cf:cdr_pool.go` and `348a2cf:cdr_ui.go`, where both are identical. Not fixed here
  because changing what a revoke-prune does to the active pool is a behavioural
  change to an admin path with its own audit and lifecycle contract, not a
  review-sized edit. Recommended: require `CertsDir != ""` for
  `bootstrapPoolFromConfig` as well, so the two arms agree, or refuse the
  implicit client outright once a registry has ever been populated.
- **The threat-feed plane has Finding A's defect, pre-existing.**
  `threatfeed_health.go:201-210` and `:277-291` latch `alerted = true` before
  calling a sink that drops the alert without a subscriber — the identical
  shape, and the pattern CHAOS-123 inherited. Deliberately **not** changed here:
  its alert goes through the deferred startup-alert queue with different
  semantics, and the 2026-11-17 review's lesson was that drift between two
  copies of one refusal *is* the vulnerability, so the two should be unified
  with that queue's ordering understood rather than patched one-sidedly.
  Recommended as its own change.
- **`internal/fileutil/rotating.go` still opens without `O_NOFOLLOW`/`O_NONBLOCK`.**
  Carried over from the 2026-11-18 review, and **unchanged by this window**:
  `internal/fileutil/` has zero changes in `348a2cf..HEAD`, and the deferred
  request-log open shares the one constructor rather than adding a weaker second
  open (flags and mode verified identical: `O_CREATE|O_WRONLY|O_APPEND, 0o600`).
  Worth noting that the repository already has the hardened idiom it needs —
  `oNoFollow` (`nofollow_unix.go`) is used by `list_backups.go` and
  `internal/fileutil/replacement_linux.go:81` — so the fix is a local change to
  `NewRotatingFile`, repairing the startup and deferred paths together.
  CWE-59/CWE-61.
- **No count cap on `AlertWebhooks` in config import.** Also carried over and
  unchanged: no `maxImportWebhooks` bound exists. `RoleAdmin` only; the cost is
  O(N²) fsync'd I/O. CWE-770.
- **`install.sh`'s `touch` + `chmod` creation race on the secret env file.**
  `scripts/install.sh:1673` creates with `0666 & ~umask` and `chmod 600`s
  immediately after, and the script sets no `umask`. Under a lax operator umask
  a local user can open the file read-only in that window and keep the fd,
  reading secrets appended later. **Pre-existing and byte-identical at
  348a2cf**; this window's only delta in that function is the lock decision,
  which does not widen it. CWE-367. Recommended: `umask 077` in `env_put`'s
  subshell, or create via `set -C`.
- **`cmd/culvert-maint/main.go:267-280` still uses the pre-`fa8c906` redaction.**
  A second, dash-keyed copy of the algorithm. Impact is low today because that
  binary defines only `--config` and `--version`, so no credential can occupy a
  value slot — but it is exactly the drift that produced Finding C. Recommended:
  port the position-based helper so there is one implementation.
- **A truncated blocklist feed body is recorded as a clean, fresh sync.** At the
  1,000,000-line cap `fetchFeedLines` returns `lines, nil`, so `lastSync`
  advances and `lastError` clears for a deny list that was silently cut short
  (the 64 MiB byte budget correctly *fails* the round; the line cap deliberately
  truncates). **Pre-existing and identical at 348a2cf.** What changed is only
  that the new plane now *asserts* freshness over that state. Recommended: carry
  a `Truncated` bit on the sync outcome and give it its own row rather than
  folding it into "fresh".
- **`CDR_SANITIZED` is unmapped in `trafficStatus.ts`,** so it renders neutral
  with no stated meaning and is absent from the status filter, even though
  `internal/reqlog/reqlog.go:107` classifies it WARN and it means the document
  was structurally rewritten. A gap against the commit's stated "CDR statuses"
  scope rather than a misrepresentation — neutral asserts nothing. One table row
  plus a filter entry.
- **`CDR_ERROR` tone disagrees between surfaces.** `warn` in the React console,
  `ERROR` in `LevelForStatus` (`internal/reqlog/reqlog.go:111`), so the badge
  colour and the legacy "Auth & Errors" grouping differ. Cosmetic.
- **The scan-cache victim scan is bounded at 8 slots.** `liveVictimLocked`
  inspects at most `evictVictimScan` slots and falls back to the root when none
  carries the full lifetime, so if short-lived entries occupy every one of the
  first eight heap slots the cooldown is again the victim. This is a bounded
  residual of the fix, not a regression — it is strictly better than 348a2cf,
  where the cooldown was *always* the victim — and the O(1) bound under the
  exclusive lock is the deliberate trade. Worth a comment stating the degradation
  mode.
- **`tunnelClassInspectFallback` remains dead in production.** Carried over
  unchanged.

---

## Verification

Toolchain `go1.27.4`, taken from `go.mod` `toolchain` (not `PATH`).

| Check | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `go test .` (root module, baseline at `491b963` before fixes) | **ok**, 457.7 s |
| `go test .` (root module, with fixes) | **ok**, 436.6 s |
| `go test ./internal/...` | **ok**, 118 packages |
| `go test ./...` in `cmd/culvert-maint` | **ok**, 10 packages |
| `go run ./cmd/contractcheck impact -base origin/main` | no contract code paths touched |
| `python3 docs/agent-context/check.py` | passes (static integrity) |
| Finding A gate reverted against merged main | **FAIL** — `delivered = 0 after the webhook was added, want 1` |
| Finding B gate reverted against merged main | **FAIL** — `a withdrawn member's connection was closed while it was STILL in the published pool` |
| Finding C gate reverted against merged main | **FAIL** — the `s3cr3t-catalog-token` appears verbatim in stderr |

New gates, all three proven to fail against the code as merged and pass against
the fix:

- `TestChaos123_UndeliveredStaleAlertDoesNotConsumeTheEpisode` — negative
  (no subscriber ⇒ nothing delivered, episode preserved), positive (subscriber
  added later ⇒ one page), and boundary (a delivered episode still pages only
  once).
- `TestCDRRedial_WithdrawnMemberIsUnpublishedBeforeItIsClosed` — asserts the
  ordering at the only point that can distinguish it, with two preconditions
  that fail loudly if the test stops reaching the post-publish withdrawal
  branch, plus the end-state teardown checks.
- `TestChaos122_BootstrapResolveRefusalRedactsFlagValues` — negative (the
  secret must not appear) and positive (every flag name, and `<value>`, must).

Pre-existing gates re-run and still green: `TestCDRRedial*` (including
`…_DeletingLastSkippedInstanceNeverActivatesBootstrap`), `TestChaos123*`,
`TestChaos122*`, `TestPolicyDestLiteral*`, `TestPolicyFlow_Blocked*`, the
`internal/hashcache` victim suite, `internal/alerts` under `-race`, and
`internal/blocklistfeed`.

**Not run, and why.** `golangci-lint` — the container's binary predates this
module's language version and refuses it, which `docs/agent-context/conventions.md`
records as the expected state; the gate's own pinned version runs in CI.
CodeQL and the hosted Fast PR Gate run on the pull request. The frontend vitest
suite needs `frontend/node_modules`, which is absent and would require a network
install; the status table was instead verified against the backend sites that
stamp each status. A passing local check is not a passing hosted review or merge
gate.

---

## Residual risk

- **Finding A's sibling in the threat-feed plane is still open** and is the same
  shape, so a node that boots with stale threat intelligence and no webhook can
  still burn that episode. It is listed above as its own change deliberately.
- **Finding B's class is only partly closed by a parameter.** The real
  underlying weakness is that `CDRClient.closedAt` is written and never read, so
  nothing *structurally* prevents a closed client from being selected — the pool
  relies on ordering discipline instead. A `pick` that skipped closed clients
  would make the invariant enforced rather than observed. Worth considering.
- **The certless bootstrap client reachable through `cdrPruneRevokedInstance`**
  is the most consequential item in this report that was not fixed, and it is
  pre-existing rather than in-window. It should not wait long.
- **Stale-detection latency grows with feed count.** The staleness bound uses a
  static worst-case per-fetch budget, so with many feeds the bound is hours even
  though real syncs take milliseconds. This is conservative by design
  (anti-false-positive) and cannot be inflated for hour-scale intervals, but it
  means detection is looser than the configured cadence suggests.
- **The freshness plane re-derives its snapshot once per feed per round**, each
  call taking a full sorted `Feeds()` copy — O(N²) transient allocation per
  round, bounded by the admin-configured feed count. Garbage, not growth, and
  not a security property, but new churn that 348a2cf did not have.
- **Nothing in this review validates the hosted gates.** CodeQL's dataflow view
  of the new `sanitizeLog` call sites and the Fast PR Gate's
  `--new-from-rev`/full-tree lint comparison are the authorities for their own
  checks.
