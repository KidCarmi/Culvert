# Security Regression Review — 2026-11-18

**Scope.** `84b1b4c…348a2cf` — the window since the 2026-11-17 review: 10 merged
pull requests (#1931–#1940), 64 files, +5,623/−344. Reviewed at
`348a2cfb1f15f2879e5617ba692fd7b186699b62`, which is also `origin/main`.

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `84b1b4c`?** Every verdict is measured against that
revision. Where a finding is pre-existing rather than newly introduced, it says
so.

**Headline.** This window is overwhelmingly *hardening*, and it closed all three
findings the 2026-11-17 review raised. One change, however, replaced a cache
eviction policy in a way its own commit message records as neutral and is not:
it makes the fail-closed scan-timeout cooldown the standing eviction victim, so
the anti-stampede guard is **inert at capacity** (Finding A). A second change
removed the only detector for an invariant it was careful to preserve
(Finding B). Both are fixed here, each proven by reverting the fix and watching
the new gate fail.

| Change | Security surface |
|---|---|
| `SEC-INSPECT-PLAINTEXT-1`, native leg | The native-ALPN inspect path now refuses a non-TLS client instead of raw-relaying. **Closes 2026-11-17 Finding A (HIGH)** |
| `countWriteErrorsN` | The audit recovery charges an evicted backlog once instead of per entry. **Closes 2026-11-17 Finding B** |
| `CULVERT_HA_TOKEN` | The HA join token leaves argv for the environment. **Closes 2026-11-17 Finding C** |
| CHAOS-122 argv guard | The binary, `bootstrap-resolve` and `culvert-maint` refuse an argv `flag.Parse` could not consume. **Hardening — removes a silent unpoliced boot** |
| OIDC `requiredScope`/`requiredAudience` | Enforced on the credential path; the local-JWT shortcut no longer answers first. **Hardening — and the source of Finding E** |
| `hashcache` heap eviction | Eviction is O(log n) instead of a full-map sweep under the lock. **Hardening for DoS — and the source of Findings A and D** |
| `internal/alerts` subscription index | Subscriber lookups answer from an immutable published view. **Hardening — and the source of Finding B** |
| `ui_config.go` webhook import gate | Config import validates webhook URLs/event names, closing the second write ingress. **Admin ingress validation** |
| `internal/reqlog` deferred open | A configured-but-unwritable request log opens without a restart. **Logging durability — and the source of Finding C** |
| `compose_file` validation | The privileged maintenance agent rejects `.`/`..` and shell-unsafe names at Load. **Hardening — and the source of Finding F** |
| `diagnostics_inspection_ca_renewal.go` | A warning row when a non-auto-renewed inspection CA is within 30 days of expiry. **Read-only; fail direction stated correctly** |

**Method.** Four independent investigations ran in parallel over the alert
plane, the audit/request-log durability paths, the hash-cache rewrite, and the
diagnostics/packaging surfaces; the OIDC, argv/HA-token and TLS-inspection legs
were reviewed directly. Every finding below was then re-derived from source by
the reviewer — no finding rests on a worker summary — and the two behavioural
fixes are proven differentially.

---

## No regression found in

- **`SEC-INSPECT-PLAINTEXT-1`, native-ALPN leg.** `relayPlaintextInspectFallback`
  is gone and both inspect legs now share one refusal,
  `refuseNonTLSInspectClient` (`proxy_tunnel.go:1668`), reached from the strip
  path (`proxy_tunnel.go:956`) and the native path (`proxy_tunnel_h2.go:189`).
  I enumerated the inspect entry points: `handleTunnelInspect` and
  `handleInspectNativeALPN` are the only two, so the unification is complete —
  there is no third leg. `maybeFailOpenClient` is correctly not consulted, so a
  refusal cannot teach an auto-exclusion for the next connection. Covered by
  `TestInspectNative_PlaintextClientCannotReachOriginUninspected`,
  `…_RefusalCoversEveryNonTLSFirstByte` (7 first-byte classes) and
  `…_ConcurrentPlaintextClientsAreAllRefused`.
- **The HA join token's new channel.** `resolveHATokenInput`
  (`cluster_startup_config.go:122`) prefers the flag and trims only the env
  value; `HAToken` is consumed solely by the join path, which requires
  `HAJoinAddr` too (`cluster_startup_config.go:70`), so a leader or standalone
  node that inherits `CULVERT_HA_TOKEN` from a shared `.env` is unaffected.
  `haDeployCommand` hands the token over as a variable assignment prefix
  (`ha.go:1795`), which the shell passes in the child's environment and not its
  argv. The token is 32 bytes of `crypto/rand` hex (`ha.go:1465`), so it cannot
  carry a shell metacharacter into a pasted command, and — relevant to the argv
  guard's redaction — it cannot begin with `-`. No diagnostics or support path
  dumps `os.Environ()`; the maintenance runner explicitly does not inherit it.
  `deploy_cmd` remains suppressed per role for non-admins
  (`ha.go:1648`, `TestSECHATOKEN1_NonAdminRolesNeverSeeTheJoinToken`).
- **The CHAOS-122 argv guard.** The refusal runs before `handleOneShotCommands`
  and therefore before anything writes to the persisted-state root
  (`main.go:222`), echoes only the first token and the discarded flag *names*
  (`redactArgValues`, `argv_guard.go:125`), and defers to
  `prepareDowngradeConfirmWord` for the one shape that owns a positional
  operand. `bootstrap-resolve`'s own `FlagSet` gets the same guard, which closes
  a real anti-rollback hole: a stray token dropped `--data-dir` and with it the
  rollback floor. Exit 2 matches the flag package's usage-error code.
- **The OIDC credential-path filters.** `identityFromIntrospectionClaims`
  evaluates both filters (`auth_oidc_flow.go:1410`, `:1415`), and with either
  set the local-JWT shortcut is skipped (`:1019`), so a profile with a filter
  and no introspection endpoint admits nothing — fail-closed. Pinned by
  `TestOIDCFlowCredential_RequiredFiltersApplyToLocallyValidJWT`,
  `…_RequiredFilterWithoutIntrospectionDenies` and `…_RequiredFilterControls`.
- **The hash-cache rewrite's mechanics.** No wrong-key hit, no stale
  resurrection, no dangling map entry from an index swap, no expired entry
  served (`Get` still re-checks expiry on every read), every heap mutation
  under the write lock, and the entry cap exact. There is no pin/hold API, so a
  client cannot defeat the bound. `go test -race -count=2` clean. The
  *mechanics* are sound; the *policy* is Finding A.
- **The alert subscription index.** `buildSubscriptions` is pure and publishes
  an immutable value through `atomic.Pointer`; every write to `as.hooks`
  republishes before releasing `mu`, including `Init`'s failure and
  `continue` branches. Equivalence with the old locked scan is pinned by a
  differential oracle over every event name.
- **Webhook SSRF.** `alerts.ValidateURL` is deliberately shape-only
  (`internal/alerts/store.go:159`); the actual barrier is `ssrf.SafeDialContext`
  on the delivery transport (`:997`), applied at every dial and therefore after
  DNS resolution — so there is no import-time/send-time TOCTOU to exploit and no
  DNS-rebinding window. The new import gate is defence in depth, placed before
  any store mutation, and the import stays all-or-nothing. Both write ingresses
  (`ui_security.go`, `ui_config.go`) now run the same two checks; `alert_webhooks`
  is a recorded rollback exclusion and is not cluster-synced, so there is no
  third ingress.
- **Webhook secret handling.** `List()` blanks `Secret`/`sealedSecret` on every
  returned copy, both export sites use it, `save()` fails closed rather than
  writing cleartext, and the wrapping key is excluded from support and backup
  archives.
- **RBAC.** No role requirement was lowered anywhere in the window; a
  whole-diff sweep for `requireRole`/`MinRole`/`Public` changes finds only prose.
  The new inspection-CA diagnostic adds no handler — it is a check function
  behind the two `RoleViewer`-gated renderers — and discloses only a day count
  and a closed-enum provenance label, a strict subset of what `/api/ca/status`
  already serves to a Viewer. No key material, no path, no fingerprint, and the
  row logs nothing.
- **Certificate validation.** The CA-renewal diagnostic is strictly read-only:
  locked reads of `Ready`/`CAExpiry`/`Provenance`, no renewal trigger, no trust
  store mutation. It is additive to `checkRootCA`, which still fails the
  contract when the CA is unusable, and its message states the fail direction
  correctly — on expiry inspected HTTPS is *refused, not bypassed*.
- **Unsafe defaults.** The `Dockerfile` and `config.example.yaml` changes in
  this window are **comment-only** (verified by filtering non-comment added
  lines from the diff): no new `ENV`/`ARG`, no capability or `USER` change, no
  secret baked into a layer, no permissive default. `docker-compose.ha.yml`
  contains no committed token, only `${HA_TOKEN:-}`.
- **XSS.** The one `static/index.html` change is static literal text; the only
  JS touching that element sets `style.display`. CSP is unchanged and still
  carries no `unsafe-inline` for script.
- **Weak crypto.** The only `math/rand` added in the window is in a hash-cache
  test; no production path gained it.
- **Audit completeness on the batched charge.** `audit.WriteErrors()` stays
  exact — `countWriteErrorsN` adds `n` and calls the observer once — and the
  loss count is separately exported, so nothing is hidden. The alert itself was
  already interval-gated, so no page is lost.

---

## Finding A — MEDIUM: heap eviction makes the fail-closed scan-timeout cooldown the standing victim

**Status: newly introduced in this window. Fixed here.**

**Affected contract.** `internal/hashcache` eviction policy; `internal/secscan`'s
anti-stampede guard.

**Evidence.** `evictLocked` (`internal/hashcache/hashcache.go`, pre-fix) chose
the live victim as `c.byExpiry[0]` — the globally minimum *absolute* expiry. The
commit's own comment records the consequence as intended: "A short-lived
scan-timeout cooldown therefore goes before an hour-long content verdict", and
justifies it with "Dropping a verdict early is never a security change: a miss
re-scans".

That justification holds for a content verdict and inverts for this entry.
`cacheTimeoutCooldown` (`internal/secscan/secscan.go:1592`) writes a **30 s**
fail-closed entry via `SetTTLUnless`, into the same cache whose content TTL
defaults to **1 h** (`config.example.yaml`). Its documented job
(`secscan.go:1601`) is "absorbing a burst of requests for the same object" while
the scanner is unhealthy. So the cooldown is *always* the heap root while any
content verdict exists, and "a miss just re-scans" is precisely the stampede the
entry exists to prevent.

**Attack scenario.** (1) An attacker drives the cache to capacity with distinct
content — 10,000 objects at defaults, or simply waits, since any proxy whose
distinct-object churn exceeds `cache_size`/`cache_ttl` sits at capacity in
steady state. (2) The scanner becomes slow or saturated, so a hot object starts
timing out and a cooldown is written. (3) Every subsequent new-key insert — any
other client fetching any other object — evicts the cooldown. Each request for
the hot object then misses and relaunches a doomed scan, and each rewritten
cooldown is itself a new-key insert that evicts another live verdict, forcing
further rescans: positive feedback.

**Preconditions.** Cache at capacity with nothing expired; a scanner that is
slow or saturated. Both are ordinary operating conditions, and the first is
attacker-forceable in one pass.

**Exploitability.** Moderate — no authentication required, but the flood is
noisy and each filler costs the attacker a full scan.
**Likelihood.** High that the guard is inert at capacity (it is a property, not
a race); moderate that an attacker deliberately drives it.
**Impact.** The documented anti-stampede protection is absent in exactly the
regime it exists for: scan CPU amplification and queue pressure. Per-request
posture on timeout stays fail-closed, so this is primarily availability. The
bypass tail is indirect but real: a genuine ClamAV *engine error* is fail-open
(`secscan.go:1843`), so driving the daemon from "slow" to "erroring" admits
content a surviving cooldown would have kept refused.
**Affected assets.** Malware/CDR scanning throughput; inspected content.
**CWE.** CWE-693 (protection mechanism failure), CWE-770 (amplification).
**OWASP.** A04:2021 Insecure Design.
**Regression risk.** The previous policy — a 25 % arbitrary drop — gave the
cooldown ~75 % survival per eviction event, so in practice it survived its whole
30 s. Measured on this window's code: **the cooldown is evicted after exactly 1
new-key insert** (reproduced by the reviewer; see Verification).

**Why it got through.** Every `secscan` cooldown test runs a 10–64-entry cache
holding a handful of entries, so eviction never fires; the new hash-cache tests
assert the *policy* rather than the guard's survival under churn.

**Fix applied (safe implementation).** Record the TTL an entry was stored with
(`hashCacheEntry.lifetime`) and split victim selection out as
`liveVictimLocked`: the victim is the earliest-expiring entry **that carries the
full configured lifetime**, and a shorter-lived entry is chosen only when the
scanned slots offer no alternative. The scan is bounded to
`evictVictimScan = 8` heap slots (the top three levels, i.e. the entries already
nearest minimum expiry), so the eviction path stays O(1) extra work plus
O(log n) removal and the DoS fix this rewrite exists for is fully preserved. The
expired-reap batch is untouched, nothing is ever served past its own expiry, and
with a uniform TTL the behaviour is byte-for-byte the old
closest-to-expiry rule. A cache dominated by cooldowns still evicts cooldowns,
so the bound cannot be defeated.

**Required tests (added).** `internal/hashcache/hashcache_victim_test.go`:
- regression — a cooldown survives `4 × capacity` new-key inserts;
- positive control — the earliest-expiring full-lifetime verdict is still the victim;
- bound control — an all-short-lived cache still evicts and never exceeds `maxSize`;
- negative control — uniform-TTL behaviour is unchanged.

**Residual risk.** Victim choice is still deterministic (Finding D).

---

## Finding B — MEDIUM: the subscription index removed the only detector for the `mu`/`saveMu` split

**Status: newly introduced in this window. Fixed here.**

**Affected contract.** `internal/alerts` "persistence must never run under `mu`"
(`internal/alerts/store.go:311`).

**Evidence.** `HasSubscriber` now answers from the atomically published index
and takes **no lock at all** (`internal/alerts/store.go:655`). The invariant's
only two regression tests —
`TestSave_DoesNotHoldMuDuringIO` and
`TestSave_ReadersProceedDuringConcurrentMutations` — used `HasSubscriber` as
their sole reader probe, so neither could observe `mu` being held any more. The
diff's own rewritten comment says the quiet part out loud — "This split used to
be stated in terms of `HasSubscriber`, which is no longer one of those readers"
— but the tests were not re-pointed.

**Attack scenario.** Not directly attacker-triggered; this is a latent
availability regression with its detector removed. A future change that moves
`persist()` back inside `mu`, or adds any fsync or key-file read under it,
passes CI. On a degraded or full data volume, `Dispatch` — which takes
`mu.RLock` on the *alert fire path* (`store.go:786`) — plus `List`, `GetByID`
and `SigningDegradedCount` then block for the duration of each write, stalling
the alert-delivery plane exactly when alert volume is highest.

**Preconditions.** A future regression plus a degraded volume.
**Exploitability.** Low (indirect). **Likelihood.** Moderate over time — this is
precisely the regression class the tests were written to stop.
**Impact.** Loss of a security-alert delivery guarantee under disk pressure.
**Affected assets.** Alert/notification egress; proxy request paths that
dispatch alerts.
**CWE.** No direct CWE (coverage regression); the guarded invariant is CWE-667 /
CWE-400. **OWASP.** A09:2021 Security Logging and Monitoring Failures.
**Regression risk.** Confirmed: with persistence moved under `mu`, the whole
`internal/alerts` package passed before this fix.

**Fix applied.** Re-point both probes at `List()`, which still takes `mu.RLock`,
and keep a separate `HasSubscriber` assertion as the explicit "answers
lock-free" check. Test-only change.

**Verification.** With `persist()` moved inside `mu` in `Add`,
`TestSave_DoesNotHoldMuDuringIO` now fails on the 5 s timeout
("List blocked while a save was in flight"). It passed with that same defect
before the fix.

---

## Finding C — MEDIUM: a URL-less webhook update blanks the destination while keeping the subscription

**Status: pre-existing; surfaced by this window's webhook-validation work, which
builds on the contract this breaks. Fixed here.**

**Affected contract.** `webhookPayloadRejected`'s shared definition of an
acceptable payload (`ui_security.go:36`).

**Evidence.** The gate admits `PUT /api/alerts/webhooks?id=X` with no `url`,
justified in its own comment by "an empty URL on an update preserves the stored
one (see `Store.Update`)". **`Store.Update` did not preserve it.** It carried
forward only `Secret`/`sealedSecret` and then assigned
`as.hooks[i] = upd` (`internal/alerts/store.go:728` post-fix), taking `URL` wholesale
from the payload.

**Attack scenario.** An operator-role actor, or any automation doing a partial
PUT (`{"name":…,"events":[…],"enabled":true}` — the natural shape for a client
that only wants to rename a hook or toggle it), blanks the stored destination.
The subscription survives, so the index still reports a subscriber, every
matching alert is still dispatched, and each delivery dies at the
`validWebhookURL` barrier. The SIEM stops receiving `threat_detected` /
`policy_block` with nothing failing loudly, and the audit record for
`alert.webhook.update` carries no detail (unlike create, which records the URL).

**Preconditions.** `RoleOperator` credentials or operator automation. The GUI is
unaffected because its edit modal pre-fills the URL, which is why this survived.
**Exploitability.** Low–moderate (requires operator role).
**Likelihood.** Moderate — a partial PUT is an ordinary API-client shape, so
this is at least as likely to happen by accident as by intent.
**Impact.** Silent loss of security-alert delivery — the failure class this
package itself calls the one kind of loss an operator cannot notice.
**Affected assets.** Alert egress to SIEM/on-call.
**CWE.** CWE-20, with a CWE-392 (missing report of error condition) impact.
**OWASP.** A09:2021 Security Logging and Monitoring Failures.
**Regression risk.** None from the fix: an empty URL is never a valid stored
state (`ValidateURL` rejects it; create requires it), so carrying it forward
cannot mask a legitimate intent to clear.

**Fix applied.** `Store.Update` carries the stored URL forward when the payload
omits it, mirroring the `Secret` branch — which makes the gate's existing
promise true rather than changing the API contract.

**Required tests (added).** `internal/alerts/store_update_url_test.go`:
preservation on a URL-less partial update (with the event list still reaching
the index), plus a positive control that a supplied URL still replaces the
stored one.

**Verification.** The preservation test fails on merged main
(`URL = "" after a URL-less update`); the positive control passes both ways.

---

## Finding D — LOW–MEDIUM: eviction is now deterministic, so cache flooding is fully efficient

**Status: newly introduced in this window. Recorded as a reviewed trade-off, not
fixed.**

With a uniform TTL, "minimum expiry" equals "oldest insert", so a flood of new
keys evicts exactly the oldest honest verdicts and never the attacker's own
(newest, therefore maximum expiry). Measured on a 1,000-entry cache pre-filled
with confirmed block verdicts, honest survivors after N flood inserts:

| flood inserts | this window | `84b1b4c` |
|---|---|---|
| 250 | 750 | 750 |
| 500 | 500 | 559 |
| **1000** | **0** | **272** |
| 2000 | 0 | 26 |
| 4000 | 0 | 8 |

A total flush now costs exactly `cache_size` distinct-content fetches instead of
~4× that, and is deterministic rather than probabilistic.

**Impact.** Forced-rescan CPU and loss of verdict memory. A miss re-scans, so
this is not itself a bypass — but it composes with the fail-open classes
(`clamDark`, and the remote scanner's fault/oversize classes in
`internal/secscan/remote.go:313`) into the sequence Finding A describes.
**Exploitability.** Low — each filler costs the attacker a full scan, so the
attack is noisy and self-throttling. **CWE.** CWE-770. **OWASP.** A04:2021.

**Recommendation (not applied).** FIFO is a defensible policy and the
performance win behind it is real, so this is left as a decision rather than
reverted — but the retention contract changed even though the TTLs did not, and
the commit message states the opposite ("Verdicts, TTLs … are unchanged").
It is recorded in `roadmap/SCAN-CACHE-EVICTION-COST.md`
(SEC-SCANCACHE-VICTIM-1) as a reviewed trade-off. If randomisation is wanted back, choose the live victim
from a small random sample of near-root candidates (power-of-k-choices) rather
than the root.

**Also recommended:** `Stats()` exposes only hits/misses/size, so an operator
cannot see eviction thrash at all. An eviction counter — as
`auth_identity_cache.go` already carries — is what would make both this and
Finding A observable in production rather than only in a test.

---

## Finding E — MEDIUM (advisory): `requiredScope` is not enforced on the browser SSO flow

**Status: pre-existing. Documented here, deliberately not changed.**

**Evidence.** This window correctly closed the credential path, and the
`CHANGELOG` scopes the fix explicitly: "the browser SSO flow … unchanged". That
asymmetry is now the whole of the gap. `CaptiveLoginURL` requests
`p.cfg.Scopes` and never adds `RequiredScope` to the authorization request
(`auth_oidc_flow.go:1111`); `ExchangeCode` validates the ID token and returns
(`:1202`); `authOIDCCallback` mints a session immediately
(`ui_auth.go:1095`, `:1101`). Neither filter is consulted on that path.

**Attack scenario.** An operator sets `requiredScope: "proxy:access"` as an
entitlement gate. A user in the same IdP tenant who does not hold that scope is
refused on `Proxy-Authorization` but authenticates successfully through the
captive portal and receives a proxy session.

**Preconditions.** An OIDC flow profile with `requiredScope` set and the
browser/captive-portal path enabled.
**Exploitability.** Moderate — any IdP-authenticated user.
**Impact.** Bypass of the operator's entitlement gate for proxy egress.
**Bounded:** the callback sets the **proxy-user** cookie `ps_session`
(`session.go:192`, `internal/session/session.go:44`), not the admin UI cookie
`ps_ui_session`, and admin roles are derived separately — so this is **not**
admin privilege escalation.
**Affected assets.** Proxy egress entitlement.
**CWE.** CWE-863 (incorrect authorization). **OWASP.** A01:2021 Broken Access
Control.

**Why not fixed here.** Enforcing it requires two coupled changes — adding the
required scope to the authorization request *and* checking the token endpoint's
`scope` response — and the token response's `scope` field is optional in
RFC 6749 §5.1. Getting either half wrong locks every SSO user out of the
gateway. That is not a change to make unattended, and `requiredScope` is
arguably an access-token concept by design (an ID token carries no scope claim,
and `requiredAudience` is already satisfied structurally because
`validateIDToken` pins `aud` to `ClientID`).

**Applied instead:** the misleading guarantee is corrected where an operator
reads it — `auth_oidc.go` (`RequiredScope`/`RequiredAudience` doc comments) and
`config.example.yaml` — stating that both filters are credential-path only and
that the captive-portal path must be restricted with group/claim mapping.

**Recommended fix (for an attended change).** Add `RequiredScope` to
`CaptiveLoginURL`'s scope set; enforce it in `ExchangeCode` against the token
response's `scope`, treating an absent `scope` field as a configuration error
surfaced on the Diagnostics contract rather than as a silent pass. **Required
tests:** a user with the scope admitted; a user without it refused; an IdP that
omits `scope` producing a loud, non-admitting failure; and the existing
credential-path tests unchanged.

---

## Finding F — LOW: hardening applied in this window

Three smaller items, all fixed here.

1. **`internal/reqlog/deferred.go` — `writerMu` was released without `defer`
   across `startPersist()`.** The retry loop asserts the opposite invariant
   ("the owner releases its locks by defer/explicit unlock, so a recovered round
   simply counts as a failed attempt", `request_log_persist_retry.go:58`). A
   panic in that window left `writerMu` write-locked for the process's life
   while `runGuarded` recovered the round — no crash, no alert. Because the
   persistence queue is deliberately blocking rather than load-shedding, once it
   filled every proxied request would wedge in `reqlog.Add`: a silent
   proxy-wide hang. Not reachable today (the one concrete panic source,
   `persistWG` misuse, cannot occur because `persistCh == nil` on this path), so
   this is a latent hazard plus an untrue comment. **Fixed** by extracting
   `publishDeferredSink`, which releases the lock by `defer`. Publish order is
   unchanged; only the unlock is now unconditional. CWE-667 / CWE-833.
2. **`observability_startup.go` — CWE-117 gap on the startup fallback lines.**
   Both `Audit:` and `RequestLog:` fallbacks printed `%v` on an error that, per
   `internal/audit`'s own note on this exact value, "embeds the
   operator-configured path and, for a wrapped syscall error, arbitrary
   OS-supplied bytes" — while the new retry code 15 lines downstream sanitises
   correctly. **Fixed**: `sanitizeLog` + `%q` on all four values in the block.
3. **`cmd/culvert-maint/internal/runner/runner.go` — `ComposeFile` accepted
   `.`/`..`.** `filepath.Base("..") == ".."`, so the runner's validator passed
   them; this window added that rejection at the config layer, leaving the three
   copies of the acceptance set (installer, config, runner) with the runner's as
   the weakest. Not exploitable — `config.validate` is the only production
   feeder and `filepath.Join` under an absolute cleaned dir yields a directory
   path, so the worst case is a failed compose call, not traversal. **Fixed** at
   the runner layer too, for defence in depth.

---

## Reported, not fixed

- **`internal/fileutil/rotating.go` opens without `O_NOFOLLOW`/`O_NONBLOCK`.**
  A local account with write access to the configured log directory can plant a
  symlink (redirecting request-log JSONL — user identities and visited URLs —
  outside its directory as the proxy's uid) or a FIFO (blocking `open(2)`
  forever, wedging the retry goroutine while the diagnostics row still says
  "retrying automatically"). File mode is correctly 0600 and the path is never
  request-derived. **Inherited, not introduced** — startup `Init` has the
  identical exposure. What this window changed is the *window*: from one instant
  at boot to every 10 s–2.5 min for the process's life. Not fixed here because
  `NewRotatingFile` is shared by the audit log and other rotating sinks, so
  changing its open flags is a broader change than this review should make
  unattended. CWE-59/CWE-61, CWE-410. Recommended fix: `O_NOFOLLOW|O_NONBLOCK`
  (or an `fstat` regular-file check) in `NewRotatingFile`, which repairs the
  startup and deferred paths together.
- **No count cap on `AlertWebhooks` in config import.** The new gate bounds each
  event name but not the list length, and each `Add` does a full O(N) snapshot
  plus an fsync'd whole-file write, so one request is O(N²) fsync'd I/O
  (measured: 881 ms at N=500, 21.5 s at N=4000; the 1 MiB body cap still allows
  tens of thousands of minimal objects). `RoleAdmin` only, and **not** caused by
  the subscription index — the new under-`mu` derivation is 0.6 % of that cost;
  the rest is the pre-existing per-`Add` fsync. CWE-770. Recommended: a
  `maxImportWebhooks` bound in the new pre-validation loop, matching the
  `SnapshotCap` posture elsewhere.
- **`culvert_storage_write_failures_total` semantics for the batched audit
  charge.** The observer is now called once for an N-entry backlog. This is
  correct and correctly prioritised — `audit.WriteErrors()` stays exact and is
  exported separately — but the new comment's premise ("The observer is not a
  counter") is inaccurate: `storageWrites.total` is one. Comment-only.
- **Request-log loss is visible but not quantified.** The deferred open
  deliberately does not backfill, and those entries are not charged to
  `reqlog.WriteErrors()`, so unlike the audit path (which reports
  `Backfilled`/`Dropped`) the operator gets no number. Not silent — the
  diagnostics row is `diagFail` with a remedy, the open logs the gap and a
  `system` audit entry records it — but a count would close it.
- **Inspection-CA renewal threshold is triplicated.** `inspectionCARenewalWarnDays
  = 30`, `caRotationOverlap = 30 * 24 * time.Hour` and
  `info["rotationOverlapDays"] = 30` are three independent copies with nothing
  pinning them together. Drift only shifts when the warning appears, so it
  cannot create an unsafe state. Governance.
- **`tunnelClassInspectFallback` is now dead in production.** Both non-TLS
  fallbacks were removed, so the drain class has test-only users. Not a defect;
  worth removing or documenting so it is not mistaken for a live path.

---

## Verification

Toolchain `go1.27.4`, taken from `go.mod` `toolchain` (not `PATH`).

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | clean |
| `go test ./...` (root module, full) | pass, no failures |
| `go test -race ./internal/hashcache ./internal/alerts ./internal/reqlog ./internal/audit` | pass |
| `go test ./internal/secscan` | pass |
| `cmd/culvert-maint` module: `go build ./...`, `go test ./...` | pass |
| Finding A gate reverted against merged main | **FAIL** — "cooldown was evicted after 1 new-key insert(s)" |
| Finding B gate with `persist()` moved under `mu` | **FAIL** — "List blocked while a save was in flight" |
| Finding C gate reverted against merged main | **FAIL** — `URL = "" after a URL-less update` |
| `golangci-lint run --new-from-rev origin/main` (gate command, v2.15.0 pinned) | **0 issues** |
| `golangci-lint run` full tree, this branch vs `origin/main` | **174 vs 174**, per-linter counts identical |
| `golangci-lint run` in `cmd/culvert-maint` | **0 issues** |

Each behavioural fix is proven differentially: the new gate fails against the
code as merged and passes against the fix.

The gate-pinned `golangci-lint` v2.15.0 was installed with the `go.mod`
toolchain, per `conventions.md`, rather than using the container's older binary.
Both passes required there were run: the gate's own `--new-from-rev`, and a
full-tree pass compared against the same measurement on the base — because
`cyclop`, `funlen` and `gocognit` attribute to a function's DECLARATION line and
`--new-from-rev` therefore cannot see a function made more complex. That second
pass earned its keep: it caught this review's own `runner.go` edit pushing
`validateComposeFilenames` from 14 to 16 against a threshold of 15, which the
`--new-from-rev` pass reported as clean. The check was extracted into
`validateComposeFileName` rather than the threshold being touched.

**Not run, and why.** CodeQL and the hosted Fast PR Gate are not reproducible
here. A passing local check is not a passing hosted gate — the PR's own checks
remain authoritative, and the CWE-117-sensitive edits in
`observability_startup.go` are the ones most worth watching there.

---

## Residual risk

1. **Finding D stands by decision.** Eviction remains deterministic, so a
   `cache_size`-sized flood still flushes every verdict; and with no eviction
   counter in `Stats()`, neither Finding A's thrash nor Finding D's flush is
   observable in production.
2. **Finding E stands by decision.** `requiredScope` still does not gate the
   browser SSO path; the guarantee is now documented accurately rather than
   enforced.
3. **`O_NOFOLLOW` is still absent** from every rotating sink, with the deferred
   open having widened the window from one instant to the process's lifetime.
4. **Finding A's fix is bounded to 8 heap slots.** In a cache whose top three
   heap levels are *all* short-lived entries, a cooldown can still be the
   victim. That is intentional — it is what keeps the bound enforced and the
   path O(1) — but it means the protection is strong, not absolute.
5. **Fail-open scanner classes are unchanged.** `clamDark` and the remote
   scanner's fault/oversize classes remain fail-open, which is what gives
   Findings A and D a bypass tail at all. That posture predates this window and
   was not re-litigated here.
