# Security Regression Review — 2026-11-17

**Scope.** `07c74ec…84b1b4c` — the window since the 2026-11-16 review: 36
non-merge commits, 98 files, +7,005/−451. Reviewed at
`84b1b4c6116166df1a77d373177b4cf16a671358`.

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `07c74ec`?** Every verdict below is measured
against that revision, not against an ideal. Where a finding is pre-existing
rather than newly introduced, it says so.

| Change | Security surface |
|---|---|
| `237209b` / `30ee1ed` `fix(proxy)` | A declined WebSocket upgrade now gets the plain-HTTP checks, and a blocked answer is not drained. **Hardening** |
| `af22214` `fix(inspect)` | `SEC-INSPECT-PLAINTEXT-1`: the strip-ALPN inspect path refuses a non-TLS client instead of raw-relaying it into the proxy's own TLS session. **Hardening — and the source of Finding A** |
| `78ae6d2` `perf(ssrf)` | Concurrent guard misses for one host share a single DNS resolution. **SSRF guard — the change most able to turn a refusal into an allow** |
| `3252991` `perf(auth)` | Auth-cache eviction victim selected from a heap instead of a scan over every client. **Authentication caching** |
| `0dc67b7` `perf(scanexcl)` | Scan-exclusion lists published as one immutable view. **Scanning bypass if a view tears or an empty list matches** |
| `6c1fef1` / `9f0d2b7` `fix(audit)` | A configured-but-unwritable audit log is reopened without a restart; `GetPersistent` snapshots the path under the lock. **Audit completeness — and the source of Finding B** |
| `a2bada4` / `dfe25e2` `fix(deploy)` | CHAOS-121: the HA compose actually hands culvert its flags and a stop grace. **Deployment secrets — and the source of Finding C** |
| `7f07ca8` `fix(ca)` | An automatically renewed Root CA keeps its key identifier. **TLS interception trust chain** |
| `434456a` / `215d04b` `alerts` | One payload validation across the webhook create and update arms; the process-wide alert store read and swapped atomically. **Admin ingress validation, alert egress** |
| `e089e83` / `8cd1ceb` / `60c5749` `crashguard`, feedsched | A contained panic that stalls a round pages the operator; the feedsched fallback reports instead of only warning. **Unsafe panic recovery, secret egress** |
| `184bc41` `diag` | A `CULVERT_C2_ENFORCE` break-glass node now says so on the Diagnostics report. **Authorization visibility** |
| 5 dependency bumps | brotli, klauspost/compress, kin-openapi, golang-x group, otel (tooling module). **Decompression limits, request validation, x509/TLS defaults** |

**Method.** Four of this window's changes are of the shape "a security control's
shape changed but its decision did not", which is only worth what the invariant
behind it is worth. Each was checked against the invariant rather than against
its commit message, and the load-bearing claims in comments were re-derived from
source. Four independent investigations ran in parallel over the auth cache,
scan exclusions, the audit/alerts plane, and CA/dependencies/deployment; every
finding below was then confirmed in the source by the reviewer, and the two
behavioural fixes were proven by reverting the fix and watching the new test
fail.

---

## No regression found in

- **The SSRF single-flight (`78ae6d2`).** The three properties that could have
  turned a refusal into an allow all hold at `internal/ssrf/ssrf.go:269-318`.
  The verdict cache is consulted *before* a flight is joined (`:274-280`), so
  the hot path is untouched. A failure is still never cached: `run` stores only
  `if err == nil` (`:409-411`). A verdict is stored **only while the flight is
  still registered** (`g.m[host] == f`), so a flight every waiter abandoned, or
  one orphaned by `CacheReset`, cannot write into the cache — and `CacheReset`
  takes `flights.reset()` before `dnsCache.mu`, so the documented lock order
  (`flightGroup.mu` → `dnsCache.mu`) has no inversion. A waiter whose own
  context ends leaves and gets `lookupAbandoned`, which is **not** wrapped in
  `ErrBlocked` and is treated as deny by every caller, as last window's review
  established. The shared lookup runs under a context derived from
  `context.Background()` rather than any caller's, so no caller's cancellation,
  deadline or values reach it; it is cancelled when the last waiter leaves, so
  it is never kept running for nobody. A panic in the resolver is contained by
  `obs.SafeCall` with `err` pre-set to `errLookupPanicked`, so a panicking
  lookup fails **closed** rather than killing the process now that it runs on
  its own goroutine. The connect-time `ssrf.Control` guard still runs
  immediately before `connect(2)`, so the DNS-rebinding TOCTOU window the
  pre-flight cannot close is still closed where it always was.
  `ssrf_lookup` is a fixed crash label and is counted by the cardinality gate
  (67 labels, cap 128 — verified by running it).

- **The auth-cache eviction index (`3252991`).** Expired-preferred is still
  structural, not best-effort: the `expiries` heap root is the minimum front
  deadline, so `!now.After(root.frontExpiry)` proves no bucket front is
  expired, which is equivalent to the old scan's early return. The fairness
  comparator is the same function the scan used (`identcache.BetterVictim`) and
  is a strict total order, so the heap root cannot diverge from the scan's
  maximum. Verified differentially against the retained scan at the real 5,000
  cap with 6,000 distinct fairness keys. Critically, a stale entry that
  survived eviction still cannot be **served**: `get` re-checks the TTL on
  every read, unchanged by this commit, so an index divergence would degrade
  the cap, never authentication. The cap is enforced on the same unchanged
  line; 60,000 insertions across 900 clients ended at exactly 5,000 entries.
  Displacing another principal's entry still requires controlling more distinct
  fairness keys (IPv4 address or IPv6 /64, XFF honoured only behind a
  configured trusted proxy) than the honest holders hold entries — unchanged
  from the scan.

- **The scan-exclusion immutable view (`0dc67b7`).** Both lists live in one
  struct behind one pointer, and a reader does one `Load`, so observing a new
  host list beside an old hash list is structurally impossible rather than
  merely unlikely. Every write to a view's fields happens before its `Store`;
  no map or slice alias escapes (`Lists` and `Save` copy keys into fresh
  slices, and `view` is unexported). Matching semantics are byte-for-byte
  identical on case folding, port stripping, trailing dots, subdomain
  behaviour (exact match only — there is no suffix or wildcard logic) and
  empty-list behaviour, confirmed by a 4,000-config differential fuzz against
  the pre-change implementation through both the `Replace` and on-disk `Load`
  paths. The catastrophic case fails **closed**: an empty, nil or
  not-yet-published view excludes nothing, so the callers scan. No regex, so no
  ReDoS surface; the view cannot grow from request traffic (the only writers
  replace both maps wholesale).

- **The Root CA key-identifier renewal (`7f07ca8`).** The renewal **reuses the
  private key** and copies the SKI onto that same key — it does not stamp an
  old key's identifier onto a new one, which would have been a spoofed
  identifier. `internal/ca/ca.go:651` passes the OLD key to
  `installSelfSignedCA` alongside the old `RawSubject` and `SubjectKeyId`, and
  renewal is gated to Culvert-generated roots, so an imported operator-owned
  root is never re-issued. `IsCA`, critical `BasicConstraints`,
  `CertSign|CRLSign`, key algorithm and subject are preserved; the serial is
  still freshly random. The bundle is still `AtomicWrite` at `0600` with the
  key, cert and provenance written in one call, so there is no window where the
  on-disk key and cert disagree. Because the key is reused, a leaf a client
  still holds validates under both the old and renewed root — which is the
  property the change restores for AKI-enforcing clients.

- **The audit deferred open's safety properties (`6c1fef1`).** The retry's open
  goes through the same constructor as the startup open with the same threshold
  (`fileutil.NewRotatingFile`, `O_CREATE|O_WRONLY|O_APPEND`, mode `0600`, no
  `O_TRUNC`), so a reopen can neither truncate an existing trail nor widen its
  mode. Entries are backlogged inside the same critical section that observed
  `persist == nil`, so an entry is either backlogged or written, never both or
  neither; the backlog is bounded at `MaxRing`; and the backfill happens before
  publishing, under the lock, so order is preserved and nothing is written
  twice. The audit path is startup-only and deployment-controlled (`-audit-log`
  / `audit_log_file`), with no admin API or UI writer, so it is not
  attacker-chosen. Publish-versus-shutdown is correct: `Close` sets `closed`
  and reads the sink in one critical section, so the handle is closed on
  exactly one of the two paths — no write to a closed file, no double close.
  The `GetPersistent` lock fix resolves a real unsynchronised read of a string
  concurrent with a write.

- **The alerts changes (`434456a`, `215d04b`).** The update arm now runs the
  same three refusals in the same order as create; `urlRequired` is the only
  difference, and `h.Enabled = true` on create is whole-resource `PUT`
  semantics rather than a validation gap. Event names never reach the outbound
  payload or headers: `Dispatch` sets `payload.Event` from the **producer's**
  compile-time string and uses the subscription list only as a match filter, so
  CRLF header injection and JSON breakout are not reachable even for a name
  that bypassed ingress. `alertStoreRef` is initialised non-nil and every
  `Store` call in the tree is in a test; production publishes once and mutates
  in place, so no reader can observe a nil or superseded store, and the retry
  queue re-reads the hook by ID and drops a deleted or disabled one.

- **The crashguard/feedsched reporting (`e089e83`, `8cd1ceb`, `60c5749`).** The
  `panic_contained` payload still carries only a compile-time component and an
  internal crash id — never the recovered panic value, which can embed a
  credential and which a webhook would egress. `feedsched`'s new fallback
  reports under ONE fixed label (`feedsched_round`, not one per feed), which is
  what keeps it inside the sink's bounded label set; the feed's identity stays
  in the WARN line, where cardinality costs nothing. Containing the `RunNow`
  cold-start predicate is strictly fail-safe: it answers `false` on a panic and
  falls through to the interval loop instead of letting an unrecovered panic in
  a bare goroutine kill the gateway.

- **The dependency bumps.** klauspost/compress 1.20.3→1.20.4 is a **hardening**
  bump (`DecodeAll` no longer allocates from the attacker-declared
  `FrameContentSize`; pooled-frame references dropped; sequence-decoder
  over-allocation slack widened to match the assembly). brotli 1.2.8→1.3.0's
  only decoder change is the **opt-in**, default-off RFC 9841 large-window
  extension, and Culvert calls plain `brotli.NewReader` with no
  `ReaderOptions`, so the window ceiling is unchanged. kin-openapi is not
  reachable at runtime (no `openapi3filter`, no router, no request validation
  anywhere in the tree — only tests and `cmd/apibundle`). In the golang-x
  group, x/crypto 0.58→0.59 changed **not one byte** of the packages Culvert
  imports, and x/text's `ParseAcceptLanguage` fix is in a package Culvert does
  not import; x/net was **not** bumped, so the http2 stack and the IDNA tables
  are untouched. Independently of the bumps, Culvert does not rely on library
  decoder defaults: every decompression call site bounds expansion itself with
  `MaxDecompressBytes` plus a ratio allowance, and a ratio breach is a refusal.
  The `godebug x509sslcertoverrideplatform=0` pin and `toolchain go1.27.4` are
  intact and asserted by existing tests. **Not verifiable offline:** no CVE or
  GHSA identifier could be confirmed from this session (no advisory-database
  access); the statements above come from each module's own source, diffed old
  against new in the module cache. `govulncheck` is a blocking gate on the root
  module, so identifiers are checked there.

- **The deployment fix's flag set (`a2bada4`), apart from Finding C.** Nothing
  in the now-applied flags weakens posture: no `-ui-no-tls`, no
  `--cluster-insecure`, no skip-verify, no break-glass env, no admin password
  or session-secret default, no host path mounted writable, no `user:` override
  (so the image's `USER proxy` applies), and `-socks5-port` is still unset so
  1080 stays closed. `-port`/`-ui-port` equal the built-in defaults, so no
  listener was newly opened by the flags. The entrypoint change is safe for
  this image: both scripts end in `exec ./culvert`, so culvert is still PID 1
  and receives SIGTERM, and they expand env only through word splitting — no
  `eval`, no command substitution — so a hostile `HA_JOIN`/`ENROLL_URL` cannot
  inject a command. The same diff closes a multi-minute **AV fail-open** window
  on every HA boot (`depends_on: clamav: service_healthy`) and stops SIGKILL
  mid-drain. One honest note: `-cp-grpc-addr :50051` is now actually set on a
  standby, so a listener that silently did not exist now does; peer auth still
  fails closed without a TLS peer certificate because `--cluster-insecure` is
  not set, but with `CP_CERT`/`CP_CA` unset the channel is plaintext.

- **`184bc41`, the break-glass diagnostics row.** Report-only: it reads the
  already-resolved, read-once mode and the existing would-deny counter and
  changes neither, contributes no row in the default enforce mode, and
  handler-level `requireRole` keeps enforcing in both modes. It makes a node
  left in break-glass after an incident distinguishable from a healthy one,
  which is a detection improvement.

---

## Finding A — HIGH: `SEC-INSPECT-PLAINTEXT-1` was closed on one of the two inspect paths

**Status.** Incomplete fix landed in this window. **Fixed here.**

The strip-ALPN inspect path now refuses a client whose first byte is not a TLS
handshake record (`0x16`). The **native-ALPN** leg — the one an
`InspectHTTP2` decryption profile or an explicit `StripALPN=false` rule selects
— kept its raw-relay fallback, and its comment still described itself as
"mirrors the strip path's non-TLS fallback", which it had stopped being.

```
proxy_tunnel_h2.go:166-169 (before this change)
    if firstByte[0] != 0x16 {
        logger.Printf("SSL_INSPECT(native) non-TLS first byte 0x%02x for %q — raw relay", …)
        relayPlaintextInspectFallback(rawClient, peekBuf, rawUpstream, hostOnly, match, id)
        return
    }
```

**Attack scenario.** A client issues `CONNECT host:443` for a destination
matched by an inspect rule with HTTP/2 inspection enabled, waits for the `200`,
and sends any first byte other than `0x16`. It receives a raw TCP tunnel to the
origin instead of an inspected session.

**Preconditions.** An inspect rule whose resolved `StripALPN` is false — i.e. a
bound decryption profile with `InspectHTTP2: true`, or `stripAlpn: false` on the
rule. This is a documented, supported operator feature
(`docs/operator/http2-inspection.md`). The default and every pre-feature rule
resolve to strip, so a deployment that has not enabled HTTP/2 inspection was
never exposed.

**Exploitability: trivial once reachable.** The discriminator is one byte and
the client chooses it. No race, no timing, no credentials beyond whatever
already authorises the CONNECT.

**Likelihood: medium.** Gated on an opt-in rule setting, not on the default.

**Impact.** Every content-level control on a destination an operator explicitly
marked for inspection is bypassed: no inner-host pin, no file-extension block,
no file-profile block, no DPI, no malware scan, and no per-request log row. The
tunnel is also recorded as `not_decrypted/non_tls_fallback` rather than as a
refusal, so the bypass reads as a benign SSH-over-CONNECT session. The
inner-host pin's absence additionally means the client can address any vhost
reachable at that address through a tunnel authorised for another name.

**This leg was the MORE reachable of the two.** The strip path handshakes the
origin *before* it peeks, so its fallback required an origin that speaks TLS
and a client that does not — which is why the strip-path fix could argue the
fallback "could not serve what it was written for". The native leg must wait
for the client's ALPN offer, so the upstream handshake is still ahead of the
peek: the client alone decided, against **any** origin, TLS or not. Proven
against a plain-TCP origin — one the strip path would have `502`'d before the
peek — where the pre-fix code relayed 43 plaintext bytes to the origin.

**Affected assets.** Inspected HTTPS traffic; the content-inspection controls
above; per-request audit completeness.

**CWE-693** (protection mechanism failure), with **CWE-350** for the unpinned
inner host. **OWASP A01:2021 — Broken Access Control** (policy bypass).
**Severity: High. Regression risk of the fix: medium** — see the behavioural
cost below.

**Fix.** The native leg refuses and closes both legs, recording the refusal
through the ADR-0011 taxonomy exactly as the strip path does. The two refusals
are now **one function**, `refuseNonTLSInspectClient` in `proxy_tunnel.go`,
because the drift *was* the vulnerability: a future change to this decision now
reaches both legs or neither. `relayPlaintextInspectFallback` is deleted, and
with it the CHAOS-57 test that existed only to prove that relay contained a
panic (the guard contract is still pinned for every relay that survives).

**Behavioural cost, stated plainly.** A genuine non-TLS protocol over CONNECT
(SSH, RDP) to a host matched by an `InspectHTTP2` rule is now **refused** rather
than tunneled. Unlike the strip path, where the owner could argue the case was
already impossible, here it was reachable. The operator remedy is an explicit
Bypass rule for that destination, which is auditable; a silent per-connection
opt-out chosen by the client is not. This follows the project's stated order —
security over convenience — and the owner decision recorded for the strip path
on PR #1929, applied to the same situation on the sibling leg. An operator
running SSH over an HTTP/2-inspect rule today will see refusals after this
change and needs that Bypass rule.

**Required tests** (all added, all verified to fail without the fix):
`TestInspectNative_PlaintextClientCannotReachOriginUninspected` (regression:
origin receives zero bytes, client reads zero back, a `DECRYPT_FAILED` entry is
recorded and no `TUNNEL_CLOSED` relay entry is),
`TestInspectNative_RefusalCoversEveryNonTLSFirstByte` (boundary/malformed: the
bytes bracketing `0x16`, plus SSH, plaintext HTTP, RDP/TPKT, NUL and `0xFF`),
`TestInspectNative_ConcurrentPlaintextClientsAreAllRefused` (concurrency: eight
simultaneous refusals relay nothing and do not deadlock). The positive control
is the existing `TestMITM_NativeH2_*` suite, which still passes — the refusal is
not over-broad.

**Contract note.** No `amended`/`retired` record is needed. `TLS-002` forbids
"forwarding inspect-matched traffic uninspected"; this change enforces that
invariant on a leg that was not enforcing it. `TLS-001` (origin verification and
the TLS floor) is untouched.

---

## Finding B — LOW: the audit recovery's charge loop is an unauthenticated DoS lever

**Status.** Newly introduced in this window by `6c1fef1`. **Fixed here.**

When the deferred open finally succeeds, `TryDeferredOpen` charged each evicted
backlog entry **one at a time**, inside the critical section that holds the
process-wide audit mutex:

```
internal/audit/deferred.go:167-169 (before this change)
    for i := 0; i < backlogDropped; i++ {
        countWriteError(path, fmt.Errorf("audit entry evicted from the %d-entry backlog …", MaxRing))
    }
```

**Attack scenario.** The configured audit log is unwritable at startup — the
premise of the feature, e.g. a volume not yet mounted. `auth.lockout` is audited
on **every** blocked login at `/api/auth/login`, before anyone is
authenticated, so an attacker adds one to `backlogDropped` per request
indefinitely (`backlogLocked` trims to `MaxRing` and adds the overflow to the
counter with no ceiling). When the operator fixes the mount, the recovery spins
that many iterations while holding `mu` — each one allocating an error and
taking the observer's own mutex — stalling every `auditEvent` from the admin API
and every audit read behind it.

**Preconditions.** Audit log unwritable at startup, plus reachability of the
unauthenticated login endpoint. **Exploitability:** easy but indirect — the
stall lands at recovery time, not at request time. **Likelihood: low** (needs
the misconfiguration to coincide). **Impact:** admin-plane and audit-read
availability during the recovery; the amplification is bounded only by the
attacker's request budget.

**Affected assets.** Admin API availability; audit read path.
**CWE-400 / CWE-770** (uncontrolled resource consumption under a shared lock).
**OWASP A04:2021 — Insecure Design.** **Severity: Low. Regression risk of the
fix: low.**

**Fix.** `countWriteErrorsN` charges the batch once: `writeErrors` still moves
by exactly `n` — it is the operator's count of entries missing from the durable
trail, surfaced on `/api/stats`, `/healthz` and `/metrics` — while the observer,
which latches "this node's durable writes are failing" and hands an alert to a
goroutine, is called once. Collapsing the loop by *under-counting* would have
hidden the loss, so the test asserts both halves together. The stale premise in
`countWriteError`'s own comment ("there is no batch to lose") is corrected: the
backlog is that batch.

**Required tests** (added, verified to fail without the fix):
`TestDeferredOpen_EvictedBacklogIsChargedInOneBatch` (500 evictions ⇒
`WriteErrors` exactly 500 **and** exactly one observer call — it reports 500
calls without the fix) and `TestCountWriteErrorsN_ZeroAndNegativeAreNoOps`
(boundary: the common path charges nothing and does not wake the observer). The
pre-existing exact-count gate still passes.

---

## Finding C — LOW–MEDIUM: CHAOS-121 moved the HA join token into argv

**Status.** Newly introduced in this window by `a2bada4`/`dfe25e2`. **Fixed
here.**

Before CHAOS-121 the HA compose's script was never executed: the image's
`ENTRYPOINT ["./culvert"]` received the script text as argv, so `$HA_TOKEN` was
never expanded — which is the bug CHAOS-121 fixed. Adding
`entrypoint: ["/bin/sh", "-c"]` made the script run, and with it
`ARGS="… --ha-token=$HA_TOKEN"` followed by `exec ./culvert $ARGS` expanded the
token into culvert's command line for the first time.

**Why the channel matters.** `/proc/<pid>/cmdline` is readable by any account in
the PID namespace; `/proc/<pid>/environ` is restricted to the process owner.
`-ha-token` was the binary's only channel — there was no env or file form —
whereas the repo states the opposite preference for its other secrets in the
very comments next to them (`main.go`: "Using an env var keeps the passphrase
out of CLI history and process listings"; `internal/ca/ca.go`: "so it never
appears in CLI history or process listings").

**Attack scenario.** The HA token is not merely a join bearer token: it is the
AES-256-GCM key-wrapping passphrase for the **cluster CA private key** in the HA
state bundle (`controlplane_server.go`, `CAKeyEncrypted` — its only transport).
Any unprivileged local account on a CP or standby host, or any additional
process inside the container (a `docker compose exec` session, a compromised
helper), reads the token from `/proc/<pid>/cmdline`, then authenticates a
standby join to the leader, pulls the HA state bundle, and decrypts the cluster
CA private key — enough to mint node certificates.

**Preconditions.** An HA deployment using the shipped compose, plus local
unprivileged read access in the PID namespace. Root or docker-socket access was
always sufficient (`docker inspect` exposes the env var), so the **new**
exposure is specifically to unprivileged local readers.
**Exploitability: easy** (a file read). **Likelihood: low–medium** — depends on
host tenancy. **Impact: high if reached** (cluster CA private key).

**Affected assets.** Cluster CA private key; HA cluster membership.
**CWE-214** (invocation of process using visible sensitive information), leading
to **CWE-522**. **OWASP A02:2021 — Cryptographic Failures.**
**Severity: Medium on a shared host, Low on a dedicated appliance. Regression
risk of the fix: low** — the flag still wins when set.

**Fix.** `CULVERT_HA_TOKEN` (`haTokenEnv`) is the env channel, mirroring the two
passphrases that already take this env-only startup-secret exception, and the
shipped compose uses it instead of a flag. `-ha-token` is kept and still wins
when both are set, so an operator invoking culvert directly is unaffected. The
env value is whitespace-trimmed (a token copied out of a deploy command easily
acquires a trailing newline, and the resulting failure reads as a wrong token);
the flag value is passed through verbatim so no existing invocation changes
behaviour. A whitespace-only env value resolves to empty, so the compose's
split-brain guard still fires rather than sending a blank token to the leader.

**Required tests** (added):
`TestResolveHATokenInput_PrecedenceAndTrimming` (10 cases: precedence both ways,
env trimming, flag verbatim),
`TestResolveHATokenInput_EmptyEnvCannotForgeAStandbyJoin` (negative control
against `haJoinMode()`), `TestHATokenEnv_IsReadAndNotLogged` (the wiring exists
and no source file logs the token), and
`TestDockerComposeHA_TokenReachesCulvertThroughTheEnvironment` (the proxy
service exports it — without this, removing the flag would silently stop
standbys joining).

**A pre-existing gate was deliberately inverted.**
`TestDockerComposeHA_JoinWithTokenYieldsValidArgv` required
`--ha-token=<value>` *in* argv. It now asserts the opposite: the token must not
appear in argv at all. That assertion is annotated with why, so the reversal is
not mistaken for a weakened test.

**Same channel, lower value, NOT fixed:** the DP service passes
`--enroll $ENROLL_URL`, putting the single-use, fingerprint-bound enrollment
token in argv too. Lower value (single-use and bound), but the same shape;
recorded as residual risk rather than expanded into this change.

---

## Pre-existing findings surfaced by this window (reported, two fixed)

**D — LOW, fixed here: `/api/config/import` was the second webhook write
ingress and validated neither field.** `webhookPayloadRejected`'s comment calls
itself the one definition of an acceptable payload and credits it with keeping
an unvalidated value "from reaching the webhook file, a support bundle or any
other consumer at all". `apiConfigImport` reconstructed webhooks straight
through `alertStore().Add` with no URL or event-name check: a v1 backup
carrying `events: ["<img src=x onerror=alert(1)>"]` and
`url: "javascript:alert(1)"` imported with **HTTP 200** and both values landed
in the store. The downstream sinks hold — the Alerts panel escapes, and a bad
URL is refused at egress by the scheme barrier plus `ssrf.SafeDialContext` — so
this is defence in depth, not a live XSS or SSRF, and the route is `RoleAdmin`,
so there is no escalation out of the operator role that
`SEC-ALERTS-EVENTNAME-1` was about. It is still the gap that matters: the
character class and the 64-byte bound exist so the value never reaches the
file, and a control enforced at one of two ingresses is the shape of defect
that produced the original finding. Now validated in the import's
pre-validation block beside the URL-category and PAC gates, so a bad backup is
refused **whole** rather than partially applied. **CWE-20.** Tests added:
hostile event names (10 shapes), non-http(s) URLs (6 shapes), a positive
control including `*` and a name exactly at the bound, and an all-or-nothing
case proving one bad entry prevents the good ones from installing.

**E — LOW, reported not fixed: `Store.Update` blanks a URL the caller omits,
and a comment claims it does not.** `ui_security.go` justifies `urlRequired`
with "an empty URL on an update preserves the stored one (see `Store.Update`)".
`Store.Update` preserves only the secret and then assigns the caller's struct
wholesale, so a `RoleOperator` `PUT` that omits `url` passes validation,
blanks the URL and persists it: the webhook stays listed and enabled while every
delivery is skipped and recorded as "invalid URL" — a silent **detection** loss
of exactly the kind this repo treats as severe. Behaviour is byte-identical to
`07c74ec` (the pre-refactor arm had the same guard), so the refactor is
faithful; what is new is a comment asserting a safety property the code does not
have, which is the kind of false premise that produced the original event-name
gap. Not fixed here because the remedy is a choice between two API contract
changes — make `Update` preserve a non-supplied URL, or require `url` on `PUT` —
and that is an owner decision, not a regression repair. **Recommended fix:**
preserve the stored URL when the caller supplies none, matching both comments.

**F — LOW, reported not fixed: the scan-exclusion tearing test asserts
nothing.** `TestConcurrentReplaceAndRead`'s comments claim its readers "assert
the only two answers a correct publish can produce, so a torn view … fails
rather than passing quietly", but every reader discards its result
(`_ = s.IsHashExcluded(...)`). Demonstrated: with a mutant whose `Replace`
deliberately publishes a half-updated view, the entire shipped suite still
passes under `-race`. It is a data-race probe only, so the "one immutable view"
invariant — the whole point of `0dc67b7` — currently rests on code reading. Also
missing: any test that excluding `mirror.example` does **not** exclude
`evil.mirror.example` (exact-match-only is unpinned, and a future "helpful"
suffix match there is a malware-delivery bypass). Separately, the file's comments
state that `mu` "serialises writers", which it no longer does — `Replace` never
takes it; the outcome is unchanged (last publish wins, no torn view either way)
and it is unreachable in practice (`Load` is startup-only, admin PUTs are
serialised by `contentSecMu`), but the next reader will rely on the stated
guarantee.

**G — LOW, reported not fixed: hardening items.** (i) Neither audit open uses
`O_NOFOLLOW`, and the retry now re-opens the same path every ≤2 minutes for the
process lifetime rather than once at startup; the precondition is write access
to the audit directory and the damage is append-only JSONL into the link target
(**CWE-59/61**). (ii) `evictOneLocked` increments the eviction counter
unconditionally after a `removeLocked` that is a silent no-op for an absent key,
so a future index bug would present as silent cap non-enforcement plus an
over-counted metric rather than a loud failure. (iii) `Close` discards the
audit backlog and its drop count with no charge, so entries buffered at
shutdown are lost silently — parity with `07c74ec`, but the new code has the
count and throws it away. (iv) `tools/gosec` is outside `govulncheck`'s scope.
(v) The declined-upgrade relay copies origin headers verbatim via `copyHeaders`,
including hop-by-hop names; unchanged from `07c74ec` and largely constrained by
`net/http`'s own response handling, but it is not a filter.

---

## Verification

Run at the working tree built on `84b1b4c`, toolchain `go1.27.4` from
`go.mod` (`toolchain` line, not the `go` minimum):

- `go build ./...`, `go vet ./...` — clean.
- `go test ./internal/... -count=1` — pass.
- `go test . -count=1 -timeout 1800s` — pass (409 s). One iteration failed
  first on `TestTestFileReadsAreCWDIndependent`, a repo wall catching a
  CWD-relative read in a new test of mine; the read is now anchored to
  `pkgSourceDir()` and the suite is green.
- `go test -race ./internal/audit/ ./internal/alerts/ ./internal/ssrf/` — pass.
- `golangci-lint v2.15.0` (the version `pr-fast-gate.yml` installs), built with
  the `go.mod` toolchain: `run --new-from-rev origin/main` → **0 issues**, and a
  **full-tree** pass → **174 issues**, byte-for-byte the same count and the same
  per-linter breakdown as the identical full-tree pass on `origin/main` measured
  in a separate worktree. The full-tree comparison was necessary, not
  ceremonial: the first version of the Finding A fix pushed
  `handleInspectNativeALPN` to 51 statements and added a **9th** `funlen`
  finding that `--new-from-rev` could not see, because `funlen` attributes to a
  function's declaration line. Consolidating both refusals into
  `refuseNonTLSInspectClient` removed it — the fix for the lint finding and the
  fix for the root cause of Finding A turned out to be the same change.
- `go run ./cmd/contractcheck impact -base origin/main` — lists PKI-900/901,
  SWG-001/002, TLS-001/002, TLS-900 as touched by the window; no invariant
  changed, so no `amended`/`retired` record is required (see the contract note
  under Finding A).
- `python3 docs/agent-context/check.py` — pass; no guidance path changed.

**Not run:** the aggregate hosted CI for this SHA, CodeQL, `govulncheck` (no
advisory-database access from this session), and any compose bring-up. A passing
local check is not a passing hosted review or merge gate.

**Residual risk.** Finding E, F and G are open by choice and recorded above. The
DP enrollment token shares Finding C's channel. Deployments that have enabled
HTTP/2 inspection and rely on non-TLS protocols over CONNECT to an
inspect-matched host need an explicit Bypass rule after Finding A's fix.
