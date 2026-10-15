# Security regression review — inspected-tunnel inner-host pinning (SEC-TUNHOST-1)

> **Window:** 2026-10-15 · **Scope:** the proxy request/response path, the TLS-inspection
> (decrypt) plane, policy default-action resolution, host normalization and the in-flight
> change set, at `origin/main` (`77c0c58`).
> **Outcome:** one HIGH policy-enforcement gap found on the inspected tunnel, reproduced
> against the real enforcement seam, fixed and walled. One MEDIUM toolchain-divergence
> finding on an in-flight dependency PR, which fails closed. Everything else reviewed in
> this window is recorded below as reviewed-and-safe, with the reason it is safe, so the
> next reviewer does not re-derive it.

---

## 1. Executive summary

A CONNECT request is authorized **once**, against the authority the client names in the
CONNECT line. `handleTunnelInspect` derives `hostOnly` from it, and on the inspected path
everything downstream is decided against that one value: `policyStore.Evaluate` ran on it,
the decryption profile resolved on it, the upstream TLS `ServerName` is it, and every log
row, scan verdict and CDR decision the tunnel produces is attributed to it — because
`runInspectExchange` threads `ex.host` and never `ex.req.Host`.

**The decrypted stream carries its own destination on every request, and nothing compared
the two.** `rq.Write` writes `req.Host` on the HTTP/1.1 leg and `upstreamCC.RoundTrip`
sends it as `:authority` on the HTTP/2 leg, so a client could open a tunnel to a
destination policy allowed and then ask that same connection for a different one. The
upstream connection is pinned to the CONNECT target's address, so this is **not** SSRF —
but any shared front end (a CDN, a cloud load balancer, any multi-tenant vhost) routes by
`Host`/`:authority`, so the response is the one the *client* named, not the one policy
allowed.

This inverts what the inspection plane is for. Decryption exists so the gateway can see and
decide on what is actually being requested; here it decrypted the request, decided against a
host the client had already abandoned, and forwarded the client's real choice untouched. The
request log then recorded the authorized host for a retrieval of the unauthorized one, so
the bypass was invisible to an operator reviewing traffic afterwards, and scan/CDR verdicts
were mis-keyed the same way.

The gap was known in part: the H2 path's own comment recorded "strict `:authority` pinning /
421 handling" as a pending refinement. It was not recorded that the H1 keep-alive loop had
the identical hole, that policy — not merely logging — was affected, or that the
authorizing value rather than the SNI is the only safe anchor.

Fixed by pinning the inner host to the CONNECT authority in `runInspectExchange`, the single
enforcement seam both protocols run (invariant C5), ahead of the round trip so an
unauthorized destination is never fetched.

## 2. Finding SEC-TUNHOST-1 — an inspected tunnel forwards a client-chosen host it never authorized

| | |
|---|---|
| **Severity** | HIGH where TLS inspection is enabled and destinations are shared-hosted (the ordinary SaaS/CDN case); not reachable where inspection is off |
| **CWE** | CWE-441 (unintended proxy / intermediary); CWE-290 (spoofing by vhost confusion); CWE-778 (the retrieval was logged under the wrong destination) |
| **OWASP** | A01:2021 Broken Access Control |
| **Regression risk** | HIGH — two protocol paths, no test pinned the invariant, and the forwarded value looked like ordinary request plumbing |
| **Status** | ✅ CLOSED for a named CONNECT target; scope limit recorded in §5 |

### Affected assets

Every policy decision on the inspected path, and the request-log/scan/CDR attribution that
rides it: destination FQDN rules, category and category-group rules, blocklist and threat-feed
verdicts, file-profile and CDR decisions — all keyed on `ex.host`, for any tunnel whose
destination resolves to an address that serves more than one name.

### Reachable paths (both reproduced through the shared seam)

| Path | Where the inner host is forwarded | Policy/attribution value |
|---|---|---|
| H1 keep-alive loop (`runH1InspectLoop`, `proxy_tunnel.go`) | `rq.Write(upstreamTLS)` writes `req.Host` | `hostOnly` (`ex.host`) |
| H2 per-stream (`h2InspectStream`, `proxy_tunnel_h2.go`) | `upstreamCC.RoundTrip(rq)` sends `req.Host` as `:authority` | `hostOnly` (`ex.host`) |

Both construct an `inspectExchange` and call `runInspectExchange`, so both inherited the
gap from one place and both are closed by one gate.

### Attack scenario

**Preconditions.** A policy rule allows `allowed.example.com` with TLS inspection enabled;
`blocked.example.com` is denied (by rule, category, blocklist or threat feed); both names
are served by the same front end — the same CDN tenant pool, load balancer or shared host.
The client is an ordinary proxy client with no special privilege. No credential, no admin
access, no network position beyond being a configured proxy client.

**Steps.**

1. `CONNECT allowed.example.com:443` — policy evaluates `allowed.example.com`, allows,
   selects the decrypt profile, and MITMs the tunnel.
2. Inside the decrypted stream: `GET /secret HTTP/1.1` with `Host: blocked.example.com`
   (or, on H2, `:authority: blocked.example.com`).
3. Culvert forwards the request over the pinned upstream TLS connection carrying the
   client's `Host` verbatim.
4. The shared front end routes by `Host` and serves `blocked.example.com`.
5. The request log records `allowed.example.com`.

**Exploitability.** Trivial — a single header. No race, no timing, no malformed input, and
nothing that an ordinary HTTP client cannot emit. On H1 the client can also reuse the same
tunnel for many such requests under one allow decision.

**Likelihood.** High in any deployment that both inspects TLS and relies on name-based
rules against shared-hosted destinations, which is the common enterprise SWG shape (the
same IP pool serves a tenant's allowed and disallowed SaaS properties).

**Impact.** Name-based policy — the gateway's primary control — is bypassed for the
inspected path, and the audit trail attributes the retrieval to the allowed host, so the
bypass does not appear in traffic review. Scanning and CDR still run (content control is
intact), but their verdicts are recorded against the wrong destination.

### Why this was invisible

The forwarded value is the request's own `Host`, which on every *other* path in the proxy
is the authorizing value. On the plain-HTTP path `r.Host` **is** what policy evaluates, so
forwarding it is correct there. The inspected path is the one place where the authorizing
value and the forwarded value are different objects, and the code that forwards
(`rq.Write`, `RoundTrip`) is exactly the code that forwards on every other path. Nothing
looked wrong at either site.

`runInspectExchange`'s own signature hid it too: it takes `host` and a `req` as separate
fields and passes `ex.host` to every helper, which reads as deliberate attribution rather
than as a value that ought to have been checked against `ex.req.Host`.

### Fix

`runInspectExchange` now pins the inner host to the CONNECT authority before anything is
forwarded:

- **Position is part of the fix.** The gate is the first statement in the function — ahead
  of the round trip, so an unauthorized destination is never *fetched* (a refusal taken
  after the round trip would already have retrieved it, which on a shared front end is the
  whole harm), and ahead of `scrubForwardedHeaders`, so the refusal cannot depend on
  anything the scrub rewrites.
- **The anchor is the CONNECT authority, not the SNI.** A client controls both its SNI and
  its `Host`, so it can make them agree with each other and still name a destination policy
  never saw. Only the authorizing value is safe. `TestInnerHostPin_SNIAgreementDoesNotExcuseTheMismatch`
  fails CI if the pin is ever "simplified" to compare against the SNI.
- **Both sides are reduced identically** — port and IPv6 brackets stripped
  (`hostutil.StripHostPort`), then IDNA-canonicalized (`hostutil.NormalizeHostStrict`) — so
  the spellings the downstream matchers already fold to one destination still pass: case, a
  trailing dot, an explicit port, and a U-label against the A-label the CONNECT carried.
  This is not laxity; a pin that refused those would reject traffic policy allowed, for
  spellings naming the very same host.
- **Not the policy matcher's comparison.** `hostutil.MatchFQDNNorm`'s bare-domain semantics
  treat `evil.allowed.example.com` as matching `allowed.example.com` — correct for a policy
  *rule*, wrong here, because a subdomain is a separate destination that got no decision of
  its own. `TestInnerHostPin_SuffixMatchWouldNotHaveCaught` pins that distinction so a
  future refactor cannot reach for the policy matcher to "reuse the host comparison".
- **Fail-closed.** A host that cannot be canonicalized on either side is refused rather
  than compared loosely. An exchange with no recorded tunnel destination is refused rather
  than forwarded on a client-chosen host.
- **Refusing cannot break a conforming client.** HTTP/1.1 requires `Host` to name the
  request target's authority. HTTP/2 permits connection reuse for a second origin
  (RFC 9113 §9.1.1) only when the certificate is authoritative for it — and the forged leaf
  carries a single SAN (`internal/ca/ca.go`: `DNSNames` is exactly `[]string{host}`, minted
  per client SNI through the `GetCertificate` hook), so no second origin is ever covered. A
  mismatch is a misconfigured client or deliberate evasion, never legitimate coalescing. A
  client that wants the other host may open a tunnel for it, which then receives its own
  policy decision — which is the property being restored.

421 Misdirected Request is the standards-correct status and is what the H2 TODO
anticipated, but `blockResponder` is deliberately frozen to one pre-commit shape
(`inspect_block.go`), which emits 403 on both protocols. 403 is honest here too: the
destination the client actually asked for was never authorized.

**Observability.** New counter `culvert_proxy_inner_host_mismatch_blocked_total`, always
emitted — so a flat zero means "no client has done this", never "the gate is off" — and an
`INNER_HOST_MISMATCH` log line naming **both** hosts, since either alone says nothing. Both
are client-influenced and go through `sanitizeLog` + `%q` (CWE-117).

### Safe implementation notes

- The inner request body is closed on the refusal path: nothing was forwarded, so the
  client's upload is not drained. On H1 the 403 carries `Connection: close` and the loop
  tears the tunnel down, so a mismatch cannot be retried by pipelining. On H2 the block is
  per-stream and writes no connection-specific header (illegal in HTTP/2, RFC 9113 §8.2.2);
  `handleH2StreamOutcome`'s `exBlocked` arm correctly leaves the responder's 403 as the
  terminal action and does not reset the stream.
- `statBlocked` is charged alongside the dedicated counter, matching the sibling tunnel
  blocks (`dpiBlock`, `scanBlockConn`, `emitFileBlock`).
- Absolute-form inner request targets are covered incidentally and correctly: Go's
  `ReadRequest` sets `req.Host` from the URL authority for absolute-form, so a
  `GET http://other.test/ HTTP/1.1` smuggled inside the tunnel is refused on the same gate.

### Required tests — all present

| Test | What it would catch |
|---|---|
| `TestInnerHostPin_MismatchIsRefusedBeforeTheUpstreamIsContacted` | **Defect gate.** Verified failing against the verbatim pre-fix body. Asserts the upstream was never *contacted*, not merely that the exchange was blocked, plus the counter and the both-hosts log line. |
| `TestInnerHostPin_AuthorizedDestinationStillFlows` | Negative control — a gate that refused everything would pass the defect gate while taking the proxy offline. Passes before and after the fix. |
| `TestInnerHostPin_ClientResolvedAddressTunnelStillFlows` | The scope shape (§5) on IPv4 and IPv6, at the pipeline level rather than only in the table, because this is what a future tightening would break. |
| `TestInnerHostPin_SNIAgreementDoesNotExcuseTheMismatch` | A self-consistent SNI/`Host` pair naming an unauthorized destination. Fails if the pin is re-anchored on the SNI. |
| `TestInnerHostPin_SuffixMatchWouldNotHaveCaught` | A subdomain of the authorized host, with a precondition asserting `MatchFQDNNorm` *would* have accepted it. |
| `TestInnerHostPinnedToTunnel_Equivalences` | Boundary/malformed table: case, trailing dot, U-label↔A-label, default and non-default ports, IPv4/IPv6 literals, bracketed IPv6, parent/subdomain/suffix-extension/prefix-truncation, unnormalizable input, empty inner host, empty tunnel host. |
| `TestInnerHostPin_RefusalIsEmittedOnBothProtocolWires` | The 403 wire bytes on each responder, including that H2 sends no `Connection` header. |
| `TestInnerHostPin_ConcurrentMismatchesAreAllCharged` | 400 concurrent refusals under `-race`; the counter is a process global every inspected tunnel charges. |

## 3. Files

| File | Change |
|---|---|
| `inspect_host_pin.go` | New. The predicate, the refusal, the counter, and the rationale including the scope limit. |
| `proxy_tunnel.go` | `runInspectExchange` gains the pin as its first statement. |
| `events.go` | Exposes `culvert_proxy_inner_host_mismatch_blocked_total` on `/metrics`. |
| `inspect_host_pin_test.go` | New. The gates above. |
| `CHANGELOG.md` | Security entry. |

## 4. Reviewed and found safe

Recorded so the next reviewer does not re-derive these.

### 4.1 Host normalization and the new IDNA memo (`internal/hostutil`, merged #1598)

A memo on the request path is where a policy-bypass regression would hide, so it was read
closely. It is sound:

- `normalizeHostStrictMemo` re-verifies the **full key** on every hit (`e.host == host`), so
  a direct-mapped collision costs a recomputation, never a wrong answer. Entries are
  immutable once published (`atomic.Pointer` to a freshly built struct), so a concurrent
  reader sees the previous entry or this one, never a mix.
- The memo is a genuine memo, not a cache: `idna.ToASCII` has no clock, configuration or
  I/O, so there is no staleness and no invalidation to get wrong. Negative results
  (`ok=false`) are equally pure and safe to retain.
- Footprint is bounded by construction — 1024 fixed slots, and `maxMemoHostLen` (253) gates
  **both** stored strings, which is the fix in `545452c` after CodeRabbit correctly showed
  the documented ceiling did not hold.
- Keys are cloned (`strings.Clone`), so an entry cannot pin a request header's backing
  array; the IP-literal branch shares the clone rather than allocating twice.
- Ordinary ASCII traffic returns from the fast path above the memo and never touches the
  table.
- Verified: `go test ./internal/hostutil` passes at this revision.

An independent check of PR #1612 found `golang.org/x/net/idna` **byte-identical** between
v0.60.0 and v0.61.0, so the exact-equivalence fast path in `NormalizeHostStrict` and its
differential test and fuzzer are unaffected by that bump.

### 4.2 The two-tier destination-authority bound (`proxy_host_bounds.go`)

The raw pre-cap (1 KiB) and the canonical cap (253) are applied at the entry points, with
`unnormalizableHostOversize` covering the band where normalization fails and the canonical
tier is unreachable. The hoist of `canonicalDestHost` above Stage-1 auth is value-preserving:
I confirmed by grep that **nothing** in the tree assigns `r.Host` on the request path, so the
value reused at the RISK-013 validity gate cannot have changed. `maxDestAuthorityLen` is
derivation-only (tests only). No gap found.

### 4.3 Policy default action is fail-closed by construction

`setDefaultPolicyAction` sets the allow bit only for the exact string `"allow"`, so every
other input — `""`, `"block"`, `"ALLOW"`, garbage — resolves to **deny**. That matters
because the config-version rollback path (`configversion.go:635`) and the cluster snapshot
path (`controlplane_snapshot.go:901`) both call it **unvalidated**, with a value taken
straight from a stored bundle or a CP snapshot. A legacy or hand-crafted bundle with an
empty `DefaultAction` therefore denies rather than opens the gateway. The zero value is
deny at revision 0. Fail-closed on every path; no finding.

`apiDefaultAction`'s POST branch validates strictly (`allow`/`deny` only), checks
`requireRole(RoleOperator)`, and audits **before** `saveConfigVersion` — the required order.
Its GET branch has no explicit `requireRole`, which is the recorded
`uiAuthMiddleware`-protected pattern documented in `ui_routes_meta.go`, not a gap.

### 4.4 Per-IP connection limiter held by value (in-flight #1625)

The pointer-to-value change is state-equivalent, and I checked the equivalence rather than
taking the commit message's word for it. A rejection requires `enabled && n > limit` with
`limit >= 1`, so `n >= 2`, so `conns[ip] >= 1` — the entry existed and the old code's
increment-then-undo restored it without deleting. Not writing it reaches the same state.
(It holds even at `limit == 0`: the old code would create, increment to 1, decrement to 0
and `delete`, leaving no entry — which is what not writing leaves.) `Release`'s single lock
hold is strictly better than the old three, and its `n <= 1` delete is exactly the old
"decrement reached <= 0" given that a present entry is always >= 1. The 64-byte shard
padding is unchanged (mutex 8 + map header 8). No regression.

### 4.5 Category-group ID index (in-flight #1619)

A second index that each write path must remember to patch is how an index comes to
disagree with its source, so every write path was enumerated: `New`, `Load`,
`restoreSnapshot`, `Add`, `Delete`, `DeleteByID` and `ReplaceAll` all rebuild wholesale.
`Rename`, `Update` and `UpdateByID` correctly do **not** need to, because `byID` aliases the
same `*Group` pointers and those three mutate in place without changing the ID or replacing
the pointer. No stale-index policy mismatch. (Pre-existing and unchanged: `GetByName`
returns the live `*Group` after releasing the lock, which a caller could read while `Update`
mutates it — noted, not introduced here.)

### 4.6 Request-log persistence gate (in-flight #1610)

The lock-free `persistRunning` gate preserves the enqueue semantics in both directions:
`startPersist` stores `true` **before** taking the mutex (so a sender seeing `true` with an
unpublished channel takes the mutex and returns on the nil, exactly as before) and
re-asserts **inside** the publishing critical section (so a `stopPersist` landing in that
window cannot leave a live channel behind a closed gate); `stopPersist` stores `false`
inside the section that nils the channel, and also on the `persistCh == nil` branch that
closes the one state `startPersist` can leave behind. No new lost-entry window. This is the
request log, not the admin audit log.

### 4.7 Mechanical sweeps with no finding

- **Weak crypto / RNG:** no `crypto/md5` or `crypto/sha1` outside `internal/totp`, where
  HMAC-SHA1 is mandated by RFC 6238 with a narrow documented `#nosec G505`. Every
  `math/rand` use is backoff/jitter/scheduling (`release_refresh.go`,
  `saas_feed_scheduler.go`, `ha_lease_recovery.go`, `internal/feedsched`,
  `internal/blocklist/hotread.go`); `store.go` aliases it as `mrand` precisely so `rand` in
  that file stays `crypto/rand`.
- **Timing-safe comparison:** secret comparisons use `subtle.ConstantTimeCompare`
  (`metrics.go`, `ha.go`, `internal/sealbox`, `internal/mcp/authn`, `internal/mcp/jose`).
  The one `!=` on a token (`ui_security.go`, CA-rotation confirmation) is not an
  authorization secret: it is a 128-bit single-use anti-fat-finger token, consumed and
  cleared before the comparison, 60-second expiry, behind `requireRole(RoleAdmin)` — an
  admin who reaches it can rotate anyway. One comparison per issued token means no timing
  oracle.
- **Archive extraction (zip-slip/traversal):** `restore.go` rejects absolute paths, any
  `".."`, duplicates and anything outside the `data/` namespace, skips symlinks, and adds a
  `filepath.Rel` containment check. `release_catalog_bundle.go` rejects non-regular entries
  and symlink/hardlink types and validates on `path.Clean`, which places any escaping `..`
  at the start where its prefix test catches it; an absolute entry is neutralized by
  `filepath.Join` into the staging dir. No traversal found.

### 4.8 In-flight change set — cluster, update and supply-chain PRs

Triaged with two independent parallel reviews; I verified the one finding myself and spot-checked
the reasoning on the rest. Reported as reviewed-and-safe, not as my own line-by-line re-derivation.

- **#1626 / #1618 / #1611 (cluster, CDR breaker, DP↔CP backoff):** no dropped auth, TLS,
  peer-identity or epoch check; no new endpoint; no `requireRole` removed; no block decision
  turned into an allow. Notably the CDR breaker change *removes* a fail-open (the half-open
  wedge where a liveness probe consumed the only half-open slot and the real `Sanitize` was
  then skipped per file, permanently), and the unenrolled-pull map bound prunes only entries
  already outside the rate window, so it is not a limiter bypass and not a revocation store.
- **#1614 / #1615 / #1605 (bootstrap registry override, release-catalog trust mode, release
  dispatch):** the registry override is only *narrowed*, and `registry_url` has no admin-API
  or UI writer at all — it is an on-disk operator file deliberately outside config
  versioning, so no runtime mutation endpoint exists or is added. `verifyMode` remains
  startup-only (set before `setReleaseManager` publishes, never mutated after) and the new
  diagnostics row is report-only behind `requireRole(RoleViewer)`, with enforce as the zero
  value — so break-glass no longer reports a fully green appliance. #1605 closes a
  false-success hole (an upgrade that never started answering `200 ok`) rather than opening
  one.

## 5. Finding SEC-TOOLCHAIN-1 (in-flight) — Dockerfile compiler bump without the `go.mod` pin

| | |
|---|---|
| **Severity** | MEDIUM — fails closed and cannot ship; the risk is in the remediation path |
| **Status** | OPEN on PR #1613, not on `main` |

PR #1613 bumps `Dockerfile` stages `builder` and `maintbuilder` to
`golang:1.27.0-alpine` while leaving `go.mod`'s `toolchain go1.26.9` and
`test/e2e/maint-agent/Dockerfile.e2e` at 1.26.9 — a three-way divergence between production
images, CI, and the E2E builder. I verified this directly against the PR head
(`3992bba`): only `Dockerfile` changes, by two lines.

It **fails closed**, and I verified the wall rather than assuming it: `Dockerfile:33-35`
compares `go env GOVERSION` to the `go.mod` toolchain and exits non-zero on mismatch, and
`toolchain_consistency_test.go:dockerToolchainViolations` independently flags every stage
whose pinned Go version differs from the `go.mod` pin. So no unqualified binary can ship
from this diff.

The risk is the remediation: clearing the red by relaxing the assertion, dropping
`ENV GOTOOLCHAIN=local`, or setting a workflow `GOTOOLCHAIN` would restore exactly the
incident this wall was built for (production images built by a compiler CI never ran the
suite under) — and `AGENTS.md` and `conventions.md` both forbid those. **Correct fix:** bump
`go.mod` `toolchain`, both `Dockerfile` stages and `Dockerfile.e2e` in one change.

## 6. Residual risk

1. **The pin does not fire when the CONNECT authority is an IP literal.** This is a
   deliberate scope limit, stated here rather than implied. A client that resolved the name
   itself legitimately CONNECTs to an address and names the origin in SNI and `Host` (`curl
   --resolve`, any client with its own resolver, and the shape this repository's own inspect
   harness models by passing `target` and `serverName` separately to `connectAndTLS`), so
   there is no name to compare and refusing would break supported traffic. **Consequence:** a
   deployment whose rules authorize a destination by IP or CIDR still gets no name-level
   enforcement on the inner request, exactly as before this change. A client can also reach
   that state deliberately by CONNECTing to an address — but doing so forfeits any
   name-based allow decision, so under a name-based default-deny policy it gains nothing.
2. **The real fix for (1) is to evaluate, not compare.** Re-running the rulebase, the
   decryption profile and the attribution against the inner host per inner request is what a
   mature SWG does and is what would close the IP case and make the attribution correct
   rather than merely consistent. That is a policy-engine change, not a gate, and is the
   recorded follow-up. This change closes the case that is both exploitable today and
   decidable at this seam: a tunnel authorized for a **name**, reused for a different name.
3. **Attribution is now consistent but still coarse.** A refused mismatch is logged, but an
   *allowed* inner request is still recorded under the CONNECT host. With the pin in place
   those are the same string, so the log is no longer wrong — but a deployment relying on
   per-URL attribution should read `LogFullURI`, not the host column.
4. **`#1626`'s crash containment is a genuine fail-closed→fail-contained direction change**
   (flagged by the cluster review, not independently re-derived): a panic mid-snapshot-apply
   now leaves a *blended* configuration for up to one poll interval instead of killing the
   process, and `markConfigSnapshotApplyRejected` is report-only. If the new generation
   tightens policy, the tightening is not enforced for that window. That is the stated
   CHAOS-24 containment trade applied repo-wide; recorded for the owner's call, not as a
   defect.
5. **Not run in this environment.** `golangci-lint` v2.5.0 is built with go1.25.1 and
   panics on this repo's go1.26 packages — including untouched files, which I confirmed — so
   the lint lane is **not run** here and belongs to CI. The frontend tree, the
   `cmd/culvert-maint` module, the `benchgate` lane, the sharded race lane with its
   privileged regression, and the coverage floors are likewise CI-owned and not run. Nine
   pre-existing IdP test failures on this revision (`TestIdPRegistry_*`, `TestAPIIdP*`) are
   environmental — the SSRF guard correctly rejects the loopback issuer URLs those tests
   use — and I confirmed they fail identically on unmodified `main`.
