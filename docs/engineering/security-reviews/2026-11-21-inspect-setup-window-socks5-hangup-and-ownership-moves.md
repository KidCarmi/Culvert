# Security Regression Review — inspect setup window, SOCKS5 hang-up cancellation, feed-alert latches, and seven ownership moves (window 060af5a → ef94311)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-11-21
> **Baseline:** `origin/main` @ `060af5a` ("docs(roadmap): record #1963 merge and the leaked IdP watchdog race", 2026-11-20 12:39)
> **Head:** `origin/main` @ `ef94311` (merge of #1991)
> **Scope reviewed:** every code-bearing change merged in the window — 146 files, +14,876 / −2,050,
> of which 67 are non-test production files. Grouped into four clusters: (1) data-plane
> lifetime bounds — the SSL-inspect setup window (CHAOS-125) and SOCKS5 connect-phase
> cancellation; (2) seven ownership moves into `internal/` (host pinning, cluster-CA validity,
> revocation-sync planning, scan-sidecar admission, MCP qualification inventory, keyed mutex,
> directory fsync) plus the hardened rotating-log open; (3) feed/health alert-latch and
> freshness reporting (threat feed, blocklist feed, ClamAV, CDR poller); (4) admin-plane
> disclosure and bounds (webhook URL redaction, webhook count cap, config-import validation,
> the new origin-verify operator row). Documentation-only commits were read for intent but not
> treated as attack surface.

---

## Executive Summary

**No CRITICAL, HIGH or MEDIUM security regressions were found.** The window is a net security
improvement on every axis it touches:

- The SSL-inspect **setup window is now bounded** (CHAOS-125). `net/http`'s `Hijack` clears the
  listener's `ReadTimeout`, so the origin TLS handshake, the client first-byte peek, the
  native leg's ClientHello peek and the forged-leaf handshake all ran with **no deadline at
  all** — 2 FDs and a goroutine per connection, holdable indefinitely by any client that
  completed CONNECT to an inspect-marked host and then went quiet, with `MaxConnsPerIP` off by
  default and no series counting them. Each leg now carries its own 30 s absolute window, and
  both are cleared the moment the tunnel is established.
- The **native-ALPN leg's silent-client branch is no longer silent**, and — the part that
  matters for posture — every way a client can stop short of an ALPN offer is now a
  *client-leg* outcome taken **before the origin is handshaked**, recorded through the ADR-0011
  taxonomy, and deliberately **not** routed to the auto-exclusion learner.
- The **SOCKS5 connect phase is cancellable**. The pre-flight SSRF guard (up to 10 s) and the
  upstream dial (10 s) ran under `context.Background()`, holding the handler goroutine, the
  client descriptor and the client's per-IP connection-limiter slot for ~20 s after the client
  had already left. Verdicts are unchanged: an undetermined destination still fails closed.
- The **audit/request log open refuses a symlink and a FIFO** at the log path
  (`O_NOFOLLOW|O_NONBLOCK` + `fstat` regular-file check), at both the startup open and the
  post-rotation reopen (CWE-59/CWE-61).
- **Feed-staleness alerts latch only on a dispatched page.** Previously the latch was taken
  before firing, so a node that went stale with no webhook configured — the default posture —
  spent its one page on nobody and never paged the operator who subscribed afterwards, while
  the gateway went on enforcing against stale intelligence.
- **Webhook URLs are redacted** to `scheme://host` for sub-operator readers and in the
  viewer-readable audit log (the URL is itself a bearer credential for most receivers), the
  store-wide 100-webhook cap is now enforced at **both** write ingresses, and `config/import`
  finally runs the same URL/event-name validation the admin API's create arm does.
- The **CDR health poller now arms on a runtime enable.** Before, a node that turned CDR on
  without a restart ran no health probes, **no client-certificate auto-renewal** and no
  server-pin rotation until it was restarted.

Two items are recorded below. **F1** is a widened fail-open window on a missing-deny path and
is the one worth scheduling. **F2** is a test-coverage gap on a newly reachable path, closed in
this change. Neither blocks a release.

### Verified-equivalent, not assumed: the seven ownership moves

Every move in this window was checked for behavioural drift rather than trusted. The predicate
bodies were compared line by line (and, for the MCP inventory, mechanically against the
pre-move file with only the documented renames normalised):

| Moved | To | Result |
| --- | --- | --- |
| `innerHostPinnedToTunnel` + bracket/wire-shape guards | `internal/hostpin` | identical: refusal order, empty-inner-host refusal, `PunycodeHostPort`/`ValidHostHeader` wire check, IP-literal tunnel skip |
| `clusterCAUsable`, kind classifier, remediation, `clampNodeCertValidity` | `internal/clusterca` | identical, including the deliberate STRICT `NotBefore` (no skew tolerance) and the error-wrapping shape |
| revocation-sync priority order, rotating window, wire envelope | `internal/session/revsync` | identical; `node_id`/`entries` JSON contract preserved; `Cursor.Active()` is the former `set` field |
| scan-sidecar admission semaphore | `internal/secscan/sidecargate` | identical two-select acquire, 5 s queue wait, gauge-before-slot release order, 2…32 slot clamp over a 256 MiB budget |
| MCP qualification inventory (11 functions) | `internal/mcp/qualinventory` | byte-identical after renames; `MaxFileBytes` = 1 MiB and `schemaVersion` = 1 unchanged; `VerifyVerified` gate and `validateRouteSafeSegment` intact |
| per-key mutex | `internal/keyedmutex` | identical refcount/GC logic; CDR lifecycle serialization preserved at all call sites |
| directory-fsync rule | `internal/fileutil.SyncDir` | identical, and pinned by a differential test against frozen copies of **both** former callers across ~196 (sync, close) outcome pairs |
| floor/activation/authority record seal | `internal/urlcatfeed/noderecord` | identical canonical bytes (same encoder, HTML-escaping off, newline stripped) and CRC-32C; timestamp and digest grammars now bind the feed protocol's own validators |

No move changed a trust decision, an error sentinel observable by `errors.Is`, a wire or
on-disk encoding, or a concurrency contract.

---

## Security Findings

### F1 — LOW/MEDIUM · Chunked blocklist merge widens an existing missing-deny window against a concurrent hot reload

| | |
| --- | --- |
| **File** | `internal/blocklist/blocklist.go:964` (`MergeFromLines`), `:1003` (`mergePending`), `:200-220` (`Load`) |
| **CWE** | CWE-367 (TOCTOU), CWE-754 (improper check of unusual condition) |
| **OWASP** | A04:2021 Insecure Design |
| **Severity** | Low → Medium (depends on feed size and reload frequency) |
| **Regression risk** | Pre-existing failure class, **materially widened window** |
| **Affected assets** | Blocklist enforcement (`bl.IsBlocked`) for feed-sourced hosts, on the HTTP/CONNECT and SOCKS5 paths |

**What changed.** `MergeFromLines` used to hold the write lock across parse + decide + apply.
It now decides under the cold read lock (`mergePending`, which **drops** every entry the store
already holds with the right attribution) and applies the remainder in 1024-entry write-lock
holds. This is a deliberate and well-reasoned stall fix (PERF-BLOCKLIST-MERGE-1): the write
lock excludes every `IsBlocked`, so its hold time is paid by every request in flight.

**Attack scenario / failure scenario.** Not attacker-initiated; an operational race.

1. The feed syncer calls `MergeFromLines` with up to `maxFeedLines` (1 M) entries. The filter
   pass runs for hundreds of milliseconds under the read lock.
2. Concurrently, a config hot reload (`applyHotReload`, `main.go:1779`) calls `bl.Load(path)`,
   which replaces `exact`, `wildcards`, `manual` and `feedSrc` **wholesale** from the on-disk
   file under the write lock.
3. Entries the filter pass had already dropped — because they were present in the *pre-`Load`*
   maps — are not re-added. With `added == 0 && !attributed`, **no `Save()` runs**, so the
   loss is not repaired on disk either.
4. Those feed hosts stay **unenforced** until the next successful sync (configured interval,
   typically 12–24 h).

**Preconditions.** A runtime hot reload landing inside a feed merge, with the on-disk blocklist
behind in-memory state. **Exploitability:** low — an unauthenticated attacker cannot trigger
the reload; an operator doing a routine reload can hit it by accident. **Likelihood:** low per
reload, rising with feed size and reload frequency. **Impact:** a block list silently stops
blocking a subset of hosts for up to a sync interval, with no alert and no log line.

**Why this is not a new failure class.** The pre-diff code had the same loss reachable in the
narrower window between the merge's `Unlock` and its `Save()`. `ReplaceFeedEntries`
(`controlplane_snapshot.go:1511`) has the identical pre-existing shape. The change does not
create the class; it widens the window from microseconds to the duration of a full filter pass.

**Recommended fix (safe implementation).** The same episode-generation trick this very window
applied to the alert latches: keep a generation counter on `Store`, bumped under the write lock
by `Load` and `ReplaceFeedEntries`; have `MergeFromLines` record it before `mergePending` and,
if it has changed once the apply phase finishes, re-run the merge **once** against the
unfiltered entry list. The steady state (no map replacement) pays nothing, so the performance
contract this change exists to satisfy is preserved. **Deliberately not implemented here:**
this is a runtime-behaviour change on a security hot path with its own performance contract and
differential oracle (`internal/blocklist/merge_stall_test.go`), and belongs with the owner.

**Required tests.** Positive: an unchanged re-sync still takes no write lock and still saves
nothing. Negative: an entry present only in memory survives a `Load` interleaved mid-filter.
Regression: the differential oracle against the single-hold body still holds. Boundary: empty
input, a single entry, exactly `mergeChunk`, `mergeChunk + 1`. Concurrency: `-race` with a
`Load` goroutine and a `ReplaceFeedEntries` goroutine racing a 1 M-line merge, asserting the
union of entries is enforced afterwards. Malformed input: lines that `NormalizeLine` rejects
must not shift the chunk boundaries.

---

### F2 — LOW (closed in this change) · The CHAOS-125 setup deadline made a new client-leg error reachable at the auto-exclusion learner, with no negative control

| | |
| --- | --- |
| **File** | `proxy_tunnel.go:1042` (arm), `proxy_tunnel.go:~1079` (client-handshake failure → `maybeFailOpenClient`), `autoexclude_resolve.go:164` (`classifyClientInspectFailure`) |
| **CWE** | CWE-1123 (excessive reliance on global variable / implicit contract), CWE-693 (protection mechanism failure) — as a latent gap |
| **OWASP** | A04:2021 Insecure Design |
| **Severity** | Low (not currently exploitable) |
| **Regression risk** | Medium — the guard is incidental, not asserted |
| **Affected assets** | Per-host SSL-inspection coverage under a fail-open decryption profile |

**What changed.** CHAOS-125 arms `sslInspectSetupTimeout` on the hijacked client leg, which now
bounds the forged-leaf handshake. The strip path's client-handshake failure site calls
`maybeFailOpenClient`, which learns an auto-exclusion for the host. Before CHAOS-125 a client
that completed CONNECT and then stalled mid-handshake hung forever and produced **no error**,
so that site was never reached for it; now the window expires and the site runs.

**Why it matters.** The same round explicitly **refused** to consult the learner on its two
sibling client-leg failures, and said why: *"learning an auto-exclusion from a client-side
stall would let anything able to open a CONNECT and go quiet TEACH the gateway to stop
inspecting the host on the next connection."* On the strip path's handshake site the only thing
standing between a deliberate stall and a learned inspection bypass is that
`classifyClientInspectFailure`'s substring set happens not to match a timeout.

**Measured, not argued.** A `tls.Server` handshake whose conn deadline expires before the
ClientHello arrives returns the underlying read's `*net.OpError` wrapping
`os.ErrDeadlineExceeded` — `read tcp <local>-><remote>: i/o timeout`. That matches none of
`bad certificate`, `unknown certificate authority`, `unknown ca`, `certificate expired`,
`certificate unknown`, `certificate revoked`, so `learn == false`. **Safe today.** ADR-0008 is
a second barrier: unauthenticated `client_pinned` evidence yields an empty token the learner
discards, so promotion would additionally need two distinct *authenticated* identities.

**The gap.** Nothing pinned it. `TestClassifyClientInspectFailure`'s negative controls are
`connection reset by peer`, `access denied` and `handshake failure` — all pre-CHAOS-125 shapes,
none a deadline expiry. Widening the classifier (adding `timeout`, or a generic `handshake`
catch-all) would convert a client-chosen stall into a per-host inspection opt-out and ship
green.

**Fix applied.** `autoexclude_setup_deadline_learn_test.go` adds the missing negative control at
both levels — the classifier and `maybeFailOpenClient` itself — under the only profile that can
learn (fail-open), at the weakest promotion bar (`ConfirmN=1`), with an **authenticated**
identity so ADR-0008's evidence gate is not what carries the test. Each test carries a positive
control so it cannot pass vacuously. Verified by mutation: adding `"i/o timeout"` to the
classifier's substring set fails the test on four of five fixtures.

---

## Regression Analysis

Checked, and found not to regress:

- **Authentication / authorization.** No `requireRole` check was removed or weakened. The one
  role-sensitive change is strictly tightening: `GET /api/alerts/webhooks` still requires
  `RoleViewer`, but below operator the URL is reduced to its origin. `alerts.Store.List()`
  returns value copies, so the redacting reader cannot corrupt stored state — confirmed at
  `internal/alerts/store.go:716`. `CULVERT_AUTHBYPASS_DISABLE` is documented in this window but
  not changed; its implementation matches the new README text, including forcing an *Open*
  default to auth-required, and the no-backend case fails closed rather than skipping the gate.
- **Fail-closed behaviour.** SOCKS5 still refuses an undetermined destination without dialing;
  the guard and the dial now share one cancellable context, so a cancellation cannot skip the
  guard and still reach a dial. A demonstrated private destination (`ssrf.ErrBlocked`) is
  **always** recorded, even if the client left in the same instant. Scan-sidecar capacity still
  answers 429, which `internal/secscan` classifies as fail-**closed**.
- **SSRF.** Every guard remains inline at the call site. `isPrivateHostBounded` + `ssrfControl`
  on the inspect dial and the SOCKS5 dial are unchanged; the blocklist feed fetch keeps
  `url.Parse` → scheme check → `ssrf.PrivateHost` before `client.Do`.
- **Request smuggling / desync / host-header.** The inner-host pin's refusal set is byte-identical
  after the move and its contract test passes. `peekClientALPN`'s new oversize branch fills the
  buffered window exactly as the former `Peek(5+recLen)` did (`bufio` reports an oversized peek
  as `ErrBufferFull` after filling), so no new ALPN decision is reachable — only a read failure
  during the fill is now attributed to the client instead of silently downgrading.
- **Audit integrity.** The cluster audit log became a true fixed-capacity ring. Window
  semantics verified by hand: `start = (head - n + maxSize) % maxSize` is always in range
  because `n ≤ live ≤ maxSize`, the two bulk copies cover the single wrap, order stays
  oldest-first, `maxSize <= 0` disables the log instead of panicking, and an oversized batch
  writes only its surviving tail. No mutation lost an `auditEvent`; the CDR toggle keeps its
  recorded `saveConfigVersion` exclusion.
- **Log injection (CWE-117).** Every new log line either carries only static text and locally
  computed counts, or wraps its untrusted value in `sanitizeLog` with `%q`. The truncation log
  line in `internal/blocklistfeed` **dropped** the token-bearing feed URL, and
  `alerts.deliveryErrText` now strips the full request URL out of `*url.Error` text, which
  previously reached both the process log and the viewer-readable delivery history.
- **Unsafe file writes / symlink / TOCTOU.** `scripts/install.sh` replaces `sudo touch` with
  `sudo sh -c 'umask 077 && set -C && : > "$1"' sh "$file"` — `O_CREAT|O_EXCL` at mode 0600,
  which refuses a planted symlink (dangling or live) instead of creating its target as root,
  and does not truncate a file a concurrent installer already filled. `$file` is passed as `$1`,
  never interpolated. The residual same-instant swap race on the following `sudo chown` is
  unchanged and is the recorded SEC-INSTALL-ENVLINK-1 owner decision. The second hunk adds
  `umask 077` inside the `flock` subshell, covering the `.tmp.$$` fallback that holds a copy of
  every existing secret.
- **DoS / memory exhaustion / amplification.** Three bounds added (inspect setup window,
  webhook count cap at both ingresses, cluster-audit ring), none removed. The only new
  allocation is the bounded one in F1.
- **Races.** `-race` green on the new concurrency: the SOCKS5 hang-up watcher, the cluster-audit
  ring, and the alert latches. The watcher's `stop()` sets an expired read deadline, joins the
  goroutine, then restores the deadline, so the handler is provably the only reader of `conn`
  afterwards and no client byte is dropped — a byte the watcher read is handed back and written
  to the destination ahead of the relay. All SOCKS5 reads go directly to `conn` (no `bufio`), so
  nothing is stranded. `latchOncePerEpisodeOnDelivery`'s `delivered` callback runs under the
  plane's lock but only probes the lock-free subscription index and hands delivery to a
  goroutine, so there is no lock cycle.
- **Certificate validation / MITM.** `clusterca.Usable` keeps the strict `NotBefore` check and
  the expiry-vs-clock-fault distinction; `clampNodeCertValidity` still pins a node leaf inside
  its issuer's window. The new `ssl_inspect_upstream_verify` operator row is report-only and
  asks the **same** `resolveInspectSkipVerify` the tunnel path uses, so it cannot disagree with
  what a session would do; it surfaces the previously invisible case of a rule that skips origin
  verification through its decryption profile. Viewer-visible and counts-only — no rule or
  profile names.
- **Secret exposure.** Webhook URL redaction (above) plus `URLOrigin` dropping userinfo, path
  and query. The deferred GeoIP load writes nothing and creates no configuration version.

---

## Attack Scenarios Specifically Tested and Found Closed

1. **Hold two FDs and a goroutine per connection, unbounded** — CONNECT to an inspect-marked
   host, read the 200, send nothing. Now bounded at 30 s per leg.
2. **Teach the gateway to stop inspecting a host by going quiet** — stall the forged-leaf
   handshake under a fail-open profile. Refused: the timeout is not a learnable signal
   (F2, now pinned by test), and ADR-0008 discards unauthenticated evidence anyway.
3. **Turn an inspect rule into a bypass by sending a non-TLS first byte** — refused on both
   the strip and native legs, and the learner is not consulted.
4. **Redirect the audit log through a symlink at its path** — refused by `O_NOFOLLOW`, at both
   the startup open and the post-rotation reopen; the archived `.1` survives.
5. **Block the startup path on a FIFO at the log path** — `O_NONBLOCK` returns at once with no
   reader; the `fstat` regular-file check refuses the FIFO that *does* have a reader.
6. **Read a webhook's bearer-token URL as a viewer** — now origin-only, in both the API listing
   and the audit log.
7. **Suppress an SSRF-block request-log row by hanging up during the SOCKS5 pre-flight** — a
   demonstrated private destination is recorded regardless. See Residual Risk.
8. **Create a root-owned file anywhere via the installer's env write** — refused by
   `O_CREAT|O_EXCL`.

---

## Files

Reviewed in full (non-test production files, 67): `alerts.go`, `background_services_startup.go`,
`blocklist_feed_health.go`, `cdr_health.go`, `cdr_lineage.go`, `cdr_startup.go`, `cdr_ui.go`,
`clamav_signature_freshness.go`, `cluster_ca_validity.go`, `contracts/registry.yaml`,
`controlplane.go`, `diagnostics.go`, `diagnostics_cdr_client_cert.go`,
`diagnostics_inspect_upstream_verify.go`, `geoip_database_health.go`, `geoip_load_retry.go`,
`geoip_startup.go`, `inspect_host_pin.go`, `internal/alerts/store.go`,
`internal/blocklist/blocklist.go`, `internal/blocklistfeed/blocklistfeed.go`,
`internal/clusterca/{doc,validity}.go`, `internal/fileutil/{fileutil,rotating,rotating_open_other,rotating_open_unix,syncdir}.go`,
`internal/geoip/{deferred,geoip}.go`, `internal/geoip/geoiptest/mmdb.go`,
`internal/hostpin/{doc,pin}.go`, `internal/keyedmutex/{doc,keyedmutex}.go`,
`internal/mcp/catalog/provenance.go`, `internal/mcp/qualinventory/{doc,inventory}.go`,
`internal/secscan/sidecargate/{doc,gate}.go`, `internal/session/revsync/{doc,revsync}.go`,
`internal/urlcatfeed/{jsonstrict,verify}.go`, `internal/urlcatfeed/noderecord/{doc,record}.go`,
`mcp_inventory.go`, `mcp_live_production_deps.go`, `packaging/culvert-maint/install.sh`,
`proxy_tunnel.go`, `proxy_tunnel_h2.go`, `revocation_sync_budget.go`,
`saas_feed_{activation,authority,floor,gc,genstore}.go`, `scan_svc.go`, `scan_svc_admission.go`,
`scripts/install.sh`, `socks5.go`, `socks5_hangup.go`, `support_durable_write.go`,
`threatfeed_health.go`, `ui_config.go`, `ui_security.go`.

Added by this review: `autoexclude_setup_deadline_learn_test.go`.

---

## Verification

Run against the reviewed head (`ef94311`) with the `go.mod` toolchain (`go1.27.4`):

| Check | Result |
| --- | --- |
| `go build ./...` | clean |
| `go test ./...` | **130 packages ok, 0 failures** (exit 0) |
| `go test .` (root package, with this review's added test) | ok, 456 s |
| `go test ./internal/{hostpin,clusterca,session/revsync,secscan/sidecargate,keyedmutex,fileutil,urlcatfeed/...,mcp/qualinventory,alerts,geoip,blocklist,blocklistfeed}` | ok |
| `go test -race -run 'SOCKS5\|Hangup\|ClusterAudit\|InspectSetup\|CHAOS125\|Latch\|ThreatFeed\|BlocklistFeed\|Webhook\|ConfigImport' .` | ok |
| The six contracts `contractcheck impact` flags for this window (SWG-001/002/901, TLS-001/002/900) — their pinned tests | all pass |
| `go run ./cmd/contractcheck validate` | 36 contracts sound |
| `python3 docs/agent-context/check.py` | exit 0 |
| Mutation check on the new guard (add `"i/o timeout"` to `classifyClientInspectFailure`) | fails as intended, then reverted |

**Not run, and why:** `golangci-lint` was not run — the container's binary is older than this
module's language version and refuses it; the gate's own pinned version must be installed with
the `go.mod` toolchain, which this review did not do. This review is **not** a hosted CI or
merge-gate result.

---

## Residual Risk

1. **F1 remains open** — a concurrent hot reload during a large feed merge can leave feed hosts
   unenforced until the next sync, without an alert. Fix proposed above; owner decision.
2. **SOCKS5 request-log row for an undecided pre-flight.** When the client hangs up while the
   SSRF pre-flight is still undecided (a DNS failure or a cancelled lookup — **not** a
   demonstrated private address), the `BLOCKED` request-log row is now waived; a process log
   line still records it. The destination was never contacted and nothing was decided about it,
   and a genuine private destination is always recorded, so this is weak as an evasion
   primitive — the attacker also gets no reply, so learns nothing. Accepted, deliberate, and
   documented at the call site.
3. **Pre-existing CWE-117 asymmetry, not introduced here.** `internal/alerts/store.go:1235`
   logs `h.Name` without `obs.Sanitize`, while the sibling line four lines up sanitizes it. The
   diff edited this line (narrowing the *other* half of the payload) without closing the
   asymmetry. `h.Name` is operator-supplied rather than remote, so severity is low. One-line
   follow-up.
4. **`internal/geoip/deferred.go:115` exports `ResetForTest()` from a production file**, an
   exported mutator of security-relevant state (it unloads the database and clears the cache).
   It matches an existing repo pattern (`internal/reqlog`, `internal/audit`) and is unreachable
   from any handler or wiring, so it is not exploitable — but root `AGENTS.md` discourages
   exporting mutable internals for tests. Consider a build tag.
5. **Non-Unix builds keep the old log-open behaviour.** `rotating_open_other.go` degrades
   `O_NOFOLLOW`/`O_NONBLOCK` to 0, so only the regular-file check applies there. Culvert ships
   as a Linux appliance and those builds are compile/CLI convenience targets; recorded in the
   file.
6. **The inspect setup window is a var, not configurable.** 30 s is the listener's own
   `ReadTimeout` restored to the socket for the window `Hijack` cleared it for. Recorded as a
   deliberate deferral — it is a security boundary, not an operator setting.
