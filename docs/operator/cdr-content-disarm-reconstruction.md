# Content Disarm & Reconstruction (CDR)

Culvert's CDR stage sends files passing through SSL-inspected traffic to
**Sluice**, a separate CDR microservice (gRPC + mTLS), which strips active
content (macros, embedded OLE objects, PDF JavaScript/launch actions, etc.)
and returns a sanitized file. CDR runs **after** file-type/extension
checks and **before** ClamAV/YARA scanning in the inspect pipeline. Manage it
via `/api/cdr/*`, or from the GUI: the default admin UI's **CDR** panel
(`data-view="cdr"`, nav item gated at the **operator** role) or, when the
experimental new frontend is armed (`CULVERT_EXPERIMENTAL_UI`), **Security →
CDR Integration** at `/app/security/cdr` (nav item gated at **viewer**,
matching the API's own read RBAC). The underlying `GET` endpoints always
accept **viewer** regardless of which nav gate a given UI applies (see **API
reference** below).

Sluice is a standalone project (`github.com/KidCarmi/Sluice`) that Culvert
talks to as a client — it is not bundled into the Culvert binary or image.
Sluice must be deployed and reachable (typically as a Docker sidecar) before
CDR can be enabled. See `roadmap/SLUICE-CDR-HANDOFF.md` for the Sluice-side
protocol and deployment shape; this page covers only the Culvert-side
integration an operator manages.

**Disabled by default.** With no configuration, no gRPC dial happens and the
inspect pipeline is byte-identical to a build with CDR compiled out.

## Enabling it

Two ways to turn CDR on, and either one is enough — you do not need both:

1. **Config file / CLI flags**, then restart. Config-file values are
   overridden by CLI flags when both are set — **except `-cdr-enabled`,
   which can only force CDR ON, never off.** `resolveCDRStartupConfig`
   only assigns `cfg.Enabled = true` when the boolean flag is `true`; it
   never assigns `false`, so `-cdr-enabled=false` (or simply omitting the
   flag) cannot override `cdr.enabled: true` in `config.yaml` — the config
   file value wins. To disable CDR via the static config, remove/set
   `cdr.enabled: false` in `config.yaml` itself; don't rely on the CLI flag
   to turn it off.

   | CLI flag | `config.yaml` key | Meaning | Default |
   |---|---|---|---|
   | `-cdr-enabled` | `cdr.enabled` | Turn the CDR stage on | `false` |
   | `-cdr-endpoint` | `cdr.endpoint` | Sluice gRPC address, `host:port` (e.g. `sluice:8443`) | — |
   | `-cdr-default-profile` | `cdr.default_profile` | Sanitization profile sent when no CDR policy rule matches; must name a profile Sluice's `Health` RPC advertises | `default` |
   | `-cdr-default-mode` | `cdr.default_mode` | Mode sent when no rule matches: `ENFORCE`, `REPORT_ONLY`, or `BYPASS_WITH_REPORT` | `ENFORCE` |
   | `-cdr-timeout-sec` | `cdr.timeout_sec` | Per-file deadline; must be ≥ 30 (Sluice's own cap is 30s — Culvert adds 5s so its own timeout fires last) | 35 |
   | `-cdr-max-file-size-mb` | `cdr.max_file_size_mb` | Skip CDR (no RPC) for a buffered body larger than this | 50 |
   | `-cdr-server-fingerprint` | `cdr.server_fingerprint` | TOFU-pinned SHA-256 of Sluice's server certificate (hex; `sha256:` prefix optional) | — |
   | `-cdr-certs-dir` | `cdr.certs_dir` | Directory holding the Sluice mTLS client bundle (`ca.pem`, `client.pem`, `client.key`) | — |
   | `-cdr-fail-mode` | `cdr.fail_mode` | Behavior when Sluice is unreachable: `open` or `closed` (see **Failure behavior** below); an invalid value is a fatal boot error | `open` |

   `-cdr-endpoint` by itself dials nothing. The config/CLI-only bootstrap
   path (no instance ever enrolled through the API) requires **all three**
   of `-cdr-enabled` (or the runtime sentinel), `-cdr-endpoint`, and
   `-cdr-server-fingerprint` — `loadCDR` skips client init entirely while
   `Enabled` is false, and `bootstrapPoolFromConfig` itself refuses to dial
   when either `Endpoint` or `ServerFingerprint` is empty. Configuring only
   the endpoint silently leaves CDR with no client. Those three values are
   still **bootstrap-only**: without `-cdr-certs-dir` pointing at a
   provisioned client bundle (`ca.pem`, `client.pem`, `client.key`),
   `buildCDRTLSConfig` presents no client certificate, so the pool holds an
   apparently active client whose `Sanitize` calls fail Sluice's mTLS check —
   and under the default `fail_mode: open` every eligible file is then
   delivered unchanged. Operational sanitization on this path requires the
   client bundle as well. This bootstrap path also
   has no certificate lifecycle automation — see **Certificate lifecycle**
   below before relying on it long-term.

2. **GUI enrollment**, no restart or config-file edit required: open
   **CDR → Enroll new Sluice instance**, paste the one-time enrollment token
   Sluice printed on first boot plus its server-certificate fingerprint.
   `POST /api/cdr/instances/enroll` exchanges the token for mTLS client
   credentials via Sluice's `Enroll` RPC, persists them, and **enables CDR
   automatically** — enrolling your first instance is a complete on-switch by
   itself. `PUT /api/cdr/config` (`{"enabled": true|false}`) is the plain
   runtime toggle for an already-enrolled deployment; `true` writes the
   enable sentinel at `<dataDir>/cdr_enabled` and `false` removes it, and
   either way the connection pool starts/stops immediately.

   > **This is the common case, and it runs on a zero-valued config.** CDR
   > ships disabled, so `loadCDR` never calls `initCDRClient` at boot and
   > `cdrActiveCfg` is never populated with your resolved `cdr.*`
   > config/CLI settings — it stays at its Go zero value. The FIRST runtime
   > enable, whether via this auto-enable-on-enroll path or a bare
   > `PUT {"enabled": true}`, only ever calls `setCDREnabledRuntime(true)`
   > (which flips the `Enabled` field on whatever `cdrActiveCfg` currently
   > holds) before `initCDRClient` builds the pool from it — so on a node
   > that has never had CDR enabled at boot, the pool comes up with
   > `fail_mode` unset (fail-**open**), no default profile/mode, and a zero
   > timeout/size cap, regardless of what you'd set in `config.yaml`/CLI
   > flags. `GET /api/cdr/config` after enrolling will show these as empty/
   > zero if this is your first enable. If you need non-default `cdr.*`
   > settings (especially `fail_mode: closed`), either start the process
   > with `-cdr-enabled`/`cdr.enabled: true` from the very first boot, or
   > restart once after your first GUI enrollment so `loadCDR` re-resolves
   > the full static config with CDR already enabled.

> **Scan-engine gate.** Enrollment turns CDR on, but CDR only runs on a
> response body that the SSL-inspection path has decided to buffer.
> `scanInspectBody` returns before `runCDRStage` whenever
> `bodyNeedsBuffering` is false, and that predicate (`security_scan.go`)
> considers only the remote scan service, text DPI, and ClamAV/YARA body
> scanning — **not CDR**. On a node where none of those body scanners is
> enabled, eligible SSL-inspected files are forwarded without ever calling
> Sluice, with no counter or log line. Enable at least one body-scanning
> engine (or the remote scan service) alongside CDR.
>
> The same function has a second, unconditional gate ahead of it: a host
> entered in **Security Scan → Exclusions** (`globalScanExclusions`) skips
> `scanInspectBody` entirely, so it bypasses CDR too — even with a body
> scanner enabled and a matching CDR policy rule. A scan exclusion is not
> scoped to AV/DPI only; treat it as an exclusion from CDR as well.

   **The sentinel can only force CDR *on*, never *off*, across a restart.**
   At boot, `loadCDR` starts from the static `cdr.enabled` value (config
   file / `-cdr-enabled`) and then forces it to `true` if the sentinel file
   is present — it never forces it to `false`. If `cdr.enabled: true` (or
   `-cdr-enabled`) is still set in your static config, a `PUT
   {"enabled": false}` disables CDR only until the next restart, at which
   point the static value wins again and CDR silently comes back on. To
   disable CDR durably, remove `-cdr-enabled` / `cdr.enabled: true` from the
   static config as well as toggling it off at runtime.

The enrolled-instance registry (names, endpoints, paths, health/breaker
state — **not** credential material) is tracked at
`<dataDir>/cdr_instances.json`; CDR policy rules are tracked at
`<dataDir>/cdr_policies.json`; enrollment recovery state (identifiable
unknown-outcome receipts) is tracked separately at
`<dataDir>/cdr_enroll_receipts.json`. All three are loaded unconditionally
(even while CDR is disabled) so a GUI enrollment done before enabling still
persists. The actual client credential bundle — CA cert, client cert, and
client key — lives under `<dataDir>/integrations/sluice/<name>/` and is
loaded lazily when the pool dials, not by `loadCDR`'s unconditional stores;
it is also deliberately excluded from `--backup` (see the Cluster note
below and `key-at-rest.md`). **`--backup` only ever retains
`cdr_policies.json`** — `defaultBackupArtifacts` deliberately omits
`cdr_instances.json` (a restored registry entry would be inert without its
credential bundle and can't simply be re-enrolled under the same name,
since enrollment refuses a name already present), `cdr_enroll_receipts.json`,
the `<dataDir>/cdr_enabled` runtime sentinel, and the credential directory
itself. A restore onto a fresh volume/host keeps your CDR policy rules but
loses the enrollment registry, credential/revocation lineage, recovery
receipts, and the runtime enable state — plan to re-enroll every instance
and re-toggle CDR on after a restore.

**Cluster note:** CDR is deliberately **not** part of the CP→DP
`ConfigSnapshot`, the config-version rollback surface, or config
export/import. Enrollment, policy rules, and the enable toggle are per-node
state — each node that terminates inspected TLS and needs CDR must be
enrolled with Sluice separately. (Client-key material at rest is covered
by the shared key-at-rest mechanism — see `key-at-rest.md`, `cdr-client`
key class.)

## Failure behavior

**`fail_mode=closed` only protects a request that reaches a live Sluice RPC
call — it does NOT protect a request when no client is available at all.**
Two distinct gates exist, and only the second one consults `cdr.fail_mode`:

1. **No client to call.** `NewCDRClient` dials with `grpc.NewClient`, which is
   **non-blocking** (lazy connect) — a client is added to the pool whether or
   not Sluice is actually reachable, and the post-init `warmupCDRClient` probe
   only logs on failure, it never removes the client. So an unreachable
   Sluice at boot does **not** leave `cdrActiveClient()` nil: the first
   eligible requests DO reach a live RPC attempt (gate 2 below, which honors
   `fail_mode`) and fail there, and only after enough consecutive failures
   open that instance's breaker does this gate start applying. This gate is
   reached only when the pool is genuinely empty — no instance was ever
   enrolled/configured, every enrolled instance's certificate bundle failed
   to load (so `buildCDRPoolFromRegistry` never added it — see **Multi-instance
   pool** below), or CDR was toggled off (`shutdownCDRClient` empties the
   pool) — or once every instance's circuit breaker is open. In any of those
   cases the request **passes through unsanitized unconditionally**,
   regardless of `fail_mode`. This path does not increment
   `culvert_cdr_fail_open_total`/`_fail_closed_total` and emits no per-request
   log line or request-log event — it is silent at the request level. The only way
   to notice it is happening is the pool/health surfaces themselves:
   `GET /api/cdr/health`, `culvert_cdr_instance_healthy`, and the per-instance
   `culvert_cdr_pool_breaker_state` (see **Multi-instance pool** below). A
   deployment relying on `closed` for a hard security guarantee must monitor
   these and alert on "no healthy instance" as its own outage condition —
   `fail_mode=closed` alone will **not** block traffic during a total Sluice
   outage.
2. **A live RPC call fails**, once a client was actually reached:

   | Outcome | `open` (default) | `closed` |
   |---|---|---|
   | Sluice unreachable mid-call / times out / returns `ERROR` | Original file passes through unchanged; `CDR_ERROR` request-log event + log line; `culvert_cdr_fail_open_total` | Delivery refused (block page); `culvert_cdr_fail_closed_total` |
   | Sluice returns `BLOCKED` (file is unsalvageable) | Delivery refused (block page) — **always**, regardless of `fail_mode` | same |
   | A panic anywhere in the CDR call path | Delivery refused (block page) — **always fail-closed**, regardless of `fail_mode` (`culvert_cdr_panics_total`) | same |
   | File exceeds `cdr.max_file_size_mb` | Skipped client-side before any bytes reach Sluice (`culvert_cdr_oversize_skipped_total`) — original file continues down the pipeline unsanitized | same |

   `fail_mode` only governs *transport/availability* failures reached this
   way. A `BLOCKED` verdict or an internal panic is never passed through, no
   matter how `fail_mode` is set — those are content decisions, not
   availability ones.

**`cdr.max_file_size_mb` is not a whole-file guarantee, because CDR never
sees the whole file for a large download in the first place.** On the
SSL-inspect path (the only path CDR runs on), the response body is first
buffered up to the shared DPI/content-scan window
(`security_scan.max_scan_mb`, a few MiB by default — see
`scan-capacity-and-timeouts.md`) *before* CDR (or ClamAV/YARA/DPI) ever sees
it; whatever comes after that window is relayed to the client as-is, with no
scanning of any kind. So for an ordinary large download, `cdr.max_file_size_mb`
being larger than the scan window buys nothing — CDR is comparing against a
prefix that was already capped upstream, and the untouched remainder ships
unsanitized regardless of what `cdr.max_file_size_mb` says. Raising
`cdr.max_file_size_mb` does not make CDR see more of a large file; raising
`security_scan.max_scan_mb` does, at the cost of buffering more of every
inspected response in memory.

Per-request outcomes are also gated by the CDR policy rule's own **Mode**
(`ENFORCE` strips and delivers the sanitized file; `REPORT_ONLY` detects and
logs but delivers the original bytes; `BYPASS_WITH_REPORT` is a VIP carve-out
— report threats, still deliver the original). An invalid mode is normally
**rejected, not defaulted**: with `cdr.enabled: true`, an invalid
`cdr.default_mode` fails config validation and stops startup, and
creating a CDR policy rule with an invalid mode is refused by the API. Only
an unchecked value that nonetheless reaches the mode normalizer falls back to
`ENFORCE` (the safer choice over `REPORT_ONLY`, which would let active
content through).

**Only non-sanitized verdicts are cached** — `CLEAN`, `UNSUPPORTED`, and
`BLOCKED` results are cached by SHA-256 of the file body for up to one hour
or 10,000 entries (`culvert_cdr_cache_hits_total` / `_cache_misses_total` /
`_cache_size`), invalidated whenever the CDR policy rule set changes. A
`SANITIZED` result is **not** cached — the reconstructed bytes aren't
retained, so an identical file that previously needed sanitizing is sent to
Sluice again on every request. Size Sluice capacity for repeat traffic in
active `ENFORCE` sanitization accordingly; the cache only saves RPCs for
files that turn out clean, unsupported, or blocked.

**The cache key is the file hash alone — it does not include the matched
policy profile or mode.** `safeCDRSanitize` evaluates the request's policy
profile and mode first and stores both on the cache entry for display, but
`cdrCacheLookup` looks entries up by SHA-256 hash + policy epoch only. So a
verdict cached under one rule's profile+mode is reused verbatim for a later
request that matches a *different* rule for the same bytes — whether that
rule selects a different, less strict profile, or the **same** profile
under a different mode (e.g. one rule runs it `ENFORCE`, another
`REPORT_ONLY`/`BYPASS_WITH_REPORT` for a different source/destination
match). In the latter case an `ENFORCE`-cached `BLOCKED` verdict can still
block a later request that matched a bypass/report-only rule, or a
report-only-cached verdict can silently skip enforcement it should have
applied. This affects any deployment with more than one CDR policy rule
that can see the same file bytes under different profiles or modes — not
just multi-profile setups.

## Multi-instance pool and circuit breaker

More than one Sluice instance can be enrolled. Each enrolled instance gets
its own circuit breaker (closed → open after 5 consecutive failures → half-open
after a 30s reset timeout → closed again after one successful probe). Live
requests round-robin across instances whose breaker is closed; an instance
with an open breaker is skipped. If every enrolled instance's breaker is
open, the pool has no client to pick and the request passes through
**unconditionally** — see the "no client to call" gate under **Failure
behavior** above; this is *not* governed by `fail_mode`.

> **Single-instance half-open recovery is currently broken.** The default
> half-open probe budget is 1 (`HalfOpenProbes`), and `runCDRStage` spends it
> before a real probe ever happens: it first calls `cdrActiveClient()` just
> to check whether *any* client exists, and that call alone invokes
> `Pool.Pick()` → `Breaker.Allow()`, consuming the sole half-open
> reservation. `safeCDRSanitize`'s own `cdrPickPooled()` call — the one that
> would actually run a probe RPC and call `OnSuccess`/`OnFailure` — then
> finds the budget already exhausted and gets `nil` back, so CDR silently
> skips (fail-open) instead of probing. With only one instance in the pool
> there is no other candidate for `Pick()` to fall through to, so the
> breaker never sees a real probe and **stays half-open indefinitely** —
> not the elapsed-time-plus-one-success path described above. Recovery
> needs the pool to be rebuilt with **no prior breaker to carry forward**:
> a process restart does this (the pool starts empty), and so does a full
> runtime **disable-then-enable** via `PUT /api/cdr/config`
> (`{"enabled":false}` calls `shutdownCDRClient()`, which empties the pool
> entirely; the following `{"enabled":true}` rebuilds from the registry
> with nothing in `oldPool` for `dialEnrolledInstance` to match by name, so
> it mints a fresh breaker). Editing or re-saving the SAME instance's
> registry entry WITHOUT a full disable/enable cycle does **not** recover
> it — that path only ever calls `initCDRClient`, which reads the CURRENT
> (still half-open) pool as `oldPool` and carries the breaker forward by
> name.
>
> **A pool with two or more *closed* instances is NOT unaffected — the
> stuck instance still never recovers, it just stops mattering for most
> requests.** `Pool.Pick()` uses ONE shared round-robin cursor that
> advances on every call, including both separate `Pick()` calls one
> request makes (`cdrActiveClient()`'s nil-check, then
> `safeCDRSanitize`'s `cdrPickPooled()`). On a request where the cursor
> happens to land on the half-open member for the FIRST call, that call
> alone consumes its sole half-open reservation via `Breaker.Allow()`; the
> cursor has advanced by the SECOND call, so the actual RPC lands on a
> different, closed member instead — the half-open member gets no real
> probe AND no `OnSuccess`/`OnFailure`, so it never closes. The pool keeps
> serving requests through its closed members (CDR isn't bypassed), but
> the half-open member stays permanently capacity-degraded — one
> pool-configured instance silently never rejoins rotation until a
> process restart or a full disable/enable cycle.
>
> **The runtime disable-then-enable recovery ALSO silently resets
> `fail_mode`, the default profile/mode, the timeout, and the size/chunk
> limits — not just the breaker.** `shutdownCDRClient()` replaces
> `cdrActiveCfg` with a fully zeroed `CDRConfig{}`; the toggle's enable
> path only ever flips `cdrActiveCfg.Enabled` back to `true` on that same
> (now-zeroed) struct before calling `initCDRClient`, and `PUT
> /api/cdr/config` accepts no field but `enabled` — there is no runtime way
> to restore the other values. So if you're running `cdr.fail_mode:
> closed` (or a non-default profile/timeout/size cap), the disable-then-
> enable recovery above will leave CDR running **fail-open** with default
> settings until the next restart, with nothing in the API response
> calling that out. **If your deployment has fail_mode set to `closed` or
> any non-default CDR setting, restart the process instead of using the
> runtime toggle to recover a stuck half-open breaker** — a restart
> re-resolves the full static config from disk and reapplies it correctly.

Two observability tiers exist. `culvert_cdr_instance_healthy` and
`culvert_cdr_queue_depth` (from the 15-second background health poll) are
**pool-wide aggregates**: `instance_healthy` is 1 when *at least one*
enrolled instance's most recent probe succeeded, and `queue_depth` is the
*minimum* Sluice-reported queue depth across the currently-healthy
instances at the LAST round that had one — `applyAggregateHealth` only
overwrites the gauge when that round found a healthy member, and the
all-members-failed path never resets it, so once every instance goes
unhealthy `queue_depth` freezes at its last observed value instead of
going to zero or empty. Never read it alone as current spare capacity;
pair it with `instance_healthy` (or the per-instance series below) to
tell "genuinely low queue" from "stale reading from before the outage".
Neither carries an instance label, so neither alone tells you
*which* member is down. Per-instance detail **is** exported separately,
labeled by `instance`: `culvert_cdr_pool_instance_healthy{instance}`,
`culvert_cdr_pool_breaker_state{instance}` (0=closed, 1=open, 2=half_open),
and `culvert_cdr_pool_breaker_trips_total{instance}`. Build per-member
alerting off the `_pool_*` series, not the two aggregates — but treat them
as **live-pool-only**: `buildCDRPoolFromRegistry` silently skips an
enrolled instance whose certificate load or dial fails at (re)init time
(logged, never added to the pool), so that instance never gets a
`_pool_*{instance}` series at all — no `breaker_state`, no `healthy`, no
error — while the two aggregates can stay green because another member
dialed successfully. A missing `instance` label is not evidence of health;
cross-check the `_pool_*` series against your enrolled-instance inventory
(`GET /api/cdr/instances`) or the `CDR: pool: skipping "<name>"` startup/
reconfigure log line to catch a member that never made it into the pool.
`GET /api/cdr/instances` is also the right surface for ad hoc inspection,
since it carries per-instance health and breaker state.
`GET /api/cdr/health` does **not** — it returns only the
cached/live Sluice `Health` response plus pool-wide `consecutiveFailures`/
`liveHealthy`, with no per-instance breakdown, so it cannot tell you which
member is unhealthy.

**A single-instance deployment cannot revoke its own credential through the
API.** `POST /api/cdr/instances/revoke` issues the revoke RPC *from* another
enrolled, reachable Sluice (Sluice refuses self-revocation), so revocation
needs a second instance enrolled. **`DELETE /api/cdr/instances` is not a
substitute** — it only removes Culvert's local registry entry and cert
files; the credential is untouched at Sluice and stays trusted there until
its natural expiry (deleting the local cert files can also destroy the
easiest record of the fingerprint you'd need to revoke it later). If you
need to revoke a credential from a single-instance deployment — especially
after a suspected compromise, where this matters most — either enroll a
second instance first and revoke through it, or revoke the credential
directly on the Sluice side (outside Culvert's control; consult Sluice's own
operator documentation).

## Certificate lifecycle

**Automatic renewal applies only to registry-backed (enrolled) instances —
not to the config/CLI-only bootstrap path.** If at least one instance has
ever been enrolled (via the GUI or `POST /api/cdr/instances/enroll`), the
pool is built from that registry and both automatic behaviors below apply.
If you instead only ever set `cdr.endpoint` (+ optionally `cdr.certs_dir`)
via config/CLI and never enrolled anything, Culvert dials a single anonymous
client (internally named `default`) that has no registry entry — and both
`maybeRenewExpiringClients` and the server-rotation reconciler skip any
instance they can't find in the registry. On that path, neither the client
certificate nor the server-fingerprint pin renews itself; you are
responsible for replacing the files under `cdr.certs_dir` and updating
`cdr.server_fingerprint` manually before they expire or rotate. Enrolling at
least one instance through the API is the only way to get the automatic
behavior described below.

**The automatic renewal below depends on the 15-second health poller, and
the poller is only started once, at boot, and only if CDR is already
enabled at that point.** `loadCDR` returns before calling
`startCDRHealthPoller` whenever CDR boots disabled — the default — and
there is no other call site for it: neither the runtime enable toggle
(`PUT /api/cdr/config {"enabled": true}`) nor enrolling an instance through
the API calls it, both only reach `initCDRClient` (which (re)builds the
connection pool). So on a node that starts with CDR disabled and is enabled
purely at runtime, the pool exists and requests flow through it, but no
certificate-expiry check, `RenewCert` call, or server-fingerprint rotation
check runs until the process is restarted with CDR enabled at boot (via
`-cdr-enabled` / `cdr.enabled: true`, or the `cdr_enabled` sentinel already
being present from a prior enable). If you enable CDR at runtime only,
schedule a restart to arm the poller, or start the node with CDR enabled in
the first place.

Both directions of the mTLS relationship renew themselves automatically for
enrolled instances — manual action is a fallback, not the normal path:

- **Client certificate (Culvert → Sluice):** issued at enrollment, valid for
  one year. The 15-second health poller checks every enrolled instance's
  client-certificate expiry and, once it's within 30 days of `NotAfter`,
  fires a `RenewCert` call in the background (single-flighted per instance,
  so repeated polls don't double-renew). Renewal is a durable, crash-safe
  transaction — an interrupted renewal is reconciled from disk at the next
  boot or health poll rather than left in an ambiguous state, and the
  previous credential keeps working until its own expiry, so a Sluice outage
  during the 30-day window doesn't cause a gap. Re-enrolling manually is only
  needed if automatic renewal has been failing (check the log for `RenewCert
  failed`) or the instance was never successfully enrolled.
- **Server certificate (Sluice's own cert, TOFU-pinned by
  `cdr.server_fingerprint`):** **on the Culvert side**, if Sluice's `Health`
  response advertises a rotation in progress (`rotated_fingerprint` +
  a grace-window deadline), Culvert stages the advertised value as a second
  accepted fingerprint (dual-pin) so a mid-rotation connection isn't dropped,
  and promotes it to primary once the grace window passes and Health reports
  it as the new primary — verified end-to-end against this repo's own
  `cdr_health.go`/`cdr_pool.go` and their tests. **Whether Sluice's rotation
  tooling actually populates those fields on a live `Health` RPC is outside
  what this Culvert-side runbook can confirm** — `roadmap/SLUICE-CDR-HANDOFF.md`,
  the only Sluice-side reference in this repo, documents an older `Health`
  message shape with no fingerprint fields at all, so it's not authoritative
  either way for the currently-pinned Sluice version. Don't treat "automatic"
  here as a guarantee: verify a real rotation against your deployed Sluice
  version before relying on it, and keep `cdr.server_fingerprint` update
  as your fallback if a rotation isn't picked up (check the log for
  `CDR: server-cert rotation` lines, or `GET /api/cdr/health` for staleness,
  to tell whether the dual-pin ever actually armed).

## Policy rules

CDR policy rules (`/api/cdr/policies`) choose **which sanitization profile**
and **which mode** apply to a given request — they do not decide whether to
allow or inspect the connection at all (that's the ordinary access-policy
engine). Fields intentionally mirror `PolicyRule` so the same matching mental
model applies:

- **Source**: source IP/CIDR, authenticated identity, IdP group, IdP name.
- **Destination**: FQDN, URL category, category group, destination country.
- **Schedule**: the same weekly time-window object used elsewhere.
- **Action**: `profileName` (must match a name Sluice's `Health` RPC
  advertises) + `mode` (`ENFORCE` / `REPORT_ONLY` / `BYPASS_WITH_REPORT`).

Rules are evaluated first-match by `priority`. When no rule matches, the
request falls through to `cdr.default_profile` / `cdr.default_mode`. Use
**CDR → Add CDR policy rule** in the GUI, or `POST /api/cdr/policies`.

## Testing a file

**CDR → (test upload)** / `POST /api/cdr/test` (admin-only) submits a file to
the active Sluice instance in `REPORT_ONLY` mode without touching live
traffic — use it to confirm connectivity and see what a given file would
trigger before writing a policy rule around it.

## Observability

Request-log events (traffic/request history, written via `recordRequest` —
**not** the admin audit trail; no CDR runtime outcome calls `auditEvent`, so
they carry request-log retention, not audit-trail semantics):
`CDR_SANITIZED`, `CDR_BLOCKED`, `CDR_ERROR` — each
carries the matched profile, but the second detail field differs by event:
`CDR_SANITIZED` carries the threat summary, while `CDR_BLOCKED` and
`CDR_ERROR` carry the block reason / transport error instead. None of the
three request-log entries carries the mode — mode appears only in the
plain-text `logger.Printf` line alongside them, not in the structured
event. Filter the events from **CDR → Recent CDR events** in the GUI.

Prometheus metrics (`culvert_cdr_*`, all counters unless noted):
`files_processed_total`, `threats_detected_total`, `errors_total`,
`fail_open_total`, `fail_closed_total`, `panics_total`,
`oversize_skipped_total`, `cache_hits_total`, `cache_misses_total`,
`cache_size` (gauge), `bytes_in_total`, `bytes_out_total`,
`instance_healthy` (gauge, pool-wide aggregate — see **Multi-instance pool**
above), `queue_depth` (gauge, pool-wide aggregate). Per-instance (labeled
`{instance}`): `pool_instance_healthy` (gauge), `pool_breaker_state` (gauge,
0=closed/1=open/2=half_open), `pool_breaker_trips_total`. Labels are
otherwise deliberately low-cardinality — no filename, destination host, or
user identity — by contract with Sluice.

**`bytes_in_total` is currently inert — it reads zero on every node.** Its
backing counter, `statCDRBytesIn`, is declared and exposed by
`cdrWriteByteMetrics` but nothing in the codebase increments it. The actual
bytes streamed to Sluice per Sanitize call are tracked by a separate
counter, `statCDRBytesSent` (incremented per chunk in `sendSanitizeBody`),
which has no Prometheus exposure at all today. `bytes_out_total`
(`statCDRBytesOut`, the sanitized bytes read back from Sluice) is wired
correctly and can be trusted. Don't build a throughput/capacity dashboard
on `bytes_in_total` expecting it to move — it won't, on any version of
Culvert as of this writing.

## API reference

All endpoints are under `/api/cdr/`, admin-UI-session-authenticated, RBAC
per the table below (reads = viewer, mutations = admin; `/api/cdr/config`
GET is viewer, PUT is admin):

| Endpoint | Method | Role | Purpose |
|---|---|---|---|
| `/api/cdr/config` | GET | viewer | Effective runtime config + derived fields (`clientActive`, `failOpen`) |
| `/api/cdr/config` | PUT | admin | Toggle `enabled`; persists and applies immediately |
| `/api/cdr/instances` | GET | viewer | List enrolled Sluice instances |
| `/api/cdr/instances` | DELETE | admin | Remove a registry entry (`?name=…`) and shred its local cert material — does **not** notify Sluice. **In a multi-instance pool this shuts down the ENTIRE pool, not just the deleted member**: the handler's check is "is any client currently pickable" (`cdrActiveClient() != nil`), not "was the deleted instance the last one", so deleting one healthy instance out of several calls `shutdownCDRClient()` and empties the pool — CDR bypasses all traffic until the pool is rebuilt. The remaining instances stay in the registry and need no re-enrollment: a disable-then-enable via `PUT /api/cdr/config` or a process restart rebuilds the pool from them. **The opposite edge case: if every pool member's breaker is open at delete time**, `cdrActiveClient()` returns nil (nothing is pickable), so the pool-shutdown branch is SKIPPED entirely — the deleted instance's already-loaded in-memory TLS client stays in the live pool even though its registry entry and cert files are gone, and it can be selected again once its breaker later closes/half-opens, using a credential Sluice was never told is revoked. Follow a DELETE with a disable/enable cycle or restart if any breaker was open at the time, to be sure the removed member is actually gone from the running pool |
| `/api/cdr/instances/enroll` | POST | admin | Exchange a one-time token + fingerprint for mTLS credentials |
| `/api/cdr/instances/enroll/recover` | POST | admin | Resolve an enrollment whose outcome was left unknown (e.g. a client-side timeout mid-exchange) |
| `/api/cdr/instances/enroll/receipts` | GET | viewer | Bounded recovery receipts for past enrollment operations |
| `/api/cdr/instances/enroll/receipts` | DELETE | admin | Remove terminal recovery receipts — the repair path for a degraded receipt store |
| `/api/cdr/instances/revoke` | POST | admin | Actively invalidate a credential at Sluice (by instance name or an orphaned fingerprint) — the Sluice-side counterpart to the local-only `DELETE` above |
| `/api/cdr/policies` | GET/POST/DELETE | viewer / admin / admin | CDR policy rule CRUD |
| `/api/cdr/health` | GET | viewer | Cached (or live, on demand) Sluice `Health` response |
| `/api/cdr/test` | POST | admin | Submit a file in `REPORT_ONLY` mode against the active instance |

## Common pitfalls

- **A runtime `PUT {"enabled": false}` doesn't stick if static config still
  enables CDR** — see the restart caveat under **Enabling it** above.
- **Enabling CDR with no reachable Sluice instance does not block traffic,
  even with `fail_mode=closed`.** With no client available at all, every
  eligible file passes through unsanitized and silently — see the "no
  client to call" gate under **Failure behavior**. `fail_mode=closed` only
  ever blocks once a client was actually reached and that specific call
  failed. Monitor `/api/cdr/health` and the per-instance breaker metrics,
  not `fail_mode`, to know whether CDR is actually protecting traffic right
  now.
- **A large download is only sanitized up to the shared scan window, not up
  to `cdr.max_file_size_mb`** — see the callout under **Failure behavior**.
  The untouched remainder past `security_scan.max_scan_mb` ships to the
  client with no CDR (or AV/YARA/DPI) inspection at all.
- **`default_profile` must exist on Sluice.** There is no client-side
  validation that the configured or rule-selected profile name is one Sluice
  actually advertises; a typo surfaces as a Sluice-side `ERROR` at request
  time, not at config time.
- **CDR state does not travel with cluster config sync, rollback, or
  export/import.** A restored config-version snapshot or a DP node's synced
  `ConfigSnapshot` will not carry CDR's enable state, enrolled instances, or
  policy rules — those must be reproduced per node.
