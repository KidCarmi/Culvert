# PAC Traffic Steering — Foundation (Part 1)

This document covers the hardened PAC (proxy auto-config) foundation: typed
validation, the deterministic compiler, HTTP delivery semantics, and the
storage migration. Profiles/proxy pools and the simulator/publish lifecycle
are delivered in follow-up parts.

## What `/proxy.pac` serves

`/proxy.pac` returns a generated `FindProxyForURL` script built from the PAC
configuration (proxy host, proxy port, exclusion list). It is served
**unauthenticated by design** on both listeners (PAC clients cannot send
credentials):

- the proxy port (plain HTTP — Windows/macOS clients fetch without TLS), and
- the admin UI port (allowlisted in the auth middleware).

Evaluation order in the generated script:

1. hostname hygiene (lowercase, strip one trailing dot),
2. plain (dotless) hostnames → `DIRECT`,
3. DNS-free exclusions — bare domains (exact + subdomains), `*.` wildcards,
   IP literals — in configured order,
4. **one** `dnsResolve(host)` call, truthiness-guarded,
5. loopback + RFC-1918 → `DIRECT`, then CIDR exclusions, in configured order,
6. terminal `PROXY <host>:<port>` (no implicit `DIRECT` fallback — the legacy
   fail-closed posture is preserved).

All rules before the terminal return `DIRECT`, so the DNS-free-first grouping
cannot change any outcome — it only avoids DNS lookups when a domain rule
already answers, and collapses the previous 5+ `dnsResolve` calls per
evaluation into at most one.

### Generated-JS portability contract

The compiler emits pure **ECMAScript 3**, 7-bit ASCII, no BOM, no trailing
commas — the floor imposed by Windows WinINET/WinHTTP's JScript engine. Only
`PROXY` and `DIRECT` directives are emitted (WinHTTP supports no others).
DNS failure is truthiness-tested, covering both `null` (Chromium, Firefox)
and `""` (Windows Ex API) return conventions. Unicode hostnames are stored
and emitted as punycode A-labels (Chromium and Firefox pass punycoded hosts
into `FindProxyForURL`).

## Validation

`POST /api/pac-config` and config **import** are strictly validated. Invalid
input is rejected with HTTP 400 and a structured issue list:

```json
{"error": "validation failed",
 "issues": [{"field": "exclusions", "entry": "192.168.0.0/33",
             "code": "invalid_cidr",
             "message": "\"192.168.0.0/33\" is not a valid CIDR (expected e.g. 192.168.0.0/16)"}]}
```

Checked: proxy host shape (hostname or IP literal, no scheme/port/credentials),
port range (0–65535; 0 = auto-detect), per-entry grammar (bare domain,
`*.wildcard`, IPv4 CIDR, IP literal), control characters, entry length
(≤253), list size (≤10 000 — the cluster snapshot cap), wildcard placement
(`*` only as a leading `*.`), IDNA normalization (Unicode → punycode), and a
compiled-output byte budget (reject > 1 MiB — Chromium's PAC fetch cap;
warn > 512 KiB). Duplicates (after normalization) are deduplicated with a
warning, and CIDRs with host bits set are normalized to the network address
with a warning. Accepted configs are persisted in canonical form.

**Replay paths stay tolerant.** Loading a legacy `pac_config.json`,
config-version rollback, and cluster snapshot apply never reject: entries
that cannot be parsed are dropped from the *generated script* with a logged
warning, and the stored file is left as-is. Strictness lives only at the API
boundary, so historical snapshots and mixed-version clusters can always
replay.

## HTTP caching

- `ETag`: strong, the SHA-256 of the exact response body; `If-None-Match`
  is honored (`304 Not Modified`).
- `X-Culvert-PAC-Version`: `<compiler-version>-<digest-prefix>`.
- When **proxyHost is configured**: `Cache-Control: max-age=0,
  must-revalidate` plus `Last-Modified` — clients may cache but revalidate
  every use, so a config change propagates on the next fetch (cheap 304s
  otherwise).
- When **proxyHost is empty** (fallback mode): the body embeds each request's
  Host header, so the response stays `Cache-Control: no-cache, no-store` —
  a shared cache must never serve one client's PAC to another. Set an
  explicit proxy host to enable revalidation caching.

## Storage location and migration

PAC configuration now lives at **`<dataDir>/pac_config.json`** (default
`/data/pac_config.json`), which puts it on the backup/restore surface —
previously it was written to `pac_config.json` in the process working
directory and was silently **absent from every backup**.

On first start after upgrade, if `<dataDir>/pac_config.json` does not exist
but the legacy CWD file does, the config is migrated automatically (one-way)
and a log line records it. The legacy file is left in place but **frozen**:

> **Downgrade note:** a binary older than this release reads the legacy CWD
> file, which stops receiving updates after migration. If you downgrade after
> changing PAC config, re-apply those changes (or copy
> `<dataDir>/pac_config.json` over the CWD file) — otherwise the downgraded
> binary serves the pre-migration config.

## Determinism

The same configuration always compiles to byte-identical PAC output
(`compiler: v1` header, config fingerprint included). Timestamps are never
embedded in the script. Golden-file tests pin the exact output; any change to
generated bytes requires a compiler-version bump.

## Client compatibility notes (authoritative-behavior basis)

- Chromium and Firefox strip the path/query from `https://` URLs before
  calling `FindProxyForURL` — rules are host-granular by design.
- WinINET caches the PAC *result per hostname* (Automatic Proxy Result
  Cache) — another reason rules are host-granular.
- Multi-entry failover chains (`PROXY a; PROXY b`) are honored by Chromium
  (~5 min bad-proxy quarantine) and Firefox (30 min,
  `network.proxy.failover_timeout`); pool-based chains arrive with PAC
  profiles in part 2.
- `isInNet` is IPv4-only in the portable API — IPv4 CIDR exclusions only.

### Intentional matching-behavior deltas vs. the legacy generator

Two fix-forward changes tighten previously inconsistent matching; both are
deliberate:

- **CIDRs with host bits set** (e.g. `192.168.1.55/24`) are normalized to the
  network address (`192.168.1.0/24`) and now match the whole network. Some
  PAC engines never matched the un-masked legacy form at all.
- **Case and trailing dots are normalized** on both sides: an exclusion for
  `corp.local` now also matches `Corp.LOCAL` and `corp.local.` (the legacy
  exact-`===` compare missed both), and a trailing-dot plain name (`foo.`)
  is treated as a plain hostname (DIRECT).

---

# PAC Traffic Steering — Profiles & Proxy Pools (Part 2)

## Steering profiles

A **profile** is a named PAC configuration served at a stable URL:

```
/pac/<profile-id>.pac
```

`/proxy.pac` remains a permanent alias for the **default** profile
(`/pac/default.pac`), which is the legacy configuration (proxy host/port +
exclusions) — managed exactly as before via the PAC panel / `/api/pac-config`,
byte-identical output. Custom profiles are managed in the PAC panel's
Steering Profiles section (`/api/pac/profiles`, admin-only mutations) and
persist in `<dataDir>/pac_profiles.json` (on the backup surface).

Each profile carries:

- a **proxy pool** reference — an ordered failover chain of 1–3 endpoints,
  rendered as `PROXY primary:port; PROXY secondary:port; …`;
- **ordered routing rules** (first match wins): kinds `domain` (exact +
  subdomains), `suffix` (subdomains only), `wildcard` (`shExpMatch` glob),
  `cidr4` (IPv4 CIDR against the resolved IP); optional `scheme` and
  explicit-`port` guards (default ports are omitted by clients and cannot be
  matched — documented limitation); actions `use_pool` (optionally naming an
  override pool) or `direct`;
- an **availability mode** (explicit, never implicit):
  - `secure` — pool chain only, **no DIRECT anywhere** (plain dotless
    hostnames excepted). DIRECT rules and `privateNetworks: direct` are
    rejected in this mode; if no proxy endpoint resolves, the generated PAC
    fails **closed** via an unresolvable placeholder, never open.
  - `balanced` — pool-chain terminal without DIRECT, but explicit `direct`
    rules are permitted where authored.
  - `availability` — pool chain then `DIRECT` (fail open).
- a **private-networks behavior** replacing the legacy hardcode: `direct`
  (loopback + RFC-1918 bypass, the legacy default) or `proxy` (private
  ranges follow rules/pool). The default profile keeps `direct`.

DNS in profile PACs is resolved at most once per evaluation (a nested ES3
helper). With `privateNetworks: proxy` the resolution is fully lazy — rule
chains that answer before any `cidr4` rule never pay for a lookup. With
`privateNetworks: direct` the private-network bypass must run before the
rules to keep its guarantee, so every evaluation resolves once up front (the
same cost profile as the legacy generator). Rules are emitted in exactly the
authored order — with `use_pool` actions, order is semantic and is never
reordered by the compiler. Explicit-port rule guards compare the URL
authority tail, never a substring of the full URL.

Profile PACs are served unauthenticated on both listeners (PAC clients
cannot send credentials) — including plain HTTP on the proxy port, like
`/proxy.pac`. Treat profile PAC contents (pool hostnames, routing rules) as
**public information**: anyone who can reach a listener and guess an enabled
profile ID can read them.

## Distribution

Profiles and pools participate in every config surface: export/import
(import never wipes; merge upserts by ID), config versioning + rollback
(nil = pre-feature snapshot skips; `[]` = explicit wipe), cluster CP→DP sync
(wire-wipe capable — clearing the last profile clears DP state; this PR also
fixes the pre-existing gap where clearing all legacy *exclusions* never
reached DPs), backup/restore, and audit (`pac.profile_*`, `pac.pool_*`).

## Observability

PAC serving is instrumented (`/metrics`): `culvert_pac_serves_total`,
`culvert_pac_not_modified_total` (304 revalidations),
`culvert_pac_compile_warnings_total` (degraded compiles surfaced at serve
time), and the gauges `culvert_pac_profiles`, `culvert_pac_profiles_enabled`,
`culvert_pac_pools`. A degraded compile — a dropped rule, an unresolvable
pool, or a secure-mode conflict in a replayed/synced config — is logged and
fires the `pac_profile_degraded` alert once per profile (the latch resets
when the profile is next mutated). A secure-mode profile whose pool becomes
unresolvable fails **closed** (an unresolvable placeholder), so the alert is
the operator's signal before the helpdesk queue is.

## Propagation to the fleet

Every control-plane PAC mutation — `/api/pac-config`, profile/pool CRUD,
config import, and config-version rollback — republishes the cluster
snapshot immediately; data-plane nodes converge on their next poll (≤~30 s).
Data-plane-local PAC mutation is refused (409, "managed by the control
plane"): the profile store on a DP is control-plane-owned, so a local edit
would silently diverge until the next snapshot overwrote it.

## Downgrade

`pac_profiles.json` is unknown to older binaries and ignored; the legacy
default profile keeps working. Clients pointed at `/pac/<id>.pac` receive
404 from a downgraded binary — **and a PAC fetch that 404s makes clients
fall back to DIRECT, so a `secure`-mode fleet silently bypasses the proxy
for the entire downgrade window.** Repoint clients at `/proxy.pac` (the
legacy default) before downgrading.

> **Downgrade + edit hazard:** the CWD→dataDir migration is one-way. If you
> downgrade, edit PAC config (the downgraded binary writes the legacy CWD
> file), then re-upgrade, the re-upgraded binary reads `<dataDir>/pac_config.json`
> and the downgrade-window edits are silently ignored. Re-apply them, or copy
> the CWD file over `<dataDir>/pac_config.json` before re-upgrading.

---

# PAC Traffic Steering — Simulation & Safe Publishing (Part 3)

## Simulator

`POST /api/pac/simulate` (viewer) answers "what would profile P return for
URL/host X?" using the **same** normalized rule evaluation the compiler
emits — not a second engine (a parity test pins agreement). It returns the
directive, the matched rule (index + kind + pattern), a human reason, the
selected pool, the failover chain, whether DIRECT is possible, the compiler
version, and the profile revision.

**No live DNS.** The API never resolves hostnames (it is viewer-reachable).
Supply an optional `resolvedIp` to evaluate `cidr4` and private-network
rules definitively; without one, those rules return an explicit
`undetermined_dns` outcome rather than a guess. The `default` profile is
simulatable too (its legacy exclusions are expressed as DIRECT rules).

## Draft → Publish → Rollback lifecycle

Each custom profile carries a mutable **draft** and an append-only stack of
**immutable published revisions** (`<dataDir>/pac_profiles_lifecycle.json`,
node-local operator history — the ACTIVE spec still cluster-syncs via the
Part 2 surface). The **mutating** lifecycle endpoint is
`POST /api/pac/profiles/{id}/lifecycle` (admin) with actions `save_draft`,
`publish`, `rollback` (plus an optional `reason` recorded on the published
revision); `GET` (viewer) returns the draft/active/history. The **read-only**
diff/impact analysis lives on its own viewer route, `POST /api/pac/analyze`
(actions `diff`, `impact`) — kept off the mutating, audited lifecycle route so
its audit-completion signal stays meaningful.

> **HA / failover note.** The revision history and drafts are **node-local**:
> they are not cluster-synced and are not on the backup-rollback config
> surface (they ARE included in `culvert backup`). After a control-plane
> failover, the promoted node serves the correct ACTIVE spec (that syncs) but
> starts with its own revision timeline — rollback targets published on the
> former leader are not present until you restore `pac_profiles_lifecycle.json`
> from a backup on the promoted node. Revision numbers are per-node.

Publishing validates + compiles the draft, then **fails closed** when any of
these hold: validation fails, no valid proxy route exists, the referenced
pool is missing, secure mode could emit DIRECT, compilation/digest fails, or
rule conflicts violate the documented invariants. Publishing a change that
introduces **new DIRECT paths** — a new DIRECT rule, switching to availability
mode, **or flipping private-networks to `direct`** (which sends the entire
RFC-1918/loopback space DIRECT) — is refused with `409 confirm_required`
until the admin retypes the server-selected `confirmValue` (the profile ID
plus the first eight hex characters of the candidate's spec digest) and echoes
the candidate-bound `challenge` + `binding` the refusal issued. The binding
covers the candidate, the active revision and spec digest, the referenced
pools and the compiled artifact; if any of them changed by the time the
retry lands, the server answers `409 challenge_stale` naming the changed
fields with a fresh challenge. A challenge is single-use for a commit.
**Rollback is gated the same way:** rolling back to a revision whose DIRECT
footprint exceeds the currently-active one also requires the typed
confirmation (bound to the rollback action and target), so the guardrail
cannot be laundered through a rollback. The pre-2F `confirmDirect=<id>`
form is no longer accepted.

**Lifecycle truth.** Every publish/rollback/repair carries a UUID
`operationId` and is at-most-once: a repeated id returns the recorded result.
The active profile store is the only commit point; the node-local history
records the outcome afterwards, and `GET …/lifecycle` reports
`historyState`: `recorded`, `pending_reconciliation` (the active profile IS
committed; a node-local effect — history revision, config version keyed by
the operation, cluster publication, success audit — is completed on the next
read, operation or restart, never duplicated), `ambiguous` (an outcome could
not be classified from the active state; an admin `repair` with
`resolution: accept_active` records the observed active spec), or
`history_reset`. **`history_reset`** means the history file was found corrupt
at startup and quarantined to `pac_profiles_lifecycle.json.corrupt.<unixnano>`
(the durable record lives in `pac_profiles_lifecycle.reset.json`); the
active profile is untouched and still served, but publish/rollback are
refused with `409 history_reset` until an admin acknowledges the loss for
that profile with `action: acknowledge_history_reset`, echoing the current
`expectedActiveRevision` and `expectedActiveSpecDigest` from the GET. The
acknowledgement never rewrites the active store and survives restarts.

**The direct CRUD path enforces the same gate.** Creating or updating a
profile through `POST /api/pac/profiles` / `PUT /api/pac/profiles/{id}` (the
Steering Profiles editor's Save) runs the identical guardrail: a candidate
that introduces a new DIRECT path is refused with `409 confirm_required`
until the caller echoes the same bound challenge in the body's `confirm`
object (the editor prompts for the typed `confirmValue`). This closes the bypass where the safe-publish
confirmation could be sidestepped by saving through the editor/API instead of
the publish lifecycle — both paths share one guardrail. (A brand-new profile
has no prior revision, so *any* DIRECT capability counts as new and prompts
once at creation; proxy-only profiles save without a prompt.)

Each published revision records the exact spec, the compiled **artifact
digest** (a local restore/verify anchor — see the pool-mutability caveat
below; convergence itself is guaranteed by the deterministic compiler, not a
cross-node digest check), author, reason, and timestamp. Revision numbers are
**monotonic** and never reused; the history is bounded (oldest revisions are
trimmed past the per-profile cap, mirroring the config-version store). A
rollback does not rewrite history — it re-activates a prior revision's spec as
a NEW revision. The active profile's own `revision` field is the Part-2 PUT
optimistic-concurrency token and advances independently of the lifecycle
revision number.

> **Pool-mutability caveat.** A revision captures the profile *spec* (which
> references pools by ID) and the artifact digest computed at publish time.
> Pools are separate, mutable objects: editing a pool's endpoints after a
> revision is published changes the compiled `/pac/{id}.pac` bytes for every
> revision that references it, so re-serving or rolling back to an older
> revision reproduces the recorded *spec* but not necessarily the recorded
> *digest*. The digest therefore verifies "same spec + same referenced pool
> definitions", not "same spec regardless of later pool edits". Treat pool
> edits as their own change event (they are audited and cluster-synced
> independently); to freeze a routing outcome end-to-end, avoid mutating a
> pool a published revision depends on.

## Change diff & impact analysis

`diff` reports rules added/removed/reordered, pool/mode/private-network
changes, and DIRECT-path deltas, flagging security-sensitive widenings.

`impact` replays a sample of destinations through the active vs candidate
revision and categorizes each: `unchanged`, `pool_changed`, `became_direct`,
`no_longer_direct`, `lost_proxy_path`, `undetermined_dns`. The sample is
either admin-supplied test vectors or (`useObserved`) a bounded snapshot of
the in-memory top-hosts counter — **real observed destination hostnames, no
fabricated telemetry**. Because observed samples carry no resolved IPs,
`cidr4`/private-network outcomes are reported `undetermined_dns`, not
guessed; full historical request-log replay is a documented future
extension. Impact also statically flags shadowed, duplicate, and unreachable
rules independent of the sample.

## Rollback

`{"action":"rollback","targetN":N}` re-activates published revision N: it
mints a new revision, updates the active served profile, audits
(`pac.profile_rollback`), snapshots config, and republishes the cluster
snapshot so DPs converge — restoring the exact prior artifact digest.

## DIRECT bypass inventory (posture)

`GET /api/pac/posture/inventory` (viewer) returns a **config-derived**
inventory of every PAC path that returns `DIRECT` — a **full security-path
bypass** (matching traffic skips TLS inspection, DLP, CDR, URL filtering,
threat inspection, authentication, policy, and all proxy logging; it never
reaches Culvert), distinct from a TLS-decryption bypass. The PAC panel renders
it read-only as **DIRECT Bypass Inventory**.

Each profile (including the synthesized legacy default) is walked for the DIRECT
sources: the always-present plain-host guard (`plain_host` — dotless intranet
hostnames go DIRECT in **every** profile; the compiler emits it unconditionally,
so even a secure/proxy-only profile bypasses for single-label names — the
profile compiler additionally excludes IPv6 literals, the legacy default
compiler does not, so the source is reported without promising IPv6 exclusion),
an explicit `direct` rule (`direct_rule` — only rules the compiler would
actually emit; a rule with an invalid pattern is dropped by the compiler and is
**not** inventoried), availability mode (`availability_mode` — appends DIRECT to
the terminal, fail-open), `private-networks=direct` (`private_networks` —
RFC-1918/loopback DIRECT), and, for the legacy default only, `fail_open` — when
**no proxy host is configured**, `/proxy.pac` fails OPEN to DIRECT for all
traffic if the fetching client supplies no resolvable Host (the request-
dependent terminal the static profile model cannot otherwise express, injected
so the whole-traffic bypass is never hidden). Secure mode neutralizes the
rule/private/availability sources but **not** the plain-host guard. Wildcards
and broad IPv4 CIDRs (≤ /16), plus the all-destination mode/private/fail-open
bypasses, are flagged `broad` (the plain-host guard is not).

**Evidence class: `config` (Observable).** The inventory reports what the
configuration makes *reachable* — it never claims a bypass was *used*. Culvert
cannot observe DIRECT traffic (it never reaches the proxy), so usage/ownership/
impact are out of scope here and are the subject of later phases (an endpoint
agent or imported firewall/DNS evidence). `serving` marks enabled profiles,
whose bypass is reachable by clients now; a disabled profile is inventoried but
serves nothing (404).

## DIRECT exception governance

The inventory answers *"which profiles can bypass?"*. Governance answers
*"is each bypass owned, justified, and time-bounded?"* — so a full-security-path
bypass is never an anonymous, permanent hole.

- `GET  /api/pac/posture/exceptions` (viewer) — one row per DIRECT-capable
  profile, joining the inventory (`directCapable`, `serving`, `name`) with its
  governance record and a computed **status**.
- `GET  /api/pac/posture/exceptions/{id}` (viewer) — one record + status.
- `PUT  /api/pac/posture/exceptions/{id}` (admin) — set governance. `owner` and
  `reason` are required; `expiresAt`/`lastReviewedAt` are RFC3339;
  `reviewCadenceDays` is `0`–`3650` (`0` = no cadence). The server preserves
  `createdAt`/`createdBy` across updates, stamps `updatedAt`, and both
  `auditEvent`s and `saveConfigVersion`s the change.
- `DELETE /api/pac/posture/exceptions/{id}` (admin) — clear governance (the
  DIRECT bypass itself is unchanged; the row reverts to `ungoverned`).

**Status** is a pure function of the record + the current time, evaluated only
for genuinely DIRECT-capable profiles (a profile that cannot emit DIRECT carries
no status):

| status       | meaning                                                        |
|--------------|----------------------------------------------------------------|
| `ungoverned` | DIRECT-capable but missing an owner or a reason                |
| `expired`    | `expiresAt` is in the past (a **malformed** `expiresAt` is treated as expired — fail-safe) |
| `review_due` | past `reviewCadenceDays` since `lastReviewedAt` (or never reviewed) |
| `governed`   | owned, justified, not expired, and review-current              |

**Node-local, not cluster-synced.** Governance records live in
`<dataDir>/pac_exceptions.json` (`0600`), are on the backup surface, and never
propagate CP→DP (a DP node does not need who-owns-this metadata to serve a PAC).
A corrupt file is quarantined to `pac_exceptions.json.corrupt` and the store
starts empty — governance metadata must never brick startup. After a failover,
restore the file on the promoted node. The PAC panel's **DIRECT Bypass
Inventory** card renders the status per row and (for admins) an inline
**Govern / Edit / Clear** editor.

**Evidence class: `config` (Observable) for the bypass; operator-attested for
ownership.** Governance metadata is asserted by an admin, not observed from
traffic — it says who *claims* this bypass and why, and it is only ever
attached to a bypass the configuration genuinely makes reachable.

## DIRECT bypass change-diff (posture)

The inventory is a snapshot; the change-diff answers *"what would this config
change do to the DIRECT surface?"* before you publish it.

`POST /api/pac/posture/diff` (viewer, read-only) takes a **candidate** steering
config in the body (`{profiles, pools}`) and returns how its DIRECT (full-
security-path) bypass surface differs from the **current active** config:

- `deltas[]` — each `profile_gained_direct` / `profile_lost_direct` /
  `path_added` / `path_removed`, with the profile, the DIRECT `kind`/`detail`,
  whether the path is `broad`, and `riskIncreasing`.
- aggregates — `profilesGainedDirect`, `profilesLostDirect`, `pathsAdded`,
  `pathsRemoved`, `broadPathsAdded`, and `riskIncreased` (true when the change
  adds any DIRECT surface; a pure narrowing/removal leaves it false).

A **broadening** (e.g. a rule changed from an exact domain to a wildcard) reads
as a removed narrow path **plus** an added `broad` path, so the risk signal
rides the addition. The diff is **order-insensitive**: reordering rules does not
change the *set* of DIRECT paths a profile can emit (that is capability, not
per-request routing — the latter is what `POST /api/pac/analyze` covers). The
proxy-host context is held constant across before/after, so the fail-open path
only appears in the diff when the profiles themselves change it.

**Evidence class: `config` (Observable).** The diff is a pure comparison of two
config-derived inventories — no traffic, no usage claim. The PAC panel's DIRECT
Bypass Inventory card has a **Change preview** section: it pre-fills the current
config, you edit the candidate, and it renders the added/removed/broadened
bypasses. Read-only — nothing is published (use the profiles editor's
draft→publish flow to apply a change).
