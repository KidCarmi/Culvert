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
