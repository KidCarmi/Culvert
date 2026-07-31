# F0 — Public SaaS URL-Category Feed Distribution (`feeds.culvertlabs.com`)

**Status:** DESIGN ONLY (F0), revision 2. No code, no CI, no GUI, no DNS, no R2,
no Cloudflare, no publishing. This document is the architecture-review gate.
Implementation (F1+) does not begin until F0 is approved.

**Product stage:** Culvert is **pre-GA — no customers, no production customer
deployments.** F0 therefore takes a clean breaking storage/protocol boundary now
rather than carrying permanent legacy compatibility. This governs §12 (legacy
store) and §13 (mirror protocol): a one-time lab migration + a single supported
protocol, not a customer-grade provenance reconstruction.

**Product boundary:** a **new, separate distribution product** from the release
catalog (`catalog.culvertlabs.com`). Separate bucket, custom domain, signing
identity, and pinned trust policy. Shared only: reusable *code* (the catalog's
fetch/verify/atomic-activate building blocks) and the **Sigstore public-good
trusted root** (a shared root, not a shared identity — §5). Never a shared bucket,
pointer, publisher, or credential.

---

## Revision-2 changelog (what changed vs rev 1)

| Blocker / decision | Resolution in this revision |
|---|---|
| B1 activation not durable | §8 replaces move-aside `current/.bak` with **immutable generations + one atomic `activation-state.json`**; single commit point; no cross-file transaction. |
| B2 crash discards `.bak` | §9 recovery reads the activation record, resolves + re-verifies the referenced generation; **never** infers from names/mtimes; GC only unreferenced. |
| B3 integrity normalized into acceptance | §7.4 now **rejects the whole candidate** on any collision (publisher + client); no winner-picking; adds **ancestor/descendant suffix** rejection. |
| B4 legacy provenance | §12 rewritten as a **pre-GA schema boundary** (backup + deterministic reset/migration + report + schema marker); no heuristic provenance reconstruction. |
| B5 custom-mirror protocol | §13: **only `signed_manifest_v1`**; no `legacy_raw_json_v0`, no unsigned fallback; unsupported URLs rejected with guidance; two historical URLs normalized. |
| B6 two-object manifest race | §4.1/§4.2 single self-contained **signed manifest envelope** object; one ETag, one purge target. |
| B7 freshness/replay | §10 fresh-install freeze/replay analysis: reject expired candidates, LKG→`stale`, 304 recomputes freshness, compiled max-validity + min-version checkpoint, documented residual window. |
| B8 CI privilege inconsistency | §11 sign job holds **no R2/CF creds**; publisher holds them and has **no OIDC**; **CAS/ETag fencing** on the envelope; honest R2 permission model (no false prefix-isolation claim). |
| Decisions 1–5 | `.sigstore` accepted (§4); F3a approved (§7); no operator `max_staleness` — `expires_at` + client bounds only (§10/§14); UT1 out of scope; envelope object adopted (§4). |
| Override/normalization | §7.5 exact suffix + normalization semantics. |
| Telemetry terminology | §14 `failures_since_start`, `compiled_trusted`, embedded/cached/downloaded provenance, 304 provenance. |

---

## 1. Scope (confirmed with review)

| Item | Decision |
|---|---|
| Public origin | `https://feeds.culvertlabs.com` |
| R2 bucket | dedicated `culvert-feeds` |
| Path prefix | `/v1/url-categories/saas/` |
| Feed protocol | **`signed_manifest_v1` only** (no unsigned mode, ever) |
| SaaS signed feed | **on by default** (§3) |
| Admin disable | supported, **durable across restart** via a sentinel (§3) |
| Manifest signature | **mandatory**, single self-contained envelope object (§4) |
| Artifact signature | **mandatory** (`.sigstore` sidecar) |
| Signing scheme | Sigstore **keyless**, separate feed identity, shared public-good root (§5) |
| Runtime credentials | **none** — anonymous HTTPS GET; in-binary verify |
| Embedded baseline | retained as offline bootstrap + `compiled_trusted` layer |
| UT1 community feed | **out of scope** (stays on its NethServer mirror; layer 4) |
| Rollback | monotonic-forward only; envelope never moves backward (§16) |
| Legacy store | pre-GA one-time migration/reset with backup + report (§12) |

---

## 2. Corrected current-state evidence

Verified against the working tree.

### 2.1 Historical built-in URLs (both migrate to the new endpoint)
- Current compiled default: `internal/saasfeed/saasfeed.go:37`
  `https://raw.githubusercontent.com/KidCarmi/Culvert/main/internal/urlcat/default_categories.json`
- Pre-`internal/urlcat`-move default (persisted on appliances that ran that build):
  `https://raw.githubusercontent.com/KidCarmi/Culvert/main/default_categories.json`

### 2.2 On-by-default via the compiled default (stale comment)
`main.go`: `initURLCategories` (**line 207**) precedes `initPersistentAdminState`/
`LoadAdminSettings` (**line 218**). `loadURLCategories` calls
`globalSaaSFeed.Configure(defaultSaaSFeedURL, 24h)` → `enabled.Store(true)` +
goroutine + immediate `Sync` (`saasfeed.go:114-154,131`). Fresh-install
`LoadAdminSettings` skips re-configure (`if s.SaaSFeedURL != ""`,
`admin_settings.go:315`). ⇒ **active by default**; the "Disabled by default"
comment (`urlcategories_startup.go:47`) is wrong. Target preserves on-by-default.

### 2.3 Explicit disable does not survive restart (sentinel gap)
`Stop()` sets `feedURL=""` (`saasfeed.go:168-181`); snapshot writes `SaaSFeedURL`
only when non-empty (`admin_settings.go:574`); next boot re-arms the default. Empty
string is ambiguous ("unset" vs "disabled") ⇒ sentinel required (§3).

### 2.4 Additive merge re-adds admin-removed hosts + mixes ownership
`mergeSaaSCategories` (`saas_feed.go:41-75`) adds any feed host not currently in the
store (`:59-68`), so an admin-removed feed host is re-added next sync (the
"removals preserved" comment `:39` is inconsistent). Also: incremental in-place
`catStore` mutation, cannot remove upstream-withdrawn hosts, feed/admin/shipped data
mixed under one `builtIn` bool (`urlcat.go:39-44`), single post-mutation `Save()`
(partial-persist hazard). This is why §7 replaces the merge.

### 2.5 Category-engine matching semantics (decisive for §7.4)
- **`matchCategory(cat, host)`** (`policy.go:1473`) → **`Store.MatchesHost`**
  (`urlcat.go:305-327`): **independent per-category suffix walk** — `sub.example.com`
  matches category *A* if *A* contains `example.com` (walk
  `sub.example.com`→`example.com`→`com`). A host can satisfy **multiple** categories
  at once. It is **not** longest-suffix-wins.
- **`lookupHostCategory`/`Store.LookupHost`** (`urlcat.go:334-347`, policy.go:1490)
  returns the **first entry in list order** — arbitrary/insertion-ordered; used only
  by the admin URL-lookup API, not the policy hot path.
- Normalization is `hostutil.NormalizeHost` (+ trailing-dot strip in the index,
  `urlcat.go:71`). The feed's normalization (§7.5) must be **parity-equal** to it.
- **Consequence:** an ancestor/descendant pair in different categories is genuinely
  ambiguous ⇒ §7.4 **rejects** such pairs rather than claiming a resolution the
  engine does not implement.

### 2.6 Reusable building blocks (catalog stack)
`release_catalog_http.go` (manifest-first, ETag pending→commit, dial-time SSRF +
redirect guard, bounded reads, UA); `release_catalog_verify.go`
(`verifyIndexSignature`, `NewTrustStoreWithSigstore`, tri-state `schemeOutcome`,
`bytesSignatureSource`); `release_catalog_sigstore.go` (offline keyless, baked
root); `release_catalog_freshness.go` (monotonic floor, fail-closed on corrupt
state); `internal/fileutil.AtomicWrite`; `internal/ssrf`.

---

## 3. Enablement & disablement (sentinel)

New `AdminSettings` fields (`admin_settings.json`):

| Field | Meaning |
|---|---|
| `saas_feed_managed` (bool) | operator has expressed explicit intent. Distinguishes "never touched" from "explicitly set." |
| `saas_feed_enabled` (bool) | explicit enable/disable; authoritative only when `managed`. |
| `saas_feed_url` (string) | custom mirror; empty ⇒ built-in endpoint. Never conflated with enable. |
| `saas_feed_protocol` (enum) | `signed_manifest_v1` (only supported value; §13). |

**Single-source resolution at startup** (replaces the 2.2/2.3 flow; the feed client
is armed from the *resolved* settings, not a compiled default a later load may or
may not override):

```
managed  = settings.saas_feed_managed
enabled  = managed ? settings.saas_feed_enabled : true      // preserve on-by-default
url      = settings.saas_feed_url != "" ? settings.saas_feed_url : builtinEnvelopeURL
protocol = signed_manifest_v1                               // enforced
!enabled → feed OFF (durable); serve embedded baseline (+admin overrides)
 enabled → poll `url`
```

Fresh install ⇒ `managed=false` ⇒ on-by-default. Explicit disable ⇒
`managed=true,enabled=false` ⇒ durable. Empty URL no longer means disabled.

---

## 4. Signed manifest envelope + immutable artifact contracts

### 4.1 Layout

```
https://feeds.culvertlabs.com/v1/url-categories/saas/
    manifest.sigstore.json              ← MUTABLE, self-contained SIGNED ENVELOPE (one object)
    <immutable-artifact>.json           ← IMMUTABLE, create-only
    <immutable-artifact>.json.sigstore  ← IMMUTABLE artifact bundle
```

`<immutable-artifact>` is read verbatim from the verified manifest payload's
`artifact_path` (validated as a safe relative key, §6.4). Producer naming:
`saas-<zero-padded feed_version>-<YYYYMMDD>.json`. **The mutable manifest is one
object** (B6): a single ETag, a single cache-purge target, and no
manifest/bundle observation race.

### 4.2 Manifest envelope object (`manifest.sigstore.json`)

An **untrusted outer wrapper** carrying the exact signed payload bytes + the
Sigstore bundle over those exact bytes:

```jsonc
{
  "payload_b64": "<base64 of the exact manifest-payload JSON bytes>",
  "bundle": { /* cosign keyless Sigstore bundle over the RAW decoded payload bytes */ }
}
```

Client rule (verify-before-parse, §6): fetch the bounded envelope → parse the outer
JSON as **untrusted** → base64-decode `payload_b64` to raw bytes → verify `bundle`
over those raw bytes against the pinned feed identity + shared root → **only then**
parse the payload JSON. A forged/invalid envelope ⇒ zero artifact fetches.

### 4.3 Manifest payload contract (the signed bytes)

All required.

```jsonc
{
  "schema_version": 1,                       // client rejects unknown major
  "protocol": "signed_manifest_v1",
  "feed": "url-categories/saas",             // canonical id (exact match)
  "feed_version": 42,                        // monotonic integer ≥ 1 (rollback floor)
  "generated_at": "2026-07-31T00:00:00Z",    // RFC3339 UTC
  "expires_at":  "2026-08-30T00:00:00Z",     // RFC3339 UTC; freshness + freeze bound (§10)
  "artifact_path": "saas-00000042-20260731.json",
  "artifact_sha256": "<64-hex>",
  "artifact_size": 148213,
  "artifact_sig_path": "saas-00000042-20260731.json.sigstore",
  "category_count": 21,
  "host_count": 1187                         // UNIQUE normalized host count
}
```

`feed` and `protocol` must match the client's expectations. `host_count`/
`category_count` are recomputed from the parsed artifact and must match. The
validity window `expires_at - generated_at` is bounded (§10).

### 4.4 Artifact contract (`<immutable>.json`)

```jsonc
{
  "schema_version": 1,
  "protocol": "signed_manifest_v1",
  "feed": "url-categories/saas",
  "feed_version": 42,                 // MUST equal the manifest's feed_version
  "generated_at": "2026-07-31T00:00:00Z",
  "categories": [ { "name": "AI", "hosts": ["anthropic.com","claude.ai", ...] }, ... ]
}
```

Hosts normalized + deduped (§7.5); **each host in exactly one category**, and **no
ancestor/descendant suffix pair across categories** (§7.4); categories and hosts
sorted for determinism. `feed`/`feed_version` bound inside the signed bytes prevent
cross-manifest/cross-feed replay.

### 4.5 Signature binding
Manifest envelope binds the artifact by `artifact_sha256`; verifying the manifest
signature then digest-matching the fetched artifact transitively authenticates it.
The artifact's own `.sigstore` bundle is required (defense-in-depth). Both verify
against the **same pinned feed identity** (§5).

---

## 5. Security model / trust (Sigstore keyless)

Trust boundary = the signatures, verified in-binary. R2 + Cloudflare = untrusted
transport.

- **Signing:** keyless cosign (Fulcio short-lived cert + Rekor), by a **dedicated
  feed signing workflow** distinct from the catalog's `ci.yml`.
- **Pinned identity (feed-specific):** separate certificate-identity + issuer
  policy anchored to the exact feed signing workflow file + tag ref pattern (issuer
  `https://token.actions.githubusercontent.com`; SAN e.g.
  `^https://github\.com/KidCarmi/Culvert/\.github/workflows/publish-feeds\.yml@refs/tags/feeds-v.*$`).
  A **separate pinned identity, NOT a separate cryptographic root.**
- **Trusted root:** the **shared Sigstore public-good `trusted_root.json`** already
  baked for the catalog (`release_catalog_sigstore.go:52-53`). No separate crypto
  root is claimed or provisioned. Overridable (public material only) via a
  feed-specific env, break-glass/fork.
- **Identity SSOT:** issuer/SAN in one `feeds_identity.env` + Go constants, pinned
  byte-equal by a test (mirrors `TestReleaseIdentitySSOT`).
- **Offline verify:** Rekor inclusion proof + integrated timestamp; nothing
  contacts sigstore.dev at runtime (air-gap safe).

Client controls: verify-before-parse (§6), artifact-path traversal gate, bounded
envelope + artifact reads, dial-time SSRF + redirect guard, monotonic floor
(fail-closed on corrupt state), validity-window + checkpoint bounds (§10).

---

## 6. Client fetch → verify → activate sequence

No live state changes until the activation commit (§8 step 4→5).

```
1. Fetch manifest.sigstore.json (bounded; If-None-Match with the last COMMITTED
   envelope ETag).
   - 304    → recompute freshness on the CURRENT active manifest (§10); NOT auto-healthy.
   - non-2xx→ keep current; record outcome; degraded.
2. Parse OUTER envelope (untrusted); base64-decode payload; verify the Sigstore
   bundle over the RAW payload bytes against the pinned feed identity + shared root.
   - FAIL/missing → keep current; F-verify; ZERO artifact fetches.
3. Parse the now-trusted payload. Validate: schema_version + protocol + feed;
   feed_version ≥ compiled checkpoint AND ≥ rollback floor (rollback/replay §10);
   generated_at not future (±skew); expires_at present AND not past;
   (expires_at - generated_at) ≤ compiled max validity; counts/sizes present.
   - a NEWLY FETCHED but already-EXPIRED manifest is REJECTED (never activated, §10).
4. Validate artifact_path + artifact_sig_path as SAFE RELATIVE IMMUTABLE KEYS
   (single segment under the prefix, no "..", no leading "/", allowed charset).
5. Fetch <artifact> with cap = min(artifact_size, MAX) via LimitReader(cap+1);
   reject if len != artifact_size or > MAX.
6. sha256(raw artifact) == artifact_sha256; fetch <artifact>.sigstore; verify its
   bundle over RAW artifact bytes against the SAME pinned identity. Both required.
7. Parse + NORMALIZE off-path (§7.5); assert single-category-per-host AND no
   ancestor/descendant cross-category pair (§7.4); recompute host_count/
   category_count and cross-check; assert artifact.feed_version == manifest.feed_version.
   Any failure → REJECT the WHOLE candidate; keep current; F-parse.
8. Build the immutable generation off-path and ACTIVATE atomically (§8).
9. On durable activation success only: COMMIT the pending envelope ETag.
```

Any failure ⇒ last-known-good preserved, live state untouched, outcome recorded,
ETag **invalidated** (never commit a rejected fetch's ETag).

---

## 7. Ownership & precedence model (replaces the additive merge)

### 7.1 Layers (highest precedence first)
1. **Administrator overrides/exceptions** — durable, admin-owned (§7.5).
2. **Active signed SaaS feed snapshot** — the last activated verified generation
   (feed-owned; replaced wholesale, never edited in place).
3. **Embedded SaaS baseline** (`go:embed`) — feed-owned layer when no valid
   generation exists (offline bootstrap / disabled). `compiled_trusted`.
4. **UT1 community fallback** — existing Layer-2 BadgerDB lookup (unchanged).

### 7.2 Feed-owned vs admin-owned separation (F3a)
- **Feed snapshot** (feed-owned): categories+hosts of layer 2 (or embedded).
  Immutable between activations; replaced as a whole unit (§8). Never edited by
  admin actions.
- **Admin overrides** (`overrides.json`, admin-owned, durable):
  ```jsonc
  { "added": {"example.com":"AI"}, "recategorized": {"slack.com":"Messaging"},
    "tombstones": ["tracker.example"] }
  ```
- **Composed effective view** = feed snapshot, then remove tombstones, apply
  recategorizations, union admin-added. Pure function; recomputed on activation and
  on override edits; it is what the policy engine reads.

Admin removals become **durable tombstones**, so a later feed cannot resurrect them
(fixes §2.4); a withdrawn feed host disappears because the whole snapshot is
replaced (only explicit admin-added hosts persist independently).

### 7.3 Cluster authority of overrides (answers B4-Q8)
URL categories are **fleet policy**, not appliance tuning. Therefore:
- **Admin overrides are CP-authoritative** and propagate CP→DP with the rest of
  policy (they belong on the `ConfigSnapshot` category surface, joining
  `URLCategories`/`CategoryGroups`). A DP does not independently edit overrides.
- **The feed snapshot generation is node-local runtime state** (like the release
  catalog): each node fetches + verifies + activates its own generation; the
  snapshot is **not** synced over `ConfigSnapshot` (volatile, re-derivable,
  signature-verified locally). The CP MAY additionally gate/observe feed enablement.
- `activation-state.json`, `generations/`, and the floor are **node-local**;
  `overrides.json` is CP-authoritative and synced. (This split is stated so F3a/F5
  wire it deliberately; the exact CP→DP field additions are an F3a design item, not
  built here.)

### 7.4 Conflict resolution — reject, never normalize into acceptance (B3)

| Scenario | Deterministic behavior |
|---|---|
| Same host in **multiple SaaS categories** (exact dup) | **Publisher REJECTS** at generation. **Client independently REJECTS the whole candidate.** No winner-picking. LKG preserved; bounded integrity failure recorded. |
| **Ancestor/descendant across categories** (`example.com`→A, `sub.example.com`→B) | **REJECTED at publisher AND client** (the engine's per-category suffix walk, §2.5, makes it ambiguous). The signed artifact must contain no host that is a suffix of another host in a different category. |
| Host in **both SaaS and UT1** | SaaS (layer 2) over UT1 (layer 4) — existing precedence. |
| Admin **recategorizes** | layer 1 wins over the snapshot. |
| Admin **tombstones** a feed host | layer 1 wins; absent from the view even if the feed re-lists it. |
| Feed **removes** a host | gone from layer 2 (wholesale replace); persists only if in admin `added`. |
| Feed **changes** a host's category | new snapshot category applies unless an admin `recategorized` pins it. |
| **Activation persistence fails** | no live change; LKG retained; F-persist; ETag invalidated (§8). |
| **Crash between staging and activation** | recovered via the activation record; no partial applied (§9). |

Integrity rejection is **all-or-nothing**: the candidate never partially activates,
and no category is inferred.

### 7.5 Override scope + host normalization (exact semantics)

**Override scope.** Tombstones, recategorizations, and additions key on a
**normalized host string** that carries the **same suffix semantics as a feed
entry** — i.e. a key `example.com` covers `example.com` **and all subdomains**
(matching `MatchesHost`'s suffix walk, §2.5). The admin GUI states this explicitly
("applies to host and its subdomains"). A tombstone suppresses the matching
feed-entry host; a recategorization re-points it; an addition inserts a new
feed-entry-equivalent host. This keeps overrides consistent with policy lookup.

**Normalization (producer + client + parity-equal to `hostutil.NormalizeHost`):**
- lowercase; strip a single trailing dot; collapse to the DNS name only (no scheme,
  userinfo, port, or path);
- **IDNA2008 / UTS-46 non-transitional**: convert U-labels to A-labels (punycode);
  store the A-label. **Reject** names that fail UTS-46 conversion.
- **Reject** wildcards (`*`, `?`), empty labels (`a..b`, leading/trailing dot after
  the single-trailing-dot strip), labels violating LDH or hyphen rules, label
  length > 63, total length > 253.
- **Reject IP literals** (IPv4/IPv6) — feed hosts are DNS names only.
- **Reject public-suffix-only entries** (e.g. `com`, `co.uk`): a bare public suffix
  would over-match via the suffix walk. The producer rejects; the client
  re-validates. (Public-suffix boundary from a bundled PSL snapshot; the PSL source
  is an F1 detail.)

Normalization runs at publish time (deterministic artifact) and is re-asserted by
the client; a mismatch between the artifact's stated hosts and their normalized
form ⇒ candidate rejected.

---

## 8. Activation transaction — immutable generations + atomic record (B1)

On-disk layout:

```
<dataDir>/saas_feed/
  generations/<feed_version>/
    manifest.envelope.json        ← exact fetched envelope bytes
    artifact.json                 ← exact fetched artifact bytes
    artifact.json.sigstore        ← exact fetched artifact bundle
    snapshot.normalized.json      ← normalized feed-owned snapshot (derived off-path)
  activation-state.json           ← THE single activation authority
  overrides.json                  ← admin-owned (CP-synced, §7.3)
```

`activation-state.json` (single atomic write via `fileutil.AtomicWrite`):

```jsonc
{
  "schema_version": 1,
  "active_feed_version": 42,
  "active_generation": "generations/42",     // relative
  "rollback_high_watermark": 42,             // = max(prev floor, active); ≥ active
  "generated_at": "2026-07-31T00:00:00Z",
  "expires_at":  "2026-08-30T00:00:00Z",
  "artifact_sha256": "<64-hex>",
  "envelope_sha256": "<64-hex>",             // integrity of the stored envelope
  "committed_etag": "\"…\"",                  // manifest-envelope ETag committed at activation
  "activated_at": "2026-07-31T09:14:02Z"
}
```

**Ordering (the only correct sequence):**
1. Build the entire immutable generation dir **off-path** (temp dir), write all
   four files.
2. **Re-verify all stored bytes** (envelope bundle + artifact bundle + digest
   against the pinned identity) and **fsync** each file **and** the generation
   directory. Then rename the temp dir to `generations/<feed_version>` (if the
   target already exists it must be byte-identical, else integrity error).
3. Build the composed effective view in memory — **do not publish it**.
4. `AtomicWrite(activation-state.json)` — **the commit point**: atomically binds
   active generation + rollback floor + committed ETag + digests. No cross-file
   transaction.
5. **Only after (4) succeeds:** `atomic.Pointer[EffectiveView].Store(view)` — the
   serving cutover (lock-free reads).
6. A failure **before (5)** changes **no** live state (in-memory pointer untouched;
   the old activation record still governs disk).
7. A crash **after (4), before (5)** is recovered on boot by loading the newly
   committed record (§9) — disk is ahead of memory, the process is dead, the system
   converges to the newer verified generation.

The activation record **must never reference a generation that has not been fully
written, fsynced, and verified** (steps 1–2 precede step 4). ETag commit is folded
into the record (step 4), so there is no separate floor/ETag write to lose.

---

## 9. Crash-recovery matrix (B2)

**Recovery is record-driven, never name/mtime-driven.**

Boot sequence:
1. Read `activation-state.json`.
2. Resolve `active_generation`; **re-verify** its `manifest.envelope.json`,
   `artifact.json`, `artifact.json.sigstore`: bundle signatures against the pinned
   identity, `artifact_sha256`, `envelope_sha256`, schema, feed, feed_version ==
   dir. Load only if valid.
3. Feed-owned layer := the verified generation's `snapshot.normalized.json`
   (re-derived/checked). Compose with `overrides.json` (§7.2).
4. Floor := `rollback_high_watermark` (never below the compiled checkpoint, §10).
5. GC: `generations/*` and any temp/partial dirs **not referenced** by the record
   may be removed **only after** proving they are unreferenced (optionally retain
   the last N verified generations as rollback candidates).

| Interruption point | On-disk state | Recovery |
|---|---|---|
| During off-path build (temp) | temp dir only; record unchanged | Serve prior active gen (record intact); GC temp. |
| After gen fsync/rename, **before** record write | `generations/<v>` exists; record still points at old | Serve old (record authority); new gen is an orphan → GC after proving unreferenced. |
| After record write, **before** pointer store | record → new gen; memory still old; process dead | Boot loads record, re-verifies new gen, serves new. Converged. |
| Record write torn / corrupt | record unreadable/invalid | **Fail closed on rollback state**: serve **embedded baseline**, `active_source=embedded`, `signature_status=compiled_trusted`, emit a **critical** operational signal; do **not** select the highest directory. Floor treated as unknown ⇒ re-established only by the next verified fetch, bounded by the compiled checkpoint (§10). Residual risk noted (§17). |
| Missing record (first ever / fresh install) | no generations | Feed-owned layer = embedded baseline; `active_source=embedded`; floor = compiled checkpoint. Normal. |
| Referenced gen fails re-verification | record points at a now-invalid gen (tamper/bit-rot) | Discard that gen; fall back to embedded baseline; `degraded`/critical signal; next fetch re-establishes. |

No path deletes the only last-known-good: the previous generation is only GC'd
after a **new** record commits referencing a **new** verified generation.

---

## 10. Freshness, fresh-install replay & freeze analysis (B7)

**`expires_at` is a security control (freeze/replay mitigation), not cosmetic.**

Client rules:
- **Newly fetched, already-expired manifest ⇒ REJECTED** (never activated).
- **Active LKG that crosses expiry ⇒ keep serving, state `stale`** (never fail
  closed on age — a valid snapshot stays usable).
- **304 recomputes freshness** on the current active manifest; it does **not** mean
  `healthy`. If the active manifest is expired, a 304 leaves/moves state to
  `stale`. Near/after expiry the client performs an **unconditional refetch** (no
  `If-None-Match`) so a CDN cannot pin staleness via a false 304.
- **Max validity window:** reject if `expires_at - generated_at >
  COMPILED_MAX_VALIDITY`.
- **Future-dated:** reject `generated_at` beyond a bounded clock skew.
- **Compiled minimum feed-version checkpoint:** each Culvert build bakes
  `COMPILED_MIN_FEED_VERSION` (the feed_version current at build time, or a
  conservative floor). A fresh install rejects any manifest with `feed_version <`
  checkpoint, so a fresh box cannot accept versions older than its own build.
- **Rollback floor:** `feed_version` must be ≥ `rollback_high_watermark`
  (fail-closed on corrupt record, §9).

**Chosen constants (justified, not the catalog's 6-month value):**
- `COMPILED_MAX_VALIDITY = 30d`. SaaS publication cadence is daily–weekly; 30d
  tolerates a multi-week CI/publishing outage without failing fresh installs, while
  bounding the replay/freeze window to ≤30d. A compiled constant, revisited if the
  cadence changes.
- Clock skew = 5m (matches the catalog).

**Documented residual replay window (fresh install):** a compromised CDN can replay
a *valid, correctly-signed* manifest whose `feed_version ≥ COMPILED_MIN_FEED_VERSION`
and that is **not yet expired**. The residual freeze window is bounded by
`min(remaining validity, time since the build checkpoint)` ≤ `COMPILED_MAX_VALIDITY`
(30d). This is inherent to offline signature trust without an online freshness
oracle; `expires_at` + the compiled checkpoint bound it. An already-provisioned box
is additionally protected by its persisted floor.

---

## 11. Publishing sequence + CI privilege separation + CAS fencing (B8)

### 11.1 Two-job privilege model (a real boundary, not named steps)

**Job A — generate + sign** (`.github/workflows/publish-feeds.yml`, generate job):
- `permissions: contents: read, id-token: write`. **No R2 credential. No
  Cloudflare credential.** It cannot write anything to R2.
- validate source → deterministically generate + normalize the artifact →
  compute counts + SHA-256 → keyless-sign the artifact → build + keyless-sign the
  manifest **envelope** → emit `{artifact.json, artifact.json.sigstore,
  manifest.sigstore.json, metadata.json}` as a **GitHub Actions workflow
  artifact** (not R2).

**Job B — publish** (same workflow, publish job; `needs: A`):
- `permissions: contents: read`. **No `id-token`.** Holds **narrowly scoped R2
  write + Cloudflare cache-purge** secrets (repository/environment secrets; a
  merged workflow edit inherits them ⇒ CODEOWNERS on the file; optional `release`
  environment approval).
- downloads Job A's workflow artifact → **re-verifies every signed input with the
  production in-binary verifier** (baked root + pinned feed identity) →
  §11.2 sequence.

**PR-untrusted runs:** receive neither production OIDC signing identity nor
publishing credentials. Job B is dormant-gated (`FEEDS_PUBLISH_ENABLED`) and runs
only via `workflow_run` on a signed tag context, default-branch workflow copy,
`harden-runner egress: block` (allow `feeds.culvertlabs.com`,
`*.r2.cloudflarestorage.com`, `api.cloudflare.com`).

### 11.2 Publish sequence (fail-closed; no public staging prefix)

```
 1. (Job A) validate source; deterministic generate + normalize; single-category +
    no ancestor/descendant enforcement (REJECT on collision); counts + SHA-256
 2. (Job A) sign artifact (.sigstore); build + sign manifest envelope; emit workflow artifact
 3. (Job B) re-verify artifact + manifest envelope with the production verifier
 4. upload the IMMUTABLE artifact + .sigstore to their FINAL create-only keys
    (put-object --if-none-match '*'; a 412 ⇒ must be byte-identical else ABORT)
 5. retrieve the artifact + .sigstore THROUGH feeds.culvertlabs.com (public path)
 6. verify the PUBLIC bytes with the production verifier (digest, size, counts, identity)
 7. CAS-guarded envelope promote (§11.3): publish manifest.sigstore.json LAST
 8. purge ONLY the manifest envelope URL from the CDN
 9. retrieve + verify the PUBLIC envelope (bundle + payload + points at the verified artifact)
10. confirm convergence (public envelope digest == published) before success
```

Invariant: **the manifest envelope must never reference an artifact that has not
already been publicly retrieved and verified** (4–6 precede 7). Any gate failure
aborts **without** promoting the envelope; the previous live envelope is untouched.

### 11.3 Concurrency + compare-and-swap fencing
- A `concurrency: group: feeds-publish, cancel-in-progress: false` serializes
  publications.
- Promotion is a **conditional write**: read the current live envelope's ETag +
  embedded `feed_version`; require the new `feed_version` **strictly greater**;
  `put-object` the new envelope with an **`If-Match: <current-ETag>`** precondition
  (first publish uses `If-None-Match: '*'`). A concurrent/stale publisher's
  conditional write **fails (412)** ⇒ abort without overwriting a newer envelope.
- The live `feed_version` is read from the **R2 origin** (authenticated S3 API),
  not the CDN, so the CAS check is not fooled by edge caching.

### 11.4 Honest R2 permission model (no false prefix-isolation claim)
R2 S3 tokens scope to a **bucket** (and can be read-only vs read-write); **per-key-
prefix write ACLs are not reliably enforceable** via S3 tokens. So F0 does **not**
claim the publisher's token is prefix-isolated. The real boundary is that **Job A
holds no R2 token at all** (cannot write anything), while **Job B** holds a
bucket-scoped write token. Artifact immutability comes from **create-only
`--if-none-match '*'` + public re-verification**, and envelope safety from the
**CAS `If-Match`** guard — not from credential prefix scoping.

---

## 12. Legacy `categories.json` migration (pre-GA schema boundary, B4)

Pre-GA (no customers): a **one-time, deterministic lab migration**, not a
provenance-reconstruction engine.

1. **Declare a schema boundary.** Add a `saas_store_schema_version` marker to the
   new stores so future upgrades have a real migration edge.
2. **Recoverable backup first.** Before any conversion, copy the existing
   `categories.json` **and** `admin_settings.json` to timestamped siblings
   (`categories.json.pre-f3a-<ts>.bak`, etc.) via `fileutil.AtomicWrite`. **Never
   silently delete the old store.**
3. **Deterministic initialization (no heuristic provenance):**
   - Feed-owned layer := the **embedded baseline** (or the first verified signed
     snapshot once fetched). The old mixed store's feed-derived entries are **not**
     carried into feed-owned data.
   - Admin-overrides store := initialized **empty**, then conservatively seeded:
     entries in the old store that are **not** present in the embedded baseline are
     recorded as admin **`added`** (best-effort preservation of possible operator
     intent); nothing is inferred as a tombstone or recategorization (that would
     require provenance we do not have).
   - Stale historical *feed* additions in the old store that happen to match the
     embedded baseline are **dropped** (they belong to feed-owned data, now
     re-derived) so they do not become immortal admin overrides.
4. **Migration report.** Emit a machine- + human-readable report:
   `{preserved_as_admin_added:[…], dropped_as_feed_derived:[…],
   requires_manual_review:[…]}` and log a summary. Ambiguous entries (e.g. an old
   entry that is an ancestor/descendant of a baseline entry) go to
   `requires_manual_review` rather than being force-classified.
5. **When intent cannot be inferred:** preserve conservatively as admin `added` +
   flag in `requires_manual_review`; never destructive.
6. **Downgrade:** after the new schema activates, **downgrade compatibility to older
   Culvert binaries is NOT guaranteed** (documented). The timestamped backup is the
   manual recovery path.
7. **Reset alternative (lab):** a documented explicit reset procedure
   (`--reset-saas-store`) that backs up then reinitializes from the embedded
   baseline + empty overrides, for clean lab boxes.

This gives deterministic behavior, backup, migration-op rollback (restore the
backup), and no silent data loss — without customer-grade intent inference.

---

## 13. Custom-mirror protocol compatibility (B5 — `signed_manifest_v1` only)

**The only supported feed protocol is `signed_manifest_v1`.** No
`legacy_raw_json_v0`, no unsigned mode, no automatic fallback.

- The built-in `feeds.culvertlabs.com` endpoint uses `signed_manifest_v1`.
- Any admin-configured mirror **must** implement the same signed
  manifest-envelope + immutable-artifact + Sigstore-bundle + monotonic-version
  contract.
- **The two exact historical Culvert GitHub URLs (§2.1) are normalized** to the new
  built-in endpoint (cheap, deterministic, cleans up lab state).
- **Any other non-empty raw-JSON URL is rejected** at settings validation with a
  clear message + migration instructions (point it at a `signed_manifest_v1`
  mirror or the built-in endpoint). It is **never** silently accepted as trusted
  feed data, and there is **no** silent try-signed-then-fall-back-to-raw path
  (that would be a downgrade vector).
- New custom mirrors default to `signed_manifest_v1` (the only value).
- **`saas_feed_protocol`** is a first-class field across **admin settings,
  export/import, config-version rollback, OpenAPI (`make api-bundle`), CP→DP
  ConfigSnapshot, and the GUI**. (Only one legal value today, but the field exists
  so a future scheme is an explicit, versioned change — not a silent behavior flip.)
- **Private/internal mirrors:** **not supported.** The canonical SSRF dialer
  rejects private destinations, and F0 does **not weaken it**. A mirror must be a
  public HTTPS origin. (An air-gap path, if ever needed, would be a separate signed
  *bundle* import like the catalog's `bundleProvider`, not a private HTTP mirror —
  out of scope here.)

---

## 14. Operational status / telemetry (corrected terminology)

**States:** `disabled` · `never_succeeded` · `healthy` · `degraded` · `stale`.

```
disabled          ─enable→ never_succeeded
never_succeeded   ─activation ok→ healthy   ─fail→ degraded ─ok→ healthy
healthy/degraded  ─now>expires_at→ stale    ─fresh activation→ healthy
any (enabled)     ─disable→ disabled
```

Corrections:
- **Health derives from recent outcome + active source, not the lifetime failure
  total.** A historical failure never keeps the feed unhealthy after a later
  successful activation.
- **`degraded`** = ≥1 successful activation exists but recent attempts fail; LKG
  still served.
- **`stale`** = serving a valid-but-expired snapshot; never fail closed on age.
- **`never_succeeded` while the embedded baseline is active:** valid, expected;
  `active_source=embedded`, categories ARE available (the baseline). "no successful
  download yet" ≠ "no categories."
- **`disabled` while embedded active:** same — embedded baseline serves.
- **Embedded signature status = `compiled_trusted`** (a distinct value, NOT
  `unverified`).
- **After restart**, a verified downloaded generation loads as
  `active_source=cached`.
- **After a 304**, no new activation occurs: `active_source` stays
  `cached`/`downloaded` per the activation provenance; only freshness is
  recomputed.
- **`context.Canceled` during shutdown is not a failure** (excluded from counters
  and never flips to `degraded`).

Fields (read-only; admin API + panel):

| Field | Notes |
|---|---|
| `state` | one of the five |
| `last_attempt` / `last_success` | RFC3339 (success nullable) |
| `last_outcome` | `ok` / sanitized failure class |
| `active_feed_version` | integer or null |
| `active_source` | `downloaded` / `cached` / `embedded` |
| `consecutive_failures` | resets to 0 on success |
| `failures_since_start` | **process-lifetime** counter (renamed from "cumulative"; matches Prometheus process-counter semantics — display only, NOT a health input) |
| `last_error_class` | sanitized enum (fetch / verify / parse / persist / http_status) |
| `last_http_status` | when applicable |
| `last_activation_delta` | hosts added/removed/changed by the **last successful** activation; **null in `never_succeeded`** (never render "0 new hosts") |
| `signature_status` | `verified` / `failed` / `compiled_trusted` (embedded) |
| `manifest_expires_at` + `expires_in_days` | freshness |

GUI parity (CLAUDE.md): state + fields on `/api/…` (viewer read); enable/disable +
mirror URL + protocol are admin writes with `saveConfigVersion`.

---

## 15. Migration matrix (persisted `saas_feed_url`)

One-way normalization at settings load (mirrors the retired `unauth_mode`
migration).

| Persisted `saas_feed_url` | Class | Action |
|---|---|---|
| `""` / absent | unset | Use built-in envelope endpoint; no rewrite; no spurious `managed`. |
| `…/main/default_categories.json` (pre-move) | historical built-in | Rewrite → built-in `feeds.culvertlabs.com` envelope URL. |
| `…/main/internal/urlcat/default_categories.json` (current) | historical built-in | Rewrite → built-in envelope URL. |
| already the built-in envelope URL | migrated | No-op (idempotent). |
| any other non-empty value | custom mirror | **Reject** at validation unless it is a `signed_manifest_v1` mirror (§13); never rewritten, never silently trusted as raw JSON. |

- Idempotent; exact-string match only (no substring/prefix matching that could
  catch a fork).
- **Durable-persistence-failure:** if writing migrated settings fails, migration is
  **not** marked applied; the in-memory resolved URL still targets the correct
  endpoint for this run; re-attempted next boot; **never** falls back to the old
  GitHub URL.

---

## 16. Rollback model

- **The envelope only advances.** To withdraw a bad `feed_version` (43), publish a
  **higher** version (44) carrying the previously-approved dataset (e.g.
  v42-equivalent). Example: bad=43, corrective=44 with v42 data.
- **Immutable artifacts are never overwritten or deleted** in routine rollback; 44
  is a new create-only artifact; the envelope repoints to 44 via CAS (§11.3).
- **Client floor never weakened for normal operations** — the monotonic
  `rollback_high_watermark` keeps rejecting `feed_version <` floor; a stale/replayed
  43 cannot re-pin. Same-version re-sign is refused unless `generated_at` is
  strictly newer (replay guard).
- **Break-glass** (emergency floor reset on a compromised box; forced re-seed) is
  documented **separately** and does not relax the normal client floor.

---

## 17. Threat model

| # | Threat | Mitigation |
|---|---|---|
| T1 | MITM/compromised R2 or CDN tampers bytes | in-binary Sigstore verify over raw bytes; transport untrusted; tamper never activated. |
| T2 | Forged/unsigned manifest drives attacker fetches | verify-before-parse on the envelope; zero artifact fetches until it verifies (§6.2). |
| T3 | Two-object manifest/bundle race → false failures | single self-contained envelope object (§4.2). |
| T4 | Signature strip / scheme downgrade | mandatory manifest + artifact bundles; single protocol; no unsigned fallback (§13). |
| T5 | Rollback/downgrade to older feed | monotonic floor in the atomic record; envelope-advances-only + CAS (§11.3, §16). |
| T6 | Same-version re-sign replay | equal-version refused unless strictly newer `generated_at`. |
| T7 | Fresh-install replay/freeze of a still-valid old manifest | compiled min-version checkpoint + max-validity window + `expires_at` enforcement; residual window documented (§10, §17-note). |
| T8 | Path traversal via `artifact_path` / version key | safe-relative-key validation (client) + strict version-string validation (publisher key segment). |
| T9 | Oversize / decompression DoS | bounded envelope + artifact reads `LimitReader(cap+1)`; `artifact_size` precheck; MAX cap. |
| T10 | SSRF / DNS-rebind (incl. admin mirror) | inline `url.Parse`+scheme+`isPrivateHost`; dial-time SSRF on resolved IP; redirect guard ≤5; private mirrors unsupported (§13). |
| T11 | Cross-feed / cross-version substitution | `feed` + `protocol` + `feed_version` equality checks in envelope and artifact. |
| T12 | Integrity collision smuggled into live state | whole-candidate rejection at publisher AND client; ancestor/descendant rejection (§7.4). |
| T13 | Partial activation / crash corrupts live feed | immutable generations + atomic activation record; record-driven recovery; LKG never deleted early (§8, §9). |
| T14 | Admin-removed host resurrected by feed | durable tombstones (§7.2). |
| T15 | CI signing-key/credential compromise | keyless (no long-lived key); pinned feed identity; **sign job has no R2/CF creds**; publisher has no OIDC; PR runs get neither (§11.1). |
| T16 | Concurrent/stale publisher overwrites a newer envelope | serialize + CAS `If-Match` on the origin ETag + strictly-greater version (§11.3). |
| T17 | Malicious PR alters publisher to exfiltrate secrets | default-branch workflow copy on `workflow_run`; dormant gate; egress-blocked runner; CODEOWNERS/environment. |

**Residual (accepted, documented):** T7 fresh-install replay within
`min(remaining validity, time since build checkpoint) ≤ 30d`; and the §9
corrupt-record path temporarily loses the persisted floor (re-established by the
next verified fetch, bounded by the compiled checkpoint). Both are inherent to
offline signature trust without an online freshness oracle.

---

## 18. Test matrix (authored with their slices)

**Migration/URL (F4):** unset; both historical URLs rewritten; other URL rejected
with guidance; already-migrated no-op; persistence-failure not-applied + no
old-URL fallback; idempotency.

**Enablement/sentinel (F4):** fresh on-by-default; explicit disable survives
restart; explicit enable survives restart; disabled+custom-URL coherent; empty ≠
disabled.

**Envelope/signature (F2/F3):** valid accept; forged envelope ⇒ zero artifact
fetches; tampered payload ⇒ reject; forged artifact ⇒ reject; wrong SAN / wrong
issuer ⇒ reject; cross-feed / cross-protocol / artifact.feed_version mismatch ⇒
reject.

**Freshness/replay (F3, §10):** expired candidate on first install rejected; active
LKG crossing expiry ⇒ `stale` but served; 304 after expiry ⇒ `stale`; validity
window > compiled max ⇒ reject; feed_version < compiled checkpoint ⇒ reject; future
`generated_at` beyond skew ⇒ reject; documented residual replay within the window.

**Integrity (F1/F3, §7.4):** exact multi-category dup rejected (publisher + client);
ancestor/descendant cross-category rejected; whole-candidate rejection (no partial
activation, no winner-pick).

**Normalization/override (F1/F3a, §7.5):** trailing-dot; IDNA/UTS-46 A-label; reject
non-convertible Unicode; reject wildcard/IP-literal/public-suffix-only/empty-label/
over-length; override host+subdomain scope matches `MatchesHost`.

**Ownership/precedence (F3a, §7.4):** SaaS∩UT1; admin recategorize; admin tombstone
not resurrected; feed removes host; feed changes category; activation-persist fail;
crash between staging and activation.

**Activation/crash (F3, §8/§9):** each interruption row; record-driven recovery;
corrupt record ⇒ embedded baseline + critical signal (not highest-dir); missing
record ⇒ embedded; referenced-gen re-verify failure ⇒ fallback; LKG never GC'd
before a new record commits.

**Telemetry (F7, §14):** each transition; `never_succeeded` renders null delta;
recovery after prior failures; embedded ⇒ `compiled_trusted`; restart ⇒ `cached`;
304 provenance unchanged; `context.Canceled` not counted; `failures_since_start`
naming.

**Publisher/CI (F5, §11):** deterministic generation (byte-stable);
single-category + ancestor/descendant rejection; unique host_count; create-only
immutability (412 ⇒ byte-identical or abort); envelope-references-only-verified-
artifact ordering; CAS `If-Match` strictly-greater version; concurrent publisher
412 without overwrite; abort-without-promote on any gate fail; version-string
traversal guard; **sign job has no R2/CF creds; publish job has no OIDC**.

**Legacy migration (F3a, §12):** backup created before conversion; embedded-derived
entries dropped; non-baseline entries preserved as admin `added`; ambiguous ⇒
`requires_manual_review`; report emitted; old store not deleted; schema marker
written; reset procedure.

---

## 19. Phased implementation plan (independently reviewable gates)

Each gate is separately reviewable; each preserves prior invariants. Nothing past
F0 starts until F0 is approved; each later gate is its own review.

| Gate | Delivers | Depends | Review focus |
|---|---|---|---|
| **F0** | this design | — | architecture (this review) |
| **F1** | deterministic generator + envelope/artifact schemas + normalization/dedup + single-category & ancestor/descendant rejection + determinism test | F0 | producer correctness + integrity rejection |
| **F2** | feed signing identity (SSOT + test) + keyless verifier wiring (shared root, pinned feed identity) + envelope verify | F1 | trust terminology + identity pinning |
| **F3a** | ownership refactor (feed-snapshot vs admin-overrides, tombstones, CP-authoritative overrides) + **legacy pre-GA migration** (§12) + schema marker | F0 | precedence + migration safety + CP/DP split |
| **F3b** | client downloader: manifest-envelope-first, verify-before-parse, size/path/digest/sig, off-path build, **immutable-generation atomic activation** (§8), **record-driven crash recovery** (§9), freshness/replay (§10) | F2, F3a | activation transaction + recovery |
| **F4** | URL migration (both) + enablement sentinel + protocol field + durable disable | F3b | migration matrix + sentinel |
| **F5** | CI publisher (`publish-feeds.yml`, dormant): two-job privilege split + §11.2 sequence + CAS fencing; workflow-invariant tests | F1, F2 | privilege boundary + CAS |
| **F6** | IaC (`cloudflare_r2_bucket "culvert-feeds"`) + `docs/operator/feeds-hosting-r2-activation.md` (DNS/domain/cache/purge/enable) | F5 | owner-applied activation |
| **F7** | GUI/status: §14 state machine + fields + protocol; export/import/rollback/OpenAPI/CP-DP wiring for the protocol field | F3b, F4 | telemetry + parity |

Suggested first PR after F0 approval: **F1 + F2** (generator + trust kernel; no
client, no CI, no live behavior change).

---

## 20. Remaining explicit risks / open items

1. **Fresh-install replay residual (T7):** bounded to ≤30d by
   `COMPILED_MAX_VALIDITY` + the compiled version checkpoint; inherent to offline
   trust. Accept, or add an (out-of-scope) online freshness oracle later.
2. **Corrupt activation-record floor loss (§9):** temporarily reopens replay to the
   compiled checkpoint until the next verified fetch. Accept as fail-closed
   behavior, or add a second floor mirror (small added complexity) — flagged for
   F3b review.
3. **CP→DP override authority (§7.3):** F0 declares overrides CP-authoritative and
   the snapshot node-local; the exact `ConfigSnapshot` field additions + parity-test
   wiring are an F3a design item, not settled here.
4. **`COMPILED_MAX_VALIDITY = 30d` and `COMPILED_MIN_FEED_VERSION`** are proposed
   constants tied to an assumed daily–weekly cadence; confirm the intended
   publication cadence so these are right-sized.
5. **PSL source for public-suffix rejection (§7.5):** bundled snapshot vs a smaller
   curated TLD set — an F1 detail; flagged.
6. **R2 conditional-write (`If-Match`) support (§11.3):** relied on for CAS; verify
   against R2's S3 semantics at F5 (fallback: a version/lease object) — flagged, no
   live check performed in F0.
