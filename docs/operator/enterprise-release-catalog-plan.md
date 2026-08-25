# Enterprise Release Catalog Plan

> **Status: Phases 1–5 implemented; legacy updater REMOVED.** The legacy Docker
> updater sidecar was fully removed on 2026-07-11 (DEBT-008, ✅ CLOSED — see
> `docs/engineering/TECHNICAL-DEBT-REGISTER.md`); there is no `updater/` module
> or fallback path left in the tree. Catalog dispatch through the maintenance
> agent (`release_dispatch*.go` → agent `/v1/upgrades/apply`) is the sole update
> path. The "legacy updater stays available as a fallback" language below and
> the Phase 6 "keep the legacy Docker updater installed" step describe the
> ORIGINAL plan and are now historical — treat them as superseded by the
> DEBT-008 closure. For current day-2 operational guidance, see
> [`release-management-agent.md`](release-management-agent.md).

This plan moves Culvert from a local integrity-only catalog to an enterprise-grade
release channel that can safely replace the legacy Docker updater after it is
proven in production. The legacy updater stays available as a fallback until the
acceptance gates below are green on real installs.

## Goals

- End users can update Culvert through Release Management without mounting the
  Docker socket into the proxy and without using the legacy updater sidecar.
- Every update is selected from trusted metadata and executed as an immutable
  `repo@sha256:<digest>` reference.
- Fresh installs can discover the official catalog automatically, but only after
  signature, freshness, and repository checks pass.
- Air-gapped operators can mirror images and catalogs without weakening
  verification.
- CI proves the catalog path works end to end and fails closed for tampering,
  stale metadata, repo mismatch, mutable tags, and agent/digest failures.

## Non-Goals

- Do not delete the legacy Docker updater in this plan.
- Do not auto-trust catalogs because they were downloaded from GitHub, a release
  asset, or any HTTPS URL.
- Do not store private signing keys, registry credentials, or access tokens in
  the repository, container image, installer, docs, or public catalog.
- Do not dispatch mutable tags or allow fallback from digest references to tags.

## Target Architecture

```text
Release CI
  -> builds image
  -> resolves image digest
  -> signs image/provenance
  -> writes release catalog metadata
  -> signs catalog metadata
  -> publishes catalog bundle

Installer / Control Plane
  -> downloads or reads catalog bundle
  -> verifies trust root, signatures, freshness, rollback counters, hashes
  -> exposes /api/releases
  -> dispatches repo@sha256 digest to culvert-maint
  -> polls operation
  -> verifies running digest equals catalog digest
```

The production design should look like a lightweight TUF-style update channel:
separate trust roots, signed targets, freshness metadata, rollback protection,
and clear key rotation. Culvert can start with its existing catalog schema and
grow toward fuller TUF roles only when needed.

## Phase 1: Trusted Catalog MVP

Deliver a secure first production path without overbuilding.

### Central rule — verification primitives are not enough; wiring must enforce

The single most important Phase 1 property is that **production wiring actually
enters `VerifyEnforce`**. Having signature/freshness primitives in the codebase
is worthless if the default boot path runs permissive with no trust roots. The
binding rule (`release_wiring.go::resolveCatalogVerifyMode`):

- **Trust roots present (baked ed25519 OR `CULVERT_RELEASE_CATALOG_TRUST_KEYS`
  OR the baked Sigstore root, see P2b-2a below) ⇒ `VerifyEnforce`.** This is
  automatic and is the only production mode.
- **No roots and no override ⇒ Release Management is DISABLED** (enforce with an
  empty ring fails closed in `NewTrustStore`). An unsigned catalog on disk is
  **never** auto-trusted — `/api/releases` reports `available:false`. **This is
  no longer the default posture of a stock build**: since P2b-2a baked the real
  Sigstore public-good `trusted_root.json` into the binary, `nSchemes` is never
  zero unless an operator explicitly empties
  `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT` — so a plain `go build` today enters
  `VerifyEnforce` and, per the baked `defaultReleaseCatalogURL` (M1-2), attempts
  a live auto-seed fetch against `catalog.culvertlabs.com` with zero
  configuration. See `docs/operator/sigstore-trusted-root-lifecycle.md`.
- **Permissive / disabled are EXPLICIT break-glass only**, via
  `CULVERT_RELEASE_CATALOG_VERIFY=permissive|disabled`, read once at startup, and
  always logged with a loud warning. Permissive accepts an *unsigned* catalog but
  still rejects a present-but-invalid signature; disabled skips verification
  (local dev only). There is no other path to a non-enforce mode.

This mirrors the existing `CULVERT_C2_ENFORCE` kill-switch convention: secure by
default, relax only by deliberate, visible opt-in.

### Status

Implemented:

- ✅ Baked trust-root seam (`bakedReleaseTrustKeysJSON`, linker-injected at
  official-build time; PUBLIC keys only) + operator extension via
  `CULVERT_RELEASE_CATALOG_TRUST_KEYS`; the two are merged into one ring.
- ✅ Enforce-by-default wiring (the central rule above); break-glass env.
- ✅ ed25519 detached-signature verification over the raw index (pre-existing),
  now actually engaged in the production holder.
- ✅ `expires_at` and `catalog_version` in the index schema (structurally
  tolerant load; **enforced** in enforce mode).
- ✅ Freshness gate: reject expired catalogs and future-dated `generated_at`
  beyond a 5-minute skew tolerance; `expires_at` is **required** in enforce.
- ✅ Rollback/freeze gate: `catalog_version` required (≥ 1) and a monotonic
  floor persisted at `<dataDir>/release_catalog_state.json`; a lower version is
  refused. A corrupt floor file fails closed (never silently resets to 0).
- ✅ `/api/releases` surfaces `verify_mode`, `catalog_version`, `expires_at`
  without leaking keys or paths.
- ✅ Phase 1 CI fail-closed matrix (see CI and E2E Gates).

- ✅ Verified auto-seed via `CULVERT_RELEASE_CATALOG_URL` (P1.7): at startup, in
  enforce mode only, fetch the signed catalog from the URL, **verify before**
  writing (signature + freshness + rollback, read-only), atomic move-aside swap
  into `release_catalog/`, fail closed to `available:false` on any error. Verify
  happens in the binary (trust roots there); the installer only forwards the env.
  See `roadmap/D1.6d-P1.7-catalog-autoseed-plan.md`.

Phase 1 is now fully shipped — the "still to do" item below (publish the
official bundle + ship the baked public root) landed in the Phase 2
release-pipeline work (see P2a/P2b status below): the baked Sigstore root
(P2b-2a) and the baked default catalog URL (M1-2) mean auto-seed no longer
needs any operator-provided URL or trust roots on a stock build.

Acceptance:
- A clean install can auto-seed the official signed catalog and show
  `available:true`.
- Removing the signature, changing a manifest, expiring the catalog, replaying
  a lower `catalog_version`, signing with an untrusted key, or using a tag
  results in `available:false` and no dispatch.
- With no trust roots configured, Release Management stays disabled; no unsigned
  catalog is ever auto-trusted. (On a stock build this requires deliberately
  emptying `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT` — see above.)

## Phase 2: Release Pipeline and Image Trust

Move catalog publication into the release process. Split into two slices because
"keyless" implies an *identity* (Fulcio) trust root, which is a change to the
baked-ed25519 model Phase 1 shipped — see
`roadmap/D1.6d-P2-release-pipeline-signing-plan.md`.

### Phase 2a — pipeline + keyless image trust (no Control-Plane trust change)

- ✅ Generate the catalog from release metadata, not hand-edited JSON
  (`release_gen.go`, deterministic; byte-stable so the loader's RAW-bytes
  manifest hashing holds).
- ✅ Release-blocking CI gate (`catalog-pipeline` job in `ci.yml`) that
  round-trips the generated bundle through the REAL `LoadVerifiedCatalog`
  (`TestReleaseCatalogGate`), so the gate can never drift from runtime
  verification. Gate asserts: refs are `repo@sha256:<64hex>` only (no tags),
  every `list_digest` equals the pushed manifest-list digest, freshness/schema
  present, generation is deterministic.
- ✅ Keyless cosign image signing + embedded provenance (already in `ci.yml`).
- ✅ Attach the generated bundle (`index.json`, manifests, `checksums.txt`) to
  the run as an artifact. The bundle is **UNSIGNED in P2a** — the gate's ephemeral
  ed25519 key is in-process/discarded and is NOT the official trust signature.
- ✅ Catalog is now trusted by a shipped Control Plane via the baked official
  Sigstore root — see Phase 2b below.

### Phase 2b — Control-Plane keyless catalog trust (separate, reviewed) — SHIPPED

- ✅ In-binary verifier (Fulcio root + pinned `KidCarmi/Culvert`
  release-workflow identity, Rekor), offline air-gap-safe verification
  (P2b-1).
- ✅ Official root baked in and ACTIVE by default (P2b-2a) — see
  `docs/operator/sigstore-trusted-root-lifecycle.md` for the provenance and
  refresh procedure.
- ✅ CI signs the catalog with the keyless backend and proves the
  end-to-end verify + image-signature identity match in the release gate
  (P2b-2b).
- ✅ Catalog freshness without a version bump: a weekly re-sign cron (M1-4)
  re-signs the same `catalog_version` with a renewed `expires_at`. See
  [`catalog-resign-runbook.md`](catalog-resign-runbook.md).

Acceptance:
- 2a: a release cannot attach a catalog unless generation + digest-match +
  freshness/schema + image signing + provenance all pass.
- 2b: a shipped Control Plane trusts the official keyless-signed catalog and
  fails closed on identity/signature/freshness/rollback violations.

## Phase 3: Rollback and Freeze Protection

Prevent stale metadata and downgrade attacks.

- ✅ Store the highest accepted catalog version in the data directory
  (`<dataDir>/release_catalog_state.json`) — landed early in Phase 1.
- ✅ Refuse catalogs with a lower version — landed early in Phase 1.
- ☐ Add an explicit break-glass recovery flag to accept a lower version
  (intentional rollback). Today a downgrade requires removing the state file.
- Add short-lived timestamp/freshness metadata for online installs.
- Keep longer-lived signed bundle mode for air-gapped installs.
- Add operator-visible states:
  - `trusted`
  - `expired`
  - `rollback_refused`
  - `signature_untrusted`
  - `repo_mismatch`
  - `catalog_missing`
- Audit every accepted catalog version and every refusal reason.

Acceptance:
- Replaying an older signed catalog is refused.
- A stale online catalog cannot silently pin users to old vulnerable releases.

## Phase 4: Key Rotation

Make trust maintainable without emergency redeploys.

- Support multiple active public catalog keys.
- Add `key_id`, `not_before`, `not_after`, and purpose fields.
- Add overlap windows for old and new release-signing keys.
- Add a documented emergency revocation process.
- Keep root trust material offline; use online signing only for short-lived
  timestamp/freshness metadata if that layer is added.
- Add CI test fixtures for:
  - old valid key
  - new valid key
  - expired key
  - unknown key
  - wrong-purpose key

Acceptance:
- Operators can rotate catalog signing keys without disabling Release
  Management or accepting unsigned metadata.

## Phase 5: Air-Gapped and Mirror Support

Support enterprise/offline deployments without weakening digest verification.

- Define an offline catalog bundle format.
- Include all metadata, signatures, key ids, and expected image digests.
- Add explicit repo rewrite configuration for mirrored registries.
- Preserve original digest identity while dispatching the local mirror repo.
- Verify the final running digest equals the catalog digest after mirror rewrite.
- Document mirror sync commands and failure modes.

Acceptance:
- An air-gapped test can import a signed catalog bundle, dispatch through a
  local mirror, and verify the running digest.

### Catalog origin: built-in default, override, and egress posture (M1-2)

As of M1-2 the appliance ships a **canonical built-in catalog origin**
(`https://catalog.culvertlabs.com/release-catalog`). A normal customer configures
nothing — in enforce mode the Control Plane fetches and verifies the signed
catalog from that origin at startup and then on the periodic refresh cadence.

**Egress posture (read this before deploying behind a strict firewall).** Because
the default origin is always set, an enforce-mode appliance makes an outbound
HTTPS request to `catalog.culvertlabs.com` at boot and every refresh interval
(default 6h, ±10% jitter; override the cadence with `CULVERT_RELEASE_REFRESH_INTERVAL`,
a Go duration clamped to a 1m floor — read once at startup). Each request is a conditional `GET` (ETag/Last-Modified)
carrying no payload beyond the appliance's source IP and the standard HTTP
validators — it is a catalog-freshness poll, not telemetry — but it is on-by-default
outbound traffic a proxy-appliance operator should know about.

`CULVERT_RELEASE_CATALOG_URL` is the operator **override**:

| Value | Effect | Trust |
| --- | --- | --- |
| _unset_ | Fetch the built-in default origin | Enforced (baked roots + pinned identity) |
| `https://mirror.example.com/…` | Fetch that mirror/staging/regional origin | Enforced — **identical**; the origin never changes trusted roots/identities |
| `off` / `none` / `disabled` | **No outbound fetch**; the appliance only uses an already-present on-disk catalog | Enforced — the disable sentinel is the trust-**safe** opt-out |

The disable sentinel exists specifically so silencing the fetch never requires
`CULVERT_RELEASE_CATALOG_VERIFY=permissive/disabled` (which would *weaken* the
trust channel). Verification is byte-identical regardless of origin: a malicious
default or mirror serving tampered bytes is rejected before promotion.

The effective origin, its source (`default` / `override` / `disabled`), the
refresh cadence, and the last-refresh outcome are surfaced read-only on
`GET /api/releases` (`catalog_origin` host-only for overrides — never the full URL,
which may carry presigned credentials — `catalog_url_source`, `refresh_interval`,
`last_refresh`) and in the admin **Release Management** panel. An internal mirror
must be served on a publicly-resolving, non-private host: the SSRF guard rejects
private-IP origins by design (a future explicit allowlist knob is a separate,
security-owner decision).

## Detection, metrics, and alerting (M1-3 — shipped)

The refresh loop (Phase 5) and startup auto-seed both feed a detection layer
that turns silent catalog failures into operator-visible signals. Three
alert events fire through the existing webhook/alerts pipeline (selectable
in the admin **Alerts → Webhooks** modal, or via `"*"`):

| Event | Fires when | What it means | Operator action |
|---|---|---|---|
| `release_catalog_stale` | The **installed** catalog's `expires_at` is within 30 days of now (incl. already expired) | The weekly re-sign pipeline (M1-4) has likely stopped updating the catalog — this is the 180-day freshness watchdog's early-warning backstop | Check CI re-sign job health (see `docs/operator/catalog-resign-runbook.md`); if it cannot be fixed before expiry, catalog dispatch will stop serving new releases (there is no updater fallback — the legacy Docker updater sidecar was removed under DEBT-008; see the status banner at the top of this document) |
| `release_catalog_refresh_failing` | 3 **consecutive** refresh failures (loop tick or manual `POST /api/releases/catalog-refresh`) | The configured catalog origin is unreachable, or a fetched catalog is failing verification/freshness/rollback checks | Check network egress to the catalog origin (`/api/releases` → `catalog_origin`), check `last_refresh` for the failure reason; the existing (unexpired) catalog stays installed and serving throughout |
| `release_catalog_recovered` | The first refresh success after a `release_catalog_refresh_failing` alert | The refresh loop is healthy again | No action; informational |

Each event fires **once per threshold crossing**, not on every evaluation
(e.g. `release_catalog_stale` does not re-fire every 6h tick while still
within the 30-day window) — an appliance restart re-arms an already-active
condition and re-fires it once. Thresholds (30 days, 3 failures) are fixed
constants, not configurable.

Prometheus exposition (`/metrics`):
- `culvert_release_catalog_refresh_total{result="success"|"failure"}` —
  cumulative refresh outcomes (startup, loop, and manual).
- `culvert_release_catalog_expires_in_seconds` — seconds until the installed
  catalog expires (negative once expired); omitted when no catalog is
  installed.

`/api/releases` also surfaces `expires_in_days`, and the admin **Release
Management** panel shows it with a warn color inside the same 30-day
threshold.

## Phase 6: Production Cutover

Only after real production verification:

- Mark release catalog dispatch as the preferred update path.
- Keep the legacy Docker updater installed but compatibility-only.
- Add metrics and a selectable alert event for **dispatch failures and digest
  mismatch** (`release_dispatch_attention` exists in code but has no Prometheus
  series and no webhook-modal checkbox yet; trust-failure and stale-catalog
  alerting shipped in M1-3 — see the section above).
- Add runbook steps for reverting to legacy updater if catalog dispatch fails in
  production.
- Deprecate legacy updater UI paths only after at least one stable release cycle
  succeeds through catalog dispatch.

Acceptance:
- At least one production update completes through catalog dispatch.
- No Docker updater endpoint, container, or socket path is used by Release
  Management.
- Operators have a documented fallback.

## Security Invariants

- Unsigned official catalogs are never accepted.
- A signed catalog is trusted only if its key is trusted, its metadata is fresh,
  its version is not a rollback, and every referenced manifest hash matches.
- Mutable tags are never dispatched.
- The proxy never receives the Docker socket.
- The maintenance agent remains the only component allowed to execute Docker
  update operations.
- Agent success is not trusted until the running digest matches the catalog
  digest.
- Private signing keys never leave the signing system.
- Logs and API responses never expose private keys, registry credentials, or
  token material.

## CI and E2E Gates

Implemented (Phase 1):

- ✅ **Fail-closed matrix** (`release_catalog_phase1_ci_test.go`,
  `TestPhase1CI_FailClosedMatrix`): through the production enforce-mode holder,
  an unsigned, sig-stripped/tampered, wrong-key, expired, missing-`expires_at`,
  and missing-`catalog_version` catalog each fails closed (matching error kind,
  nothing published). Plus `TestPhase1CI_RollbackReplayRefused` for downgrade
  replay against the persisted floor.
- ✅ **Wiring-mode tests** (`release_wiring_test.go`):
  `TestResolveCatalogVerifyMode` (roots ⇒ enforce; permissive/disabled are
  break-glass; unrecognized ⇒ enforce), `TestCombinedReleaseTrustKeys_*` (baked
  ∪ env, malformed baked fails closed),
  `TestLoadReleaseManagement_UnsignedNotAutoTrusted` (no roots ⇒ disabled, never
  auto-trust unsigned).
- ✅ **Freshness/rollback unit tests** (`release_catalog_freshness_test.go`):
  expiry, skew tolerance, future-dating, version floor persistence + corrupt
  floor fail-closed.
- ✅ **Install contract** (`release_management_install_contract_test.go`): the
  break-glass env is forwarded by compose; no Docker socket; no unsigned
  auto-seed.

Remaining:

- Unit tests for key rotation fixtures.
- Contract tests for installer behavior:
  - no unsigned catalog seed
  - no default trusted URL without verification
  - atomic write after verification
  - fail closed on download, parse, signature, expiry, or permission failure
- Release workflow tests:
  - generated catalog digest matches pushed image digest
  - catalog signature verifies with public test key
  - generated catalog refuses tag refs
- E2E test:
  - start Culvert without the legacy updater sidecar
  - seed or download a signed catalog
  - call `/api/releases`
  - call `/api/releases/current?agent=local`
  - dispatch a catalog release
  - poll `/api/releases/dispatch/status`
  - assert terminal success
  - assert `running_image.repo_digests` equals the catalog digest
  - assert no legacy updater endpoint, container, or Docker socket path was used

## Open Decisions

- Signing backend: GitHub OIDC keyless signing, cloud KMS, Vault transit, or an
  offline release key with manual ceremony.
- Catalog publication location: GitHub Release assets, GitHub Pages, OCI
  artifact, or dedicated release bucket.
- Freshness model: simple `expires_at` in the signed index first, or a separate
  timestamp role from day one.
- Whether image signatures are required by the Control Plane before dispatch or
  enforced in the release pipeline only for the first production slice.
- How much TUF compatibility to adopt now versus after the first production
  catalog update succeeds.

## Recommended Execution Order

1. Trusted catalog MVP with baked public key, `expires_at`, catalog version, and
   verified installer auto-seed.
2. Release workflow generation/signing so no human hand-edits official catalogs.
3. Rollback/freeze protection and key rotation fixtures.
4. Air-gapped mirror bundle and repo rewrite dispatch.
5. Production cutover after a successful catalog-driven update.

The shortest safe path for end users is phases 1 and 2. The full
enterprise-grade path is complete when phases 1 through 6 are implemented and
the production cutover acceptance gates are met.
