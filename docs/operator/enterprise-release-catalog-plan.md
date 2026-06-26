# Enterprise Release Catalog Plan

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

- Add baked public release catalog trust roots to the Control Plane image.
- Keep operator override/extension via `CULVERT_RELEASE_CATALOG_TRUST_KEYS`.
- Require signed catalogs for the official auto-seed path.
- Add `expires_at` and monotonically increasing catalog version metadata.
- Reject expired catalogs, future-dated catalogs beyond clock skew tolerance,
  unsupported schema majors, duplicate versions, repo mismatch, mutable tags,
  malformed digests, missing manifests, and manifest hash mismatch.
- Publish official catalog bundle as:
  - `index.json`
  - `index.json.sig`
  - referenced manifest files
  - optional `catalog.bundle.json` for one-file offline transfer
- Add installer support for `CULVERT_RELEASE_CATALOG_URL`.
  - Download to a temp path.
  - Verify before writing into `release_catalog/`.
  - Atomic rename into place.
  - Fail closed to `available:false` if anything is wrong.
- Update `/api/releases` status to expose catalog trust/freshness state without
  leaking keys or sensitive paths.

Acceptance:
- A clean install can auto-seed the official signed catalog and show
  `available:true`.
- Removing the signature, changing a manifest, expiring the catalog, or using a
  tag results in `available:false` and no dispatch.

## Phase 2: Release Pipeline and Image Trust

Move catalog publication into the release process.

- Extend release workflow to resolve the pushed image digest after publish.
- Generate the catalog from release metadata, not hand-edited JSON.
- Sign container images with cosign or an equivalent supported signer.
- Sign catalog metadata with a release signing key held outside the repository.
- Emit provenance/attestation for the build.
- Attach catalog bundle, signatures, checksums, and provenance to the GitHub
  Release or an official immutable release bucket.
- Add CI gates:
  - catalog refs are `repo@sha256:<64 hex>` only
  - catalog digest matches the image digest produced by the workflow
  - catalog verifies with the baked public key
  - image signature verifies against the expected identity/key
  - provenance exists for release images

Acceptance:
- A release cannot publish an official catalog unless image, catalog, and
  provenance checks all pass.

## Phase 3: Rollback and Freeze Protection

Prevent stale metadata and downgrade attacks.

- Store the highest accepted catalog version in the data directory.
- Refuse catalogs with a lower version unless an explicit break-glass recovery
  flag is present.
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

## Phase 6: Production Cutover

Only after real production verification:

- Mark release catalog dispatch as the preferred update path.
- Keep the legacy Docker updater installed but compatibility-only.
- Add metrics and alerts for catalog trust failures, dispatch failures, digest
  mismatch, and stale catalogs.
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

- Unit tests for signature verification, expiry, rollback counters, key
  rotation, repo mismatch, and malformed refs.
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
