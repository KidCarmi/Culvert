# Sigstore Trusted-Root Lifecycle (keyless catalog verification)

Culvert's keyless (Sigstore-identity) release-catalog verification (P2b) checks the
official catalog signature **offline** against a **baked Sigstore trusted root** plus
a **pinned workflow identity**. This doc covers where that trusted root comes from,
how it is pinned, and what to do when it goes stale.

## What is baked

- **File:** `trusted_root.json` at the repo root, embedded via `//go:embed` into the
  binary (`bakedSigstoreTrustedRootJSON`, `release_catalog_sigstore.go`).
- **What it is:** the Sigstore **public-good** `trusted_root.json` — media type
  `application/vnd.dev.sigstore.trustedroot+json` — containing the **public** Fulcio
  CA(s), Rekor transparency-log key(s), CT-log key(s), and the timestamp authority.
  **PUBLIC trust material only — never any private signing key.**
- **Not** the TUF `root.json` metadata. The two are different artifacts; only the
  `trusted_root.json` is consumed by `root.NewTrustedRootFromJSON`.
- **Provenance:** recorded in `trusted_root.provenance.txt` (source URL, fetch date,
  sha256, structure summary). `TestSigstore_BakedRootCanBeParsed` asserts the embed
  is non-empty, parses, and carries Fulcio + Rekor material.

## Why it is pinned (not auto-refreshed)

The trusted root is a **pinned snapshot**, deliberately NOT refreshed at runtime via
go-tuf — that keeps the dependency/attack surface small and verification fully
offline/air-gap-safe (the published catalog bundle carries its own Rekor inclusion
proof + integrated timestamp, so nothing reaches sigstore.dev at verify time). The
cost is that the snapshot can go stale if Sigstore rotates Fulcio/Rekor keys.

## Refreshing the baked root (routine)

Do this when Sigstore announces a Fulcio/Rekor key rotation, or each release cycle:

1. Re-fetch the target:
   `curl -fsSLo trusted_root.json https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json`
2. Confirm it parses and carries Fulcio + Rekor + CT material (run
   `go test -run TestSigstore_BakedRootCanBeParsed`).
3. Update `trusted_root.provenance.txt` (new sha256 + date).
4. Commit. The next release ships the refreshed root.

## Emergency root rotation (operator break-glass)

If a shipped Control Plane's baked root has gone stale and official catalog
verification starts failing with certificate/trust errors **before** you can deploy a
new Culvert release:

1. Fetch a fresh `trusted_root.json` from the Sigstore public-good instance (URL
   above) onto the host.
2. Point the Control Plane at it:
   `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT=/path/to/trusted_root.json`
3. Restart. The override replaces the baked embed (the env value wins). PUBLIC
   material only — never place a private key here.

To **deactivate** the keyless scheme entirely (e.g. fall back to operator ed25519
roots only), point the override at an **empty** file.

## Pinned signer identity

Catalog signatures are accepted only from this exact identity:

- **issuer:** `https://token.actions.githubusercontent.com` (GitHub Actions OIDC).
- **SAN:** `https://github.com/KidCarmi/Culvert/.github/workflows/ci.yml@refs/tags/v*`
  — this repo, the **`ci.yml`** signing workflow, on a **release tag** only.

The SAN is pinned to the exact workflow file (`ci.yml`) to keep the signing surface
to the one intended workflow. **Renaming the signing workflow file** therefore
requires a coordinated change: update `officialSigstoreSANRegex`, ship it, and run an
**overlap window** where both the old and new identity are accepted until all
Control Planes have upgraded.

### Forks / mirrors

A fork's tag signatures carry the fork's repo slug, not `KidCarmi/Culvert`, so they
will not match the baked identity. A fork that publishes its own keyless catalog sets
`CULVERT_RELEASE_SIGSTORE_IDENTITY` (JSON `{"issuer","san_regex"}`) — and, if it uses
a different Sigstore instance, `CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT`. With neither a
matching root nor an override, the keyless scheme stays dormant and the deployment
falls back to operator-configured ed25519 roots (or `CULVERT_RELEASE_CATALOG_VERIFY`
break-glass).

## Default-posture note (P2b-2a)

Baking the official root makes the keyless scheme **ACTIVE by default** — any build
with no operator trust config now enters **enforce** mode with the Sigstore scheme.
With no signed catalog present this simply yields `available:false` on
`/api/releases` (no dispatch); the legacy Docker updater remains the primary update
path until the Phase 6 cutover. Until P2b-2b ships CI keyless signing, no official
keyless-signed catalog is published yet.
