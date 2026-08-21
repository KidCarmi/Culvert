# Catalog-driven fresh install — operator & release runbook

Fresh installs select their image from the **signed release catalog** — the same
authority that governs day-2 updates — instead of enumerating GHCR tags. This
document is the operator reference for that flow plus two release-engineering
runbooks the code cannot enforce on its own:

- **Release cutover checklist** — what must be true before the first
  catalog-driven install can succeed.
- **Pinned-identity rotation** — how to rotate/rename the signing identity
  without bricking installs.

(These two checklists are unrelated to the "G1"/"G3"/"G4" rulebase-UX gap IDs in
`docs/design/M3-POLICY-ARCH-REVIEW.md` — that is a different numbering series for a
different feature; this doc never uses the bracketed-letter shorthand to avoid
colliding with it.)

For the trust internals (baked roots, Sigstore identity, freshness/rollback) see
`enterprise-release-catalog-plan.md` and `sigstore-trusted-root-lifecycle.md`.

---

## How a fresh install resolves its image

1. The installer downloads the signed `culvert-linux-<arch>` release asset (the
   **verifier binary**) from GitHub Releases and **cosign verify-blob's it** against
   the pinned release identity **before executing it**
   (`scripts/install.sh: verify_bootstrap_verifier`). Fail-closed.
2. It runs `culvert bootstrap-resolve`, which fetches the signed catalog and
   verifies **signature + freshness + anti-rollback/replay** (baked roots + pinned
   identity, enforce mode — the *same* code the appliance runs at startup), then
   resolves the install channel to an **immutable `repo@sha256` digest**.
3. The installer pulls that exact digest (content-addressed), tags it
   `culvert/proxy:pinned`, extracts `/app/deploy` (compose + agent packaging) from
   that same image, runs the compose↔binary preflight, and starts the stack.
4. The catalog decision is recorded to `/data/bootstrap_decision.json` and surfaced
   read-only on `GET /api/releases` (field `bootstrap`) so the appliance can prove
   which digest/`catalog_version`/trust scheme provisioned it.

No cryptography or JSON trust parsing happens in shell; the trust policy is
identical to the runtime verifier and cannot drift (`TestReleaseIdentitySSOT`,
`TestInstaller_VerifierIsCosignVerified`).

### Operator inputs

| Env var | Default | Meaning |
|---|---|---|
| `CULVERT_RELEASE_CATALOG_URL` | baked canonical origin | Operator mirror/staging origin. `off`/`none`/`disabled` ⇒ NO catalog fetch (requires an explicit seed; never downgrades to tags). **Origin never changes trust.** |
| `CULVERT_INSTALL_CHANNEL` | `stable` | `stable` (⇒ catalog `recommended`), `lts`, or `critical`. |
| `CULVERT_PROXY_SEED_REF` | unset | Explicit, verified image seed — the supported **offline / break-glass** path. |
| `CULVERT_BOOTSTRAP_VERIFIER_VERSION` | latest release | Pin the verifier release tag (e.g. air-gapped mirrors). |
| `CULVERT_BOOTSTRAP_SKIP_VERIFY` | unset | **Break-glass**: trust the verifier download WITHOUT cosign (air-gapped/egress-filtered only). Loud. |
| `CULVERT_INSTALL_ALLOW_TAG_DISCOVERY` | unset | **Break-glass**: legacy GHCR tag discovery. Disabled by default; never a trusted catalog decision. |
| `CULVERT_GITHUB_REPO` | `KidCarmi/Culvert` | Source/release repo for the verifier asset (validated `owner/name`). |

### Fallback matrix (fail-closed)

| Condition | Behaviour |
|---|---|
| Catalog unreachable / signature invalid / expired / replayed | **Fail closed**, actionable diagnostics. No tag fallback. |
| Verifier cosign verification fails | **Fail closed** (unless `CULVERT_BOOTSTRAP_SKIP_VERIFY=1`). |
| Selected release missing digest / malformed / repo outside allowlist | **Fail closed** in `bootstrap-resolve`. |
| `/app/deploy` missing in the pulled image | **Fail closed** at extraction. |
| Unsupported architecture | **Fail clearly** (linux/amd64, linux/arm64 only). |
| Catalog fetch disabled (`off`/`none`/`disabled`) | Require an explicit `CULVERT_PROXY_SEED_REF`; **never** tag discovery. |
| Healthy existing deployment re-run | Preserved — the catalog path is not taken (running image reused). |
| Stale `culvert/proxy:pinned` with no deployment (the EC2 `0.0.238` case) | Refreshed from the signed catalog. |

### Prerequisites

- **NTP synced before install.** The catalog signature is clock-independent, but
  `expires_at` is checked against the **local** clock — a pre-NTP cloud-first-boot
  host that thinks it is months in the past can accept a long-expired (genuinely
  signed) catalog. The installer warns on >1h skew vs network time; heed it:
  `sudo timedatectl set-ntp true` (or `sudo chronyc makestep`).
- **Egress for cosign** on a locked-down network: the verifier cosign check reaches
  the Sigstore endpoints (**Fulcio**, **Rekor**, and the **TUF CDN** —
  `fulcio.sigstore.dev`, `rekor.sigstore.dev`, `tuf-repo-cdn.sigstore.dev`). Allow
  them, or use `CULVERT_PROXY_SEED_REF` (offline). Do **not** reflexively set
  `CULVERT_BOOTSTRAP_SKIP_VERIFY=1` — a verification everyone bypasses is worse than
  none.

---

## Release cutover checklist

The installer path is version-decoupled by design: the verifier is downloaded as
`releases/latest`, and the **catalog** — not the verifier — picks the appliance
image. Two ordering facts the code cannot self-check must be verified by the release
owner **before** a catalog goes live:

1. **The verifier release carries `bootstrap-resolve`.** The first `releases/latest`
   after this feature merges must be cut from a **post-merge** commit. A verifier
   from a pre-feature release lacks the subcommand; the installer's capability probe
   (`grep -qa 'bootstrap-resolve'`) then fails **closed** with guidance — it never
   silently starts the proxy — but the fresh-install path is unavailable until a
   post-merge release exists. Sequence the first tagged release accordingly.

2. **The `recommended` channel resolves to a `/app/deploy`-bearing digest.** If the
   live catalog's `recommended` pointer still resolves to a pre-bundle image, the
   installer will faithfully, verifiably install a **broken** image (extraction of
   `/app/deploy` fails). Before flipping the catalog live, confirm the resolved
   digest contains `/app/deploy`:

   ```bash
   # resolve what the catalog would install, then check the image has the bundle
   ref=$(culvert bootstrap-resolve --channel stable --print image_ref)
   docker pull "$ref"
   docker run --rm --entrypoint sh "$ref" -c 'test -f /app/deploy/docker-compose.yml && echo OK'
   ```

3. **CI publishes the signed verifier asset.** Confirm the tagged release attached
   `culvert-linux-amd64` / `culvert-linux-arm64` **and** their `.sigstore.json`
   bundles (ci.yml "Upload proxy release asset"). Without the `.sigstore.json`, the
   cosign gate fails closed on every install.

Smoke test against a staging origin before production:

```bash
CULVERT_RELEASE_CATALOG_URL=https://staging.example/release-catalog \
  culvert bootstrap-resolve --channel stable --print json
# expect a decision whose digest matches the intended release; non-zero ⇒ do not ship
```

---

## Pinned-identity rotation

The keyless signing identity (issuer + SAN regex) is **byte-pinned** so trust cannot
drift. Rotating it — or **renaming the `ci.yml` signing workflow** (the SAN anchors
to `.../.github/workflows/ci.yml@refs/tags/v.*`) — is a coordinated, multi-artifact
change. The literal lives in **four** places, kept in lockstep by SSOT tests:

| Location | Symbol | Pinned by |
|---|---|---|
| `release_identity.env` | `CULVERT_RELEASE_SIGSTORE_ISSUER` / `_SAN_REGEX` | source of truth |
| `release_catalog_sigstore.go` | `officialSigstoreIssuer` / `officialSigstoreSANRegex` | `TestReleaseIdentitySSOT` (== env) |
| `scripts/install.sh` | `MAINT_SIGSTORE_ISSUER` / `MAINT_SIGSTORE_SAN_REGEX` | `TestInstallScriptPinsSameReleaseIdentity` (== env) |
| `packaging/culvert-maint/install.sh` | `CERT_OIDC_ISSUER` + `cert_identity_for` | derived (exact `@refs/tags/<ver>`), reviewed |

`scripts/install.sh`'s `MAINT_SIGSTORE_SAN_REGEX` now gates **both** the proxy image
and the **verifier binary** cosign check, so an identity change affects the fresh
install directly.

### Procedure (add-new-then-retire, with an overlap window)

1. **Prepare** the new identity (new signing workflow ref, or new issuer). Do **not**
   remove the old one yet.
2. **Widen** the SAN regex to match **both** old and new identities in all four
   locations in a single change; update `release_identity.env` first, then run
   `go test -run 'TestReleaseIdentitySSOT|TestInstallScriptPinsSameReleaseIdentity'`
   until green. During the overlap, artifacts signed under either identity verify.
3. **Cut a release** signed under the **new** identity; verify end-to-end
   (`bootstrap-resolve` against the freshly signed catalog, image cosign, agent).
4. **Drain**: keep the widened (both-identities) window until every reachable
   appliance and every cached copy of `install.sh` (the canonical `curl | bash`
   fetches it fresh, but pinned/mirrored copies do not) has updated. There is **no
   revocation channel** for an already-distributed installer script — an old
   `install.sh` carries the old SAN literally, so plan the overlap to cover your
   longest realistic cached-installer lifetime.
5. **Narrow** the SAN regex back to the **new** identity only, in all four locations,
   once drain is complete. SSOT tests must stay green.

### Compromise of the signing identity

If the private signing path is compromised, treat it as a security incident, not a
routine rotation: (a) stop publishing under the compromised identity immediately;
(b) rotate the Fulcio/OIDC trust as above but **narrow to the new identity without a
long overlap** (accept that old cached installers fail closed rather than trust a
compromised signer); (c) rely on the appliance's persisted anti-rollback floor and
`catalog_version` monotonicity so a fleet cannot be pushed a signed-old catalog; and
(d) communicate the required minimum `install.sh` re-fetch to operators — the
installer cannot self-revoke.

---

## Provenance & forensics

`GET /api/releases` returns a `bootstrap` object (when present) with the immutable
`image_ref`/`digest`, `catalog_version`, `generated_at`/`expires_at`, resolved
channel, and `trust_schemes` that provisioned the host. Use it to answer "was this
fleet member provisioned during a suspect catalog window?" without SSH. The record
is also at `/data/bootstrap_decision.json` inside the appliance and is included in
`/data` backups.
