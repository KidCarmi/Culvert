# Supply-chain integrity & release management

Culvert treats its own updates as a supply-chain trust problem. The Control Plane
loads a **cryptographically signed release catalog**, verifies it fail-closed,
and dispatches updates as **digest-pinned images** applied by a scoped host
agent. This guide explains the trust model, the verification posture, and how to
operate it — including the deliberate break-glass escapes.

Prerequisite reading: [Architecture](../01-overview/architecture.md).

---

## Purpose

Ensure the software Culvert runs is the software its maintainers signed — with
freshness and rollback protection — and give operators a controlled update path.

## The signed release catalog

The catalog is the authenticated record of available releases. Culvert verifies
it with **two coexisting signature schemes** (`release_catalog_verify.go`):

- **Ed25519** — a signature over the catalog manifest, checked against trust
  roots (baked roots ∪ `CULVERT_RELEASE_CATALOG_TRUST_KEYS`, public keys only).
- **Sigstore keyless (identity-pinned)** — a cosign keyless bundle verified
  offline against a baked Sigstore trusted root and a pinned signing identity
  (the GitHub Actions OIDC issuer + a SAN anchored to a tagged release of this
  repo's signing workflow).

Either scheme satisfies enforcement; a present-but-invalid artifact for one
scheme is rejected rather than silently falling through to the other.

## Trust posture: enforce by default

`VerifyMode` defaults to **`VerifyEnforce`**, which **rejects a missing or
invalid signature** (`release_catalog_verify.go:44-45`). Enforcement requires at
least one trust scheme to be present; with a trust root configured, an unsigned
catalog is never auto-trusted (`release_catalog_verify.go:153`). With **no** trust
root and no override, Release Management is **disabled** (fail closed) rather than
trusting anything.

In enforce mode the holder also runs a **freshness + rollback gate**: the
catalog's `expires_at` must be present and not past (with clock skew), and its
`catalog_version` must be ≥ a monotonic floor persisted on disk — so a valid but
**stale** or **rolled-back** catalog is refused.

> **Break-glass only.** `CULVERT_RELEASE_CATALOG_VERIFY=permissive` accepts an
> unsigned catalog (but still rejects a present-but-invalid signature);
> `=disabled` skips verification. Both are deliberate, logged escapes — leave
> them unset in production.

## Verified auto-seed at startup

When `CULVERT_RELEASE_CATALOG_URL` is set **and** in enforce mode, the Control
Plane fetches the signed catalog at startup, runs verify + freshness + rollback
on a staged copy, and atomically installs it — **failing closed** (leaving the
existing catalog untouched) on any error. The fetch is SSRF-guarded (private-IP
origins are rejected). **The origin never affects trust:** verification is
identical for the default and an overridden origin, and changing the URL cannot
change which signing identities are trusted.

## Digest-pinned dispatch

An update resolves to an immutable `repo@sha256:<digest>` reference. The image is
**pinned at the sudo boundary** and retagged to a fixed local tag, so a
compromised maintenance user can only run a digest of the one configured
repository — not an arbitrary image (`release_dispatch.go`; see the packaging
sudoers contract).

## The maintenance agent

Day-2 updates are applied by a host-side **maintenance agent** (a systemd
service installed by the quick-start installer), reached over a local Unix
socket. Release Management dispatches to the agent's apply endpoint; the agent
pulls the pinned digest, retags, and restarts via compose. It never mounts the
Docker socket into the proxy, and its trust is established fail-closed (the agent
binary is trusted only after the proxy image's signature verifies).

## Build provenance (CI)

Releases ship **SLSA Level 3** provenance and **Cosign keyless** signatures on
images, binaries, SBOMs, and the catalog itself. This is produced by the release
**CI pipeline** (`.github/workflows/ci.yml`), not by the runtime binary.

## API surface

| Route | Purpose |
|---|---|
| `/api/releases` | Catalog state: `verify_mode`, `trust_schemes`, `expires_at`, `catalog_version`, origin/source, refresh status |
| `/api/releases/current` | The running release |
| `/api/releases/dispatch` · `/dispatch/status` · `/dispatch/resume` | Trigger / observe / resume an update |
| `/api/releases/catalog-refresh` | Force a verified catalog refresh |

(`release_api.go:288-293`.)

## Configuration

Release-management settings are configured through the `CULVERT_RELEASE_*`
environment family (trust keys, verify mode, catalog URL, refresh interval,
Sigstore identity/root). These are **env-only today** — a recorded GUI-parity
deferral — while the read-only status is surfaced on `/api/releases` and the
admin Release Management panel. See the
[README environment variables](../../../README.md) for the full list and the
in-repo plan for detail.

## Validation steps

```bash
# Catalog + trust status (verify mode, schemes, freshness)
curl -sk https://<host>:9090/api/releases
```

Expect `verify_mode: enforce` and a non-empty `trust_schemes` in a production
build; `expires_at` in the future; `catalog_version` ≥ the last installed.

## Failure modes

| Condition | Behavior |
|---|---|
| Catalog signature missing/invalid (enforce) | Rejected (fail closed) |
| Catalog expired or version below the floor | Refused (freshness/rollback gate) |
| No trust root and no override | Release Management disabled |
| Auto-seed fetch fails / SSRF-blocked origin | Existing catalog untouched (fail closed) |
| Break-glass verify mode set | Verification relaxed — logged; not for production |

## Security implications

- Keep `CULVERT_RELEASE_CATALOG_VERIFY` unset (enforce) in production; the
  break-glass modes exist for recovery, not normal operation.
- Only **public** trust material belongs in the `CULVERT_RELEASE_*` trust
  variables — never private signing keys.
- The digest-pin + scoped sudoers is the containment boundary: protect the
  maintenance-agent user and its config.

## Known limitations

- Release-management configuration is **env-only** (GUI-parity deferral); the UI
  is read-only status.
- SLSA/Cosign provenance is a property of the **release pipeline**, not
  something the runtime binary produces.
- Freshness/rollback thresholds are compile-time constants (recorded deferral).

## Related documentation

- [Architecture](../01-overview/architecture.md) ·
  [Control Plane / Data Plane](../08-distributed/control-plane-data-plane.md).
- In-repo: [`../../../docs/operator/enterprise-release-catalog-plan.md`](../../../docs/operator/enterprise-release-catalog-plan.md),
  [`../../../docs/operator/release-management-agent.md`](../../../docs/operator/release-management-agent.md),
  [`../../../docs/operator/sigstore-trusted-root-lifecycle.md`](../../../docs/operator/sigstore-trusted-root-lifecycle.md).

## Source evidence

Claim-evidence ledger: [`release-management.evidence.md`](release-management.evidence.md).
