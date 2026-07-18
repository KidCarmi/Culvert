# Claim-Evidence Ledger — "Supply-chain integrity & release management"

Article: [`release-management.md`](release-management.md). Verified against repo
revision `ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| Two coexisting signature schemes (Ed25519 + Sigstore keyless) | src | `release_catalog_verify.go:107-153`; `release_catalog_sigstore.go` |
| `VerifyEnforce` default; rejects missing/invalid signature | src | `release_catalog_verify.go:44-45` |
| Enforce requires ≥1 trust scheme; no root + no override ⇒ disabled | src | `release_catalog_verify.go:153`; `release_wiring.go` |
| Freshness + rollback gate (`expires_at`, monotonic `catalog_version`) | src | `release_catalog_freshness.go`; CLAUDE.md release-catalog trust note |
| Break-glass `permissive`/`disabled` via `CULVERT_RELEASE_CATALOG_VERIFY` | src | `resolveCatalogVerifyMode`; README env vars |
| Verified auto-seed when `CULVERT_RELEASE_CATALOG_URL` set + enforce; fail-closed; SSRF-guarded; origin never affects trust | src | `release_autoseed.go`; CLAUDE.md `CULVERT_RELEASE_CATALOG_URL` note |
| Digest-pinned dispatch (`repo@sha256:…`) at the sudo boundary | src | `release_dispatch.go:177` (`splitRepoRef`); packaging sudoers contract |
| Maintenance agent applies updates over a local Unix socket; no docker.sock in proxy | src | `dp_enrollment.go`/agent packaging; `docs/operator/release-management-agent.md` |
| SLSA L3 + Cosign keyless in the release CI pipeline (not runtime) | ci | `.github/workflows/ci.yml` (provenance + cosign sign) |
| API: `/api/releases` (+ current/dispatch/dispatch-status/dispatch-resume/catalog-refresh) | src | `release_api.go:288-293` |
| `/api/releases` surfaces `verify_mode`, `trust_schemes`, `expires_at`, `catalog_version` | src | CLAUDE.md release-catalog notes; `apiReleases` |
| Release-management config is env-only (GUI-parity deferral); UI read-only | src | CLAUDE.md `CULVERT_RELEASE_*` notes ("env-only … GUI-parity deferral") |

## Notes

- This article summarizes a large, evolving subsystem (P1–P2b) and delegates
  depth to the in-repo operator plans; the ledger anchors each user-facing claim
  to source or CI. Break-glass and env-only caveats are stated plainly rather
  than implying full GUI parity.
