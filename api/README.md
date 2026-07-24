# Culvert API contract

This directory is the source of truth for the Culvert admin-API OpenAPI contract.

| File | Role | Edit? |
|---|---|---|
| `openapi/openapi.yaml` | **The contract** (OpenAPI 3.0.4). Hand-authored. | ✅ edit this |
| `openapi/openapi.json` | Canonical, deterministic JSON — generated. | ❌ `make api-bundle` |
| `openapi/index.html` | Self-contained offline docs — generated. | ❌ `make api-bundle` |
| `route-classification.yaml` | Every registered route: documented OR exempt (owner+expiry). | ✅ add rows |

## Enforcement

The engine lives in `internal/apicontract` and is exercised by tests in the repo
root (`apicontract_*_test.go`) that bind the **live** `uiRoutes` table. Because
they are ordinary Go tests, they run in the required `go test -race ./...` fast PR
gate — the contract cannot silently drift from the router.

See `docs/api/API-CONTRIBUTING.md` for the workflow, `docs/adr/0018-openapi-contract.md`
for the architecture decision, and `docs/api/` for the style guide, versioning
and deprecation policies, inventory, research, and risk register.

## Quick start

```
make api-verify     # validate + lint + route-coverage + conformance (offline, Go-native)
make api-bundle      # regenerate openapi.json + index.html from the YAML
open api/openapi/index.html   # offline docs, no network required
```

## Scope

Documents the HTTP/JSON admin API (`/api/*`, `/healthz`, setup, PAC-admin) served
on the UI port. Out of scope (not RESTful): the forward-proxy data path, the CP↔DP
gRPC stream, and the scan sidecar — see the consistency risk register.
