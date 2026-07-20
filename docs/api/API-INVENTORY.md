# API Inventory

Human-readable summary of the Culvert admin-API route inventory. The
**authoritative, machine-readable** inventory is `api/route-classification.yaml`,
which is derived from the live `uiRoutes` table and enforced by the
route-coverage gate (`TestOpenAPI_Gate3_RouteCoverage`). This file is a
generated summary — do not hand-edit classifications here.

- **Total route method-entries:** 284
- **Documented in the OpenAPI contract:** 19
- **Exempt (time-boxed, expiry 2027-01-31):** 265

## By visibility

| Visibility | Count |
|---|---|
| admin-supported | 270 |
| health-ops | 1 |
| public-supported | 13 |

## By domain

| Domain | Entries | Documented |
|---|---|---|
| auth | 18 | 7 |
| cdr | 11 | 0 |
| cluster | 31 | 0 |
| dashboard | 13 | 2 |
| governance | 1 | 1 |
| observability | 2 | 1 |
| pac | 23 | 0 |
| policy | 65 | 2 |
| release | 6 | 0 |
| security | 51 | 2 |
| settings | 30 | 2 |
| setup | 2 | 2 |
| static | 1 | 0 |
| support | 30 | 0 |

## By danger level

| Danger | Count |
|---|---|
| high | 40 |
| medium | 133 |
| none | 111 |

## Documented operations (baseline contract v1.0.0)

| Method | Route | Handler | Visibility | Min role | Danger |
|---|---|---|---|---|---|
| POST | `/api/auth/change-password` | apiAuthChangePassword | admin-supported | viewer | medium |
| POST | `/api/auth/login` | apiAuthLogin | public-supported | public | medium |
| POST | `/api/auth/logout` | apiAuthLogout | public-supported | public | medium |
| GET | `/api/auth/status` | apiAuthStatus | public-supported | public | none |
| DELETE | `/api/auth/users` | apiAuthUsers | admin-supported | admin | high |
| GET | `/api/auth/users` | apiAuthUsers | admin-supported | admin | none |
| POST | `/api/auth/users` | apiAuthUsers | admin-supported | admin | medium |
| POST | `/api/ca/rotate` | apiCARotate | admin-supported | admin | high |
| GET | `/api/ca/status` | apiCAStatus | admin-supported | viewer | none |
| GET | `/api/config/export` | apiConfigExport | admin-supported | admin | none |
| POST | `/api/config/import` | apiConfigImport | admin-supported | admin | high |
| DELETE | `/api/decryption-exclusions` | apiDecryptionExclusions | admin-supported | operator | high |
| GET | `/api/decryption-exclusions` | apiDecryptionExclusions | admin-supported | viewer | none |
| GET | `/api/governance/control-plane` | apiGovernanceControlPlane | admin-supported | admin | none |
| POST | `/api/setup/complete` | apiSetupComplete | public-supported | public | medium |
| GET | `/api/setup/status` | apiSetupStatus | public-supported | public | none |
| * | `/api/stats` | apiStats | admin-supported | viewer | medium |
| * | `/api/top-hosts` | apiTopHosts | admin-supported | viewer | medium |
| GET | `/healthz` | apiHealthz | health-ops | public | none |

## Non-REST surfaces (out of OpenAPI scope, documented in the risk register)

- Forward-proxy data path (HTTP CONNECT / plain-HTTP / SOCKS5) on `-port` — a proxy protocol, not a resource API.
- Control-Plane ↔ Data-Plane **gRPC** stream — described by protobuf.
- Proxy-listener built-ins (`/health`, `/ready`, `/metrics`, `/proxy.pac`) — see risk register §8.
- Scan sidecar HTTP service — unauthenticated internal surface, risk register §9 (High).
