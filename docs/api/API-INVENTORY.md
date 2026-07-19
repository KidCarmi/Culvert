# API Inventory

Human-readable summary. The **authoritative, machine-readable** inventory is
`api/route-classification.yaml`, derived from the live `uiRoutes` table and
enforced by the route-coverage gate. Generated — do not hand-edit.

- **Total route method-entries:** 284
- **Documented in the OpenAPI contract:** 31
- **Exempt (time-boxed, ≤270-day horizon):** 253

## By domain

| Domain | Entries | Documented |
|---|---|---|
| auth | 18 | 7 |
| cdr | 11 | 0 |
| cluster | 31 | 0 |
| dashboard | 13 | 2 |
| governance | 1 | 1 |
| observability | 2 | 1 |
| pac | 23 | 1 |
| policy | 65 | 7 |
| release | 6 | 0 |
| security | 51 | 5 |
| settings | 30 | 5 |
| setup | 2 | 2 |
| static | 1 | 0 |
| support | 30 | 0 |

## Documented operations

| Method | Route | Handler | Min role | Danger |
|---|---|---|---|---|
| POST | `/api/auth/change-password` | apiAuthChangePassword | viewer | medium |
| POST | `/api/auth/login` | apiAuthLogin | public | medium |
| POST | `/api/auth/logout` | apiAuthLogout | public | medium |
| GET | `/api/auth/status` | apiAuthStatus | public | none |
| DELETE | `/api/auth/users` | apiAuthUsers | admin | high |
| GET | `/api/auth/users` | apiAuthUsers | admin | none |
| POST | `/api/auth/users` | apiAuthUsers | admin | medium |
| GET | `/api/authpolicy` | apiAuthPolicy | viewer | none |
| GET | `/api/blocklist/mode` | apiBlocklistMode | viewer | none |
| POST | `/api/ca/rotate` | apiCARotate | admin | high |
| GET | `/api/ca/status` | apiCAStatus | viewer | none |
| GET | `/api/config/export` | apiConfigExport | admin | none |
| POST | `/api/config/import` | apiConfigImport | admin | high |
| GET | `/api/connlimit` | apiConnLimit | viewer | none |
| DELETE | `/api/decryption-exclusions` | apiDecryptionExclusions | operator | high |
| GET | `/api/decryption-exclusions` | apiDecryptionExclusions | viewer | none |
| GET | `/api/decryption/health` | apiDecryptionHealth | viewer | none |
| GET | `/api/default-action` | apiDefaultAction | viewer | none |
| GET | `/api/governance/control-plane` | apiGovernanceControlPlane | admin | none |
| GET | `/api/logger` | apiLoggerConfig | viewer | none |
| GET | `/api/ocsp` | apiOCSPConfig | viewer | none |
| GET | `/api/pac-config` | apiPACConfig | viewer | none |
| GET | `/api/policy` | apiPolicy | viewer | none |
| GET | `/api/security` | apiSecurity | viewer | none |
| GET | `/api/session-timeout` | apiSessionTimeout | viewer | none |
| POST | `/api/setup/complete` | apiSetupComplete | public | medium |
| GET | `/api/setup/status` | apiSetupStatus | public | none |
| GET | `/api/ssl-bypass` | apiSSLBypass | viewer | none |
| * | `/api/stats` | apiStats | viewer | medium |
| * | `/api/top-hosts` | apiTopHosts | viewer | medium |
| GET | `/healthz` | apiHealthz | public | none |

## Non-REST surfaces (out of OpenAPI scope)

- Forward-proxy data path (CONNECT/plain-HTTP/SOCKS5); CP↔DP gRPC; proxy-listener built-ins; scan sidecar (risk register §8/§9).
