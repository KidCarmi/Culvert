# API Inventory

Authoritative source: `api/route-classification.yaml` (enforced by the route-coverage gate). Generated.

- **Total method-entries:** 284
- **Documented:** 61
- **Exempt (≤270-day horizon):** 223

## By domain

| Domain | Entries | Documented |
|---|---|---|
| auth | 18 | 7 |
| cdr | 11 | 0 |
| cluster | 31 | 0 |
| dashboard | 13 | 3 |
| governance | 1 | 1 |
| observability | 2 | 1 |
| pac | 23 | 4 |
| policy | 65 | 18 |
| release | 6 | 1 |
| security | 51 | 13 |
| settings | 30 | 11 |
| setup | 2 | 2 |
| static | 1 | 0 |
| support | 30 | 0 |

## Documented operations

| Method | Route | Handler | Min role |
|---|---|---|---|
| POST | `/api/auth/change-password` | apiAuthChangePassword | viewer |
| POST | `/api/auth/login` | apiAuthLogin | public |
| POST | `/api/auth/logout` | apiAuthLogout | public |
| GET | `/api/auth/status` | apiAuthStatus | public |
| DELETE | `/api/auth/users` | apiAuthUsers | admin |
| GET | `/api/auth/users` | apiAuthUsers | admin |
| POST | `/api/auth/users` | apiAuthUsers | admin |
| GET | `/api/authpolicy` | apiAuthPolicy | viewer |
| GET | `/api/blocklist/exceptions` | apiBlocklistExceptions | viewer |
| GET | `/api/blocklist/feed` | apiBlocklistFeed | viewer |
| GET | `/api/blocklist/mode` | apiBlocklistMode | viewer |
| GET | `/api/ca/key-provider` | apiCAKeyProvider | viewer |
| POST | `/api/ca/rotate` | apiCARotate | admin |
| GET | `/api/ca/status` | apiCAStatus | viewer |
| GET | `/api/category-groups` | apiCategoryGroups | viewer |
| GET | `/api/config/export` | apiConfigExport | admin |
| POST | `/api/config/import` | apiConfigImport | admin |
| GET | `/api/config/versions` | apiConfigVersions | viewer |
| GET | `/api/connlimit` | apiConnLimit | viewer |
| DELETE | `/api/decryption-exclusions` | apiDecryptionExclusions | operator |
| GET | `/api/decryption-exclusions` | apiDecryptionExclusions | viewer |
| GET | `/api/decryption-profiles` | apiDecryptionProfiles | viewer |
| GET | `/api/decryption/health` | apiDecryptionHealth | viewer |
| GET | `/api/decryption/redaction` | apiDecryptionRedaction | viewer |
| GET | `/api/default-action` | apiDefaultAction | viewer |
| GET | `/api/dpi` | apiContentScan | viewer |
| GET | `/api/dpi/bypass` | apiContentScanBypass | viewer |
| GET | `/api/fileblock` | apiFileblock | viewer |
| GET | `/api/fileblock/profiles` | apiFileblockProfiles | viewer |
| GET | `/api/governance/control-plane` | apiGovernanceControlPlane | admin |
| GET | `/api/logger` | apiLoggerConfig | viewer |
| GET | `/api/logs/retention` | apiLogsRetention | viewer |
| GET | `/api/metrics-config` | apiMetricsConfig | viewer |
| GET | `/api/objects/references` | apiObjectReferences | viewer |
| GET | `/api/ocsp` | apiOCSPConfig | viewer |
| GET | `/api/pac-config` | apiPACConfig | viewer |
| GET | `/api/pac/pools` | apiPACPools | viewer |
| GET | `/api/pac/posture/inventory` | apiPACPostureInventory | viewer |
| GET | `/api/pac/profiles` | apiPACProfiles | viewer |
| GET | `/api/policy` | apiPolicy | viewer |
| GET | `/api/policy/draft` | apiPolicyDraft | viewer |
| GET | `/api/releases` | apiReleases | viewer |
| GET | `/api/rewrite` | apiRewrite | viewer |
| GET | `/api/security` | apiSecurity | viewer |
| GET | `/api/security-scan/cache` | apiScanCache | viewer |
| GET | `/api/security-scan/feeds/domain-allowlist` | apiDomainAllowlist | viewer |
| GET | `/api/security-scan/status` | apiSecScanStatus | viewer |
| GET | `/api/security-scan/svc` | apiScanSvcConfig | viewer |
| GET | `/api/security-scan/yara/settings` | apiSecYARASettings | viewer |
| GET | `/api/session-secret` | apiSessionSecret | viewer |
| GET | `/api/session-timeout` | apiSessionTimeout | viewer |
| GET | `/api/settings` | apiSettings | viewer |
| GET | `/api/settings/log-level` | apiLogLevel | viewer |
| GET | `/api/settings/network` | apiNetworkSettings | viewer |
| POST | `/api/setup/complete` | apiSetupComplete | public |
| GET | `/api/setup/status` | apiSetupStatus | public |
| GET | `/api/ssl-bypass` | apiSSLBypass | viewer |
| * | `/api/stats` | apiStats | viewer |
| * | `/api/top-hosts` | apiTopHosts | viewer |
| GET | `/api/urlcat` | apiURLCat | viewer |
| GET | `/healthz` | apiHealthz | public |
