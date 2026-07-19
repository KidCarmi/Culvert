# API Inventory

Authoritative source: `api/route-classification.yaml` (enforced by the route-coverage gate). Generated.

- **Total method-entries:** 284
- **Documented:** 103
- **Exempt (≤270-day horizon):** 181

## By domain

| Domain | Entries | Documented |
|---|---|---|
| auth | 18 | 7 |
| cdr | 11 | 0 |
| cluster | 31 | 15 |
| dashboard | 13 | 9 |
| governance | 1 | 1 |
| observability | 2 | 2 |
| pac | 23 | 4 |
| policy | 65 | 22 |
| release | 6 | 1 |
| security | 51 | 18 |
| settings | 30 | 16 |
| setup | 2 | 2 |
| static | 1 | 0 |
| support | 30 | 6 |

## Documented operations

| Method | Route | Handler | Min role |
|---|---|---|---|
| GET | `/api/audit` | apiAudit | viewer |
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
| POST | `/api/blocklist/mode` | apiBlocklistMode | operator |
| GET | `/api/ca/key-provider` | apiCAKeyProvider | viewer |
| POST | `/api/ca/rotate` | apiCARotate | admin |
| GET | `/api/ca/status` | apiCAStatus | viewer |
| GET | `/api/category-groups` | apiCategoryGroups | viewer |
| GET | `/api/cluster/audit` | apiClusterAudit | viewer |
| GET | `/api/cluster/bandwidth` | apiBandwidthPolicies | viewer |
| GET | `/api/cluster/ca` | apiClusterCA | viewer |
| GET | `/api/cluster/ha` | apiClusterHA | viewer |
| GET | `/api/cluster/metrics` | apiClusterMetrics | viewer |
| GET | `/api/cluster/node-groups` | apiNodeGroups | viewer |
| GET | `/api/cluster/node-groups/membership` | apiNodeGroupMembership | viewer |
| GET | `/api/cluster/nodes` | apiClusterNodes | viewer |
| GET | `/api/cluster/rate-limits` | apiClusterRateLimits | viewer |
| GET | `/api/cluster/revocations` | apiClusterRevocations | viewer |
| GET | `/api/cluster/rotation` | apiClusterRotation | viewer |
| GET | `/api/cluster/status` | apiClusterStatus | viewer |
| GET | `/api/cluster/tokens` | apiClusterTokens | viewer |
| GET | `/api/config/diff` | apiConfigDiff | viewer |
| GET | `/api/config/export` | apiConfigExport | admin |
| POST | `/api/config/import` | apiConfigImport | admin |
| GET | `/api/config/versions` | apiConfigVersions | viewer |
| GET | `/api/connlimit` | apiConnLimit | viewer |
| POST | `/api/connlimit` | apiConnLimit | admin |
| * | `/api/country-traffic` | apiCountryTraffic | viewer |
| * | `/api/dashboard/health` | apiDashboardHealth | viewer |
| * | `/api/dashboard/threats` | apiDashboardThreats | viewer |
| * | `/api/dashboard/top-rules` | apiDashboardTopRules | viewer |
| DELETE | `/api/decryption-exclusions` | apiDecryptionExclusions | operator |
| GET | `/api/decryption-exclusions` | apiDecryptionExclusions | viewer |
| GET | `/api/decryption-exclusions/tunables` | apiDecryptionExclusionTunables | viewer |
| GET | `/api/decryption-profiles` | apiDecryptionProfiles | viewer |
| GET | `/api/decryption/health` | apiDecryptionHealth | viewer |
| GET | `/api/decryption/redaction` | apiDecryptionRedaction | viewer |
| PUT | `/api/decryption/redaction` | apiDecryptionRedaction | admin |
| GET | `/api/default-action` | apiDefaultAction | viewer |
| POST | `/api/default-action` | apiDefaultAction | operator |
| GET | `/api/diagnostics` | apiDiagnostics | viewer |
| GET | `/api/dpi` | apiContentScan | viewer |
| GET | `/api/dpi/bypass` | apiContentScanBypass | viewer |
| PUT | `/api/dpi/bypass` | apiContentScanBypass | admin |
| GET | `/api/fileblock` | apiFileblock | viewer |
| GET | `/api/fileblock/profiles` | apiFileblockProfiles | viewer |
| GET | `/api/governance/control-plane` | apiGovernanceControlPlane | admin |
| GET | `/api/health/explain` | apiHealthExplain | viewer |
| GET | `/api/logger` | apiLoggerConfig | viewer |
| GET | `/api/logs/retention` | apiLogsRetention | viewer |
| GET | `/api/metrics-config` | apiMetricsConfig | viewer |
| POST | `/api/metrics-config` | apiMetricsConfig | admin |
| GET | `/api/objects/references` | apiObjectReferences | viewer |
| GET | `/api/ocsp` | apiOCSPConfig | viewer |
| POST | `/api/ocsp` | apiOCSPConfig | admin |
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
| GET | `/api/security-scan/exclusions` | apiSecScanExclusions | viewer |
| GET | `/api/security-scan/feeds/domain-allowlist` | apiDomainAllowlist | viewer |
| GET | `/api/security-scan/status` | apiSecScanStatus | viewer |
| GET | `/api/security-scan/svc` | apiScanSvcConfig | viewer |
| GET | `/api/security-scan/yara/rules` | apiSecYARARules | viewer |
| GET | `/api/security-scan/yara/settings` | apiSecYARASettings | viewer |
| GET | `/api/session-secret` | apiSessionSecret | viewer |
| GET | `/api/session-timeout` | apiSessionTimeout | viewer |
| POST | `/api/session-timeout` | apiSessionTimeout | admin |
| GET | `/api/settings` | apiSettings | viewer |
| GET | `/api/settings/log-level` | apiLogLevel | viewer |
| PUT | `/api/settings/log-level` | apiLogLevel | admin |
| GET | `/api/settings/network` | apiNetworkSettings | viewer |
| POST | `/api/setup/complete` | apiSetupComplete | public |
| GET | `/api/setup/status` | apiSetupStatus | public |
| GET | `/api/ssl-bypass` | apiSSLBypass | viewer |
| POST | `/api/ssl-bypass` | apiSSLBypass | operator |
| * | `/api/stats` | apiStats | viewer |
| GET | `/api/support/bundles` | apiSupportBundles | viewer |
| GET | `/api/support/debug-level` | apiSupportDebugLevel | viewer |
| GET | `/api/support/recipients` | apiSupportRecipients | viewer |
| GET | `/api/support/retention` | apiSupportRetention | viewer |
| GET | `/api/support/status` | apiSupportStatus | viewer |
| * | `/api/timeseries` | apiTimeseries | viewer |
| * | `/api/top-hosts` | apiTopHosts | viewer |
| GET | `/api/upstream` | apiUpstream | viewer |
| GET | `/api/upstream/settings` | apiUpstreamSettings | viewer |
| GET | `/api/urlcat` | apiURLCat | viewer |
| GET | `/healthz` | apiHealthz | public |
