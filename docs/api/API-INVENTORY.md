# API Inventory

Authoritative source: `api/route-classification.yaml` (enforced by the route-coverage gate). Generated.

- **Total method-entries:** 284
- **Documented:** 156
- **Exempt (≤270-day horizon):** 128

## By domain

| Domain | Entries | Documented |
|---|---|---|
| auth | 18 | 7 |
| cdr | 11 | 0 |
| cluster | 31 | 20 |
| dashboard | 13 | 10 |
| governance | 1 | 1 |
| observability | 2 | 2 |
| pac | 23 | 15 |
| policy | 65 | 36 |
| release | 6 | 1 |
| security | 51 | 35 |
| settings | 30 | 19 |
| setup | 2 | 2 |
| static | 1 | 0 |
| support | 30 | 8 |

## Documented operations

| Method | Route | Handler | Min role |
|---|---|---|---|
| DELETE | `/api/alerts/webhooks` | apiAlertsWebhooks | operator |
| GET | `/api/alerts/webhooks` | apiAlertsWebhooks | viewer |
| POST | `/api/alerts/webhooks` | apiAlertsWebhooks | operator |
| PUT | `/api/alerts/webhooks` | apiAlertsWebhooks | operator |
| GET | `/api/audit` | apiAudit | viewer |
| POST | `/api/auth/change-password` | apiAuthChangePassword | viewer |
| POST | `/api/auth/login` | apiAuthLogin | public |
| POST | `/api/auth/logout` | apiAuthLogout | public |
| GET | `/api/auth/status` | apiAuthStatus | public |
| DELETE | `/api/auth/users` | apiAuthUsers | admin |
| GET | `/api/auth/users` | apiAuthUsers | admin |
| POST | `/api/auth/users` | apiAuthUsers | admin |
| GET | `/api/authpolicy` | apiAuthPolicy | viewer |
| DELETE | `/api/blocklist/exceptions` | apiBlocklistExceptions | operator |
| GET | `/api/blocklist/exceptions` | apiBlocklistExceptions | viewer |
| POST | `/api/blocklist/exceptions` | apiBlocklistExceptions | operator |
| DELETE | `/api/blocklist/feed` | apiBlocklistFeed | operator |
| GET | `/api/blocklist/feed` | apiBlocklistFeed | viewer |
| POST | `/api/blocklist/feed` | apiBlocklistFeed | operator |
| GET | `/api/blocklist/mode` | apiBlocklistMode | viewer |
| POST | `/api/blocklist/mode` | apiBlocklistMode | operator |
| GET | `/api/ca-cert` | apiCACert | viewer |
| POST | `/api/ca/cache-clear` | apiCACacheClear | admin |
| GET | `/api/ca/download` | apiCADownload | viewer |
| GET | `/api/ca/key-provider` | apiCAKeyProvider | viewer |
| POST | `/api/ca/rotate` | apiCARotate | admin |
| GET | `/api/ca/status` | apiCAStatus | viewer |
| DELETE | `/api/category-groups` | apiCategoryGroups | operator |
| GET | `/api/category-groups` | apiCategoryGroups | viewer |
| POST | `/api/category-groups` | apiCategoryGroups | operator |
| PUT | `/api/category-groups` | apiCategoryGroups | operator |
| GET | `/api/cluster/audit` | apiClusterAudit | viewer |
| GET | `/api/cluster/bandwidth` | apiBandwidthPolicies | viewer |
| GET | `/api/cluster/ca` | apiClusterCA | viewer |
| GET | `/api/cluster/ha` | apiClusterHA | viewer |
| GET | `/api/cluster/metrics` | apiClusterMetrics | viewer |
| DELETE | `/api/cluster/node-groups` | apiNodeGroups | admin |
| GET | `/api/cluster/node-groups` | apiNodeGroups | viewer |
| POST | `/api/cluster/node-groups` | apiNodeGroups | admin |
| GET | `/api/cluster/node-groups/membership` | apiNodeGroupMembership | viewer |
| GET | `/api/cluster/nodes` | apiClusterNodes | viewer |
| GET | `/api/cluster/rate-limits` | apiClusterRateLimits | viewer |
| GET | `/api/cluster/revocations` | apiClusterRevocations | viewer |
| GET | `/api/cluster/rotation` | apiClusterRotation | viewer |
| GET | `/api/cluster/status` | apiClusterStatus | viewer |
| DELETE | `/api/cluster/tokens` | apiClusterTokens | admin |
| GET | `/api/cluster/tokens` | apiClusterTokens | viewer |
| POST | `/api/cluster/tokens` | apiClusterTokens | admin |
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
| PUT | `/api/decryption-exclusions/tunables` | apiDecryptionExclusionTunables | admin |
| DELETE | `/api/decryption-profiles` | apiDecryptionProfiles | operator |
| GET | `/api/decryption-profiles` | apiDecryptionProfiles | viewer |
| POST | `/api/decryption-profiles` | apiDecryptionProfiles | operator |
| PUT | `/api/decryption-profiles` | apiDecryptionProfiles | operator |
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
| POST | `/api/fileblock` | apiFileblock | operator |
| GET | `/api/fileblock/profiles` | apiFileblockProfiles | viewer |
| GET | `/api/governance/control-plane` | apiGovernanceControlPlane | admin |
| GET | `/api/health/explain` | apiHealthExplain | viewer |
| GET | `/api/logger` | apiLoggerConfig | viewer |
| GET | `/api/logs/retention` | apiLogsRetention | viewer |
| PUT | `/api/logs/retention` | apiLogsRetention | admin |
| GET | `/api/metrics-config` | apiMetricsConfig | viewer |
| POST | `/api/metrics-config` | apiMetricsConfig | admin |
| GET | `/api/objects/references` | apiObjectReferences | viewer |
| GET | `/api/ocsp` | apiOCSPConfig | viewer |
| POST | `/api/ocsp` | apiOCSPConfig | admin |
| GET | `/api/pac-config` | apiPACConfig | viewer |
| POST | `/api/pac-config` | apiPACConfig | admin |
| GET | `/api/pac/pools` | apiPACPools | viewer |
| DELETE | `/api/pac/pools/` | apiPACPoolItem | admin |
| GET | `/api/pac/pools/` | apiPACPoolItem | viewer |
| PUT | `/api/pac/pools/` | apiPACPoolItem | admin |
| DELETE | `/api/pac/posture/exceptions/` | apiPACExceptionItem | admin |
| GET | `/api/pac/posture/exceptions/` | apiPACExceptionItem | viewer |
| PUT | `/api/pac/posture/exceptions/` | apiPACExceptionItem | admin |
| GET | `/api/pac/posture/inventory` | apiPACPostureInventory | viewer |
| GET | `/api/pac/profiles` | apiPACProfiles | viewer |
| DELETE | `/api/pac/profiles/` | apiPACProfileItem | admin |
| GET | `/api/pac/profiles/` | apiPACProfileItem | viewer |
| POST | `/api/pac/profiles/` | apiPACProfileItem | admin |
| PUT | `/api/pac/profiles/` | apiPACProfileItem | admin |
| GET | `/api/policy` | apiPolicy | viewer |
| GET | `/api/policy/draft` | apiPolicyDraft | viewer |
| GET | `/api/releases` | apiReleases | viewer |
| DELETE | `/api/rewrite` | apiRewrite | operator |
| GET | `/api/rewrite` | apiRewrite | viewer |
| POST | `/api/rewrite` | apiRewrite | operator |
| GET | `/api/security` | apiSecurity | viewer |
| POST | `/api/security` | apiSecurity | admin |
| GET | `/api/security-scan/cache` | apiScanCache | viewer |
| GET | `/api/security-scan/exclusions` | apiSecScanExclusions | viewer |
| PUT | `/api/security-scan/exclusions` | apiSecScanExclusions | admin |
| GET | `/api/security-scan/feeds/domain-allowlist` | apiDomainAllowlist | viewer |
| PUT | `/api/security-scan/feeds/domain-allowlist` | apiDomainAllowlist | admin |
| POST | `/api/security-scan/feeds/sync` | apiSecFeedsSync | admin |
| GET | `/api/security-scan/status` | apiSecScanStatus | viewer |
| GET | `/api/security-scan/svc` | apiScanSvcConfig | viewer |
| POST | `/api/security-scan/yara/reload` | apiSecYARAReload | admin |
| GET | `/api/security-scan/yara/rules` | apiSecYARARules | viewer |
| DELETE | `/api/security-scan/yara/rules/` | apiSecYARARules | admin |
| GET | `/api/security-scan/yara/rules/` | apiSecYARARules | viewer |
| PUT | `/api/security-scan/yara/rules/` | apiSecYARARules | admin |
| GET | `/api/security-scan/yara/settings` | apiSecYARASettings | viewer |
| PUT | `/api/security-scan/yara/settings` | apiSecYARASettings | admin |
| POST | `/api/security-scan/yara/validate` | apiSecYARAValidate | operator |
| GET | `/api/session-secret` | apiSessionSecret | viewer |
| POST | `/api/session-secret` | apiSessionSecret | admin |
| GET | `/api/session-timeout` | apiSessionTimeout | viewer |
| POST | `/api/session-timeout` | apiSessionTimeout | admin |
| GET | `/api/settings` | apiSettings | viewer |
| POST | `/api/settings` | apiSettings | admin |
| GET | `/api/settings/log-level` | apiLogLevel | viewer |
| PUT | `/api/settings/log-level` | apiLogLevel | admin |
| GET | `/api/settings/network` | apiNetworkSettings | viewer |
| POST | `/api/settings/network` | apiNetworkSettings | admin |
| POST | `/api/setup/complete` | apiSetupComplete | public |
| GET | `/api/setup/status` | apiSetupStatus | public |
| GET | `/api/ssl-bypass` | apiSSLBypass | viewer |
| POST | `/api/ssl-bypass` | apiSSLBypass | operator |
| * | `/api/stats` | apiStats | viewer |
| GET | `/api/support/bundles` | apiSupportBundles | viewer |
| GET | `/api/support/debug-level` | apiSupportDebugLevel | viewer |
| GET | `/api/support/recipients` | apiSupportRecipients | viewer |
| POST | `/api/support/recipients` | apiSupportRecipients | admin |
| GET | `/api/support/retention` | apiSupportRetention | viewer |
| PUT | `/api/support/retention` | apiSupportRetention | admin |
| GET | `/api/support/status` | apiSupportStatus | viewer |
| * | `/api/timeseries` | apiTimeseries | viewer |
| * | `/api/top-hosts` | apiTopHosts | viewer |
| GET | `/api/upstream` | apiUpstream | viewer |
| POST | `/api/upstream` | apiUpstream | admin |
| GET | `/api/upstream/settings` | apiUpstreamSettings | viewer |
| GET | `/api/urlcat` | apiURLCat | viewer |
| GET | `/healthz` | apiHealthz | public |
