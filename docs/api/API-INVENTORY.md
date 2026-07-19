# API Inventory

Authoritative source: `api/route-classification.yaml` (enforced by the route-coverage gate). Generated.

- **Total method-entries:** 284
- **Documented:** 196
- **Exempt (≤270-day horizon):** 88

## By domain

| Domain | Entries | Documented |
|---|---|---|
| auth | 18 | 7 |
| cdr | 11 | 9 |
| cluster | 31 | 26 |
| dashboard | 13 | 10 |
| governance | 1 | 1 |
| observability | 2 | 2 |
| pac | 23 | 17 |
| policy | 65 | 50 |
| release | 6 | 5 |
| security | 51 | 40 |
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
| DELETE | `/api/authpolicy` | apiAuthPolicy | admin |
| GET | `/api/authpolicy` | apiAuthPolicy | viewer |
| POST | `/api/authpolicy` | apiAuthPolicy | admin |
| PUT | `/api/authpolicy` | apiAuthPolicy | admin |
| DELETE | `/api/blocklist/exceptions` | apiBlocklistExceptions | operator |
| GET | `/api/blocklist/exceptions` | apiBlocklistExceptions | viewer |
| POST | `/api/blocklist/exceptions` | apiBlocklistExceptions | operator |
| DELETE | `/api/blocklist/feed` | apiBlocklistFeed | operator |
| GET | `/api/blocklist/feed` | apiBlocklistFeed | viewer |
| POST | `/api/blocklist/feed` | apiBlocklistFeed | operator |
| GET | `/api/blocklist/mode` | apiBlocklistMode | viewer |
| POST | `/api/blocklist/mode` | apiBlocklistMode | operator |
| PUT | `/api/blockpage` | apiBlockPage | admin |
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
| GET | `/api/cdr/config` | apiCDRConfig | viewer |
| PUT | `/api/cdr/config` | apiCDRConfig | admin |
| GET | `/api/cdr/health` | apiCDRHealth | viewer |
| DELETE | `/api/cdr/instances` | apiCDRInstances | admin |
| GET | `/api/cdr/instances` | apiCDRInstances | viewer |
| DELETE | `/api/cdr/policies` | apiCDRPolicies | admin |
| GET | `/api/cdr/policies` | apiCDRPolicies | viewer |
| POST | `/api/cdr/policies` | apiCDRPolicies | admin |
| POST | `/api/cdr/test` | apiCDRTest | admin |
| GET | `/api/cluster/audit` | apiClusterAudit | viewer |
| DELETE | `/api/cluster/bandwidth` | apiBandwidthPolicies | admin |
| GET | `/api/cluster/bandwidth` | apiBandwidthPolicies | viewer |
| POST | `/api/cluster/bandwidth` | apiBandwidthPolicies | admin |
| GET | `/api/cluster/ca` | apiClusterCA | viewer |
| POST | `/api/cluster/ca` | apiClusterCA | admin |
| POST | `/api/cluster/drain` | apiClusterDrain | admin |
| GET | `/api/cluster/ha` | apiClusterHA | viewer |
| POST | `/api/cluster/ha` | apiClusterHA | admin |
| POST | `/api/cluster/ha/promote` | apiClusterHAPromote | admin |
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
| DELETE | `/api/dpi` | apiContentScan | operator |
| GET | `/api/dpi` | apiContentScan | viewer |
| POST | `/api/dpi` | apiContentScan | operator |
| GET | `/api/dpi/bypass` | apiContentScanBypass | viewer |
| PUT | `/api/dpi/bypass` | apiContentScanBypass | admin |
| GET | `/api/fileblock` | apiFileblock | viewer |
| POST | `/api/fileblock` | apiFileblock | operator |
| DELETE | `/api/fileblock/profiles` | apiFileblockProfiles | operator |
| GET | `/api/fileblock/profiles` | apiFileblockProfiles | viewer |
| POST | `/api/fileblock/profiles` | apiFileblockProfiles | operator |
| PUT | `/api/fileblock/profiles` | apiFileblockProfiles | operator |
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
| POST | `/api/pac/pools` | apiPACPools | admin |
| DELETE | `/api/pac/pools/` | apiPACPoolItem | admin |
| GET | `/api/pac/pools/` | apiPACPoolItem | viewer |
| PUT | `/api/pac/pools/` | apiPACPoolItem | admin |
| DELETE | `/api/pac/posture/exceptions/` | apiPACExceptionItem | admin |
| GET | `/api/pac/posture/exceptions/` | apiPACExceptionItem | viewer |
| PUT | `/api/pac/posture/exceptions/` | apiPACExceptionItem | admin |
| GET | `/api/pac/posture/inventory` | apiPACPostureInventory | viewer |
| GET | `/api/pac/profiles` | apiPACProfiles | viewer |
| POST | `/api/pac/profiles` | apiPACProfiles | admin |
| DELETE | `/api/pac/profiles/` | apiPACProfileItem | admin |
| GET | `/api/pac/profiles/` | apiPACProfileItem | viewer |
| POST | `/api/pac/profiles/` | apiPACProfileItem | admin |
| PUT | `/api/pac/profiles/` | apiPACProfileItem | admin |
| DELETE | `/api/policy` | apiPolicy | operator |
| GET | `/api/policy` | apiPolicy | viewer |
| POST | `/api/policy` | apiPolicy | operator |
| PUT | `/api/policy` | apiPolicy | operator |
| GET | `/api/policy/draft` | apiPolicyDraft | viewer |
| PUT | `/api/policy/draft` | apiPolicyDraft | admin |
| GET | `/api/releases` | apiReleases | viewer |
| POST | `/api/releases/catalog-refresh` | apiReleaseCatalogRefresh | admin |
| GET | `/api/releases/current` | apiReleaseCurrent | viewer |
| POST | `/api/releases/dispatch/resume` | apiReleaseDispatchResume | admin |
| GET | `/api/releases/dispatch/status` | apiReleaseDispatchStatus | viewer |
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
| DELETE | `/api/security-scan/yara/rules` | apiSecYARARules | admin |
| GET | `/api/security-scan/yara/rules` | apiSecYARARules | viewer |
| POST | `/api/security-scan/yara/rules` | apiSecYARARules | admin |
| PUT | `/api/security-scan/yara/rules` | apiSecYARARules | admin |
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
| DELETE | `/api/urlcat` | apiURLCat | operator |
| GET | `/api/urlcat` | apiURLCat | viewer |
| POST | `/api/urlcat` | apiURLCat | operator |
| PUT | `/api/urlcat` | apiURLCat | operator |
| GET | `/healthz` | apiHealthz | public |
