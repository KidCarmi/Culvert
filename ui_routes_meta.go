package main

// ── Phase C1: Route Metadata Table (SHADOW / REPORT-ONLY) ─────────────────
//
// uiRoutes is the canonical, alphabetised metadata for every admin-UI
// route. It supersedes the hand-maintained d0KnownRoutes mirror as the
// authoritative inventory source for D0 regression tests.
//
// PHASE C1 SHADOW MODE — every field below is documentation only:
//   • MinRole, Mutating, AuditExpected, Public, Domain, Handler are
//     declarations of intent. Nothing in the request lifecycle reads
//     these fields. uiAuthMiddleware still uses its hand-coded
//     allowlist; per-handler requireRole calls still gate RBAC; the
//     securityMiddleware CSRF/body/rate-limit checks still derive
//     "mutating" from r.Method directly.
//   • The metadata exists so tests can verify intent matches the
//     registered mux, and so Phase C2 can switch enforcement on without
//     introducing the table at the same time.
//
// PHASE C2 (NOT YET): the metadata becomes authoritative. Middleware
// will look up MinRole, Mutating, etc. from this table instead of
// duplicating the logic at each call site.

// RolePublic is a sentinel UIRole used in metadata to mark a route as
// intentionally exposed without authentication. It is NOT enrolled in
// rolePriority, so HasRole(RolePublic, anyRealRole) is false for every
// real role — the value is documentation, not an enforcement primitive.
const RolePublic UIRole = "public"

// uiRouteMetadata captures the intended contract of one admin-UI route.
// See the package-level comment above for SHADOW-MODE caveats.
type uiRouteMetadata struct {
	Path          string // ServeMux pattern (exact path or trailing-slash prefix)
	Handler       string // handler function name, for documentation/tooling
	Domain        string // panel grouping owning the route ("auth", "policy", ...)
	Public        bool   // intended public-allowlist membership (doc only)
	MinRole       UIRole // intended minimum role (doc only)
	Mutating      bool   // route accepts at least one mutating method (doc only)
	AuditExpected bool   // handler is expected to call auditEvent on success (doc only)
}

// uiRoutes is the alphabetised metadata table for all 131 admin-UI routes.
// Length is locked by TestC1_RouteMetadata_Locked131; bidirectional parity
// with the wired mux is checked by TestC1_RouteMetadata_Forward and
// TestC1_RouteMetadata_Reverse.
//
// MinRole reflects the LOWEST role the handler accepts on any path
// through it (a switch-on-method handler that allows GET=Viewer and
// POST=Admin records MinRole=RoleViewer here).
//
// Mutating is true for any route whose handler has at least one
// POST/PUT/DELETE branch.
//
// AuditExpected is true when the handler calls auditEvent on a
// successful mutation; status/read-only routes are false.
var uiRoutes = []uiRouteMetadata{
	// ── Static SPA ────────────────────────────────────────────────────────
	{Path: "/", Handler: "serveUIShell", Domain: "static",
		Public: true, MinRole: RolePublic, Mutating: false, AuditExpected: false},

	// ── Setup bootstrap (public allowlist /api/setup) ─────────────────────
	{Path: "/api/setup/status", Handler: "apiSetupStatus", Domain: "setup",
		Public: true, MinRole: RolePublic, Mutating: false, AuditExpected: false},
	{Path: "/api/setup/complete", Handler: "apiSetupComplete", Domain: "setup",
		Public: true, MinRole: RolePublic, Mutating: true, AuditExpected: true},

	// ── Admin session auth ────────────────────────────────────────────────
	{Path: "/api/auth/login", Handler: "apiAuthLogin", Domain: "auth",
		Public: true, MinRole: RolePublic, Mutating: true, AuditExpected: true},
	{Path: "/api/auth/status", Handler: "apiAuthStatus", Domain: "auth",
		Public: true, MinRole: RolePublic, Mutating: false, AuditExpected: false},
	{Path: "/api/auth/logout", Handler: "apiAuthLogout", Domain: "auth",
		Public: true, MinRole: RolePublic, Mutating: true, AuditExpected: true},
	{Path: "/api/auth/users", Handler: "apiAuthUsers", Domain: "auth",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/auth/change-password", Handler: "apiAuthChangePassword", Domain: "auth",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},

	// ── Generic IdP framework ─────────────────────────────────────────────
	{Path: "/api/idp", Handler: "apiIdPList", Domain: "auth",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/idp/discover", Handler: "apiIdPDiscover", Domain: "auth",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: false},
	{Path: "/api/idp/", Handler: "apiIdPRouter", Domain: "auth",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},

	// ── Auth callbacks (browser redirects from IdPs, public allowlist) ────
	{Path: "/auth/oidc/callback", Handler: "authOIDCCallback", Domain: "auth",
		Public: true, MinRole: RolePublic, Mutating: false, AuditExpected: false},
	{Path: "/auth/saml/callback", Handler: "authSAMLCallback", Domain: "auth",
		Public: true, MinRole: RolePublic, Mutating: false, AuditExpected: false},
	{Path: "/auth/select", Handler: "authSelectProvider", Domain: "auth",
		Public: true, MinRole: RolePublic, Mutating: false, AuditExpected: false},
	{Path: "/auth/logout", Handler: "authLogout", Domain: "auth",
		Public: true, MinRole: RolePublic, Mutating: false, AuditExpected: false},

	// ── Dashboard / live stats ────────────────────────────────────────────
	{Path: "/api/stats", Handler: "apiStats", Domain: "dashboard",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/dashboard/health", Handler: "apiDashboardHealth", Domain: "dashboard",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/dashboard/threats", Handler: "apiDashboardThreats", Domain: "dashboard",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/dashboard/top-rules", Handler: "apiDashboardTopRules", Domain: "dashboard",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/timeseries", Handler: "apiTimeseries", Domain: "dashboard",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/logs", Handler: "apiLogs", Domain: "dashboard",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/top-hosts", Handler: "apiTopHosts", Domain: "dashboard",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/audit", Handler: "apiAudit", Domain: "dashboard",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/events", Handler: "apiEvents", Domain: "dashboard",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/country-traffic", Handler: "apiCountryTraffic", Domain: "dashboard",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},

	// ── Policy / blocklist / filtering ────────────────────────────────────
	{Path: "/api/blocklist", Handler: "apiBlocklist", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/fileblock", Handler: "apiFileblock", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/fileblock/profiles", Handler: "apiFileblockProfiles", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/rewrite", Handler: "apiRewrite", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/policy", Handler: "apiPolicy", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/policy/reorder", Handler: "apiPolicyReorder", Domain: "policy",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: true},
	{Path: "/api/policy/move", Handler: "apiPolicyMove", Domain: "policy",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: true},
	{Path: "/api/policy/test", Handler: "apiPolicyTest", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: false},
	{Path: "/api/default-action", Handler: "apiDefaultAction", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/blocklist/mode", Handler: "apiBlocklistMode", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/blocklist/feed", Handler: "apiBlocklistFeed", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/blocklist/feed/sync", Handler: "apiBlocklistFeedSync", Domain: "policy",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: true},
	{Path: "/api/blocklist/exceptions", Handler: "apiBlocklistExceptions", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/category-groups", Handler: "apiCategoryGroups", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/urlcat", Handler: "apiURLCat", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/urlcat/host", Handler: "apiURLCatHost", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/urlcat/lookup", Handler: "apiURLCatLookup", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/blockpage", Handler: "apiBlockPage", Domain: "policy",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},

	// ── PAC file ──────────────────────────────────────────────────────────
	{Path: "/proxy.pac", Handler: "servePACFile", Domain: "pac",
		Public: true, MinRole: RolePublic, Mutating: false, AuditExpected: false},
	{Path: "/api/pac-config", Handler: "apiPACConfig", Domain: "pac",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},

	// ── Security: TLS inspect (CA, certs, SSL bypass) ─────────────────────
	{Path: "/api/security", Handler: "apiSecurity", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/ca-cert", Handler: "apiCACert", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/certs/upload", Handler: "apiCertsUpload", Domain: "security",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/ssl-bypass", Handler: "apiSSLBypass", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/content-scan", Handler: "apiContentScan", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},

	// ── Security: ClamAV / YARA / Threat Feeds ────────────────────────────
	{Path: "/api/security-scan/status", Handler: "apiSecScanStatus", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/security-scan/feeds/sync", Handler: "apiSecFeedsSync", Domain: "security",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: true},
	{Path: "/api/security-scan/feeds/domain-allowlist", Handler: "apiDomainAllowlist", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/security-scan/yara/reload", Handler: "apiSecYARAReload", Domain: "security",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: true},
	{Path: "/api/security-scan/yara/rules", Handler: "apiSecYARARules", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/security-scan/yara/rules/", Handler: "apiSecYARARules", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/security-scan/yara/validate", Handler: "apiSecYARAValidate", Domain: "security",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: false},
	{Path: "/api/security-scan/yara/settings", Handler: "apiSecYARASettings", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/security-scan/exclusions", Handler: "apiSecScanExclusions", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/security-scan/svc", Handler: "apiScanSvcConfig", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/security-scan/cache", Handler: "apiScanCache", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/content-scan/bypass", Handler: "apiContentScanBypass", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},

	// ── Security: alert webhooks ──────────────────────────────────────────
	{Path: "/api/alerts/webhooks", Handler: "apiAlertsWebhooks", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/alerts/webhooks/test", Handler: "apiAlertsWebhookTest", Domain: "security",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: false},
	{Path: "/api/alerts/webhooks/history", Handler: "apiAlertsDeliveryHist", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},

	// ── Security: CA management ───────────────────────────────────────────
	{Path: "/api/ca/status", Handler: "apiCAStatus", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/ca/key-provider", Handler: "apiCAKeyProvider", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/ca/download", Handler: "apiCADownload", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/ca/cache-clear", Handler: "apiCACacheClear", Domain: "security",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/ca/rotate", Handler: "apiCARotate", Domain: "security",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},

	// ── Security: OCSP, GeoIP ─────────────────────────────────────────────
	{Path: "/api/ocsp", Handler: "apiOCSPConfig", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/geoip", Handler: "apiGeoIPConfig", Domain: "security",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},

	// ── Settings panel (Option-A panel grouping; handlers may live in
	// logger.go / metrics.go / otlp.go / connlimit.go / blockpage.go) ──────
	{Path: "/api/settings", Handler: "apiSettings", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/export", Handler: "apiExport", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/config/export", Handler: "apiConfigExport", Domain: "settings",
		Public: false, MinRole: RoleAdmin, Mutating: false, AuditExpected: true},
	{Path: "/api/config/import", Handler: "apiConfigImport", Domain: "settings",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/config/versions", Handler: "apiConfigVersions", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/config/diff", Handler: "apiConfigDiff", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/settings/unauth-mode", Handler: "apiUnauthMode", Domain: "settings",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/settings/log-level", Handler: "apiLogLevel", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/settings/network", Handler: "apiNetworkSettings", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/session-timeout", Handler: "apiSessionTimeout", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/session-secret", Handler: "apiSessionSecret", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/ui-allow-ips", Handler: "apiUIAllowIPs", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/syslog", Handler: "apiSyslogConfig", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/syslog/test", Handler: "apiSyslogTest", Domain: "settings",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: false},
	{Path: "/api/logger", Handler: "apiLoggerConfig", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/metrics-config", Handler: "apiMetricsConfig", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/otlp", Handler: "apiOTLPConfig", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/connlimit", Handler: "apiConnLimit", Domain: "settings",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},

	// ── Cluster: upstream proxy chain ─────────────────────────────────────
	{Path: "/api/upstream", Handler: "apiUpstream", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/upstream/settings", Handler: "apiUpstreamSettings", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/upstream/health", Handler: "apiUpstreamHealth", Domain: "cluster",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: false},

	// ── Cluster: multi-node management ────────────────────────────────────
	{Path: "/api/cluster/status", Handler: "apiClusterStatus", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/cluster/mode", Handler: "apiClusterMode", Domain: "cluster",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/cluster/tokens", Handler: "apiClusterTokens", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/cluster/nodes", Handler: "apiClusterNodes", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/cluster/revoke", Handler: "apiClusterRevoke", Domain: "cluster",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/cluster/labels", Handler: "apiClusterLabels", Domain: "cluster",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: true},
	{Path: "/api/cluster/node-groups", Handler: "apiNodeGroups", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/cluster/node-groups/membership", Handler: "apiNodeGroupMembership", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/cluster/drain", Handler: "apiClusterDrain", Domain: "cluster",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: true},
	{Path: "/api/cluster/metrics", Handler: "apiClusterMetrics", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/cluster/ca", Handler: "apiClusterCA", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/cluster/rate-limits", Handler: "apiClusterRateLimits", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/cluster/audit", Handler: "apiClusterAudit", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/cluster/revocations", Handler: "apiClusterRevocations", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/cluster/rotation", Handler: "apiClusterRotation", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/cluster/ha", Handler: "apiClusterHA", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/cluster/bandwidth", Handler: "apiBandwidthPolicies", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/cluster/bootstrap/", Handler: "apiBootstrapRouter", Domain: "cluster",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},

	// ── Updates: self-update + rolling cluster update ─────────────────────
	{Path: "/api/update/status", Handler: "apiUpdateStatus", Domain: "update",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/update/check", Handler: "apiUpdateCheck", Domain: "update",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: false},
	{Path: "/api/update/apply", Handler: "apiUpdateApply", Domain: "update",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/update/preview", Handler: "apiUpdatePreview", Domain: "update",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: false},
	{Path: "/api/update/reports", Handler: "apiUpdateReports", Domain: "update",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/update/rollback", Handler: "apiUpdateRollback", Domain: "update",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/update/rollback/status", Handler: "apiUpdateRollbackStatus", Domain: "update",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/update/session", Handler: "apiUpdateSession", Domain: "update",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/update/cluster", Handler: "apiClusterUpdate", Domain: "update",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/update/cluster/status", Handler: "apiClusterUpdateStatus", Domain: "update",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/update/registry", Handler: "apiRegistrySettings", Domain: "update",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},

	// ── CDR (Sluice) integration ──────────────────────────────────────────
	{Path: "/api/cdr/config", Handler: "apiCDRConfig", Domain: "cdr",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/cdr/instances", Handler: "apiCDRInstances", Domain: "cdr",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/cdr/instances/enroll", Handler: "apiCDREnroll", Domain: "cdr",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/cdr/instances/revoke", Handler: "apiCDRRevokeRPC", Domain: "cdr",
		Public: false, MinRole: RoleAdmin, Mutating: true, AuditExpected: true},
	{Path: "/api/cdr/policies", Handler: "apiCDRPolicies", Domain: "cdr",
		Public: false, MinRole: RoleViewer, Mutating: true, AuditExpected: true},
	{Path: "/api/cdr/health", Handler: "apiCDRHealth", Domain: "cdr",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/api/cdr/test", Handler: "apiCDRTest", Domain: "cdr",
		Public: false, MinRole: RoleOperator, Mutating: true, AuditExpected: false},

	// ── Observability ─────────────────────────────────────────────────────
	{Path: "/api/diagnostics", Handler: "apiDiagnostics", Domain: "observability",
		Public: false, MinRole: RoleViewer, Mutating: false, AuditExpected: false},
	{Path: "/healthz", Handler: "apiHealthz", Domain: "observability",
		Public: true, MinRole: RolePublic, Mutating: false, AuditExpected: false},
}
