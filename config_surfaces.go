package main

// config_surfaces.go — the declarative config-surface registry (DEBT-004/006/009).
//
// Culvert's configuration crosses FIVE hand-maintained lists that historically
// drifted only prose could prevent:
//
//  1. configBackup (ui_policy.go)      — export/import AND version-rollback DTO
//  2. captureConfigBackup / applyConfigBackup / diffConfigs (configversion.go)
//     — the rollback trio, per-field lockstep + nil-vs-[] semantics
//  3. AdminSettings (admin_settings.go) — restart durability (+ sentinel booleans)
//  4. ConfigSnapshot (controlplane.go)  — CP→DP sync DTO
//  5. validateConfigSnapshot caps       — per-slice DoS bounds (H5)
//
// This file is the single source of truth for WHICH logical setting lives on
// WHICH surface with WHAT semantics. It is data only — no behavior. The parity
// tests in config_surfaces_test.go enforce it both ways (every struct field is
// claimed by exactly one row; every binding resolves to a real field), so the
// table cannot go stale the same way the uiRoutes/C1 layer keeps route
// metadata honest.
//
// Adding a config field now means: add the struct field, add (or extend) a
// registry row, and the tests tell you every place you still need to wire.
// Forgetting the registry is a compile-adjacent test failure, not a code
// review hope.

// fieldKind classifies what a bound struct field IS, so meta/sentinel fields
// are registered (parity must see every field) without pretending they are
// operator-facing configuration.
type fieldKind int

const (
	kindConfig          fieldKind = iota // an operator-facing setting
	kindMeta                             // format versions, timestamps, epochs, informational mirrors
	kindSentinel                         // AdminSettings *Saved booleans gating their value fields
	kindLegacyMigration                  // read-only migration inputs; never written back
)

// emptySemantics records what the APPLY path on a given surface does with an
// empty/zero value for the field. This is the axis that actually drifts —
// diffConfigs must mirror applyConfigBackup's nil-guards or dry-run rollback
// lies to the operator (the ContentScanBypassHosts bug fixed alongside this
// registry).
type emptySemantics int

const (
	semNA               emptySemantics = iota // not applied on this surface (export-only, meta, informational)
	semAlwaysReplace                          // zero/empty value is applied and wipes/overwrites live state
	semNilSkipEmptyWipe                       // nil → leave live state untouched; non-nil [] → explicit wipe
	semSkipIfZero                             // zero value keeps live state (cannot roll back TO zero)
	semValidatedSkip                          // applied only if it passes validation; invalid input skipped
)

// surfaceBinding ties a logical setting to one concrete struct field.
// Apply records the empty-value semantics of THAT struct's apply path:
// configBackup → applyConfigBackup (rollback), ConfigSnapshot → the
// applySnapshot* family (DP), AdminSettings → semNA (its load path is
// sentinel-structured, recorded via kindSentinel rows).
type surfaceBinding struct {
	Struct   string // "configBackup" | "AdminSettings" | "ConfigSnapshot"
	Field    string // exact Go field name; reflection-verified by the parity test
	Apply    emptySemantics
	Redacted bool // true when the capture/export accessor strips secret material
	// AppliesOnDP marks a ConfigSnapshot binding that the Data Plane consumes
	// but whose consumption is NOT an empty-value config apply (so Apply stays
	// semNA). Today the sole case is Epoch — read by dpObserveEpoch as the
	// ADR-0005 fence ratchet, not applied as configuration. SnapshotApplyParity
	// keys "must be consumed on the DP" on (Apply != semNA || AppliesOnDP), so a
	// fence/rotation field mislabeled kindMeta is still apply-verified.
	AppliesOnDP bool
}

// configSurfaceRow is one logical setting spanning up to three structs.
type configSurfaceRow struct {
	ID             string    // stable snake_case identifier
	Kind           fieldKind // config / meta / sentinel / legacy-migration
	Owner          string    // owning store/global ("bl", "policyStore", "rl", …)
	Export         bool      // serialized by apiConfigExport (all-branch)
	Import         bool      // applied by apiConfigImport (note: import skips empty lists, unlike rollback)
	Rollback       bool      // captured + applied + diffed by the configversion.go trio
	Diffed         bool      // reported by diffConfigs
	DiffKey        string    // Field name diffConfigs emits (when Diffed)
	DiffNilGuarded bool      // diffConfigs nil-skips, mirroring apply's semNilSkipEmptyWipe
	AdminDurable   bool      // restart-durable via /data/admin_settings.json
	ClusterSynced  bool      // pushed CP→DP in ConfigSnapshot
	Sensitive      bool      // may carry secret material (never Rollback; Export only via Redacted accessor)
	SnapshotCap    int       // validateConfigSnapshot cap for the ConfigSnapshot slice/map binding (0 = scalar / not synced)
	// WireWipeCapable marks a semNilSkipEmptyWipe ConfigSnapshot slice whose
	// EMPTY state must actually propagate CP→DP (clearing the last entry wipes
	// the DP's copy). That requires the JSON tag to OMIT `omitempty` — else Go
	// drops a non-nil empty slice on the wire and the DP reads it as nil→skip,
	// keeping stale state. Today only rate_limit_exempt. Every OTHER
	// semNilSkipEmptyWipe field keeps `omitempty`, so its []-wipe is
	// intentionally wire-dead (an operator clearing the list must push a
	// non-empty replacement); SnapshotWireWipe pins both postures.
	WireWipeCapable bool
	Note            string // constraint the flags can't express (ordering, validation, known gaps)
	Bindings        []surfaceBinding
}

// configSurfaces is the registry. Ordering: meta rows, then the
// configBackup-anchored rows in struct order, then AdminSettings-only rows in
// struct order, then ConfigSnapshot-only rows in struct order.
var configSurfaces = []configSurfaceRow{
	// ── Meta fields ──────────────────────────────────────────────────────
	{ID: "backup_format_version", Kind: kindMeta,
		Note:     "always 1; apiConfigImport rejects other values",
		Bindings: []surfaceBinding{{Struct: "configBackup", Field: "Version"}}},
	{ID: "exported_at", Kind: kindMeta,
		Bindings: []surfaceBinding{{Struct: "configBackup", Field: "ExportedAt"}}},
	{ID: "snapshot_version", Kind: kindMeta,
		Note:     "monotonic publish counter stamped by ConfigStore.Update — unrelated to backup_format_version",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "Version"}}},
	{ID: "snapshot_epoch", Kind: kindMeta,
		Note:     "ADR-0005 fencing epoch; DPs CAS-ratchet and reject stale-epoch snapshots",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "Epoch", AppliesOnDP: true}}},
	// PR-10 signed MCP CP→DP snapshots — derived, independently-signed integrity
	// artifacts (RC-5 snapshot-meta): consumed on the DP (applySnapshotMCP) but not
	// applied as an operator config value, so kindMeta + AppliesOnDP like Epoch. NOT
	// sensitive: the envelope carries only a public content hash + ed25519 signature
	// and a secret-free reviewed payload — the signing private key and any credential
	// value NEVER enter it (guaranteed by construction in internal/mcp/cpdp). Absent
	// (nil) on a disabled node ⇒ omitempty ⇒ byte-compatible SWG snapshot.
	{ID: "mcp_gateway_snapshot", Kind: kindMeta, ClusterSynced: true,
		Note:     "PR-10 signed MCP Gateway snapshot; DP verifies signature/epoch/version and applies whole or rejects whole (SWG unaffected)",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "MCPGatewaySnapshot", AppliesOnDP: true}}},
	{ID: "mcp_management_snapshot", Kind: kindMeta, ClusterSynced: true,
		Note:     "PR-10 signed MCP Management snapshot; capability-isolated from Gateway; DP applies whole or rejects whole",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "MCPManagementSnapshot", AppliesOnDP: true}}},
	{ID: "snapshot_updated_at", Kind: kindMeta,
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "UpdatedAt"}}},
	{ID: "policy_version", Kind: kindMeta,
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "PolicyVersion"}}},
	{ID: "cp_addresses", Kind: kindMeta, ClusterSynced: true, SnapshotCap: maxSnapCPAddresses,
		Note:     "HA failover discovery, populated by the leader; len>0-guarded apply",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "CPAddresses", Apply: semSkipIfZero}}},
	{ID: "ca_fingerprint", Kind: kindMeta,
		Note:     "cluster-CA rotation detection trigger; \"\"-skip",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "CAFingerprint", Apply: semSkipIfZero}}},
	{ID: "auth_enabled", Kind: kindMeta,
		Note:     "informational mirror — no DP apply function consumes it",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "AuthEnabled"}}},
	{ID: "default_auth_outcome", Kind: kindMeta,
		Note:     "informational mirror (defaultAuthOutcome spec) — DP does not apply it",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "DefaultAuthOutcome"}}},

	// ── configBackup-anchored settings (export/import/rollback core) ─────
	{ID: "blocklist_mode", Kind: kindConfig, Owner: "bl",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "blocklist_mode",
		Bindings: []surfaceBinding{{Struct: "configBackup", Field: "BlocklistMode", Apply: semValidatedSkip}}},
	{ID: "blocklist", Kind: kindConfig, Owner: "bl",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "blocklist",
		ClusterSynced: true, SnapshotCap: maxSnapBlockedHosts,
		Note: "DP apply replaces feed entries only, preserving DP-local mode/manual/exceptions",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "Blocklist", Apply: semAlwaysReplace},
			{Struct: "ConfigSnapshot", Field: "BlockedHosts", Apply: semAlwaysReplace}}},
	{ID: "policy_rules", Kind: kindConfig, Owner: "policyStore",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "policy_rules",
		ClusterSynced: true, SnapshotCap: maxSnapPolicyRules,
		Note: "rollback validates per-rule (invalid rules silently dropped); apply ordered AFTER url_categories → category_groups; diff keys on Priority and compares Name only",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "PolicyRules", Apply: semAlwaysReplace},
			{Struct: "ConfigSnapshot", Field: "PolicyRules", Apply: semNilSkipEmptyWipe}}},
	{ID: "default_action", Kind: kindConfig, Owner: "policyStore",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "default_action",
		AdminDurable: true, ClusterSynced: true,
		Note: "rollback applies unconditionally; import validates; DP \"\"-skips",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "DefaultAction", Apply: semAlwaysReplace},
			{Struct: "AdminSettings", Field: "DefaultAction"},
			{Struct: "ConfigSnapshot", Field: "DefaultAction", Apply: semSkipIfZero}}},
	{ID: "rewrite_rules", Kind: kindConfig, Owner: "rewriter",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "rewrite_rules",
		AdminDurable: true, ClusterSynced: true, SnapshotCap: maxSnapRewriteRules,
		Note: "diff keys on Host only (in-place op edits on the same host are invisible); Rule.ID is a runtime handle reassigned by SetRules — not config identity",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "RewriteRules", Apply: semAlwaysReplace},
			{Struct: "AdminSettings", Field: "RewriteRules"},
			{Struct: "ConfigSnapshot", Field: "RewriteRules", Apply: semNilSkipEmptyWipe}}},
	{ID: "ssl_bypass", Kind: kindConfig, Owner: "sslBypass",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "ssl_bypass",
		ClusterSynced: true, SnapshotCap: maxSnapSSLBypassPatterns,
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "SSLBypass", Apply: semAlwaysReplace},
			{Struct: "ConfigSnapshot", Field: "SSLBypassPatterns", Apply: semNilSkipEmptyWipe}}},
	{ID: "content_scan_patterns", Kind: kindConfig, Owner: "dpiScanner",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "content_scan_patterns",
		ClusterSynced: true, SnapshotCap: maxSnapDPIPatterns,
		Note: "invalid regex aborts patterns AND bypass hosts AND the shared envelope Save",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "ContentScanPatterns", Apply: semValidatedSkip},
			{Struct: "ConfigSnapshot", Field: "DPIPatterns", Apply: semNilSkipEmptyWipe}}},
	{ID: "file_block_extensions", Kind: kindConfig, Owner: "fileBlocker",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "file_block_extensions",
		ClusterSynced: true, SnapshotCap: maxSnapFileBlockExtensions,
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "FileBlockExtensions", Apply: semAlwaysReplace},
			{Struct: "ConfigSnapshot", Field: "FileBlockExtensions", Apply: semNilSkipEmptyWipe}}},
	{ID: "ip_filter_mode", Kind: kindConfig, Owner: "ipf",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "ip_filter_mode",
		AdminDurable: true, ClusterSynced: true,
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "IPFilterMode", Apply: semAlwaysReplace},
			{Struct: "AdminSettings", Field: "IPFilterMode"},
			{Struct: "ConfigSnapshot", Field: "IPFilterMode", Apply: semAlwaysReplace}}},
	{ID: "ip_list", Kind: kindConfig, Owner: "ipf",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "ip_list",
		AdminDurable: true, ClusterSynced: true, SnapshotCap: maxSnapIPList,
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "IPList", Apply: semAlwaysReplace},
			{Struct: "AdminSettings", Field: "IPFilterList"},
			{Struct: "ConfigSnapshot", Field: "IPList", Apply: semAlwaysReplace}}},
	{ID: "rate_limit_rpm", Kind: kindConfig, Owner: "rl",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "rate_limit_rpm",
		AdminDurable: true, ClusterSynced: true,
		Note: "rollback skips ≤0 (cannot roll back to unlimited)",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "RateLimitRPM", Apply: semSkipIfZero},
			{Struct: "AdminSettings", Field: "RateLimitRPM"},
			{Struct: "ConfigSnapshot", Field: "RateLimitRPM", Apply: semAlwaysReplace}}},
	{ID: "rate_limit_exempt", Kind: kindConfig, Owner: "rl",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "rate_limit_exempt", DiffNilGuarded: true,
		AdminDurable: true, ClusterSynced: true, SnapshotCap: maxSnapRateLimitExempt, WireWipeCapable: true,
		Note: "wire-wipe-capable synced slice (joined by pac_exclusions/pac_profiles/pac_pools in the PAC initiative): NO omitempty so an empty list clears DP exemptions; CurrentConfigSnapshot sends non-nil",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "RateLimitExempt", Apply: semNilSkipEmptyWipe},
			{Struct: "AdminSettings", Field: "RateLimitExemptions"},
			{Struct: "ConfigSnapshot", Field: "RateLimitExempt", Apply: semNilSkipEmptyWipe}}},
	{ID: "pac_proxy_host", Kind: kindConfig, Owner: "pacStore",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "pac_proxy_host",
		Note:     "rollback replaces the whole PACConfig unconditionally (snapshot with no PAC opinion wipes live PAC)",
		Bindings: []surfaceBinding{{Struct: "configBackup", Field: "PACProxyHost", Apply: semAlwaysReplace}}},
	{ID: "pac_proxy_port", Kind: kindConfig, Owner: "pacStore",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "pac_proxy_port",
		Bindings: []surfaceBinding{{Struct: "configBackup", Field: "PACProxyPort", Apply: semAlwaysReplace}}},
	{ID: "pac_exclusions", Kind: kindConfig, Owner: "pacStore",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "pac_exclusions",
		ClusterSynced: true, SnapshotCap: maxSnapPACExclusions, WireWipeCapable: true,
		Note: "wire-wipe fix (PAC initiative PR 2): NO omitempty + non-nil capture so clearing all exclusions on the CP propagates to DPs instead of leaving stale entries",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "PACExclusions", Apply: semAlwaysReplace},
			{Struct: "ConfigSnapshot", Field: "PACExclusions", Apply: semNilSkipEmptyWipe}}},
	{ID: "pac_profiles", Kind: kindConfig, Owner: "pacProfiles",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "pac_profiles", DiffNilGuarded: true,
		ClusterSynced: true, SnapshotCap: maxSnapPACProfiles, WireWipeCapable: true,
		Note: "PAC steering profiles (initiative PR 2): import never wipes (merge = upsert-by-ID); rollback/wire nil-skip + []-wipe; NO omitempty on either surface; the virtual 'default' profile is legacy-backed and never stored here",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "PACProfiles", Apply: semNilSkipEmptyWipe},
			{Struct: "ConfigSnapshot", Field: "PACProfiles", Apply: semNilSkipEmptyWipe}}},
	{ID: "pac_pools", Kind: kindConfig, Owner: "pacProfiles",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "pac_pools", DiffNilGuarded: true,
		ClusterSynced: true, SnapshotCap: maxSnapPACPools, WireWipeCapable: true,
		Note: "PAC proxy pools (initiative PR 2): same semantics as pac_profiles",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "PACPools", Apply: semNilSkipEmptyWipe},
			{Struct: "ConfigSnapshot", Field: "PACPools", Apply: semNilSkipEmptyWipe}}},
	{ID: "alert_webhooks", Kind: kindConfig, Owner: "globalAlertStore",
		Export: true, Import: true, Sensitive: true,
		Note:     "export via List() which strips HMAC secrets; off the rollback surface by design (Finding 10.3)",
		Bindings: []surfaceBinding{{Struct: "configBackup", Field: "AlertWebhooks", Redacted: true}}},
	{ID: "block_page_html", Kind: kindConfig, Owner: "blockPage",
		Export: true, Import: true, AdminDurable: true,
		Note: "operational setting, not versioned policy — off the rollback surface by design",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "BlockPageHTML"},
			{Struct: "AdminSettings", Field: "BlockPageHTML"}}},
	{ID: "upstream_proxies", Kind: kindConfig, Owner: "upstreamPool",
		Export: true, Import: true, Sensitive: true, AdminDurable: true,
		Note: "2F-C: export via List() (credential-free authorities); admin_settings persists the CREDENTIAL-FREE legacy list beside upstream_proxies_v2 (UpstreamProxiesSaved sentinel; a sentinel-less legacy file with userinfo URLs is migrated once at boot); import merges by authority and never carries a password — off the rollback surface by design",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "UpstreamProxies", Redacted: true},
			{Struct: "AdminSettings", Field: "UpstreamProxies"}}},
	{ID: "upstream_proxies_v2", Kind: kindConfig, Owner: "upstreamPool",
		Sensitive: true, AdminDurable: true,
		Note:     "2F-C: the managed Upstream v2 document (ULID identities, canonical authorities, SEALED credentials under the node-local .upstream_cred_key); node-local only — never exported, imported, rolled back or CP→DP synced; credentials are write-only and sealed at rest",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "UpstreamProxiesV2"}}},
	{ID: "conn_limit_enabled", Kind: kindConfig, Owner: "connLimiter",
		Export: true, Import: true, AdminDurable: true,
		Note: "operational setting — off the rollback surface by design",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "ConnLimitEnabled"},
			{Struct: "AdminSettings", Field: "ConnLimitEnabled"}}},
	{ID: "conn_limit_max_per_ip", Kind: kindConfig, Owner: "connLimiter",
		Export: true, Import: true, AdminDurable: true, ClusterSynced: true,
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "ConnLimitMaxPerIP"},
			{Struct: "AdminSettings", Field: "ConnLimitMaxPerIP"},
			{Struct: "ConfigSnapshot", Field: "MaxConnsPerIP", Apply: semSkipIfZero}}},
	{ID: "category_groups", Kind: kindConfig, Owner: "globalCategoryGroups",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "category_groups", DiffNilGuarded: true,
		ClusterSynced: true, SnapshotCap: maxSnapCategoryGroups,
		Note: "apply ordered after url_categories, before policy_rules (import and rollback both); import never wipes (merge = upsert-by-name)",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "CategoryGroups", Apply: semNilSkipEmptyWipe},
			{Struct: "ConfigSnapshot", Field: "CategoryGroups", Apply: semNilSkipEmptyWipe}}},
	{ID: "decryption_profiles", Kind: kindConfig, Owner: "globalDecryptionProfiles",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "decryption_profiles", DiffNilGuarded: true,
		ClusterSynced: true, SnapshotCap: maxSnapDecryptionProfiles, WireWipeCapable: true,
		Note: "named 'how to decrypt' object referenced per rule; apply ordered before policy_rules (import and rollback); import never wipes (merge = upsert-by-name); configBackup field has NO omitempty; ConfigSnapshot field ALSO has NO omitempty (WireWipeCapable) — unlike category_groups, an empty set propagates CP→DP so a last-profile delete clears stale profiles on DP nodes (these govern security-relevant cert/H2/TLS settings)",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "DecryptionProfiles", Apply: semNilSkipEmptyWipe},
			{Struct: "ConfigSnapshot", Field: "DecryptionProfiles", Apply: semNilSkipEmptyWipe}}},
	{ID: "url_categories", Kind: kindConfig, Owner: "catStore",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "url_categories", DiffNilGuarded: true,
		ClusterSynced: true, SnapshotCap: maxSnapURLCategories,
		Note: "admin-managed Layer 1 only (communityDB untouched); import never wipes",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "URLCategories", Apply: semNilSkipEmptyWipe},
			{Struct: "ConfigSnapshot", Field: "URLCategories", Apply: semNilSkipEmptyWipe}}},
	{ID: "content_scan_bypass_hosts", Kind: kindConfig, Owner: "dpiScanner",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "content_scan_bypass_hosts", DiffNilGuarded: true,
		Note:     "shares the content_scan.json envelope with content_scan_patterns (single Save on import and rollback); import never wipes",
		Bindings: []surfaceBinding{{Struct: "configBackup", Field: "ContentScanBypassHosts", Apply: semNilSkipEmptyWipe}}},

	// ── AdminSettings-only settings ──────────────────────────────────────
	{ID: "require_commit", Kind: kindConfig, Owner: "policyDraft", AdminDurable: true,
		Note:     "policy-draft opt-in governance mode; admin-durable only (governance posture, NOT rulebase content), NOT cluster-synced, NOT on the rollback surface — a rules rollback must not silently flip the commit mode",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "RequireCommit"}}},
	{ID: "syslog_addr", Kind: kindConfig, Owner: "syslog", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "SyslogAddr"}}},
	{ID: "syslog_format", Kind: kindConfig, Owner: "syslog", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "SyslogFormat"}}},
	{ID: "otlp_endpoint", Kind: kindConfig, Owner: "globalOTLP", AdminDurable: true, ClusterSynced: true,
		Note: "DP apply: \"\" is an ACTIVE clear (stops the exporter) — the one snapshot field where empty is a command",
		Bindings: []surfaceBinding{
			{Struct: "AdminSettings", Field: "OTLPEndpoint"},
			{Struct: "ConfigSnapshot", Field: "OTLPEndpoint", Apply: semAlwaysReplace}}},
	{ID: "otlp_headers", Kind: kindConfig, Owner: "globalOTLP", AdminDurable: true, Sensitive: true,
		Note:     "headers commonly carry API keys; persisted raw in the 0600 admin_settings file",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "OTLPHeaders"}}},
	{ID: "metrics_token", Kind: kindConfig, Owner: "metricsAuth", AdminDurable: true, Sensitive: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "MetricsToken"}}},
	{ID: "log_level", Kind: kindConfig, Owner: "logger", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "LogLevel"}}},
	{ID: "log_retention_days", Kind: kindConfig, Owner: "logStore", AdminDurable: true,
		Note:     "gated by log_retention_saved sentinel",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "LogRetentionDays"}}},
	{ID: "log_retention_max_gb", Kind: kindConfig, Owner: "logStore", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "LogRetentionMaxGB"}}},
	{ID: "log_store_enabled", Kind: kindConfig, Owner: "logStore", AdminDurable: true,
		Note:     "gated by log_store_enabled_saved sentinel",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "LogStoreEnabled"}}},
	{ID: "log_critical_disk_pct", Kind: kindConfig, Owner: "logStore", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "LogCriticalDiskPct"}}},
	{ID: "session_timeout_hours", Kind: kindConfig, Owner: "session", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "SessionTimeoutHours"}}},
	{ID: "ui_allow_ips", Kind: kindConfig, Owner: "uiIPGuard", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "UIAllowIPs"}}},
	{ID: "trusted_proxy_cidrs", Kind: kindConfig, Owner: "trustedProxyNets", AdminDurable: true,
		Note:     "RISK-019 reverse-proxy trust set for admin-UI client-IP; admin-durable only (per-node topology), NOT cluster-synced; empty len-guarded apply",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "TrustedProxyCIDRs"}}},
	{ID: "base_url", Kind: kindConfig, Owner: "proxyBaseURL", AdminDurable: true, ClusterSynced: true,
		Bindings: []surfaceBinding{
			{Struct: "AdminSettings", Field: "BaseURL"},
			{Struct: "ConfigSnapshot", Field: "ProxyBaseURL", Apply: semAlwaysReplace}}},
	{ID: "ui_sans", Kind: kindConfig, Owner: "uitls", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "UISANs"}}},
	{ID: "trust_forwarded_headers", Kind: kindConfig, Owner: "identity", AdminDurable: true, ClusterSynced: true,
		Bindings: []surfaceBinding{
			{Struct: "AdminSettings", Field: "TrustForwardedHeaders"},
			{Struct: "ConfigSnapshot", Field: "TrustForwardedHeaders", Apply: semAlwaysReplace}}},
	{ID: "blocklist_feeds", Kind: kindConfig, Owner: "blocklistfeed", AdminDurable: true,
		Note:     "gated by blocklist_feeds_saved sentinel (authoritative incl. empty list)",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "BlocklistFeeds"}}},
	// SaaS signed category feed (F3a-2). Dual AdminDurable + ClusterSynced (the
	// default_action shape): CP-authoritative fleet policy, exported/imported,
	// rollback-able, and pushed CP→DP. Each scalar row carries an AdminSettings
	// binding (restart durability), a configBackup binding (export/import/rollback),
	// and a ConfigSnapshot binding (CP→DP). managed/enabled are *bool PRESENCE
	// fields with a NIL-SKIP snapshot apply — nil ⇒ DP keeps local, non-nil ⇒
	// authoritative even when false — so a rolled-back CP that omits them can never
	// re-enable a durably-disabled DP (§A.2.2, Codex P1). configBackup rollback
	// applies unconditionally (like default_action); import gates on protocol
	// presence (never-wipe). Not secrets ⇒ not redacted; scalars ⇒ no SnapshotCap.
	{ID: "saas_feed_url", Kind: kindConfig, Owner: "saasFeed",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "saas_feed_url",
		AdminDurable: true, ClusterSynced: true,
		Note: "official-origin URL contract (resolveFeedURL/validateOfficialManifestURL); decoupled from the legacy syncer (F3a-2); DP \"\"-skips",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "SaaSFeedURL", Apply: semAlwaysReplace},
			{Struct: "AdminSettings", Field: "SaaSFeedURL"},
			{Struct: "ConfigSnapshot", Field: "SaaSFeedURL", Apply: semSkipIfZero}}},
	{ID: "saas_feed_managed", Kind: kindConfig, Owner: "saasFeed",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "saas_feed_managed",
		AdminDurable: true, ClusterSynced: true,
		Note: "on-by-default sentinel: false ⇒ never-touched ⇒ enabled; true ⇒ SaaSFeedEnabled authoritative. ConfigSnapshot binding is a *bool presence field: nil ⇒ keep DP-local (never re-enable a durable disable), non-nil ⇒ apply even false",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "SaaSFeedManaged", Apply: semAlwaysReplace},
			{Struct: "AdminSettings", Field: "SaaSFeedManaged"},
			{Struct: "ConfigSnapshot", Field: "SaaSFeedManaged", Apply: semNilSkipEmptyWipe}}},
	{ID: "saas_feed_enabled", Kind: kindConfig, Owner: "saasFeed",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "saas_feed_enabled",
		AdminDurable: true, ClusterSynced: true,
		Note: "authoritative only when managed=true. ConfigSnapshot binding is a *bool presence field (nil-skip apply)",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "SaaSFeedEnabled", Apply: semAlwaysReplace},
			{Struct: "AdminSettings", Field: "SaaSFeedEnabled"},
			{Struct: "ConfigSnapshot", Field: "SaaSFeedEnabled", Apply: semNilSkipEmptyWipe}}},
	{ID: "saas_feed_protocol", Kind: kindConfig, Owner: "saasFeed",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "saas_feed_protocol",
		AdminDurable: true, ClusterSynced: true,
		Note: "signed_manifest_v1 only (no unsigned/raw fallback); DP \"\"-skips",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "SaaSFeedProtocol", Apply: semAlwaysReplace},
			{Struct: "AdminSettings", Field: "SaaSFeedProtocol"},
			{Struct: "ConfigSnapshot", Field: "SaaSFeedProtocol", Apply: semSkipIfZero}}},
	{ID: "saas_feed_refresh_seconds", Kind: kindConfig, Owner: "saasFeed",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "saas_feed_refresh_seconds",
		AdminDurable: true, ClusterSynced: true,
		Note: "poll cadence (≥1h); DP 0-skips",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "SaaSFeedRefreshSeconds", Apply: semAlwaysReplace},
			{Struct: "AdminSettings", Field: "SaaSFeedRefreshSeconds"},
			{Struct: "ConfigSnapshot", Field: "SaaSFeedRefreshSeconds", Apply: semSkipIfZero}}},
	{ID: "category_overrides", Kind: kindConfig, Owner: "globalCategoryOverrides",
		Export: true, Import: true, Rollback: true, Diffed: true, DiffKey: "category_overrides",
		DiffNilGuarded: true, ClusterSynced: true, WireWipeCapable: true,
		SnapshotCap: maxSnapCategoryOverrides,
		Note:        "admin overrides layered on the feed snapshot (added/recategorized/tombstones). Pointer-to-struct on BOTH configBackup and ConfigSnapshot for presence: nil ⇒ keep-local (never wipe), non-nil (even empty) ⇒ authoritative replacement. WireWipeCapable + NO omitempty on ConfigSnapshot: unlike category_groups, clearing the last override MUST reach every DP (a stale tombstone would keep a host suppressed — the DecryptionProfiles delete-propagation posture). Import never wipes (skips nil/empty); apply ordered before policy_rules. Host-aggregate cap enforced in validateConfigSnapshot (pointer-to-struct is not a configSnapshotSliceCaps row, so the capped-count literal is unchanged)",
		Bindings: []surfaceBinding{
			{Struct: "configBackup", Field: "CategoryOverrides", Apply: semNilSkipEmptyWipe},
			{Struct: "ConfigSnapshot", Field: "CategoryOverrides", Apply: semNilSkipEmptyWipe}}},
	{ID: "saas_store_schema_version", Kind: kindMeta, Owner: "saasFeed", AdminDurable: true,
		Note:     "F3a-1 durable migration marker; absence triggers one-time schema init, a newer value is refused (fail-closed downgrade guard)",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "SaaSStoreSchemaVersion"}}},
	{ID: "yara_enabled", Kind: kindConfig, Owner: "yara", AdminDurable: true,
		Note:     "gated by yara_settings_saved sentinel (as are all yara_* rows)",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "YARAEnabled"}}},
	{ID: "yara_timeout_secs", Kind: kindConfig, Owner: "yara", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "YARATimeoutSecs"}}},
	{ID: "yara_max_inflight", Kind: kindConfig, Owner: "yara", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "YARAMaxInflight"}}},
	{ID: "yara_on_timeout", Kind: kindConfig, Owner: "yara", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "YARAOnTimeout"}}},
	{ID: "yara_on_saturation", Kind: kindConfig, Owner: "yara", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "YARAOnSaturation"}}},
	{ID: "yara_alert_degraded", Kind: kindConfig, Owner: "yara", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "YARAAlertDegraded"}}},

	// Adaptive decryption-exclusion tunables (F10). AdminDurable-only — mirroring
	// metrics_token / syslog_addr / yara_*: OFF export/import, OFF version-rollback,
	// OFF CP→DP (ClusterSynced), not Sensitive. These are node-local OPERATIONAL
	// tuning, not policy; the learned cache they govern is itself volatile and off
	// every surface. Gated by the autoexclude_tunables_saved sentinel on load.
	{ID: "autoexclude_confirm_n", Kind: kindConfig, Owner: "autoExclude", AdminDurable: true,
		Note:     "gated by autoexclude_tunables_saved sentinel (as are all autoexclude_* tunable rows)",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "AutoExcludeConfirmN"}}},
	{ID: "autoexclude_ttl_secs", Kind: kindConfig, Owner: "autoExclude", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "AutoExcludeTTLSecs"}}},
	{ID: "autoexclude_pinned_ttl_secs", Kind: kindConfig, Owner: "autoExclude", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "AutoExcludePinnedTTLSecs"}}},
	{ID: "autoexclude_window_secs", Kind: kindConfig, Owner: "autoExclude", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "AutoExcludeWindowSecs"}}},
	{ID: "autoexclude_max_entries", Kind: kindConfig, Owner: "autoExclude", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "AutoExcludeMaxEntries"}}},

	// Policy Learning Mode governance (ADR-0025 M5A) — deliberately AdminDurable-ONLY:
	// OFF export/import, version-rollback, and CP→DP. Learning is node-local advisory
	// observation; a config rollback or cross-node import that silently re-enabled
	// observation or swapped the recommendable-category guardrail would be a governance
	// hazard (the learned/tunable-state-is-node-local precedent). The node-local
	// learning STATE (sessions/aggregates/recommendations + subject key) is off every
	// config surface entirely — it is engine-owned files, not configuration.
	{ID: "policy_learning_enabled", Kind: kindConfig, Owner: "policyLearn", AdminDurable: true,
		Note:     "gated by policy_learning_saved sentinel; enable ≠ start learning (observation arms only via an explicit session start)",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "PolicyLearningEnabled"}}},
	{ID: "policy_learning_recommendable_categories", Kind: kindConfig, Owner: "policyLearn", AdminDurable: true,
		Note:     "fail-closed allowlist (M4 guardrail); no omitempty — a governed EMPTY list must survive the round trip; identity = GuardrailsHash",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "PolicyLearningRecommendableCategories"}}},

	// ADR-0011 §4 host/SNI redaction posture — a node-local privacy choice, durable in
	// admin_settings.json but OFF export/import, version-rollback, and CP→DP (like the
	// autoexclude tunables). Plain bool: default false is both "off" and "unset", so no
	// sentinel row is needed.
	{ID: "decryption_redact_hosts", Kind: kindConfig, Owner: "decRedact", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "DecryptionRedactHosts"}}},
	// PR3 Option B node-local pseudonym key. Sensitive + AdminDurable-only (0600 file,
	// like metrics_token): OFF export/import, version-rollback, and CP→DP — a
	// per-appliance privacy secret; fleet-wide key sync is the deferred B3 follow-up.
	{ID: "traffic_pseudonym_key", Kind: kindConfig, Owner: "trafficRedact", AdminDurable: true, Sensitive: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "TrafficPseudonymKey"}}},
	// 2E-B §B: the NON-SECRET pseudonym-generation id persisted beside the key
	// (random, never derived from key material) — what the admin API exposes as
	// key_id so a lost rotation response is resolvable without a blind retry.
	// AdminDurable-only like the key itself; deliberately NOT Sensitive (it is
	// designed to be shown), but it travels nowhere the key doesn't.
	{ID: "traffic_pseudonym_key_id", Kind: kindConfig, Owner: "trafficRedact", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "TrafficPseudonymKeyID"}}},

	// Rotation operation-identity record (2E-B correction, Blocker A): the
	// durable monotonic key-generation sequence + the bounded NON-SECRET
	// rotation receipts ({op_id, key_id, seq, ts} — never key material, pinned
	// by TestDec2EB2_RotationSurfacesCarryNoKeyMaterial). AdminDurable-only,
	// node-local like the key they describe; deliberately NOT Sensitive.
	{ID: "traffic_key_rotation_seq", Kind: kindConfig, Owner: "trafficRedact", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "TrafficKeyRotationSeq"}}},
	{ID: "traffic_key_rotation_receipts", Kind: kindConfig, Owner: "trafficRedact", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "TrafficKeyRotationReceipts"}}},

	// Support-bundle retention caps (Slice B). AdminDurable-only — node-local
	// OPERATIONAL tuning over DURABLE forensic evidence: OFF export/import,
	// version-rollback (a rollback must never mass-evict bundles), and CP→DP.
	// Gated by the support_retention_saved sentinel on load.
	{ID: "support_retention_keep", Kind: kindConfig, Owner: "supportRetention", AdminDurable: true,
		Note:     "gated by support_retention_saved sentinel (as is support_retention_max_age_days)",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "SupportRetentionKeep"}}},
	{ID: "support_retention_max_age_days", Kind: kindConfig, Owner: "supportRetention", AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "SupportRetentionMaxAgeDays"}}},

	// ── AdminSettings sentinels + legacy migration inputs ────────────────
	{ID: "log_retention_saved", Kind: kindSentinel, AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "LogRetentionSaved"}}},
	{ID: "log_store_enabled_saved", Kind: kindSentinel, AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "LogStoreEnabledSaved"}}},
	{ID: "blocklist_feeds_saved", Kind: kindSentinel, AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "BlocklistFeedsSaved"}}},
	{ID: "upstream_proxies_saved", Kind: kindSentinel, AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "UpstreamProxiesSaved"}}},
	{ID: "trusted_proxy_cidrs_saved", Kind: kindSentinel, AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "TrustedProxyCIDRsSaved"}}},
	{ID: "rewrite_rules_saved", Kind: kindSentinel, AdminDurable: true,
		Note:     "2D-C: saved-authoritative rewrite list (incl. explicit empty — deleting the last rule survives restart); sentinel-less legacy files keep the len>0 YAML-seed gate",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "RewriteRulesSaved"}}},
	{ID: "rewrite_seed_identities", Kind: kindSentinel, AdminDurable: true,
		Note:     "2D-C final §7: durable identity LEDGER for YAML-seeded rewrite rules on nodes where AdminSettings does not own the rewrite surface — stable IDs re-attach per position+content each boot, written only by the targeted migration writer (never the omnibus snapshot, which drops it once the surface is admin-owned); node-local, OFF export/import/rollback/CP→DP",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "RewriteSeedIdentities"}}},
	{ID: "legacy_ldap_retired", Kind: kindSentinel, AdminDurable: true,
		Note:     "ADR-0027 P1-2 durable LDAP-authority cutover: node-local, OFF export/import/rollback/CP→DP — a restore must never resurrect the retired YAML authenticator",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "LegacyLDAPRetired"}}},
	{ID: "yara_settings_saved", Kind: kindSentinel, AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "YARASettingsSaved"}}},
	{ID: "autoexclude_tunables_saved", Kind: kindSentinel, AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "AutoExcludeTunablesSaved"}}},
	{ID: "policy_learning_saved", Kind: kindSentinel, AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "PolicyLearningSaved"}}},
	{ID: "support_retention_saved", Kind: kindSentinel, AdminDurable: true,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "SupportRetentionSaved"}}},
	{ID: "blocklist_feed_url_legacy", Kind: kindLegacyMigration,
		Note:     "read iff blocklist_feeds_saved is false; never written back",
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "BlocklistFeedURL"}}},
	{ID: "blocklist_feed_interval_legacy", Kind: kindLegacyMigration,
		Bindings: []surfaceBinding{{Struct: "AdminSettings", Field: "BlocklistFeedInterval"}}},

	// ── ConfigSnapshot-only settings (cluster sync) ──────────────────────
	{ID: "file_profiles", Kind: kindConfig, Owner: "globalProfileStore",
		ClusterSynced: true, SnapshotCap: maxSnapFileProfiles,
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "FileProfiles", Apply: semNilSkipEmptyWipe}}},
	{ID: "threat_feed_urls", Kind: kindConfig, Owner: "globalThreatFeed",
		ClusterSynced: true, SnapshotCap: maxSnapThreatFeedURLs,
		Note:     "len>0-guarded import (can be large); paired with threat_feed_domains",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "ThreatFeedURLs", Apply: semSkipIfZero}}},
	{ID: "threat_feed_domains", Kind: kindConfig, Owner: "globalThreatFeed",
		ClusterSynced: true, SnapshotCap: maxSnapThreatFeedDomains,
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "ThreatFeedDomains", Apply: semSkipIfZero}}},
	{ID: "threat_domain_allowlist", Kind: kindConfig, Owner: "globalThreatFeed",
		ClusterSynced: true, SnapshotCap: maxSnapDomainAllowlist, WireWipeCapable: true,
		Note:     "no omitempty: the allowlist gates lookup verdicts, so an admin's full clear must reach DPs (stale allowlist = fail-open mask)",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "ThreatDomainAllowlist", Apply: semNilSkipEmptyWipe}}},
	{ID: "session_hmac", Kind: kindConfig, Owner: "session", Sensitive: true, ClusterSynced: true,
		Note:     "deliberate secret sync (cross-node sessions); redacted for unenrolled GetConfig callers; hex ≥32B validated on apply",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "SessionHMAC", Apply: semValidatedSkip}}},
	{ID: "idp_profiles", Kind: kindConfig, Owner: "idpRegistry", Sensitive: true,
		ClusterSynced: true, SnapshotCap: maxSnapIdPProfiles,
		Note:     "carries OIDC client secrets and LDAP bind credentials by design (DP-local auth); redacted for unenrolled callers; compile-validated ReplaceAll, rejection aborts extended state",
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "IdPProfiles", Apply: semValidatedSkip}}},
	{ID: "bandwidth_policies", Kind: kindConfig, Owner: "globalBandwidth",
		ClusterSynced: true, SnapshotCap: maxSnapBandwidthPolicies,
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "BandwidthPolicies", Apply: semNilSkipEmptyWipe}}},
	{ID: "node_groups", Kind: kindConfig, Owner: "globalNodeGroups",
		ClusterSynced: true, SnapshotCap: maxSnapNodeGroups,
		Bindings: []surfaceBinding{{Struct: "ConfigSnapshot", Field: "NodeGroups", Apply: semNilSkipEmptyWipe}}},
}
