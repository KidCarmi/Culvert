package main

// admin_settings.go — Unified persistence for admin GUI settings.
//
// Problem: 14 admin-configurable components stored state in-memory only.
// Changes made via the GUI were silently lost on container restart/update.
//
// Solution: A single /data/admin_settings.json file that snapshots all
// runtime-configurable values. Loaded once at startup (after all components
// init), saved atomically after every API mutation.

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// AdminSettings holds every admin-configurable value that needs to survive
// a restart but isn't already persisted by its own dedicated file.
type AdminSettings struct {
	// Policy
	DefaultAction string `json:"default_action,omitempty"` // "allow" or "deny"
	RequireCommit bool   `json:"require_commit"`           // policy-draft opt-in: stage rulebase edits + require an explicit commit (default false ⇒ live-write)

	// Security
	IPFilterMode        string   `json:"ip_filter_mode,omitempty"`
	IPFilterList        []string `json:"ip_filter_list,omitempty"`
	RateLimitRPM        int      `json:"rate_limit_rpm"`
	RateLimitExemptions []string `json:"rate_limit_exemptions,omitempty"`
	ConnLimitMaxPerIP   int      `json:"conn_limit_max_per_ip"`
	ConnLimitEnabled    bool     `json:"conn_limit_enabled"`

	// Rewrite
	RewriteRules []RewriteRule `json:"rewrite_rules,omitempty"`

	// Block page
	BlockPageHTML string `json:"block_page_html,omitempty"`

	// Logging / monitoring
	SyslogAddr   string            `json:"syslog_addr,omitempty"`
	SyslogFormat string            `json:"syslog_format,omitempty"`
	OTLPEndpoint string            `json:"otlp_endpoint,omitempty"`
	OTLPHeaders  map[string]string `json:"otlp_headers,omitempty"`
	MetricsToken string            `json:"metrics_token,omitempty"`
	LogLevel     string            `json:"log_level,omitempty"`

	// TrafficPseudonymKey is the node-local 32-byte HMAC key for the PR3 Option B
	// destination-privacy posture (traffic_redaction.go). Sensitive + AdminDurable-only
	// (0600 file, like MetricsToken): OFF export/import, version-rollback, and CP→DP —
	// destination pseudonymization is a per-appliance privacy choice, and a synced key
	// (fleet correlation) is the deferred B3 follow-up. Generated on first enable.
	TrafficPseudonymKey []byte `json:"traffic_pseudonym_key,omitempty"`

	// History-store retention. LogRetentionSaved is a sentinel (like
	// YARASettingsSaved): when false the values below are not applied on load,
	// so a zero value can't override the YAML/CLI-seeded retention on settings
	// files that predate this feature.
	LogRetentionSaved bool    `json:"log_retention_saved"`
	LogRetentionDays  int     `json:"log_retention_days,omitempty"`
	LogRetentionMaxGB float64 `json:"log_retention_max_gb,omitempty"`

	// LogStoreEnabledSaved is a separate sentinel: when true the admin has set
	// the enable state from the GUI and it is authoritative (so a saved "off"
	// disables even a YAML-seeded store). When false (settings files predating
	// the GUI toggle) the YAML seed + retention path is honored unchanged.
	LogStoreEnabledSaved bool `json:"log_store_enabled_saved"`
	LogStoreEnabled      bool `json:"log_store_enabled"`

	// LogCriticalDiskPct is the disk-protection threshold (%). 0 = use default.
	LogCriticalDiskPct int `json:"log_critical_disk_pct,omitempty"`

	// LegacyLDAPRetired is the durable LDAP-authority cutover sentinel
	// (ADR-0025 / P1-2): once an enabled registry LDAP identity provider is
	// observed on a node that carries a legacy YAML ldap block, the block is
	// permanently retired as an operational authenticator — across registry
	// disable/delete and every restart. Node-local + AdminDurable-only (never
	// exported/imported, never rolled back, never CP→DP synced): authority
	// ownership is per-node state, and a config restore must not resurrect a
	// retired authenticator. Break-glass revert is an explicit offline edit
	// (documented in docs/operator/ldap-identity-provider.md).
	LegacyLDAPRetired bool `json:"legacy_ldap_retired"`

	// Session
	SessionTimeoutHours int `json:"session_timeout_hours,omitempty"`

	// Network
	UIAllowIPs            []string `json:"ui_allow_ips,omitempty"`
	BaseURL               string   `json:"base_url,omitempty"`
	UISANs                []string `json:"ui_sans,omitempty"`
	TrustForwardedHeaders bool     `json:"trust_forwarded_headers"`
	TrustedProxyCIDRs     []string `json:"trusted_proxy_cidrs,omitempty"` // RISK-019: reverse-proxy IPs/CIDRs whose XFF is trusted for admin-UI client-IP
	// TrustedProxyCIDRsSaved is a sentinel (mirroring UpstreamProxiesSaved):
	// once the admin has saved network settings the persisted list is
	// AUTHORITATIVE — including an empty list, which CLEARS any YAML seed.
	// Without it, clearing the trust set in the GUI would silently be undone by
	// the YAML seed on restart (a security control failing toward MORE trust).
	TrustedProxyCIDRsSaved bool `json:"trusted_proxy_cidrs_saved"`

	// Blocklist feeds (multi-feed). BlocklistFeedsSaved is a sentinel
	// (mirroring YARASettingsSaved): when true the persisted feed list is
	// authoritative and REPLACES the YAML/CLI-seeded feed — including the
	// empty list, so deleting every feed in the GUI survives a restart.
	// When false (pre-multi-feed settings files), the legacy single-feed
	// fields below are read for migration; they are no longer written.
	BlocklistFeedsSaved   bool                   `json:"blocklist_feeds_saved"`
	BlocklistFeeds        []BlocklistFeedSetting `json:"blocklist_feeds,omitempty"`
	BlocklistFeedURL      string                 `json:"blocklist_feed_url,omitempty"`
	BlocklistFeedInterval string                 `json:"blocklist_feed_interval,omitempty"` // e.g. "24h"

	// SaaS signed category feed (F3a-1). SaaSFeedManaged is the sentinel that
	// distinguishes "operator never touched it" (false ⇒ on-by-default) from
	// "explicitly configured"; SaaSFeedEnabled is authoritative only when managed.
	// Empty URL ⇒ the built-in official endpoint. Protocol has one legal value
	// today (signed_manifest_v1). SaaSStoreSchemaVersion is the durable migration
	// marker (§A.5) — its absence triggers the one-time schema init; a value newer
	// than this binary supports is refused. These fields are node-local and durable
	// in F3a-1 (the CP→DP wire + *bool presence lands in F3a-2).
	SaaSFeedURL            string `json:"saas_feed_url,omitempty"`
	SaaSFeedManaged        bool   `json:"saas_feed_managed"`
	SaaSFeedEnabled        bool   `json:"saas_feed_enabled"`
	SaaSFeedProtocol       string `json:"saas_feed_protocol,omitempty"`
	SaaSFeedRefreshSeconds int64  `json:"saas_feed_refresh_seconds,omitempty"`
	SaaSStoreSchemaVersion int    `json:"saas_store_schema_version,omitempty"`

	// Upstream proxy chaining. UpstreamProxiesSaved is a sentinel (mirroring
	// BlocklistFeedsSaved): when true the persisted list is authoritative and
	// REPLACES the YAML/CLI-seeded pool — including the empty list, so
	// deleting every parent proxy in the GUI survives a restart. When false
	// (settings files predating this feature) the YAML seed is kept.
	// Entries are stored raw because a proxy URL may embed inline
	// credentials; the file is mode 0600 and already carries secrets
	// (metrics_token). Circuit-breaker parameters are NOT persisted here —
	// they stay YAML-owned and are re-applied by the upstream-pool startup
	// slice before this file loads.
	UpstreamProxiesSaved bool            `json:"upstream_proxies_saved"`
	UpstreamProxies      []UpstreamEntry `json:"upstream_proxies,omitempty"`

	// YARA engine runtime configuration.
	// YARASettingsSaved is a sentinel: when false the YARA fields below are not
	// applied on load, preventing zero-value bools from overriding init() defaults
	// on installations that pre-date this feature.
	YARASettingsSaved bool   `json:"yara_settings_saved"`
	YARAEnabled       bool   `json:"yara_enabled"`
	YARATimeoutSecs   int64  `json:"yara_timeout_secs,omitempty"`
	YARAMaxInflight   int64  `json:"yara_max_inflight,omitempty"`
	YARAOnTimeout     string `json:"yara_on_timeout,omitempty"`
	YARAOnSaturation  string `json:"yara_on_saturation,omitempty"`
	YARAAlertDegraded bool   `json:"yara_alert_degraded"`

	// Adaptive decryption-exclusion tunables (F10). AutoExcludeTunablesSaved is a
	// sentinel (like YARASettingsSaved): when false the values below are not applied
	// on load, so a zero-value field can't override the engine defaults on settings
	// files predating this feature. Durations persist as integer SECONDS to match the
	// autoexclude.Stats() contract. The learned cache itself stays VOLATILE and
	// node-local — only these five PARAMETERS are durable, and they are deliberately
	// OFF export/import, version-rollback, and CP→DP propagation.
	AutoExcludeTunablesSaved bool `json:"autoexclude_tunables_saved"`
	AutoExcludeConfirmN      int  `json:"autoexclude_confirm_n,omitempty"`
	AutoExcludeTTLSecs       int  `json:"autoexclude_ttl_secs,omitempty"`
	AutoExcludePinnedTTLSecs int  `json:"autoexclude_pinned_ttl_secs,omitempty"`
	AutoExcludeWindowSecs    int  `json:"autoexclude_window_secs,omitempty"`
	AutoExcludeMaxEntries    int  `json:"autoexclude_max_entries,omitempty"`

	// ADR-0011 §4 host/SNI redaction posture. When true, the projected decryption
	// blocks hash host/SNI instead of recording plaintext. Default false (record
	// plaintext); a plain bool needs no sentinel (false is both "off" and "unset").
	// Node-local like the auto-exclusion tunables — OFF export/import, rollback, CP→DP.
	DecryptionRedactHosts bool `json:"decryption_redact_hosts,omitempty"`

	// Support-bundle retention caps (Slice B). SupportRetentionSaved is a sentinel
	// (like AutoExcludeTunablesSaved): when false the values below are not applied on
	// load, so a zero-value field can't override the compiled defaults on files
	// predating this feature. These caps govern DURABLE forensic evidence, so they
	// are node-local OPERATIONAL tuning — OFF export/import, version-rollback, and
	// CP→DP propagation (the learned/tunable-state-is-node-local precedent; a synced
	// surface would carry a config-rollback mass-eviction hazard).
	SupportRetentionSaved      bool `json:"support_retention_saved"`
	SupportRetentionKeep       int  `json:"support_retention_keep,omitempty"`
	SupportRetentionMaxAgeDays int  `json:"support_retention_max_age_days,omitempty"`
}

var (
	adminSettingsMu   sync.Mutex
	adminSettingsPath string
)

// adminSettingsOverriddenSurfaces holds the operator-facing names of the
// sentinel-gated surfaces that are CURRENTLY durably overridden by
// admin_settings.json — snapshotted whenever the file is loaded at startup or
// durably saved (SaveAdminSettings). Per-sentinel, not a single any-set flag:
// an admin_settings.json written by an OLDER build carries only the sentinels
// that existed then (e.g. no autoexclude_tunables_saved / support_retention_
// saved), and those un-sentineled surfaces still follow config.yaml/CLI — a
// blanket "everything is overridden" claim would be wrong for exactly the
// upgraded installs that most need this diagnostic. Diagnostics-only; never
// consulted by load/apply/save logic itself.
var adminSettingsOverriddenSurfaces atomic.Pointer[[]string]

// AdminSettingsOverriddenSurfaces returns the operator-facing names of the
// surfaces currently pinned by a saved sentinel (empty = everything still
// follows config.yaml/CLI). Race-free, no I/O; safe for the read-only
// diagnostics handler.
func AdminSettingsOverriddenSurfaces() []string {
	if p := adminSettingsOverriddenSurfaces.Load(); p != nil {
		return *p
	}
	return nil
}

// snapshotOverriddenSurfaces derives the per-sentinel surface list from s and
// publishes it. The field list lives in exactly one place — here — shared by
// the load and save paths.
func snapshotOverriddenSurfaces(s AdminSettings) {
	var out []string
	add := func(saved bool, name string) {
		if saved {
			out = append(out, name)
		}
	}
	add(s.LogRetentionSaved, "log retention")
	add(s.LogStoreEnabledSaved, "log-store enable")
	add(s.TrustedProxyCIDRsSaved, "trusted-proxy CIDRs")
	add(s.BlocklistFeedsSaved, "blocklist feeds")
	add(s.UpstreamProxiesSaved, "upstream proxy pool")
	add(s.YARASettingsSaved, "YARA engine settings")
	add(s.AutoExcludeTunablesSaved, "decryption auto-exclusion tunables")
	add(s.SupportRetentionSaved, "support-bundle retention")
	adminSettingsOverriddenSurfaces.Store(&out)
}

// LoadAdminSettings reads the settings file and applies each field to its
// respective component. Called once in main() after all components init.
// Missing file = first run; each component keeps its config/default value.
func LoadAdminSettings(path string) {
	adminSettingsMu.Lock()
	adminSettingsPath = path
	adminSettingsMu.Unlock()

	// Re-surface an unreconciled quarantine from a prior boot (CHAOS-05 pattern): after
	// a corrupt load we default and the next save writes a clean file, so the /readyz
	// row + alert would otherwise vanish while every GUI-saved admin setting stays lost.
	noteResidualQuarantine("admin_settings", path)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return // first run — no settings file yet; components keep their config defaults
	}
	if err != nil {
		// Read error on an EXISTING file (EACCES/EIO): the content may be intact, so do
		// NOT quarantine (a rename could move a healthy file aside on a transient
		// permission blip — the documented state-corruption posture). Surface it
		// loudly — every durable admin setting silently reverts to its default until
		// this is fixed — but keep booting.
		logger.Printf("AdminSettings: cannot read %q (%v) — every GUI-saved admin setting is using its default until the file is readable and the node is restarted", sanitizeLog(path), err)
		return
	}
	var s AdminSettings
	if err := json.Unmarshal(data, &s); err != nil {
		// Present-but-corrupt settings. Previously this logged and returned — and the
		// NEXT SaveAdminSettings (any admin mutation) then atomically OVERWROTE the
		// corrupt file with a defaults-only snapshot, destroying the only copy of the
		// operator's durable GUI config with one log line as the trace. Route it
		// through the CHAOS-05/07 quarantine-don't-overwrite mechanism (shared with
		// ui_users.json / cluster.json): rename the corrupt file aside so no save can
		// clobber it, fire the state_file_corrupt alert, and record a /readyz fail row.
		quarantineCorruptStateFile("admin_settings", path, err)
		return
	}

	// F3a-1: initialize the SaaS feed-config schema boundary before applying admin
	// services. Idempotent (marker-guarded), backed up before mutation, atomic, and
	// fail-safe — a failure logs and this boot proceeds with the pre-migration
	// (safe-default) resolution, retrying next boot. It does NOT change the persisted
	// URL the legacy syncer reads, so there is no live behavior change here.
	if rep, mErr := migrateSaaSFeedStore(&s, path, data, time.Now); mErr != nil {
		if errors.Is(mErr, ErrSaaSSchemaTooNew) {
			// A feed-store schema newer than this binary supports: fail CLOSED to the
			// compiled baseline. Clear the persisted feed URL in memory so the legacy
			// syncer below does NOT consume a field from a schema we just declared
			// unsafe (the file is left untouched — the migration refused to write).
			s.SaaSFeedURL = ""
			logger.Printf("AdminSettings: SaaS feed store schema newer than supported (%v) — failing closed to the baseline feed config", mErr)
		} else {
			logger.Printf("AdminSettings: SaaS feed store migration not applied (%v); outcome=%s", mErr, rep.Outcome)
		}
	} else if rep.Outcome == "migrated" {
		logger.Printf("AdminSettings: migrated SaaS feed store to schema %d (url_class=%s protocol_reset=%t backup=%q)",
			rep.ToSchema, rep.URLClass, rep.ProtocolReset, sanitizeLog(rep.BackupPath))
	}

	applyAdminSecurity(&s)
	applyAdminServices(&s)
	applyLegacyLDAPRetirement(&s)
	applyAdminNetwork(&s)
	applyAdminYARA(&s)
	applyAdminAutoExcludeTunables(&s)
	applyAdminSupportRetention(&s)             // Slice B: configurable support-bundle retention caps
	setDecRedactHosts(s.DecryptionRedactHosts) // ADR-0011 §4 host/SNI redaction posture

	snapshotOverriddenSurfaces(s)

	logger.Printf("AdminSettings: loaded from %s", path)
}

// applyAdminSecurity applies policy, IP filter, rate limiter, and connection
// limit settings. Extracted to keep LoadAdminSettings under the cyclop cap.
func applyAdminSecurity(s *AdminSettings) {
	if s.DefaultAction != "" {
		setDefaultPolicyAction(s.DefaultAction)
	}
	// policy-draft opt-in. Plain bool (no sentinel): the default is false and
	// there is no YAML seed to protect, so a pre-feature settings file (field
	// absent ⇒ false) correctly lands on live-write mode.
	setRequireCommit(s.RequireCommit)
	if s.IPFilterMode != "" {
		ipf.SetMode(s.IPFilterMode)
		for _, ip := range s.IPFilterList {
			_ = ipf.Add(ip)
		}
	}
	if s.RateLimitRPM > 0 {
		rl.Configure(s.RateLimitRPM, time.Minute)
		for _, ex := range s.RateLimitExemptions {
			_ = rl.AddExemption(ex)
		}
	}
	if s.ConnLimitEnabled && s.ConnLimitMaxPerIP > 0 {
		connLimiter.Enable(s.ConnLimitMaxPerIP)
	}
	if s.BlockPageHTML != "" {
		_ = setBlockPageHTML(s.BlockPageHTML)
	}
	if len(s.RewriteRules) > 0 {
		rewriter.SetRules(s.RewriteRules)
	}
}

// applyAdminServices applies logging, monitoring, and session settings.
func applyAdminServices(s *AdminSettings) {
	if s.SyslogAddr != "" {
		// Record intent even if the connect fails so checkSyslogFeed surfaces a
		// silently-down SIEM feed (see syslogConfiguredAddr).
		syslogConfiguredAddr = s.SyslogAddr
		if err := InitSyslog(s.SyslogAddr, s.SyslogFormat); err == nil {
			syslogConfigured = s.SyslogAddr
		}
	}
	if s.OTLPEndpoint != "" {
		globalOTLP.Configure(s.OTLPEndpoint, s.OTLPHeaders)
		globalOTLPTraces.Configure(s.OTLPEndpoint, s.OTLPHeaders)
	}
	if s.MetricsToken != "" {
		metricsToken = s.MetricsToken
	}
	// PR3 Option B node-local pseudonym key. Accept ONLY a full-length (32-byte) key —
	// a truncated/corrupt/hand-edited value is ignored so the posture fails closed to a
	// sentinel rather than HMACing with a weak key.
	if len(s.TrafficPseudonymKey) == trafficKeyLen {
		setTrafficPseudonymKey(s.TrafficPseudonymKey)
	}
	// If the destination-privacy posture is ON but no valid key was restored (a node
	// upgrading from the legacy/B0 host/SNI toggle, which had no key), mint one now so
	// redaction produces real tokens instead of the fail-closed sentinel. Generated
	// in-memory here; it persists on the next SaveAdminSettings. Logged so the operator
	// knows a key was minted (pseudonym correlation for this node begins here).
	//
	// Gate on the LOADED posture (s.DecryptionRedactHosts), NOT the live decRedactHosts()
	// flag: applyAdminServices runs BEFORE setDecRedactHosts restores the flag at the end
	// of LoadAdminSettings, so the live flag still holds the pre-load default here. Reading
	// it would make a legacy `decryption_redact_hosts:true` file with no key skip minting,
	// leaving the node emitting the fail-closed sentinel until the next settings save.
	if s.DecryptionRedactHosts && len(getTrafficPseudonymKey()) != trafficKeyLen {
		if err := ensureTrafficPseudonymKey(); err != nil {
			logger.Printf("TrafficRedaction: pseudonym key generation failed; destination redaction fails closed to a sentinel: %v", err)
		} else {
			logger.Printf("TrafficRedaction: destination-privacy posture is on but no key was stored; minted a node-local pseudonym key (persists on next settings save)")
		}
	}
	if s.LogLevel != "" {
		SetLogLevel(ParseLogLevel(s.LogLevel))
	}
	if s.SessionTimeoutHours > 0 {
		SetSessionTTL(time.Duration(s.SessionTimeoutHours) * time.Hour)
	}
	switch {
	case s.LogStoreEnabledSaved:
		// GUI-controlled enable state is authoritative.
		setLogStoreDesired(s.LogRetentionDays, s.LogRetentionMaxGB)
		if s.LogStoreEnabled {
			if err := enableLogStore(resolveLifecycleCtx(), logStoreDir, s.LogRetentionDays, s.LogRetentionMaxGB); err != nil {
				logger.Printf("WARN AdminSettings: cannot enable history store: %v", err)
			}
		} else {
			disableLogStore()
		}
	case s.LogRetentionSaved && globalLogStore.Load() != nil:
		// Legacy settings (pre-GUI-toggle): store enabled via YAML, apply saved
		// retention only — never force-disable.
		globalLogStore.Load().SetRetention(s.LogRetentionDays, s.LogRetentionMaxGB)
		setLogStoreDesired(s.LogRetentionDays, s.LogRetentionMaxGB)
	}
	if s.LogCriticalDiskPct > 0 {
		setCriticalDiskPct(s.LogCriticalDiskPct)
	}
	applyBlocklistFeeds(s)
	// F3a-2: the signed-feed URL is NO LONGER routed into the legacy additive
	// syncer (globalSaaSFeed). The legacy syncer keeps whatever URL it was
	// configured with at startup; the new signed-feed URL lives only in the
	// durable holder below. This is the "critical separation" contract — a
	// persisted signed URL (feeds.culvertlabs.com/…/manifest.sigstore.json) must
	// never be handed to the raw-category syncer, which would misinterpret it and
	// fetch it as a plain feed. No downloader consumes the holder in F3a-2; it is
	// inert configuration until the F3b signed-feed client lands.
	setSaaSFeedDurable(saasFeedDurable{
		Managed:        s.SaaSFeedManaged,
		Enabled:        s.SaaSFeedEnabled,
		URL:            s.SaaSFeedURL,
		Protocol:       s.SaaSFeedProtocol,
		RefreshSeconds: s.SaaSFeedRefreshSeconds,
		SchemaVersion:  s.SaaSStoreSchemaVersion,
	})
}

// BlocklistFeedSetting is the persisted form of one blocklist feed.
type BlocklistFeedSetting struct {
	URL      string `json:"url"`
	Interval string `json:"interval,omitempty"` // Go duration; "0s" = auto-sync disabled
}

// applyBlocklistFeeds restores blocklist feeds into blFeedSyncer. Settings
// files written before the multi-feed rework carry a single
// blocklist_feed_url/interval pair — migrate it when no feed list exists.
// The persisted list is authoritative: it replaces any YAML/CLI-seeded
// feed, so feeds deleted or edited in the GUI stay that way across
// restarts. Files with no feed opinion at all (sentinel unset, no legacy
// URL) leave the startup seed untouched.
func applyBlocklistFeeds(s *AdminSettings) {
	feeds := s.BlocklistFeeds
	if len(feeds) == 0 && s.BlocklistFeedURL != "" {
		feeds = []BlocklistFeedSetting{{URL: s.BlocklistFeedURL, Interval: s.BlocklistFeedInterval}}
	}
	if !s.BlocklistFeedsSaved && len(feeds) == 0 {
		return // pre-feature settings file with no feed config — keep startup seed
	}
	blFeedSyncer.ClearFeeds()
	for i := range feeds {
		if feeds[i].URL == "" {
			continue
		}
		interval := blFeedDefaultInterval
		if feeds[i].Interval != "" {
			if d, err := time.ParseDuration(feeds[i].Interval); err == nil {
				if d < 0 {
					d = 0
				}
				interval = d
			}
		}
		blFeedSyncer.SetFeed(feeds[i].URL, interval)
	}
}

// applyLegacyLDAPRetirement applies the durable LDAP-authority cutover
// sentinel (ADR-0025 / P1-2). LoadAdminSettings runs AFTER the legacy auth
// providers wire (main.go init order), so a retired-but-still-wired legacy
// provider from THIS boot is deactivated here via the shared enforcement
// path. The reverse reconciliation also lives here: a cutover observed
// earlier in boot (registry profile present before the settings path was
// known) persists now.
func applyLegacyLDAPRetirement(s *AdminSettings) {
	if s.LegacyLDAPRetired {
		legacyLDAPRetiredFlag.Store(true)
	}
	enforceLegacyLDAPShadowing()
	if legacyLDAPRetired() && !s.LegacyLDAPRetired {
		// In-memory cutover predates the settings load — make it durable.
		adminSettingsSave()
	}
}

// applyAdminNetwork applies UI access, TLS, and network settings.
func applyAdminNetwork(s *AdminSettings) {
	if len(s.UIAllowIPs) > 0 {
		_ = SetUIAllowedCIDRs(s.UIAllowIPs)
	}
	if s.BaseURL != "" {
		SetProxyBaseURL(s.BaseURL)
	}
	if len(s.UISANs) > 0 {
		uiExtraSANs = s.UISANs
	}
	if s.TrustForwardedHeaders {
		trustForwardedHeaders = true
	}
	if s.TrustedProxyCIDRsSaved {
		// Authoritative replace (empty list wipes the YAML seed), mirroring the
		// UpstreamProxiesSaved sentinel. Sentinel-less legacy files keep the
		// YAML/CLI seed applied by the startup slice.
		if err := SetTrustedProxyCIDRs(s.TrustedProxyCIDRs); err != nil {
			logger.Printf("AdminSettings: invalid trusted_proxy_cidrs (%v) — X-Forwarded-For will NOT be trusted", err)
		}
	}
	if s.UpstreamProxiesSaved {
		// Authoritative replace (empty list wipes the YAML seed). SetProxies
		// keeps the circuit-breaker parameters the startup slice configured.
		upstreamPool.SetProxies(s.UpstreamProxies)
		applyUpstreamProxy()
	}
}

// applyAdminYARA restores YARA engine settings saved via the Admin GUI.
// Only applied when YARASettingsSaved is true, preventing zero-value bools
// from disabling YARA on installations that pre-date this feature.
func applyAdminYARA(s *AdminSettings) {
	if !s.YARASettingsSaved {
		return
	}
	yaraSetEnabled(s.YARAEnabled)
	if s.YARATimeoutSecs > 0 {
		yaraSetTimeoutSecs(s.YARATimeoutSecs)
	}
	if s.YARAMaxInflight > 0 {
		yaraSetMaxInflight(s.YARAMaxInflight)
	}
	if s.YARAOnTimeout != "" {
		yaraSetOnTimeout(s.YARAOnTimeout)
	}
	if s.YARAOnSaturation != "" {
		yaraSetOnSaturation(s.YARAOnSaturation)
	}
	yaraSetAlertDegraded(s.YARAAlertDegraded)
}

// applyAdminAutoExcludeTunables restores the adaptive decryption-exclusion tunables
// saved via the admin GUI (F10). Only applied when the sentinel is set, so a
// settings file predating this feature (fields absent ⇒ zero, sentinel false) leaves
// the engine defaults intact — feature-off is byte-identical. The persisted set is
// resolved (zero ⇒ default) and VALIDATED; an out-of-range value (e.g. a hand-edited
// file) is refused and the engine keeps its defaults (fail-closed), rather than
// letting an out-of-bounds value through the engine's weaker last-resort clamp.
func applyAdminAutoExcludeTunables(s *AdminSettings) {
	if !s.AutoExcludeTunablesSaved {
		return
	}
	resolved := resolveAutoExcludeTunables(autoExcludeTunables{
		ConfirmN:      s.AutoExcludeConfirmN,
		TTLSecs:       s.AutoExcludeTTLSecs,
		PinnedTTLSecs: s.AutoExcludePinnedTTLSecs,
		WindowSecs:    s.AutoExcludeWindowSecs,
		MaxEntries:    s.AutoExcludeMaxEntries,
	})
	if err := validateAutoExcludeTunables(resolved); err != nil {
		logger.Printf("AdminSettings: ignoring invalid persisted auto-exclusion tunables (%v) — keeping engine defaults", err)
		return
	}
	autoExclude().Reconfigure(resolved.engineConfig())
}

// snapshotAdminEndpoints copies the external-URL / SANs, syslog, and OTLP endpoint
// settings into s. Extracted to keep SaveAdminSettings under the funlen cap (mirrors
// snapshotBlocklistFeeds / snapshotAutoExcludeTunables); no behavior change.
func snapshotAdminEndpoints(s *AdminSettings) {
	if proxyExternalBaseURL != "" {
		s.BaseURL = proxyExternalBaseURL
	}
	if len(uiExtraSANs) > 0 {
		s.UISANs = uiExtraSANs
	}
	if syslogConfigured != "" {
		s.SyslogAddr = syslogConfigured
		if globalSyslog != nil {
			s.SyslogFormat = globalSyslog.Format()
		}
	}
	s.OTLPEndpoint = globalOTLP.Endpoint()
	if h := globalOTLP.Headers(); len(h) > 0 {
		s.OTLPHeaders = h
	}
}

// snapshotAutoExcludeTunables copies the effective tunables into s, so the durable
// file always reflects what is (or is about to be) applied; on load they resolve to
// themselves and Reconfigure is a no-op when unchanged. The learned cache contents
// are NOT persisted (volatile). Extracted to keep SaveAdminSettings under the funlen
// cap (mirrors snapshotBlocklistFeeds).
//
// override lets the F10 tunables PUT persist the TARGET values BEFORE they are applied
// to the live cache (persist-before-apply): a persist failure then never touches the
// cache, so learned entries an operator lowered max_entries below are not evicted-then-
// stranded. nil ⇒ snapshot the current live values (every other caller).
func snapshotAutoExcludeTunables(s *AdminSettings, override *autoExcludeTunables) {
	t := currentAutoExcludeTunables()
	if override != nil {
		t = *override
	}
	s.AutoExcludeTunablesSaved = true
	s.AutoExcludeConfirmN = t.ConfirmN
	s.AutoExcludeTTLSecs = t.TTLSecs
	s.AutoExcludePinnedTTLSecs = t.PinnedTTLSecs
	s.AutoExcludeWindowSecs = t.WindowSecs
	s.AutoExcludeMaxEntries = t.MaxEntries
}

// snapshotBlocklistFeeds copies the live feed set into s. blFeedSyncer is
// nil until main() runs loadBlocklist, and SaveAdminSettings can run from a
// detached goroutine (adminSettingsSave) that outlives the caller — so guard
// against nil rather than deref it, mirroring the globalSyslog guard. The
// legacy single-feed fields are intentionally not written anymore (read-only
// migration path). BlocklistFeedsSaved stays false on a nil syncer so the
// snapshot's (necessarily empty) list is not treated as authoritative on load.
func snapshotBlocklistFeeds(s *AdminSettings) {
	if blFeedSyncer == nil {
		return
	}
	s.BlocklistFeedsSaved = true
	for _, f := range blFeedSyncer.Feeds() {
		s.BlocklistFeeds = append(s.BlocklistFeeds, BlocklistFeedSetting{
			URL:      f.URL,
			Interval: f.Interval.String(),
		})
	}
}

// adminSaveOverrides carries per-feature TARGET values a persist-before-apply PUT
// wants written to disk instead of the current live values. Every field is nil for
// an ordinary omnibus save; a PUT sets exactly the one it owns so a persist failure
// never leaves that feature's live state changed vs disk. The omnibus save rebuilds
// AdminSettings from scratch on EVERY admin mutation, so a new durable field MUST be
// snapshotted in saveAdminSettingsWithOverrides or it is silently dropped on the next
// unrelated mutation.
type adminSaveOverrides struct {
	autoExclude      *autoExcludeTunables
	supportRetention *supportRetentionConfig
	// applyOnSuccess, when set, is the runtime apply for a persist-before-apply PUT.
	// It runs INSIDE the save's adminSettingsMu critical section, immediately after a
	// successful write — so no concurrent omnibus save can snapshot the pre-apply
	// runtime value and then land its own AtomicWrite after this one, reverting the
	// just-persisted setting on disk. It runs only on a successful write (persist
	// failure ⇒ never applied ⇒ runtime and disk stay in agreement).
	applyOnSuccess func()
}

// SaveAdminSettings snapshots all current runtime values and writes them
// atomically to the settings file. Called after every API mutation. Returns the
// write error so a caller that needs durable-vs-runtime consistency can detect a
// persist failure; the fire-and-forget adminSettingsSave wrapper ignores it.
func SaveAdminSettings() error { return saveAdminSettingsWithOverrides(adminSaveOverrides{}) }

// saveAdminSettingsWithOverrides is SaveAdminSettings with optional per-feature
// TARGET overrides. When a field is non-nil the durable file records those TARGET
// values instead of the live ones — the owning PUT persists the target FIRST, then
// (only on success) applies it to the live runtime. Because those applies are
// infallible, a persist failure leaves the live state — and any data it governs —
// untouched.
func saveAdminSettingsWithOverrides(ov adminSaveOverrides) error {
	// Hold adminSettingsMu across the ENTIRE snapshot → write → apply sequence, not
	// just the path read. Every save (omnibus or override-carrying) is thereby
	// serialized: a concurrent adminSettingsSave() goroutine can neither snapshot a
	// half-applied runtime nor land its AtomicWrite between this save's write and its
	// applyOnSuccess. Saves are per-mutation and infrequent, so full serialization is
	// free; adminSettingsSave already runs this off the request goroutine.
	adminSettingsMu.Lock()
	defer adminSettingsMu.Unlock()
	path := adminSettingsPath
	if path == "" {
		return nil
	}

	s := AdminSettings{
		DefaultAction:          defaultPolicyAction(),
		RequireCommit:          requireCommitEnabled(),
		IPFilterMode:           ipf.Mode(),
		IPFilterList:           ipf.List(),
		RateLimitRPM:           rl.Limit(),
		RateLimitExemptions:    rl.ListExemptions(),
		ConnLimitEnabled:       connLimiter.Enabled(),
		ConnLimitMaxPerIP:      connLimiter.MaxPerIP(),
		BlockPageHTML:          getBlockPageHTML(),
		MetricsToken:           metricsToken,
		LogLevel:               effectiveAdminLogLevel().String(),
		SessionTimeoutHours:    int(getSessionTTL().Hours()),
		UIAllowIPs:             ListUIAllowedCIDRs(),
		TrustForwardedHeaders:  trustForwardedHeaders,
		TrustedProxyCIDRs:      ListTrustedProxyCIDRs(),
		TrustedProxyCIDRsSaved: true, // once saved, the persisted list is authoritative (incl. empty)
		LegacyLDAPRetired:      legacyLDAPRetired(),
	}

	snapshotAdminEndpoints(&s)

	// Rewrite rules
	s.RewriteRules = rewriter.List()

	snapshotBlocklistFeeds(&s)

	// SaaS feed (F3a-2). ALL durable feed-config fields — including the URL —
	// are snapshotted from the holder (snapshotSaaSFeedDurable is the sole writer
	// of s.SaaSFeedURL). The legacy syncer no longer owns the URL, so an unrelated
	// admin mutation preserves the signed-feed config + schema marker without
	// re-reading (and thereby coupling to) the legacy additive syncer.
	snapshotSaaSFeedDurable(&s)

	// Upstream proxy pool (raw entries — see field comment)
	s.UpstreamProxiesSaved = true
	s.UpstreamProxies = upstreamPool.Entries()

	// History-store enable state + retention (retention remembered even when off)
	s.LogStoreEnabledSaved = true
	s.LogStoreEnabled = globalLogStore.Load() != nil
	s.LogRetentionSaved = true
	s.LogRetentionDays, s.LogRetentionMaxGB = getLogStoreDesired()
	s.LogCriticalDiskPct = getCriticalDiskPct()

	// YARA engine settings
	s.YARASettingsSaved = true
	s.YARAEnabled = yaraGetEnabled()
	s.YARATimeoutSecs = yaraGetTimeoutSecs()
	s.YARAMaxInflight = yaraGetMaxInflight()
	s.YARAOnTimeout = yaraGetOnTimeout()
	s.YARAOnSaturation = yaraGetOnSaturation()
	s.YARAAlertDegraded = yaraGetAlertDegraded()

	snapshotAutoExcludeTunables(&s, ov.autoExclude)
	snapshotSupportRetention(&s, ov.supportRetention) // Slice B: configurable retention caps
	s.DecryptionRedactHosts = decRedactHosts()        // ADR-0011 §4 / PR3 Option B destination-privacy posture
	s.TrafficPseudonymKey = getTrafficPseudonymKey()  // PR3 Option B node-local pseudonym key (nil when unset)

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		logger.Printf("AdminSettings: marshal error: %v", err)
		return err
	}
	// AtomicWrite (unique temp + fsync): adminSettingsSave spawns this in a
	// goroutine per API mutation, so a fixed ".tmp" name lets concurrent
	// saves interleave into the same temp file and publish a torn result.
	if err := fileutil.AtomicWrite(path, data, 0o600); err != nil {
		logger.Printf("AdminSettings: write error: %v", err)
		return err
	}
	snapshotOverriddenSurfaces(s)
	// Persist-before-apply: the durable write succeeded, so apply the target to the
	// live runtime now — still under adminSettingsMu, so the (disk, runtime) pair
	// moves atomically w.r.t. every other save.
	if ov.applyOnSuccess != nil {
		ov.applyOnSuccess()
	}
	return nil
}

// adminSettingsSave is a convenience alias for use in API handlers.
// Runs SaveAdminSettings in a goroutine to avoid blocking the HTTP response.
// The write error is intentionally ignored here (best-effort, logged inside
// SaveAdminSettings); callers that need durable-vs-runtime consistency call
// SaveAdminSettings directly and handle the returned error (the F10 tunables PUT).
func adminSettingsSave() {
	go func() { _ = SaveAdminSettings() }()
}

// syslogConfigured is declared in ui.go (line 2404).
// SetProxyBaseURL is declared in store.go (line 1502).
