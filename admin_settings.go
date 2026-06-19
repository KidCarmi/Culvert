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
	"os"
	"sync"
	"time"
)

// AdminSettings holds every admin-configurable value that needs to survive
// a restart but isn't already persisted by its own dedicated file.
type AdminSettings struct {
	// Policy
	DefaultAction string `json:"default_action,omitempty"` // "allow" or "deny"

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

	// Session
	SessionTimeoutHours int `json:"session_timeout_hours,omitempty"`

	// Network
	UIAllowIPs            []string `json:"ui_allow_ips,omitempty"`
	BaseURL               string   `json:"base_url,omitempty"`
	UISANs                []string `json:"ui_sans,omitempty"`
	TrustForwardedHeaders bool     `json:"trust_forwarded_headers"`

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

	// SaaS category feed
	SaaSFeedURL string `json:"saas_feed_url,omitempty"`

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
}

var (
	adminSettingsMu   sync.Mutex
	adminSettingsPath string
)

// LoadAdminSettings reads the settings file and applies each field to its
// respective component. Called once in main() after all components init.
// Missing file = first run; each component keeps its config/default value.
func LoadAdminSettings(path string) {
	adminSettingsMu.Lock()
	adminSettingsPath = path
	adminSettingsMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return // first run or missing file — use config defaults
	}
	var s AdminSettings
	if json.Unmarshal(data, &s) != nil {
		logger.Printf("AdminSettings: unmarshal error from %s — using defaults", path)
		return
	}

	applyAdminSecurity(&s)
	applyAdminServices(&s)
	applyAdminNetwork(&s)
	applyAdminYARA(&s)

	logger.Printf("AdminSettings: loaded from %s", path)
}

// applyAdminSecurity applies policy, IP filter, rate limiter, and connection
// limit settings. Extracted to keep LoadAdminSettings under the cyclop cap.
func applyAdminSecurity(s *AdminSettings) {
	if s.DefaultAction != "" {
		setDefaultPolicyAction(s.DefaultAction)
	}
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
	if s.SaaSFeedURL != "" {
		globalSaaSFeed.Configure(s.SaaSFeedURL, 24*time.Hour)
	}
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

// SaveAdminSettings snapshots all current runtime values and writes them
// atomically to the settings file. Called after every API mutation.
func SaveAdminSettings() {
	adminSettingsMu.Lock()
	path := adminSettingsPath
	adminSettingsMu.Unlock()
	if path == "" {
		return
	}

	s := AdminSettings{
		DefaultAction:         defaultPolicyAction(),
		IPFilterMode:          ipf.Mode(),
		IPFilterList:          ipf.List(),
		RateLimitRPM:          rl.Limit(),
		RateLimitExemptions:   rl.ListExemptions(),
		ConnLimitEnabled:      connLimiter.enabled.Load(),
		ConnLimitMaxPerIP:     connLimiter.MaxPerIP(),
		BlockPageHTML:         getBlockPageHTML(),
		MetricsToken:          metricsToken,
		LogLevel:              effectiveAdminLogLevel().String(),
		SessionTimeoutHours:   int(getSessionTTL().Hours()),
		UIAllowIPs:            ListUIAllowedCIDRs(),
		TrustForwardedHeaders: trustForwardedHeaders,
	}

	// BaseURL / SANs
	if proxyExternalBaseURL != "" {
		s.BaseURL = proxyExternalBaseURL
	}
	if len(uiExtraSANs) > 0 {
		s.UISANs = uiExtraSANs
	}

	// Syslog
	if syslogConfigured != "" {
		s.SyslogAddr = syslogConfigured
		if globalSyslog != nil {
			s.SyslogFormat = globalSyslog.Format()
		}
	}

	// OTLP
	globalOTLP.mu.RLock()
	s.OTLPEndpoint = globalOTLP.endpoint
	if len(globalOTLP.headers) > 0 {
		s.OTLPHeaders = globalOTLP.headers
	}
	globalOTLP.mu.RUnlock()

	// Rewrite rules
	s.RewriteRules = rewriter.List()

	snapshotBlocklistFeeds(&s)

	// SaaS feed
	if saasURL := globalSaaSFeed.FeedURL(); saasURL != "" {
		s.SaaSFeedURL = saasURL
	}

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

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		logger.Printf("AdminSettings: marshal error: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		logger.Printf("AdminSettings: write error: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		logger.Printf("AdminSettings: rename error: %v", err)
	}
}

// adminSettingsSave is a convenience alias for use in API handlers.
// Runs SaveAdminSettings in a goroutine to avoid blocking the HTTP response.
func adminSettingsSave() {
	go SaveAdminSettings()
}

// syslogConfigured is declared in ui.go (line 2404).
// SetProxyBaseURL is declared in store.go (line 1502).
