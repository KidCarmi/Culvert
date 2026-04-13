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

	// Session
	SessionTimeoutHours int `json:"session_timeout_hours,omitempty"`

	// Network
	UIAllowIPs            []string `json:"ui_allow_ips,omitempty"`
	BaseURL               string   `json:"base_url,omitempty"`
	UISANs                []string `json:"ui_sans,omitempty"`
	TrustForwardedHeaders bool     `json:"trust_forwarded_headers"`

	// Blocklist feed
	BlocklistFeedURL      string `json:"blocklist_feed_url,omitempty"`
	BlocklistFeedInterval string `json:"blocklist_feed_interval,omitempty"` // e.g. "24h"

	// SaaS category feed
	SaaSFeedURL string `json:"saas_feed_url,omitempty"`
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
	if s.BlocklistFeedURL != "" {
		interval := 24 * time.Hour
		if d, err := time.ParseDuration(s.BlocklistFeedInterval); err == nil && d > 0 {
			interval = d
		}
		blFeedSyncer.SetFeed(s.BlocklistFeedURL, interval)
	}
	if s.SaaSFeedURL != "" {
		globalSaaSFeed.Configure(s.SaaSFeedURL, 24*time.Hour)
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
		LogLevel:              GetLogLevel().String(),
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

	// Blocklist feed
	feedURL, _, _, feedInterval := blFeedSyncer.Stats()
	if feedURL != "" {
		s.BlocklistFeedURL = feedURL
	}

	// SaaS feed
	if saasURL := globalSaaSFeed.FeedURL(); saasURL != "" {
		s.SaaSFeedURL = saasURL
		s.BlocklistFeedInterval = feedInterval.String()
	}

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
