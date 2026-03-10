package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

// FileConfig mirrors the YAML structure of config.yaml.
// CLI flags always override file values.
type FileConfig struct {
	Proxy struct {
		Port      int    `yaml:"port"`
		UIPort    int    `yaml:"ui_port"`
		Blocklist string `yaml:"blocklist"`
		LogFile   string `yaml:"log_file"`
		LogMaxMB  int    `yaml:"log_max_mb"`
		TLSCert    string `yaml:"tls_cert"`    // path to TLS cert for UI
		TLSKey     string `yaml:"tls_key"`     // path to TLS key for UI
		SOCKS5Port   int    `yaml:"socks5_port"`   // 0 = disabled
		MetricsToken string `yaml:"metrics_token"` // Bearer token for /metrics; empty=open
		PolicyFile   string `yaml:"policy_file"`   // JSON file for PBAC policy rules
		CAPath            string   `yaml:"ca_path"`            // Path for encrypted Root CA bundle
		SSLBypassFile     string   `yaml:"ssl_bypass_file"`    // JSON file for persistent/dynamic SSL bypass patterns
		SSLBypassPatterns []string `yaml:"ssl_bypass_patterns"` // Initial patterns (seeded into ssl_bypass_file on first run)
		ContentScanFile     string   `yaml:"content_scan_file"`     // JSON file for persistent DPI signature patterns
		ContentScanPatterns []string `yaml:"content_scan_patterns"` // Initial DPI patterns (seeded into content_scan_file on first run)
		GeoIPDB             string   `yaml:"geoip_db"`              // Path to GeoLite2-Country.mmdb; empty = GeoIP disabled
		IdPProfilesFile     string   `yaml:"idp_profiles_file"`     // JSON file for generic IdP profiles
		BaseURL             string   `yaml:"base_url"`              // External base URL for OIDC/SAML callbacks (e.g. "https://proxy.corp.com:9090")
	} `yaml:"proxy"`
	Auth struct {
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
	} `yaml:"auth"`
	Security struct {
		IPFilterMode string   `yaml:"ip_filter_mode"` // "allow" | "block" | ""
		IPList       []string `yaml:"ip_list"`        // IPs or CIDRs
		RateLimit    int      `yaml:"rate_limit"`     // max requests per minute (0=off)
	} `yaml:"security"`

	// LDAP / Active Directory authentication backend.
	// When URL is set, LDAP auth is used instead of local username/password.
	LDAP LDAPConfig `yaml:"ldap"`

	// OIDC / OAuth2 token-introspection authentication backend.
	// When IntrospectionURL is set, OIDC auth is used instead of local auth.
	// LDAP takes precedence over OIDC if both are configured.
	OIDC OIDCConfig `yaml:"oidc"`

	// Rewrite defines header mutation rules applied to matching requests/responses.
	Rewrite []RewriteRule `yaml:"rewrite"`

	// FileBlock configures the file-extension block profile.
	// When Extensions is empty the built-in default list is loaded instead.
	FileBlock struct {
		Extensions []string `yaml:"extensions"`
	} `yaml:"file_block"`

	// LogFormat controls the system-log output format: "text" (default) or "json".
	LogFormat string `yaml:"log_format"`

	// DefaultAction controls what happens when no policy rule matches a request.
	// "allow" (passthrough mode) or "deny" (zero-trust, default).
	// Use "allow" for initial setup; switch to "deny" once rules are configured.
	DefaultAction string `yaml:"default_action"`

	// AuditLogFile is the path for persistent JSONL audit log.
	// When empty audit events are kept in-memory only (lost on restart).
	AuditLogFile string `yaml:"audit_log_file"`

	// SyslogAddr enables forwarding of all log lines and audit events to a
	// remote syslog server. Format: "udp://host:514" or "tcp://host:601".
	SyslogAddr string `yaml:"syslog_addr"`

	// UIAllowIPs is an optional list of CIDRs/IPs allowed to access the admin
	// panel. Empty = allow from any IP address (default).
	UIAllowIPs []string `yaml:"ui_allow_ips"`

	// SessionTimeoutHours overrides the default 8-hour UI session lifetime.
	// Must be 1–168 (one hour to one week). Zero = use the default (8h).
	SessionTimeoutHours int `yaml:"session_timeout_hours"`

	// SecurityScan configures the local security scanning stack:
	// ClamAV antivirus, YARA rule-based detection, and threat-intelligence
	// feed lookups — all running locally with no external API dependency.
	SecurityScan struct {
		// Enabled activates the security scanner subsystem.
		// Individual components (ClamAV, YARA, feeds) are only active when
		// their respective options are also set.
		Enabled bool `yaml:"enabled"`

		// ClamAVAddr is the address of the ClamAV daemon.
		// Formats: "unix:/var/run/clamav/clamd.sock"  or  "tcp:localhost:3310"
		// Leave empty to disable ClamAV scanning.
		ClamAVAddr string `yaml:"clamav_addr"`

		// YARARulesDir is the path to a directory containing *.yar / *.yara
		// rule files.  All files in the directory are loaded at startup.
		// Leave empty to disable YARA scanning.
		YARARulesDir string `yaml:"yara_rules_dir"`

		// ThreatFeedDB is the path to the JSON file used to persist threat
		// feed data across restarts.  The file is created automatically on
		// the first sync.  Leave empty to keep feed data in-memory only.
		ThreatFeedDB string `yaml:"threat_feed_db"`

		// SyncInterval is how often the threat feeds are re-downloaded.
		// Valid Go duration string, e.g. "6h", "12h", "24h".  Default: 6h.
		SyncInterval string `yaml:"sync_interval"`

		// CacheTTL is how long a scan result is cached by SHA-256 hash.
		// Valid Go duration string, e.g. "1h", "4h".  Default: 1h.
		CacheTTL string `yaml:"cache_ttl"`

		// CacheSize is the maximum number of hash entries in the scan cache.
		// Default: 10 000.
		CacheSize int `yaml:"cache_size"`

		// MaxScanMB is the maximum megabytes to buffer per HTTP response for
		// scanning.  Responses larger than this are forwarded unscanned.
		// Default: 5 (5 MiB).
		MaxScanMB int `yaml:"max_scan_mb"`
	} `yaml:"security_scan"`
}

func loadFileConfig(path string) (*FileConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var fc FileConfig
	if err := yaml.NewDecoder(f).Decode(&fc); err != nil {
		return nil, err
	}
	return &fc, nil
}
