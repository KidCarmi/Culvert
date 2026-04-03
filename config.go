package main

import (
	"fmt"
	"os"
	"strings"

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
		URLCategoriesFile   string   `yaml:"url_categories_file"`   // JSON file for dynamic URL categories (host lists per category)
		BaseURL             string   `yaml:"base_url"`              // External base URL for OIDC/SAML callbacks (e.g. "https://proxy.corp.com:9090")
		BlocklistFeedURL      string   `yaml:"blocklist_feed_url"`      // URL to auto-sync blocklist from (one domain per line)
		BlocklistFeedInterval string   `yaml:"blocklist_feed_interval"` // sync interval (e.g. "24h"); default 24h
		FileProfilesFile      string   `yaml:"fileprofiles_file"`       // JSON file for dynamic file extension profiles
		ClientCertFile        string   `yaml:"client_cert_file"`        // Client TLS cert for upstream mTLS
		ClientKeyFile         string   `yaml:"client_key_file"`         // Client TLS key for upstream mTLS
		OCSPCheck             bool     `yaml:"ocsp_check"`              // Enable OCSP revocation checking for upstream certs
	} `yaml:"proxy"`
	Auth struct {
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
	} `yaml:"auth"`
	Security struct {
		IPFilterMode string   `yaml:"ip_filter_mode"` // "allow" | "block" | ""
		IPList       []string `yaml:"ip_list"`        // IPs or CIDRs
		RateLimit     int      `yaml:"rate_limit"`      // max requests per minute (0=off)
		MaxConnsPerIP int      `yaml:"max_conns_per_ip"` // max concurrent connections per IP (0=off)
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

	// Upstream proxy chaining with failover and circuit breaker.
	Upstream UpstreamConfig `yaml:"upstream"`

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

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true) // reject unknown fields (catch typos)
	var fc FileConfig
	if err := dec.Decode(&fc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := fc.validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
	}
	return &fc, nil
}

// validate checks FileConfig fields for invalid values at startup.
func (fc *FileConfig) validate() error {
	var errs []string

	// default_action
	if da := fc.DefaultAction; da != "" && da != "allow" && da != "deny" {
		errs = append(errs, fmt.Sprintf("default_action: must be \"allow\" or \"deny\", got %q", da))
	}

	// ip_filter_mode
	if m := fc.Security.IPFilterMode; m != "" && m != "allow" && m != "block" {
		errs = append(errs, fmt.Sprintf("security.ip_filter_mode: must be \"allow\" or \"block\", got %q", m))
	}

	// log_format
	if f := fc.LogFormat; f != "" && f != "text" && f != "json" {
		errs = append(errs, fmt.Sprintf("log_format: must be \"text\" or \"json\", got %q", f))
	}

	// session_timeout_hours
	if h := fc.SessionTimeoutHours; h != 0 && (h < 1 || h > 168) {
		errs = append(errs, fmt.Sprintf("session_timeout_hours: must be 1–168, got %d", h))
	}

	// port ranges
	if p := fc.Proxy.Port; p != 0 && (p < 1 || p > 65535) {
		errs = append(errs, fmt.Sprintf("proxy.port: must be 1–65535, got %d", p))
	}
	if p := fc.Proxy.UIPort; p != 0 && (p < 1 || p > 65535) {
		errs = append(errs, fmt.Sprintf("proxy.ui_port: must be 1–65535, got %d", p))
	}
	if p := fc.Proxy.SOCKS5Port; p != 0 && (p < 1 || p > 65535) {
		errs = append(errs, fmt.Sprintf("proxy.socks5_port: must be 1–65535, got %d", p))
	}

	// max_conns_per_ip
	if n := fc.Security.MaxConnsPerIP; n < 0 {
		errs = append(errs, fmt.Sprintf("security.max_conns_per_ip: must be >= 0, got %d", n))
	}

	// rate_limit
	if n := fc.Security.RateLimit; n < 0 {
		errs = append(errs, fmt.Sprintf("security.rate_limit: must be >= 0, got %d", n))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
