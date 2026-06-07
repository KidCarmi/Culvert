package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
)

// FileConfig mirrors the YAML structure of config.yaml.
// CLI flags always override file values.
type FileConfig struct {
	Proxy struct {
		Port                  int      `yaml:"port"`
		UIPort                int      `yaml:"ui_port"`
		Blocklist             string   `yaml:"blocklist"`
		LogFile               string   `yaml:"log_file"`
		LogMaxMB              int      `yaml:"log_max_mb"`
		TLSCert               string   `yaml:"tls_cert"`                // path to TLS cert for UI
		TLSKey                string   `yaml:"tls_key"`                 // path to TLS key for UI
		UISANs                []string `yaml:"ui_sans"`                 // additional SANs for self-signed cert (IPs or hostnames)
		SOCKS5Port            int      `yaml:"socks5_port"`             // 0 = disabled
		MetricsToken          string   `yaml:"metrics_token"`           // Bearer token for /metrics; empty=open
		PolicyFile            string   `yaml:"policy_file"`             // JSON file for PBAC policy rules
		CAPath                string   `yaml:"ca_path"`                 // Path for encrypted Root CA bundle
		SSLBypassFile         string   `yaml:"ssl_bypass_file"`         // JSON file for persistent/dynamic SSL bypass patterns
		SSLBypassPatterns     []string `yaml:"ssl_bypass_patterns"`     // Initial patterns (seeded into ssl_bypass_file on first run)
		ContentScanFile       string   `yaml:"content_scan_file"`       // JSON file for persistent DPI signature patterns
		ContentScanPatterns   []string `yaml:"content_scan_patterns"`   // Initial DPI patterns (seeded into content_scan_file on first run)
		GeoIPDB               string   `yaml:"geoip_db"`                // Path to GeoLite2-Country.mmdb; empty = GeoIP disabled
		IdPProfilesFile       string   `yaml:"idp_profiles_file"`       // JSON file for generic IdP profiles
		URLCategoriesFile     string   `yaml:"url_categories_file"`     // JSON file for dynamic URL categories (host lists per category)
		BaseURL               string   `yaml:"base_url"`                // External base URL for OIDC/SAML callbacks (e.g. "https://proxy.corp.com:9090")
		TrustForwardedHeaders bool     `yaml:"trust_forwarded_headers"` // Trust X-Forwarded-* headers (enable when behind reverse proxy)
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
		IPFilterMode  string   `yaml:"ip_filter_mode"`   // "allow" | "block" | ""
		IPList        []string `yaml:"ip_list"`          // IPs or CIDRs
		RateLimit     int      `yaml:"rate_limit"`       // max requests per minute (0=off)
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

	// LogLevel sets the minimum log level: "DEBUG", "INFO" (default), "WARN", "ERROR".
	LogLevel string `yaml:"log_level"`

	// DefaultAction controls what happens when no policy rule matches a request.
	// "allow" (passthrough mode) or "deny" (zero-trust, default).
	// Use "allow" for initial setup; switch to "deny" once rules are configured.
	DefaultAction string `yaml:"default_action"`

	// AuditLogFile is the path for persistent JSONL audit log.
	// When empty audit events are kept in-memory only (lost on restart).
	AuditLogFile string `yaml:"audit_log_file"`

	// RequestLogFile is the path for persistent JSONL request log (Finding 6.1).
	// When empty, request logs are kept in-memory only (lost on restart).
	RequestLogFile string `yaml:"request_log_file"`

	// RequestLogMaxMB is the rotation size in MB for the request log file.
	// Default: 100 MB.
	RequestLogMaxMB int `yaml:"request_log_max_mb"`

	// SyslogAddr enables forwarding of all log lines and audit events to a
	// remote syslog server. Format: "udp://host:514" or "tcp://host:601".
	SyslogAddr string `yaml:"syslog_addr"`

	// SyslogFormat selects the syslog message format.
	// "rfc3164" (BSD syslog, default) or "rfc5424" (IETF structured syslog).
	// Modern SIEMs (Splunk HEC, Elastic, QRadar) prefer RFC 5424.
	SyslogFormat string `yaml:"syslog_format"`

	// OTLPEndpoint is the URL of an OpenTelemetry Collector OTLP/HTTP receiver.
	// Metrics are pushed as JSON to POST {endpoint}/v1/metrics every 15s.
	// Example: "http://otel-collector:4318"
	OTLPEndpoint string `yaml:"otlp_endpoint"`

	// UIAllowIPs is an optional list of CIDRs/IPs allowed to access the admin
	// panel. Empty = allow from any IP address (default).
	UIAllowIPs []string `yaml:"ui_allow_ips"`

	// SessionTimeoutHours overrides the default 8-hour UI session lifetime.
	// Must be 1–168 (one hour to one week). Zero = use the default (8h).
	SessionTimeoutHours int `yaml:"session_timeout_hours"`

	// SessionSecret is a hex-encoded HMAC key for signing session cookies.
	// When set, all nodes behind a load balancer share the same signing key
	// so sessions are valid across nodes. If empty, a random key is generated
	// at startup (single-node only). Also readable from CULVERT_SESSION_SECRET.
	SessionSecret string `yaml:"session_secret"`

	// Update configures the Docker self-update system.
	Update struct {
		UpdaterURL   string   `yaml:"updater_url"`   // URL of the updater sidecar (default: http://culvert-updater:7123)
		URLAllowlist []string `yaml:"url_allowlist"` // H4: operator-curated trusted updater URLs; empty ⇒ default + loopback only
	} `yaml:"update"`

	// Cluster configures Control Plane / Data Plane multi-node mode.
	// When Cluster.Role is "control-plane", this node starts a gRPC server
	// for Data Plane enrollment and config distribution.
	Cluster struct {
		Role     string `yaml:"role"`      // "control-plane" or "" (standalone); DP mode uses -enroll CLI
		GRPCAddr string `yaml:"grpc_addr"` // gRPC listen address (e.g. ":50051")
		CertFile string `yaml:"cert_file"` // TLS cert for gRPC mTLS (optional)
		KeyFile  string `yaml:"key_file"`  // TLS key for gRPC mTLS (optional)
		CAFile   string `yaml:"ca_file"`   // CA cert for client validation (optional)
		StateDB  string `yaml:"state_db"`  // Path to cluster.json (default: "cluster.json")
		// HA is configured at runtime from the admin GUI (Enable HA button) or
		// via --ha-join/--ha-token flags on the standby. No shared filesystem needed —
		// state is replicated over the existing mTLS gRPC channel.
	} `yaml:"cluster"`

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

		// ScanSvcListen starts the scan microservice sidecar on this address.
		// When set, this process runs ClamAV/YARA/DPI as an HTTP service that
		// other proxy instances can call. Example: ":8484".
		ScanSvcListen string `yaml:"scan_svc_listen"`

		// ScanSvcURL is the URL of a remote scan microservice.
		// When set, the proxy delegates body scanning to this service instead of
		// running ClamAV/YARA/DPI in-process. Example: "http://scan-svc:8484".
		ScanSvcURL string `yaml:"scan_svc_url"`
	} `yaml:"security_scan"`

	// CDR configures integration with the Sluice Content Disarm &
	// Reconstruction engine. Sluice runs as a Docker sidecar and strips
	// active content (macros, JS, OLE) from files passing through the
	// proxy before they reach the user.
	//
	// Phase 1 (this ships): single-instance gRPC client + TOFU pinning
	// at enrollment. Pool, circuit breaker, and policy engine land later.
	CDR CDRConfig `yaml:"cdr"`
}

// CDRConfig holds the YAML-addressable surface for Sluice integration.
// Paired with `-cdr-*` CLI flags in main.go (full GUI parity comes in a
// later phase via an Integrations → CDR panel).
type CDRConfig struct {
	// Enabled turns the CDR stage on.  Default off — operators must opt in.
	Enabled bool `yaml:"enabled"`

	// Endpoint of the single Sluice instance Culvert talks to.  Format
	// "host:port", e.g. "sluice:8443" (docker-compose) or "127.0.0.1:8443".
	// Multiple endpoints + load balancing are Phase 2.
	Endpoint string `yaml:"endpoint"`

	// FailMode selects behaviour when Sluice is unreachable / returns ERROR.
	//   "open"   — pass the original file through + audit event + alert
	//   "closed" — return 503 + block page + alert
	// Default "open". Per-policy overrides come with the policy engine.
	FailMode string `yaml:"fail_mode"`

	// DefaultProfile is the name sent in SanitizeHeader when no policy rule
	// applies.  Must match a profile advertised by Sluice's Health response.
	// Use "default" (reserved name) unless you know you've added others.
	DefaultProfile string `yaml:"default_profile"`

	// DefaultMode is the Mode sent when no policy rule applies.
	//   "ENFORCE"             — strip threats and return sanitized bytes
	//   "REPORT_ONLY"         — detect only, deliver original bytes
	//   "BYPASS_WITH_REPORT"  — VIP carve-out: report threats, deliver original
	// Default "ENFORCE".
	DefaultMode string `yaml:"default_mode"`

	// TimeoutSec bounds a single Sanitize call.  Sluice's internal cap is
	// 30s; we default to 35 so our context expires after and we surface a
	// meaningful error.  Must be ≥ 30.
	TimeoutSec int `yaml:"timeout_sec"`

	// MaxFileSizeMB rejects files above this size client-side before any
	// bytes hit the wire.  Must match Sluice's application-level cap.
	MaxFileSizeMB int `yaml:"max_file_size_mb"`

	// ChunkSizeKB is the streaming payload per gRPC message.  Lower values
	// help with backpressure visibility; higher values reduce syscall rate.
	ChunkSizeKB int `yaml:"chunk_size_kb"`

	// ServerFingerprint is the TOFU-pinned SHA-256 of Sluice's server cert,
	// printed by `sluice token` on Sluice's first boot and entered during
	// enrollment.  Format: hex string, optional "sha256:" prefix.  Once an
	// enrollment has happened, this field keeps the identity pinned so a
	// stolen client cert still can't be used against a rogue Sluice.
	ServerFingerprint string `yaml:"server_fingerprint"`

	// Paths populated by the enrollment flow (or pre-provisioned for HA/
	// DR). When CertsDir is set, Culvert expects files:
	//   <CertsDir>/ca.pem
	//   <CertsDir>/client.pem
	//   <CertsDir>/client.key
	CertsDir string `yaml:"certs_dir"`
}

// CDRFailOpen reports whether fail-open is configured.  Any value other
// than the explicit string "closed" is treated as open — prefer safety-of-
// availability by default, admins opt into fail-closed.
func (c CDRConfig) CDRFailOpen() bool {
	return !strings.EqualFold(strings.TrimSpace(c.FailMode), "closed")
}

func loadFileConfig(path string) (*FileConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f, yaml.DisallowUnknownField())
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
func (fc *FileConfig) validate() error { //nolint:cyclop // flat switch-style validation; each branch is trivial
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

	// log_level
	if l := fc.LogLevel; l != "" {
		upper := strings.ToUpper(l)
		if upper != "DEBUG" && upper != "INFO" && upper != "WARN" && upper != "WARNING" && upper != "ERROR" {
			errs = append(errs, fmt.Sprintf("log_level: must be DEBUG/INFO/WARN/ERROR, got %q", l))
		}
	}

	// syslog_format
	if f := fc.SyslogFormat; f != "" && f != "rfc3164" && f != "rfc5424" {
		errs = append(errs, fmt.Sprintf("syslog_format: must be \"rfc3164\" or \"rfc5424\", got %q", f))
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

	// cluster.role
	if r := fc.Cluster.Role; r != "" && r != "control-plane" {
		errs = append(errs, fmt.Sprintf("cluster.role: must be \"control-plane\" or empty, got %q", r))
	}
	if fc.Cluster.Role == "control-plane" && fc.Cluster.GRPCAddr == "" {
		errs = append(errs, "cluster.grpc_addr is required when cluster.role is \"control-plane\"")
	}
	// Validate cert/key/ca paths don't contain path traversal.
	for _, p := range []struct{ name, val string }{
		{"cluster.cert_file", fc.Cluster.CertFile},
		{"cluster.key_file", fc.Cluster.KeyFile},
		{"cluster.ca_file", fc.Cluster.CAFile},
	} {
		if p.val != "" && strings.Contains(p.val, "..") {
			errs = append(errs, fmt.Sprintf("%s: must not contain path traversal (..)", p.name))
		}
	}

	// CDR validation.
	if fc.CDR.Enabled {
		if fc.CDR.Endpoint == "" {
			errs = append(errs, "cdr.endpoint is required when cdr.enabled is true")
		}
		if fm := fc.CDR.FailMode; fm != "" && fm != "open" && fm != "closed" {
			errs = append(errs, fmt.Sprintf("cdr.fail_mode: must be \"open\" or \"closed\", got %q", fm))
		}
		if m := fc.CDR.DefaultMode; m != "" && m != "ENFORCE" && m != "REPORT_ONLY" && m != "BYPASS_WITH_REPORT" {
			errs = append(errs, fmt.Sprintf("cdr.default_mode: must be ENFORCE | REPORT_ONLY | BYPASS_WITH_REPORT, got %q", m))
		}
		if t := fc.CDR.TimeoutSec; t != 0 && t < 30 {
			errs = append(errs, fmt.Sprintf("cdr.timeout_sec: must be >= 30 (Sluice's own cap), got %d", t))
		}
		if s := fc.CDR.MaxFileSizeMB; s < 0 {
			errs = append(errs, fmt.Sprintf("cdr.max_file_size_mb: must be >= 0, got %d", s))
		}
		if s := fc.CDR.ChunkSizeKB; s != 0 && (s < 16 || s > 3072) {
			// 3072 KB = 3 MiB, a safe ceiling under the 4 MiB gRPC frame cap.
			errs = append(errs, fmt.Sprintf("cdr.chunk_size_kb: must be 16–3072, got %d", s))
		}
		if fp := strings.TrimSpace(fc.CDR.ServerFingerprint); fp != "" {
			fp = strings.TrimPrefix(fp, "sha256:")
			fp = strings.TrimPrefix(fp, "SHA256:")
			fp = strings.ReplaceAll(fp, ":", "")
			if len(fp) != 64 {
				errs = append(errs, fmt.Sprintf("cdr.server_fingerprint: expected 64 hex chars (SHA-256), got %d", len(fp)))
			}
		}
		if p := fc.CDR.CertsDir; p != "" && strings.Contains(p, "..") {
			errs = append(errs, "cdr.certs_dir: must not contain path traversal (..)")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
