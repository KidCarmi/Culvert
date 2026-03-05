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

	// LogFormat controls the system-log output format: "text" (default) or "json".
	LogFormat string `yaml:"log_format"`
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
