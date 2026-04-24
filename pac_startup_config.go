package main

// pac_startup_config.go — resolved config for the PAC slice (PR3
// expansion, Batch 3): JSON config path + the proxy listener port that
// /proxy.pac embeds in its "PROXY host:port" directive.

// pacStartupConfig carries the resolved PAC configuration. Value-type
// DTO; no methods.
type pacStartupConfig struct {
	// ConfigPath is the JSON file that persists PAC rules (host → proxy
	// mappings and exclusion patterns). Currently hard-coded relative
	// to cwd as "pac_config.json"; the field exists so the loader is
	// testable without a fixed filename.
	ConfigPath string
	// DefaultProxyPort is the proxy listener's *effective* port after
	// flag/file-config resolution. /proxy.pac auto-generates a PROXY
	// directive pointing at this port when no explicit host:port is
	// configured for a PAC rule.
	DefaultProxyPort int
}

// resolvePACStartupConfig is the single startup-time reader of the PAC
// inputs. proxyPort is the already-resolved proxy listener port (from
// startupState.pPort) — the resolver stays independent of startupState.
func resolvePACStartupConfig(proxyPort int) pacStartupConfig {
	return pacStartupConfig{
		ConfigPath:       "pac_config.json",
		DefaultProxyPort: proxyPort,
	}
}
