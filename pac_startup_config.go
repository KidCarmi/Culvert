package main

// pac_startup_config.go — resolved config for the PAC slice (PR3
// expansion, Batch 3): JSON config path + the proxy listener port that
// /proxy.pac embeds in its "PROXY host:port" directive.

import "path/filepath"

// pacStartupConfig carries the resolved PAC configuration. Value-type
// DTO; no methods.
type pacStartupConfig struct {
	// ConfigPath is the authoritative JSON file that persists PAC rules
	// (host → proxy mappings and exclusion patterns): <dataDir>/pac_config.json,
	// so PAC config participates in the /data backup surface.
	ConfigPath string
	// LegacyConfigPath is the pre-migration CWD-relative location
	// ("pac_config.json"). When ConfigPath does not exist yet but this file
	// does, the loader one-way migrates it (the legacy file is left in place,
	// frozen — a downgraded binary reads it stale).
	LegacyConfigPath string
	// ProfilesPath is the JSON file persisting PAC steering profiles and
	// proxy pools (<dataDir>/pac_profiles.json, initiative PR 2).
	ProfilesPath string
	// LifecyclePath is the JSON file persisting per-profile draft/revision
	// lifecycle metadata (<dataDir>/pac_profiles_lifecycle.json, PR 3).
	// Node-local operator history (not cluster-synced).
	LifecyclePath string
	// ExceptionsPath is the JSON file persisting per-profile DIRECT-exception
	// governance metadata (<dataDir>/pac_exceptions.json, PAC Exception
	// Intelligence P2). Node-local operator metadata (not cluster-synced).
	ExceptionsPath string
	// DefaultProxyPort is the proxy listener's *effective* port after
	// flag/file-config resolution. /proxy.pac auto-generates a PROXY
	// directive pointing at this port when no explicit host:port is
	// configured for a PAC rule.
	DefaultProxyPort int
}

// resolvePACStartupConfig is the single startup-time reader of the PAC
// inputs. dir is the resolved data directory (main's dataDir); proxyPort is
// the already-resolved proxy listener port (from startupState.pPort) — the
// resolver stays independent of startupState.
func resolvePACStartupConfig(dir string, proxyPort int) pacStartupConfig {
	return pacStartupConfig{
		ConfigPath:       filepath.Join(dir, "pac_config.json"),
		LegacyConfigPath: "pac_config.json",
		ProfilesPath:     filepath.Join(dir, "pac_profiles.json"),
		LifecyclePath:    filepath.Join(dir, "pac_profiles_lifecycle.json"),
		ExceptionsPath:   filepath.Join(dir, "pac_exceptions.json"),
		DefaultProxyPort: proxyPort,
	}
}
