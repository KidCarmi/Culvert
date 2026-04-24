package main

// ui_access_policy_startup.go — startup-time loader for the admin-UI
// access-policy slice (PR3 expansion, Batch 2): merges the --ui-allow-ip
// CLI value with fc.UIAllowIPs and applies it via SetUIAllowedCIDRs,
// wires the external base URL (with an OIDC/SAML-aware warning when
// unset), and loads the generic IdP profiles registry.

import (
	"fmt"
	"strings"
)

// loadUIAccessPolicy applies cfg. Returns an error only for the
// IdP-profiles load path — the shim log.Fatalf's it verbatim to match
// the pre-pilot "IdP profiles load error:" message. Allowlist-parse
// failures are logged and do NOT fail startup, preserving original
// behaviour.
func loadUIAccessPolicy(cfg uiAccessPolicyStartupConfig) error {
	allowList := cfg.AllowList
	if cfg.AllowIPCLI != "" {
		for _, cidr := range strings.Split(cfg.AllowIPCLI, ",") {
			allowList = append(allowList, strings.TrimSpace(cidr))
		}
	}
	if len(allowList) > 0 {
		if err := SetUIAllowedCIDRs(allowList); err != nil {
			logger.Printf("UIGuard: invalid IP/CIDR (%v) — allowing all IPs", err)
		} else {
			logger.Printf("UIGuard: admin panel restricted to %v", allowList)
		}
	}

	if cfg.BaseURL != "" {
		SetProxyBaseURL(cfg.BaseURL)
		logger.Printf("BaseURL: %s", cfg.BaseURL)
	} else if cfg.HasOIDCOrSAML {
		logger.Printf("WARNING: base_url not set — OIDC/SAML callbacks will use request Host header. Set proxy.base_url in config for reliable IdP redirects.")
	}

	if cfg.IdPProfilesFile != "" {
		if err := idpRegistry.Load(cfg.IdPProfilesFile); err != nil {
			return fmt.Errorf("IdP profiles load error: %w", err)
		}
		logger.Printf("IdP: loaded from %s (%d profiles)", cfg.IdPProfilesFile, len(idpRegistry.All()))
	}
	return nil
}
