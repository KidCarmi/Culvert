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

	// RISK-019 trusted-proxy set: merge --trusted-proxy-cidrs with
	// fc.Proxy.TrustedProxyCIDRs. Invalid entries are logged and leave the set
	// empty (fail-safe: X-Forwarded-For stays untrusted, admin-UI per-IP logic
	// keys on the direct peer).
	trustedProxies := cfg.TrustedProxyList
	if cfg.TrustedProxyCLI != "" {
		for _, cidr := range strings.Split(cfg.TrustedProxyCLI, ",") {
			trustedProxies = append(trustedProxies, strings.TrimSpace(cidr))
		}
	}
	if len(trustedProxies) > 0 {
		if err := SetTrustedProxyCIDRs(trustedProxies); err != nil {
			logger.Printf("TrustedProxy: invalid IP/CIDR (%v) — X-Forwarded-For will NOT be trusted", err)
		} else {
			logger.Printf("TrustedProxy: admin-UI client-IP trusts X-Forwarded-For from %v", ListTrustedProxyCIDRs())
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
		// CHAOS-66: Load reports a compile failure with one log line and
		// leaves the profile enabled-but-not-live, which before this was
		// PERMANENT for the process lifetime — an IdP that was briefly
		// unreachable at boot (ordinary on a host reboot, where the container
		// and the network come up concurrently) stayed dark until somebody
		// restarted the appliance or re-saved the profile. The loop exits
		// immediately when every enabled profile compiled, so a healthy boot
		// costs one goroutine that returns at once.
		// Keyed on the loop's OWN predicate (every enabled profile with no
		// live provider, LDAP included), not on the interactive-only counts
		// the contract row reports — a start condition narrower than what the
		// loop recovers would leave a dark profile with no way back.
		if len(idpRegistry.darkEnabledProfiles()) > 0 {
			go runIdPRecoveryLoop(resolveLifecycleCtx())
		}
	}
	return nil
}
