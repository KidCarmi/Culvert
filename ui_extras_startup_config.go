package main

// ui_extras_startup_config.go — resolved config for the admin-UI TLS-SAN
// and trust-forwarded-headers slice (PR3 expansion, Batch 1).

import "strings"

// uiExtrasStartupConfig carries the resolved extras that feed
// selfSignedTLS() and request header handling.
type uiExtrasStartupConfig struct {
	// ExtraSANs is the merged list of additional TLS SANs for the
	// self-signed admin-UI cert (CLI --ui-san + fc.Proxy.UISANs).
	ExtraSANs []string
	// TrustForwardedHeaders is the disjunction of the CLI flag and the
	// FileConfig toggle; true enables X-Forwarded-* parsing for the
	// reverse-proxy deployment case.
	TrustForwardedHeaders bool
}

// resolveUIExtrasStartupConfig is the single startup-time reader of
// fc.Proxy.UISANs and fc.Proxy.TrustForwardedHeaders.
// uiSANsFlag is the dereferenced --ui-san CLI value (comma-separated);
// trustFwdFlag is the dereferenced --trust-forwarded-headers CLI value.
func resolveUIExtrasStartupConfig(fc *FileConfig, uiSANsFlag string, trustFwdFlag bool) uiExtrasStartupConfig {
	var sans []string
	if uiSANsFlag != "" {
		for _, san := range strings.Split(uiSANsFlag, ",") {
			if san = strings.TrimSpace(san); san != "" {
				sans = append(sans, san)
			}
		}
	}
	sans = append(sans, fc.Proxy.UISANs...)
	return uiExtrasStartupConfig{
		ExtraSANs:             sans,
		TrustForwardedHeaders: trustFwdFlag || fc.Proxy.TrustForwardedHeaders,
	}
}
