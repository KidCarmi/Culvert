package main

// ui_access_policy_startup_config.go — resolved config for the admin-UI
// access-policy slice (PR3 expansion, Batch 2): IP allowlist + external
// base URL + generic IdP profile registry.

// uiAccessPolicyStartupConfig carries the resolved UI access policy.
// Value-type DTO; no methods.
type uiAccessPolicyStartupConfig struct {
	// AllowIPCLI is the dereferenced --ui-allow-ip CLI value (comma-
	// separated list); empty when the flag is unset.
	AllowIPCLI string
	// AllowList is fc.UIAllowIPs (additional entries from file config
	// that are merged with AllowIPCLI).
	AllowList []string
	// BaseURL is fc.Proxy.BaseURL, the externally-visible URL used for
	// OIDC/SAML callback construction.
	BaseURL string
	// IdPProfilesFile is the generic-IdP registry JSON path: the
	// -idp-profiles-file CLI value when set, else fc.Proxy.IdPProfilesFile.
	// Empty ⇒ registry is in-memory only (profiles lost on restart).
	IdPProfilesFile string
	// HasOIDCOrSAML is true when any OIDC/SAML configuration is present
	// (legacy introspection URL OR generic IdP registry file). Used
	// only to emit the "WARNING: base_url not set" advisory.
	HasOIDCOrSAML bool
}

// resolveUIAccessPolicyStartupConfig is the single startup-time reader of
// fc.UIAllowIPs and fc.Proxy.BaseURL + fc.Proxy.IdPProfilesFile for the
// UI access-policy slice. uiAllowIPCLI is the dereferenced --ui-allow-ip
// CLI value; idpProfilesFileCLI is the dereferenced -idp-profiles-file CLI
// value and takes precedence over fc.Proxy.IdPProfilesFile when non-empty.
// The resolver ALSO observes fc.OIDC.IntrospectionURL and the resolved IdP
// path to precompute HasOIDCOrSAML, but those fields remain primarily owned
// by legacy-auth-providers / UI-access (respectively).
func resolveUIAccessPolicyStartupConfig(fc *FileConfig, uiAllowIPCLI, idpProfilesFileCLI string) uiAccessPolicyStartupConfig {
	idpFile := fc.Proxy.IdPProfilesFile
	if idpProfilesFileCLI != "" {
		idpFile = idpProfilesFileCLI
	}
	return uiAccessPolicyStartupConfig{
		AllowIPCLI:      uiAllowIPCLI,
		AllowList:       fc.UIAllowIPs,
		BaseURL:         fc.Proxy.BaseURL,
		IdPProfilesFile: idpFile,
		HasOIDCOrSAML:   fc.OIDC.IntrospectionURL != "" || idpFile != "",
	}
}
