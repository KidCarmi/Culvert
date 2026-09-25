package main

import (
	"fmt"
	"strings"
)

// auth_startup_config.go — resolved config for the auth startup
// slice (P4.4 / S1). Covers the caller-side mutation of the `cfg`
// singleton that `initAuth` performs at startup:
//   - cfg.ProxyPort + cfg.UIPort (unguarded exported fields)
//   - cfg.SetAuth (local bcrypt admin credentials)
//   - cfg.SetUIUsersFile + cfg.LoadUIUsersFile (persisted UI users)
//
// Out of scope (each owned elsewhere): LDAP / OIDC (legacy_auth_
// providers slice + IdP registry), SAML / OIDC-flow (runtime IdP
// registry in auth_idp.go), session (session_startup slice), MFA /
// TOTP (admin API), middleware routing, RBAC, and the `cfg`
// singleton's ownership / lock / surface.

// authStartupConfig carries the resolved inputs for initAuth.
// Value-type DTO; no methods.
type authStartupConfig struct {
	// ProxyPort is assigned to cfg.ProxyPort. Set pre-goroutine and
	// read by the admin UI config display path.
	ProxyPort int

	// UIPort is assigned to cfg.UIPort.
	UIPort int

	// AuthUser is the local bcrypt admin username — passed to
	// cfg.SetAuth. "" plus AuthPass "" clears local auth (matches
	// the pre-extraction behaviour and existing test cleanup
	// patterns in d0_helpers_test.go / pkce_ui2_test.go).
	AuthUser string

	// AuthPass is the plain admin password. bcrypt hashing runs
	// inside cfg.SetAuth — the slice never holds plaintext beyond
	// the immediate call.
	AuthPass string

	// UIUsersFile is the path to the persisted UI users JSON. ""
	// skips the SetUIUsersFile / LoadUIUsersFile pair entirely.
	UIUsersFile string
}

// resolveAuthStartupConfig is a trivial constructor: all five
// inputs are already-resolved scalars from startupState. Four come
// from loadFileConfigAndFlags' CLI/FileConfig precedence (s.pPort,
// s.uPort, s.authU, s.authP). The fifth is the CLI pointer deref
// (*s.uiUsersFile) — no FileConfig counterpart exists, so the
// resolver does not consult *FileConfig (pac convention).
//
// Pure; deterministic; safe on all-zero inputs.
//
// AuthUser is trimmed of leading/trailing whitespace before it is stored.
// Every other local-admin-credential entry point (apiSetupComplete's web
// setup wizard) already trims this exact field; this one — the CLI -user
// flag / config.yaml auth.user merge — did not, and a YAML literal block
// scalar (`user: |` instead of `user: admin`) always carries a trailing
// "\n" per the YAML spec, a common habit for a templated or copy-pasted
// value. Left untrimmed, the stored username becomes "admin\n" verbatim —
// permanently unusable, since nothing typed at a login prompt can produce a
// trailing newline — with no error at startup and no indication of the
// cause. AuthPass is deliberately NOT trimmed: unlike a username, a
// password may legitimately contain leading/trailing whitespace.
func resolveAuthStartupConfig(proxyPort, uiPort int, authUser, authPass, uiUsersFile string) authStartupConfig {
	return authStartupConfig{
		ProxyPort:   proxyPort,
		UIPort:      uiPort,
		AuthUser:    strings.TrimSpace(authUser),
		AuthPass:    authPass,
		UIUsersFile: uiUsersFile,
	}
}

// validateAuthStartupCredentials enforces the same password-complexity
// floor (validatePasswordComplexity) that every other local-admin-credential
// entry point already applies — the web setup wizard (apiSetupComplete), the
// admin config-auth API handler, and --reset-password (via SetUIUser). The
// CLI -user/-pass flags and YAML auth.user/auth.pass keys resolve into this
// authStartupConfig and previously reached cfg.SetAuth with no such gate.
//
// An empty AuthUser is the "clear/unconfigured" case (loadAuth passes it
// straight to cfg.SetAuth to disable local auth) ONLY when AuthPass is ALSO
// empty. A non-empty AuthPass paired with an empty AuthUser is never that
// case: since resolveAuthStartupConfig trims AuthUser, it happens when a
// real -user/auth.user value collapses to "" after trimming (e.g. a
// deployment wrapper's -user "$ADMIN_USER" with $ADMIN_USER rendering to
// pure whitespace) while a real password was still supplied. Silently
// exempting that would reach cfg.SetAuth("", pass), which DISABLES local
// authentication entirely and discards the configured password — a fail-open
// admin UI with no error pointing at the cause (Codex review, PR #1443).
// Reject it instead, the same as any other invalid startup credential.
//
// Pure; deterministic.
func validateAuthStartupCredentials(auth authStartupConfig) error {
	if auth.AuthUser == "" {
		if auth.AuthPass != "" {
			return fmt.Errorf("a password was supplied (-pass / auth.pass) but the resolved admin username is empty — a whitespace-only -user/auth.user value trims to \"\", and silently disabling local authentication here would discard the configured password; set a non-blank username, or remove the password to genuinely leave auth unconfigured")
		}
		return nil
	}
	return validatePasswordComplexity(auth.AuthPass)
}
