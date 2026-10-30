package main

// checkAuthExemptKillSwitch surfaces the Auth Exempt break-glass kill switch on
// the operator contract. The switch (env CULVERT_AUTHBYPASS_DISABLE or the
// runtime toggle) was visible only inside the Auth Policy panel, so an admin
// who engaged it during an incident and navigated away had no signal anywhere
// else — in Support bundles, the diagnostics report or the dashboard roll-up —
// that every Exempt rule was being ignored. Report-only: reads the same
// accessors the enforcement path already uses and changes no decision.
//
// Contributes nothing while the switch is clear, like the other auth_exempt_*
// rows, so a healthy appliance's report is unchanged.
//
// The backend state mirrors the Stage-1 gate's backend term in
// resolveRequestAuth (credCapable || ssoCapable) and then separates what is
// actually loaded:
//   - ssoCapable (HasEnabledInteractiveProvider) is a LIVE predicate;
//   - credCapable (hasCredentialCapableProvider) is NOT: it counts an enabled
//     OIDC/LDAP profile even when it failed to compile and has no live
//     provider (it is read on every request and deliberately skips the live
//     map). The gate still challenges then, but nothing loaded can validate
//     the credential, so the row reports that state on its own.
//
// Without any backend the no-credential Default arm is inert and falls
// through to Stage 2 (TestKillSwitchNoBackend_NoRule_InertStage2), so the row
// must not claim formerly exempt clients are now authenticated.
//
// SEC-AUTHENABLED-1 added a FOURTH state that neither of the two probes above
// can see. A roster holding admitted accounts with no present admin and no
// provider — the clamped or legacy-role state — leaves credCapable and
// ssoCapable both false, but resolveRequestAuth's rosterWithoutVerifier term
// arms the Stage-1 gate anyway and is excluded from the no-backend inert
// guard, so the forced-Default arm answers with a 407 nothing can satisfy.
// Reporting killSwitchBackendNone there told the operator the opposite of what
// the gateway does, and named the wrong repair: the roster is a lockout for the
// --reset-password break-glass, not a failed IdP profile.
type killSwitchBackend int

const (
	killSwitchBackendNone      killSwitchBackend = iota // gate sees no backend: Stage 2 decides
	killSwitchBackendNotLoaded                          // gate sees an enabled credential profile, but none is loaded
	killSwitchBackendLive                               // a loaded validator or live SSO provider exists
	// killSwitchBackendNoVerifier is the SEC-AUTHENABLED-1 state: the roster
	// holds accounts, so the gate is armed, but nothing can verify a presented
	// credential. Every formerly exempt request is refused, not fallen through.
	killSwitchBackendNoVerifier
)

func checkAuthExemptKillSwitch() []OperatorContractCheck {
	return authExemptKillSwitchRows(authBypassDisabled(), authExemptDisabledRuntimeState(), currentKillSwitchBackend())
}

func currentKillSwitchBackend() killSwitchBackend {
	sso := idpRegistry.HasEnabledInteractiveProvider()
	if !hasCredentialCapableProvider() && !sso {
		// cfg.AuthEnabled() is the exact discriminator resolveRequestAuth uses
		// for rosterWithoutVerifier, read here only as a boolean: with neither
		// a credential-capable validator nor a live interactive provider, an
		// active authentication backend can only be an admitted roster account,
		// and that arms the gate rather than leaving it inert.
		if cfg != nil && cfg.AuthEnabled() {
			return killSwitchBackendNoVerifier
		}
		return killSwitchBackendNone
	}
	liveCred := cfg != nil && (cfg.GetUser() != "" || cfg.ProviderEnabled())
	if !liveCred && idpRegistry != nil {
		liveCred = len(idpRegistry.EnabledCredentialProviders()) > 0
	}
	if liveCred || sso {
		return killSwitchBackendLive
	}
	return killSwitchBackendNotLoaded
}

func authExemptKillSwitchRows(envDisabled, runtimeDisabled bool, backend killSwitchBackend) []OperatorContractCheck {
	if !envDisabled && !runtimeDisabled {
		return nil
	}
	// The runtime layer is an in-memory toggle (not persisted), so it reverts
	// on restart; the env layer is read once at startup and survives it.
	layer := "runtime toggle, reverts on restart"
	action := "Return to normal operation from Auth Policy → Kill switch (clear the toggle) once the incident is resolved, then confirm formerly exempt clients are exempt again. The runtime toggle is not persisted: a restart also clears it, so re-engage it after a restart if the incident is still ongoing."
	switch {
	case envDisabled && runtimeDisabled:
		layer = "environment variable CULVERT_AUTHBYPASS_DISABLE and runtime toggle"
		action = "Clear the runtime toggle in Auth Policy → Kill switch, then unset CULVERT_AUTHBYPASS_DISABLE and restart: the environment layer is read once at startup and cannot be cleared from the GUI (the runtime toggle reverts on restart on its own)."
	case envDisabled:
		layer = "environment variable CULVERT_AUTHBYPASS_DISABLE"
		action = "Unset CULVERT_AUTHBYPASS_DISABLE and restart the node: the environment layer is read once at startup and cannot be cleared from the GUI."
	}
	effect := "so clients that were exempt from authentication must now authenticate"
	if backend == killSwitchBackendNotLoaded {
		effect = "so formerly exempt clients are now challenged for credentials, but no loaded provider can validate them: an enabled credential (OIDC/LDAP) profile is configured but failed to load"
		action = "Fix or re-enable the failed profile under Identity Providers (the startup log names the error) so challenged clients can authenticate. " + action
	}
	if backend == killSwitchBackendNoVerifier {
		// SEC-AUTHENABLED-1: the gate IS armed here, so this is the opposite of
		// the killSwitchBackendNone row below — nothing falls through to Stage 2.
		// Stated as a refusal rather than a challenge, because that is what the
		// client observes: the 407 is real but unsatisfiable.
		effect = "so formerly exempt clients are now challenged for credentials (407) that nothing on this node can verify: the administrator roster holds accounts but no usable administrator account, and no identity provider is enabled, so every formerly exempt request is refused"
		action = "Restore an administrator account with the --reset-password break-glass before clearing the kill switch — the roster holds accounts whose effective role is not administrator (a restored backup from a newer build, or a pre-RBAC roster), so no presented credential can be verified and proxy traffic is refused whether the kill switch is engaged or not. " + action
	}
	if backend == killSwitchBackendNone {
		// Deliberately not an enumeration of per-rule outcomes: without a
		// backend the result depends on the global default, the rule order
		// and whether the client presented Proxy-Authorization (which turns
		// the Stage-1 outcome into Default), so a list here is either
		// incomplete or wrong. The row states only what holds in every case.
		// It does not point at the Policy Tester: its stage2Reached flag
		// assumes a backend for the Default outcome, so on this node it would
		// contradict the runtime fall-through to Stage 2.
		effect = "but no credential or SSO provider is usable on this node (none is enabled, or an SSO profile failed to load), so this does not make formerly exempt clients authenticate: their requests are decided by the remaining authentication rules and Stage 2 policy"
	}
	return []OperatorContractCheck{{
		Code:           "auth_exempt_kill_switch",
		Status:         diagWarn,
		Message:        "Auth Exempt kill switch is ENGAGED (" + layer + "): every Exempt rule and the Exempt default are ignored, " + effect,
		OperatorAction: action,
	}}
}
