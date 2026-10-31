package main

// authExemptKillSwitchContractRows surfaces the Auth Exempt break-glass kill switch on
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
//
// That fourth state is admin-roster posture, and the operator contract is
// viewer-readable (SEC-DIAG-ROSTER-1). The clamp leaves the restored accounts
// able to sign in at RoleViewer, so they could otherwise read that their own
// roster holds no administrator. Below admin, redactContractForRole swaps in
// authExemptKillSwitchViewerRow, which keeps the engaged layer and the traffic
// impact and withholds the cause and the remediation.
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

// authExemptKillSwitchCode is the operator-contract code of the kill-switch
// row. Named so redactContractForRole and the row cannot drift apart on a
// string literal.
const authExemptKillSwitchCode = "auth_exempt_kill_switch"

// authExemptKillSwitchNoVerifierViewerEffect is the below-admin form of the
// killSwitchBackendNoVerifier effect clause (SEC-KSROSTER-1). It is a CONSTANT:
// it keeps the traffic impact a viewer or operator needs in order to escalate
// (formerly exempt clients are challenged and refused) and withholds the
// cause, which is admin-roster posture — that the roster holds accounts but no
// usable administrator, and the effective role those accounts carry.
const authExemptKillSwitchNoVerifierViewerEffect = "so formerly exempt clients are now challenged " +
	"for credentials and their requests are refused; the cause and the remediation are shown to " +
	"administrators only"

// authExemptKillSwitchContractRows renders the engaged row twice from ONE read
// of the backend: the admin row that goes into the contract, and the
// below-admin rendering redactContractForRole swaps in. One read for the same
// reason as accessCIDRListsRows: two reads could straddle a roster change and
// describe different states to different roles. The caller has already read
// the switch layers and calls this only while at least one is engaged.
func authExemptKillSwitchContractRows(envDisabled, runtimeDisabled bool) (admin, viewer OperatorContractCheck) {
	backend := currentKillSwitchBackend()
	return authExemptKillSwitchRow(envDisabled, runtimeDisabled, backend),
		authExemptKillSwitchViewerRow(envDisabled, runtimeDisabled, backend)
}

// currentKillSwitchBackend classifies the gate's backend for the row.
//
// Its result is ADMIN-ONLY in one state: killSwitchBackendNoVerifier encodes
// that the roster holds admitted accounts but no usable administrator, which
// is roster posture (SEC-DIAG-ROSTER-1). A contract row must therefore render
// it through authExemptKillSwitchContractRows, whose below-admin rendering
// withholds it; the operator-contract roster wall enforces that.
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

// authExemptKillSwitchRows is the admin rendering as the contract carries it:
// nothing while the switch is clear, one row while either layer is engaged.
func authExemptKillSwitchRows(envDisabled, runtimeDisabled bool, backend killSwitchBackend) []OperatorContractCheck {
	if !envDisabled && !runtimeDisabled {
		return nil
	}
	return []OperatorContractCheck{authExemptKillSwitchRow(envDisabled, runtimeDisabled, backend)}
}

// killSwitchLayer names the engaged layer(s) and the remediation that clears
// them. Neither names roster state, so both renderings carry the layer.
func killSwitchLayer(envDisabled, runtimeDisabled bool) (layer, action string) {
	// The runtime layer is an in-memory toggle (not persisted), so it reverts
	// on restart; the env layer is read once at startup and survives it.
	switch {
	case envDisabled && runtimeDisabled:
		return "environment variable CULVERT_AUTHBYPASS_DISABLE and runtime toggle",
			"Clear the runtime toggle in Auth Policy → Kill switch, then unset CULVERT_AUTHBYPASS_DISABLE and restart: the environment layer is read once at startup and cannot be cleared from the GUI (the runtime toggle reverts on restart on its own)."
	case envDisabled:
		return "environment variable CULVERT_AUTHBYPASS_DISABLE",
			"Unset CULVERT_AUTHBYPASS_DISABLE and restart the node: the environment layer is read once at startup and cannot be cleared from the GUI."
	}
	return "runtime toggle, reverts on restart",
		"Return to normal operation from Auth Policy → Kill switch (clear the toggle) once the incident is resolved, then confirm formerly exempt clients are exempt again. The runtime toggle is not persisted: a restart also clears it, so re-engage it after a restart if the incident is still ongoing."
}

// authExemptKillSwitchMessage is the row message for an engaged layer.
func authExemptKillSwitchMessage(layer, effect string) string {
	return "Auth Exempt kill switch is ENGAGED (" + layer + "): every Exempt rule and the Exempt default are ignored, " + effect
}

// authExemptKillSwitchRow is the ADMIN row for an engaged switch. Callers
// guarantee at least one layer is engaged.
func authExemptKillSwitchRow(envDisabled, runtimeDisabled bool, backend killSwitchBackend) OperatorContractCheck {
	layer, action := killSwitchLayer(envDisabled, runtimeDisabled)
	effect := "so clients that were exempt from authentication must now authenticate"
	switch backend {
	case killSwitchBackendNotLoaded:
		effect = "so formerly exempt clients are now challenged for credentials, but no loaded provider can validate them: an enabled credential (OIDC/LDAP) profile is configured but failed to load"
		action = "Fix or re-enable the failed profile under Identity Providers (the startup log names the error) so challenged clients can authenticate. " + action
	case killSwitchBackendNoVerifier:
		// SEC-AUTHENABLED-1: the gate IS armed here, so this is the opposite of
		// the killSwitchBackendNone row below — nothing falls through to Stage 2.
		// Stated as a refusal rather than a challenge, because that is what the
		// client observes: the 407 is real but unsatisfiable.
		//
		// Only AUTH-REQUIRED traffic stays refused once the switch is cleared:
		// resolveRequestAuth leaves Exempt outcomes untouched in this state
		// (TestAuthEnabled_HTTPProxyExemptStillExempt), so credential-free
		// requests an Exempt rule or the Exempt default covers resume when the
		// switch clears (TestKillSwitchBackend_NoVerifierClearedSwitchResumesExempt).
		effect = "so formerly exempt clients are now challenged for credentials (407) that nothing on this node can verify: the administrator roster holds accounts but no usable administrator account, and no identity provider is enabled, so every formerly exempt request is refused"
		action = "Restore an administrator account with the --reset-password break-glass: the roster holds accounts whose effective role is not administrator (a restored backup from a newer build, or a pre-RBAC roster), so no presented credential can be verified, and traffic that requires authentication stays refused until an administrator account exists, whether the kill switch is engaged or not. Clearing the kill switch alone restores only credential-free requests covered by an Exempt rule or the Exempt default. " + action
	case killSwitchBackendNone:
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
	return OperatorContractCheck{
		Code:           authExemptKillSwitchCode,
		Status:         diagWarn,
		Message:        authExemptKillSwitchMessage(layer, effect),
		OperatorAction: action,
	}
}

// authExemptKillSwitchViewerRow is the below-admin rendering. Only the
// no-verifier state differs from the admin row: the other three states carry
// provider facts and the switch layer, already reviewed as safe below admin.
// The status is warn in every state, so the verdict needs no recomputation.
func authExemptKillSwitchViewerRow(envDisabled, runtimeDisabled bool, backend killSwitchBackend) OperatorContractCheck {
	if backend != killSwitchBackendNoVerifier {
		return authExemptKillSwitchRow(envDisabled, runtimeDisabled, backend)
	}
	layer, _ := killSwitchLayer(envDisabled, runtimeDisabled)
	return OperatorContractCheck{
		Code:           authExemptKillSwitchCode,
		Status:         diagWarn,
		Message:        authExemptKillSwitchMessage(layer, authExemptKillSwitchNoVerifierViewerEffect),
		OperatorAction: diagnosticsRedactedAction,
	}
}
