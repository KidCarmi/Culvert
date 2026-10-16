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
// authBackend mirrors the Stage-1 gate's backend term in resolveRequestAuth
// (credCapable || ssoCapable). Without a backend the no-credential Default arm
// is inert and falls through to Stage 2 (TestKillSwitchNoBackend_NoRule_InertStage2),
// so the row must not claim formerly exempt clients are now authenticated.
func checkAuthExemptKillSwitch() []OperatorContractCheck {
	authBackend := hasCredentialCapableProvider() || idpRegistry.HasEnabledInteractiveProvider()
	return authExemptKillSwitchRows(authBypassDisabled(), authExemptDisabledRuntimeState(), authBackend)
}

func authExemptKillSwitchRows(envDisabled, runtimeDisabled, authBackend bool) []OperatorContractCheck {
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
	if !authBackend {
		effect = "but no credential or SSO backend is configured, so formerly exempt clients are not challenged: Credential Required rules still return 407 and Stage 2 policy decides every other request"
	}
	return []OperatorContractCheck{{
		Code:           "auth_exempt_kill_switch",
		Status:         diagWarn,
		Message:        "Auth Exempt kill switch is ENGAGED (" + layer + "): every Exempt rule and the Exempt default are ignored, " + effect,
		OperatorAction: action,
	}}
}
