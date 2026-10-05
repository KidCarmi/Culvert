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
func checkAuthExemptKillSwitch() []OperatorContractCheck {
	return authExemptKillSwitchRows(authBypassDisabled(), authExemptDisabledRuntimeState())
}

func authExemptKillSwitchRows(envDisabled, runtimeDisabled bool) []OperatorContractCheck {
	if !envDisabled && !runtimeDisabled {
		return nil
	}
	layer := "runtime toggle"
	action := "Return to normal operation from Auth Policy → Kill switch (clear the toggle) once the incident is resolved, then confirm exempt clients stop receiving 407."
	switch {
	case envDisabled && runtimeDisabled:
		layer = "environment variable CULVERT_AUTHBYPASS_DISABLE and runtime toggle"
		action = "Clear the runtime toggle in Auth Policy → Kill switch, then unset CULVERT_AUTHBYPASS_DISABLE and restart: the environment layer is read once at startup and cannot be cleared from the GUI."
	case envDisabled:
		layer = "environment variable CULVERT_AUTHBYPASS_DISABLE"
		action = "Unset CULVERT_AUTHBYPASS_DISABLE and restart the node: the environment layer is read once at startup and cannot be cleared from the GUI."
	}
	return []OperatorContractCheck{{
		Code:           "auth_exempt_kill_switch",
		Status:         diagWarn,
		Message:        "Auth Exempt kill switch is ENGAGED (" + layer + "): every Exempt rule and the Exempt default are ignored, so clients that were exempt from authentication must now authenticate",
		OperatorAction: action,
	}}
}
