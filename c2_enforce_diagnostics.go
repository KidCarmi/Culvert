package main

import "fmt"

// adminRouteEnforcementCode is the operator-contract code of the row below.
const adminRouteEnforcementCode = "admin_route_enforcement_shadow"

// checkAdminRouteEnforcement makes the CULVERT_C2_ENFORCE break-glass visible on
// the operator contract. Setting it to a false-ish value puts the admin-route
// metadata gate (C2) in shadow: requests the route table would refuse are only
// logged and counted. Until now the only places an operator could discover that
// were the startup environment and the admin-only Governance page — whose
// governance_health still reads "healthy" in shadow — so a node left in
// break-glass after an incident looked identical to a healthy one on the
// Diagnostics report. Report-only: it reads the already-resolved, read-once mode
// and the existing would-deny counter, and changes neither. Handler-level
// requireRole checks keep enforcing in both modes. Contributes NO row in the
// default enforce mode, so a normal appliance's report is unchanged.
func checkAdminRouteEnforcement() []OperatorContractCheck {
	if c2Mode() != c2ModeShadow {
		return nil
	}
	wouldDeny := c2CounterSnapshot().WouldDeny
	return []OperatorContractCheck{{
		Code:   adminRouteEnforcementCode,
		Status: diagWarn,
		Message: fmt.Sprintf("admin-route authorization metadata is in SHADOW mode (break-glass, %s is false) — the route-level "+
			"role gate logs but does not block; each admin handler's own role check still applies. %d request(s) the route "+
			"gate would have refused were let through to that handler check since startup", c2EnforceEnvVar, wouldDeny),
		OperatorAction: "Break-glass is meant to be temporary. Remove " + c2EnforceEnvVar + " from the proxy environment (or set it to " +
			"true) and restart the node: the setting is read once at startup and cannot be changed from the GUI. Administrators can " +
			"review the would-deny counter on the Governance page before and after the change.",
	}}
}
