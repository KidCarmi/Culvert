package main

// diagnostics_mcp_gateway.go — operator-contract row for a faulted MCP gateway.
//
// An MCP gateway that was enabled but did not start (invalid configuration or
// TLS material), or that stopped or degraded afterwards, is reported on
// /readyz, /healthz, /metrics and by the mcp_gateway_unhealthy alert
// (mcp_health_plane.go). The one-page diagnostics report, where an operator
// checks "is this node healthy", did not carry it: an administrator who enabled
// MCP and saw nothing listening had to scrape /readyz or read the logs.
//
// Report-only: derived from the same mcpHealthState snapshot the other surfaces
// use, no I/O, no change to MCP startup or readiness. Contributes nothing when
// MCP was never requested, is starting, draining or serving. The row is
// readable by the viewer role, so the message is a fixed string — the
// activation reason can name a configuration fault and stays on the MCP panels.

// checkMCPGateway returns zero or one row for a faulted MCP gateway.
func checkMCPGateway() []OperatorContractCheck {
	snap := mcpHealthState()
	if !snap.Faulted() {
		return nil
	}
	msg := "MCP gateway is not accepting requests"
	if snap.State == mcpCapInvalid {
		msg = "MCP gateway was enabled but did not start"
	}
	return []OperatorContractCheck{{
		Code:           "mcp_gateway",
		Status:         diagWarn,
		Message:        msg + " — MCP clients cannot reach this node; web proxying is unaffected",
		OperatorAction: "MCP Gateway → Overview shows the capability state and the activation reason. Correct the MCP configuration, then restart Culvert if the panel reports a startup failure.",
	}}
}
