package main

import (
	"strings"
	"testing"
)

func TestMCPGatewayDiagnostics(t *testing.T) {
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveDisabled})
	if rows := checkMCPGateway(); len(rows) != 0 {
		t.Fatalf("a node that never requested MCP must add no row, got %+v", rows)
	}

	const secretReason = "tls_cert_path=/etc/culvert/private/mcp.pem"
	withMCPStatus(t, mcpObserveActivation{State: mcpObserveInvalid, EnableRequested: true, Reason: secretReason})
	rows := checkMCPGateway()
	if len(rows) != 1 {
		t.Fatalf("faulted MCP must add exactly one row, got %d", len(rows))
	}
	r := rows[0]
	if r.Code != "mcp_gateway" || r.Status != diagWarn || r.OperatorAction == "" {
		t.Fatalf("unexpected row %+v", r)
	}
	if strings.Contains(r.Message, secretReason) || strings.Contains(r.OperatorAction, secretReason) {
		t.Fatalf("viewer-readable row must not carry the activation reason: %+v", r)
	}

	found := false
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "mcp_gateway" {
			found = true
		}
	}
	if !found {
		t.Fatal("mcp_gateway row missing from the assembled contract")
	}
}
