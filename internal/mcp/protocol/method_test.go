package protocol

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func TestAdmittedSetIsExactlySix(t *testing.T) {
	want := map[string]bool{
		"initialize": true, "notifications/initialized": true, "ping": true,
		"notifications/cancelled": true, "tools/list": true, "tools/call": true,
	}
	got := AdmittedMethods()
	if len(got) != len(want) {
		t.Fatalf("admitted count = %d, want %d (%v)", len(got), len(want), got)
	}
	for _, m := range got {
		if !want[m] {
			t.Fatalf("unexpected admitted method %q", m)
		}
	}
}

func TestUnsupportedFamiliesRejected(t *testing.T) {
	rejects := []string{
		"resources/read", "resources/list", "resources/templates/list", "resources/subscribe",
		"prompts/list", "prompts/get", "completion/complete",
		"sampling/createMessage", "elicitation/create", "roots/list",
		"tasks/cancel", "tasks/create", "tasks/list", "tasks/get", "tasks/result",
		"logging/setLevel", "notifications/tools/list_changed", "notifications/resources/list_changed",
		"", "TOOLS/CALL", "tools/call ", "unknown", "allow_unknown_methods",
	}
	for _, m := range rejects {
		adm := Admit(Gateway, ClientOriginated, jsonrpc.ClassRequest, m)
		if adm.Handling != HandlingRejected || adm.Reason != mcperr.ReasonUnsupportedMethod {
			t.Fatalf("method %q should be rejected as unsupported, got handling=%v reason=%v", m, adm.Handling, adm.Reason)
		}
	}
}

func TestAdmittedHandling(t *testing.T) {
	terminal := []string{"initialize", "notifications/initialized", "ping", "notifications/cancelled"}
	for _, m := range terminal {
		if adm := Admit(Gateway, ClientOriginated, classFor(m), m); adm.Handling != HandlingKernelTerminal {
			t.Fatalf("%q handling = %v, want kernel-terminal", m, adm.Handling)
		}
	}
	// tools/list and tools/call are decision points with per-capability owners.
	if adm := Admit(Gateway, ClientOriginated, jsonrpc.ClassRequest, "tools/call"); adm.Handling != HandlingDecisionPoint || adm.DecisionPoint != "policy_engine" {
		t.Fatalf("gateway tools/call = %v/%q", adm.Handling, adm.DecisionPoint)
	}
	if adm := Admit(Management, ClientOriginated, jsonrpc.ClassRequest, "tools/call"); adm.Handling != HandlingDecisionPoint || adm.DecisionPoint != "management_authorization" {
		t.Fatalf("management tools/call = %v/%q", adm.Handling, adm.DecisionPoint)
	}
	if adm := Admit(Gateway, ClientOriginated, jsonrpc.ClassRequest, "tools/list"); adm.DecisionPoint != "tool_catalog_discovery" {
		t.Fatalf("gateway tools/list point = %q", adm.DecisionPoint)
	}
}

func TestReverseChannelDirectionRejected(t *testing.T) {
	// Server-originated instances of client-direction methods are reverse-channel
	// requests, not proxied in V1.
	for _, m := range []string{"initialize", "notifications/initialized", "tools/list", "tools/call"} {
		if adm := Admit(Gateway, ServerOriginated, jsonrpc.ClassRequest, m); adm.Handling != HandlingRejected {
			t.Fatalf("server-originated %q should be rejected, got %v", m, adm.Handling)
		}
	}
	// ping and notifications/cancelled are bidirectional and stay admitted.
	for _, m := range []string{"ping", "notifications/cancelled"} {
		if adm := Admit(Gateway, ServerOriginated, classFor(m), m); adm.Handling != HandlingKernelTerminal {
			t.Fatalf("bidirectional %q should be admitted from server too, got %v", m, adm.Handling)
		}
	}
}

// Forward + reverse parity (predicate-28 class, #928): every admitted method
// resolves to exactly one of {kernel-terminal, per-capability decision point} and
// no method is duplicated. A registry edit that broke this would fail here.
func TestRegistryParity(t *testing.T) {
	if err := ValidateRegistry(); err != nil {
		t.Fatalf("registry parity violated: %v", err)
	}
}

// TestClassMismatchRejected proves the "notifications with ids" / "requests
// without ids" guard end-to-end: a notification-only method carrying an id, and a
// request method sent without one, are both rejected.
func TestClassMismatchRejected(t *testing.T) {
	// notifications/initialized decodes to a request (method + id) -> mismatch.
	if adm := Admit(Gateway, ClientOriginated, jsonrpc.ClassRequest, "notifications/initialized"); adm.Handling != HandlingRejected || adm.Reason != mcperr.ReasonInvalidJSONRPC {
		t.Fatalf("notification-with-id not rejected: %+v", adm)
	}
	// tools/call decodes to a notification (method, no id) -> mismatch.
	if adm := Admit(Gateway, ClientOriginated, jsonrpc.ClassNotification, "tools/call"); adm.Handling != HandlingRejected || adm.Reason != mcperr.ReasonInvalidJSONRPC {
		t.Fatalf("request-without-id not rejected: %+v", adm)
	}
}

// classFor returns the wire class the admitted method expects (notifications are
// notification-class; everything else is request-class).
func classFor(method string) jsonrpc.Class {
	switch method {
	case "notifications/initialized", "notifications/cancelled":
		return jsonrpc.ClassNotification
	default:
		return jsonrpc.ClassRequest
	}
}
