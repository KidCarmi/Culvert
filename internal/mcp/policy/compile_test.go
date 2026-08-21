package policy

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func TestCompile_RejectsMalformedDocuments(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"empty", ``},
		{"trailing data", gwSnap("") + `garbage`},
		{"duplicate key", `{"schema_version":1,"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`},
		{"unknown top-level field", `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[],"extra":true}`},
		{"unknown rule field", gwSnap(`{"id":"R","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"bogus":1}`)},
		{"unsupported schema", `{"schema_version":2,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`},
		{"bad capability", `{"schema_version":1,"capability":"other","policy_revision":1,"default_action":"DENY","rules":[]}`},
		{"non-deny default", `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"ALLOW","rules":[]}`},
		{"zero revision", `{"schema_version":1,"capability":"gateway","policy_revision":0,"default_action":"DENY","rules":[]}`},
		{"malformed action", gwSnap(`{"id":"R","priority":1,"action":"YOLO","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]}`)},
		{"malformed reason", gwSnap(`{"id":"R","priority":1,"action":"DENY","reason":"nope","remediation":"none","conditions":[]}`)},
		{"malformed remediation", gwSnap(`{"id":"R","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"do_a_thing","conditions":[]}`)},
		{"unknown condition field", gwSnap(`{"id":"R","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"whoami","op":"exact","value":"x"}]}`)},
		{"duplicate rule id", gwSnap(`{"id":"R","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]},{"id":"R","priority":2,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]}`)},
		{"duplicate priority", gwSnap(`{"id":"A","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]},{"id":"B","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[]}`)},
		{"glob double-star", gwSnap(`{"id":"R","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"resource.id","op":"glob","value":"a/**"}]}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Compile([]byte(tc.doc), CreatedMeta{}, DefaultLimits()); err == nil {
				t.Fatalf("expected compile error for %s", tc.name)
			}
		})
	}
}

func TestCompile_ObligationMatrix(t *testing.T) {
	bad := []struct {
		name string
		rule string
	}{
		{"cred profile on DENY", `{"id":"R","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"credential_profile":"p1"}}`},
		{"approval on plain ALLOW", `{"id":"R","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"approval":true}}`},
		{"ALLOW_ONCE missing once", `{"id":"R","priority":1,"action":"ALLOW_ONCE","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`},
		{"ALLOW_FOR_SESSION missing session", `{"id":"R","priority":1,"action":"ALLOW_FOR_SESSION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`},
		{"session zero ttl", `{"id":"R","priority":1,"action":"ALLOW_FOR_SESSION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"session":{"ttl_seconds":0,"max_calls":5}}}`},
		{"ALLOW_WITH_REDACTION missing redaction", `{"id":"R","priority":1,"action":"ALLOW_WITH_REDACTION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`},
		{"allow_destructive on plain ALLOW", `{"id":"R","priority":1,"action":"ALLOW","allow_destructive":true,"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"audit"}}`},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Compile([]byte(gwSnap(tc.rule)), CreatedMeta{}, DefaultLimits()); err == nil {
				t.Fatalf("expected obligation validation error for %s", tc.name)
			}
		})
	}
}

func TestCompile_AllNineActions(t *testing.T) {
	// Each action compiles with a minimally-valid obligation set.
	rules := []string{
		`{"id":"a1","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`,
		`{"id":"a2","priority":2,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"request_access","conditions":[]}`,
		`{"id":"a3","priority":3,"action":"MONITOR","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"full"}}`,
		`{"id":"a4","priority":4,"action":"QUARANTINE","reason":"MCP.TOOL.SEMANTIC_DRIFT","remediation":"review_tool_drift","conditions":[]}`,
		`{"id":"a5","priority":5,"action":"REQUIRE_CONFIRMATION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"request_confirmation","conditions":[],"obligations":{"confirmation":true}}`,
		`{"id":"a6","priority":6,"action":"REQUIRE_APPROVAL","reason":"MCP.POLICY.APPROVAL_REQUIRED","remediation":"request_approval","conditions":[],"obligations":{"approval":true,"ticket_required":true}}`,
		`{"id":"a7","priority":7,"action":"ALLOW_ONCE","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"once_call":true,"logging":"standard"}}`,
		`{"id":"a8","priority":8,"action":"ALLOW_FOR_SESSION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"session":{"session_bound":true,"ttl_seconds":300,"max_calls":5,"revoke_required":true},"logging":"standard"}}`,
		`{"id":"a9","priority":9,"action":"ALLOW_WITH_REDACTION","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"redaction":{"profile_ref":"r1","transformed_hash_required":true},"logging":"standard"}}`,
	}
	snap := mustCompile(t, gwSnap(strings.Join(rules, ",")))
	if snap.RuleCount() != 9 {
		t.Fatalf("compiled %d rules, want 9", snap.RuleCount())
	}
}

func TestCompile_CanonicalHashKeyOrderIndependent(t *testing.T) {
	a := `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[{"id":"R","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"principal.groups","op":"contains_any","values":["a","b"]}]}]}`
	b := `{"capability":"gateway","default_action":"DENY","policy_revision":1,"rules":[{"action":"DENY","conditions":[{"op":"contains_any","field":"principal.groups","values":["b","a"]}],"id":"R","priority":1,"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none"}],"schema_version":1}`
	sa := mustCompile(t, a)
	sb := mustCompile(t, b)
	if sa.Hash() != sb.Hash() {
		t.Fatalf("canonical hash differs by key/order: %s != %s", sa.Hash(), sb.Hash())
	}
}

func TestCompile_ManagementLegalActionsOnly(t *testing.T) {
	// ALLOW/DENY/REQUIRE_APPROVAL compile; the others do not.
	legal := []string{"ALLOW", "DENY", "REQUIRE_APPROVAL"}
	for _, a := range legal {
		obl := `,"obligations":{"logging":"standard"}`
		if a == "REQUIRE_APPROVAL" {
			obl = `,"obligations":{"approval":true}`
		}
		if a == "DENY" {
			obl = ""
		}
		rule := `{"id":"M","priority":1,"action":"` + a + `","reason":"MCP.MANAGEMENT.TENANT_SCOPE","remediation":"none","conditions":[]` + obl + `}`
		if _, err := Compile([]byte(mgmtSnap(rule)), CreatedMeta{}, DefaultLimits()); err != nil {
			t.Fatalf("management %s should compile: %v", a, err)
		}
	}
	for _, a := range []string{"MONITOR", "QUARANTINE", "ALLOW_ONCE", "REQUIRE_CONFIRMATION"} {
		rule := `{"id":"M","priority":1,"action":"` + a + `","reason":"MCP.MANAGEMENT.TENANT_SCOPE","remediation":"none","conditions":[]}`
		if _, err := Compile([]byte(mgmtSnap(rule)), CreatedMeta{}, DefaultLimits()); err == nil {
			t.Fatalf("management %s should NOT compile", a)
		}
	}
}

func TestCompile_ManagementCannotSelectGatewayCredential(t *testing.T) {
	rule := `{"id":"M","priority":1,"action":"ALLOW","reason":"MCP.MANAGEMENT.TENANT_SCOPE","remediation":"none","conditions":[],"obligations":{"credential_profile":"p1","logging":"standard"}}`
	if _, err := Compile([]byte(mgmtSnap(rule)), CreatedMeta{}, DefaultLimits()); err == nil {
		t.Fatal("management rule selecting a credential profile should fail compilation")
	}
}

func TestCompile_ReasonIsTypedError(t *testing.T) {
	_, err := Compile([]byte(`bad`), CreatedMeta{}, DefaultLimits())
	if mcperr.ReasonOf(err) != mcperr.ReasonPolicySnapshotInvalid {
		t.Fatalf("reason = %v, want policy_snapshot_invalid", mcperr.ReasonOf(err))
	}
}
