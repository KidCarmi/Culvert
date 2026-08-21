package policy

import "testing"

// allowRule builds a single-condition ALLOW rule for matcher tests.
func allowRule(field, op, value string) string {
	cond := `{"field":"` + field + `","op":"` + op + `","value":"` + value + `"}`
	return gwSnap(`{"id":"R1","priority":10,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[` + cond + `],"obligations":{"logging":"standard"}}`)
}

func TestMatch_Matchers(t *testing.T) {
	tests := []struct {
		name       string
		doc        string
		mutate     func(*DecisionInput)
		wantAction Action
	}{
		{"exact hit", allowRule("tool.name", "exact", "read_file"), nil, ActionAllow},
		{"exact miss", allowRule("tool.name", "exact", "other"), nil, ActionDeny},
		{"prefix hit", allowRule("tool.name", "prefix", "read_"), nil, ActionAllow},
		{"glob hit", allowRule("tool.name", "glob", "read_*"), nil, ActionAllow},
		{"glob miss", allowRule("tool.name", "glob", "write_*"), nil, ActionDeny},
		{"drift class", allowRule("tool.drift", "exact", "no_material_change"), nil, ActionAllow},
		{"destination", allowRule("tool.destination", "exact", "approved"), nil, ActionAllow},
		{"server environment", allowRule("server.environment", "exact", "prod"), nil, ActionAllow},
		{"operation class", allowRule("operation.class", "exact", "read"), nil, ActionAllow},
		{"operation namespace", allowRule("operation.namespace", "exact", "gateway_tool"), nil, ActionAllow},
		{"min assurance hit", allowRule("principal.assurance", "min_assurance", "high"), nil, ActionAllow},
		{"min assurance miss", allowRule("principal.assurance", "min_assurance", "high"),
			func(in *DecisionInput) { in.Principal.Assurance = AssuranceLow }, ActionDeny},
		{"max power hit", allowRule("tool.credential_power", "max_power", "write"), nil, ActionAllow},
		{"fingerprint equal", allowRule("tool.fingerprint", "exact", "abc123"), nil, ActionAllow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := gwInput()
			in.Principal.Assurance = AssuranceHigh
			if tc.mutate != nil {
				tc.mutate(&in)
			}
			snap := mustCompile(t, tc.doc)
			d, _ := eval(t, snap, in)
			if d.Action != tc.wantAction {
				t.Fatalf("action = %v, want %v", d.Action, tc.wantAction)
			}
		})
	}
}

func TestMatch_OneOfAndContains(t *testing.T) {
	doc := gwSnap(`{"id":"R","priority":10,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",
		"conditions":[
			{"field":"operation.method","op":"one_of","values":["tools/call","tools/list"]},
			{"field":"principal.groups","op":"contains_any","values":["ops","developers"]}
		],"obligations":{"logging":"standard"}}`)
	d, _ := eval(t, mustCompile(t, doc), gwInput())
	if d.Action != ActionAllow {
		t.Fatalf("one_of + contains_any: %v", d.Action)
	}
}

func TestMatch_FirstByPriority(t *testing.T) {
	// Lower priority evaluated first: a high-priority DENY beats a low-priority ALLOW.
	doc := gwSnap(`{"id":"DENY1","priority":1,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"request_access","conditions":[{"field":"tool.name","op":"exact","value":"read_file"}]},{"id":"ALLOW2","priority":2,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)
	d, _ := eval(t, mustCompile(t, doc), gwInput())
	if d.Action != ActionDeny || d.MatchedRule != "DENY1" {
		t.Fatalf("first-match: action=%v rule=%v", d.Action, d.MatchedRule)
	}
}

func TestMatch_DisabledRuleSkipped(t *testing.T) {
	doc := gwSnap(`{"id":"OFF","priority":1,"enabled":false,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)
	d, _ := eval(t, mustCompile(t, doc), gwInput())
	if d.Action != ActionDeny || d.Reason != ReasonNoMatchDefaultDeny {
		t.Fatalf("disabled-only snapshot must default-deny: %v/%v", d.Action, d.Reason)
	}
}

func TestHardOverride_BeatsBroadAllow(t *testing.T) {
	// A broad, high-priority ALLOW must never override a hard security override.
	broad := `{"id":"BROAD","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	cases := []struct {
		name   string
		mutate func(*DecisionInput)
		action Action
		reason ReasonCode
	}{
		{"unknown tool", func(in *DecisionInput) { in.Tool.Drift = DriftUnknownTool; in.Tool.Disposition = DispQuarantined }, ActionQuarantine, ReasonToolUnknown},
		{"privilege expansion", func(in *DecisionInput) { in.Tool.Drift = DriftPrivilegeExpansion }, ActionQuarantine, ReasonToolPrivilegeExpansion},
		{"server disabled", func(in *DecisionInput) { in.Server.Enabled = false }, ActionDeny, ReasonServerDisabled},
		{"server identity changed", func(in *DecisionInput) { in.Server.Verification = ServerIdentityMismatch }, ActionDeny, ReasonServerIdentityChanged},
		{"cross-tenant resource", func(in *DecisionInput) {
			in.Resource = &Resource{Type: "repo", ID: "r1", Tenant: "tenant-b"}
		}, ActionDeny, ReasonTenantMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := gwInput()
			tc.mutate(&in)
			d, _ := eval(t, mustCompile(t, gwSnap(broad)), in)
			if d.Action != tc.action || d.Reason != tc.reason {
				t.Fatalf("%s: action=%v reason=%v, want %v/%v", tc.name, d.Action, d.Reason, tc.action, tc.reason)
			}
			if !d.HardOverride {
				t.Fatalf("%s must be a hard override", tc.name)
			}
		})
	}
}

func TestIdentityAmbiguous_WriteDenied(t *testing.T) {
	in := gwInput()
	in.Operation.Class = OpWrite
	in.Principal.Assurance = AssuranceUnknown
	broad := `{"id":"BROAD","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	d, _ := eval(t, mustCompile(t, gwSnap(broad)), in)
	if d.Action != ActionDeny || d.Reason != ReasonIdentityAmbiguous {
		t.Fatalf("ambiguous identity on write: %v/%v", d.Action, d.Reason)
	}
}

func TestReasonAndRevisionAlwaysStamped(t *testing.T) {
	docs := []struct {
		name string
		doc  string
		in   func() DecisionInput
	}{
		{"default deny", gwSnap(""), gwInput},
		{"allow", allowRule("tool.name", "exact", "read_file"), gwInput},
	}
	for _, tc := range docs {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in()
			d, _ := eval(t, mustCompile(t, tc.doc), in)
			if d.Reason == "" || !d.Reason.Valid() {
				t.Fatalf("missing/invalid reason: %q", d.Reason)
			}
			if d.PolicyRevision == 0 || d.CatalogRevision == 0 {
				t.Fatalf("missing revision context: pol=%d cat=%d", d.PolicyRevision, d.CatalogRevision)
			}
			if d.Remediation == "" || !d.Remediation.Valid() {
				t.Fatalf("missing/invalid remediation: %q", d.Remediation)
			}
		})
	}
}

func TestExplainTrace_SafeAndBounded(t *testing.T) {
	doc := gwSnap(`{"id":"R1","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"tool.name","op":"exact","value":"nope"}]},{"id":"R2","priority":2,"action":"DENY","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"request_access","conditions":[{"field":"operation.method","op":"exact","value":"tools/call"}]}`)
	_, tr := eval(t, mustCompile(t, doc), gwInput())
	if tr.Winner != "R2" {
		t.Fatalf("trace winner = %q, want R2", tr.Winner)
	}
	// The trace must show R1's decisive mismatch on tool.name and never a raw value.
	foundMismatch := false
	for _, e := range tr.Entries {
		if e.ConditionID == "tool.name|exact" && !e.Matched {
			foundMismatch = true
		}
		// A trace entry must not embed the raw tool name.
		if e.Label == "read_file" || e.ConditionID == "read_file" {
			t.Fatal("trace leaked a raw value")
		}
	}
	if !foundMismatch {
		t.Fatal("trace did not record the decisive mismatch condition id")
	}
}

func TestInvalidInput_IsNotDefaultDeny(t *testing.T) {
	snap := mustCompile(t, gwSnap(""))
	in := gwInput()
	in.Principal.SubjectID = "" // structurally invalid
	e := NewEngine(DefaultLimits())
	d, _, err := e.Evaluate(snap, &in)
	if err == nil {
		t.Fatal("invalid input must return an error")
	}
	if d.Reason != ReasonInvalidInput {
		t.Fatalf("invalid input reason = %v, want INVALID_INPUT (not NO_MATCH_DEFAULT_DENY)", d.Reason)
	}
	if d.Action != ActionDeny {
		t.Fatalf("invalid input must fail closed: %v", d.Action)
	}
}
