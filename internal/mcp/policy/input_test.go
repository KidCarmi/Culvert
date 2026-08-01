package policy

import (
	"testing"
	"time"
)

// TestInput_ValidateRejects pins the structural-validity contract: each mutation of
// an otherwise well-formed tuple must fail closed with an input error (never a
// no-match default deny).
func TestInput_ValidateRejects(t *testing.T) {
	lim := DefaultLimits()
	tests := []struct {
		name   string
		mutate func(*DecisionInput)
	}{
		{"zero capability", func(in *DecisionInput) { in.Capability = CapabilityUnset }},
		{"zero policy revision", func(in *DecisionInput) { in.PolicyRevision = 0 }},
		{"zero catalog revision", func(in *DecisionInput) { in.CatalogRevision = 0 }},
		{"zero eval time", func(in *DecisionInput) { in.EvalTime = time.Time{} }},
		{"missing subject id", func(in *DecisionInput) { in.Principal.SubjectID = "" }},
		{"missing tenant", func(in *DecisionInput) { in.Principal.Tenant = "" }},
		{"missing method", func(in *DecisionInput) { in.Operation.Method = "" }},
		{"client capability mismatch", func(in *DecisionInput) { in.Client.Capability = CapManagement }},
		{"client tenant conflict", func(in *DecisionInput) { in.Client.Tenant = "other" }},
		{"gateway missing server", func(in *DecisionInput) { in.Server = nil }},
		{"tool not bound to server", func(in *DecisionInput) { in.Tool.ServerID = "srv-other" }},
		{"known tool missing fingerprint", func(in *DecisionInput) { in.Tool.FingerprintHash = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := gwInput()
			tc.mutate(&in)
			if err := in.Validate(lim); err == nil {
				t.Fatalf("expected an input-validation error for %s", tc.name)
			}
		})
	}
}

// TestInput_UnknownToolNeedsNoFingerprint: an unknown tool (catalog miss) is a VALID
// tuple even without a fingerprint — it must reach the engine to be quarantined.
func TestInput_UnknownToolNeedsNoFingerprint(t *testing.T) {
	in := gwInput()
	in.Tool.FingerprintHash = ""
	in.Tool.Drift = DriftUnknownTool
	in.Tool.Disposition = DispQuarantined
	if err := in.Validate(DefaultLimits()); err != nil {
		t.Fatalf("unknown tool without fingerprint must validate: %v", err)
	}
	// And the engine quarantines it.
	d, _ := eval(t, mustCompile(t, gwSnap(`{"id":"B","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)), in)
	if d.Action != ActionQuarantine || d.Reason != ReasonToolUnknown {
		t.Fatalf("unknown tool must quarantine: %v/%v", d.Action, d.Reason)
	}
}

// TestInput_ManagementRejectsGatewayAuthority: a Management tuple carrying a Gateway
// server/tool is structurally invalid (capability leakage).
func TestInput_ManagementRejectsGatewayAuthority(t *testing.T) {
	in := mgmtInput()
	in.Server = &Server{ServerID: "srv-1", Enabled: true, Verification: ServerVerified}
	if err := in.Validate(DefaultLimits()); err == nil {
		t.Fatal("management input carrying a gateway server must be rejected")
	}
}
