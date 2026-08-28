package execution

import (
	"encoding/json"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// shadowDecisionSpread returns one ShadowDecision per Model-1 outcome, with the
// credential-plan / inspection sub-facts set to the exact combinations decide() produces,
// so the parity check exercises every field across every verdict.
func shadowDecisionSpread() []ShadowDecision {
	return []ShadowDecision{
		{EvaluatedAction: "ALLOW", Outcome: ShadowWouldExecute, ShadowOverride: false,
			CredentialPlan: planStatusValid, MaterializeReady: materializeNotEval,
			RequestInspection: inspectionWouldPass, ResponseInspection: inspectionNotEval},
		{EvaluatedAction: "DENY", Outcome: ShadowWouldBlock, ShadowOverride: true,
			CredentialPlan: planStatusNone, MaterializeReady: materializeNotEval,
			RequestInspection: inspectionNotEval, ResponseInspection: inspectionNotEval},
		{EvaluatedAction: "REQUIRE_APPROVAL", Outcome: ShadowWouldRequireApproval, ShadowOverride: true,
			CredentialPlan: planStatusNone, MaterializeReady: materializeNotEval,
			RequestInspection: inspectionNotEval, ResponseInspection: inspectionNotEval},
		{EvaluatedAction: "ALLOW", Outcome: ShadowWouldFailCredentialReadiness, ShadowOverride: false,
			CredentialPlan: planStatusInvalid, MaterializeReady: materializeNotEval,
			RequestInspection: inspectionWouldPass, ResponseInspection: inspectionNotEval},
		{EvaluatedAction: "ALLOW", Outcome: ShadowWouldFailInspection, ShadowOverride: false,
			CredentialPlan: planStatusNone, MaterializeReady: materializeNotEval,
			RequestInspection: inspectionWouldFail, ResponseInspection: inspectionNotEval},
		{EvaluatedAction: "ALLOW", Outcome: ShadowWouldFailStaleDecision, ShadowOverride: false,
			CredentialPlan: planStatusValid, MaterializeReady: materializeNotEval,
			RequestInspection: inspectionWouldPass, ResponseInspection: inspectionNotEval},
		{EvaluatedAction: "ALLOW", Outcome: ShadowWouldFailHardControl, ShadowOverride: false,
			CredentialPlan: planStatusNone, MaterializeReady: materializeNotEval,
			RequestInspection: inspectionNotEval, ResponseInspection: inspectionNotEval},
	}
}

// TestShadowEvidence_ResponseAndDurableDeriveFromOneDecision is the §3 / mutation-#10 gate:
// the transient JSON-RPC response body the client sees and the durable ShadowEvidence
// persisted to the archive MUST carry the SAME facts, because both derive from the SAME
// ShadowDecision via the single shadowEvidence() mapping. It parses the actual response
// bytes and compares field-by-field to the actual durable facts. Mutation: making
// shadowResult or shadowDecisionFacts compute a value independently (so response and
// durable can disagree) fails this gate.
func TestShadowEvidence_ResponseAndDurableDeriveFromOneDecision(t *testing.T) {
	in := execInput(policy.ActionAllow, false)
	for _, d := range shadowDecisionSpread() {
		// Reflect production: the evaluated action the response reports is the policy
		// action, whose durable home is Decision.Action (set by decisionFacts(in)).
		d.EvaluatedAction = in.Decision.Action.String()

		body := shadowResult(jsonrpc.ID{Kind: jsonrpc.IDInt, Int: 1}, d)
		var parsed struct {
			Result map[string]any `json:"result"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("%s: response unmarshal: %v", d.Outcome, err)
		}
		facts := shadowDecisionFacts(in, d)
		if facts.Shadow == nil {
			t.Fatalf("%s: durable facts carry no ShadowEvidence", d.Outcome)
		}
		sh := facts.Shadow

		// execution_state / executed must match and be the shadow markers.
		if parsed.Result["execution_state"] != "shadow_evaluated" || facts.Decision.ExecutionState != "shadow_evaluated" {
			t.Fatalf("%s: execution_state mismatch (resp %v / durable %q)", d.Outcome, parsed.Result["execution_state"], facts.Decision.ExecutionState)
		}
		if parsed.Result["executed"] != false {
			t.Fatalf("%s: response executed must be false", d.Outcome)
		}
		// The evaluated policy action: response field == durable Decision.Action.
		if parsed.Result["evaluated_policy_action"] != facts.Decision.Action {
			t.Fatalf("%s: evaluated_policy_action resp %v != durable %q", d.Outcome, parsed.Result["evaluated_policy_action"], facts.Decision.Action)
		}
		// Every shadow sub-fact: response == durable == the single mapping.
		checks := []struct {
			field   string
			respVal any
			durable any
		}{
			{"shadow_outcome", parsed.Result["shadow_outcome"], sh.Outcome},
			{"shadow_override", parsed.Result["shadow_override"], sh.Override},
			{"credential_plan", parsed.Result["credential_plan"], sh.CredentialPlan},
			{"materialization_ready", parsed.Result["materialization_ready"], sh.MaterializationReadiness},
			{"request_inspection", parsed.Result["request_inspection"], sh.RequestInspection},
			{"response_inspection", parsed.Result["response_inspection"], sh.ResponseInspection},
		}
		for _, c := range checks {
			if c.respVal != c.durable {
				t.Fatalf("%s: field %q response %v != durable %v", d.Outcome, c.field, c.respVal, c.durable)
			}
		}
		// And the durable evidence must equal the single mapping's output exactly.
		if *sh != shadowEvidence(d) {
			t.Fatalf("%s: durable ShadowEvidence diverged from shadowEvidence(d)", d.Outcome)
		}
	}
}

// TestShadowEvidence_DurableEventIsV2AndValidates proves shadowDecisionFacts drives a
// SchemaVersionV2 event through the REAL events.Manager that validates and commits — so
// the durable record carries the full ShadowEvidence and passes the model's v2 contract.
func TestShadowEvidence_DurableEventIsV2AndValidates(t *testing.T) {
	mgr := realEvents(t, nil)
	in := execInput(policy.ActionAllow, false)
	d := shadowDecisionSpread()[0]
	d.EvaluatedAction = in.Decision.Action.String()

	rec, err := mgr.CommitDecision(shadowDecisionFacts(in, d))
	if err != nil {
		t.Fatalf("a valid v2 shadow event must commit: %v", err)
	}
	if !rec.Valid() {
		t.Fatal("shadow decision commit returned no valid receipt")
	}
}
