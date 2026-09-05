package canary

import "testing"

// TestAbortConditions_ClassificationIsComplete pins the §16 taxonomy: the whole-Canary
// breaches and the per-request fail-closed conditions are classified correctly and
// distinctly, with no condition left AbortScopeUnset and no whole-Canary breach mislabeled
// as a mere per-request refusal (or vice-versa).
func TestAbortConditions_ClassificationIsComplete(t *testing.T) {
	conds := AbortConditions()
	if len(conds) < 10 {
		t.Fatalf("abort taxonomy unexpectedly small (%d)", len(conds))
	}
	wantCanary := map[string]bool{
		"out_of_scope_execution": true, "scope_escape": true, "tool_fingerprint_drift": true,
		"server_identity_drift": true, "outcome_evidence_loss": true, "credential_safety_failure": true,
		"budget_exhausted": true, "elevated_error_rate": true, "latency_pathology": true,
		"unexpected_upstream_response": true,
		// independent_witness_mismatch: authoritative reconciliation contradicting Culvert's own
		// record. window_expired: the time-boxed activation ending on its own, with or without
		// traffic — an automatic STOP, classified whole-Canary because it revokes execution
		// authority for the generation exactly as a fault-driven abort does.
		"independent_witness_mismatch": true, "window_expired": true,
	}
	wantRequest := map[string]bool{
		"policy_deny": true, "stale_decision": true, "credential_not_ready": true,
		"response_inspection_block": true, "emergency_kill_for_request": true, "allowance_consumed": true,
	}
	seen := map[string]bool{}
	for _, c := range conds {
		if c.Scope == AbortScopeUnset {
			t.Errorf("condition %q has no abort scope (would fail closed to unset)", c.Code)
		}
		if seen[c.Code] {
			t.Errorf("duplicate abort condition %q", c.Code)
		}
		seen[c.Code] = true
		switch {
		case wantCanary[c.Code]:
			if c.Scope != AbortCanary {
				t.Errorf("condition %q must be whole-Canary (AbortCanary), got %s", c.Code, c.Scope)
			}
			if c.WhyCanaryWide == "" {
				t.Errorf("whole-Canary condition %q must document why a single occurrence stops the Canary", c.Code)
			}
		case wantRequest[c.Code]:
			if c.Scope != AbortRequest {
				t.Errorf("condition %q must be per-request (AbortRequest), got %s", c.Code, c.Scope)
			}
		default:
			t.Errorf("condition %q is not classified in the expected taxonomy", c.Code)
		}
	}
	for code := range wantCanary {
		if !seen[code] {
			t.Errorf("missing whole-Canary abort condition %q", code)
		}
	}
	for code := range wantRequest {
		if !seen[code] {
			t.Errorf("missing per-request abort condition %q", code)
		}
	}
}

// TestAbortScope_UnsetIsZero guards that the invalid zero value stays zero, so a
// forgotten classification is caught by the "no unset" check above rather than defaulting
// to the weaker per-request action.
func TestAbortScope_UnsetIsZero(t *testing.T) {
	if AbortScopeUnset != 0 {
		t.Fatal("AbortScopeUnset must be the zero value so a forgotten scope fails the completeness check")
	}
	if AbortScopeUnset.String() != "unset" {
		t.Fatalf("unset label = %q", AbortScopeUnset.String())
	}
}
