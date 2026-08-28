package mcpacceptance

import "testing"

// passingSet returns a criteria slice in which every canonically-required ID is
// present, flagged required, and passing — i.e. a genuinely valid run.
func passingSet(authoritative bool) []CriterionResult {
	exp := expectedRequiredIDs(authoritative)
	out := make([]CriterionResult, 0, len(exp))
	for _, id := range exp {
		out = append(out, CriterionResult{ID: id, Required: true, Status: StatusPass})
	}
	return out
}

// A valid run must still PASS — the guard below must not be a blanket denial.
func TestOverall_ValidRunPasses(t *testing.T) {
	exp := expectedRequiredIDs(false)
	if got, missing := computeOverall(passingSet(false), exp, false, false); got != StatusPass {
		t.Fatalf("a fully passing run reported %v (missing=%v)", got, missing)
	}
}

// The defect: a canonically-required criterion that FAILS while flagged
// Required:false used to satisfy the presence check and be skipped by the failure
// check, so the harness reported PASS for a run in which a required control
// failed. Requiredness now comes from the canonical set, so the flag cannot
// suppress a failure.
func TestOverall_FlagCannotSuppressARequiredFailure(t *testing.T) {
	exp := expectedRequiredIDs(false)
	for _, victim := range []string{"startup.ready", "tenant.no_leak", "policy.default_deny"} {
		crit := passingSet(false)
		found := false
		for i := range crit {
			if crit[i].ID == victim {
				crit[i].Required = false // the mistyped flag
				crit[i].Status = StatusFail
				found = true
			}
		}
		if !found {
			t.Fatalf("fixture drift: %q is no longer a required criterion", victim)
		}
		got, missing := computeOverall(crit, exp, false, false)
		if got != StatusFail {
			t.Errorf("required criterion %q FAILED but overall was %v (missing=%v): "+
				"the Required flag suppressed a real failure", victim, got, missing)
		}
	}
}

// A required criterion that is merely non-passing (skipped, errored) must also
// fail, not just an explicit StatusFail.
func TestOverall_NonPassingRequiredCriterionFails(t *testing.T) {
	exp := expectedRequiredIDs(false)
	crit := passingSet(false)
	for i := range crit {
		if crit[i].ID == "oauth.expired" {
			crit[i].Status = StatusSkip
		}
	}
	if got, _ := computeOverall(crit, exp, false, false); got != StatusFail {
		t.Fatalf("a skipped required criterion reported %v", got)
	}
}

// Declaration drift is itself a defect: if the canonical set says a criterion is
// required and the call site says it is not, the harness disagrees with itself and
// must not issue a PASS even when everything passed.
func TestOverall_RequirednessDriftIsReported(t *testing.T) {
	exp := expectedRequiredIDs(false)
	crit := passingSet(false)
	for i := range crit {
		if crit[i].ID == "mgmt.disabled" {
			crit[i].Required = false // still PASSING, only the declaration drifted
		}
	}
	if got, _ := computeOverall(crit, exp, false, false); got != StatusFail {
		t.Fatalf("requiredness drift on a passing criterion reported %v; the canonical set "+
			"and the call site disagree and that must be surfaced", got)
	}
}

// An advisory criterion outside the canonical set may fail without failing the run
// — that is what "advisory" means, and the fix must not have swallowed it.
func TestOverall_AdvisoryFailureDoesNotFailTheRun(t *testing.T) {
	exp := expectedRequiredIDs(false)
	crit := append(passingSet(false), CriterionResult{
		ID: "evidence.denial_aggregated", Required: false, Status: StatusFail,
	})
	if got, missing := computeOverall(crit, exp, false, false); got != StatusPass {
		t.Fatalf("an advisory failure reported %v (missing=%v); advisory criteria must not gate", got, missing)
	}
}

// A criterion outside the canonical set that declares itself required still gates.
func TestOverall_SelfDeclaredRequiredOutsideTheSetStillGates(t *testing.T) {
	exp := expectedRequiredIDs(false)
	crit := append(passingSet(false), CriterionResult{
		ID: "tls.mtls", Required: true, Status: StatusFail,
	})
	if got, _ := computeOverall(crit, exp, false, false); got != StatusFail {
		t.Fatalf("a self-declared required failure outside the canonical set reported %v", got)
	}
}

// Absence still fails: a required criterion that never ran is not a pass.
func TestOverall_MissingRequiredCriterionFails(t *testing.T) {
	exp := expectedRequiredIDs(false)
	crit := passingSet(false)[1:] // drop the first required criterion entirely
	got, missing := computeOverall(crit, exp, false, false)
	if got != StatusFail || len(missing) == 0 {
		t.Fatalf("a missing required criterion reported %v missing=%v", got, missing)
	}
}
