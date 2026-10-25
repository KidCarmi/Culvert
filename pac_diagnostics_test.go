package main

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
)

func TestCheckPACDegraded_AbsentWhenClean(t *testing.T) {
	resetPACDegraded(t)
	if got := checkPACDegraded(); len(got) != 0 {
		t.Fatalf("no degraded profile must add no row, got %+v", got)
	}
}

func TestCheckPACDegraded_WarnNamesProfilesAndCodesNotMessages(t *testing.T) {
	resetPACDegraded(t)
	w := pac.ValidationIssue{Code: "pool_not_found", Message: "pool \"secret-pool\" not found"}
	pacUpdateDegraded("branch-il", []pac.ValidationIssue{w})
	pacUpdateDegraded("default", []pac.ValidationIssue{w})

	got := checkPACDegraded()
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	c := got[0]
	if c.Code != "pac_profile_degraded" || c.Status != diagWarn {
		t.Fatalf("unexpected row: %+v", c)
	}
	for _, want := range []string{"2 PAC profile(s)", "branch-il, default", "pool_not_found"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message %q missing %q", c.Message, want)
		}
	}
	if strings.Contains(c.Message, "secret-pool") {
		t.Errorf("warning message text must not leak into the row: %q", c.Message)
	}
	if c.OperatorAction == "" {
		t.Error("row needs an operator action")
	}
}

func TestCheckPACDegraded_BoundsProfileList(t *testing.T) {
	resetPACDegraded(t)
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		pacUpdateDegraded(id, []pac.ValidationIssue{{Code: "x"}})
	}
	c := checkPACDegraded()[0]
	if !strings.Contains(c.Message, "(+2 more)") || strings.Contains(c.Message, "f,") {
		t.Errorf("list not bounded: %q", c.Message)
	}
}

func TestBuildOperatorContract_PACDegradedRollsUpToWarn(t *testing.T) {
	resetPACDegraded(t)
	pacUpdateDegraded("default", []pac.ValidationIssue{{Code: "pool_not_found"}})
	found := false
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "pac_profile_degraded" {
			found = c.Status == diagWarn
		}
	}
	if !found {
		t.Fatal("degraded PAC must appear as a warn row in the operator contract")
	}
}
