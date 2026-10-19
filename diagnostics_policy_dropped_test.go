package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A rule Load rejects fail-closed must be visible in the operator contract, not
// only in the boot log; a clean reload must clear the row.
func TestCheckPolicyRulesDroppedOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	bad := `[
		{"priority":1,"name":"scoped-should-drop","action":"Allow",
		 "subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.0.0.0/8"]}]}},
		{"priority":2,"name":"plain-allow","action":"Allow"}
	]`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := &PolicyStore{}
	if rows := checkPolicyRulesDroppedOnLoad(ps); rows != nil {
		t.Fatalf("never-loaded store must contribute no row, got %+v", rows)
	}
	if err := ps.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	rows := checkPolicyRulesDroppedOnLoad(ps)
	if len(rows) != 1 || rows[0].Code != "policy_rules_dropped_on_load" || rows[0].Status != diagWarn {
		t.Fatalf("want one warn row, got %+v", rows)
	}
	if !strings.Contains(rows[0].Message, `"scoped-should-drop"`) || strings.Contains(rows[0].Message, "plain-allow") {
		t.Errorf("row must name only the dropped rule: %q", rows[0].Message)
	}

	if err := os.WriteFile(path, []byte(`[{"priority":2,"name":"plain-allow","action":"Allow"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ps.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if rows := checkPolicyRulesDroppedOnLoad(ps); rows != nil {
		t.Errorf("clean reload must clear the row, got %+v", rows)
	}
}

func TestCheckPolicyRulesDroppedOnLoad_CapsNames(t *testing.T) {
	ps := &PolicyStore{}
	names := []string{"a", "b", "c", "d", "e", "f", "g"}
	ps.loadDropped.Store(&names)
	rows := checkPolicyRulesDroppedOnLoad(ps)
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "7 rule(s)") || !strings.Contains(rows[0].Message, "and 2 more") || strings.Contains(rows[0].Message, `"f"`) {
		t.Fatalf("unexpected row: %+v", rows)
	}
}
