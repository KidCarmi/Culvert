package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
)

// groupScopedPolicy is a Block rule scoped to the fixture's group, with an
// Allow-everything behind it: the shape in which an unresolvable group forwards
// what the rule was written to stop.
func groupScopedPolicy() []PolicyRule {
	return []PolicyRule{
		{Priority: 10, Name: "block-nonproductive", DestCategoryGroup: "non-productive", DestCategoryGroupID: mbrGroupID, Action: ActionBlockPage},
		{Priority: 20, Name: "allow-all", DestFQDN: "*", Action: ActionAllow},
	}
}

// What a failed groups load does to enforcement, and what startup now decides
// about it. Before the guard, the load error was one log line and the proxy
// started with the group-scoped rule matching nothing.
func TestCategoryGroupsLoadFailure_WeakensGroupScopedRulesAndIsFatalAtStartup(t *testing.T) {
	installMembershipFixture(t, true)
	ps := &PolicyStore{}
	ps.ReplaceAll(groupScopedPolicy())
	matched := func() string {
		m := ps.Evaluate("203.0.113.7", "", "unauth", mbrHostNews, nil)
		if m == nil || m.Rule == nil {
			return ""
		}
		return m.Rule.Name
	}
	if got := matched(); got != "block-nonproductive" {
		t.Fatalf("premise: with the group loaded %s matches %q, want block-nonproductive", mbrHostNews, got)
	}

	// The groups file is corrupt: the store that startup would serve from is empty.
	file := filepath.Join(t.TempDir(), "category_groups.json")
	if err := os.WriteFile(file, []byte(`{"schema_version":1,"groups":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	globalCategoryGroups = catgroup.New() // restored by the fixture's cleanup
	loadErr := globalCategoryGroups.Load(file)
	if loadErr == nil {
		t.Fatal("a corrupt category groups file loaded without error")
	}
	if got := matched(); got != "allow-all" {
		t.Fatalf("after the failed load %s matches %q; the test's premise is that the group-scoped Block falls through to the Allow", mbrHostNews, got)
	}

	// The startup decision: fatal, naming the rule that would be inert.
	deps := policyRulesUsingCategoryGroups(ps.List())
	if len(deps) != 1 || deps[0] != "block-nonproductive" {
		t.Fatalf("dependents = %v, want [block-nonproductive]", deps)
	}
	fatal := categoryGroupsStartupVerdict(loadErr, deps, file)
	for _, want := range []string{"Cannot load category groups", "block-nonproductive", "will not start"} {
		if !strings.Contains(fatal, want) {
			t.Errorf("fatal message lacks %q: %q", want, fatal)
		}
	}

	// Controls: nothing depends on a group, or the load succeeded → startup continues.
	if v := categoryGroupsStartupVerdict(loadErr, nil, file); v != "" {
		t.Errorf("no dependent rule, yet the verdict is fatal: %q", v)
	}
	if v := categoryGroupsStartupVerdict(nil, deps, file); v != "" {
		t.Errorf("a clean load is fatal: %q", v)
	}
	off := false
	disabled := groupScopedPolicy()
	disabled[0].Enabled = &off
	if deps := policyRulesUsingCategoryGroups(disabled); len(deps) != 0 {
		t.Errorf("a DISABLED group-scoped rule counts as a dependent (%v); it enforces nothing", deps)
	}
	nameOnly := []PolicyRule{{Priority: 1, Name: "by-name", DestCategoryGroup: "non-productive", Action: ActionDrop}}
	if deps := policyRulesUsingCategoryGroups(nameOnly); len(deps) != 1 {
		t.Errorf("a rule scoped by group NAME only is not counted (%v)", deps)
	}
	// Many dependents: the message is bounded and a hostile name cannot forge a line.
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, "rule\nforged")
	}
	long := categoryGroupsStartupVerdict(errors.New("x"), many, file)
	if strings.ContainsAny(long, "\r\n") || !strings.Contains(long, "and 35 more") {
		t.Errorf("fatal message is unbounded or carries a raw line break: %q", long)
	}
}

func TestCategoryGroupsLoadFailure_NonFatalCaseStaysVisibleInDiagnostics(t *testing.T) {
	installMembershipFixture(t, true)
	prev := categoryGroupsLoadFailure.Load()
	t.Cleanup(func() { categoryGroupsLoadFailure.Store(prev) })

	categoryGroupsLoadFailure.Store(nil)
	if rows := checkCategoryGroupsLoadFailed(); rows != nil {
		t.Fatalf("a row without a load failure: %+v", rows)
	}
	msg := "category groups: unsupported envelope schema_version 2 (want 1)"
	categoryGroupsLoadFailure.Store(&msg)
	// Groups are present (a later sync repopulated the store): nothing to report.
	if rows := checkCategoryGroupsLoadFailed(); rows != nil {
		t.Errorf("a row while the store holds groups: %+v", rows)
	}
	globalCategoryGroups = catgroup.New() // empty; restored by the fixture's cleanup
	rows := checkCategoryGroupsLoadFailed()
	if len(rows) != 1 || rows[0].Code != "category_groups_load_failed" || rows[0].Status != diagWarn {
		t.Fatalf("rows = %+v, want one category_groups_load_failed warning", rows)
	}
	if !strings.Contains(rows[0].Message, "schema_version 2") || rows[0].OperatorAction == "" {
		t.Errorf("row does not carry the cause or an action: %+v", rows[0])
	}
}
