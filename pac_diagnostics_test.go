package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func resetPACLegacyNewer(t *testing.T) {
	t.Helper()
	orig := pacLegacyNewerAtBoot.Load()
	t.Cleanup(func() { pacLegacyNewerAtBoot.Store(orig) })
	pacLegacyNewerAtBoot.Store(false)
}

func TestCheckPACLegacyNewer_AbsentUntilBootFindsIt(t *testing.T) {
	resetPACLegacyNewer(t)
	if got := checkPACLegacyNewer(); len(got) != 0 {
		t.Fatalf("no boot finding must add no row, got %+v", got)
	}
}

func TestLoadPAC_StaleLegacyRaisesDiagnosticsRow(t *testing.T) {
	resetPACStartupGlobals(t)
	resetPACLegacyNewer(t)
	ensurePACStartupTestLogger(t)
	dir := t.TempDir()
	newPath := filepath.Join(dir, "pac_config.json")
	legacy := filepath.Join(dir, "legacy_pac_config.json")
	if err := os.WriteFile(newPath, []byte(`{"proxyHost":"current.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte(`{"proxyHost":"edited-while-downgraded.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(legacy, future, future); err != nil {
		t.Fatal(err)
	}
	if err := loadPAC(pacStartupConfig{ConfigPath: newPath, LegacyConfigPath: legacy, DefaultProxyPort: 8080}); err != nil {
		t.Fatalf("loadPAC: %v", err)
	}
	got := checkPACLegacyNewer()
	if len(got) != 1 || got[0].Code != "pac_legacy_config_newer" || got[0].Status != diagWarn || got[0].OperatorAction == "" {
		t.Fatalf("want one warn row with an action, got %+v", got)
	}
	if strings.Contains(got[0].Message, dir) {
		t.Errorf("row must not name file paths: %q", got[0].Message)
	}
	found := false
	for _, c := range buildOperatorContract().Checks {
		found = found || c.Code == "pac_legacy_config_newer"
	}
	if !found {
		t.Error("row missing from the aggregated operator contract")
	}
	// A clean reload (legacy no longer newer) clears the boot finding.
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(legacy, past, past); err != nil {
		t.Fatal(err)
	}
	if err := loadPAC(pacStartupConfig{ConfigPath: newPath, LegacyConfigPath: legacy, DefaultProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}
	if got := checkPACLegacyNewer(); len(got) != 0 {
		t.Fatalf("finding must clear when legacy is not newer, got %+v", got)
	}
}
