package main

import (
	"os"
	"regexp"
	"testing"
)

// Every bounded DP-compose failure reason the Go side can emit must have an
// operator-readable label in the Command Center "Needs attention" list, so a
// fail-closed distribution applier is never visible only in the startup log.
func TestMCPDistributionComposeReasonsAreLabelledInGUI(t *testing.T) {
	gui, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]bool{}
	for _, f := range []string{"mcp_distribution_startup_config.go", "mcp_distribution_startup.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		re := regexp.MustCompile(`(?:off\(|composeReason = )"([a-z_]+)"`)
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			reasons[m[1]] = true
		}
	}
	delete(reasons, "not_configured")
	delete(reasons, "ready")
	if len(reasons) < 5 {
		t.Fatalf("reason scan found %d reasons; selector stopped matching", len(reasons))
	}
	for r := range reasons {
		if !regexp.MustCompile(r + `:'`).Match(gui) {
			t.Errorf("dp_compose_reason %q has no GUI label", r)
		}
	}
}
