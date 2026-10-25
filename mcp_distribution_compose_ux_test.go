package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Every bounded DP-compose failure reason the Go side can emit must have an
// operator-readable label in the Command Center "Needs attention" list, so a
// fail-closed distribution applier is never visible only in the startup log.
func TestMCPDistributionComposeReasonsAreLabelledInGUI(t *testing.T) {
	gui, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]bool{}
	for _, f := range []string{"mcp_distribution_startup_config.go", "mcp_distribution_startup.go"} {
		src, err := os.ReadFile(filepath.Join(pkgSourceDir(), f))
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

// The Command Center item links to the Health view, so that view must render
// the same compose diagnosis; otherwise the drill-down lands on healthy-looking
// cards and hides the cause.
func TestMCPHealthViewRendersComposeReason(t *testing.T) {
	gui, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatal(err)
	}
	html := string(gui)
	i := regexp.MustCompile(`async function mcpxHealthLoad\(\)\{`).FindStringIndex(html)
	if i == nil {
		t.Fatal("mcpxHealthLoad not found")
	}
	body := html[i[1]:]
	if end := regexp.MustCompile(`\n\}\n`).FindStringIndex(body); end != nil {
		body = body[:end[0]]
	}
	for _, want := range []string{`/api/mcp/distribution`, `mcpxDpComposeWarning(dist.dp_compose_reason)`} {
		if !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(body) {
			t.Errorf("mcpxHealthLoad must render the DP compose diagnosis; missing %q", want)
		}
	}
}
