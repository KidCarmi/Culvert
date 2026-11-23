package main

// Keeps the event catalog in docs/operator/alert-webhooks.md equal to the Alerts
// panel's checkboxes. TestChaos113_EveryFiredAlertIsSubscribableInTheGUI ties
// the panel to the events the code fires, so the two together tie the catalog
// to the implementation.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var docCatalogRowRe = regexp.MustCompile("(?m)^\\| (`[a-z0-9_`, ]+`) \\|")

func TestAlertWebhooksGuideCatalogMatchesPanel(t *testing.T) {
	// Anchored to the source directory, not the CWD (see pkgSourceDir).
	doc, err := os.ReadFile(filepath.Join(pkgSourceDir(), "docs", "operator", "alert-webhooks.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, catalog, found := strings.Cut(string(doc), "\n## Event catalog\n")
	if !found {
		t.Fatal(`alert-webhooks.md has no "## Event catalog" section`)
	}
	documented := map[string]bool{}
	for _, row := range docCatalogRowRe.FindAllStringSubmatch(catalog, -1) {
		for _, name := range strings.Split(row[1], ",") {
			documented[strings.Trim(name, "` ")] = true
		}
	}
	panel := guiSubscribableEvents(t)
	for name := range panel {
		if !documented[name] {
			t.Errorf("event %q has a checkbox in the Alerts panel but no row in docs/operator/alert-webhooks.md", name)
		}
	}
	for name := range documented {
		if !panel[name] {
			t.Errorf("docs/operator/alert-webhooks.md lists event %q, which the Alerts panel does not offer", name)
		}
	}
}
