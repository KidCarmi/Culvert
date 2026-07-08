package main

import (
	"net/http"

	"github.com/KidCarmi/Culvert/internal/blockpage"
)

// The corporate block page moved to internal/blockpage (ADR-0002). These thin
// wrappers keep the unqualified call sites unchanged — proxy.go (serveBlockPage
// on every deny path), admin_settings.go (get/set for restart-durable custom
// HTML), and the black-box tests in edge_audit_test.go / policy_misc_test.go.
// No new exported API.
func setBlockPageHTML(html string) error { return blockpage.SetHTML(html) }
func getBlockPageHTML() string           { return blockpage.GetHTML() }

func serveBlockPage(w http.ResponseWriter, url, category, ruleName string) {
	blockpage.Serve(w, url, category, ruleName)
}
