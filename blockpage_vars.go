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

// serveBlockPage is the single chokepoint every block page passes through, so
// the CHAOS-92 clamp on the client-supplied portion of url goes HERE rather
// than at the five call sites: the template renders url with html/template
// escaping, which turns a megabyte of `'` into ~5 MiB buffered in memory and
// written back to an unauthenticated client. See proxy_path_bounds.go.
func serveBlockPage(w http.ResponseWriter, url, category, ruleName string) {
	blockpage.Serve(w, boundRetainedBlockPageURL(url), category, ruleName)
}
