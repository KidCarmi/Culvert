//go:build uie2e

package main

// Synthetic MCP API fixtures for the UX-audit screenshot harness.
//
// A *mcpFixture is a set of SYNTHETIC JSON bodies keyed by a URL-path substring.
// When installed, any loopback request whose path contains a key is fulfilled
// with the canned body (status 200 unless overridden) instead of hitting the
// real handler — this lets one hermetic run render every operational posture
// (healthy / shadow / canary / hard-failure / DP-incompatible / durability-
// degraded / kill-switch / rollback / production-locked / stale …) deterministic-
// ally, with NO real tenant data, NO tokens, NO secrets.
//
// fixture == nil  → no stubbing: the REAL unseeded handler answers (used for the
//                   genuine current-state / empty-state / API-error captures and
//                   for the real-viewer permission-denied captures).

import (
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

type mcpRoute struct {
	// match is a substring of the request URL path (e.g. "/api/mcp/rollout").
	match string
	// body is the raw JSON returned. status defaults to 200.
	body   string
	status int
}

type mcpFixture struct {
	name   string
	routes []mcpRoute
	// failAll, when set, makes EVERY /api/mcp/* request return this status with a
	// small JSON error — used for the API-failure / degraded-backend scenario.
	failAll     int
	failAllBody string
}

// installRoutes wires request interception: external → abort (hermetic);
// loopback /api/mcp/* → fixture (if any) else real handler; everything else →
// continue. Observations (blocked/failed) still flow through the page observers.
func installRoutes(t *testing.T, ctx playwright.BrowserContext, base string, fx *mcpFixture, obs *pageObservation) {
	t.Helper()
	err := ctx.Route("**/*", func(route playwright.Route) {
		u := route.Request().URL()
		loopback := strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost")
		if !loopback && !strings.HasPrefix(u, "data:") && !strings.HasPrefix(u, "blob:") {
			_ = route.Abort()
			return
		}
		if fx != nil && strings.Contains(u, "/api/mcp") {
			// Whole-backend failure scenario.
			if fx.failAll != 0 {
				body := fx.failAllBody
				if body == "" {
					body = `{"error":"mcp backend unavailable"}`
				}
				_ = route.Fulfill(playwright.RouteFulfillOptions{
					Status:      playwright.Int(fx.failAll),
					ContentType: playwright.String("application/json"),
					Body:        playwright.String(body),
				})
				return
			}
			for i := range fx.routes {
				if strings.Contains(u, fx.routes[i].match) {
					st := fx.routes[i].status
					if st == 0 {
						st = 200
					}
					_ = route.Fulfill(playwright.RouteFulfillOptions{
						Status:      playwright.Int(st),
						ContentType: playwright.String("application/json"),
						Body:        playwright.String(fx.routes[i].body),
					})
					return
				}
			}
		}
		_ = route.Continue()
	})
	if err != nil {
		t.Fatalf("route install: %v", err)
	}
}

// ── fixture registry ───────────────────────────────────────────────────────
// Populated in ux_audit_fixtures_data_e2e_test.go once the exact MCP GET JSON
// shapes are confirmed. Kept in a separate file so this routing core stays
// stable. The map key is the scenario slug used in screenshot filenames.
