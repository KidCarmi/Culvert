//go:build uie2e

package main

// UX-audit run entrypoints (advisory — SKIP without a browser, NEVER a merge
// gate). TestUXAudit_Validate is a fast smoke; TestUXAudit_Matrix is the full
// capture run that backs the current-state visual report.

import (
	"net/http/httptest"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUXAudit_Validate(t *testing.T) {
	seedUXRoster(t)
	srv := httptest.NewServer(newAdminUIHandler())
	defer srv.Close()
	browser := uiE2EBrowser(t)
	lg := &ledger{}
	admin := uxRoles[0]
	viewer := uxRoles[2]
	capture(t, browser, srv.URL, admin, "dark", 1920, 1080, "mcp-overview", "current", nil, lg)
	capture(t, browser, srv.URL, admin, "dark", 1920, 1080, "mcp-rollout", "current", nil, lg)
	capture(t, browser, srv.URL, admin, "light", 1920, 1080, "mcp-overview", "current", nil, lg)
	capture(t, browser, srv.URL, viewer, "dark", 1920, 1080, "mcp-settings", "viewer-denied", nil, lg)
	lg.flush(t, uxAuditRoot+"/_validate-ledger.json")
}

// spec is one screenshot request in the matrix.
type spec struct {
	role     string // admin|operator|viewer
	theme    string // dark|light
	width    int
	view     string
	scenario string // "current" (real) | posture slug | "viewer-denied"
}

func heightFor(w int) int {
	switch w {
	case 1440:
		return 900
	case 1280:
		return 800
	default:
		return 1080
	}
}

func roleByName(n string) roleSpec {
	for _, r := range uxRoles {
		if r.name == n {
			return r
		}
	}
	return uxRoles[0]
}

func TestUXAudit_Matrix(t *testing.T) {
	seedUXRoster(t)
	srv := httptest.NewServer(newAdminUIHandler())
	defer srv.Close()
	browser := uiE2EBrowser(t)
	lg := &ledger{}

	specs := []spec{}
	add := func(s ...spec) { specs = append(specs, s...) }

	// ── 1. Current-state baseline: every MCP view + activity surfaces, real
	//      unseeded server (disabled-default), admin / dark / 1920. ───────────
	for _, v := range mcpViews {
		add(spec{"admin", "dark", 1920, v, "current"})
	}
	for _, v := range activityViews {
		add(spec{"admin", "dark", 1920, v, "current"})
	}

	// ── 2. Healthy operational posture (synthetic fixture). ──────────────────
	add(
		spec{"admin", "dark", 1920, "mcp-overview", "healthy"},
		spec{"admin", "dark", 1920, "mcp-health", "healthy"},
		spec{"admin", "dark", 1920, "mcp-rollout", "healthy"},
	)

	// ── 3. Operational posture scenarios, each on its most telling view. ─────
	add(
		spec{"admin", "dark", 1920, "mcp-rollout", "observe"},
		spec{"admin", "dark", 1920, "mcp-rollout", "shadow"},
		spec{"admin", "dark", 1920, "mcp-decisions", "shadow"},
		spec{"admin", "dark", 1920, "mcp-rollout", "canary"},
		spec{"admin", "dark", 1920, "mcp-decisions", "canary"},
		spec{"admin", "dark", 1920, "mcp-decisions", "hardfail"},
		spec{"admin", "dark", 1920, "mcp-servers", "unknowntool"},
		spec{"admin", "dark", 1920, "mcp-decisions", "dlpblock"},
		spec{"admin", "dark", 1920, "mcp-decisions", "dlpredact"},
		spec{"admin", "dark", 1920, "mcp-health", "partialack"},
		spec{"admin", "dark", 1920, "mcp-health", "dpincompat"},
		spec{"admin", "dark", 1920, "mcp-health", "durability"},
		spec{"admin", "dark", 1920, "mcp-overview", "durability"},
		spec{"admin", "dark", 1920, "mcp-rollout", "killswitch"},
		spec{"admin", "dark", 1920, "mcp-health", "rollback"},
		spec{"admin", "dark", 1920, "mcp-rollout", "prodlocked"},
		spec{"admin", "dark", 1920, "mcp-overview", "apifail"},
		spec{"admin", "dark", 1920, "mcp-approvals", "approvals"},
	)

	// ── 4. RBAC: operator + viewer contrast on posture-bearing views. ────────
	add(
		spec{"operator", "dark", 1920, "mcp-overview", "healthy"},
		spec{"operator", "dark", 1920, "mcp-rollout", "healthy"},
		spec{"operator", "dark", 1920, "mcp-settings", "current"},
		spec{"viewer", "dark", 1920, "mcp-overview", "healthy"},
		spec{"viewer", "dark", 1920, "mcp-rollout", "healthy"},
		spec{"viewer", "dark", 1920, "mcp-settings", "viewer-denied"},
	)

	// ── 5. Light theme on primary overview + investigation surfaces. ─────────
	add(
		spec{"admin", "light", 1920, "mcp-overview", "healthy"},
		spec{"admin", "light", 1920, "mcp-decisions", "shadow"},
		spec{"admin", "light", 1920, "mcp-rollout", "healthy"},
		spec{"admin", "light", 1920, "dashboard", "current"},
		spec{"admin", "light", 1920, "livefeed", "current"},
	)

	// ── 6. Responsive widths on overview + rollout. ──────────────────────────
	add(
		spec{"admin", "dark", 1440, "mcp-overview", "healthy"},
		spec{"admin", "dark", 1440, "mcp-rollout", "healthy"},
		spec{"admin", "dark", 1280, "mcp-overview", "healthy"},
		spec{"admin", "dark", 1280, "mcp-rollout", "healthy"},
	)

	for _, s := range specs {
		var fx *mcpFixture
		if s.scenario != "current" && s.scenario != "viewer-denied" {
			fx = fixtureFor(s.scenario)
		}
		capture(t, browser, srv.URL, roleByName(s.role), s.theme, s.width, heightFor(s.width), s.view, s.scenario, fx, lg)
	}
	lg.flush(t, uxAuditRoot+"/_ledger.json")
	t.Logf("UX-audit matrix complete: %d captures", len(specs))
}

var _ = playwright.Bool
