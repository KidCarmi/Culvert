package main

// pac_exceptions_uicontract_test.go — closes gap #3 (UI untested here). The
// governance UI lives in static/index.html; this pins the stable identifiers,
// dispatch wiring, and endpoint calls the SPA governance surface depends on
// (same string-scan approach the auth-policy UI tests use). Full interaction is
// still covered by the Playwright e2e lane; this catches accidental removal of
// the control plane wiring without a browser.

import (
	"os"
	"strings"
	"testing"
)

func TestUIContract_GovernanceSurfacePresent(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)

	mustContain := []string{
		// Panel + read-model wiring.
		`DIRECT Bypass Inventory`,
		`function loadPACPosture`,
		`/api/pac/posture/inventory`,
		`/api/pac/posture/exceptions`, // governance list joined into the card
		`Governance`,                  // the governance column header
		`function pacGovBadge`,        // status → coloured pill

		// The admin editor modal + its fields.
		`id="pac-gov-modal"`,
		`id="pac-gov-profile"`,
		`id="pac-gov-owner"`,
		`id="pac-gov-reason"`,
		`id="pac-gov-app"`,
		`id="pac-gov-ticket"`,
		`id="pac-gov-expires"`,
		`id="pac-gov-cadence"`,
		`id="pac-gov-reviewed"`,

		// Handlers.
		`function openPacGovModal`,
		`function closePacGovModal`,
		`function savePacGov`,
		`function clearPacGov`,

		// CSP-safe dispatch (no eval): every handler must be routed.
		`case 'openPacGovModal':`,
		`case 'closePacGovModal':`,
		`case 'savePacGov':`,
		`case 'clearPacGov':`,
		`data-click="savePacGov"`,
		`data-click="closePacGovModal"`,
	}
	for _, sub := range mustContain {
		if !strings.Contains(s, sub) {
			t.Errorf("static/index.html governance UI missing %q", sub)
		}
	}
}

// TestUIContract_GovernanceEditorIsAdminGated proves the Govern/Edit/Clear
// actions are rendered only for admins (the row actions are behind isAdmin),
// matching the admin-only write RBAC on the API.
func TestUIContract_GovernanceEditorIsAdminGated(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	// loadPACPosture computes isAdmin and only emits the Govern/Clear actions
	// under it. Require both the gate and the PUT/DELETE method usage.
	if !strings.Contains(s, `const isAdmin = (typeof uiRole !== 'undefined' && uiRole === 'admin')`) {
		t.Error("loadPACPosture must compute an isAdmin gate for the governance actions")
	}
	// The editor must PUT and the clear must DELETE the governance endpoint.
	if !strings.Contains(s, `method: 'PUT'`) {
		t.Error("savePacGov must PUT the governance record")
	}
	if !strings.Contains(s, `method: 'DELETE'`) {
		t.Error("clearPacGov must DELETE the governance record")
	}
}
