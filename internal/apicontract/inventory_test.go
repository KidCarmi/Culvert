package apicontract

import (
	"bytes"
	"strings"
	"testing"
)

// A tiny manifest fixture: 2 documented + 1 intentionally-undocumented exemption
// across two domains, deliberately unsorted so the generator's sort is exercised.
const invFixture = `version: 1
baseline_exemption_expiry: &baseline '2027-01-31'
routes:
  - route: "/api/zeta"
    method: "GET"
    handler: "apiZeta"
    domain: "zeta"
    visibility: admin-supported
    min_role: "viewer"
    mutating: false
    audit_expected: false
    danger_level: none
    documented: true
  - route: "/api/alpha"
    method: "POST"
    handler: "apiAlpha"
    domain: "alpha"
    visibility: admin-supported
    min_role: "admin"
    mutating: true
    audit_expected: true
    danger_level: medium
    documented: true
  - route: "/events"
    method: "*"
    handler: "serveEvents"
    domain: "alpha"
    visibility: intentionally-undocumented
    min_role: "public"
    mutating: false
    audit_expected: false
    danger_level: none
    documented: false
    exemption:
      owner: platform-team
      reason: SSE stream, not a JSON resource
      security_class: non-rest-surface
      expires: *baseline
`

func TestRenderInventory_DeterministicAndCorrect(t *testing.T) {
	path := writeTemp(t, "route-classification.yaml", invFixture)

	out1, err := RenderInventory(path)
	if err != nil {
		t.Fatalf("RenderInventory: %v", err)
	}
	// Determinism: repeated renders are byte-identical (guards the sort contract
	// that the drift gate cannot see on its own).
	for i := 0; i < 5; i++ {
		out, err := RenderInventory(path)
		if err != nil {
			t.Fatalf("RenderInventory (rerun %d): %v", i, err)
		}
		if !bytes.Equal(out, out1) {
			t.Fatalf("RenderInventory is non-deterministic across runs")
		}
	}

	s := string(out1)
	// Totals counted from the manifest, not asserted by hand.
	for _, want := range []string{
		"**Total method-entries:** 3",
		"**Documented:** 2",
		"**Exempt:** 1",
		"DO NOT EDIT",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("inventory missing %q\n---\n%s", want, s)
		}
	}
	// The undocumented surface is listed with its security class.
	if !strings.Contains(s, "`/events`") || !strings.Contains(s, "non-rest-surface") {
		t.Errorf("inventory missing the intentionally-undocumented row\n---\n%s", s)
	}
	// By-domain section is sorted (alpha before zeta).
	ai := strings.Index(s, "| alpha |")
	zi := strings.Index(s, "| zeta |")
	if ai < 0 || zi < 0 || ai > zi {
		t.Errorf("by-domain rows not sorted alpha<zeta (alpha=%d zeta=%d)", ai, zi)
	}
}
