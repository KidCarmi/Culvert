package main

// access_cidr_diag_role_redaction_test.go — SEC-DIAG-ACCESSCIDR-1.
//
// checkAccessCIDRLists (access_cidr_diag.go, added in #1596) joined the
// operator contract, which GET /api/diagnostics and GET /api/health/explain
// serve at RoleVIEWER. Its warn row carries two facts that are admin-only
// everywhere else on the appliance:
//
//   - the VERBATIM offending entry, because the message embeds
//     SetUIAllowedCIDRs' / SetTrustedProxyCIDRs' error text, which is
//     fmt.Errorf("invalid IP/CIDR: %s", c) over the configured value; and
//   - whether the list actually in force is EMPTY — spelled out as "the admin
//     UI accepts every client IP" — or else its entry count.
//
// The UI allowlist is reachable only at RoleAdmin: GET /api/ui-allow-ips
// enforces requireRole(RoleAdmin) in BOTH methods (ui_config.go, uiRoutes) and
// nothing else reads it. redactContractForRole classified only
// admin_username_length and admin_roster_durability, so the new code was served
// to a viewer verbatim.
//
// The scope is the UI-allowlist half ONLY. GET /api/settings/network already
// returns trusted_proxy_cidrs and trust_forwarded_headers at RoleViewer, so
// the trusted-proxy clause discloses nothing a viewer cannot read directly and
// is deliberately carried through unredacted — withholding it would cost an
// operator remediation detail for no confidentiality gain. These tests pin
// both halves of that line so a later "tighten everything" change does not
// quietly over-redact, and a later widening does not re-expose the allowlist.
//
// Why it matters beyond the address itself: the row is an oracle for "is
// admin-UI IP restriction in force on this node?", answered to the lowest
// authenticated role. That is exactly the question an attacker holding a
// stolen or low-privilege console credential asks before trying it from
// off-network, and apiDiagnostics' own docstring commits to redacting any
// field "that could leak sensitive data" to admin-only at the API layer.
//
// Fail-closed direction, as with the two rows already classified: the row
// keeps its code and its WARN status below admin — an operator must still be
// able to see that something is misconfigured and escalate — and loses the
// list name, the entry, the count and the posture clause.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// accessCIDRRowAt drives the real /api/diagnostics handler at role and returns
// the access_cidr_lists row.
func accessCIDRRowAt(t *testing.T, role UIRole) *OperatorContractCheck {
	t.Helper()
	r := roleCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody), role)
	w := httptest.NewRecorder()
	apiDiagnostics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("role %q: status = %d, want 200", role, w.Code)
	}
	row := findDiagnosticCheck(decodeContract(t, w), accessCIDRListsCode)
	if row == nil {
		t.Fatalf("role %q: %s row missing from the contract", role, accessCIDRListsCode)
	}
	return row
}

// TestAccessCIDRRow_RejectedEntryIsAdminOnly is the disclosure control: the
// offending entry, the entry count and the "accepts every client IP" posture
// must reach an admin and nobody else.
func TestAccessCIDRRow_RejectedEntryIsAdminOnly(t *testing.T) {
	snapshotAccessCIDRRejects(t)
	prevUI := ListUIAllowedCIDRs()
	t.Cleanup(func() {
		_ = SetUIAllowedCIDRs(prevUI)
		noteAccessCIDRResult(accessCIDRUIAllow, nil)
		noteAccessCIDRResult(accessCIDRTrustedProxy, nil)
	})

	// The shape that discloses the most: a rejected update over an EMPTY live
	// allowlist, so the row spells out that the admin UI admits every client.
	if err := SetUIAllowedCIDRs(nil); err != nil {
		t.Fatal(err)
	}
	const offending = "10.20.30.0/33"
	noteAccessCIDRResult(accessCIDRUIAllow, errors.New("invalid IP/CIDR: "+offending))
	noteAccessCIDRResult(accessCIDRTrustedProxy, nil)

	admin := accessCIDRRowAt(t, RoleAdmin)
	if admin.Status != diagWarn {
		t.Fatalf("admin row status = %q, want warn", admin.Status)
	}
	// Positive control: redaction must not have silently cost the admin the
	// evidence this row exists to deliver.
	for _, want := range []string{offending, "accepts every client IP"} {
		if !strings.Contains(admin.Message, want) {
			t.Errorf("admin row lost %q; message = %q", want, admin.Message)
		}
	}
	if admin.OperatorAction == "" {
		t.Error("admin warn row has no operator_action")
	}

	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		row := accessCIDRRowAt(t, role)
		// The condition stays visible so a non-admin can escalate.
		if row.Status != diagWarn {
			t.Errorf("role %q: status = %q, want warn (the condition must stay visible)", role, row.Status)
		}
		detail := row.Message + " " + row.OperatorAction
		for _, leaked := range []string{
			offending,              // the configured entry, verbatim
			"accepts every client", // whether admin-UI IP restriction is in force
			"stays in force",       // the entry count / emptiness of the live list
		} {
			if strings.Contains(detail, leaked) {
				t.Errorf("role %q: %s row discloses %q to a non-admin; row = %q / %q",
					role, accessCIDRListsCode, leaked, row.Message, row.OperatorAction)
			}
		}
		if row.Message == "" {
			t.Errorf("role %q: redacted row has an empty message", role)
		}
		// Only the UI half was rejected here, so the sole remaining action is
		// to escalate.
		if row.OperatorAction != diagnosticsRedactedAction {
			t.Errorf("role %q: operator_action = %q, want the shared redacted action",
				role, row.OperatorAction)
		}
	}
}

// TestAccessCIDRRow_HealthyRowIsNotRedacted mirrors the admin_username_length
// precedent: an ok row names nothing about either list, so redacting it would
// report a condition that does not exist and send an operator looking for a
// misconfiguration that is not there.
func TestAccessCIDRRow_HealthyRowIsNotRedacted(t *testing.T) {
	snapshotAccessCIDRRejects(t)
	t.Cleanup(func() {
		noteAccessCIDRResult(accessCIDRUIAllow, nil)
		noteAccessCIDRResult(accessCIDRTrustedProxy, nil)
	})
	noteAccessCIDRResult(accessCIDRUIAllow, nil)
	noteAccessCIDRResult(accessCIDRTrustedProxy, nil)

	admin := accessCIDRRowAt(t, RoleAdmin)
	viewer := accessCIDRRowAt(t, RoleViewer)
	if admin.Status != diagOK || viewer.Status != diagOK {
		t.Fatalf("healthy row: admin = %q, viewer = %q, want ok/ok", admin.Status, viewer.Status)
	}
	if viewer.Message != admin.Message || viewer.OperatorAction != admin.OperatorAction {
		t.Errorf("healthy row differs by role:\nadmin  = %q / %q\nviewer = %q / %q",
			admin.Message, admin.OperatorAction, viewer.Message, viewer.OperatorAction)
	}
}

// TestAccessCIDRRow_TrustedProxyHalfStaysVisible is the over-redaction control.
// trusted_proxy_cidrs is already served at RoleViewer by GET
// /api/settings/network, so the trusted-proxy clause must reach a viewer
// unchanged — both when it is the only rejection and when the admin-only UI
// half is rejected alongside it.
func TestAccessCIDRRow_TrustedProxyHalfStaysVisible(t *testing.T) {
	snapshotAccessCIDRRejects(t)
	prevTP := ListTrustedProxyCIDRs()
	t.Cleanup(func() {
		_ = SetTrustedProxyCIDRs(prevTP)
		noteAccessCIDRResult(accessCIDRUIAllow, nil)
		noteAccessCIDRResult(accessCIDRTrustedProxy, nil)
	})

	if err := SetTrustedProxyCIDRs([]string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	noteAccessCIDRResult(accessCIDRUIAllow, nil)
	noteAccessCIDRResult(accessCIDRTrustedProxy, errors.New("invalid IP/CIDR: bogus-proxy"))

	admin := accessCIDRRowAt(t, RoleAdmin)
	if !strings.Contains(admin.Message, "bogus-proxy") {
		t.Fatalf("admin row lost the rejected trusted-proxy entry; message = %q", admin.Message)
	}
	// Trusted-proxy only: identical for both roles, nothing withheld.
	if viewer := accessCIDRRowAt(t, RoleViewer); viewer.Message != admin.Message {
		t.Errorf("trusted-proxy-only rejection differs by role:\nadmin  = %q\nviewer = %q",
			admin.Message, viewer.Message)
	}

	// Both halves rejected: the viewer keeps the trusted-proxy clause verbatim
	// and loses only the UI-allowlist detail.
	noteAccessCIDRResult(accessCIDRUIAllow, errors.New("invalid IP/CIDR: 10.20.30.0/33"))
	both := accessCIDRRowAt(t, RoleViewer)
	if !strings.Contains(both.Message, "bogus-proxy") || !strings.Contains(both.Message, "X-Forwarded-For") {
		t.Errorf("viewer lost the already-public trusted-proxy clause; message = %q", both.Message)
	}
	for _, leaked := range []string{"10.20.30.0/33", "accepts every client"} {
		if strings.Contains(both.Message+" "+both.OperatorAction, leaked) {
			t.Errorf("viewer row discloses %q; row = %q / %q", leaked, both.Message, both.OperatorAction)
		}
	}
}
