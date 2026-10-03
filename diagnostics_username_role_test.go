package main

// Regression gates for the admin-roster disclosure on the viewer-readable
// operator contract.
//
// checkOversizeConfiguredUsernames derives its row from the admin roster
// (cfg.ListUIUsers / cfg.GetUser / cfg.UserHasTOTP). That roster is gated at
// RoleAdmin — GET /api/auth/users is RoleAdmin on every method — but
// GET /api/diagnostics is deliberately RoleViewer, so the row's detail reached
// viewers and operators: the affected count, the longest name's byte length,
// whether a legacy single-user login exists and is mirrored, that login's
// EFFECTIVE ROLE (interpolated verbatim), and whether an affected account has
// TOTP enrolled.
//
// redactContractForRole withholds that detail below admin while keeping the row
// itself visible. These gates pin both halves: the withholding (so the leak
// cannot return) and the visibility (so the cheapest wrong fix — dropping the
// row for non-admins, which would hide a real condition from the operator and
// from monitoring — fails too).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// roleCtx attaches an arbitrary role so the fail-closed sweep can drive roles
// the named helpers do not cover (including unenrolled and empty ones).
func roleCtx(r *http.Request, role UIRole) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
}

// seedOversizeRosterWithTOTP installs the worst case: an oversize NON-ADMIN
// roster account with TOTP enrolled, mirrored by an oversize legacy
// single-user login. That is the shape whose remediation text names the role,
// the legacy topology and the second factor all at once.
func seedOversizeRosterWithTOTP(t *testing.T) string {
	t.Helper()
	snapshotCfgUIUsers(t)
	name := strings.Repeat("z", adminUsernameAccountLimit+1)
	if err := cfg.SetUIUser(name, "Chaos63-role-redact-1!", RoleOperator); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}
	if !cfg.SetTOTPSecret(name, "JBSWY3DPEHPK3PXP", []string{"bcrypt-code-1"}) {
		t.Fatal("seed SetTOTPSecret returned false")
	}
	cfg.mu.Lock()
	cfg.user = name
	cfg.mu.Unlock()
	return name
}

// fetchUsernameRow drives the real handler at the given role and returns the
// raw body plus the decoded row.
func fetchUsernameRow(t *testing.T, role UIRole) (string, *OperatorContractCheck) {
	t.Helper()
	r := roleCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody), role)
	w := httptest.NewRecorder()
	apiDiagnostics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("role %q: status = %d, want 200", role, w.Code)
	}
	return w.Body.String(), findDiagnosticCheck(decodeContract(t, w), adminUsernameLengthCode)
}

// rosterDisclosureTokens are the roster-derived facts that must never ride a
// response below admin. They are matched against the ROW's own message and
// operator_action rather than the raw body, because the body necessarily
// contains the JSON field name "operator_action" — matching the whole body for
// a bare role name produced a false positive on that key, which is exactly the
// kind of needle that makes a disclosure gate untrustworthy in both directions.
// Each phrase is asserted PRESENT in the admin rendering of the seeded worst
// case below, so none of them is a needle that can never appear.
var rosterDisclosureTokens = []string{
	"two-factor (TOTP) enrolled", // whether an affected account has a second factor
	"back to operator",           // the legacy login's effective role, interpolated verbatim
	"longest:",                   // the longest configured username's byte length
	"legacy single-user login",   // existence/topology of the legacy single-user login
	"Admin Users",                // the roster remediation workflow
}

// usernameRowDetail is everything the row itself discloses.
func usernameRowDetail(row *OperatorContractCheck) string {
	if row == nil {
		return ""
	}
	return row.Message + "\x00" + row.OperatorAction
}

// TestApiDiagnostics_UsernameRowDetailIsAdminOnly is the primary regression
// gate. Verified failing against the pre-fix handler (which passed
// buildOperatorContract() straight to jsonOK): viewer and operator responses
// carried every token below.
func TestApiDiagnostics_UsernameRowDetailIsAdminOnly(t *testing.T) {
	seedOversizeRosterWithTOTP(t)

	// Positive: an admin still receives the full remediation. Without this the
	// gate would pass against a build that deleted the detail for everyone,
	// which would destroy the operator's only in-product remediation guidance.
	_, adminRow := fetchUsernameRow(t, RoleAdmin)
	if adminRow == nil || adminRow.Status != diagWarn {
		t.Fatalf("admin: admin_username_length = %+v, want warn", adminRow)
	}
	if adminRow.OperatorAction == "" {
		t.Fatal("admin: operator_action is empty — the admin rendering must keep the remediation")
	}
	adminDetail := usernameRowDetail(adminRow)
	for _, tok := range rosterDisclosureTokens {
		if !strings.Contains(adminDetail, tok) {
			t.Fatalf("admin rendering does not contain %q — the seeded fixture no longer "+
				"produces the disclosure this test exists to withhold, so the negative "+
				"half below would be vacuous", tok)
		}
	}

	// Negative: no role below admin may see any of it.
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		_, row := fetchUsernameRow(t, role)
		if row == nil {
			t.Fatalf("role %q: admin_username_length row is missing entirely", role)
		}
		if row.OperatorAction != "" {
			t.Errorf("role %q: operator_action = %q, want empty — it names the legacy "+
				"login's role, the TOTP posture and the roster remediation", role, row.OperatorAction)
		}
		if row.Message != diagnosticsRedactedUsernameMessage {
			t.Errorf("role %q: message = %q, want the constant redacted form", role, row.Message)
		}
		detail := usernameRowDetail(row)
		for _, tok := range rosterDisclosureTokens {
			if strings.Contains(detail, tok) {
				t.Errorf("role %q: row leaked roster-derived fact %q; detail=%q", role, tok, detail)
			}
		}
	}
}

// TestApiDiagnostics_UsernameRowStaysVisibleToViewer is the CONTROL for the
// gate above: the cheapest way to pass "a viewer must not see the detail" is
// to drop the row for non-admins, which would hide a live warn condition from
// the operator contract and from anything monitoring the verdict. The row's
// code, its warn status and the overall verdict must survive redaction.
func TestApiDiagnostics_UsernameRowStaysVisibleToViewer(t *testing.T) {
	seedOversizeRosterWithTOTP(t)

	r := roleCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody), RoleViewer)
	w := httptest.NewRecorder()
	apiDiagnostics(w, r)
	c := decodeContract(t, w)

	row := findDiagnosticCheck(c, adminUsernameLengthCode)
	if row == nil {
		t.Fatal("viewer: admin_username_length row absent — redaction must withhold detail, never the row")
	}
	if row.Status != diagWarn {
		t.Errorf("viewer: status = %q, want warn — the condition must stay observable", row.Status)
	}
	if row.Message == "" {
		t.Error("viewer: message is empty — the row must still say that the condition exists")
	}
	if c.Verdict == "ok" {
		t.Error("viewer: verdict rolled up to ok despite a warn row — redaction must not clear the verdict")
	}
}

// TestApiDiagnostics_OkUsernameRowIsNotRedacted is a BOUNDARY control: an ok
// row names nothing about the roster, so redacting it would report a condition
// that does not exist and send an operator hunting an account that is fine.
func TestApiDiagnostics_OkUsernameRowIsNotRedacted(t *testing.T) {
	snapshotCfgUIUsers(t)
	cfg.mu.Lock()
	cfg.uiUsers = map[string]*uiAdminUser{}
	cfg.user = ""
	cfg.mu.Unlock()
	if err := cfg.SetUIUser("ordinary-admin", "Chaos63-ordinary-2!", RoleAdmin); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}

	for _, role := range []UIRole{RoleViewer, RoleOperator, RoleAdmin} {
		_, row := fetchUsernameRow(t, role)
		if row == nil || row.Status != diagOK {
			t.Fatalf("role %q: admin_username_length = %+v, want ok", role, row)
		}
		if row.Message == diagnosticsRedactedUsernameMessage {
			t.Errorf("role %q: an ok row was replaced with the redacted warn message", role)
		}
	}
}

// TestRedactContractForRole_FailsClosedForEveryNonAdminRole sweeps every
// enrolled role plus unenrolled and empty values. Only a proven admin may
// un-redact, so a role added below admin later — or a caller whose role could
// not be resolved — is withheld without this function being revisited.
func TestRedactContractForRole_FailsClosedForEveryNonAdminRole(t *testing.T) {
	full := OperatorContract{Checks: []OperatorContractCheck{{
		Code:           adminUsernameLengthCode,
		Status:         diagWarn,
		Message:        "3 admin accounts have a username above the 64-byte account limit (longest: 99 bytes)",
		OperatorAction: "set its role back to operator ... TOTP ...",
	}}}

	roles := []UIRole{RoleViewer, RoleOperator, RolePublic, UIRole(""), UIRole("none"), UIRole("Admin"), UIRole("superuser")}
	for _, role := range roles {
		if role.HasRole(RoleAdmin) {
			t.Fatalf("test premise broken: role %q satisfies RoleAdmin", role)
		}
		got := redactContractForRole(full, role.HasRole(RoleAdmin))
		if got.Checks[0].OperatorAction != "" {
			t.Errorf("role %q: operator_action survived redaction", role)
		}
		if got.Checks[0].Message != diagnosticsRedactedUsernameMessage {
			t.Errorf("role %q: message = %q, want redacted", role, got.Checks[0].Message)
		}
	}

	// And the one role that may read it does.
	if got := redactContractForRole(full, RoleAdmin.HasRole(RoleAdmin)); got.Checks[0].OperatorAction == "" {
		t.Error("RoleAdmin: operator_action was redacted; admins must keep the remediation")
	}
}

// TestRedactContractForRole_DoesNotMutateInput pins the aliasing invariant: a
// redacted render must not alter the contract it was handed, or a redacted
// response could poison a later admin response through the shared backing
// array. Verified failing against an in-place loop over c.Checks.
func TestRedactContractForRole_DoesNotMutateInput(t *testing.T) {
	const action = "the full remediation"
	full := OperatorContract{Checks: []OperatorContractCheck{{
		Code: adminUsernameLengthCode, Status: diagWarn,
		Message: "detailed", OperatorAction: action,
	}}}

	_ = redactContractForRole(full, false)

	if full.Checks[0].OperatorAction != action {
		t.Errorf("input contract was mutated: operator_action = %q, want %q", full.Checks[0].OperatorAction, action)
	}
	if full.Checks[0].Message != "detailed" {
		t.Errorf("input contract was mutated: message = %q", full.Checks[0].Message)
	}
	// A second, admin render of the same value must still be complete.
	if got := redactContractForRole(full, true); got.Checks[0].OperatorAction != action {
		t.Errorf("admin render after a redacted one = %q, want %q", got.Checks[0].OperatorAction, action)
	}
}

// TestApiDiagnostics_ConcurrentMixedRoleReadsDoNotLeak drives admin and viewer
// readers in parallel under -race. Redaction copies the row slice, so an admin
// render running concurrently with a viewer render must never put the detail
// into the viewer's body.
//
//	go test -race -run TestApiDiagnostics_ConcurrentMixedRoleReadsDoNotLeak .
func TestApiDiagnostics_ConcurrentMixedRoleReadsDoNotLeak(t *testing.T) {
	seedOversizeRosterWithTOTP(t)

	var wg sync.WaitGroup
	leaks := make(chan string, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			role := RoleViewer
			if i%2 == 0 {
				role = RoleAdmin
			}
			for n := 0; n < 25; n++ {
				r := roleCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody), role)
				w := httptest.NewRecorder()
				apiDiagnostics(w, r)
				if role != RoleViewer {
					continue
				}
				var c OperatorContract
				if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
					continue
				}
				detail := usernameRowDetail(findDiagnosticCheck(c, adminUsernameLengthCode))
				for _, tok := range rosterDisclosureTokens {
					if strings.Contains(detail, tok) {
						select {
						case leaks <- tok:
						default:
						}
					}
				}
			}
		}(i)
	}
	wg.Wait()
	close(leaks)
	for tok := range leaks {
		t.Errorf("a concurrent viewer read leaked roster-derived token %q", tok)
	}
}

// TestApiDiagnostics_MalformedRoleValueIsRedacted drives role values a
// well-behaved middleware would never set — whitespace, mixed case, a very
// long string, JSON-ish and control bytes — to prove the redaction decision
// cannot be talked out of fail-closed by an odd context value.
func TestApiDiagnostics_MalformedRoleValueIsRedacted(t *testing.T) {
	seedOversizeRosterWithTOTP(t)

	for _, role := range []UIRole{
		UIRole(" admin"), UIRole("admin "), UIRole("ADMIN"), UIRole("Admin\n"),
		UIRole(strings.Repeat("admin", 200)), UIRole(`{"role":"admin"}`),
		UIRole("admin\x00"), UIRole("adm\tin"),
	} {
		r := roleCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody), role)
		w := httptest.NewRecorder()
		apiDiagnostics(w, r)
		// Such a role does not satisfy RoleViewer either, so the handler may
		// refuse outright; what it must never do is answer 200 WITH the detail.
		if w.Code != http.StatusOK {
			continue
		}
		var c OperatorContract
		if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
			t.Fatalf("role %q: body is not an OperatorContract: %v", role, err)
		}
		row := findDiagnosticCheck(c, adminUsernameLengthCode)
		if row != nil && row.OperatorAction != "" {
			t.Errorf("role %q: answered 200 with the full remediation", role)
		}
	}
}

// TestWall_RosterDerivedDiagnosticsAreEnumerated is the governance wall, and it
// enumerates from the PRIMITIVE rather than from the row that happened to be
// edited. Any check that reads the admin roster produces a row whose detail is
// admin-only, so a NEW such check must either be redacted or be a deliberate,
// stated exception. Behavioural coverage cannot catch that: a future row would
// simply ship, green, on a viewer-readable surface.
func TestWall_RosterDerivedDiagnosticsAreEnumerated(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "diagnostics.go"))
	if err != nil {
		t.Fatalf("read diagnostics.go: %v", err)
	}
	body := string(src)

	// The roster accessors. A check reaching any of these is describing
	// admin-only state.
	primitives := []string{"ListUIUsers(", "UserHasTOTP(", "GetUser("}
	matched := 0
	for _, prim := range primitives {
		for idx := 0; ; {
			k := strings.Index(body[idx:], prim)
			if k < 0 {
				break
			}
			at := idx + k
			idx = at + len(prim)
			// Attribute the call to the enclosing func declaration.
			start := strings.LastIndex(body[:at], "\nfunc ")
			if start < 0 {
				t.Fatalf("%s at offset %d is outside any function", prim, at)
			}
			decl := body[start+1:]
			if nl := strings.IndexByte(decl, '\n'); nl >= 0 {
				decl = decl[:nl]
			}
			matched++
			// Stated exceptions:
			//   checkOversizeConfiguredUsernames / collectAdminUsernames — the
			//     redacted row itself.
			//   hasCredentialCapableProvider — reads cfg.GetUser() only as a
			//     BOOLEAN existence probe ("is any credential validator
			//     configured"). It never renders a name, a role, a count or a
			//     second-factor posture, and the row it feeds describes policy
			//     posture rather than roster content.
			if !strings.Contains(decl, "checkOversizeConfiguredUsernames") &&
				!strings.Contains(decl, "collectAdminUsernames") &&
				!strings.Contains(decl, "hasCredentialCapableProvider") {
				t.Errorf("new roster-derived diagnostics code %q calls %s: its row rides the "+
					"viewer-readable /api/diagnostics, so either redact it in "+
					"redactContractForRole (and add a gate beside "+
					"TestApiDiagnostics_UsernameRowDetailIsAdminOnly) or record here why "+
					"its detail is safe for a viewer and an operator to read", decl, prim)
			}
		}
	}
	if matched == 0 {
		t.Fatal("not-vacuous check: no roster accessor call found in diagnostics.go — " +
			"the accessor names changed and this wall is now scanning for nothing")
	}
}
