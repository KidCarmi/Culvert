package main

// auth_killswitch_roster_backend_test.go — SEC-KSROSTER-1.
//
// SEC-AUTHENABLED-1 (#1756/#1758) armed the Stage-1 gate for a roster that
// holds admitted accounts but has no present admin and no provider: the
// clamped-admin state loadedRosterRole reaches on a restore from a newer
// build, and the legacy pre-RBAC empty-role state. resolveRequestAuth's
// rosterWithoutVerifier term is also excluded from the no-backend inert guard,
// so the forced-Default arm answers with a 407 nothing can satisfy — the
// intended fail-closed answer.
//
// currentKillSwitchBackend was not updated with it. Both of its probes
// (hasCredentialCapableProvider, HasEnabledInteractiveProvider) are false in
// that state, so it reported killSwitchBackendNone and the
// auth_exempt_kill_switch row told the operator the OPPOSITE of what the
// gateway does: that engaging the break-glass "does not make formerly exempt
// clients authenticate" and their requests "are decided by the remaining
// authentication rules and Stage 2 policy". Engaging it there refuses every
// formerly exempt client instead, and the row named the wrong repair (a failed
// IdP profile) rather than the --reset-password break-glass.
//
// The gates below are a DIFFERENTIAL ORACLE between the two: each drives the
// real handleRequest in the same process state the row is rendered from, and
// requires the row's claim and the gateway's answer to agree. Asserting the
// enum alone would not have caught the original defect, because the enum was
// self-consistent — it was the enforcement path that moved.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// killSwitchProbeEnv puts the process in the deployment shape the row is about:
// no interactive IdP, global default Exempt (so the kill switch has something
// to suppress), and the switch engaged. Mirrors
// setupNoBackendKillSwitchTest's shape, but leaves cfg to the caller so a
// roster can be loaded into it first.
func killSwitchProbeEnv(t *testing.T) {
	t.Helper()
	origRegistry := idpRegistry
	idpRegistry = &IdPRegistry{live: map[string]IdentityProvider{}}
	t.Cleanup(func() { idpRegistry = origRegistry })

	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })

	setAuthExemptDisabled(true)
	t.Cleanup(func() { setAuthExemptDisabled(false) })
}

// killSwitchRow renders the single engaged ADMIN row for the live process
// state, through the operator contract the handlers serve.
func killSwitchRow(t *testing.T) OperatorContractCheck {
	t.Helper()
	var rows []OperatorContractCheck
	for _, c := range buildOperatorContract().Checks {
		if c.Code == authExemptKillSwitchCode {
			rows = append(rows, c)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("engaged kill switch must contribute exactly one row, got %d", len(rows))
	}
	return rows[0]
}

// proxyAnswer drives the real request path and returns the status the client
// sees plus the challenge header, so a row's claim can be checked against it.
func proxyAnswer(t *testing.T, host string) (status int, challenge string) {
	t.Helper()
	w := httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))
	return w.Code, w.Header().Get("Proxy-Authenticate")
}

// assertNoVerifierRowMatchesTheGateway is the shared defect gate.
func assertNoVerifierRowMatchesTheGateway(t *testing.T, host string) {
	t.Helper()
	if hasCredentialCapableProvider() {
		t.Fatal("premise broken: want no credential-capable validator")
	}
	if !cfg.AuthEnabled() {
		t.Fatal("premise broken: an admitted roster account must make AuthEnabled true (SEC-AUTHENABLED-1)")
	}

	if got := currentKillSwitchBackend(); got != killSwitchBackendNoVerifier {
		t.Errorf("SEC-KSROSTER-1: a roster with accounts and no verifier must classify as "+
			"killSwitchBackendNoVerifier (%d), got %d", killSwitchBackendNoVerifier, got)
	}

	row := killSwitchRow(t)
	if row.Code != "auth_exempt_kill_switch" || row.Status != diagWarn {
		t.Fatalf("want the engaged warn row, got %+v", row)
	}
	// The row must not carry the no-backend claim, which is what it said before.
	if strings.Contains(row.Message, "does not make formerly exempt clients authenticate") ||
		strings.Contains(row.Message, "Stage 2 policy") {
		t.Errorf("SEC-KSROSTER-1: the row still claims a Stage-2 fall-through that does not happen: %q", row.Message)
	}
	if !strings.Contains(row.Message, "refused") {
		t.Errorf("the row must say formerly exempt requests are refused, got %q", row.Message)
	}
	// The only repair is the break-glass; a failed IdP profile is the wrong one.
	if !strings.Contains(row.OperatorAction, "--reset-password") {
		t.Errorf("the row must name the --reset-password break-glass, got %q", row.OperatorAction)
	}
	if strings.Contains(row.OperatorAction, "Identity Providers") {
		t.Errorf("no provider is configured here; the row must not send the operator to Identity Providers: %q", row.OperatorAction)
	}

	// The oracle: what the gateway actually answers formerly exempt traffic.
	code, challenge := proxyAnswer(t, host)
	if code != http.StatusProxyAuthRequired {
		t.Errorf("premise broken: SEC-AUTHENABLED-1 must refuse this state with a 407, got %d", code)
	}
	if challenge == "" {
		t.Errorf("a 407 must carry a Proxy-Authenticate challenge, got none")
	}
}

// TestKillSwitchBackend_ClampedAdminRosterIsNotNoBackend covers the clamp route:
// a restored backup whose only admin carries a role this build does not enroll.
func TestKillSwitchBackend_ClampedAdminRosterIsNotNoBackend(t *testing.T) {
	setupProxyTest(t)
	if roleEnrolled(UIRole("superadmin")) {
		t.Skip("this build enrolls 'superadmin'; the clamp cannot be provoked with it")
	}
	c := loadRoster(t, rosterWithRole(t, UIRole("superadmin")))
	if c.uiUsers["alice"].role != RoleViewer || c.user != "" || c.provider != nil {
		t.Fatalf("premise broken: want the clamp to leave RoleViewer with no admin term, got role=%q user=%q provider=%v",
			c.uiUsers["alice"].role, c.user, c.provider)
	}
	killSwitchProbeEnv(t)
	assertNoVerifierRowMatchesTheGateway(t, "ks-clamped.example.test")
}

// TestKillSwitchBackend_LegacyEmptyRoleRosterIsNotNoBackend covers the second
// route: an empty role is never RoleAdmin, so c.user stays empty.
func TestKillSwitchBackend_LegacyEmptyRoleRosterIsNotNoBackend(t *testing.T) {
	setupProxyTest(t)
	c := loadRoster(t, rosterWithRole(t, ""))
	if c.user != "" || c.provider != nil || len(c.uiUsers) != 1 {
		t.Fatalf("premise broken: want one admitted record and no admin term, got user=%q provider=%v records=%d",
			c.user, c.provider, len(c.uiUsers))
	}
	killSwitchProbeEnv(t)
	assertNoVerifierRowMatchesTheGateway(t, "ks-legacy.example.test")
}

// TestKillSwitchBackend_GenuineNoBackendUnchanged is the negative control that
// matters most: a gateway with NO accounts at all must keep the
// killSwitchBackendNone row AND the Stage-2 fall-through it describes. If this
// regresses, the fix has changed enforcement rather than the report.
func TestKillSwitchBackend_GenuineNoBackendUnchanged(t *testing.T) {
	setupProxyTest(t) // fresh cfg: empty roster, no legacy pair, no provider
	killSwitchProbeEnv(t)

	if cfg.AuthEnabled() {
		t.Fatal("premise broken: a gateway with no accounts must keep AuthEnabled false")
	}
	if got := currentKillSwitchBackend(); got != killSwitchBackendNone {
		t.Errorf("no accounts at all must still classify as killSwitchBackendNone (%d), got %d",
			killSwitchBackendNone, got)
	}
	row := killSwitchRow(t)
	if !strings.Contains(row.Message, "does not make formerly exempt clients authenticate") ||
		!strings.Contains(row.Message, "remaining authentication rules and Stage 2 policy") {
		t.Errorf("the no-backend row must keep its Stage-2 claim, got %q", row.Message)
	}
	if strings.Contains(row.OperatorAction, "--reset-password") {
		t.Errorf("a fresh gateway has no roster to repair; the row must not name the break-glass: %q", row.OperatorAction)
	}

	// And the claim must still be true: inert fall-through to Stage-2 default-deny.
	code, challenge := proxyAnswer(t, "ks-nobackend-control.example.test")
	if code != http.StatusForbidden {
		t.Errorf("no-backend unmatched traffic must stay inert at Stage-2 default-deny (403), got %d", code)
	}
	if challenge != "" {
		t.Errorf("the inert fall-through must not emit an unfulfillable challenge, got %q", challenge)
	}
}

// TestKillSwitchBackend_AdminRosterUnchanged is the second negative control: a
// normal roster has a live verifier, so the row keeps the plain claim.
func TestKillSwitchBackend_AdminRosterUnchanged(t *testing.T) {
	setupProxyTest(t)
	if c := loadRoster(t, adminRoster(t, RoleAdmin)); c.user != "alice" {
		t.Fatalf("premise broken: want the admin term set from the roster, got %q", c.user)
	}
	killSwitchProbeEnv(t)

	if got := currentKillSwitchBackend(); got != killSwitchBackendLive {
		t.Errorf("an admin roster is a live verifier: want killSwitchBackendLive (%d), got %d",
			killSwitchBackendLive, got)
	}
	if row := killSwitchRow(t); !strings.Contains(row.Message, "must now authenticate") {
		t.Errorf("the backend-present row must keep the authentication claim, got %q", row.Message)
	}
}

// TestKillSwitchBackendRows_NoVerifierRowShape pins the row text on the pure
// function, independent of process state, including the boundary cases the two
// layer variants produce.
func TestKillSwitchBackendRows_NoVerifierRowShape(t *testing.T) {
	if rows := authExemptKillSwitchRows(false, false, killSwitchBackendNoVerifier); len(rows) != 0 {
		t.Fatalf("a clear switch must contribute nothing in this state too, got %+v", rows)
	}
	// The break-glass sentence is a PREFIX: each layer's own remediation must
	// survive it unchanged, so the row still tells the operator how to clear
	// the layer it actually found.
	for name, tc := range map[string]struct {
		rows  []OperatorContractCheck
		layer string
	}{
		"runtime": {authExemptKillSwitchRows(false, true, killSwitchBackendNoVerifier), "Kill switch (clear the toggle)"},
		"env":     {authExemptKillSwitchRows(true, false, killSwitchBackendNoVerifier), "Unset CULVERT_AUTHBYPASS_DISABLE and restart"},
		"both":    {authExemptKillSwitchRows(true, true, killSwitchBackendNoVerifier), "unset CULVERT_AUTHBYPASS_DISABLE and restart"},
	} {
		rows := tc.rows
		if len(rows) != 1 || rows[0].Status != diagWarn || !strings.Contains(rows[0].Message, "ENGAGED") {
			t.Fatalf("%s: want one engaged warn row, got %+v", name, rows)
		}
		if !strings.Contains(rows[0].Message, "refused") || !strings.Contains(rows[0].Message, "407") {
			t.Errorf("%s: the row must name the unsatisfiable challenge and the refusal, got %q", name, rows[0].Message)
		}
		if !strings.HasPrefix(rows[0].OperatorAction, "Restore an administrator account with the --reset-password") {
			t.Errorf("%s: the break-glass must lead the operator action, got %q", name, rows[0].OperatorAction)
		}
		if !strings.Contains(rows[0].OperatorAction, tc.layer) {
			t.Errorf("%s: the layer remediation %q must survive the break-glass prefix, got %q",
				name, tc.layer, rows[0].OperatorAction)
		}
		// Codex P2 on PR #1765: clearing the switch does NOT keep every request
		// refused — Exempt outcomes resume (resolveRequestAuth preserves them).
		// The action must scope the "refused either way" claim to traffic that
		// requires authentication and say what clearing restores.
		if strings.Contains(rows[0].OperatorAction, "proxy traffic is refused whether the kill switch is engaged or not") {
			t.Errorf("%s: the action still claims ALL proxy traffic stays refused once the switch clears: %q",
				name, rows[0].OperatorAction)
		}
		for _, want := range []string{
			"traffic that requires authentication stays refused until an administrator account exists",
			"Clearing the kill switch alone restores only credential-free requests covered by an Exempt rule or the Exempt default",
		} {
			if !strings.Contains(rows[0].OperatorAction, want) {
				t.Errorf("%s: the action must say %q, got %q", name, want, rows[0].OperatorAction)
			}
		}
	}
}

// TestKillSwitchBackend_NoVerifierClearedSwitchResumesExempt is the oracle for
// the row's "clearing restores exempt traffic" sentence (Codex P2 on PR
// #1765): in the same roster-without-verifier state, clearing the switch lets
// a credential-free request the Exempt default covers leave Stage 1 without a
// challenge, while it stays a 407 with the switch engaged. Without this the
// row's claim that only auth-required traffic stays refused would be prose.
func TestKillSwitchBackend_NoVerifierClearedSwitchResumesExempt(t *testing.T) {
	setupProxyTest(t)
	loadRoster(t, rosterWithRole(t, ""))
	killSwitchProbeEnv(t) // default Exempt, switch engaged

	if got := currentKillSwitchBackend(); got != killSwitchBackendNoVerifier {
		t.Fatalf("premise broken: want killSwitchBackendNoVerifier, got %d", got)
	}
	if code, _ := proxyAnswer(t, "ks-cleared-engaged.example.test"); code != http.StatusProxyAuthRequired {
		t.Fatalf("premise broken: engaged switch in this state must answer 407, got %d", code)
	}

	setAuthExemptDisabled(false)
	code, challenge := proxyAnswer(t, "ks-cleared-exempt.example.test")
	if code == http.StatusProxyAuthRequired || challenge != "" {
		t.Errorf("cleared switch: Exempt-default traffic must not be challenged in the no-verifier state "+
			"(the row says clearing restores it), got %d challenge=%q", code, challenge)
	}
	if rows := authExemptKillSwitchRows(false, false, currentKillSwitchBackend()); len(rows) != 0 {
		t.Errorf("a cleared switch must contribute no row, got %+v", rows)
	}
}

// TestKillSwitchBackend_NilConfigDoesNotPanic is the malformed-state boundary:
// the probe runs from the diagnostics report, which must never panic the admin
// plane, and a nil cfg must classify as no backend rather than dereference.
func TestKillSwitchBackend_NilConfigDoesNotPanic(t *testing.T) {
	origCfg, origRegistry := cfg, idpRegistry
	cfg = nil
	idpRegistry = &IdPRegistry{live: map[string]IdentityProvider{}}
	t.Cleanup(func() { cfg, idpRegistry = origCfg, origRegistry })

	if got := currentKillSwitchBackend(); got != killSwitchBackendNone {
		t.Errorf("a nil cfg must classify as killSwitchBackendNone (%d), got %d", killSwitchBackendNone, got)
	}
}

// TestKillSwitchBackend_ConcurrentProbesAgree runs the probe under -race from
// many goroutines: it reads cfg under the Config's own RLock, and the
// diagnostics report is served concurrently with proxy traffic.
func TestKillSwitchBackend_ConcurrentProbesAgree(t *testing.T) {
	setupProxyTest(t)
	loadRoster(t, rosterWithRole(t, ""))
	killSwitchProbeEnv(t)

	const workers = 16
	results := make([]killSwitchBackend, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = currentKillSwitchBackend()
		}(i)
	}
	wg.Wait()
	for i, got := range results {
		if got != killSwitchBackendNoVerifier {
			t.Fatalf("worker %d disagreed: got %d, want %d", i, got, killSwitchBackendNoVerifier)
		}
	}
}
