package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Phase 4 Slice 4 — surface the already-live S2 runtime in the settings API, the
// admin UI, and the policy simulator. defaultAuthOutcome is the canonical
// contract; the simulator mirrors the Slice 3 runtime decision matrix. No
// proxy.go / runtime / cluster / persistence-model change.

// ── Settings API: defaultAuthOutcome contract ────────────────────────────────

func TestP4S4_API_SettingsExposesDefaultAuthOutcome(t *testing.T) {
	setupProxyTest(t)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	cfg.SetDefaultAuthOutcome(OutcomeExempt)

	w := httptest.NewRecorder()
	apiSettings(w, roleReq(RoleViewer, http.MethodGet, "/api/settings", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/settings = %d", w.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m["defaultAuthOutcome"] != "Exempt" {
		t.Errorf("defaultAuthOutcome = %v, want Exempt", m["defaultAuthOutcome"])
	}
	if _, present := m["unauthMode"]; present {
		t.Errorf("legacy unauthMode field must be gone from the settings response")
	}
}

func TestP4S4_API_PutPersistsAndValidates(t *testing.T) {
	setupProxyTest(t)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })

	for _, v := range []string{"Exempt", "Default"} {
		w := httptest.NewRecorder()
		apiUnauthMode(w, adminRequest(http.MethodPut, "/api/settings/unauth-mode", `{"defaultAuthOutcome":"`+v+`"}`))
		if w.Code != http.StatusOK {
			t.Fatalf("PUT %s = %d: %s", v, w.Code, w.Body.String())
		}
		if string(cfg.DefaultAuthOutcome()) != v {
			t.Errorf("after PUT %s, DefaultAuthOutcome = %q", v, cfg.DefaultAuthOutcome())
		}
	}
	// Invalid values rejected, state unchanged.
	for _, v := range []string{"", "open", "CredentialRequired", "SSORequired", "exempt"} {
		w := httptest.NewRecorder()
		apiUnauthMode(w, adminRequest(http.MethodPut, "/api/settings/unauth-mode", `{"defaultAuthOutcome":"`+v+`"}`))
		if w.Code != http.StatusBadRequest {
			t.Errorf("PUT invalid %q = %d, want 400", v, w.Code)
		}
	}
}

func TestP4S4_API_RBAC(t *testing.T) {
	setupProxyTest(t)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		w := httptest.NewRecorder()
		req := jsonReq(http.MethodPut, "/api/settings/unauth-mode", map[string]any{"defaultAuthOutcome": "Exempt"})
		apiUnauthMode(w, withRoleCtx(req, role))
		if w.Code != http.StatusForbidden {
			t.Errorf("role %v: PUT = %d, want 403", role, w.Code)
		}
	}
	if cfg.DefaultAuthOutcome() != OutcomeDefault {
		t.Error("blocked writes must not change the setting")
	}
}

// ── Simulator parity with the Slice 3 runtime matrix ─────────────────────────

// simBlock calls the simulator (client 10.0.5.7) and returns its auth block.
func simBlock(t *testing.T, rules []PolicyRule, host string) map[string]any {
	t.Helper()
	_, block := simulateAuthOutcome(rules, "10.0.5.7", host, "http", "GET", "", "")
	return block
}

// assertBlock fails for each want key whose simulator-block value differs.
func assertBlock(t *testing.T, label string, b, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if b[k] != v {
			t.Errorf("%s: block[%q] = %v, want %v", label, k, b[k], v)
		}
	}
}

func TestP4S4_Simulator_Matrix(t *testing.T) {
	setupProxyTest(t)
	t.Cleanup(func() {
		cfg.SetDefaultAuthOutcome(OutcomeDefault)
		setAuthExemptDisabled(false)
	})

	// Scoped-rule cases (global default does not matter — a rule matches).
	assertBlock(t, "scoped Exempt", simBlock(t, []PolicyRule{validExemptRule()}, "updates.example.com"),
		map[string]any{"outcome": "Exempt", "stage2AuthSource": authSourceExempt, "stage2Reached": true, "fromDefault": false})
	assertBlock(t, "scoped CR", simBlock(t, []PolicyRule{validCRRule()}, "updates.example.com"),
		map[string]any{"outcome": "CredentialRequired", "stage2Reached": false})
	assertBlock(t, "scoped SSO", simBlock(t, []PolicyRule{validSSORule()}, "portal.example.com"),
		map[string]any{"outcome": "SSORequired", "stage2Reached": false})

	// no match + Default → 407/redirect first, Stage-2 not reached.
	cfg.SetDefaultAuthOutcome(OutcomeDefault)
	assertBlock(t, "no-match Default", simBlock(t, nil, "nomatch.example.com"),
		map[string]any{"outcome": "Default", "fromDefault": true, "stage2Reached": false})

	// no match + Exempt → default-Exempt: authSource=unauth, Stage-2 reached, no scoped rule.
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	b := simBlock(t, nil, "nomatch.example.com")
	assertBlock(t, "no-match Exempt", b,
		map[string]any{"outcome": "Exempt", "stage2AuthSource": "unauth", "stage2Reached": true, "fromDefault": true, "defaultAuthOutcome": "Exempt"})
	if b["rule"] != nil {
		t.Errorf("default-Exempt must carry no scoped rule, got %+v", b["rule"])
	}

	// kill switch forces Default even when the global default is Exempt.
	setAuthExemptDisabled(true)
	assertBlock(t, "kill switch", simBlock(t, nil, "nomatch.example.com"),
		map[string]any{"outcome": "Default", "killSwitch": true})
}

// ── Static UI: new default-authentication language ───────────────────────────

func TestP4S4_UI_DefaultAuthLanguage(t *testing.T) {
	html, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	mustContain := []string{
		"Default authentication behavior",
		"Require authentication",
		"Open unmatched traffic",
		`id="s-default-auth-select"`,
		`data-change="setDefaultAuthOutcome"`,
		"function renderDefaultAuthUI",
		"function setDefaultAuthOutcome",
		"s.defaultAuthOutcome",
		`body: JSON.stringify({defaultAuthOutcome: outcome})`,
		"not Allow",          // open ≠ allow
		"evaluated first",    // scoped rules first
		"stage2Reached",      // simulator surfaces Stage-2 reached/not-reached
		"defaultAuthOutcome", // simulator surfaces the global default
	}
	for _, sub := range mustContain {
		if !strings.Contains(s, sub) {
			t.Errorf("static/index.html missing %q", sub)
		}
	}
	// Legacy toggle language and handlers must be gone.
	for _, gone := range []string{"toggleUnauthMode", "renderUnauthModeUI", "Open / Policy-Only", "s-unauth-toggle-btn"} {
		if strings.Contains(s, gone) {
			t.Errorf("legacy UI reference %q must be removed", gone)
		}
	}
}
