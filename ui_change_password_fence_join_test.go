package main

// ui_change_password_fence_join_test.go — FE-6AR merge 12: the legacy
// console's self-service "Change Password" dialog (#1425 on main) meets this
// tree's FENCED handler (FE-6A.2: the caller names the security generation it
// observed for its own account; 428 without it, 409 `stale` when the account
// changed since; decided before anything is written).
//
// Two halves. The SCRIPT half is a string/structure scan of static/index.html,
// pinning that the dialog binds the authenticated subject + server-owned
// generation at open (GET /api/auth/status → securityGeneration), sends exactly
// that generation, never re-fetches a fence to retry a refusal, and separates
// a refusal (nothing written, dialog open) from an unproven outcome (secrets
// dropped, no success claimed). The HANDLER half drives the real fenced
// handler behind the real session middleware as a NON-ADMIN user and pins the
// three server verdicts the script relies on — a bound generation changes the
// password and advances the generation; a stale one is refused with nothing
// written; a missing one is refused with nothing written — plus the Blocker-2
// consequence that an account changed after the dialog bound is refused at
// the session fence (401, cookie cleared), also with nothing written.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func cpJoinScript(t *testing.T) (all, block, submit, bind string) {
	t.Helper()
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	i := strings.Index(s, "// ── Self-service password change")
	j := strings.Index(s, "// ── Users & Roles")
	if i < 0 || j < 0 || j < i {
		t.Fatal("change-password script block not found")
	}
	block = s[i:j]
	return s, block, uiContractFuncBody(t, s, "async function submitChangePassword() {"), uiContractFuncBody(t, s, "async function bindChangePasswordAuthority(gen) {")
}

// The dialog sends the generation it BOUND — the fence the handler requires.
func TestCPJoin_ScriptSendsTheBoundGeneration(t *testing.T) {
	_, _, submit, bind := cpJoinScript(t)
	for _, want := range []string{
		`generation: bound.generation`,
		`const bound = _cpBound;`,
		`bound.subject !== uiUsername`,
	} {
		if !strings.Contains(submit, want) {
			t.Errorf("submitChangePassword must fence on the bound authority: missing %q", want)
		}
	}
	for _, want := range []string{
		`api('/api/auth/status')`,
		`st.securityGeneration`,
		`subject !== uiUsername`,
		`_cpBound = { subject: subject, generation: g };`,
	} {
		if !strings.Contains(bind, want) {
			t.Errorf("bindChangePasswordAuthority must bind subject + server generation: missing %q", want)
		}
	}
	// Binding happens at OPEN, not at submit.
	_, _, _, _ = cpJoinScript(t)
}

// A refused submit is never retried with a fresh fence: the ONLY read of the
// authority lives in the bind function, the ONLY mutation call in submit, and
// the refusal branch calls neither.
func TestCPJoin_NoSilentRefenceAndRetry(t *testing.T) {
	_, block, submit, _ := cpJoinScript(t)
	code := stripJSComments(block)
	if n := strings.Count(code, "'/api/auth/status'"); n != 1 {
		t.Fatalf("the authority is read from /api/auth/status %d times in the change-password block, want exactly 1 (inside the bind at open)", n)
	}
	if n := strings.Count(code, "'/api/auth/change-password'"); n != 1 {
		t.Fatalf("/api/auth/change-password is called from %d sites, want exactly 1", n)
	}
	if strings.Contains(stripJSComments(submit), "/api/auth/status") {
		t.Fatal("submitChangePassword re-reads the authority — a stale fence must be shown, not silently refreshed")
	}
	// The refusal branch shows the refusal and nothing else.
	ref := between(t, submit, "} else if (err instanceof ChangePasswordRefused) {", "} else {")
	for _, banned := range []string{"apiFetch(", "api(", "submitChangePassword(", "bindChangePasswordAuthority("} {
		if strings.Contains(stripJSComments(ref), banned) {
			t.Errorf("the refusal branch must not call %s", banned)
		}
	}
	if !strings.Contains(ref, "showChangePasswordErr(err.userText)") {
		t.Error("the refusal branch must show the refusal")
	}
}

// A refusal keeps the dialog OPEN with nothing written; an unproven outcome
// CLOSES it (dropping the typed secrets) and claims neither success nor
// failure; a 2xx is a success ONLY when action-bound.
func TestCPJoin_RefusalVersusUnprovenOutcome(t *testing.T) {
	_, block, submit, _ := cpJoinScript(t)
	unproven := between(t, submit, "} else {\n      // UNPROVEN", "\n    }\n  }")
	if !strings.Contains(unproven, "closeChangePasswordModal()") {
		t.Error("an unproven outcome must close the dialog (dropping the typed passwords)")
	}
	if !strings.Contains(unproven, "could not be confirmed") || strings.Contains(unproven, "toast('Password changed.')") {
		t.Error("an unproven outcome must be stated as unconfirmed, never as a change")
	}
	ref := between(t, submit, "} else if (err instanceof ChangePasswordRefused) {", "} else {")
	if strings.Contains(ref, "closeChangePasswordModal()") {
		t.Error("a refusal must leave the dialog open — nothing was written and the operator decides")
	}
	// The success proof is action-bound.
	proof := uiContractFuncBody(t, block, "async function changePasswordProof(r, bound) {")
	for _, want := range []string{
		`j.ok !== true`,
		`j.selfAffected !== true`,
		`j.securityGeneration <= bound.generation`,
		`startsWith('application/json')`,
	} {
		if !strings.Contains(proof, want) {
			t.Errorf("changePasswordProof must bind the 2xx to the action: missing %q", want)
		}
	}
	if !strings.Contains(submit, "if (!proof) throw new Error('unproven');") {
		t.Error("a 2xx that is not action-bound must be treated as UNPROVEN")
	}
	// The refusal CLASSIFIER names the two fence refusals as refusals (6ARR-C12b
	// moved classification out of the ChangePasswordRefused class into
	// classifyChangePasswordRefusal, which is code-bound per status; the
	// assertions are the originals, re-pointed at the function that now
	// carries them).
	cls := uiContractFuncBody(t, block, "function classifyChangePasswordRefusal(")
	for _, want := range []string{"status === 428", "status === 409", "Nothing was changed"} {
		if !strings.Contains(cls, want) {
			t.Errorf("classifyChangePasswordRefusal must classify the fence refusals: missing %q", want)
		}
	}
}

// Every close path clears the typed secrets AND the bound authority.
func TestCPJoin_CloseDropsSecretsAndBinding(t *testing.T) {
	all, _, _, _ := cpJoinScript(t)
	closeFn := uiContractFuncBody(t, all, "function closeChangePasswordModal() {")
	for _, want := range []string{"_cpBound = null;", "clearChangePasswordFields()"} {
		if !strings.Contains(closeFn, want) {
			t.Errorf("closeChangePasswordModal must %s", want)
		}
	}
	open := uiContractFuncBody(t, all, "function openChangePasswordModal() {")
	if !strings.Contains(open, "bindChangePasswordAuthority(_cpReqGen);") {
		t.Error("openChangePasswordModal must bind the authority for THIS dialog instance")
	}
}

func stripJSComments(s string) string {
	return regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(s, "")
}

func between(t *testing.T, s, from, to string) string {
	t.Helper()
	i := strings.Index(s, from)
	if i < 0 {
		t.Fatalf("marker %q not found", from)
	}
	rest := s[i+len(from):]
	j := strings.Index(rest, to)
	if j < 0 {
		t.Fatalf("marker %q not found after %q", to, from)
	}
	return rest[:j]
}

// ── Handler half ────────────────────────────────────────────────────────────

type cpJoinFixture struct {
	user, pass string
	handler    http.Handler
}

func cpJoinSetup(t *testing.T) *cpJoinFixture {
	t.Helper()
	withSessionKey(t)
	prev := cfg
	t.Cleanup(func() { cfg = prev })
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	dir := t.TempDir()
	cfg.SetUIUsersFile(filepath.Join(dir, "ui_users.json"))
	if err := cfg.SetAuth("root", "Sup3rSecret!x"); err != nil {
		t.Fatalf("seed auth: %v", err)
	}
	const user, pass = "cp-viewer", "V1ewerSecret!"
	if _, err := cfg.CreateUIUser(user, pass, RoleViewer, cfg.RosterRevision()); err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	if !cfg.IsConfigured() {
		t.Fatal("precondition: configured")
	}
	return &cpJoinFixture{user: user, pass: pass, handler: uiAuthMiddleware(http.HandlerFunc(apiAuthChangePassword))}
}

func (f *cpJoinFixture) cookie(t *testing.T, gen int64) *http.Cookie {
	t.Helper()
	value, err := encodeSession(&Session{
		Sub: f.user, Provider: "local", Role: string(RoleViewer), Gen: gen,
		Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	return &http.Cookie{Name: uiSessionCookieName, Value: value} // #nosec G124 -- request-side test cookie
}

func (f *cpJoinFixture) post(t *testing.T, sessGen int64, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(f.cookie(t, sessGen))
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *cpJoinFixture) gen(t *testing.T) int64 {
	t.Helper()
	g, ok := cfg.UserSecurityGeneration(f.user)
	if !ok {
		t.Fatal("viewer has no security generation")
	}
	return g
}

// The dialog's happy path: a non-admin user, the generation it observed,
// a 2xx that is action-bound (ok, selfAffected, a LATER generation) — and the
// new password is the one that authenticates afterwards.
func TestCPJoin_ViewerWithBoundGenerationChangesPassword(t *testing.T) {
	f := cpJoinSetup(t)
	g0 := f.gen(t)
	rec := f.post(t, g0, map[string]any{"current_password": f.pass, "new_password": "N3wSecret!pass", "generation": g0})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json (the script refuses to credit anything else)", ct)
	}
	var body struct {
		OK                 bool  `json:"ok"`
		SelfAffected       bool  `json:"selfAffected"`
		SecurityGeneration int64 `json:"securityGeneration"`
		Persisted          bool  `json:"persisted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.OK || !body.SelfAffected || body.SecurityGeneration <= g0 || !body.Persisted {
		t.Fatalf("2xx is not action-bound: %+v (sent generation %d)", body, g0)
	}
	if _, ok := cfg.VerifyUIUser(f.user, "N3wSecret!pass"); !ok {
		t.Fatal("new password does not authenticate")
	}
	if _, ok := cfg.VerifyUIUser(f.user, f.pass); ok {
		t.Fatal("old password still authenticates")
	}
	if g := f.gen(t); g != body.SecurityGeneration {
		t.Fatalf("record generation %d != answered %d", g, body.SecurityGeneration)
	}
}

// A STALE bound generation (the session is still valid at the CURRENT
// generation, the dialog carries an older one) is 409 `stale` with the
// current generation named and NOTHING written.
func TestCPJoin_StaleBoundGenerationIsRefusedWithoutMutation(t *testing.T) {
	f := cpJoinSetup(t)
	g0 := f.gen(t)
	rec := f.post(t, g0, map[string]any{"current_password": f.pass, "new_password": "N3wSecret!pass", "generation": g0 - 1})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s, want 409", rec.Code, rec.Body.String())
	}
	var body struct {
		Code    string           `json:"code"`
		Current map[string]int64 `json:"current"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Code != string(refusalStale) || body.Current["generation"] != g0 {
		t.Fatalf("refusal = %s, want code %q naming generation %d", rec.Body.String(), refusalStale, g0)
	}
	if _, ok := cfg.VerifyUIUser(f.user, f.pass); !ok {
		t.Fatal("the old password no longer authenticates: a refused change was written")
	}
	if g := f.gen(t); g != g0 {
		t.Fatalf("generation moved to %d on a refusal", g)
	}
}

// A MISSING generation is 428 with the current generation named and NOTHING
// written — the server-side twin of the dialog refusing to send unbound.
func TestCPJoin_MissingGenerationIsRefusedWithoutMutation(t *testing.T) {
	f := cpJoinSetup(t)
	g0 := f.gen(t)
	rec := f.post(t, g0, map[string]any{"current_password": f.pass, "new_password": "N3wSecret!pass"})
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d body=%s, want 428", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"generation":`+jsonInt(g0)) {
		t.Fatalf("428 must name the current generation %d: %s", g0, rec.Body.String())
	}
	if _, ok := cfg.VerifyUIUser(f.user, f.pass); !ok {
		t.Fatal("a refused change was written")
	}
}

// The account CHANGED after the dialog bound (an administrator reset, another
// session): the browser's session was issued under the previous generation,
// so the session fence refuses it BEFORE the handler — 401, cookie cleared,
// nothing written. This is the reachable "stale authority" path for a live
// browser (a session at the current generation cannot carry a stale one).
func TestCPJoin_AccountChangedAfterBindIsRefusedAtTheSessionFence(t *testing.T) {
	f := cpJoinSetup(t)
	g0 := f.gen(t)
	// An administrator resets the viewer's password → generation advances.
	if _, err := cfg.UpdateUIUser(f.user, "Adm1nReset!pw", RoleViewer, cfg.RosterRevision()); err != nil {
		t.Fatalf("admin reset: %v", err)
	}
	g1 := f.gen(t)
	if g1 <= g0 {
		t.Fatalf("generation did not advance: %d → %d", g0, g1)
	}
	rec := f.post(t, g0, map[string]any{"current_password": "Adm1nReset!pw", "new_password": "N3wSecret!pass", "generation": g0})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s, want 401 from the session fence", rec.Code, rec.Body.String())
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == uiSessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("the stale session cookie was not cleared")
	}
	if _, ok := cfg.VerifyUIUser(f.user, "Adm1nReset!pw"); !ok {
		t.Fatal("the administrator's reset no longer authenticates: the stale dialog wrote")
	}
	if g := f.gen(t); g != g1 {
		t.Fatalf("generation moved to %d on a refused request", g)
	}
}

func jsonInt(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
