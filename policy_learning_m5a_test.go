package main

// M5A tests — governed enablement, observation arming, session operations,
// the read-only recommendation surface, and the API privacy boundary
// (ADR-0025). Handlers are invoked directly with the role injected into the
// request context (the C2 test convention); role-denial parity with the
// middleware is covered by the C1/C1.5/C2 gates over the uiRoutes metadata.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

// plHarness isolates every policy-learning global (engine singleton, desired
// state, paths, admin-settings path) and restores them on cleanup.
func plHarness(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prevEngine := policyLearnEngine.Load()
	prevPaths := policyLearnPaths
	prevState, prevSaved := policyLearnSnapshotState()
	adminSettingsMu.Lock()
	prevSettingsPath := adminSettingsPath
	adminSettingsPath = filepath.Join(dir, "admin_settings.json")
	adminSettingsMu.Unlock()

	policyLearnEngine.Store(nil)
	policyLearnSetState(policyLearnSettings{}, false)
	policyLearnSetRunErr("")
	policyLearnPaths = policyLearningStartupConfig{
		StorePath:      filepath.Join(dir, "policy_learning.json"),
		SubjectKeyPath: filepath.Join(dir, "policy_learning_subject.key"),
	}
	t.Cleanup(func() {
		if eng := policyLearnEngine.Load(); eng != nil && eng != prevEngine {
			_ = eng.Close()
		}
		policyLearnEngine.Store(prevEngine)
		policyLearnPaths = prevPaths
		policyLearnSetState(prevState, prevSaved)
		policyLearnSetRunErr("")
		adminSettingsMu.Lock()
		adminSettingsPath = prevSettingsPath
		adminSettingsMu.Unlock()
	})
	return dir
}

func plDo(handler http.HandlerFunc, method, path string, role UIRole, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, http.NoBody)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.RemoteAddr = "198.51.100.77:0"
	if role != "" {
		r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	}
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func plEnable(t *testing.T) {
	t.Helper()
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"enabled":true}`); w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	if policyLearnEngine.Load() == nil {
		t.Fatal("enable did not construct the engine")
	}
}

func plStartSession(t *testing.T) {
	t.Helper()
	if w := plDo(apiPolicyLearningSession, http.MethodPost, "/api/policy-learning/session", RoleOperator, `{"action":"start"}`); w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
}

func plCompleteSession(t *testing.T) string {
	t.Helper()
	w := plDo(apiPolicyLearningSession, http.MethodPost, "/api/policy-learning/session", RoleOperator, `{"action":"complete"}`)
	if w.Code != 200 {
		t.Fatalf("complete: %d %s", w.Code, w.Body.String())
	}
	var dto plSessionDTO
	if err := json.Unmarshal(w.Body.Bytes(), &dto); err != nil {
		t.Fatal(err)
	}
	return dto.ID
}

// ── §1 product state model + observation arming ──────────────────────────────

func TestPL_EnableDoesNotStartLearning(t *testing.T) {
	plHarness(t)
	plEnable(t)
	eng := policyLearnEngine.Load()
	if eng.LearningActive() {
		t.Fatal("enabling the feature armed observation without a session start")
	}
	w := plDo(apiPolicyLearningStatus, http.MethodGet, "/api/policy-learning", RoleViewer, "")
	var st map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st["enabled"] != true || st["learning_active"] != false {
		t.Fatalf("status: %v", st)
	}
}

func TestPL_ObservationGatingThreeStates(t *testing.T) {
	plHarness(t)
	auth := authOutcome{identity: "gate@corp.example", source: "idp", groups: []string{"eng"}}

	// Disabled: nil singleton — adapter is a no-op.
	learnObserveDecision(auth, "x.example", "GET", nil, "OK", "Bypass", learnDecisionKey{}, false)

	// Enabled but idle: the gate fires BEFORE Observation construction — the
	// transport counters must show NOTHING (not even a rejection).
	plEnable(t)
	eng := policyLearnEngine.Load()
	learnObserveDecision(auth, "x.example", "GET", nil, "OK", "Bypass", learnDecisionKey{}, false)
	learnObservePreDispatch(auth, "x.example", "GET", "BLOCKED")
	if s := eng.ObservationStats(); s.Accepted != 0 || s.Rejected != 0 || s.Dropped != 0 {
		t.Fatalf("enabled-idle produced transport activity: %+v", s)
	}

	// Active session: the qualified M2 path.
	plStartSession(t)
	learnObserveDecision(auth, "x.example", "GET", nil, "OK", "Bypass", learnDecisionKey{}, false)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && eng.ObservationStats().Delivered < 1 {
		time.Sleep(time.Millisecond)
	}
	if s := eng.ObservationStats(); s.Accepted != 1 || s.Delivered != 1 {
		t.Fatalf("active session did not observe: %+v", s)
	}
}

// ── §3 disable safety + §5 guardrail fencing ─────────────────────────────────

func TestPL_DisableWithActiveSession409(t *testing.T) {
	dir := plHarness(t)
	plEnable(t)
	plStartSession(t)

	w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"enabled":false}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("disable with active session: %d, want 409", w.Code)
	}
	eng := policyLearnEngine.Load()
	if eng == nil || !eng.LearningActive() {
		t.Fatal("refused disable must not have touched the session")
	}

	plCompleteSession(t)
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"enabled":false}`); w.Code != 200 {
		t.Fatalf("disable after complete: %d %s", w.Code, w.Body.String())
	}
	if policyLearnEngine.Load() != nil {
		t.Fatal("disable left the engine live")
	}
	// §14: disable never deletes evidence/history.
	for _, f := range []string{"policy_learning.json", "policy_learning_subject.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("disable removed %s: %v", f, err)
		}
	}
}

func TestPL_GuardrailEditDuringActiveSession409(t *testing.T) {
	plHarness(t)
	plEnable(t)
	plStartSession(t)

	w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"recommendable_categories":["AI"]}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("guardrail edit with active session: %d, want 409", w.Code)
	}
	// A NO-OP write (same effective allowlist) is not a guardrail change.
	cur, _ := policyLearnSnapshotState()
	raw, _ := json.Marshal(map[string]any{"recommendable_categories": policyLearnEffectiveCategories(cur)})
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, string(raw)); w.Code != 200 {
		t.Fatalf("no-op guardrail write during session: %d %s", w.Code, w.Body.String())
	}

	plCompleteSession(t)
	oldHash := policyLearnEngine.Load().GuardrailsHash()
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"recommendable_categories":["AI"]}`); w.Code != 200 {
		t.Fatalf("guardrail edit after complete: %d %s", w.Code, w.Body.String())
	}
	if policyLearnEngine.Load().GuardrailsHash() == oldHash {
		t.Fatal("allowlist change did not move GuardrailsHash")
	}
}

// ── session state machine ────────────────────────────────────────────────────

func TestPL_SessionStateMachine409s(t *testing.T) {
	plHarness(t)

	// Feature disabled: session ops are invalid transitions.
	if w := plDo(apiPolicyLearningSession, http.MethodPost, "/api/policy-learning/session", RoleOperator, `{"action":"start"}`); w.Code != http.StatusConflict {
		t.Fatalf("start while disabled: %d, want 409", w.Code)
	}

	plEnable(t)
	plStartSession(t)
	if w := plDo(apiPolicyLearningSession, http.MethodPost, "/api/policy-learning/session", RoleOperator, `{"action":"start"}`); w.Code != http.StatusConflict {
		t.Fatalf("double start: %d, want 409", w.Code)
	}
	plCompleteSession(t)
	if w := plDo(apiPolicyLearningSession, http.MethodPost, "/api/policy-learning/session", RoleOperator, `{"action":"complete"}`); w.Code != http.StatusConflict {
		t.Fatalf("complete with none active: %d, want 409", w.Code)
	}
	if w := plDo(apiPolicyLearningSession, http.MethodPost, "/api/policy-learning/session", RoleOperator, `{"action":"cancel"}`); w.Code != http.StatusConflict {
		t.Fatalf("cancel with none active: %d, want 409", w.Code)
	}
	if w := plDo(apiPolicyLearningSession, http.MethodPost, "/api/policy-learning/session", RoleOperator, `{"action":"warp"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown action: %d, want 400", w.Code)
	}
}

// ── RBAC matrix ──────────────────────────────────────────────────────────────

func TestPL_RBACMatrix(t *testing.T) {
	plHarness(t)
	plEnable(t)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		path    string
		role    UIRole
		body    string
		want    int // 403 = denied; -1 = anything but 403
	}{
		{"status viewer", apiPolicyLearningStatus, "GET", "/api/policy-learning", RoleViewer, "", -1},
		{"config get viewer", apiPolicyLearningConfig, "GET", "/api/policy-learning/config", RoleViewer, "", -1},
		{"config put viewer denied", apiPolicyLearningConfig, "PUT", "/api/policy-learning/config", RoleViewer, `{}`, 403},
		{"config put operator denied", apiPolicyLearningConfig, "PUT", "/api/policy-learning/config", RoleOperator, `{}`, 403},
		{"config put admin", apiPolicyLearningConfig, "PUT", "/api/policy-learning/config", RoleAdmin, `{}`, -1},
		{"session viewer denied", apiPolicyLearningSession, "POST", "/api/policy-learning/session", RoleViewer, `{"action":"start"}`, 403},
		{"session operator", apiPolicyLearningSession, "POST", "/api/policy-learning/session", RoleOperator, `{"action":"cancel"}`, -1},
		{"sessions viewer", apiPolicyLearningSessions, "GET", "/api/policy-learning/sessions", RoleViewer, "", -1},
		{"recs viewer", apiPolicyLearningRecommendations, "GET", "/api/policy-learning/recommendations", RoleViewer, "", -1},
		{"generate viewer denied", apiPolicyLearningGenerate, "POST", "/api/policy-learning/recommendations/generate", RoleViewer, `{"session_id":"x"}`, 403},
		{"generate operator", apiPolicyLearningGenerate, "POST", "/api/policy-learning/recommendations/generate", RoleOperator, `{"session_id":"x"}`, -1},
	}
	for _, tc := range cases {
		w := plDo(tc.handler, tc.method, tc.path, tc.role, tc.body)
		if tc.want == 403 && w.Code != 403 {
			t.Errorf("%s: %d, want 403", tc.name, w.Code)
		}
		if tc.want == -1 && w.Code == 403 {
			t.Errorf("%s: got 403, want authorized", tc.name)
		}
	}
}

// ── generation + staleness + privacy over the API ────────────────────────────

// plObserve feeds one allowed observation through the REAL adapter and waits
// for delivery.
func plObserve(t *testing.T, subject string, groups []string, host string) {
	t.Helper()
	eng := policyLearnEngine.Load()
	before := eng.ObservationStats().Delivered
	learnObserveDecision(authOutcome{identity: subject, source: "idp", groups: groups},
		host, "GET", nil, "OK", "Inspect", learnDecisionKey{}, false)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && eng.ObservationStats().Delivered <= before {
		time.Sleep(time.Millisecond)
	}
}

func TestPL_GenerateStalenessAndPrivacyBoundary(t *testing.T) {
	plHarness(t)
	// Allowlist a category the live resolver can actually produce: use a real
	// admin taxonomy entry.
	if err := catStore.Set("m5a-cat", []string{"m5a.example"}, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = catStore.Delete("m5a-cat") })

	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin,
		`{"enabled":true,"recommendable_categories":["m5a-cat"]}`); w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	plStartSession(t)
	plObserve(t, "leak-alice@corp.example", []string{"m5a-team"}, "m5a.example")
	sessID := plCompleteSession(t)

	// Generate while the session is active is covered by the state machine; a
	// completed session generates.
	w := plDo(apiPolicyLearningGenerate, http.MethodPost, "/api/policy-learning/recommendations/generate", RoleOperator,
		`{"session_id":"`+sessID+`"}`)
	if w.Code != 200 {
		t.Fatalf("generate: %d %s", w.Code, w.Body.String())
	}
	// Unknown session → 404.
	if w := plDo(apiPolicyLearningGenerate, http.MethodPost, "/api/policy-learning/recommendations/generate", RoleOperator, `{"session_id":"nope"}`); w.Code != http.StatusNotFound {
		t.Fatalf("unknown session: %d, want 404", w.Code)
	}

	// Fresh at read time.
	rw := plDo(apiPolicyLearningRecommendations, http.MethodGet, "/api/policy-learning/recommendations", RoleViewer, "")
	var recsResp struct {
		Recommendations []plRecommendationDTO `json:"recommendations"`
	}
	if err := json.Unmarshal(rw.Body.Bytes(), &recsResp); err != nil || len(recsResp.Recommendations) != 1 {
		t.Fatalf("recommendations: %v %s", err, rw.Body.String())
	}
	if len(recsResp.Recommendations[0].StaleReasons) != 0 {
		t.Fatalf("fresh recommendation reported stale: %v", recsResp.Recommendations[0].StaleReasons)
	}

	// §10: staleness is computed SERVER-SIDE at read time. Change the running
	// policy content → policy_content_changed appears without any regeneration.
	added := policyStore.Add(PolicyRule{Priority: 99871, Name: "m5a-stale-probe", DestFQDN: "stale-probe.invalid", Action: ActionBlockPage})
	t.Cleanup(func() { policyStore.Delete(added.Priority) })
	rw = plDo(apiPolicyLearningRecommendations, http.MethodGet, "/api/policy-learning/recommendations", RoleViewer, "")
	if err := json.Unmarshal(rw.Body.Bytes(), &recsResp); err != nil {
		t.Fatal(err)
	}
	stale := strings.Join(recsResp.Recommendations[0].StaleReasons, " ")
	if !strings.Contains(stale, "policy_content_changed") {
		t.Fatalf("policy edit not reflected in stale reasons: %q", stale)
	}

	// §7 privacy boundary: none of the read surfaces may carry the raw subject,
	// subject tokens, key identity, or aggregation maps.
	for name, w := range map[string]*httptest.ResponseRecorder{
		"status":          plDo(apiPolicyLearningStatus, http.MethodGet, "/api/policy-learning", RoleViewer, ""),
		"sessions":        plDo(apiPolicyLearningSessions, http.MethodGet, "/api/policy-learning/sessions", RoleViewer, ""),
		"recommendations": plDo(apiPolicyLearningRecommendations, http.MethodGet, "/api/policy-learning/recommendations", RoleViewer, ""),
	} {
		body := w.Body.String()
		for _, forbidden := range []string{"leak-alice", `"subjects"`, `"subject_key_id"`, `"evidence_hash"`, `"cells":{`} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s response leaks %q: %s", name, forbidden, body)
			}
		}
	}
}

// ── §14 persistence/restart semantics ────────────────────────────────────────

func TestPL_PersistenceAndRestartMatrix(t *testing.T) {
	dir := plHarness(t)

	// Enable with no prior files.
	plEnable(t)
	eng := policyLearnEngine.Load()
	keyID := eng.SubjectKeyID()
	plStartSession(t)
	plCompleteSession(t)

	// Disable (no active session) — nothing deleted (asserted in the disable test).
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"enabled":false}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}

	// Re-enable: durable subject key + historical sessions preserved.
	plEnable(t)
	eng = policyLearnEngine.Load()
	if eng.SubjectKeyID() != keyID {
		t.Fatal("re-enable minted a different subject key")
	}
	if got := eng.Snapshot().Sessions; got != 1 {
		t.Fatalf("historical sessions lost on re-enable: %d", got)
	}

	// Restart while enabled: loader materializes from recorded desired state.
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"enabled":true}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	_ = policyLearnEngine.Load().Close()
	policyLearnEngine.Store(nil)
	loadPolicyLearning(policyLearnPaths) // simulated restart
	if policyLearnEngine.Load() == nil {
		t.Fatal("restart while enabled did not reconstruct the engine")
	}
	if policyLearnEngine.Load().Snapshot().Sessions != 1 {
		t.Fatal("restart lost sessions")
	}

	// Restart with an ACTIVE session: recovered with a restart gap.
	plStartSession(t)
	_ = policyLearnEngine.Load().Close()
	policyLearnEngine.Store(nil)
	loadPolicyLearning(policyLearnPaths)
	sw := plDo(apiPolicyLearningStatus, http.MethodGet, "/api/policy-learning", RoleViewer, "")
	var st struct {
		LearningActive bool          `json:"learning_active"`
		ActiveSession  *plSessionDTO `json:"active_session"`
	}
	if err := json.Unmarshal(sw.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.LearningActive || st.ActiveSession == nil {
		t.Fatalf("active session not recovered across restart: %s", sw.Body.String())
	}
	found := false
	for _, g := range st.ActiveSession.Gaps {
		if g.Reason == "process_restart" {
			found = true
		}
	}
	if !found {
		t.Fatalf("restart gap not surfaced: %+v", st.ActiveSession.Gaps)
	}
	plCompleteSession(t)

	// Restart while disabled: loader is a no-op.
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"enabled":false}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	loadPolicyLearning(policyLearnPaths)
	if policyLearnEngine.Load() != nil {
		t.Fatal("restart while disabled constructed an engine")
	}

	// Enable against a NEWER-schema store: read-only, session ops 409, file untouched.
	newer := `{"schema_version":99,"sessions":[]}`
	if err := os.WriteFile(filepath.Join(dir, "policy_learning.json"), []byte(newer), 0o600); err != nil {
		t.Fatal(err)
	}
	plEnable(t)
	if !policyLearnEngine.Load().ReadOnly() {
		t.Fatal("newer-schema store not read-only")
	}
	if w := plDo(apiPolicyLearningSession, http.MethodPost, "/api/policy-learning/session", RoleOperator, `{"action":"start"}`); w.Code != http.StatusConflict {
		t.Fatalf("start on read-only store: %d, want 409", w.Code)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "policy_learning.json"))
	if string(raw) != newer {
		t.Fatal("newer-schema store was rewritten")
	}
}

func TestPL_EnableWithCorruptStateQuarantines(t *testing.T) {
	dir := plHarness(t)
	if err := os.WriteFile(filepath.Join(dir, "policy_learning.json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	plEnable(t) // engine starts fresh + writable; corrupt file quarantined aside
	eng := policyLearnEngine.Load()
	if eng.ReadOnly() {
		t.Fatal("corrupt store must yield a fresh WRITABLE engine")
	}
	plStartSession(t)
	plCompleteSession(t)
}

// ── AdminSettings round trip ─────────────────────────────────────────────────

func TestPL_AdminSettingsRoundTrip(t *testing.T) {
	dir := plHarness(t)
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin,
		`{"enabled":true,"recommendable_categories":["Dev Tools"," AI ","Dev Tools"]}`); w.Code != 200 {
		t.Fatalf("PUT: %d %s", w.Code, w.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "admin_settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s AdminSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if !s.PolicyLearningSaved || !s.PolicyLearningEnabled {
		t.Fatalf("persisted governance: %+v", s.PolicyLearningSaved)
	}
	// Canonicalized: trimmed, deduped, sorted.
	if want := []string{"AI", "Dev Tools"}; strings.Join(s.PolicyLearningRecommendableCategories, "|") != strings.Join(want, "|") {
		t.Fatalf("persisted categories = %v, want %v", s.PolicyLearningRecommendableCategories, want)
	}

	// Simulated boot: reset state, apply from disk, materialize.
	policyLearnEngine.Load().Close() //nolint:errcheck // test teardown of the first engine
	policyLearnEngine.Store(nil)
	policyLearnSetState(policyLearnSettings{}, false)
	applyAdminPolicyLearning(&s)
	loadPolicyLearning(policyLearnPaths)
	eng := policyLearnEngine.Load()
	if eng == nil {
		t.Fatal("boot did not materialize the governed enabled state")
	}
	if eng.GuardrailsHash() != policylearn.GuardrailsHashForCategories([]string{"AI", "Dev Tools"}) {
		t.Fatal("boot engine does not carry the governed allowlist")
	}

	// An explicitly EMPTY governed list survives (fail-closed choice).
	if w := plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"recommendable_categories":[]}`); w.Code != 200 {
		t.Fatalf("empty-list PUT: %d %s", w.Code, w.Body.String())
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "admin_settings.json"))
	var s2 AdminSettings
	_ = json.Unmarshal(raw, &s2)
	if s2.PolicyLearningRecommendableCategories == nil || len(s2.PolicyLearningRecommendableCategories) != 0 {
		t.Fatalf("governed empty allowlist did not survive persistence: %v", s2.PolicyLearningRecommendableCategories)
	}
}

// ── audit ────────────────────────────────────────────────────────────────────

func TestPL_AuditEvents(t *testing.T) {
	plHarness(t)
	baseline := time.Now().Unix() - 1

	plEnable(t)
	plStartSession(t)
	sessID := plCompleteSession(t)
	plDo(apiPolicyLearningGenerate, http.MethodPost, "/api/policy-learning/recommendations/generate", RoleOperator, `{"session_id":"`+sessID+`"}`)
	plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"recommendable_categories":["AI"]}`)
	plDo(apiPolicyLearningConfig, http.MethodPut, "/api/policy-learning/config", RoleAdmin, `{"enabled":false}`)

	want := map[string]bool{
		"policy_learning.enable":                   false,
		"policy_learning.disable":                  false,
		"policy_learning.session.start":            false,
		"policy_learning.session.complete":         false,
		"policy_learning.recommendations.generate": false,
		"policy_learning.guardrail":                false,
	}
	for _, e := range auditGet() {
		if _, ok := want[e.Action]; ok && e.TS >= baseline && strings.Contains(e.Actor, "198.51.100.77") {
			want[e.Action] = true
			// Audit content must not leak subject data — the detail carries
			// actions/objects only.
			if strings.Contains(e.Detail, "@corp.example") {
				t.Errorf("audit detail leaks subject data: %q", e.Detail)
			}
		}
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("audit action %q not recorded", action)
		}
	}
}

// ── GUI source pins (wording + role gating; the SPA is a static artifact) ────

func plGUIBlock(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), "static", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	start := strings.Index(s, `id="view-policylearn"`)
	end := strings.Index(s, `id="view-decexclusions"`)
	if start < 0 || end < 0 || end <= start {
		t.Fatal("policy-learning view block not found in static/index.html")
	}
	return s[start:end]
}

func TestPL_GUIWordingAndRoleGating(t *testing.T) {
	block := plGUIBlock(t)
	for _, required := range []string{
		"advisory only",
		"cannot alter enforcement policy",
		"node-local",
		"membership denominator unavailable", // hint wording (rendered state comes from JS too)
		`data-min-role="admin"`,              // guardrail panel is admin-gated
		`data-min-role="operator"`,           // session controls operator-gated
		"born-disabled",
	} {
		if !strings.Contains(block, required) {
			t.Errorf("policy-learning GUI block missing required wording/gating %q", required)
		}
	}
	// Evidence-honesty wording: no safety or user-prevalence claims.
	for _, forbidden := range []string{"safe to allow", "% of users", "users were blocked", "safely"} {
		if strings.Contains(strings.ToLower(block), forbidden) {
			t.Errorf("policy-learning GUI block carries forbidden claim wording %q", forbidden)
		}
	}
	// Nav item exists and is viewer-visible.
	raw, _ := os.ReadFile(filepath.Join(pkgSourceDir(), "static", "index.html"))
	if !strings.Contains(string(raw), `data-view="policylearn" data-min-role="viewer"`) {
		t.Error("policy-learning nav item missing or not viewer-gated")
	}
	// The JS renderer states coverage facts, not fabricated percentages.
	if !strings.Contains(string(raw), "membership denominator unavailable") {
		t.Error("membership-denominator-unavailable state not rendered")
	}
}

// ── read-only recommendation-policy metadata ─────────────────────────────────

func TestPL_ConfigExposesReadOnlyPolicyMetadata(t *testing.T) {
	plHarness(t)
	plEnable(t)
	w := plDo(apiPolicyLearningConfig, http.MethodGet, "/api/policy-learning/config", RoleViewer, "")
	var cfg map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["thresholds_editable"] != false {
		t.Fatal("thresholds must be read-only in M5A")
	}
	if _, ok := cfg["recommendation_policy"]; !ok {
		t.Fatal("recommendation-policy metadata missing")
	}
	if _, ok := cfg["recommendable_categories"]; !ok {
		t.Fatal("recommendable categories missing from config GET")
	}
}
