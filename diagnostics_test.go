package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withCachedStorageState saves and restores both dataDir and the cached
// writability state so a test can drive the cache without leaking into
// neighbours. Call from any test that mutates either.
func withCachedStorageState(t *testing.T) {
	t.Helper()
	prevDir := dataDir
	prevState := storageWritableState.Load()
	t.Cleanup(func() {
		dataDir = prevDir
		if prevState == nil {
			// atomic.Value cannot be cleared once written; store the
			// "unknown" sentinel so storageWritability() reports the
			// pre-test default.
			storageWritableState.Store(storageStateUnknown)
		} else {
			storageWritableState.Store(prevState)
		}
	})
}

// primeWritable points dataDir at a fresh tempdir and runs the probe so
// the cache reports writable. Used by tests that need the diagnostics
// "default OK" baseline.
func primeWritable(t *testing.T) string {
	t.Helper()
	withCachedStorageState(t)
	dir := t.TempDir()
	dataDir = dir
	probeStorageWritability()
	if got := storageWritability(); got != storageStateWritable {
		t.Fatalf("primeWritable: cache = %q, want %q", got, storageStateWritable)
	}
	return dir
}

// viewerCtx attaches RoleViewer to the request context — the minimum role
// /api/diagnostics requires.
func viewerCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleViewer)
	return r.WithContext(ctx)
}

// noRoleCtx attaches a role that does NOT satisfy RoleViewer so we can
// exercise the requireRole(RoleViewer) failure path. UIRole("none") has
// rolePriority 0, below RoleViewer's 1.
func noRoleCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), uiRoleKey{}, UIRole("none"))
	return r.WithContext(ctx)
}

// decodeContract parses the response body into an OperatorContract value.
// Tests use this to assert structure without re-parsing maps each time.
func decodeContract(t *testing.T, w *httptest.ResponseRecorder) OperatorContract {
	t.Helper()
	var c OperatorContract
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatalf("response is not a valid OperatorContract: %v; body=%s", err, w.Body.String())
	}
	return c
}

// assertCheckShape validates one OperatorContractCheck row's required
// fields and status invariants. Extracted from TestApiDiagnostics_DefaultOK
// so the test stays under the project's cyclop=15 threshold.
func assertCheckShape(t *testing.T, idx int, ck OperatorContractCheck) {
	t.Helper()
	if ck.Code == "" {
		t.Errorf("check[%d] has empty code", idx)
	}
	if ck.Message == "" {
		t.Errorf("check[%d] (%s) has empty message", idx, ck.Code)
	}
	switch ck.Status {
	case diagOK:
	case diagWarn, diagFail:
		if ck.OperatorAction == "" {
			t.Errorf("check %s is %s but operator_action is empty", ck.Code, ck.Status)
		}
	default:
		t.Errorf("check %s has invalid status %q", ck.Code, ck.Status)
	}
}

func TestApiDiagnostics_DefaultOK(t *testing.T) {
	primeWritable(t) // baseline expects storage_path=ok
	r := viewerCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody))
	w := httptest.NewRecorder()

	apiDiagnostics(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	c := decodeContract(t, w)

	switch c.Verdict {
	case diagOK, diagWarn, diagFail:
	default:
		t.Errorf("verdict = %q, want one of ok/warn/fail", c.Verdict)
	}
	if c.GeneratedAt == "" {
		t.Error("generated_at is empty")
	}
	if len(c.Checks) == 0 {
		t.Fatal("checks slice is empty")
	}

	// Every check must populate the required fields and use a known status.
	requiredCodes := map[string]bool{
		"storage_path":              false,
		"policy_loaded":             false,
		"root_ca":                   false,
		"session_secret":            false,
		"cdr":                       false,
		"cluster_posture":           false,
		"unauth_mode":               false,
		"updater_url":               false,
		"config_snapshot_validator": false,
	}
	for i := range c.Checks {
		assertCheckShape(t, i, c.Checks[i])
		if _, ok := requiredCodes[c.Checks[i].Code]; ok {
			requiredCodes[c.Checks[i].Code] = true
		}
	}
	for code, seen := range requiredCodes {
		if !seen {
			t.Errorf("expected check %q in default report", code)
		}
	}
}

func TestApiDiagnostics_WarnsOnClusterInsecure(t *testing.T) {
	// Snapshot + restore the globals we mutate so this test is hermetic.
	prevInsecure := clusterInsecure
	clusterRoleMu.Lock()
	prevRole := clusterRole.role
	clusterRole.role = "control-plane"
	clusterRoleMu.Unlock()
	clusterInsecure = true
	t.Cleanup(func() {
		clusterRoleMu.Lock()
		clusterRole.role = prevRole
		clusterRoleMu.Unlock()
		clusterInsecure = prevInsecure
	})

	r := viewerCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody))
	w := httptest.NewRecorder()
	apiDiagnostics(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	c := decodeContract(t, w)

	var found *OperatorContractCheck
	for i := range c.Checks {
		if c.Checks[i].Code == "cluster_posture" {
			found = &c.Checks[i]
			break
		}
	}
	if found == nil {
		t.Fatal("cluster_posture check missing")
	}
	if found.Status != diagWarn {
		t.Errorf("cluster_posture status = %q, want warn (clusterInsecure must NOT escalate to fail)", found.Status)
	}
	if found.OperatorAction == "" {
		t.Error("cluster_posture warn must include operator_action explaining how to harden")
	}
	if c.Verdict == diagFail {
		t.Error("top-level verdict escalated to fail; clusterInsecure must remain a warn")
	}
}

func TestApiDiagnostics_RoleGated(t *testing.T) {
	// Insufficient role → 403.
	r := noRoleCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody))
	w := httptest.NewRecorder()
	apiDiagnostics(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("no-role status = %d, want 403", w.Code)
	}

	// Viewer role → 200.
	r2 := viewerCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody))
	w2 := httptest.NewRecorder()
	apiDiagnostics(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("viewer status = %d, want 200; body=%s", w2.Code, w2.Body.String())
	}

	// Wrong method → 405.
	r3 := viewerCtx(httptest.NewRequest(http.MethodPost, "/api/diagnostics", http.NoBody))
	w3 := httptest.NewRecorder()
	apiDiagnostics(w3, r3)
	if w3.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", w3.Code)
	}
}

func TestApiDiagnostics_NoSideEffects(t *testing.T) {
	// The handler must not mutate observable state. We sample three
	// reads of state-version counters across calls and assert none of
	// them advanced.
	policyVerBefore, _ := policyStore.policyVersion()
	cdrEpochBefore := cdrPolicyStore.Epoch()

	for i := 0; i < 3; i++ {
		r := viewerCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody))
		w := httptest.NewRecorder()
		apiDiagnostics(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("iter %d: status = %d", i, w.Code)
		}
	}

	policyVerAfter, _ := policyStore.policyVersion()
	cdrEpochAfter := cdrPolicyStore.Epoch()

	if policyVerBefore != policyVerAfter {
		t.Errorf("policy version mutated by handler: %d → %d", policyVerBefore, policyVerAfter)
	}
	if cdrEpochBefore != cdrEpochAfter {
		t.Errorf("cdr epoch mutated by handler: %d → %d", cdrEpochBefore, cdrEpochAfter)
	}
}

// TestApiDiagnostics_DegradedCDRNoPanic exercises the "enabled but no
// instances" branch of checkCDR to confirm the report renders a
// well-formed warn/fail entry rather than panicking.
func TestApiDiagnostics_DegradedCDRNoPanic(t *testing.T) {
	prev := cdrActiveCfg
	cdrClientMu.Lock()
	cdrActiveCfg = CDRConfig{Enabled: true} // no FailMode, no DefaultProfile, empty pool
	cdrClientMu.Unlock()
	t.Cleanup(func() {
		cdrClientMu.Lock()
		cdrActiveCfg = prev
		cdrClientMu.Unlock()
	})

	// Build the contract directly so a panic surfaces as a test failure
	// rather than being swallowed by the HTTP recorder.
	c := buildOperatorContract()

	var found *OperatorContractCheck
	for i := range c.Checks {
		if c.Checks[i].Code == "cdr" {
			found = &c.Checks[i]
			break
		}
	}
	if found == nil {
		t.Fatal("cdr check missing from degraded report")
	}
	if found.Status != diagFail && found.Status != diagWarn {
		t.Errorf("cdr status = %q, want warn or fail in degraded mode", found.Status)
	}
	if found.OperatorAction == "" {
		t.Error("degraded CDR check must include operator_action")
	}
}

// TestApiDiagnostics_NoSensitiveValues is a guardrail: the report must
// never include the session secret, full updater URL, IdP tokens, file
// paths, or other operator secrets. New checks that need to display
// sensitive data must redact at the API boundary, not in the SPA.
func TestApiDiagnostics_NoSensitiveValues(t *testing.T) {
	// Plant a recognisable sentinel into globals the report inspects so
	// that, if a future change leaks them, this test fails loudly.
	prevURL := updaterURL
	prevAllow := append([]string(nil), updaterURLAllowlist...)
	updaterURL = "https://leaky.example.invalid/secret-path"
	updaterURLAllowlist = []string{updaterURL}
	t.Cleanup(func() {
		updaterURL = prevURL
		updaterURLAllowlist = prevAllow
	})

	r := viewerCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody))
	w := httptest.NewRecorder()
	apiDiagnostics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	body := w.Body.String()
	forbidden := []string{
		"leaky.example.invalid", // raw updater URL
		"secret-path",           // raw updater URL path
		"sessionSecret",         // Go symbol leak
		"CULVERT_SESSION_SECRET",
		"-----BEGIN",            // PEM material
		"/data/",                // raw filesystem paths
	}
	for _, needle := range forbidden {
		if strings.Contains(body, needle) {
			t.Errorf("response leaked sensitive token %q; body=%s", needle, body)
		}
	}

	// The session-secret check must remain boolean-only — no hex digest.
	for _, ck := range decodeContract(t, w).Checks {
		if ck.Code != "session_secret" {
			continue
		}
		// 32 bytes hex would be 64 chars — easy heuristic to spot a leak.
		if hasLongHexRun(ck.Message) || hasLongHexRun(ck.OperatorAction) {
			t.Errorf("session_secret check appears to leak secret material: %+v", ck)
		}
	}
}

// hasLongHexRun returns true when s contains a run of 32+ contiguous hex
// characters — a cheap heuristic for accidentally-included key material.
func hasLongHexRun(s string) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if isHex {
			run++
			if run >= 32 {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// ── storage writability probe ─────────────────────────────────────────────

func TestProbeStorageWritability_Writable(t *testing.T) {
	withCachedStorageState(t)
	dataDir = t.TempDir()

	probeStorageWritability()

	if got := storageWritability(); got != storageStateWritable {
		t.Errorf("got %q, want %q", got, storageStateWritable)
	}
	// The probe must clean up after itself — no leftover temp files.
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".culvert-writability-probe-") {
			t.Errorf("probe left temp file behind: %s", e.Name())
		}
	}

	// checkStorage must report ok with a non-empty message.
	ck := checkStorage()
	if ck.Status != diagOK {
		t.Errorf("checkStorage status = %q, want ok", ck.Status)
	}
	if ck.Message == "" {
		t.Error("checkStorage message is empty")
	}
}

func TestProbeStorageWritability_Unwritable(t *testing.T) {
	withCachedStorageState(t)
	// Point at a path whose parent does not exist. os.CreateTemp fails
	// with ENOENT — robust against the test running as root (chmod
	// would not be enforced for uid 0).
	dataDir = filepath.Join(t.TempDir(), "deliberately", "missing", "subdir")

	probeStorageWritability()

	if got := storageWritability(); got != storageStateUnwritable {
		t.Errorf("got %q, want %q", got, storageStateUnwritable)
	}
	ck := checkStorage()
	if ck.Status != diagFail {
		t.Errorf("checkStorage status = %q, want fail", ck.Status)
	}
	if ck.OperatorAction == "" {
		t.Error("checkStorage operator_action is empty for fail")
	}
}

func TestProbeStorageWritability_NoDataDir(t *testing.T) {
	withCachedStorageState(t)
	dataDir = ""

	probeStorageWritability()

	if got := storageWritability(); got != storageStateUnknown {
		t.Errorf("got %q, want %q", got, storageStateUnknown)
	}
	ck := checkStorage()
	if ck.Status != diagWarn {
		t.Errorf("checkStorage status = %q, want warn", ck.Status)
	}
	if ck.OperatorAction == "" {
		t.Error("checkStorage operator_action is empty for warn")
	}
}

// TestApiDiagnostics_NoIOOnRepeatedCalls proves the handler does not
// re-probe storage on every call. We probe once against a tempdir, then
// remove the directory and call apiDiagnostics ten times. The cached
// "writable" verdict must persist — a real I/O probe would now see the
// missing directory and downgrade to fail.
func TestApiDiagnostics_NoIOOnRepeatedCalls(t *testing.T) {
	withCachedStorageState(t)
	dir := t.TempDir()
	dataDir = dir
	probeStorageWritability()
	if got := storageWritability(); got != storageStateWritable {
		t.Fatalf("setup: cache = %q, want writable", got)
	}

	// Make subsequent disk access impossible: replace the directory with
	// nothing. CreateTemp on this path would now fail.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	for i := 0; i < 10; i++ {
		r := viewerCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody))
		w := httptest.NewRecorder()
		apiDiagnostics(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("iter %d: status = %d", i, w.Code)
		}
		c := decodeContract(t, w)
		var found *OperatorContractCheck
		for j := range c.Checks {
			if c.Checks[j].Code == "storage_path" {
				found = &c.Checks[j]
				break
			}
		}
		if found == nil {
			t.Fatalf("iter %d: storage_path missing", i)
		}
		if found.Status != diagOK {
			t.Errorf("iter %d: storage_path status = %q, want ok (handler re-probed disk!)", i, found.Status)
		}
	}
}
