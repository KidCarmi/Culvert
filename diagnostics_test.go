package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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
		"storage_path":               false,
		"policy_loaded":              false,
		"root_ca":                    false,
		"session_secret":             false,
		"cdr":                        false,
		"cluster_posture":            false,
		"saml_state_posture":         false,
		"saml_base_url":              false,
		"unauth_mode":                false,
		"yara_engine_posture":        false,
		"updater_url":                false,
		"config_snapshot_validator":  false,
		"config_versions_present":    false,
		"config_versions_readable":   false,
		"config_rollback_validation": false,
		"key_at_rest":                false,
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

func findDiagnosticCheck(c OperatorContract, code string) *OperatorContractCheck {
	for i := range c.Checks {
		if c.Checks[i].Code == code {
			return &c.Checks[i]
		}
	}
	return nil
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

func TestApiDiagnostics_WarnsOnClusteredSAMLState(t *testing.T) {
	prevRegistry := idpRegistry
	prevInsecure := clusterInsecure
	clusterRoleMu.Lock()
	prevRole := clusterRole.role
	clusterRole.role = "data-plane"
	clusterRoleMu.Unlock()
	clusterInsecure = false
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{{ID: "saml-diag", Name: "SAML", Type: IdPTypeSAML, Enabled: true}},
		live: map[string]IdentityProvider{
			"saml-diag": &SAMLProvider{profile: &IdPProfile{ID: "saml-diag", Type: IdPTypeSAML}},
		},
	}
	t.Cleanup(func() {
		idpRegistry = prevRegistry
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
	found := findDiagnosticCheck(c, "saml_state_posture")
	if found == nil {
		t.Fatal("saml_state_posture check missing")
	}
	if found.Status != diagWarn {
		t.Fatalf("saml_state_posture status = %q, want warn", found.Status)
	}
	if !strings.Contains(found.OperatorAction, "load-balancer affinity") {
		t.Fatalf("operator_action = %q, want load-balancer affinity guidance", found.OperatorAction)
	}
	if c.Verdict == diagFail {
		t.Fatal("clustered SAML state warning must not escalate diagnostics verdict to fail")
	}
}

func withEnabledSAMLDiagnosticProfile(t *testing.T) {
	t.Helper()
	prevRegistry := idpRegistry
	prevBaseURL := cfg.ProxyBaseURL()
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{{ID: "saml-diag", Name: "SAML", Type: IdPTypeSAML, Enabled: true}},
		live:     map[string]IdentityProvider{},
	}
	t.Cleanup(func() {
		idpRegistry = prevRegistry
		SetProxyBaseURL(prevBaseURL)
	})
}

func TestSAMLBaseURLPostureWarnsWhenUnset(t *testing.T) {
	withEnabledSAMLDiagnosticProfile(t)
	SetProxyBaseURL("")

	found := checkSAMLBaseURLPosture()
	if found.Status != diagWarn {
		t.Fatalf("saml_base_url status = %q, want warn", found.Status)
	}
	if !strings.Contains(found.Message, "proxy.base_url is unset") {
		t.Fatalf("message = %q, want unset base_url guidance", found.Message)
	}
	if !strings.Contains(found.OperatorAction, "/auth/saml/callback") {
		t.Fatalf("operator_action = %q, want ACS callback guidance", found.OperatorAction)
	}
}

func TestSAMLBaseURLPostureWarnsOnLocalhost(t *testing.T) {
	withEnabledSAMLDiagnosticProfile(t)
	SetProxyBaseURL("https://localhost:9090")

	found := checkSAMLBaseURLPosture()
	if found.Status != diagWarn {
		t.Fatalf("saml_base_url status = %q, want warn", found.Status)
	}
	if !strings.Contains(found.Message, "localhost") {
		t.Fatalf("message = %q, want localhost guidance", found.Message)
	}
}

func TestSAMLBaseURLPostureOKForExternalHTTPS(t *testing.T) {
	withEnabledSAMLDiagnosticProfile(t)
	SetProxyBaseURL("https://proxy.example.com/culvert")

	found := checkSAMLBaseURLPosture()
	if found.Status != diagOK {
		t.Fatalf("saml_base_url status = %q, want ok; action=%q", found.Status, found.OperatorAction)
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
		"-----BEGIN", // PEM material
		"/data/",     // raw filesystem paths
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

// ── config-version diagnostics ────────────────────────────────────────────

// writeConfigVersionFile writes a v{N}.json envelope into dir using the
// same shape saveConfigVersion produces. Used by tests to seed disk
// state without invoking the writer (which would touch the production
// /data/config_versions path).
func writeConfigVersionFile(t *testing.T, dir string, version int, body any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	path := filepath.Join(dir, "v"+strconv.Itoa(version)+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// validEnvelope builds a {meta, config} envelope that parses cleanly,
// passes envelope-shape checks, and produces no validateConfigBackup
// warnings. JSON tag names match the configBackup struct in ui_policy.go.
func validEnvelope(version int) map[string]any {
	return map[string]any{
		"meta": map[string]any{
			"version":    version,
			"created_at": "2026-04-26T00:00:00Z",
			"actor":      "test",
			"action":     "test.seed",
		},
		"config": map[string]any{
			"version":       1,
			"exportedAt":    "2026-04-26T00:00:00Z",
			"blocklistMode": "block",
			"defaultAction": "block",
			"ipFilterMode":  "block",
			"rateLimitRPM":  60,
		},
	}
}

func TestConfigVersionsCheck_NoVersions(t *testing.T) {
	dir := t.TempDir()

	sum := summarizeLatestConfigVersionAt(dir)
	if sum.Found {
		t.Fatalf("Found = true on empty dir; sum=%+v", sum)
	}
	if !sum.DirAccessible {
		t.Errorf("DirAccessible = false on existing empty dir")
	}

	if got := checkConfigVersionsPresent(sum); got.Status != diagWarn {
		t.Errorf("present status = %q, want warn", got.Status)
	} else if got.OperatorAction == "" {
		t.Error("present warn must include operator_action")
	}

	// The other two checks should NOT cascade — they return ok because
	// the present-check already surfaced the root cause.
	if got := checkConfigVersionsReadable(sum); got.Status != diagOK {
		t.Errorf("readable status = %q, want ok (no version to read)", got.Status)
	}
	if got := checkConfigRollbackValidation(sum); got.Status != diagOK {
		t.Errorf("rollback_validation status = %q, want ok (nothing to validate)", got.Status)
	}
}

func TestConfigVersionsCheck_LatestValid(t *testing.T) {
	dir := t.TempDir()
	writeConfigVersionFile(t, dir, 1, validEnvelope(1))

	sum := summarizeLatestConfigVersionAt(dir)
	if !sum.Found || sum.LatestVersion != 1 || sum.Count != 1 {
		t.Fatalf("summary=%+v, want Found=true LatestVersion=1 Count=1", sum)
	}
	if sum.LoadErr != nil || sum.BadShape {
		t.Fatalf("summary=%+v, want clean parse", sum)
	}
	if len(sum.Warnings) != 0 {
		t.Errorf("Warnings=%v, want empty", sum.Warnings)
	}

	for _, ck := range []OperatorContractCheck{
		checkConfigVersionsPresent(sum),
		checkConfigVersionsReadable(sum),
		checkConfigRollbackValidation(sum),
	} {
		if ck.Status != diagOK {
			t.Errorf("%s status = %q, want ok", ck.Code, ck.Status)
		}
	}
}

func TestConfigVersionsCheck_LatestCorrupt(t *testing.T) {
	dir := t.TempDir()
	// Valid v1, corrupt v2 — the latest should be selected and reported.
	writeConfigVersionFile(t, dir, 1, validEnvelope(1))
	if err := os.WriteFile(filepath.Join(dir, "v2.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	sum := summarizeLatestConfigVersionAt(dir)
	if sum.LatestVersion != 2 {
		t.Fatalf("LatestVersion = %d, want 2 (corrupt file should still be the latest by number)", sum.LatestVersion)
	}
	if sum.LoadErr == nil {
		t.Fatal("LoadErr nil, want non-nil")
	}

	if got := checkConfigVersionsReadable(sum); got.Status != diagFail {
		t.Errorf("readable status = %q, want fail", got.Status)
	} else if got.OperatorAction == "" {
		t.Error("readable fail must include operator_action")
	}
	if got := checkConfigRollbackValidation(sum); got.Status != diagFail {
		t.Errorf("rollback_validation status = %q, want fail (parse failure)", got.Status)
	}
}

func TestConfigVersionsCheck_LatestBadShape(t *testing.T) {
	dir := t.TempDir()
	// Parses as JSON but is missing the meta block — the envelope-shape
	// guard should catch this and report fail.
	noMeta := map[string]any{
		"config": map[string]any{"blocklist_mode": "block"},
	}
	writeConfigVersionFile(t, dir, 1, noMeta)

	sum := summarizeLatestConfigVersionAt(dir)
	if !sum.BadShape {
		t.Fatalf("BadShape = false; sum=%+v", sum)
	}
	if got := checkConfigVersionsReadable(sum); got.Status != diagFail {
		t.Errorf("readable status = %q, want fail (bad envelope shape)", got.Status)
	}
}

func TestConfigVersionsCheck_ValidationWarning(t *testing.T) {
	dir := t.TempDir()
	// Parses cleanly, envelope is well-shaped, but blocklist_mode is
	// invalid — validateConfigBackup should return one warning and the
	// rollback_validation check should report warn (not fail).
	env := validEnvelope(1)
	env["config"].(map[string]any)["blocklistMode"] = "not-a-mode"
	writeConfigVersionFile(t, dir, 1, env)

	sum := summarizeLatestConfigVersionAt(dir)
	if sum.LoadErr != nil || sum.BadShape {
		t.Fatalf("expected clean parse; sum=%+v", sum)
	}
	if len(sum.Warnings) == 0 {
		t.Fatal("validateConfigBackup returned no warnings; expected at least one")
	}

	if got := checkConfigRollbackValidation(sum); got.Status != diagWarn {
		t.Errorf("rollback_validation status = %q, want warn", got.Status)
	} else if got.OperatorAction == "" {
		t.Error("rollback_validation warn must include operator_action")
	} else if strings.Contains(got.Message, "not-a-mode") {
		t.Error("rollback_validation message leaked the raw invalid value")
	}
}

func TestConfigVersionsCheck_LatestSelectionByNumber(t *testing.T) {
	dir := t.TempDir()
	// Write v3 first, then v10, then v2. Latest must be v10 strictly by
	// numeric version — never by file creation/mtime order.
	writeConfigVersionFile(t, dir, 3, validEnvelope(3))
	writeConfigVersionFile(t, dir, 10, validEnvelope(10))
	writeConfigVersionFile(t, dir, 2, validEnvelope(2))

	sum := summarizeLatestConfigVersionAt(dir)
	if sum.LatestVersion != 10 {
		t.Errorf("LatestVersion = %d, want 10", sum.LatestVersion)
	}
	if sum.Count != 3 {
		t.Errorf("Count = %d, want 3", sum.Count)
	}
}

// TestConfigVersionsCheck_NoSideEffects asserts the diagnostics path
// performs no writes against configVersionsDir: snapshots the seeded
// directory before and after repeated calls and requires the listing to
// match exactly (no new probe files, no removed versions).
func TestConfigVersionsCheck_NoSideEffects(t *testing.T) {
	dir := t.TempDir()
	writeConfigVersionFile(t, dir, 1, validEnvelope(1))
	writeConfigVersionFile(t, dir, 2, validEnvelope(2))

	snapshot := func() []string {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return names
	}
	before := snapshot()

	for i := 0; i < 5; i++ {
		sum := summarizeLatestConfigVersionAt(dir)
		// Exercise all three checks each iteration so any of them
		// accidentally touching the dir would be caught.
		_ = checkConfigVersionsPresent(sum)
		_ = checkConfigVersionsReadable(sum)
		_ = checkConfigRollbackValidation(sum)
	}

	after := snapshot()
	if len(before) != len(after) {
		t.Errorf("dir entry count changed: before=%v after=%v", before, after)
	}
	for i := range before {
		if i >= len(after) || before[i] != after[i] {
			t.Errorf("dir contents changed: before=%v after=%v", before, after)
			return
		}
	}
}

// TestConfigVersionsCheck_NoBackupContentLeak ensures the diagnostics
// output does not echo raw backup contents (rule names, IP addresses,
// mode strings) when validateConfigBackup flags warnings.
func TestConfigVersionsCheck_NoBackupContentLeak(t *testing.T) {
	dir := t.TempDir()
	env := validEnvelope(1)
	cfg := env["config"].(map[string]any)
	// Plant several recognisable sentinels that, if leaked, will be
	// trivial to detect in the JSON output.
	cfg["blocklistMode"] = "leaky-sentinel-mode"
	cfg["defaultAction"] = "leaky-sentinel-action"
	writeConfigVersionFile(t, dir, 1, env)

	sum := summarizeLatestConfigVersionAt(dir)
	checks := []OperatorContractCheck{
		checkConfigVersionsPresent(sum),
		checkConfigVersionsReadable(sum),
		checkConfigRollbackValidation(sum),
	}
	body, err := json.Marshal(checks)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, needle := range []string{"leaky-sentinel-mode", "leaky-sentinel-action"} {
		if strings.Contains(string(body), needle) {
			t.Errorf("config-version checks leaked backup content %q; body=%s", needle, body)
		}
	}
}

// ── failure-mode validation matrix (PR #159) ──────────────────────────────
//
// These tests pin specific failure modes for the operator-contract
// surface, complementing the readiness tests in misc_test.go. The matrix
// (scenario / expected / test name) is documented in the PR body.

// TestApiDiagnostics_SessionSecretMissingFail — Scenario 1, diagnostics
// side. Companion to TestHandleReady_SessionSecretMissing503 in
// misc_test.go which covers the readiness side. Asserts that, with no
// admin session HMAC initialised, /api/diagnostics returns 200 (the
// endpoint itself is healthy and responsive) but the session_secret
// row reports fail with a non-empty operator_action.
func TestApiDiagnostics_SessionSecretMissingFail(t *testing.T) {
	prev := sessionSecret
	sessionSecret = nil
	t.Cleanup(func() { sessionSecret = prev })

	r := viewerCtx(httptest.NewRequest(http.MethodGet, "/api/diagnostics", http.NoBody))
	w := httptest.NewRecorder()
	apiDiagnostics(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (handler stays responsive)", w.Code)
	}
	c := decodeContract(t, w)
	var found *OperatorContractCheck
	for i := range c.Checks {
		if c.Checks[i].Code == "session_secret" {
			found = &c.Checks[i]
			break
		}
	}
	if found == nil {
		t.Fatal("session_secret check missing from report")
	}
	if found.Status != diagFail {
		t.Errorf("session_secret status = %q, want fail", found.Status)
	}
	if found.OperatorAction == "" {
		t.Error("session_secret fail must include operator_action")
	}
}

// TestApiDiagnostics_EmptyPolicyWarn — Scenario 3, diagnostics side.
// Explicit assertion that policy_loaded surfaces as warn (not fail)
// when the ruleset is empty. The default test process has policyStore
// at version 0 / no rules; this test snapshots and restores the store
// so it is hermetic regardless of run order with future policy tests.
func TestApiDiagnostics_EmptyPolicyWarn(t *testing.T) {
	policyStore.mu.Lock()
	prevRules := policyStore.rules
	prevVersion := policyStore.version
	prevUpdated := policyStore.updatedAt
	policyStore.rules = nil
	policyStore.version = 0
	policyStore.updatedAt = ""
	policyStore.mu.Unlock()
	t.Cleanup(func() {
		policyStore.mu.Lock()
		policyStore.rules = prevRules
		policyStore.version = prevVersion
		policyStore.updatedAt = prevUpdated
		policyStore.mu.Unlock()
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
		if c.Checks[i].Code == "policy_loaded" {
			found = &c.Checks[i]
			break
		}
	}
	if found == nil {
		t.Fatal("policy_loaded check missing from report")
	}
	if found.Status != diagWarn {
		t.Errorf("policy_loaded status = %q, want warn (empty ruleset must NOT escalate to fail — default-deny is a valid Zero-Trust posture)", found.Status)
	}
	if found.OperatorAction == "" {
		t.Error("policy_loaded warn must include operator_action")
	}
	// Belt and braces: top-level verdict must not have escalated to
	// fail purely because of empty policy.
	if c.Verdict == diagFail {
		t.Errorf("top-level verdict = %q, want ok or warn (empty policy alone must not fail the report)", c.Verdict)
	}
}
