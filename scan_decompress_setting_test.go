package main

// CHAOS-106 follow-up — the operator setting for the scan-path decompression
// ratio (GET/PUT /api/security-scan/decompression).
//
// internal/secscan owns the bound and pins its range and runtime semantics
// (decompress_ratio_setting_test.go). These are the admin-plane half: the
// handler validates, enforces RBAC at the handler, audits, persists through
// admin_settings.json and survives a reload, deliberately creates NO config
// version (D-sec, like the YARA engine settings), surfaces a relaxed posture on
// the operator contract, and — end to end on the SSL-inspect path — actually
// changes which responses are refused.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// restoreScanDecompressRatio restores the live ratio a test changes.
func restoreScanDecompressRatio(t *testing.T) {
	t.Helper()
	prev := secscan.DecompressRatioLimit()
	t.Cleanup(func() { _ = secscan.SetDecompressRatioLimit(prev) })
}

// setScanDecompressRatio installs ratio (restored at cleanup).
func setScanDecompressRatio(t *testing.T, ratio int64) {
	t.Helper()
	restoreScanDecompressRatio(t)
	if err := secscan.SetDecompressRatioLimit(ratio); err != nil {
		t.Fatalf("SetDecompressRatioLimit(%d): %v", ratio, err)
	}
}

// withAdminSettingsPathForTest points the settings writer at path ("" = no
// persistence) and restores the original.
func withAdminSettingsPathForTest(t *testing.T, path string) {
	t.Helper()
	adminSettingsMu.Lock()
	orig := adminSettingsPath
	adminSettingsPath = path
	adminSettingsMu.Unlock()
	t.Cleanup(func() {
		adminSettingsMu.Lock()
		adminSettingsPath = orig
		adminSettingsMu.Unlock()
	})
}

func putScanDecompressionAs(t *testing.T, role UIRole, actorIP, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := withRole(httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/security-scan/decompression", strings.NewReader(body)), role)
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = actorIP + ":0"
	w := httptest.NewRecorder()
	apiSecScanDecompression(w, r)
	return w
}

func getScanDecompression(t *testing.T) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	apiSecScanDecompression(w, newViewerRequest("/api/security-scan/decompression"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET status %d: %s", w.Code, w.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("GET body: %v", err)
	}
	return m
}

// scanDecompressAuditFromActor returns this run's audit entry for actorIP, or nil.
func scanDecompressAuditFromActor(actorIP string, sinceTS int64) *AuditEntry {
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.Actor == actorIP && e.Action == scanDecompressAuditAction && e.TS >= sinceTS {
			return e
		}
	}
	return nil
}

// ratio100Gzip is a gzip stream expanding at ~90-100:1 — a legitimately
// repetitive export: 1 KiB of incompressible bytes then 99 KiB of zeros,
// repeated to 8 MiB. Refused at the 64 default, admitted at 128.
func ratio100Gzip(t *testing.T) []byte {
	t.Helper()
	const chunk, noise, chunks = 100 << 10, 1 << 10, 80
	raw := make([]byte, chunk*chunks)
	var ctr [8]byte
	for c := 0; c < chunks; c++ {
		// Incompressible, deterministic noise: SHA-256 in counter mode.
		for off := 0; off < noise; off += sha256.Size {
			binary.BigEndian.PutUint64(ctr[:], uint64(c*noise+off))
			sum := sha256.Sum256(ctr[:])
			copy(raw[c*chunk+off:c*chunk+noise], sum[:])
		}
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if r := len(raw) / buf.Len(); r <= 64 || r >= 128 {
		t.Fatalf("fixture ratio %d:1, want strictly between 64 and 128", r)
	}
	if int64(buf.Len()) > chaos106ScanWindow {
		t.Fatalf("fixture %d bytes exceeds the %d scan window", buf.Len(), int64(chaos106ScanWindow))
	}
	return buf.Bytes()
}

// ─── Read side ───────────────────────────────────────────────────────────────

func TestScanDecompressSetting_GETReportsTheDefaultWhenUnset(t *testing.T) {
	setScanDecompressRatio(t, secscan.DefaultDecompressRatioLimit) // == unset

	m := getScanDecompression(t)
	want := map[string]float64{"ratio_limit": 64, "default_ratio_limit": 64, "min_ratio_limit": 16, "max_ratio_limit": 256}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %v", k, m[k], v)
		}
	}
	if m["relaxed"] != false {
		t.Errorf("relaxed = %v at the default", m["relaxed"])
	}
	if rev, _ := m["revision"].(string); !strings.HasPrefix(rev, "sha256:") {
		t.Errorf("revision = %v, want a content revision", m["revision"])
	}
}

// ─── Write side: apply + audit, and NO config version ───────────────────────

func TestScanDecompressSetting_PUTAppliesAuditsAndCreatesNoConfigVersion(t *testing.T) {
	setScanDecompressRatio(t, secscan.DefaultDecompressRatioLimit)
	withAdminSettingsPathForTest(t, "")
	versionsDir := snapshotConfigVersionsDir(t)
	baseline := time.Now().UnixMilli()
	const actorIP = "198.51.100.171"

	w := putScanDecompressionAs(t, RoleAdmin, actorIP, `{"ratio_limit":128}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT status %d: %s", w.Code, w.Body.String())
	}
	if got := secscan.DecompressRatioLimit(); got != 128 {
		t.Fatalf("live ratio = %d after PUT 128", got)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["ratio_limit"] != float64(128) || resp["relaxed"] != true {
		t.Errorf("response = %v, want ratio_limit 128 relaxed true", resp)
	}

	e := scanDecompressAuditFromActor(actorIP, baseline)
	if e == nil {
		t.Fatal("no audit entry from this run for the ratio change")
	}
	if e.Object != "scan_decompress" || !strings.Contains(e.Detail, "64 -> 128") || !strings.Contains(e.Detail, "RELAXED") {
		t.Errorf("audit entry = %+v, want object scan_decompress and a RELAXED 64 -> 128 detail", *e)
	}
	if !strings.Contains(e.Before, `"ratio_limit":64`) || !strings.Contains(e.After, `"ratio_limit":128`) {
		t.Errorf("audit diff before=%q after=%q", e.Before, e.After)
	}

	// D-sec: the setting is out of the rollback surface, so the PUT must not
	// write ANY version envelope (a version that cannot restore the value
	// would be the Category D' misleading-version bug).
	assertNoConfigVersionWithAction(t, versionsDir, scanDecompressAuditAction)
	if entries, err := os.ReadDir(versionsDir); err != nil || len(entries) != 0 {
		t.Errorf("config versions dir holds %d entries (err %v) after the PUT, want none", len(entries), err)
	}
}

func TestScanDecompressSetting_PUTRejectsInvalidValues(t *testing.T) {
	setScanDecompressRatio(t, 100)
	withAdminSettingsPathForTest(t, "")
	baseline := time.Now().UnixMilli()
	const actorIP = "198.51.100.172"

	for _, body := range []string{
		`{"ratio_limit":15}`,
		`{"ratio_limit":257}`,
		`{"ratio_limit":1024}`,
		`{"ratio_limit":0}`,
		`{"ratio_limit":-64}`,
		`{"ratio_limit":64.5}`,
		`{"ratio_limit":"128"}`,
		`{"ratio_limit":true}`,
		`{}`,
		`not json`,
	} {
		w := putScanDecompressionAs(t, RoleAdmin, actorIP, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("PUT %s: status %d, want 400", body, w.Code)
		}
		if got := secscan.DecompressRatioLimit(); got != 100 {
			t.Fatalf("PUT %s changed the live ratio to %d", body, got)
		}
	}
	if e := scanDecompressAuditFromActor(actorIP, baseline); e != nil {
		t.Errorf("a refused PUT was audited: %+v", *e)
	}
}

func TestScanDecompressSetting_PUTRequiresAdmin(t *testing.T) {
	setScanDecompressRatio(t, secscan.DefaultDecompressRatioLimit)
	withAdminSettingsPathForTest(t, "")
	baseline := time.Now().UnixMilli()
	const actorIP = "198.51.100.173"

	for _, role := range []UIRole{RoleOperator, RoleViewer} {
		w := putScanDecompressionAs(t, role, actorIP, `{"ratio_limit":200}`)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s PUT: status %d, want 403", role, w.Code)
		}
	}
	if got := secscan.DecompressRatioLimit(); got != secscan.DefaultDecompressRatioLimit {
		t.Fatalf("a non-admin PUT changed the ratio to %d", got)
	}
	if e := scanDecompressAuditFromActor(actorIP, baseline); e != nil {
		t.Errorf("a forbidden PUT was audited: %+v", *e)
	}
	// Metadata must not be more permissive than the handler.
	m := lookupUIRouteMeta(t, "/api/security-scan/decompression", http.MethodPut)
	if m.MinRole != RoleAdmin || !m.Mutating || !m.AuditExpected {
		t.Errorf("uiRoutes PUT metadata = %+v, want admin/mutating/audit-expected", m)
	}
}

func lookupUIRouteMeta(t *testing.T, path, method string) uiRouteMethod {
	t.Helper()
	for i := range uiRoutes {
		if uiRoutes[i].Path != path {
			continue
		}
		for _, m := range uiRoutes[i].Methods {
			if m.Method == method {
				return m
			}
		}
	}
	t.Fatalf("no uiRoutes metadata for %s %s", method, path)
	return uiRouteMethod{}
}

func TestScanDecompressSetting_StaleRevisionIsRefused(t *testing.T) {
	setScanDecompressRatio(t, secscan.DefaultDecompressRatioLimit)
	withAdminSettingsPathForTest(t, "")

	stale, _ := getScanDecompression(t)["revision"].(string)
	if err := secscan.SetDecompressRatioLimit(32); err != nil { // a concurrent admin's change
		t.Fatal(err)
	}
	w := putScanDecompressionAs(t, RoleAdmin, "198.51.100.174", `{"ratio_limit":200,"ifRevision":"`+stale+`"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale ifRevision: status %d, want 409", w.Code)
	}
	if got := secscan.DecompressRatioLimit(); got != 32 {
		t.Fatalf("a fenced-out PUT changed the ratio to %d", got)
	}
	fresh, _ := getScanDecompression(t)["revision"].(string)
	w = putScanDecompressionAs(t, RoleAdmin, "198.51.100.174", `{"ratio_limit":200,"ifRevision":"`+fresh+`"}`)
	if w.Code != http.StatusOK || secscan.DecompressRatioLimit() != 200 {
		t.Fatalf("current ifRevision: status %d ratio %d, want 200/200", w.Code, secscan.DecompressRatioLimit())
	}
}

// ─── Persistence ─────────────────────────────────────────────────────────────

// The PUT writes the target to admin_settings.json BEFORE applying it, and the
// persisted bytes restore it across a restart.
func TestScanDecompressSetting_PersistsAndReloads(t *testing.T) {
	setScanDecompressRatio(t, secscan.DefaultDecompressRatioLimit)
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	withAdminSettingsPathForTest(t, path)

	if w := putScanDecompressionAs(t, RoleAdmin, "198.51.100.175", `{"ratio_limit":128}`); w.Code != http.StatusOK {
		t.Fatalf("PUT status %d: %s", w.Code, w.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("settings file not written: %v", err)
	}
	var onDisk AdminSettings
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.ScanDecompressRatioLimit != 128 {
		t.Fatalf("persisted ratio = %d, want 128", onDisk.ScanDecompressRatioLimit)
	}

	// Simulate a restart: the process comes up at the default, then loads.
	_ = secscan.SetDecompressRatioLimit(secscan.DefaultDecompressRatioLimit)
	LoadAdminSettings(path)
	if got := secscan.DecompressRatioLimit(); got != 128 {
		t.Fatalf("after reload the ratio is %d, want the persisted 128", got)
	}

	// Resetting to the default is recorded as ABSENT, so the node follows
	// the shipped default again rather than pinning 64.
	if w := putScanDecompressionAs(t, RoleAdmin, "198.51.100.175", `{"ratio_limit":64}`); w.Code != http.StatusOK {
		t.Fatalf("PUT 64 status %d", w.Code)
	}
	raw, _ = os.ReadFile(path)
	if bytes.Contains(raw, []byte("scan_decompress_ratio_limit")) {
		t.Errorf("the default was persisted explicitly; want it absent:\n%s", raw)
	}
	_ = secscan.SetDecompressRatioLimit(200)
	LoadAdminSettings(path)
	if got := secscan.DecompressRatioLimit(); got != secscan.DefaultDecompressRatioLimit {
		t.Fatalf("a file without the field loaded ratio %d, want the default", got)
	}
}

// An omnibus save from an UNRELATED mutation must carry the live ratio, not
// drop it (the adminSaveOverrides contract for every durable field).
func TestScanDecompressSetting_UnrelatedSaveKeepsTheRatio(t *testing.T) {
	setScanDecompressRatio(t, 200)
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	withAdminSettingsPathForTest(t, path)

	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("SaveAdminSettings: %v", err)
	}
	var onDisk AdminSettings
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.ScanDecompressRatioLimit != 200 {
		t.Fatalf("omnibus save recorded ratio %d, want the live 200", onDisk.ScanDecompressRatioLimit)
	}
}

// A hand-edited out-of-range value can never widen the bound: it is refused on
// load and the default is installed.
func TestScanDecompressSetting_LoadRefusesOutOfRange(t *testing.T) {
	for _, bad := range []int64{5000, 4, -1} {
		setScanDecompressRatio(t, 200)
		applyAdminScanDecompressRatio(&AdminSettings{ScanDecompressRatioLimit: bad})
		if got := secscan.DecompressRatioLimit(); got != secscan.DefaultDecompressRatioLimit {
			t.Errorf("persisted %d loaded as %d, want the default %d", bad, got, secscan.DefaultDecompressRatioLimit)
		}
	}
}

// Persist-before-apply: a failed write is a truthful 500 and the live bound is
// untouched.
func TestScanDecompressSetting_PersistFailureLeavesTheBoundUnchanged(t *testing.T) {
	setScanDecompressRatio(t, secscan.DefaultDecompressRatioLimit)
	withAdminSettingsPathForTest(t, filepath.Join(t.TempDir(), "missing-dir", "admin_settings.json"))
	baseline := time.Now().UnixMilli()
	const actorIP = "198.51.100.176"

	w := putScanDecompressionAs(t, RoleAdmin, actorIP, `{"ratio_limit":200}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 on a persist failure", w.Code)
	}
	if got := secscan.DecompressRatioLimit(); got != secscan.DefaultDecompressRatioLimit {
		t.Fatalf("a non-durable PUT applied ratio %d", got)
	}
	if e := scanDecompressAuditFromActor(actorIP, baseline); e != nil {
		t.Errorf("a failed PUT was audited as a change: %+v", *e)
	}
}

// ─── Runtime effect, end to end on the primary SWG path ─────────────────────

func TestScanDecompressSetting_ChangesTheInspectPathVerdict(t *testing.T) {
	withScanLimit(t, chaos106ScanWindow)
	wire := ratio100Gzip(t)

	setScanDecompressRatio(t, secscan.DefaultDecompressRatioLimit)
	if br, _, out := chaos106InspectFixture(t, wire, "gzip"); out != scanBlocked || br.calls != 1 {
		t.Fatalf("default 64: outcome %v (blocks %d), want the ~100:1 export refused", out, br.calls)
	}

	withAdminSettingsPathForTest(t, "")
	if w := putScanDecompressionAs(t, RoleAdmin, "198.51.100.177", `{"ratio_limit":128}`); w.Code != http.StatusOK {
		t.Fatalf("PUT status %d", w.Code)
	}
	if br, _, out := chaos106InspectFixture(t, wire, "gzip"); out != scanClean || br.calls != 0 {
		t.Fatalf("ratio 128: outcome %v (blocks %d), want the ~100:1 export admitted", out, br.calls)
	}
}

// ─── Operator contract ───────────────────────────────────────────────────────

func TestScanDecompressSetting_DiagnosticsWarnWhenRelaxed(t *testing.T) {
	for _, tc := range []struct {
		ratio int64
		want  string
	}{{64, diagOK}, {16, diagOK}, {65, diagWarn}, {256, diagWarn}} {
		setScanDecompressRatio(t, tc.ratio)
		ck := checkScanDecompressRatioPosture()
		if ck.Code != "scan_decompress_ratio" || ck.Status != tc.want {
			t.Errorf("ratio %d: row %s/%s, want scan_decompress_ratio/%s", tc.ratio, ck.Code, ck.Status, tc.want)
		}
		if tc.want == diagWarn && ck.OperatorAction == "" {
			t.Errorf("ratio %d: a warn row needs an operator action", tc.ratio)
		}
	}
	setScanDecompressRatio(t, 128)
	if c := findDiagnosticCheck(buildOperatorContract(), "scan_decompress_ratio"); c == nil || c.Status != diagWarn {
		t.Fatalf("operator contract row = %+v, want a warn row at ratio 128", c)
	}
}

// ─── API contract (Gates 4/5) ────────────────────────────────────────────────

func TestConformance_ScanDecompression(t *testing.T) {
	spec := loadContract(t)
	setScanDecompressRatio(t, secscan.DefaultDecompressRatioLimit)
	withAdminSettingsPathForTest(t, "")

	w := httptest.NewRecorder()
	apiSecScanDecompression(w, newViewerRequest("/api/security-scan/decompression"))
	if err := spec.ValidateJSONResponse("GET", "/api/security-scan/decompression", 200, w.Body.Bytes()); err != nil {
		t.Fatalf("GET response violates contract: %v\nbody: %s", err, w.Body.String())
	}
	w = putScanDecompressionAs(t, RoleAdmin, "198.51.100.178", `{"ratio_limit":96}`)
	if err := spec.ValidateJSONResponse("PUT", "/api/security-scan/decompression", 200, w.Body.Bytes()); err != nil {
		t.Fatalf("PUT response violates contract: %v\nbody: %s", err, w.Body.String())
	}
	if err := spec.ValidateJSONRequest("PUT", "/api/security-scan/decompression", []byte(`{"ratio_limit":128,"ifRevision":"sha256:x"}`)); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}
	for _, bad := range []string{`{"ratio_limit":"128"}`, `{}`, `{"ratio_limit":128,"extra":1}`, `{"ratio_limit":1024}`} {
		if err := spec.ValidateJSONRequest("PUT", "/api/security-scan/decompression", []byte(bad)); err == nil {
			t.Errorf("contract accepted invalid body %s", bad)
		}
	}
}
