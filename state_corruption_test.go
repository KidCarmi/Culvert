package main

// state_corruption_test.go — CHAOS-05/07 regression coverage.
//
// A present-but-corrupt ui_users.json or cluster.json used to be logged,
// skipped (empty in-memory store), and then OVERWRITTEN by the next save —
// permanently destroying the admin roster + TOTP enrollments (CHAOS-05) or
// the enrolled-node roster + revoked-cert list (CHAOS-07). These tests pin
// the new response: the corrupt file is quarantined to
// <path>.corrupt.<unixnano> byte-intact BEFORE any save can touch it, a
// state_file_corrupt alert is queued until the webhook store loads (the
// CHAOS-06 deferStartupAlert contract), and /readyz surfaces a report-only
// fail row. Missing files stay silent (first-run path, unchanged).

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolateStateCorruption resets the recorded-corruption map for one test
// and restores emptiness afterwards (other tests in the suite load corrupt
// fixtures too — the map is a process-global).
func isolateStateCorruption(t *testing.T) {
	t.Helper()
	resetStateCorruption()
	t.Cleanup(resetStateCorruption)
}

// quarantinedFiles returns the quarantine siblings of path.
func quarantinedFiles(t *testing.T, path string) []string {
	t.Helper()
	matches, err := filepath.Glob(path + ".corrupt.*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return matches
}

func TestLoadUIUsersFile_CorruptRosterQuarantinedNotOverwritten(t *testing.T) {
	captured := captureStartupAlerts(t)
	isolateStateCorruption(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")
	// A torn write: valid prefix of a real envelope, cut mid-record.
	corrupt := []byte(`{"users":[{"username":"admin","pass_hash_hex":"deadbeef","role":"admi`)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	c := &Config{}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err == nil {
		t.Fatal("expected parse error on corrupt roster")
	}

	// The corrupt file must be MOVED, not left where the next save lands.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("corrupt file still present at %s — the next save would overwrite the only copy of the roster", path)
	}
	qfiles := quarantinedFiles(t, path)
	if len(qfiles) != 1 {
		t.Fatalf("want exactly 1 quarantine file, got %v", qfiles)
	}
	got, err := os.ReadFile(qfiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, corrupt) {
		t.Fatalf("quarantine content differs from the original corrupt bytes")
	}

	// The exact pre-fix destruction scenario: an admin mutation (or the
	// --reset-password one-shot) saves a fresh roster afterwards. The
	// evidence must survive byte-identical.
	if err := c.SetUIUser("rescue", "Password123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fresh roster not written after quarantine: %v", err)
	}
	after, err := os.ReadFile(qfiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, corrupt) {
		t.Fatal("post-quarantine save destroyed the quarantined evidence")
	}

	// Alert is queued until the webhook store loads, then fires once.
	if len(*captured) != 0 {
		t.Fatalf("alert fired before webhook store loaded (got %d) — it would fan out to an empty list and vanish", len(*captured))
	}
	flushStartupAlerts()
	if len(*captured) != 1 {
		t.Fatalf("flush delivered %d alerts, want 1", len(*captured))
	}
	if a := (*captured)[0]; a.event != "state_file_corrupt" || a.payload.Source != "storage" {
		t.Fatalf("unexpected alert %q source %q, want state_file_corrupt/storage", a.event, a.payload.Source)
	}
}

func TestClusterStoreLoad_CorruptDBQuarantined_RevocationEvidencePreserved(t *testing.T) {
	captured := captureStartupAlerts(t)
	isolateStateCorruption(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	// Torn mid-write through the revoked-cert list — the security-relevant
	// content CHAOS-07 is about (revoked DP certs validating again).
	corrupt := []byte(`{"revoked":[{"cert_serial":"1234deadbeef","node_id":"dp-1"`)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	cs := &ClusterStore{st: ClusterState{
		Nodes:   make(map[string]*EnrolledNode),
		Tokens:  make(map[string]*EnrollToken),
		Revoked: []RevokedCert{},
	}}
	if err := cs.Load(path); err == nil {
		t.Fatal("expected parse error on corrupt cluster DB")
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("corrupt cluster DB still present at %s", path)
	}
	qfiles := quarantinedFiles(t, path)
	if len(qfiles) != 1 {
		t.Fatalf("want exactly 1 quarantine file, got %v", qfiles)
	}

	// The "starting fresh" follow-up: the empty store saves. The revoked-
	// serial evidence must survive so an operator can restore it.
	if err := cs.Save(); err != nil {
		t.Fatalf("post-quarantine save: %v", err)
	}
	after, err := os.ReadFile(qfiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, corrupt) {
		t.Fatal("starting-fresh save destroyed the quarantined revocation evidence")
	}
	if !strings.Contains(string(after), "1234deadbeef") {
		t.Fatal("quarantined bytes lost the revoked serial")
	}

	flushStartupAlerts()
	if len(*captured) != 1 {
		t.Fatalf("flush delivered %d alerts, want 1", len(*captured))
	}
	if a := (*captured)[0]; a.event != "state_file_corrupt" || a.payload.Source != "storage" {
		t.Fatalf("unexpected alert %q source %q, want state_file_corrupt/storage", a.event, a.payload.Source)
	}
}

func TestLoadUIUsersFile_MissingFile_NoQuarantineNoAlert(t *testing.T) {
	captured := captureStartupAlerts(t)
	isolateStateCorruption(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")
	c := &Config{}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("missing file must stay a silent first-run success: %v", err)
	}
	if qfiles := quarantinedFiles(t, path); len(qfiles) != 0 {
		t.Fatalf("missing file must not quarantine anything, got %v", qfiles)
	}
	flushStartupAlerts()
	if len(*captured) != 0 {
		t.Fatalf("missing file must not alert, got %d", len(*captured))
	}
	if snap := stateCorruptionSnapshot(); len(snap) != 0 {
		t.Fatalf("missing file must not record corruption, got %v", snap)
	}
}

// TestQuarantineCorruptStateFile_RenameFailureStillAlertsAndRecords pins
// the fallback branch: when the quarantine rename itself fails, the alert
// and the /readyz record must still happen, with the detail warning that
// the evidence is still in the save path's line of fire.
func TestQuarantineCorruptStateFile_RenameFailureStillAlertsAndRecords(t *testing.T) {
	captured := captureStartupAlerts(t)
	isolateStateCorruption(t)

	// Renaming a nonexistent path fails deterministically.
	path := filepath.Join(t.TempDir(), "gone.json")
	if q := quarantineCorruptStateFile("ui_users", path, errors.New("boom")); q != "" {
		t.Fatalf("rename cannot have succeeded, got quarantine path %q", q)
	}
	snap := stateCorruptionSnapshot()
	detail, ok := snap["ui_users"]
	if !ok {
		t.Fatal("rename failure must still record the corruption for /readyz")
	}
	if !strings.Contains(detail, "could not be quarantined") {
		t.Fatalf("detail must warn the evidence was NOT moved aside: %q", detail)
	}
	flushStartupAlerts()
	if len(*captured) != 1 {
		t.Fatalf("rename failure must still alert (got %d)", len(*captured))
	}
}

// TestLoadUIUsersFile_ResidualQuarantineResurfacedAcrossRestart pins the
// Codex P2 follow-up: the corruption signal is process-local, so after a
// restart it must be re-derived from the on-disk quarantine sibling.
// Otherwise the flow "corrupt load → run → save fresh empty file → reboot"
// silently goes green while the roster/revocation loss persists.
func TestLoadUIUsersFile_ResidualQuarantineResurfacedAcrossRestart(t *testing.T) {
	captured := captureStartupAlerts(t)
	isolateStateCorruption(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")

	// Boot 1: corrupt file → quarantined, one alert queued.
	if err := os.WriteFile(path, []byte(`{"users":[bad`), 0o600); err != nil {
		t.Fatal(err)
	}
	c1 := &Config{}
	c1.SetUIUsersFile(path)
	if err := c1.LoadUIUsersFile(); err == nil {
		t.Fatal("expected parse error on boot 1")
	}
	qfiles := quarantinedFiles(t, path)
	if len(qfiles) != 1 {
		t.Fatalf("boot 1 must produce exactly 1 quarantine file, got %v", qfiles)
	}

	// The node keeps running and saves a fresh, VALID roster — the file
	// that would fool the next boot into thinking all is well.
	if err := c1.SetUIUser("rescue", "Password123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := c1.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}

	// Simulate the restart: a brand-new process (empty corruption map, new
	// Config) loads the now-VALID file. Pre-fix this returns nil with an
	// empty map and probes go green — the regression this test guards.
	resetStateCorruption()
	c2 := &Config{}
	c2.SetUIUsersFile(path)
	if err := c2.LoadUIUsersFile(); err != nil {
		t.Fatalf("boot 2 load of the fresh valid file must succeed: %v", err)
	}
	snap := stateCorruptionSnapshot()
	detail, ok := snap["ui_users"]
	if !ok {
		t.Fatal("boot 2: unreconciled quarantine sibling must re-surface the /readyz record")
	}
	if !strings.Contains(detail, "unreconciled") {
		t.Fatalf("boot 2 detail should flag the residual quarantine: %q", detail)
	}
	flushStartupAlerts()
	if len(*captured) != 2 {
		t.Fatalf("want 2 alerts total (boot 1 corrupt + boot 2 residual), got %d", len(*captured))
	}

	// Operator reconciles by removing the quarantine file → boot 3 clean.
	if err := os.Remove(qfiles[0]); err != nil {
		t.Fatal(err)
	}
	resetStateCorruption()
	c3 := &Config{}
	c3.SetUIUsersFile(path)
	if err := c3.LoadUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	if snap := stateCorruptionSnapshot(); len(snap) != 0 {
		t.Fatalf("boot 3 after reconciliation must be clean, got %v", snap)
	}
}

// TestHandleReady_SurfacesStateFileCorruption pins the /readyz row: a
// recorded corruption shows as a failing state_file_<kind> check, and it
// is report-only — the readiness verdict must not change (the node still
// serves; env fallback creds / re-enrollment are the recovery paths).
func TestHandleReady_SurfacesStateFileCorruption(t *testing.T) {
	captureStartupAlerts(t)
	isolateStateCorruption(t)

	type readyResp struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	ready := func() (readyResp, int) {
		rr := httptest.NewRecorder()
		handleReady(rr, nil)
		var r readyResp
		if err := json.NewDecoder(rr.Body).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r, rr.Code
	}

	base, baseCode := ready()
	if _, ok := base.Checks["state_file_ui_users"]; ok {
		t.Fatal("baseline: no corruption recorded, row must be absent")
	}

	// Drive the real loader, not the recorder directly.
	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")
	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Config{}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err == nil {
		t.Fatal("expected parse error")
	}

	got, gotCode := ready()
	row, ok := got.Checks["state_file_ui_users"]
	if !ok {
		t.Fatal("state_file_ui_users row missing from /readyz after a corrupt roster load (CHAOS-05)")
	}
	if row.Status != "fail" {
		t.Fatalf("row = %+v, want fail", row)
	}
	// The UNAUTHENTICATED /ready row must carry only a fixed, non-path detail —
	// the absolute state-file path, the raw parse error, and the quarantine
	// filename would fingerprint a security-degraded node to any proxy-port
	// client. The full detail lives in the logs/alert/authenticated diagnostics.
	if strings.Contains(row.Detail, "quarantined to") || strings.Contains(row.Detail, path) || strings.Contains(row.Detail, dir) {
		t.Fatalf("readyz row leaked the quarantine path/detail on the unauthenticated probe: %q", row.Detail)
	}
	if row.Detail == "" {
		t.Fatal("readyz row must still carry a (generic) degradation signal")
	}
	if gotCode != baseCode || got.Status != base.Status {
		t.Fatalf("state-file row changed readiness (%s/%d → %s/%d) — must be report-only", base.Status, baseCode, got.Status, gotCode)
	}
}
