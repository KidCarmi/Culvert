package main

// upstream_v2_portability_red_test.go — the 2F-D RED matrix (approved 2F
// contract C5/C7/C9/C12 + the 2F-D execution directive,
// docs/design/FRONTEND-MIGRATION-PLAN.md): R24 (manual-probe lifecycle),
// R32 (authority-changing import: plan, zero mutation), R33 (import
// removal), R34 (dry-run applies nothing), R40 (restore boots into
// requiresReplacement) and the COMPLETE R15 sink matrix (canary password +
// sealed ciphertext absent from every portable artifact).
//
// RED-before evidence: every test was committed against the frozen 2F-C
// baseline (ef9cb045) BEFORE the implementation. On that baseline:
//   - R24: POST /api/upstream/health is unaudited, runs concurrently and is
//     never rate-limited (a second call within the window answers 200);
//   - R32/R33/R34: the import decoder refuses the versioned
//     upstream_proxies_v2 export representation outright (400), so no plan,
//     no digest, no 409 credential_clear_required and no dryRun=1 exist;
//   - R40: admin_settings.json is archived VERBATIM (sealed ciphertext +
//     key id travel in both backup modes, no manifest marker), the restore
//     dry-run reports nothing about credentials, a restored node boots the
//     credential into `unusable` (not the distinct `requiresReplacement`),
//     the read model has no credentialsRequiringReplacement, and a full
//     restore drops the node's existing .upstream_cred_key;
//   - R15: the ciphertext canary is present in both backup archives; the
//     export carries the legacy list instead of the versioned v2 shape.
// Fault injection is deterministic (upstream.ProbeTransport seam with
// channel handshakes, temp data dirs, captured stdout/logger); no sleeps,
// no probabilistic concurrency. Only symbols that exist on the baseline
// are referenced, so the file compiles there and fails on assertions.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/configver"
	"github.com/KidCarmi/Culvert/internal/support"
	"github.com/KidCarmi/Culvert/internal/upstream"
)

const (
	pdCanaryPW   = "Canary-Portability-PW-7e1c" // #nosec G101 -- test-only fake parent-proxy password
	pdCanaryHost = "parent-pd.test"
	pdCanaryUser = "svc"
)

// pdSeed configures one credentialed managed parent and returns its id plus
// the sealed ciphertext the settings file carries for it (the second canary
// every portable artifact must be free of).
func pdSeed(t *testing.T) (id, ciphertext string) {
	t.Helper()
	id = upSeedCredentialed(t, pdCanaryHost, pdCanaryUser, pdCanaryPW)
	if id == "" {
		t.Fatal("v2 endpoints are required for the 2F-D matrix")
	}
	return id, pdCiphertext(t, upSettingsFile(t), id)
}

// pdCiphertext extracts the sealed ciphertext of entry id from a settings
// file body (fails the test if the file carries none — the seed must have
// sealed).
func pdCiphertext(t *testing.T, settings, id string) string {
	t.Helper()
	var s struct {
		V2 struct {
			Entries []struct {
				ID         string `json:"id"`
				Credential *struct {
					Ciphertext string `json:"ciphertext"`
				} `json:"credential"`
			} `json:"entries"`
		} `json:"upstream_proxies_v2"`
	}
	if err := json.Unmarshal([]byte(settings), &s); err != nil {
		t.Fatalf("settings file is not JSON: %v", err)
	}
	for _, e := range s.V2.Entries {
		if e.ID == id && e.Credential != nil && e.Credential.Ciphertext != "" {
			return e.Credential.Ciphertext
		}
	}
	t.Fatal("the settings file must carry a sealed credential for the seeded entry")
	return ""
}

// pdImport POSTs a config import with an explicit query string.
func pdImport(t *testing.T, body, query string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/config/import"
	if query != "" {
		path += "?" + query
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = upRedIP + ":40031"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiConfigImport(rec, req)
	return rec
}

func pdExport(t *testing.T, section string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/config/export"
	if section != "" {
		path += "?section=" + section
	}
	req := httptest.NewRequest("GET", path, http.NoBody)
	req.RemoteAddr = upRedIP + ":40032"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rec := httptest.NewRecorder()
	apiConfigExport(rec, req)
	return rec
}

// pdV2Payload renders the versioned export representation (C5) for the
// given entries. credentialState is what an export would have declared.
func pdV2Payload(entries ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"version":              2,
		"exportedAt":           "2026-09-04T00:00:00Z",
		"upstream_proxies_v2":  map[string]any{"entries": entries},
		"upstream_credentials": "omitted",
	})
	return string(b)
}

func pdEntry(id, host string, credState string) map[string]any {
	return map[string]any{"id": id, "scheme": "http", "host": host, "port": 3128, "username": pdCanaryUser, "credentialState": credState}
}

// pdPlan extracts the import plan (dry-run or refusal body).
func pdPlan(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	body := upJSON(t, rec)
	plan, _ := body["plan"].(map[string]any)
	if plan == nil {
		t.Fatalf("response carries no plan (%d): %s", rec.Code, rec.Body.String())
	}
	return plan
}

func pdPlanAction(plan map[string]any, list, id string) string {
	items, _ := plan[list].([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		if m["id"] == id {
			a, _ := m["action"].(string)
			return a
		}
	}
	return ""
}

func pdPlanClearRequired(plan map[string]any) []string {
	raw, _ := plan["credentialClearRequired"].([]any)
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		s, _ := r.(string)
		out = append(out, s)
	}
	return out
}

func pdContains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func pdAuditCount(since int64, action string) int {
	n := 0
	entries := auditGet()
	for i := range entries {
		if entries[i].TS >= since && entries[i].Action == action {
			n++
		}
	}
	return n
}

// pdTarFiles gunzips + untars a bundle into path → body.
func pdTarFiles(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar body %s: %v", h.Name, err)
		}
		out[h.Name] = b
	}
	return out
}

// pdBlockingProbe installs a probe transport that reports entry on
// `entered` and parks until `release` is closed. Every probe reports 200
// once released.
type pdBlockingRT struct {
	entered chan struct{}
	release chan struct{}
}

func (b pdBlockingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	b.entered <- struct{}{}
	<-b.release
	return &http.Response{StatusCode: 200, Status: "200", Body: io.NopCloser(strings.NewReader("x")), Header: http.Header{}, Request: req}, nil
}

// ── R24: manual probe is audited, rate-limited and single-flight ──

func TestUpstreamV2D_R24_ManualProbeIsAuditedAndRateLimited(t *testing.T) {
	upEnv(t)
	pdSeed(t)
	upProbe(200, nil)
	since := time.Now().UnixMilli()

	rec := upReq(t, "POST", "/api/upstream/health", "")
	if rec.Code != 200 {
		t.Fatalf("first manual probe: %d %s", rec.Code, rec.Body.String())
	}
	// Audited with bounded counts + the node-local scope, never a raw error.
	var audited bool
	for _, e := range auditGet() {
		if e.TS >= since && e.Action == "upstream.probe.manual" {
			audited = true
			if !strings.Contains(e.Detail, "scope=node-local") || !strings.Contains(e.Detail, "probed=") {
				t.Fatalf("manual-probe audit must carry counts + scope=node-local, got %q", e.Detail)
			}
		}
	}
	if !audited {
		t.Fatal("an accepted manual probe run must be audited (upstream.probe.manual)")
	}
	// A repeated run inside the 10 s window is refused with 429 and leaves
	// no success audit behind.
	rec = upReq(t, "POST", "/api/upstream/health", "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a repeated manual probe within 10s must answer 429, got %d %s", rec.Code, rec.Body.String())
	}
	if got := pdAuditCount(since, "upstream.probe.manual"); got != 1 {
		t.Fatalf("a rate-limited run must not produce a success audit (got %d entries)", got)
	}
	// Control: the probe stays admin-only.
	req := httptest.NewRequest("POST", "/api/upstream/health", http.NoBody)
	req.RemoteAddr = upRedIP + ":40033"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleOperator))
	opRec := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerClusterRoutes(mux)
	mux.ServeHTTP(opRec, req)
	if opRec.Code != http.StatusForbidden {
		t.Fatalf("operator must be refused (403), got %d", opRec.Code)
	}
}

func TestUpstreamV2D_R24b_ManualProbeIsSingleFlight(t *testing.T) {
	upEnv(t)
	pdSeed(t)
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	upstream.ProbeTransport = func(*url.URL) http.RoundTripper { return pdBlockingRT{entered: entered, release: release} }

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- upReq(t, "POST", "/api/upstream/health", "") }()
	<-entered // the first run is parked inside its probe

	second := make(chan *httptest.ResponseRecorder, 1)
	go func() { second <- upReq(t, "POST", "/api/upstream/health", "") }()
	// The second run must be refused WITHOUT entering a probe: either it
	// answers (429) or — on the defect — it enters the transport too.
	var rec *httptest.ResponseRecorder
	select {
	case rec = <-second:
	case <-entered:
		close(release)
		<-first
		<-second
		t.Fatal("a second manual run must not probe while one is in flight (single-flight)")
	}
	close(release)
	f := <-first
	if f.Code != 200 {
		t.Fatalf("the in-flight run must complete normally: %d %s", f.Code, f.Body.String())
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a concurrent manual run must answer 429, got %d %s", rec.Code, rec.Body.String())
	}
	// The probe deadline handed to the transport is bounded at 5 s per entry.
	upstream.ProbeTransport = func(*url.URL) http.RoundTripper {
		return pdDeadlineRT{t: t}
	}
	// A fresh window is not required for the deadline probe: the engine
	// call is exercised directly (the handler's own gates are pinned above).
	upstreamPool.HealthCheck(upstream.ProbeManual)
}

type pdDeadlineRT struct{ t *testing.T }

func (d pdDeadlineRT) RoundTrip(req *http.Request) (*http.Response, error) {
	dl, ok := req.Context().Deadline()
	if !ok || time.Until(dl) > 5*time.Second+500*time.Millisecond {
		d.t.Errorf("every manual probe must carry a ≤5s deadline (ok=%v until=%v)", ok, time.Until(dl))
	}
	return &http.Response{StatusCode: 200, Status: "200", Body: io.NopCloser(strings.NewReader("x")), Header: http.Header{}, Request: req}, nil
}

// ── R32: an authority-changing import of a credentialed entry is planned,
// refused with 409 credential_clear_required, and mutates nothing ──

func TestUpstreamV2D_R32_AuthorityChangingImportRefusedWithPlanZeroMutation(t *testing.T) {
	upEnv(t)
	id, _ := pdSeed(t)
	before := upSettingsFile(t)
	rev := upDocRevision(t)
	since := time.Now().UnixMilli()

	rec := pdImport(t, pdV2Payload(pdEntry(id, "parent-moved.test", "configured")), "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("authority change of a credentialed entry must be 409, got %d %s", rec.Code, rec.Body.String())
	}
	if upJSON(t, rec)["code"] != "credential_clear_required" {
		t.Fatalf("code must be credential_clear_required: %s", rec.Body.String())
	}
	plan := pdPlan(t, rec)
	if a := pdPlanAction(plan, "incoming", id); a != "requiresReplacement" {
		t.Fatalf("incoming %s must be requiresReplacement (changed authority never inherits), got %q", id, a)
	}
	if a := pdPlanAction(plan, "existing", id); a != "remove" {
		t.Fatalf("existing %s must be planned as remove, got %q", id, a)
	}
	if !pdContains(pdPlanClearRequired(plan), id) {
		t.Fatalf("credentialClearRequired must name %s: %v", id, plan)
	}
	// Zero mutation, no success audit, no config version.
	e := upEntry(t, id)
	if e["host"] != pdCanaryHost || e["credentialState"] != upstream.CredentialConfigured {
		t.Fatalf("the refused import must not touch the entry: %v", e)
	}
	if upDocRevision(t) != rev || upSettingsFile(t) != before {
		t.Fatal("the refused import must leave the document and the settings file untouched")
	}
	if pdAuditCount(since, "config.import") != 0 {
		t.Fatal("a refused import must not audit success")
	}
}

// ── R33: an import that omits a credentialed entry in replace mode is a
// planned removal, refused before any store is touched ──

func TestUpstreamV2D_R33_ImportRemovalOfCredentialedEntryRefused(t *testing.T) {
	upEnv(t)
	id, _ := pdSeed(t)
	before := upSettingsFile(t)
	rules := len(policyStore.List())

	rec := pdImport(t, pdV2Payload(pdEntry("01ARZ3NDEKTSV4RRFFQ69G5FAV", "parent-new.test", "none")), "mode=replace")
	if rec.Code != http.StatusConflict || upJSON(t, rec)["code"] != "credential_clear_required" {
		t.Fatalf("omitting a credentialed entry in replace mode must be 409 credential_clear_required, got %d %s", rec.Code, rec.Body.String())
	}
	plan := pdPlan(t, rec)
	if a := pdPlanAction(plan, "existing", id); a != "remove" {
		t.Fatalf("existing %s must be planned as remove, got %q", id, a)
	}
	if a := pdPlanAction(plan, "incoming", "01ARZ3NDEKTSV4RRFFQ69G5FAV"); a != "create" {
		t.Fatalf("the new incoming entry must be planned as create, got %q", a)
	}
	if !pdContains(pdPlanClearRequired(plan), id) {
		t.Fatal("credentialClearRequired must name the removed credentialed entry")
	}
	entries, _ := upGet(t)["entries"].([]any)
	if len(entries) != 1 || upEntry(t, id) == nil {
		t.Fatalf("no store may be touched before the plan is accepted (entries=%d)", len(entries))
	}
	if upSettingsFile(t) != before || len(policyStore.List()) != rules {
		t.Fatal("the refused import must mutate nothing")
	}
	// Merge mode keeps the credentialed entry (retain) and is accepted.
	rec = pdImport(t, pdV2Payload(pdEntry("01ARZ3NDEKTSV4RRFFQ69G5FAV", "parent-new.test", "none")), "dryRun=1")
	if rec.Code != 200 {
		t.Fatalf("merge-mode dry-run: %d %s", rec.Code, rec.Body.String())
	}
	if a := pdPlanAction(pdPlan(t, rec), "existing", id); a != "retain" {
		t.Fatalf("merge mode must retain the unnamed credentialed entry, got %q", a)
	}
}

// ── R34: dryRun=1 returns the plan + a deterministic digest and applies
// nothing; the commit reports counts only ──

func TestUpstreamV2D_R34_DryRunReturnsPlanAndDigestAppliesNothing(t *testing.T) {
	upEnv(t)
	id, _ := pdSeed(t)
	verDir := t.TempDir()
	prevVersions := configVersions
	configVersions = configver.New(verDir, 0)
	t.Cleanup(func() { configVersions = prevVersions })
	before := upSettingsFile(t)
	rev := upDocRevision(t)
	since := time.Now().UnixMilli()
	newID := "01ARZ3NDEKTSV4RRFFQ69G5FAW"
	payload := pdV2Payload(pdEntry(id, pdCanaryHost, "configured"), pdEntry(newID, "parent-new.test", "none"))

	rec := pdImport(t, payload, "dryRun=1")
	if rec.Code != 200 {
		t.Fatalf("dryRun=1 must answer 200 with the plan, got %d %s", rec.Code, rec.Body.String())
	}
	body := upJSON(t, rec)
	if body["dryRun"] != true {
		t.Fatalf("dryRun flag missing: %v", body)
	}
	digest, _ := body["importDigest"].(string)
	if digest == "" {
		t.Fatal("dry-run must return importDigest")
	}
	plan := pdPlan(t, rec)
	if a := pdPlanAction(plan, "incoming", id); a != "preserve" {
		t.Fatalf("unchanged id+authority must be preserve, got %q", a)
	}
	if a := pdPlanAction(plan, "incoming", newID); a != "create" {
		t.Fatalf("unknown id must be create, got %q", a)
	}
	// Deterministic digest.
	again := pdImport(t, payload, "dryRun=1")
	if d2, _ := upJSON(t, again)["importDigest"].(string); d2 != digest {
		t.Fatalf("importDigest must be deterministic: %q vs %q", digest, d2)
	}
	// Nothing applied: no entry, no revision bump, no settings write, no
	// config version, no commit audit.
	if upEntry(t, newID) != nil || upDocRevision(t) != rev || upSettingsFile(t) != before {
		t.Fatal("a dry-run must apply nothing")
	}
	if n, _ := os.ReadDir(verDir); len(n) != 0 {
		t.Fatalf("a dry-run must create no config version (got %d files)", len(n))
	}
	if pdAuditCount(since, "config.import") != 0 {
		t.Fatal("a dry-run must not audit a commit")
	}
	// Commit with the digest: counts only.
	rec = pdImport(t, payload, "importDigest="+digest)
	if rec.Code != 200 {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body.String())
	}
	up, _ := upJSON(t, rec)["upstream"].(map[string]any)
	if up == nil {
		t.Fatalf("commit must report the upstream counts: %s", rec.Body.String())
	}
	for _, k := range []string{"preserved", "omitted", "cleared", "requiresReplacement"} {
		if _, ok := up[k].(float64); !ok {
			t.Fatalf("upstream.%s must be a count: %v", k, up)
		}
	}
	if up["preserved"] != float64(1) || up["cleared"] != float64(0) {
		t.Fatalf("expected preserved=1 cleared=0: %v", up)
	}
	if e := upEntry(t, id); e["credentialState"] != upstream.CredentialConfigured {
		t.Fatalf("the preserved entry must keep its credential: %v", e)
	}
	if e := upEntry(t, newID); e == nil || e["credentialState"] != upstream.CredentialNone {
		t.Fatalf("the created entry must exist without a credential: %v", e)
	}
	// A stale digest (the document moved on) is refused under the lock.
	rec = pdImport(t, payload, "importDigest="+digest)
	if rec.Code != http.StatusConflict {
		t.Fatalf("a stale importDigest must be refused (409), got %d %s", rec.Code, rec.Body.String())
	}
}

// ── R40: backups strip credentials (both modes, manifest marker, key never
// archived, live untouched) and a restore boots into requiresReplacement ──

func pdAssertArchiveStripped(t *testing.T, label string, files map[string][]byte, ciphertext string) {
	t.Helper()
	if _, ok := files["data/"+upstream.KeyFileName]; ok {
		t.Fatalf("%s: the node-local credential key must never be archived", label)
	}
	settings, ok := files["data/admin_settings.json"]
	if !ok {
		t.Fatalf("%s: admin_settings.json missing from the archive", label)
	}
	for name, needle := range map[string]string{"ciphertext": ciphertext, "ciphertext key": `"ciphertext"`, "keyId key": `"keyId"`,
		"authorityHash key": `"authorityHash"`, "redaction marker": "xxxxx", "password": pdCanaryPW} {
		if strings.Contains(string(settings), needle) {
			t.Fatalf("%s: the archived admin_settings.json must carry no credential material (%s found)", label, name)
		}
	}
	var m map[string]any
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatalf("%s: manifest: %v", label, err)
	}
	if m["credentialsOmitted"] != true {
		t.Fatalf("%s: manifest must record credentialsOmitted:true, got %v", label, m["credentialsOmitted"])
	}
	for name, body := range files {
		if strings.Contains(string(body), ciphertext) || strings.Contains(string(body), pdCanaryPW) {
			t.Fatalf("%s: %s carries credential material", label, name)
		}
	}
}

func TestUpstreamV2D_R40_BackupStripsAndRestoreBootsIntoRequiresReplacement(t *testing.T) {
	upEnv(t)
	id, ciphertext := pdSeed(t)
	srcDir := dataDir
	liveBefore := upSettingsFile(t)

	plain := filepath.Join(t.TempDir(), "plain.tar.gz")
	if err := runBackup(plain, srcDir); err != nil {
		t.Fatalf("backup: %v", err)
	}
	files, _, err := readTarball(plain, "")
	if err != nil {
		t.Fatal(err)
	}
	pdAssertArchiveStripped(t, "plain backup", files, ciphertext)

	enc := filepath.Join(t.TempDir(), "enc.tar.gz")
	const pass = "portability-pass-phrase-2026"
	if err := runBackupEncrypted(enc, srcDir, pass); err != nil {
		t.Fatalf("encrypted backup: %v", err)
	}
	encFiles, _, err := readTarball(enc, pass)
	if err != nil {
		t.Fatal(err)
	}
	pdAssertArchiveStripped(t, "encrypted backup", encFiles, ciphertext)

	// The live file and the live pool are untouched by the sanitized archive.
	if upSettingsFile(t) != liveBefore {
		t.Fatal("producing a sanitized archive must not rewrite the live settings file")
	}
	if e := upEntry(t, id); e["credentialState"] != upstream.CredentialConfigured {
		t.Fatalf("the live pool must keep its credential: %v", e)
	}

	// Restore onto a fresh node that already holds its own credential key.
	dstDir := t.TempDir()
	ownKey := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(filepath.Join(dstDir, upstream.KeyFileName), ownKey, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error {
		return runRestoreDryRun(plain, dstDir, "", restoreOpts{Mode: modeFull})
	})
	if err != nil {
		t.Fatalf("restore dry-run: %v", err)
	}
	if !strings.Contains(out, "credentials requiring replacement: 1") {
		t.Fatalf("the restore dry-run must report the exact count, got:\n%s", out)
	}
	if strings.Contains(out, ciphertext) || strings.Contains(out, pdCanaryPW) {
		t.Fatal("the restore dry-run must carry no credential material")
	}
	if _, err := captureStdout(t, func() error {
		return runRestoreCommit(plain, dstDir, "", restoreOpts{Mode: modeFull})
	}); err != nil {
		t.Fatalf("restore commit: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstDir, upstream.KeyFileName))
	if err != nil || !bytes.Equal(got, ownKey) {
		t.Fatalf("a restore must never delete or overwrite the node's existing credential key (err=%v)", err)
	}

	// Boot the restored node.
	snapshotUpstreamPool(t)
	upstreamPool.Configure(nil, 5, 60*time.Second)
	prevData := dataDir
	dataDir = dstDir
	t.Cleanup(func() { dataDir = prevData })
	swapAdminSettingsPath(t, filepath.Join(dstDir, "admin_settings.json"))
	raw, err := os.ReadFile(filepath.Join(dstDir, "admin_settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s AdminSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("restored settings: %v", err)
	}
	applyAdminNetwork(&s)

	v := upGet(t)
	e := upEntry(t, id)
	if e == nil {
		t.Fatalf("the restored entry must exist: %v", v)
	}
	if e["credentialState"] != "requiresReplacement" {
		t.Fatalf("a restored formerly-credentialed entry must be requiresReplacement, got %v", e["credentialState"])
	}
	if e["eligible"] != false {
		t.Fatalf("requiresReplacement must be ineligible: %v", e)
	}
	if v["credentialsRequiringReplacement"] != float64(1) {
		t.Fatalf("GET must surface credentialsRequiringReplacement:1, got %v", v["credentialsRequiringReplacement"])
	}
	if v["mode"] != upstream.ModeNoEligibleParent {
		t.Fatalf("before any traffic the mode must be no_eligible_parent, got %v", v["mode"])
	}
	if df, _ := v["direct_fallback"].(map[string]any); df["active"] != false {
		t.Fatalf("no fallback may be claimed before a request fell back: %v", df)
	}
	if u := upProxyURL(t); u != nil {
		t.Fatalf("a requiresReplacement parent must never be selected (url=%v)", u)
	}
	// The durable state survives an unrelated save + reload.
	if err := SaveAdminSettings(); err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(filepath.Join(dstDir, "admin_settings.json"))
	if strings.Contains(string(raw2), ciphertext) {
		t.Fatal("the restored node must not resurrect the ciphertext")
	}
	var s2 AdminSettings
	if err := json.Unmarshal(raw2, &s2); err != nil {
		t.Fatal(err)
	}
	upstreamPool.Configure(nil, 5, 60*time.Second)
	applyAdminNetwork(&s2)
	if e := upEntry(t, id); e["credentialState"] != "requiresReplacement" {
		t.Fatalf("requiresReplacement must be durable across save + reload, got %v", e["credentialState"])
	}
	// Explicit replacement (T2) clears the state.
	rev := int64(upEntry(t, id)["revision"].(float64))
	rec := upReq(t, "POST", "/api/upstream/entries/"+id+"/credential", fmt.Sprintf(`{"action":"replace","password":"new-pw-after-restore","revision":%d}`, rev))
	if rec.Code != 200 {
		t.Fatalf("replace after restore: %d %s", rec.Code, rec.Body.String())
	}
	if e := upEntry(t, id); e["credentialState"] != upstream.CredentialConfigured {
		t.Fatalf("T2 replace must resolve requiresReplacement, got %v", e["credentialState"])
	}
	if upGet(t)["credentialsRequiringReplacement"] != float64(0) {
		t.Fatal("the warning must clear once every affected entry is replaced")
	}
}

// ── C5 export contract: versioned v2 representation, credentials omitted ──

func TestUpstreamV2D_ExportCarriesVersionedV2ShapeWithoutCredentialMaterial(t *testing.T) {
	upEnv(t)
	id, ciphertext := pdSeed(t)
	for _, section := range []string{"", "upstream"} {
		rec := pdExport(t, section)
		if rec.Code != 200 {
			t.Fatalf("export %q: %d", section, rec.Code)
		}
		body := rec.Body.String()
		for _, needle := range []string{pdCanaryPW, ciphertext, "xxxxx", `"upstreamProxies"`, `"ciphertext"`, `"keyId"`} {
			if strings.Contains(body, needle) {
				t.Fatalf("export %q must not carry %q", section, needle)
			}
		}
		m := upJSON(t, rec)
		if m["version"] != float64(2) {
			t.Fatalf("export schema version must bump to 2, got %v", m["version"])
		}
		if m["upstream_credentials"] != "omitted" {
			t.Fatalf("export must declare upstream_credentials:\"omitted\", got %v", m["upstream_credentials"])
		}
		v2, _ := m["upstream_proxies_v2"].(map[string]any)
		entries, _ := v2["entries"].([]any)
		if len(entries) != 1 {
			t.Fatalf("export must carry the v2 entries: %v", m["upstream_proxies_v2"])
		}
		e, _ := entries[0].(map[string]any)
		if e["id"] != id || e["scheme"] != "http" || e["host"] != pdCanaryHost || e["port"] != float64(3128) ||
			e["username"] != pdCanaryUser || e["credentialState"] != upstream.CredentialConfigured {
			t.Fatalf("export entry shape: %v", e)
		}
		for k := range e {
			switch k {
			case "id", "scheme", "host", "port", "username", "credentialState":
			default:
				t.Fatalf("export entry carries an unexpected field %q", k)
			}
		}
	}
}

// ── R15: the complete sink matrix (canary password + ciphertext) ──

func TestUpstreamV2D_R15_CompleteSinkMatrix(t *testing.T) {
	upEnv(t)
	verDir := t.TempDir()
	prevVersions := configVersions
	configVersions = configver.New(verDir, 0)
	t.Cleanup(func() { configVersions = prevVersions })
	since := time.Now().UnixMilli()

	sinks := map[string]string{}
	var id, ciphertext string
	logOut := captureLogger(t, func() {
		id, ciphertext = pdSeed(t)
		upProbe(407, nil)
		sinks["api:GET /api/upstream"] = upReq(t, "GET", "/api/upstream", "").Body.String()
		sinks["api:GET /api/upstream/settings"] = upReq(t, "GET", "/api/upstream/settings", "").Body.String()
		sinks["api:GET /api/upstream/entries"] = upReq(t, "GET", "/api/upstream/entries", "").Body.String()
		sinks["api:POST /api/upstream/health"] = upReq(t, "POST", "/api/upstream/health", "").Body.String()
		sinks["api:error stale PUT"] = upReq(t, "PUT", "/api/upstream/entries/"+id,
			fmt.Sprintf(`{"scheme":"http","host":%q,"port":3128,"username":%q,"revision":999}`, pdCanaryHost, pdCanaryUser)).Body.String()
		sinks["api:error credentialState asserted"] = upReq(t, "POST", "/api/upstream/entries",
			fmt.Sprintf(`{"scheme":"http","host":"x.test","port":3128,"credentialState":"configured","revision":%d}`, upDocRevision(t))).Body.String()
		exp := pdExport(t, "")
		sinks["export:all"] = exp.Body.String()
		sinks["export:upstream"] = pdExport(t, "upstream").Body.String()
		sinks["import:dry-run report"] = pdImport(t, exp.Body.String(), "dryRun=1").Body.String()
		sinks["import:commit report"] = pdImport(t, exp.Body.String(), "").Body.String()
		d, _ := json.Marshal(diagnoseUpstream(time.Now()))
		sinks["diagnose upstream"] = string(d)
		snap, _ := json.Marshal(CurrentConfigSnapshot())
		sinks["cluster snapshot"] = string(snap)
		saveConfigVersion("pd-test", "upstream.pd")
	})
	sinks["process log"] = logOut
	for _, e := range auditGet() {
		if e.TS >= since {
			sinks["audit ring"] += e.Action + " " + e.Object + " " + e.Detail + " " + e.Before + " " + e.After + "\n"
		}
	}
	entries, _ := os.ReadDir(verDir)
	for _, f := range entries {
		b, _ := os.ReadFile(filepath.Join(verDir, f.Name()))
		sinks["config-version file "+f.Name()] = string(b)
	}
	for _, scope := range []string{"standard", "upstream"} {
		res, err := buildSupportBundle(context.Background(), support.L2, scope, "")
		if err != nil {
			t.Fatalf("support bundle %s: %v", scope, err)
		}
		for name, b := range pdTarFiles(t, res.TarGz) {
			sinks["support bundle "+scope+": "+name] = string(b)
		}
	}
	plain := filepath.Join(t.TempDir(), "plain.tar.gz")
	if err := runBackup(plain, dataDir); err != nil {
		t.Fatal(err)
	}
	files, _, err := readTarball(plain, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		sinks["backup plain: "+name] = string(b)
	}
	enc := filepath.Join(t.TempDir(), "enc.tar.gz")
	const pass = "portability-pass-phrase-2026"
	if err := runBackupEncrypted(enc, dataDir, pass); err != nil {
		t.Fatal(err)
	}
	encFiles, _, err := readTarball(enc, pass)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range encFiles {
		sinks["backup encrypted: "+name] = string(b)
	}
	dst := t.TempDir()
	out, err := captureStdout(t, func() error { return runRestoreDryRun(plain, dst, "", restoreOpts{Mode: modeFull}) })
	if err != nil {
		t.Fatal(err)
	}
	sinks["restore dry-run stdout"] = out

	if ciphertext == "" {
		t.Fatal("no ciphertext canary")
	}
	for name, body := range sinks {
		if strings.Contains(body, pdCanaryPW) {
			t.Errorf("sink %q carries the plaintext password", name)
		}
		if strings.Contains(body, ciphertext) {
			t.Errorf("sink %q carries the sealed ciphertext", name)
		}
	}
	// The live file (node-local, 0600) is the ONLY place the ciphertext lives.
	if !strings.Contains(upSettingsFile(t), ciphertext) {
		t.Fatal("control: the live settings file must still carry the sealed credential")
	}
}
