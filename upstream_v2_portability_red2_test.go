package main

// upstream_v2_portability_red2_test.go — 2F-D CORRECTION RED matrix,
// written against the rejected candidate 4b60d810 and executed on that
// untouched tree BEFORE the correction (external freeze review, two
// source-level blockers):
//
//   CR1  an existing requiresReplacement entry (no ciphertext) + same-id
//        import with a CHANGED authority and credentialState "none" must be
//        refused 409 credential_clear_required with the complete plan and
//        zero mutation — the candidate ran the ordinary update path and
//        assigned RequiresReplacement=false.
//   CR2  replace-mode OMISSION of such an entry must be refused the same
//        way — the candidate classified it as `remove` and the guard
//        checked Credential != nil only.
//   CR3  CONTROL: an identity-keyed preserve keeps the marker, and the
//        marker survives a disk reload.
//   CR4  CONTROL: only T2 replace / T3 clear resolve the marker.
//   CR5  an UNKNOWN credentialState is refused 400 (structured, offending
//        index only, the value never echoed) — the candidate read any
//        non-"none" value as credential evidence.
//   CR6  a MISSING credentialState is refused 400 the same way — the
//        candidate treated it as "none".
//   CR7  a v2 section without `upstream_credentials:"omitted"` (missing or
//        any other value) is refused 400 — the candidate never validated
//        the marker.
//   CR8  version/section mismatch (a v2 section under version 1; a
//        version-1 legacy list carrying the v2 marker) is refused 400.
//
// Every refusal: zero store mutation, no key minting, no success audit,
// no config-version advancement. Deterministic, no sleeps.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/configver"
	"github.com/KidCarmi/Culvert/internal/upstream"
)

const (
	pdcMarkedID = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
	pdcOtherID  = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
	pdcUnknown  = "sealed-elsewhere-8c1d" // an invented credentialState
)

// pdcEnv is upEnv plus an isolated config-version store; it returns the
// version directory so a refusal can be proven to advance nothing.
func pdcEnv(t *testing.T) string {
	t.Helper()
	upEnv(t)
	upstreamPool.Restore(upstream.PoolState{CBThreshold: 5, CBTimeout: time.Minute})
	verDir := t.TempDir()
	prev := configVersions
	configVersions = configver.New(verDir, 0)
	t.Cleanup(func() { configVersions = prev })
	return verDir
}

// pdcSeedMarked lands pdcMarkedID in the DISTINCT requiresReplacement state
// through the product's own path (a declared credential on an unknown
// identity — the export-onto-second-node shape); no key is ever minted.
func pdcSeedMarked(t *testing.T) {
	t.Helper()
	rec := pdImport(t, pdV2Payload(pdEntry(pdcMarkedID, pdCanaryHost, upstream.CredentialConfigured)), "")
	if rec.Code != 200 {
		t.Fatalf("seed: %d %s", rec.Code, rec.Body.String())
	}
	if e := upEntry(t, pdcMarkedID); e == nil || e["credentialState"] != upstream.CredentialRequiresReplacement {
		t.Fatalf("seed must land in requiresReplacement: %v", e)
	}
	adminSettingsSaveWG.Wait()
}

type pdcSnapshot struct {
	file    string
	rev     int64
	since   int64
	entries int
	verDir  string
}

func pdcSnap(t *testing.T, verDir string) pdcSnapshot {
	t.Helper()
	entries, _ := upGet(t)["entries"].([]any)
	return pdcSnapshot{file: upSettingsFile(t), rev: upDocRevision(t), since: time.Now().UnixMilli(), entries: len(entries), verDir: verDir}
}

// pdcAssertZeroMutation is the refusal contract: nothing on disk, in the
// runtime document, in the audit ring, in the version store or in the key
// file changed.
func pdcAssertZeroMutation(t *testing.T, label string, s pdcSnapshot) {
	t.Helper()
	if upSettingsFile(t) != s.file {
		t.Fatalf("%s: the settings file changed", label)
	}
	if upDocRevision(t) != s.rev {
		t.Fatalf("%s: the document revision moved", label)
	}
	if entries, _ := upGet(t)["entries"].([]any); len(entries) != s.entries {
		t.Fatalf("%s: entry count changed %d → %d", label, s.entries, len(entries))
	}
	if pdAuditCount(s.since, "config.import") != 0 {
		t.Fatalf("%s: a refused import must not audit success", label)
	}
	if n, _ := os.ReadDir(s.verDir); len(n) != 0 {
		t.Fatalf("%s: a refused import must not advance the config version (%d files)", label, len(n))
	}
	if _, err := os.Stat(filepath.Join(dataDir, upstream.KeyFileName)); err == nil {
		t.Fatalf("%s: a refused import must never mint the node-local key", label)
	}
}

// pdcReload re-reads the settings file the way a restart does and republishes.
func pdcReload(t *testing.T) {
	t.Helper()
	adminSettingsSaveWG.Wait()
	raw, err := os.ReadFile(adminSettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var s AdminSettings
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	upstreamPool.Configure(nil, 5, 60*time.Second)
	applyAdminNetwork(&s)
}

func pdcAssertClearRequired(t *testing.T, label string, rec *httptest.ResponseRecorder, id string) map[string]any {
	t.Helper()
	if rec.Code != http.StatusConflict {
		t.Fatalf("%s: must be 409, got %d %s", label, rec.Code, rec.Body.String())
	}
	if upJSON(t, rec)["code"] != "credential_clear_required" {
		t.Fatalf("%s: code must be credential_clear_required: %s", label, rec.Body.String())
	}
	plan := pdPlan(t, rec)
	if !pdContains(pdPlanClearRequired(plan), id) {
		t.Fatalf("%s: credentialClearRequired must name %s: %v", label, id, plan)
	}
	if a := pdPlanAction(plan, "existing", id); a != planRemove {
		t.Fatalf("%s: existing %s must be planned as remove, got %q", label, id, a)
	}
	return plan
}

// ── CR1: changed authority on a requiresReplacement entry ──

func TestUpstreamV2DC_CR1_ChangedAuthorityImportCannotClearRequiresReplacement(t *testing.T) {
	verDir := pdcEnv(t)
	pdcSeedMarked(t)
	snap := pdcSnap(t, verDir)
	moved := pdV2Payload(pdEntry(pdcMarkedID, "parent-moved.test", upstream.CredentialNone))

	for _, q := range []string{"", "dryRun=1", "mode=replace"} {
		rec := pdImport(t, moved, q)
		plan := pdcAssertClearRequired(t, "changed authority ("+q+")", rec, pdcMarkedID)
		if a := pdPlanAction(plan, "incoming", pdcMarkedID); a != planRequiresReplacement {
			t.Fatalf("incoming %s must be requiresReplacement (a changed authority never inherits the trust state), got %q", pdcMarkedID, a)
		}
		pdcAssertZeroMutation(t, "changed authority ("+q+")", snap)
		if e := upEntry(t, pdcMarkedID); e["host"] != pdCanaryHost || e["credentialState"] != upstream.CredentialRequiresReplacement {
			t.Fatalf("the refused import must leave the entry untouched: %v", e)
		}
	}
	// Durable: the marker is still on disk after a restart-shaped reload.
	pdcReload(t)
	if e := upEntry(t, pdcMarkedID); e["credentialState"] != upstream.CredentialRequiresReplacement || e["eligible"] != false {
		t.Fatalf("requiresReplacement must survive reload untouched: %v", e)
	}
}

// ── CR2: replace-mode omission of a requiresReplacement entry ──

func TestUpstreamV2DC_CR2_ReplaceModeOmissionCannotDiscardRequiresReplacement(t *testing.T) {
	verDir := pdcEnv(t)
	pdcSeedMarked(t)
	snap := pdcSnap(t, verDir)
	other := pdV2Payload(pdEntry(pdcOtherID, "parent-new.test", upstream.CredentialNone))

	for _, q := range []string{"mode=replace", "mode=replace&dryRun=1"} {
		rec := pdImport(t, other, q)
		plan := pdcAssertClearRequired(t, "replace omission ("+q+")", rec, pdcMarkedID)
		if a := pdPlanAction(plan, "incoming", pdcOtherID); a != planCreate {
			t.Fatalf("the unrelated incoming entry must still be planned as create, got %q", a)
		}
		pdcAssertZeroMutation(t, "replace omission ("+q+")", snap)
		if upEntry(t, pdcMarkedID) == nil || upEntry(t, pdcOtherID) != nil {
			t.Fatal("no store may be touched before the plan is accepted")
		}
	}
	// Merge mode retains it and is accepted (dry-run): the marker is never
	// the reason a merge is refused.
	rec := pdImport(t, other, "dryRun=1")
	if rec.Code != 200 {
		t.Fatalf("merge dry-run: %d %s", rec.Code, rec.Body.String())
	}
	if a := pdPlanAction(pdPlan(t, rec), "existing", pdcMarkedID); a != planRetain {
		t.Fatalf("merge must retain the marked entry, got %q", a)
	}
	pdcReload(t)
	if e := upEntry(t, pdcMarkedID); e["credentialState"] != upstream.CredentialRequiresReplacement {
		t.Fatalf("requiresReplacement must survive reload: %v", e)
	}
}

// ── CR3 (control): identity-keyed preserve keeps the marker; durable ──

func TestUpstreamV2DC_CR3_PreserveKeepsRequiresReplacementAcrossReload(t *testing.T) {
	verDir := pdcEnv(t)
	pdcSeedMarked(t)
	for _, declared := range []string{upstream.CredentialRequiresReplacement, upstream.CredentialNone, upstream.CredentialConfigured} {
		rec := pdImport(t, pdV2Payload(pdEntry(pdcMarkedID, pdCanaryHost, declared)), "")
		if rec.Code != 200 {
			t.Fatalf("same id + same authority (declared %s) must be accepted as preserve: %d %s", declared, rec.Code, rec.Body.String())
		}
		if e := upEntry(t, pdcMarkedID); e["credentialState"] != upstream.CredentialRequiresReplacement {
			t.Fatalf("preserve must keep the marker (declared %s): %v", declared, e)
		}
		if v := upGet(t); v["credentialsRequiringReplacement"] != float64(1) {
			t.Fatalf("count must stay 1: %v", v["credentialsRequiringReplacement"])
		}
	}
	// A legacy-list import naming the same authority (xxxxx) preserves too.
	rec := pdImport(t, fmt.Sprintf(`{"version":1,"upstreamProxies":[{"url":"http://%s:xxxxx@%s:3128"}]}`, pdCanaryUser, pdCanaryHost), "")
	if rec.Code != 200 {
		t.Fatalf("legacy preserve: %d %s", rec.Code, rec.Body.String())
	}
	if e := upEntry(t, pdcMarkedID); e["credentialState"] != upstream.CredentialRequiresReplacement {
		t.Fatalf("legacy preserve must keep the marker: %v", e)
	}
	pdcReload(t)
	if e := upEntry(t, pdcMarkedID); e["credentialState"] != upstream.CredentialRequiresReplacement {
		t.Fatalf("marker must survive reload: %v", e)
	}
	if n, _ := os.ReadDir(verDir); len(n) == 0 {
		t.Fatal("an ACCEPTED import must advance the config version (control)")
	}
}

// ── CR4 (control): only T2 replace / T3 clear resolve the marker ──

func TestUpstreamV2DC_CR4_OnlyT2OrT3ResolveRequiresReplacement(t *testing.T) {
	pdcEnv(t)
	pdcSeedMarked(t)
	rev := int64(upEntry(t, pdcMarkedID)["revision"].(float64))
	rec := upReq(t, "POST", "/api/upstream/entries/"+pdcMarkedID+"/credential",
		fmt.Sprintf(`{"action":"replace","password":%q,"revision":%d}`, pdCanaryPW, rev))
	if rec.Code != 200 {
		t.Fatalf("T2 replace: %d %s", rec.Code, rec.Body.String())
	}
	if e := upEntry(t, pdcMarkedID); e["credentialState"] != upstream.CredentialConfigured {
		t.Fatalf("T2 replace must resolve the marker into configured: %v", e)
	}
	// Second marked entry → T3 clear.
	rec = pdImport(t, pdV2Payload(pdEntry(pdcOtherID, "parent-two.test", upstream.CredentialConfigured)), "")
	if rec.Code != 200 {
		t.Fatalf("seed second: %d %s", rec.Code, rec.Body.String())
	}
	rev = int64(upEntry(t, pdcOtherID)["revision"].(float64))
	rec = upReq(t, "POST", "/api/upstream/entries/"+pdcOtherID+"/credential",
		fmt.Sprintf(`{"action":"clear","confirm":%q,"revision":%d}`, pdcOtherID, rev))
	if rec.Code != 200 {
		t.Fatalf("T3 clear: %d %s", rec.Code, rec.Body.String())
	}
	if e := upEntry(t, pdcOtherID); e["credentialState"] != upstream.CredentialNone {
		t.Fatalf("T3 clear must resolve the marker into none: %v", e)
	}
	if v := upGet(t); v["credentialsRequiringReplacement"] != float64(0) {
		t.Fatalf("count must be 0 after T2 + T3: %v", v["credentialsRequiringReplacement"])
	}
}

// ── schema validation (CR5–CR8) ──

// pdcSeedPlain creates a credential-free managed entry so the environment
// carries state to protect and NO key file (minting is observable).
func pdcSeedPlain(t *testing.T) string {
	t.Helper()
	rec := upReq(t, "POST", "/api/upstream/entries",
		fmt.Sprintf(`{"scheme":"http","host":%q,"port":3128,"username":%q,"revision":%d}`, pdCanaryHost, pdCanaryUser, upDocRevision(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed plain: %d %s", rec.Code, rec.Body.String())
	}
	entry, _ := upJSON(t, rec)["entry"].(map[string]any)
	id, _ := entry["id"].(string)
	adminSettingsSaveWG.Wait()
	return id
}

// pdcAssertSchema400 pins the structured refusal: 400, JSON, the bounded
// code, the offending index (when one applies) and never the offending
// value.
func pdcAssertSchema400(t *testing.T, label string, rec *httptest.ResponseRecorder, code string, index int, neverEcho string) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%s: must be 400, got %d %s", label, rec.Code, rec.Body.String())
	}
	body := upJSON(t, rec)
	if body["code"] != code {
		t.Fatalf("%s: code must be %s: %s", label, code, rec.Body.String())
	}
	if index >= 0 {
		if idx, ok := body["index"].(float64); !ok || int(idx) != index {
			t.Fatalf("%s: index must be %d: %s", label, index, rec.Body.String())
		}
	}
	if neverEcho != "" && strings.Contains(rec.Body.String(), neverEcho) {
		t.Fatalf("%s: the refusal must not echo the offending value: %s", label, rec.Body.String())
	}
}

func pdcPayloadRaw(version int, v2 any, marker any, legacy any) string {
	m := map[string]any{"version": version, "exportedAt": "2026-09-04T00:00:00Z"}
	if v2 != nil {
		m["upstream_proxies_v2"] = v2
	}
	if marker != nil {
		m["upstream_credentials"] = marker
	}
	if legacy != nil {
		m["upstreamProxies"] = legacy
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestUpstreamV2DC_CR5_UnknownCredentialStateRefused400(t *testing.T) {
	verDir := pdcEnv(t)
	id := pdcSeedPlain(t)
	snap := pdcSnap(t, verDir)
	payload := pdV2Payload(pdEntry(id, pdCanaryHost, upstream.CredentialNone), pdEntry(pdcOtherID, "parent-new.test", pdcUnknown))
	for _, q := range []string{"", "dryRun=1", "mode=replace"} {
		rec := pdImport(t, payload, q)
		pdcAssertSchema400(t, "unknown credentialState ("+q+")", rec, "invalid_credential_state", 1, pdcUnknown)
		pdcAssertZeroMutation(t, "unknown credentialState ("+q+")", snap)
		if upEntry(t, pdcOtherID) != nil {
			t.Fatal("no entry may be created by a refused import")
		}
	}
}

func TestUpstreamV2DC_CR6_MissingCredentialStateRefused400(t *testing.T) {
	verDir := pdcEnv(t)
	id := pdcSeedPlain(t)
	snap := pdcSnap(t, verDir)
	missing := pdEntry(pdcOtherID, "parent-new.test", "")
	delete(missing, "credentialState")
	empty := pdEntry("01ARZ3NDEKTSV4RRFFQ69G5FB2", "parent-three.test", "")
	for i, e := range []map[string]any{missing, empty} {
		payload := pdV2Payload(pdEntry(id, pdCanaryHost, upstream.CredentialNone), e)
		rec := pdImport(t, payload, "")
		pdcAssertSchema400(t, fmt.Sprintf("missing credentialState (variant %d)", i), rec, "invalid_credential_state", 1, "")
		pdcAssertZeroMutation(t, fmt.Sprintf("missing credentialState (variant %d)", i), snap)
	}
	// Control: every recognized state is accepted on a dry-run.
	for _, st := range []string{upstream.CredentialNone, upstream.CredentialConfigured, upstream.CredentialUnusable, upstream.CredentialMismatch, upstream.CredentialRequiresReplacement} {
		rec := pdImport(t, pdV2Payload(pdEntry(id, pdCanaryHost, upstream.CredentialNone), pdEntry(pdcOtherID, "parent-new.test", st)), "dryRun=1")
		if rec.Code != 200 {
			t.Fatalf("recognized state %q must plan: %d %s", st, rec.Code, rec.Body.String())
		}
	}
	pdcAssertZeroMutation(t, "dry-runs", snap)
}

func TestUpstreamV2DC_CR7_OmissionMarkerRequiredAndValidated(t *testing.T) {
	verDir := pdcEnv(t)
	id := pdcSeedPlain(t)
	snap := pdcSnap(t, verDir)
	v2 := map[string]any{"entries": []any{pdEntry(id, pdCanaryHost, upstream.CredentialNone)}}
	cases := []struct {
		label  string
		marker any
	}{
		{"marker missing", nil},
		{"marker included", "included"},
		{"marker invented", "sealed-4f2a"},
		{"marker wrong type", true},
	}
	for _, c := range cases {
		rec := pdImport(t, pdcPayloadRaw(2, v2, c.marker, nil), "")
		if s, ok := c.marker.(string); ok && s != "" {
			pdcAssertSchema400(t, c.label, rec, "invalid_upstream_credentials_marker", -1, s)
		} else if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: must be 400, got %d %s", c.label, rec.Code, rec.Body.String())
		}
		pdcAssertZeroMutation(t, c.label, snap)
	}
	// Control: the exact contract value is accepted.
	rec := pdImport(t, pdcPayloadRaw(2, v2, "omitted", nil), "dryRun=1")
	if rec.Code != 200 {
		t.Fatalf("the contract marker must be accepted: %d %s", rec.Code, rec.Body.String())
	}
}

func TestUpstreamV2DC_CR8_VersionSectionMismatchRefused400(t *testing.T) {
	verDir := pdcEnv(t)
	id := pdcSeedPlain(t)
	snap := pdcSnap(t, verDir)
	v2 := map[string]any{"entries": []any{pdEntry(id, pdCanaryHost, upstream.CredentialNone)}}
	legacy := []any{map[string]any{"url": "http://" + pdCanaryHost + ":3128"}}
	cases := []struct {
		label   string
		payload string
	}{
		{"v2 section under version 1", pdcPayloadRaw(1, v2, "omitted", nil)},
		{"version-1 legacy list carrying the v2 marker", pdcPayloadRaw(1, nil, "omitted", legacy)},
		{"version-2 file carrying the legacy list", pdcPayloadRaw(2, nil, nil, legacy)},
	}
	for _, c := range cases {
		rec := pdImport(t, c.payload, "")
		pdcAssertSchema400(t, c.label, rec, "schema_mismatch", -1, "")
		pdcAssertZeroMutation(t, c.label, snap)
	}
	// Controls: a coherent version-2 v2 document and a coherent version-1
	// legacy list both plan.
	for _, c := range []struct{ label, payload string }{
		{"coherent v2", pdcPayloadRaw(2, v2, "omitted", nil)},
		{"coherent legacy", pdcPayloadRaw(1, nil, nil, legacy)},
	} {
		rec := pdImport(t, c.payload, "dryRun=1")
		if rec.Code != 200 {
			t.Fatalf("%s must plan: %d %s", c.label, rec.Code, rec.Body.String())
		}
	}
	pdcAssertZeroMutation(t, "controls", snap)
}
