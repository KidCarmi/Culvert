package main

// config_import_warnings_test.go — POST /api/config/import must never report
// "ok: true" while silently discarding part of the backup. Several sections
// (policy rules that fail validation, content-scan patterns that share an
// envelope with bypass hosts, the block page template, IP filter entries)
// were previously only logged via logger.Printf on skip — an admin restoring
// a backup after an incident had no way to learn from the API response that
// anything was dropped. This pins the `warnings` field that now carries those
// already-computed skip reasons into the response.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAPIConfigImport_WarnsOnSkippedPolicyRule verifies that a policy rule
// dropped for failing validation (here: a priority collision with an
// existing rule) is named in the response's "warnings" field, not just the
// process log.
func TestAPIConfigImport_WarnsOnSkippedPolicyRule(t *testing.T) {
	withFreshPolicyStore(t)

	const clashPri = 511
	policyStore.Add(PolicyRule{Priority: clashPri, Name: "seed-rule", Action: ActionAllow})

	backup := configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			{Priority: clashPri, Name: "import-clash-rule", Action: ActionDrop},
		},
	}
	bodyJSON, _ := json.Marshal(backup)
	req := httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.3:9999"
	req = adminCtx(req)

	w := httptest.NewRecorder()
	apiConfigImport(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("apiConfigImport returned %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["ok"] != true {
		t.Fatalf("expected ok:true, got %v", resp["ok"])
	}
	warnings, ok := resp["warnings"].([]any)
	if !ok || len(warnings) == 0 {
		t.Fatalf("BUG: import silently dropped a rule but response carries no warnings: %v", resp)
	}
	found := false
	for _, w := range warnings {
		if s, ok := w.(string); ok && strings.Contains(s, "import-clash-rule") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings %v do not mention the skipped rule name", warnings)
	}
}

// TestAPIConfigImport_NoWarningsWhenNothingSkipped confirms the field is
// absent (not an empty list a caller must always check) when every section
// of the backup applies cleanly, keeping the common-case response unchanged.
func TestAPIConfigImport_NoWarningsWhenNothingSkipped(t *testing.T) {
	withFreshPolicyStore(t)

	backup := configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			{Priority: 512, Name: "clean-import-rule", Action: ActionAllow},
		},
	}
	bodyJSON, _ := json.Marshal(backup)
	req := httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.4:9999"
	req = adminCtx(req)

	w := httptest.NewRecorder()
	apiConfigImport(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("apiConfigImport returned %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, present := resp["warnings"]; present {
		t.Errorf("expected no warnings field on a clean import, got %v", resp["warnings"])
	}
}
