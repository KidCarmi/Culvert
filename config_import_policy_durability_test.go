package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// importDurabilityFixture seeds one persisted Drop rule and returns the policy
// file's directory, so a test can take the storage away.
func importDurabilityFixture(t *testing.T) (dir, path string) {
	t.Helper()
	refGateSetup(t)
	prev := defaultPolicyAction()
	setDefaultPolicyAction("allow")
	t.Cleanup(func() { setDefaultPolicyAction(prev) })

	dir = filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "policy.json")
	policyStore.ReplaceAll([]PolicyRule{{Name: "old-block", Priority: 1, Action: ActionDrop, DestFQDN: "evil.example"}})
	policyStore.path = path // restored by refGateSetup's policy-store snapshot
	if err := policyStore.SaveErr(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	return dir, path
}

func importReplaceForTest(t *testing.T, rules []PolicyRule) (code int, resp map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode=replace", &configBackup{Version: 1, PolicyRules: rules}))
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return w.Code, resp
}

// An import whose policy rules are live but could not be written to the policy
// file used to answer 200 {"ok":true} with no warning: the running policy was
// the imported one, the file still held the previous one, and a restart
// reverted the import. It must say so.
func TestConfigImport_PolicyWriteFailureIsReportedNotOK(t *testing.T) {
	dir, path := importDurabilityFixture(t)

	// Storage becomes unavailable (stands in for a full, read-only or
	// unmounted volume).
	parked := dir + ".offline"
	if err := os.Rename(dir, parked); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			_ = os.Rename(parked, dir)
		}
	}
	t.Cleanup(restore)
	if err := policyStore.SaveErr(); err == nil {
		t.Fatal("premise: the policy write must fail while storage is unavailable")
	}

	uniq := "exported-" + t.Name()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode=replace", &configBackup{
		Version: 1, ExportedAt: uniq,
		PolicyRules: []PolicyRule{{Name: "new-allow", Priority: 1, Action: ActionAllow, DestFQDN: "evil.example"}},
	}))
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500: the import did not fully succeed", w.Code)
	}
	if resp["ok"] != false || resp["status"] != "imported_not_durable" ||
		resp["applied"] != true || resp["policy_persisted"] != false {
		t.Errorf("response does not report the non-durable import: %v", resp)
	}
	if resp["retry_safe"] != true {
		t.Errorf("a replace-mode import is idempotent; retry_safe = %v, want true", resp["retry_safe"])
	}
	if rec, _ := resp["recovery"].(string); rec == "" {
		t.Error("the not-durable response carries no recovery guidance")
	}
	if msg, _ := resp["error"].(string); strings.Contains(msg, dir) || strings.Contains(msg, parked) {
		t.Errorf("response error carries a filesystem path: %q", msg)
	}

	// The body must be truthful about both halves: applied, and not durable.
	if got := ruleNamesOf(policyStore.List()); got != "new-allow" {
		t.Errorf("active rules = [%s], want [new-allow] (the response says applied)", got)
	}
	restore()
	disk := &PolicyStore{}
	if err := disk.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := ruleNamesOf(disk.List()); got != "old-block" {
		t.Errorf("persisted rules = [%s], want [old-block] (the response says not persisted)", got)
	}

	found := false
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.Action == "config.import" && strings.Contains(e.Detail, uniq) {
			found = true
			if !strings.Contains(e.Detail, "NOT DURABLE") {
				t.Errorf("audit entry does not record the failed write: %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("no config.import audit entry for this import")
	}
}

// Control: with storage available the same import answers 200 ok and the file
// holds the imported rules, so the test above fails for the write and nothing
// else.
func TestConfigImport_PolicyWriteSuccessStaysOK(t *testing.T) {
	_, path := importDurabilityFixture(t)
	code, resp := importReplaceForTest(t, []PolicyRule{{Name: "new-allow", Priority: 1, Action: ActionAllow, DestFQDN: "evil.example"}})
	if code != http.StatusOK || resp["ok"] != true {
		t.Fatalf("status %d, body %v", code, resp)
	}
	if _, present := resp["policy_persisted"]; present {
		t.Errorf("a durable import must not carry the not-durable fields: %v", resp)
	}
	disk := &PolicyStore{}
	if err := disk.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := ruleNamesOf(disk.List()); got != "new-allow" {
		t.Errorf("persisted rules = [%s], want [new-allow]", got)
	}
}

// Retrying the same replace-mode import once storage is back must converge:
// 200, the file holds the imported rules, and the rule set is exactly the
// imported one (no duplicates, nothing left from the failed attempt).
func TestConfigImport_RetryAfterStorageReturnsIsIdempotent(t *testing.T) {
	dir, path := importDurabilityFixture(t)
	parked := dir + ".offline"
	if err := os.Rename(dir, parked); err != nil {
		t.Fatal(err)
	}
	rules := []PolicyRule{
		{Name: "new-block", Priority: 1, Action: ActionDrop, DestFQDN: "evil.example"},
		{Name: "new-allow", Priority: 2, Action: ActionAllow, DestFQDN: "ok.example"},
	}
	code, _ := importReplaceForTest(t, rules)
	if err := os.Rename(parked, dir); err != nil {
		t.Fatal(err)
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("premise: first attempt status = %d, want 500", code)
	}

	code, resp := importReplaceForTest(t, rules)
	if code != http.StatusOK || resp["ok"] != true {
		t.Fatalf("retry status %d, body %v", code, resp)
	}
	const want = "new-block,new-allow"
	if got := ruleNamesOf(policyStore.List()); got != want {
		t.Errorf("active rules after retry = [%s], want [%s]", got, want)
	}
	disk := &PolicyStore{}
	if err := disk.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := ruleNamesOf(disk.List()); got != want {
		t.Errorf("persisted rules after retry = [%s], want [%s]", got, want)
	}
}

// A merge-mode import is not idempotent (alert webhooks are appended), so its
// not-durable answer must not invite a blind retry.
func TestConfigImport_MergeModeNotDurableIsNotRetrySafe(t *testing.T) {
	importDurabilityFixture(t)
	prev := persistRunningPolicy
	persistRunningPolicy = func() error { return os.ErrPermission }
	t.Cleanup(func() { persistRunningPolicy = prev })

	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import", &configBackup{
		Version:     1,
		PolicyRules: []PolicyRule{{Name: "merged", Priority: 7, Action: ActionDrop, DestFQDN: "m.example"}},
	}))
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	if w.Code != http.StatusInternalServerError || resp["status"] != "imported_not_durable" {
		t.Fatalf("status %d, body %v", w.Code, resp)
	}
	if resp["retry_safe"] != false {
		t.Errorf("merge mode retry_safe = %v, want false", resp["retry_safe"])
	}
}

// A write that replaced the policy file but could not sync its directory HAS
// landed; reporting it as not persisted would be untrue the other way round.
func TestConfigImport_ReplacedButNotSyncedCountsAsPersisted(t *testing.T) {
	importDurabilityFixture(t)
	prev := persistRunningPolicy
	persistRunningPolicy = func() error {
		if err := policyStore.SaveErr(); err != nil {
			return err
		}
		return fileutil.ErrReplacedNotSynced
	}
	t.Cleanup(func() { persistRunningPolicy = prev })

	code, resp := importReplaceForTest(t, []PolicyRule{{Name: "new-allow", Priority: 1, Action: ActionAllow, DestFQDN: "evil.example"}})
	if code != http.StatusOK || resp["ok"] != true {
		t.Fatalf("status %d, body %v", code, resp)
	}
}
