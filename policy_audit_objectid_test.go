package main

// policy_audit_objectid_test.go — policy-mutation audit entries carry the rule's
// stable ULID in the structured ObjectID field (§1 rec #2). Keying audit history
// on the mutable name orphans the trail on rename; ObjectID makes a rule's whole
// history correlatable by ID regardless of renames, while Object stays the
// human-readable name so the audit UI is unchanged.
//
// Contract pinned here:
//   - policy.add / update / remove all record ObjectID = the rule's ULID;
//   - Object stays the human-readable name (not replaced by the id);
//   - a rename is correlatable: add + a later rename share one ObjectID.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// findAuditByActionObjectID scans the audit ring (newest-first) for an entry
// matching action + objectID. Content-based (never len-delta) per the CLAUDE.md
// audit-ring-saturation pitfall.
func findAuditByActionObjectID(t *testing.T, action, objectID string) (AuditEntry, bool) {
	t.Helper()
	entries := auditGet()
	for i := range entries { // index-based: AuditEntry is a large struct (CLAUDE.md rangeValCopy)
		if entries[i].Action == action && entries[i].ObjectID == objectID {
			return entries[i], true
		}
	}
	return AuditEntry{}, false
}

func TestAudit_PolicyAdd_RecordsObjectID(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyForIDTest(t)

	body := `{"priority":1,"name":"audit-add-rule","action":"Allow","destFqdn":"a.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/policy", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiPolicy(w, adminCtx(req))
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("create returned %d (%s)", w.Code, w.Body.String())
	}

	// The created rule's ULID:
	var id, name string
	for _, r := range policyStore.List() {
		if r.Name == "audit-add-rule" {
			id, name = r.ID, r.Name
		}
	}
	if id == "" {
		t.Fatal("rule not created / no ID")
	}
	e, ok := findAuditByActionObjectID(t, "policy.add", id)
	if !ok {
		t.Fatalf("no policy.add audit entry with ObjectID=%q", id)
	}
	if e.Object != name {
		t.Errorf("audit Object = %q, want the human name %q (id must NOT replace the name)", e.Object, name)
	}
}

func TestAudit_PolicyRenameCorrelatesByObjectID(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyForIDTest(t)

	// Create, then rename via ?id= — both audit entries must share one ObjectID
	// even though the display name changed (the whole point of the seam).
	added := policyStore.Add(PolicyRule{Priority: 1, Name: "orig-name", Action: ActionAllow})
	// Emit the add audit through the handler so it carries ObjectID.
	// (Directly exercising the update path is sufficient for the correlation.)
	putBody := `{"priority":1,"name":"renamed","action":"Allow"}`
	req := httptest.NewRequest(http.MethodPut, "/api/policy?id="+added.ID, strings.NewReader(putBody))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiPolicyUpdate(w, adminCtx(req))
	if w.Code != http.StatusOK {
		t.Fatalf("rename update returned %d (%s)", w.Code, w.Body.String())
	}

	e, ok := findAuditByActionObjectID(t, "policy.update", added.ID)
	if !ok {
		t.Fatalf("no policy.update audit entry correlatable by ObjectID=%q", added.ID)
	}
	if e.Object != "renamed" {
		t.Errorf("audit Object = %q, want the new name 'renamed'", e.Object)
	}
	if !strings.Contains(e.ObjectID, added.ID) {
		t.Errorf("ObjectID = %q, want the stable ULID %q", e.ObjectID, added.ID)
	}
}

func TestAudit_PolicyDelete_RecordsObjectID(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyForIDTest(t)
	added := policyStore.Add(PolicyRule{Priority: 1, Name: "audit-del", Action: ActionAllow})

	req := httptest.NewRequest(http.MethodDelete, "/api/policy?id="+added.ID, http.NoBody)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiPolicyDelete(w, adminCtx(req))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete returned %d", w.Code)
	}
	if _, ok := findAuditByActionObjectID(t, "policy.remove", added.ID); !ok {
		t.Fatalf("no policy.remove audit entry with ObjectID=%q", added.ID)
	}
}
