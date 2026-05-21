package main

// cdr_hygiene_no_versioning_test.go — regression coverage for the
// Category D' (direction A) CDR hygiene removal. Per
// roadmap/CATEGORY-D-PRIME-DIRECTION.md §3.
//
// Five CDR handlers previously called saveConfigVersion(...) for a
// state surface that is not in captureConfigBackup/applyConfigBackup.
// This PR removed those calls; cdr.instance.revoke_rpc was removed
// separately in PR #263 as a security-sensitive Category D-sec case.
//
// Handlers covered here:
//   - apiCDRConfigToggle      ("cdr.config.toggle")
//   - apiCDRInstances DELETE  ("cdr.instance.remove")
//   - apiCDRPolicies POST     ("cdr.policy.add")
//   - apiCDRPolicies DELETE   ("cdr.policy.remove")
//
// The fifth handler (apiCDREnroll → "cdr.instance.enroll") performs a
// real Sluice gRPC Enroll RPC with TLS fingerprint pinning, which is
// impractical to fake at unit-test scope. For that handler the test
// suite uses a STRUCTURAL assertion that scans cdr_ui.go for any
// remaining live saveConfigVersion(...) call sites — combined with
// the four full-path tests below, this proves the file is clean.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ─── apiCDRConfigToggle ──────────────────────────────────────────────

// TestCDRHygiene_ConfigToggle_NoConfigVersion exercises
// PUT /api/cdr/config with {"enabled": true}, asserts 200, asserts the
// audit ring contains a "cdr.config.toggle" entry, and asserts no
// config-version envelope with that action exists on disk.
func TestCDRHygiene_ConfigToggle_NoConfigVersion(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	tmp := snapshotConfigVersionsDir(t)

	// PUT enable.
	w := httptest.NewRecorder()
	apiCDRConfig(w, newAdminRequest(http.MethodPut, "/api/cdr/config",
		[]byte(`{"enabled":true}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	if !cdrActiveConfig().Enabled {
		t.Fatal("runtime flag did not flip to enabled — handler did not reach audit")
	}
	assertAuditAction(t, "cdr.config.toggle")
	assertNoConfigVersionWithAction(t, tmp, "cdr.config.toggle")
}

// ─── apiCDRInstances DELETE ──────────────────────────────────────────

// TestCDRHygiene_InstanceRemove_NoConfigVersion seeds an instance,
// DELETEs it, asserts 200, asserts the audit ring contains a
// "cdr.instance.remove" entry, and asserts no config-version envelope.
func TestCDRHygiene_InstanceRemove_NoConfigVersion(t *testing.T) {
	resetCDRState(t)
	tmp := snapshotConfigVersionsDir(t)

	const name = "cdr-hygiene-instance-remove-target"
	if _, err := cdrInstances.Add(CDREnrolledInstance{
		Name:     name,
		Endpoint: "sluice:8443",
	}); err != nil {
		t.Fatalf("seed cdrInstances: %v", err)
	}

	w := httptest.NewRecorder()
	apiCDRInstances(w, newAdminRequest(http.MethodDelete,
		"/api/cdr/instances?name="+name, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	if cdrInstances.Get(name) != nil {
		t.Errorf("instance %q still in registry after DELETE", name)
	}
	assertAuditAction(t, "cdr.instance.remove")
	assertNoConfigVersionWithAction(t, tmp, "cdr.instance.remove")
}

// ─── apiCDRPolicies POST ─────────────────────────────────────────────

// TestCDRHygiene_PolicyAdd_NoConfigVersion POSTs a minimal valid
// policy rule, asserts 200, asserts the audit ring contains a
// "cdr.policy.add" entry, and asserts no config-version envelope.
func TestCDRHygiene_PolicyAdd_NoConfigVersion(t *testing.T) {
	resetCDRState(t)
	tmp := snapshotConfigVersionsDir(t)

	rule := CDRPolicyRule{
		Priority:    100,
		Name:        "cdr-hygiene-policy-add",
		ProfileName: "default",
		Mode:        "ENFORCE",
	}
	body, _ := json.Marshal(rule)

	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodPost, "/api/cdr/policies", body))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	assertAuditAction(t, "cdr.policy.add")
	assertNoConfigVersionWithAction(t, tmp, "cdr.policy.add")
}

// ─── apiCDRPolicies DELETE ───────────────────────────────────────────

// TestCDRHygiene_PolicyRemove_NoConfigVersion seeds a policy rule
// directly into cdrPolicyStore, DELETEs it via the handler, asserts
// 200 + audit + no envelope.
func TestCDRHygiene_PolicyRemove_NoConfigVersion(t *testing.T) {
	resetCDRState(t)
	tmp := snapshotConfigVersionsDir(t)

	const name = "cdr-hygiene-policy-remove-target"
	if _, err := cdrPolicyStore.Add(CDRPolicyRule{
		Priority:    200,
		Name:        name,
		ProfileName: "default",
		Mode:        "ENFORCE",
	}); err != nil {
		t.Fatalf("seed cdrPolicyStore: %v", err)
	}

	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodDelete,
		"/api/cdr/policies?name="+name, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	assertAuditAction(t, "cdr.policy.remove")
	assertNoConfigVersionWithAction(t, tmp, "cdr.policy.remove")
}

// ─── Structural assertion (covers apiCDREnroll + belt-and-suspenders) ─

// TestCDRHygiene_NoLiveSaveConfigVersionCallsInCDRUI scans cdr_ui.go
// for any remaining live `saveConfigVersion(...)` call site. With this
// PR + PR #263 (revoke_rpc), the file has zero such calls. Catches
// future regressions where a new handler is added with a
// saveConfigVersion call that contradicts the file's documented
// rollback contract (see cdr_ui.go header).
//
// Required because apiCDREnroll is impractical to exercise at unit-
// test scope (real Sluice gRPC endpoint with TLS fingerprint pinning).
// This structural test catches the enroll case AND any future CDR
// handler that drifts back into the misleading pattern.
func TestCDRHygiene_NoLiveSaveConfigVersionCallsInCDRUI(t *testing.T) {
	data, err := os.ReadFile("cdr_ui.go")
	if err != nil {
		t.Fatalf("read cdr_ui.go: %v", err)
	}
	// Walk line-by-line so comment lines (which legitimately mention
	// the identifier) can be excluded. A "live call" is a non-comment
	// line containing `saveConfigVersion(`.
	for i, line := range bytes.Split(data, []byte("\n")) {
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "//") {
			continue // comment line — header references to the function name
		}
		if strings.Contains(trimmed, "saveConfigVersion(") {
			t.Errorf("cdr_ui.go line %d contains a live saveConfigVersion call: %s\n"+
				"CDR state is NOT in the rollback surface (captureConfigBackup does NOT read cdr_*.json). "+
				"Per roadmap/CATEGORY-D-PRIME-DIRECTION.md §3, CDR handlers must NOT call saveConfigVersion. "+
				"See cdr_ui.go header for the documented rollback contract.",
				i+1, trimmed)
		}
	}
}

// ─── shared assertion helper ─────────────────────────────────────────

// assertAuditAction scans the audit ring for an entry with the given
// Action string. Per CLAUDE.md test-authoring pitfalls, does NOT
// assert on len(auditGet()) deltas — the ring saturates at
// maxAuditLogs=500.
//
// Lighter than assertAuditEntryWithDiscriminator (used by the
// security-PR tests) because these hygiene tests just need to confirm
// the audit path executed; discriminator-based search is unnecessary
// when the Action is unique per test and other tests in the suite
// don't emit the same Action.
func assertAuditAction(t *testing.T, action string) {
	t.Helper()
	for _, e := range auditGet() {
		if e.Action == action {
			return
		}
	}
	t.Errorf("no audit entry with Action=%q found — proves audit path did NOT execute "+
		"(test setup is broken OR the production removal removed too much)", action)
}
