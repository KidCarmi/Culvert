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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── apiCDRConfigToggle ──────────────────────────────────────────────

// TestCDRHygiene_ConfigToggle_NoConfigVersion exercises
// PUT /api/cdr/config with {"enabled": true}, asserts 200, asserts the
// audit ring contains a "cdr.config.toggle" entry FROM THIS RUN (via
// TS baseline + unique TEST-NET-2 Actor IP per CLAUDE.md test-authoring
// pitfalls), and asserts no config-version envelope with that action
// exists on disk.
func TestCDRHygiene_ConfigToggle_NoConfigVersion(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	tmp := snapshotConfigVersionsDir(t)

	baselineTS := time.Now().UnixMilli()
	const actorIP = "198.51.100.61"

	w := httptest.NewRecorder()
	r := newAdminRequest(http.MethodPut, "/api/cdr/config", []byte(`{"enabled":true}`))
	r.RemoteAddr = actorIP + ":0"
	apiCDRConfig(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	if !cdrActiveConfig().Enabled {
		t.Fatal("runtime flag did not flip to enabled — handler did not reach audit")
	}
	assertCDRAuditFromThisRun(t, actorIP, "cdr.config.toggle", "cdr.enabled", baselineTS)
	assertNoConfigVersionWithAction(t, tmp, "cdr.config.toggle")
}

// ─── apiCDRInstances DELETE ──────────────────────────────────────────

// TestCDRHygiene_InstanceRemove_NoConfigVersion seeds an instance,
// DELETEs it, asserts 200, asserts the audit ring contains a
// "cdr.instance.remove" entry FROM THIS RUN, and asserts no
// config-version envelope. The instance Name is a unique
// discriminator that also appears as the audit Object.
func TestCDRHygiene_InstanceRemove_NoConfigVersion(t *testing.T) {
	resetCDRState(t)
	tmp := snapshotConfigVersionsDir(t)

	const (
		name    = "cdr-hygiene-instance-remove-target"
		actorIP = "198.51.100.62"
	)
	if _, err := cdrInstances.Add(CDREnrolledInstance{
		Name:     name,
		Endpoint: "sluice:8443",
	}); err != nil {
		t.Fatalf("seed cdrInstances: %v", err)
	}

	baselineTS := time.Now().UnixMilli()
	w := httptest.NewRecorder()
	r := newAdminRequest(http.MethodDelete, "/api/cdr/instances?name="+name, nil)
	r.RemoteAddr = actorIP + ":0"
	apiCDRInstances(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	if cdrInstances.Get(name) != nil {
		t.Errorf("instance %q still in registry after DELETE", name)
	}
	assertCDRAuditFromThisRun(t, actorIP, "cdr.instance.remove", name, baselineTS)
	assertNoConfigVersionWithAction(t, tmp, "cdr.instance.remove")
}

// ─── apiCDRPolicies POST ─────────────────────────────────────────────

// TestCDRHygiene_PolicyAdd_NoConfigVersion POSTs a minimal valid
// policy rule, asserts 200, asserts the audit ring contains a
// "cdr.policy.add" entry FROM THIS RUN, and asserts no config-version
// envelope. The rule Name is a unique discriminator that also appears
// as the audit Object.
func TestCDRHygiene_PolicyAdd_NoConfigVersion(t *testing.T) {
	resetCDRState(t)
	tmp := snapshotConfigVersionsDir(t)

	const (
		name    = "cdr-hygiene-policy-add"
		actorIP = "198.51.100.63"
	)
	rule := CDRPolicyRule{
		Priority:    100,
		Name:        name,
		ProfileName: "default",
		Mode:        "ENFORCE",
	}
	body, _ := json.Marshal(rule)

	baselineTS := time.Now().UnixMilli()
	w := httptest.NewRecorder()
	r := newAdminRequest(http.MethodPost, "/api/cdr/policies", body)
	r.RemoteAddr = actorIP + ":0"
	apiCDRPolicies(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	assertCDRAuditFromThisRun(t, actorIP, "cdr.policy.add", name, baselineTS)
	assertNoConfigVersionWithAction(t, tmp, "cdr.policy.add")
}

// ─── apiCDRPolicies DELETE ───────────────────────────────────────────

// TestCDRHygiene_PolicyRemove_NoConfigVersion seeds a policy rule
// directly into cdrPolicyStore, DELETEs it via the handler, asserts
// 200 + audit FROM THIS RUN + no envelope.
func TestCDRHygiene_PolicyRemove_NoConfigVersion(t *testing.T) {
	resetCDRState(t)
	tmp := snapshotConfigVersionsDir(t)

	const (
		name    = "cdr-hygiene-policy-remove-target"
		actorIP = "198.51.100.64"
	)
	if _, err := cdrPolicyStore.Add(CDRPolicyRule{
		Priority:    200,
		Name:        name,
		ProfileName: "default",
		Mode:        "ENFORCE",
	}); err != nil {
		t.Fatalf("seed cdrPolicyStore: %v", err)
	}

	baselineTS := time.Now().UnixMilli()
	w := httptest.NewRecorder()
	r := newAdminRequest(http.MethodDelete, "/api/cdr/policies?name="+name, nil)
	r.RemoteAddr = actorIP + ":0"
	apiCDRPolicies(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	assertCDRAuditFromThisRun(t, actorIP, "cdr.policy.remove", name, baselineTS)
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
	data, err := os.ReadFile(filepath.Join(pkgSourceDir(), "cdr_ui.go"))
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

// assertCDRAuditFromThisRun scans the audit ring for an entry whose
// (Actor, Action, Object) match the given values AND whose TS is
// >= sinceTS. Per CLAUDE.md test-authoring pitfalls and the canonical
// pattern in security_feedsync_audit_test.go: the Action string alone
// is NOT a sufficient discriminator because sibling tests in the
// suite (e.g. TestApiCDRConfigToggle_OnThenOff in cdr_ui_test.go)
// emit the same Actions during the same -shuffle=on test binary
// invocation, leaving matching entries in the global ring.
//
// The three-axis discriminator (TEST-NET-2 Actor IP unique per
// hygiene test + Action + Object + TS baseline) guarantees the entry
// can only have been emitted by THIS test's invocation of the
// production handler.
//
// Codex P2 catch on PR #265 — replaces the earlier (weaker)
// assertAuditAction helper which only matched on Action.
func assertCDRAuditFromThisRun(t *testing.T, actor, action, object string, sinceTS int64) {
	t.Helper()
	for _, e := range auditGet() {
		if e.Actor == actor && e.Action == action && e.Object == object && e.TS >= sinceTS {
			return
		}
	}
	t.Errorf("no audit entry from this run found "+
		"(Actor=%q Action=%q Object=%q TS>=%d) — proves audit path did NOT "+
		"execute on this test's handler invocation (test setup is broken OR "+
		"the production removal removed too much)", actor, action, object, sinceTS)
}
