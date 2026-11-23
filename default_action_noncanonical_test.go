package main

// default_action_noncanonical_test.go — owner decision D: a stored default
// policy action that is not exactly "allow" or "deny" is enforced as deny
// (unchanged) and REPORTED at every door that ingests one: admin_settings.json
// (log + gauge + diagnostics row, raw value kept on disk until an explicit
// set), config-version rollback (real response + audit detail), config import
// (response + preview) and the CP→DP snapshot (warn + counter, never
// rejected). Nothing here may reinterpret a value as allow.

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
)

// keepDefaultPolicyAction restores the enforced default action after a test.
// The restoring set also advances the action word, which retires any
// non-canonical record the test left behind.
func keepDefaultPolicyAction(t *testing.T) {
	t.Helper()
	orig := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(orig) })
}

// noncanonicalGauge reads culvert_default_action_noncanonical{source} from the
// exposition the metrics handler emits.
func noncanonicalGauge(t *testing.T, source string) string {
	t.Helper()
	var b strings.Builder
	defaultActionWritePrometheus(&b)
	prefix := fmt.Sprintf("culvert_default_action_noncanonical{source=%q} ", source)
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("no %s series in:\n%s", prefix, b.String())
	return ""
}

func noncanonicalApplied(source string) int64 {
	return noncanonicalDefaultActionApplied[noncanonicalDefaultActionSourceIndex(source)].Load()
}

func TestParseDefaultAction_OnlyExactSpellings(t *testing.T) {
	for _, s := range []string{"allow", "deny"} {
		if got, ok := parseDefaultAction(s); !ok || got != s {
			t.Errorf("parseDefaultAction(%q) = %q,%v; want %q,true", s, got, ok, s)
		}
	}
	for _, s := range []string{"", "Allow", "ALLOW", "Deny", "block", " allow", "allow ", "permit"} {
		if got, ok := parseDefaultAction(s); ok || got != "" {
			t.Errorf("parseDefaultAction(%q) = %q,%v; want \"\",false", s, got, ok)
		}
	}
}

// TestSetDefaultPolicyAction_SemanticsUnchanged pins the enforcement the
// owner decision preserves: exactly "allow" is allow, every other string is
// deny — no case folding, no trimming, "block" is deny.
func TestSetDefaultPolicyAction_SemanticsUnchanged(t *testing.T) {
	keepDefaultPolicyAction(t)
	cases := []struct{ in, want string }{
		{"allow", "allow"}, {"deny", "deny"}, {"Allow", "deny"}, {"ALLOW", "deny"},
		{"block", "deny"}, {" allow", "deny"}, {"", "deny"}, {"permit", "deny"},
	}
	for _, tc := range cases {
		setDefaultPolicyAction("allow") // start from allow so a deny is observable
		setDefaultPolicyAction(tc.in)
		if got := defaultPolicyAction(); got != tc.want {
			t.Errorf("setDefaultPolicyAction(%q) enforced %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestAdminSettingsDefaultAction_NoncanonicalDeniesWarnsAndRaisesGauge(t *testing.T) {
	keepDefaultPolicyAction(t)
	for _, raw := range []string{"Allow", "ALLOW", "block", " allow"} {
		t.Run(fmt.Sprintf("%q", raw), func(t *testing.T) {
			setDefaultPolicyAction("allow") // e.g. YAML said allow before admin settings applied
			before := noncanonicalApplied(defaultActionSourceAdminSettings)
			out := captureLogger(t, func() { applyAdminDefaultAction(raw) })

			if got := defaultPolicyAction(); got != "deny" {
				t.Fatalf("enforced %q; want deny (fail-closed, never reinterpreted)", got)
			}
			want := fmt.Sprintf("AdminSettings: default_action %q is not \"allow\" or \"deny\"; enforcing deny (fail-closed). Set it explicitly via Policy → Default action.", raw)
			if !strings.Contains(out, want) {
				t.Errorf("log = %q; want it to contain %q", out, want)
			}
			if g := noncanonicalGauge(t, defaultActionSourceAdminSettings); g != "1" {
				t.Errorf("gauge{admin_settings} = %s; want 1", g)
			}
			if g := noncanonicalGauge(t, defaultActionSourceSnapshot); g != "0" {
				t.Errorf("gauge{cluster_snapshot} = %s; want 0", g)
			}
			if got := noncanonicalApplied(defaultActionSourceAdminSettings); got != before+1 {
				t.Errorf("applied counter = %d; want %d", got, before+1)
			}
			row := checkDefaultActionStoredValue()
			if row.Status != diagWarn || !strings.Contains(row.Message, fmt.Sprintf("%q", raw)) || row.OperatorAction == "" {
				t.Errorf("diagnostics row = %+v; want warn naming %q with an operator action", row, raw)
			}

			// An explicit set retires the report without a restart.
			setDefaultPolicyAction("deny")
			if g := noncanonicalGauge(t, defaultActionSourceAdminSettings); g != "0" {
				t.Errorf("gauge after explicit set = %s; want 0", g)
			}
			if row := checkDefaultActionStoredValue(); row.Status != diagOK {
				t.Errorf("diagnostics row after explicit set = %+v; want ok", row)
			}
		})
	}
}

func TestAdminSettingsDefaultAction_CanonicalAndEmptyAreSilent(t *testing.T) {
	keepDefaultPolicyAction(t)
	setDefaultPolicyAction("deny")
	out := captureLogger(t, func() { applyAdminDefaultAction("allow") })
	if defaultPolicyAction() != "allow" || out != "" {
		t.Fatalf("canonical allow: enforced %q, log %q; want allow and no log", defaultPolicyAction(), out)
	}
	out = captureLogger(t, func() { applyAdminDefaultAction("") })
	if defaultPolicyAction() != "allow" || out != "" {
		t.Fatalf("empty: enforced %q, log %q; want the current action kept, no log", defaultPolicyAction(), out)
	}
	if row := checkDefaultActionStoredValue(); row.Status != diagOK {
		t.Fatalf("diagnostics row = %+v; want ok", row)
	}
}

// TestApplyAdminSecurity_RoutesDefaultActionThroughValidator: the load path
// (LoadAdminSettings → applyAdminSecurity) uses the validator.
func TestApplyAdminSecurity_RoutesDefaultActionThroughValidator(t *testing.T) {
	keepDefaultPolicyAction(t)
	origCommit, origLedger := requireCommitEnabled(), rewriteSeedLedgerAtLoad
	t.Cleanup(func() { setRequireCommit(origCommit); rewriteSeedLedgerAtLoad = origLedger })
	setDefaultPolicyAction("allow")
	out := captureLogger(t, func() {
		applyAdminSecurity(&AdminSettings{DefaultAction: "Allow", RequireCommit: origCommit})
	})
	if defaultPolicyAction() != "deny" || !strings.Contains(out, `default_action "Allow" is not`) {
		t.Fatalf("enforced %q, log %q; want deny with the warning", defaultPolicyAction(), out)
	}
}

// TestAdminSettingsDefaultAction_UnrelatedSaveKeepsRawValue: an unrelated
// settings save must not silently normalise the stored value; the first
// explicit set through the API writes the canonical value.
func TestAdminSettingsDefaultAction_UnrelatedSaveKeepsRawValue(t *testing.T) {
	keepDefaultPolicyAction(t)
	snapshotConfigVersionsDir(t)
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	if err := os.WriteFile(path, []byte(`{"default_action":"Allow"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	swapAdminSettingsPath(t, path)
	readStored := func() string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var s AdminSettings
		if err := json.Unmarshal(data, &s); err != nil {
			t.Fatal(err)
		}
		return s.DefaultAction
	}

	captureLogger(t, func() { applyAdminDefaultAction("Allow") }) // the boot apply
	if err := SaveAdminSettings(); err != nil {                   // any unrelated admin mutation
		t.Fatalf("save: %v", err)
	}
	if got := readStored(); got != "Allow" {
		t.Fatalf("after an unrelated save default_action = %q; want the raw \"Allow\" kept", got)
	}
	if defaultPolicyAction() != "deny" {
		t.Fatalf("enforced %q; want deny", defaultPolicyAction())
	}

	// Explicit set through the API: the canonical value is written.
	w := httptest.NewRecorder()
	apiDefaultAction(w, jsonReq(http.MethodPost, "/api/policy/default-action", map[string]string{"action": "deny"}))
	assertStatus(t, w, http.StatusOK)
	adminSettingsSaveWG.Wait()
	if got := readStored(); got != "deny" {
		t.Fatalf("after an explicit set default_action = %q; want \"deny\"", got)
	}
	if g := noncanonicalGauge(t, defaultActionSourceAdminSettings); g != "0" {
		t.Fatalf("gauge after explicit set = %s; want 0", g)
	}
}

// TestAPIDefaultAction_StillRejectsNoncanonical: the API door stays exact.
func TestAPIDefaultAction_StillRejectsNoncanonical(t *testing.T) {
	keepDefaultPolicyAction(t)
	setDefaultPolicyAction("deny")
	for _, a := range []string{"Allow", "block", " allow", ""} {
		w := httptest.NewRecorder()
		apiDefaultAction(w, jsonReq(http.MethodPost, "/api/policy/default-action", map[string]string{"action": a}))
		assertStatus(t, w, http.StatusBadRequest)
	}
	if defaultPolicyAction() != "deny" {
		t.Fatalf("a rejected request changed the action to %q", defaultPolicyAction())
	}
}

// seedDefaultActionVersion stores a config version identical to the live
// capture except for its default_action, under a unique actor.
func seedDefaultActionVersion(t *testing.T, actor, raw string) int {
	t.Helper()
	snap := captureConfigBackup()
	snap.DefaultAction = raw
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := configVersions.SaveWithNote(actor, "seed", time.Now().UTC().Format(time.RFC3339), "", data)
	if err != nil {
		t.Fatalf("seed version: %v", err)
	}
	return ver
}

// rollbackResponseHasWarning decodes a rollback response and reports its
// status and whether warnings carries note.
func rollbackResponseHasWarning(t *testing.T, body []byte, note string) (string, bool) {
	t.Helper()
	var resp struct {
		Status   string   `json:"status"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	for _, w := range resp.Warnings {
		if w == note {
			return resp.Status, true
		}
	}
	return resp.Status, false
}

// auditDetailHas reports whether an audit entry of action carries every part.
func auditDetailHas(action string, parts ...string) bool {
	entries := auditGet()
	for i := range entries {
		if entries[i].Action != action {
			continue
		}
		all := true
		for _, p := range parts {
			all = all && strings.Contains(entries[i].Detail, p)
		}
		if all {
			return true
		}
	}
	return false
}

func TestRollback_NoncanonicalDefaultActionWarnsInRealResponseAndAudit(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)
	keepDefaultPolicyAction(t)
	snapshotConfigVersionsDir(t)
	snapshotPolicyStoreForTest(t)
	policyStore.path = filepath.Join(t.TempDir(), "policy.json")
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))

	for i, raw := range []string{"Allow", "", "block"} {
		t.Run(fmt.Sprintf("%q", raw), func(t *testing.T) {
			actor := fmt.Sprintf("da-nc-rollback-%d-%d", i, time.Now().UnixNano())
			ver := seedDefaultActionVersion(t, actor, raw)
			setDefaultPolicyAction("allow")

			rec := postRollback(t, ver)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
			}
			if got := defaultPolicyAction(); got != "deny" {
				t.Fatalf("enforced %q after rollback; want deny", got)
			}
			note := fmt.Sprintf("default_action applied as deny (stored %q)", raw)
			if status, found := rollbackResponseHasWarning(t, rec.Body.Bytes(), note); status != "rolled_back" || !found {
				t.Fatalf("real response = %s; want status rolled_back with warning %q", rec.Body.String(), note)
			}
			if g := noncanonicalGauge(t, defaultActionSourceRollback); g != "1" {
				t.Errorf("gauge{config_rollback} = %s; want 1", g)
			}
			if !auditDetailHas("config.rollback", actor, note) {
				t.Errorf("no config.rollback audit entry for %s carrying %q", actor, note)
			}
		})
	}
}

func TestRollback_CanonicalDefaultActionHasNoNoteAndDryRunValidityUnchanged(t *testing.T) {
	keepDefaultPolicyAction(t)
	snapshotConfigVersionsDir(t)
	// Canonical: no note.
	if w, valid := rollbackWarnings(&configBackup{DefaultAction: "allow"}, false); len(w) != 0 || !valid {
		t.Fatalf("canonical allow: warnings=%v valid=%v; want none, valid", w, valid)
	}
	// "" (pre-field version) and "block" stay VALID for the pre-flight
	// verdict; the note is informational.
	for _, raw := range []string{"", "block"} {
		w, valid := rollbackWarnings(&configBackup{DefaultAction: raw}, true)
		want := fmt.Sprintf("default_action will be applied as deny (stored %q)", raw)
		if !valid || len(w) != 1 || w[0] != want {
			t.Errorf("%q dry-run: warnings=%v valid=%v; want [%q] valid", raw, w, valid, want)
		}
	}
	// Real dry-run response carries it.
	ver := seedDefaultActionVersion(t, "da-nc-dryrun", "block")
	body, _ := json.Marshal(map[string]any{"version": ver, "dry_run": true})
	req := adminCtx(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/config/versions", strings.NewReader(string(body))))
	rec := httptest.NewRecorder()
	rollbackConfigVersion(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `default_action will be applied as deny (stored \"block\")`) {
		t.Fatalf("dry-run = %d %s; want the note", rec.Code, rec.Body.String())
	}
}

func TestImport_NoncanonicalDefaultActionIgnoredWithWarning(t *testing.T) {
	keepDefaultPolicyAction(t)
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	const want = `defaultAction "Allow" ignored: must be "allow" or "deny"`
	backup := map[string]any{"version": 1, "exportedAt": "2026-03-03T00:00:00Z", "defaultAction": "Allow"}

	// Preview: the warning, and no "Default Policy Action" setting row.
	setDefaultPolicyAction("deny")
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?dryRun=true", backup))
	assertStatus(t, w, http.StatusOK)
	var prev struct {
		Settings []importPreviewSetting `json:"settings"`
		Warnings []string               `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &prev); err != nil {
		t.Fatal(err)
	}
	if len(prev.Warnings) != 1 || prev.Warnings[0] != want {
		t.Fatalf("preview warnings = %v; want [%q]", prev.Warnings, want)
	}
	for _, s := range prev.Settings {
		if s.Setting == "Default Policy Action" {
			t.Fatalf("preview claims the ignored value applies: %+v", s)
		}
	}

	// Commit: current action unchanged, warning returned.
	for _, current := range []string{"deny", "allow"} {
		setDefaultPolicyAction(current)
		w = httptest.NewRecorder()
		apiConfigImport(w, jsonReq("POST", "/api/config/import", backup))
		assertStatus(t, w, http.StatusOK)
		var resp struct {
			OK       bool     `json:"ok"`
			Warnings []string `json:"warnings"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, s := range resp.Warnings {
			found = found || s == want
		}
		if !resp.OK || !found {
			t.Fatalf("import response = %s; want ok with %q", w.Body.String(), want)
		}
		if got := defaultPolicyAction(); got != current {
			t.Fatalf("import changed the action %q → %q; an ignored value must keep the current one", current, got)
		}
	}

	// A section export without the field reports nothing.
	if got := importDefaultActionWarnings(""); got != nil {
		t.Fatalf("absent defaultAction warned: %v", got)
	}
}

func TestSnapshotApply_NoncanonicalDefaultActionDeniesWarnsAndCounts(t *testing.T) {
	keepDefaultPolicyAction(t)
	bindFreshAdmissionOwners(t)
	snap := func(action string) ConfigSnapshot {
		// Echo the live external-auth settings so this apply changes only
		// the default action.
		return ConfigSnapshot{DefaultAction: action, ProxyBaseURL: proxyExternalBaseURL, TrustForwardedHeaders: trustForwardedHeaders}
	}
	setDefaultPolicyAction("allow")
	before := noncanonicalApplied(defaultActionSourceSnapshot)

	out := captureLogger(t, func() {
		applySnapshotTrafficExceptBlocklist(snap("Allow"))
		applySnapshotTrafficExceptBlocklist(snap("Allow")) // re-push: counted, not re-logged
	})
	if got := defaultPolicyAction(); got != "deny" {
		t.Fatalf("enforced %q; want deny", got)
	}
	if got := noncanonicalApplied(defaultActionSourceSnapshot); got != before+2 {
		t.Fatalf("counter = %d; want %d", got, before+2)
	}
	if n := strings.Count(out, `DataPlane: config snapshot default_action "Allow" is not "allow" or "deny"; enforcing deny (fail-closed)`); n != 1 {
		t.Fatalf("warning logged %d time(s); want once per episode. log=%q", n, out)
	}
	if g := noncanonicalGauge(t, defaultActionSourceSnapshot); g != "1" {
		t.Fatalf("gauge{cluster_snapshot} = %s; want 1", g)
	}

	// A canonical push afterwards clears it; an empty one keeps the action.
	applySnapshotTrafficExceptBlocklist(snap("allow"))
	if defaultPolicyAction() != "allow" || noncanonicalGauge(t, defaultActionSourceSnapshot) != "0" {
		t.Fatalf("canonical push: enforced %q, gauge %s; want allow, 0", defaultPolicyAction(), noncanonicalGauge(t, defaultActionSourceSnapshot))
	}
	applySnapshotTrafficExceptBlocklist(snap(""))
	if defaultPolicyAction() != "allow" {
		t.Fatalf("empty push changed the action to %q", defaultPolicyAction())
	}
}

func TestMetrics_ExposesNoncanonicalDefaultActionSeries(t *testing.T) {
	w := httptest.NewRecorder()
	handleMetrics(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	if w.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_default_action_noncanonical gauge",
		`culvert_default_action_noncanonical{source="admin_settings"} `,
		`culvert_default_action_noncanonical{source="config_rollback"} `,
		`culvert_default_action_noncanonical{source="cluster_snapshot"} `,
		"# TYPE culvert_default_action_noncanonical_applied_total counter",
		`culvert_default_action_noncanonical_applied_total{source="cluster_snapshot"} `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func TestDiagnostics_IncludesDefaultActionStoredValueRow(t *testing.T) {
	c := buildOperatorContract()
	for _, row := range c.Checks {
		if row.Code == "default_action_stored_value" {
			return
		}
	}
	t.Fatal("operator contract has no default_action_stored_value row")
}
