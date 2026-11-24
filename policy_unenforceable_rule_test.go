package main

// A rule of a KNOWN type that this build cannot enforce as written (an access
// rule carrying a subjectMatch or an auth spec, an invalid auth rule, a null
// entry) used to be DROPPED by Load and ReplaceAll, with the rest of the ruleset
// installed. For a rule that restricts, dropping is the fail-open direction.
// Measured before this change, over a real socket, default allow:
//
//	ReplaceAll{Block backend, subjectMatch cidr 127.0.0.0/8}
//	  running rules = (none)   status=200   backend_hits=1
//
// The whole ruleset is refused instead, by the POL-005 gate and at its doors.
// Each real-socket test starts from a running Block rule under default allow,
// offers a replacement in which that restriction is unenforceable, and requires
// that the backend is still not reached.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scopedBlockRuleset is what a newer release might publish: the same block,
// narrowed by a subject scope this build does not evaluate, plus an ordinary
// Allow for the same destination behind it.
func scopedBlockRuleset(host string) []PolicyRule {
	return []PolicyRule{
		{Priority: 1, Name: "scoped-block", DestFQDN: host, Action: ActionBlockPage,
			SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"127.0.0.0/8"}}}}},
		{Priority: 2, Name: "allow-backend", DestFQDN: host, Action: ActionAllow},
	}
}

func assertUnenforceableRow(t *testing.T, wantDoor, wantRule string) {
	t.Helper()
	rows := checkPolicyRulesetRefused(policyStore)
	if len(rows) != 1 {
		t.Fatalf("Diagnostics: %d refusal row(s), want 1", len(rows))
	}
	r := rows[0]
	if r.Code != "policy_ruleset_refused_unenforceable_rule" || r.Status != diagWarn {
		t.Errorf("Diagnostics row = %s/%s, want policy_ruleset_refused_unenforceable_rule/warn", r.Code, r.Status)
	}
	for _, want := range []string{wantDoor, wantRule, "still enforcing"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("Diagnostics message lacks %q: %s", want, r.Message)
		}
	}
	if !strings.Contains(r.OperatorAction, "policy-check") {
		t.Errorf("operator action does not point at the preflight: %s", r.OperatorAction)
	}
}

func TestUnenforceableRule_E2E_BulkReplaceIsRefusedAndTheBlockStillHolds(t *testing.T) {
	client, cb, target, host := pol004Setup(t)
	t.Cleanup(func() { policyStore.rulesetRefused.Store(nil) })
	version := lastKnownGood(t, host)

	policyStore.ReplaceAll(scopedBlockRuleset(host))
	assertStillLastKnownGood(t, client, cb, target, version, "bulk replace")
	assertUnenforceableRow(t, "bulk replace", "scoped-block")

	// Control: the same ruleset without the scoped rule is accepted and its
	// Allow forwards. Default-allow semantics for a valid policy are unchanged.
	policyStore.ReplaceAll(scopedBlockRuleset(host)[1:])
	if got := pol004GetNames(); got != "allow-backend" {
		t.Fatalf("control: clean ruleset not installed, running policy is %q", got)
	}
	if status, hits := pol004Get(t, client, cb, target); status != http.StatusOK || hits != 1 {
		t.Errorf("control: clean Allow gave status %d with %d backend hit(s), want 200 and 1", status, hits)
	}
	if rows := checkPolicyRulesetRefused(policyStore); rows != nil {
		t.Errorf("Diagnostics row still present after an accepted ruleset: %+v", rows)
	}
	// Control: an EMPTY ruleset is a valid policy and is accepted (default allow forwards).
	policyStore.ReplaceAll(nil)
	if status, hits := pol004Get(t, client, cb, target); status != http.StatusOK || hits != 1 {
		t.Errorf("control: empty rulebase under default allow gave status %d with %d hit(s), want 200 and 1", status, hits)
	}
}

func TestUnenforceableRule_E2E_PolicyFileIsRefusedAndTheBlockStillHolds(t *testing.T) {
	client, cb, target, host := pol004Setup(t)
	t.Cleanup(func() { policyStore.rulesetRefused.Store(nil) })
	version := lastKnownGood(t, host)
	pathBefore := policyStore.path

	raw, err := json.Marshal(scopedBlockRuleset(host))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = policyStore.Load(file)
	var ue *unenforceableRuleError
	if !errors.As(err, &ue) {
		t.Fatalf("Load returned %v, want an unenforceableRuleError", err)
	}
	if ue.Name != "scoped-block" || ue.Count != 1 || !strings.Contains(ue.Reason, "subjectMatch") {
		t.Errorf("error = %q/%q x%d, want scoped-block / a subjectMatch reason / 1", ue.Name, ue.Reason, ue.Count)
	}
	if policyStore.path != pathBefore {
		t.Errorf("Load adopted the refused file's path (%q)", policyStore.path)
	}
	assertStillLastKnownGood(t, client, cb, target, version, "policy file")
	assertUnenforceableRow(t, "policy file", "scoped-block")

	// Startup: nothing to fall back on means an error and NO rules, which
	// initPolicy turns into a fatal exit.
	fresh := &PolicyStore{}
	if err := fresh.Load(file); err == nil || len(fresh.List()) != 0 {
		t.Fatalf("a fresh store loaded a refused file: err=%v rules=%d", err, len(fresh.List()))
	}
	if hotReloadPolicyFile(file) {
		t.Error("reload reports the new default action may be applied after refusing the policy file")
	}
}

func TestUnenforceableRule_E2E_SnapshotIsRefusedBeforeAnyMutation(t *testing.T) {
	bindFreshAdmissionOwners(t) // the apply path mutates ipf and rl in place
	client, cb, target, host := pol004Setup(t)
	t.Cleanup(func() { policyStore.rulesetRefused.Store(nil) })
	version := lastKnownGood(t, host)

	setDefaultPolicyAction("deny")
	snap := ConfigSnapshot{Version: 1 << 40, DefaultAction: "allow", PolicyRules: scopedBlockRuleset(host)}
	err := applyConfigSnapshot(snap)
	var ue *unenforceableRuleError
	if !errors.As(err, &ue) {
		t.Fatalf("applyConfigSnapshot returned %v, want an unenforceableRuleError", err)
	}
	if got := defaultPolicyAction(); got != "deny" {
		t.Errorf("default action is %q after a refused snapshot, want deny (partial apply)", got)
	}
	setDefaultPolicyAction("allow")
	assertStillLastKnownGood(t, client, cb, target, version, "control-plane snapshot")
	assertUnenforceableRow(t, "control-plane snapshot", "scoped-block")
}

// Every reason the gate has, alone and beside valid rules, through both store
// doors: nothing is installed and nothing that was installed is lost.
func TestUnenforceableRule_EveryReasonRefusesTheWholeRulesetAtBothStoreDoors(t *testing.T) {
	valid := PolicyRule{Priority: 9, Name: "valid-block", DestFQDN: "blocked.example.com", Action: ActionBlockPage}
	cases := map[string]string{
		"subjectMatch on an access rule": `{"priority":1,"name":"bad","destFqdn":"x.example.com","action":"Drop","subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.0.0.0/8"]}]}}`,
		"auth spec on an access rule":    `{"priority":1,"name":"bad","destFqdn":"x.example.com","action":"Block_Page","auth":{"outcome":"exempt"}}`,
		"invalid auth rule":              `{"priority":1,"name":"bad","ruleType":"auth","destFqdn":"x.example.com"}`,
		"null entry":                     `null`,
		"empty object":                   `{}`,
	}
	validJSON, _ := json.Marshal(valid)
	for label, bad := range cases {
		for _, mixed := range []bool{false, true} {
			body := "[" + bad + "]"
			if mixed {
				body = "[" + string(validJSON) + "," + bad + "]"
			}
			assertRefusedAtBothStoreDoors(t, label, mixed, bad, body)
		}
	}
	// Controls: valid rulesets of every kind are accepted exactly as before.
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{valid, {Priority: 2, Name: "future-action", DestFQDN: "y.example.com", Action: "Quarantine"}})
	if got := ruleNames(ps.List()); len(got) != 2 {
		t.Errorf("a valid ruleset with a retained unknown ACTION was not installed whole: %v (POL-004 must be unchanged)", got)
	}
	if rows := checkPolicyRulesetRefused(ps); rows != nil {
		t.Errorf("a valid ruleset produced a refusal row: %+v", rows)
	}
}

// assertRefusedAtBothStoreDoors offers one refused ruleset to Load and to
// ReplaceAll on a store that already enforces a Block, and requires that the
// store ends exactly as it began.
func assertRefusedAtBothStoreDoors(t *testing.T, label string, mixed bool, bad, body string) {
	t.Helper()
	// Load, onto a store that already enforces something.
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "prior-block", DestFQDN: "prior.example.com", Action: ActionBlockPage}})
	file := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ps.Load(file)
	var ue *unenforceableRuleError
	if !errors.As(err, &ue) {
		t.Errorf("%s (mixed=%v): Load returned %v, want an unenforceableRuleError", label, mixed, err)
		return
	}
	if got := ps.List(); len(got) != 1 || got[0].Name != "prior-block" {
		t.Errorf("%s (mixed=%v): after a refused Load the store holds %d rule(s) %v, want only prior-block", label, mixed, len(got), ruleNames(got))
	}
	if m := ps.Evaluate("203.0.113.9", "", "", "prior.example.com", nil); m == nil || m.Rule == nil || m.Rule.Name != "prior-block" {
		t.Errorf("%s (mixed=%v): the prior Block no longer matches after a refused Load", label, mixed)
	}
	// ReplaceAll with the same content. Decoded into a VALUE slice, as import,
	// snapshot and rollback decode it, a null becomes an empty rule: the gate
	// must refuse that too, or one null is an allow-everything rule.
	var rules []PolicyRule
	if err := json.Unmarshal([]byte(body), &rules); err != nil {
		t.Fatalf("%s: decode: %v", label, err)
	}
	ps.ReplaceAll(rules)
	if got := ps.List(); len(got) != 1 || got[0].Name != "prior-block" {
		t.Errorf("%s (mixed=%v): after a refused ReplaceAll the store holds %v, want only prior-block", label, mixed, ruleNames(got))
	}
	if rows := checkPolicyRulesetRefused(ps); len(rows) != 1 || rows[0].Code != "policy_ruleset_refused_unenforceable_rule" {
		t.Errorf("%s (mixed=%v): refusal row = %+v", label, mixed, rows)
	}
}

// Rollback. A stored version holding a rule the gate refuses is refused whole,
// in the handler, as a truthful 400. A version the gate accepts is restored
// with EVERY rule it holds, as stored: the restore used to skip any rule the
// write-time validator disliked, which removed live rules by restoring.
func TestUnenforceableRule_RollbackRefusesWholeOrRestoresEveryStoredRule(t *testing.T) {
	_, _, _, host := pol004Setup(t)
	origDir := configVersions.Dir()
	configVersions.SetDirForTest(t.TempDir())
	t.Cleanup(func() { configVersions.SetDirForTest(origDir) })
	version := lastKnownGood(t, host)
	seed := func(rules string) int {
		t.Helper()
		target, err := configVersions.Save("test", "test.version", "2026-01-01T00:00:00Z",
			json.RawMessage(`{"version":1,"defaultAction":"deny","policyRules":`+rules+`}`))
		if err != nil {
			t.Fatalf("seed stored version: %v", err)
		}
		return target
	}
	scoped, _ := json.Marshal(scopedBlockRuleset(host))

	for label, rules := range map[string]string{
		"subject-scoped block": string(scoped),
		"null entry":           `[{"priority":1,"name":"blk","destFqdn":"` + host + `","action":"Drop"},null]`,
	} {
		assertRollbackRefusedWhole(t, label, seed(rules))
	}
	if v := storeVersion(policyStore); v != version {
		t.Errorf("policy version moved %d -> %d across refused rollbacks", version, v)
	}
	joined := strings.Join(validateConfigBackup(&configBackup{Version: 1, PolicyRules: scopedBlockRuleset(host)}), "\n")
	if !strings.Contains(joined, "cannot be restored") || strings.Contains(joined, "will be skipped") {
		t.Errorf("preview = %q, want only a cannot-be-restored statement", joined)
	}

	// Shapes the store legitimately holds and enforces, which the write-time
	// validator refuses (two of them only after a DNS lookup). A version
	// captured from a running system that holds them must restore, whole.
	live := `[
{"priority":1,"name":"lower-drop","destFqdn":"` + host + `","action":"drop"},
{"priority":2,"destFqdn":"nameless.example.com","action":"Drop"},
{"priority":3,"name":"no-action","destFqdn":"legacy.example.com"},
{"priority":4,"name":"redirect-no-url","destFqdn":"r1.example.com","action":"Redirect"},
{"priority":5,"name":"redirect-unresolvable","destFqdn":"r2.example.com","action":"Redirect","redirectUrl":"https://blockpage.corp.invalid/"},
{"priority":6,"name":"odd-zone","destFqdn":"tz.example.com","action":"Drop","schedule":{"timezone":"Mars/Olympus"}},
{"priority":7,"name":"future-action","destFqdn":"q.example.com","action":"Quarantine"}]`
	var liveRules []PolicyRule
	if err := json.Unmarshal([]byte(live), &liveRules); err != nil {
		t.Fatal(err)
	}
	if warnings := validateConfigBackup(&configBackup{Version: 1, PolicyRules: liveRules}); strings.Contains(strings.Join(warnings, "\n"), "policy rule") || strings.Contains(strings.Join(warnings, "\n"), "cannot be restored") {
		t.Errorf("preview objects to a restorable version: %v", warnings)
	}
	rec := postRollback(t, seed(live))
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback of a version of live shapes: status %d body %s", rec.Code, rec.Body.String())
	}
	got := policyStore.List()
	if len(got) != len(liveRules) {
		t.Fatalf("restore brought back %d of %d rules (%s): a stored rule was skipped", len(got), len(liveRules), pol004GetNames())
	}
	if got[0].Name != "lower-drop" || got[0].Action != "drop" {
		t.Errorf("first restored rule = %q action %q, want lower-drop with its action as stored", got[0].Name, got[0].Action)
	}
	if m := policyStore.Evaluate("203.0.113.9", "", "", host, nil); m == nil || m.Rule == nil || m.Rule.Name != "lower-drop" {
		t.Errorf("after the restore %s matches %+v, want the Drop rule", host, m)
	}
	if m := policyStore.Evaluate("203.0.113.9", "", "", "nameless.example.com", nil); m == nil || m.Rule == nil || m.Rule.Action != ActionDrop {
		t.Errorf("after the restore the nameless Drop no longer matches: %+v", m)
	}

	lastKnownGood(t, host)
	assertImportRefusedWhole(t, host)
}

// assertRollbackRefusedWhole rolls back to a stored version the gate refuses and
// requires a truthful 400 with nothing applied, versioned or changed.
func assertRollbackRefusedWhole(t *testing.T, label string, target int) {
	t.Helper()
	seq := configVersions.Seq()
	rec := postRollback(t, target)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "rollback refused") {
		t.Errorf("%s: rollback status %d body %q, want 400 rollback refused", label, rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"applied"`) {
		t.Errorf("%s: a refused rollback is reported as applied: %s", label, rec.Body.String())
	}
	if configVersions.Seq() != seq {
		t.Errorf("%s: a refused rollback created a config version", label)
	}
	if got := pol004GetNames(); got != "lkg-block" {
		t.Errorf("%s: running policy is %q after a refused rollback, want lkg-block", label, got)
	}
	if got := defaultPolicyAction(); got != "allow" {
		t.Errorf("%s: default action is %q after a refused rollback, want allow", label, got)
	}
}

// assertImportRefusedWhole offers gate-refused rulesets to config import in both
// modes and as a dry run, and requires a 400 with the running policy untouched.
func assertImportRefusedWhole(t *testing.T, host string) {
	t.Helper()
	for _, q := range []string{"mode=merge", "mode=replace", "mode=replace&dryRun=true"} {
		for label, rules := range map[string]any{"subject-scoped block": scopedBlockRuleset(host), "null entry": []any{nil}} {
			w := httptest.NewRecorder()
			apiConfigImport(w, jsonReq("POST", "/api/config/import?"+q, map[string]any{
				"version": 1, "defaultAction": "deny", "policyRules": rules}))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "import refused") {
				t.Errorf("import %s (%s): status %d body %q, want 400 import refused", q, label, w.Code, w.Body.String())
			}
		}
	}
	if got := pol004GetNames(); got != "lkg-block" {
		t.Errorf("running policy is %q after refused imports, want lkg-block", got)
	}
}

// The same refusal repeated (a data plane polling a control plane it cannot
// follow) is logged once, not once per poll; a different refusal is logged at
// once; Diagnostics counts every one.
func TestUnenforceableRule_RepeatedRefusalIsLoggedOnceAndCountedEveryTime(t *testing.T) {
	sink := captureLoggerForTest(t)
	// logSnapshotRejection records on the GLOBAL store; put its record back.
	prevGlobal := policyStore.rulesetRefused.Load()
	t.Cleanup(func() { policyStore.rulesetRefused.Store(prevGlobal) })
	ps := &PolicyStore{}
	bad := scopedBlockRuleset("a.example.com")
	for i := 0; i < 5; i++ {
		ps.ReplaceAll(bad)
	}
	if n := strings.Count(sink.String(), "REFUSED"); n != 1 {
		t.Errorf("five identical refusals wrote %d log line(s), want 1:\n%s", n, sink.String())
	}
	rows := checkPolicyRulesetRefused(ps)
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "refused 5 times") {
		t.Errorf("Diagnostics does not count the repeats: %+v", rows)
	}
	// A different offending ruleset is news and is logged immediately.
	other := []PolicyRule{{Priority: 1, Name: "other", RuleType: "posture", DestFQDN: "a.example.com", Action: ActionBlockPage}}
	ps.ReplaceAll(other)
	if n := strings.Count(sink.String(), "REFUSED"); n != 2 {
		t.Errorf("a different refusal was not logged at once (%d line(s))", n)
	}
	// After the quiet period the unchanged refusal is logged again.
	ref := *ps.rulesetRefused.Load()
	ref.Logged = ref.Logged.Add(-2 * rulesetRefusalRelogEvery)
	ps.rulesetRefused.Store(&ref)
	ps.ReplaceAll(other)
	if n := strings.Count(sink.String(), "REFUSED"); n != 3 {
		t.Errorf("an unchanged refusal was not re-logged after the quiet period (%d line(s))", n)
	}
	// The data-plane rejection path logs through the same deduplicated record
	// and writes no line of its own for a gate refusal.
	before := strings.Count(sink.String(), "rejecting")
	gateErr := policyRulesetError(other)
	for i := 0; i < 3; i++ {
		logSnapshotRejection("config snapshot", 7, gateErr)
	}
	if n := strings.Count(sink.String(), "rejecting") - before; n != 0 {
		t.Errorf("a gate refusal wrote %d undeduplicated \"rejecting\" line(s) on the data-plane path", n)
	}
	logSnapshotRejection("config snapshot", 7, errors.New("some other reason"))
	if n := strings.Count(sink.String(), "rejecting config snapshot v7: some other reason"); n != 1 {
		t.Errorf("a non-gate rejection must still be logged every time (%d line(s))", n)
	}
	// A hostile name cannot bloat the row or forge a line.
	long := (&unenforceableRuleError{Name: strings.Repeat("A", 5000) + "\nforged", Reason: "r", Count: 1}).Error()
	if len(long) > 600 || strings.ContainsAny(long, "\r\n") {
		t.Errorf("error text is unbounded or carries a line break (%d bytes)", len(long))
	}
	// An accepted ruleset clears the record; the next refusal starts a new count.
	ps.ReplaceAll(nil)
	ps.ReplaceAll(bad)
	if rows := checkPolicyRulesetRefused(ps); len(rows) != 1 || strings.Contains(rows[0].Message, "times") {
		t.Errorf("the count did not restart after an accepted ruleset: %+v", rows)
	}
}

func TestPolicyPreflight_ListsEveryRefusedRuleAndChangesNothing(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.json", `[{"priority":1,"name":"ok","destFqdn":"a.example.com","action":"Block_Page"},
{"priority":2,"name":"future-action","destFqdn":"b.example.com","action":"Quarantine"}]`)
	bad := write("bad.json", `[{"priority":1,"name":"typo","ruleType":"Access","destFqdn":"a.example.com","action":"Block_Page"},
{"priority":2,"name":"ok","destFqdn":"b.example.com","action":"Allow"},
{"priority":3,"name":"scoped","destFqdn":"c.example.com","action":"Drop","subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.0.0.0/8"]}]}},
null]`)
	backup := write("backup.json", `{"version":1,"policyRules":[{"priority":1,"name":"future","ruleType":"posture","action":"Allow"}]}`)
	draft := write("draft.json", `{"state":{"active":true},"rules":[{"priority":1,"name":"ok","destFqdn":"a.example.com","action":"Allow"}]}`)
	other := write("other.json", `{"hello":"world"}`)
	stored := write("stored-version.json", `{"meta":{"version":7},"config":{"version":1,"policyRules":[{"priority":1,"name":"scoped","action":"Drop","subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.0.0.0/8"]}]}}]}}`)
	noPolicy := write("no-policy.json", `{"version":1}`)
	nullPolicy := write("null-policy.json", `{"version":1,"policyRules":null}`)
	emptyObj := write("empty-entry.json", `{"version":1,"policyRules":[{}]}`)
	before, _ := os.ReadFile(bad)

	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		return runPolicyPreflight(args, &out, &errb), out.String(), errb.String()
	}
	if code, out, _ := run(good, draft); code != 0 || strings.Count(out, ": OK") != 2 {
		t.Errorf("enforceable files: exit %d, output %q; want 0 and two OK lines (an unknown ACTION is not a refusal)", code, out)
	}
	code, out, _ := run(bad)
	if code != 1 {
		t.Errorf("refused file: exit %d, want 1", code)
	}
	for _, want := range []string{"REFUSED — 3 of 4", `rule #1 "typo"`, `ruleType "Access"`, `rule #3 "scoped"`, "subjectMatch", "rule #4", "null entry"} {
		if !strings.Contains(out, want) {
			t.Errorf("refused file: output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `rule #2`) {
		t.Errorf("an enforceable rule was reported:\n%s", out)
	}
	if code, out, _ := run(backup); code != 1 || !strings.Contains(out, "config backup") || !strings.Contains(out, `"future"`) {
		t.Errorf("config backup: exit %d, output %q", code, out)
	}
	if code, out, _ := run(stored); code != 1 || !strings.Contains(out, "stored config version") || !strings.Contains(out, `"scoped"`) {
		t.Errorf("stored config version: exit %d, output %q; want 1 naming the rule", code, out)
	}
	if code, out, _ := run(noPolicy, nullPolicy); code != 0 || strings.Count(out, "0 rule(s)") != 2 {
		t.Errorf("backups with no policy section: exit %d, output %q; want 0 (they hold no rules)", code, out)
	}
	if code, out, _ := run(emptyObj); code != 1 || !strings.Contains(out, "empty entry") {
		t.Errorf("backup with an empty rule entry: exit %d, output %q; want 1", code, out)
	}
	if code, _, _ := run("-h"); code != 0 {
		t.Errorf("-h: exit %d, want 0", code)
	}
	if code, _, errOut := run(other); code != 2 || !strings.Contains(errOut, "no policy rules found") {
		t.Errorf("unrecognised file: exit %d, stderr %q; want 2", code, errOut)
	}
	if code, _, _ := run(filepath.Join(dir, "missing.json")); code != 2 {
		t.Errorf("missing file: exit %d, want 2", code)
	}
	if code, _, _ := run(); code != 2 {
		t.Errorf("no arguments: exit %d, want 2", code)
	}
	// A refused file among good ones decides the status; an unrecognised one outranks it.
	if code, _, _ := run(good, bad); code != 1 {
		t.Errorf("good+bad: exit %d, want 1", code)
	}
	if code, _, _ := run(bad, other); code != 2 {
		t.Errorf("bad+unreadable: exit %d, want 2", code)
	}
	if after, _ := os.ReadFile(bad); !bytes.Equal(before, after) {
		t.Error("the preflight modified the file it checked")
	}
	assertPreflightAgreesWithTheGate(t, map[string]bool{backup: true, emptyObj: true, noPolicy: false}, map[string]bool{good: false, bad: true})
}

// assertPreflightAgreesWithTheGate holds the preflight's verdicts (file → refused)
// against the real doors: the import gate for backups, Load for policy files.
func assertPreflightAgreesWithTheGate(t *testing.T, backups, policyFiles map[string]bool) {
	t.Helper()
	// The import door must agree with the preflight on a backup.
	for path, wantRefused := range backups {
		raw, _ := os.ReadFile(path)
		var b configBackup
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		if got := policyRulesetError(b.PolicyRules) != nil; got != wantRefused {
			t.Errorf("%s: the import gate refuses=%v, preflight says refused=%v; they must agree", filepath.Base(path), got, wantRefused)
		}
	}
	// The preflight and the gate must agree on which files are refused.
	for path, wantRefused := range policyFiles {
		err := (&PolicyStore{}).Load(path)
		if (err != nil) != wantRefused {
			t.Errorf("%s: Load error = %v, preflight says refused=%v; they must agree", filepath.Base(path), err, wantRefused)
		}
	}
}
