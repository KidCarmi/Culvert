package main

// Every door through which an OPERATOR SUBMITS policy rules runs the same
// per-rule validation (validateRuleIngress) through one ruleset-level function
// (validateIngressRuleset / validateIngressRule). Before this, replace-mode
// config import ran only the POL-005 gate, so it installed rules the policy API
// refuses. Measured before the change, default allow:
//
//	running: quarantine Drop sourceIP=10.0.0.5        verdict(10.0.0.5) = quarantine:Drop
//	POST /api/config/import?mode=replace  quarantine Drop sourceIP="10.0.0.5-10.0.0.9"
//	  200 {"ok":true}, no warning                     verdict(10.0.0.5) = no match (default allow)
//
// The stored and wire doors (policy file, rollback, control-plane snapshot,
// pending draft) are deliberately NOT part of this: they stay on the pure
// POL-005 gate, and the last test pins that.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const ingressCanaryHost = "ingress-canary.example"

// ingressFixture seeds one persisted Drop rule for 10.0.0.5 under default
// allow and returns the policy file path.
func ingressFixture(t *testing.T) (path string) {
	t.Helper()
	_, path = importDurabilityFixture(t)
	policyStore.ReplaceAll([]PolicyRule{{Name: "quarantine", Priority: 1, Action: ActionDrop, SourceIP: "10.0.0.5"}})
	if err := policyStore.SaveErr(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	t.Cleanup(func() { bl.Remove(ingressCanaryHost) })
	return path
}

func ingressVerdict(clientIP, host string) string {
	m := policyStore.Evaluate(clientIP, "", "", host, nil)
	if m == nil {
		return "no-match"
	}
	act, _ := canonicalPolicyAction(m.Action)
	return m.Rule.Name + ":" + string(act)
}

// ingressImport posts a backup that carries the rules plus two canaries from
// OTHER sections (a blocklist host, which the handler applies before the policy
// rules, and a default action), so a partial apply is visible.
func ingressImport(t *testing.T, query, exportedAt string, rules []PolicyRule) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?"+query, &configBackup{
		Version: 1, ExportedAt: exportedAt, PolicyRules: rules,
		Blocklist: []string{ingressCanaryHost}, DefaultAction: "deny",
	}))
	return w
}

// assertIngressUntouched is the acceptance check for a refused import: no
// section applied, the running and persisted policy are byte-for-byte what they
// were, the request is neither audited nor versioned, and 10.0.0.5 is still
// dropped.
func assertIngressUntouched(t *testing.T, label, path string, wantFile []byte, wantVersion int64, exportedAt string) {
	t.Helper()
	if got := ruleNamesOf(policyStore.List()); got != "quarantine" {
		t.Errorf("%s: running rules = [%s], want [quarantine]", label, got)
	}
	if v := storeVersion(policyStore); v != wantVersion {
		t.Errorf("%s: policy version moved %d -> %d on a refused import", label, wantVersion, v)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, wantFile) {
		t.Errorf("%s: policy file changed on a refused import (read err %v)", label, err)
	}
	if bl.IsBlocked(ingressCanaryHost) {
		t.Errorf("%s: the blocklist section was applied before the import was refused", label)
	}
	if got := defaultPolicyAction(); got != "allow" {
		t.Errorf("%s: default action is %q, want allow (unchanged)", label, got)
	}
	if auditHas("config.import", "from config exported "+exportedAt) {
		t.Errorf("%s: a refused import was audited", label)
	}
	if configVersionSaved("config.import") {
		t.Errorf("%s: a refused import saved a config version", label)
	}
	if got := ingressVerdict("10.0.0.5", "anything.example"); got != "quarantine:Drop" {
		t.Errorf("%s: 10.0.0.5 verdict is %q after the refused import, want quarantine:Drop", label, got)
	}
}

// Replace-mode import refuses, whole and before any section applies, every
// rule shape the policy API refuses.
func TestRulesetIngress_ReplaceImportRefusesWhatThePolicyAPIRefuses(t *testing.T) {
	good := PolicyRule{Name: "keep", Priority: 9, Action: ActionAllow, DestFQDN: "ok.example"}
	cases := []struct {
		label      string
		rules      []PolicyRule
		wantInBody []string
		apiRefuses *PolicyRule // the rule POST /api/policy must also refuse on its own
	}{
		{"inert sourceIP range",
			[]PolicyRule{{Name: "quarantine", Priority: 1, Action: ActionDrop, SourceIP: "10.0.0.5-10.0.0.9"}, good},
			[]string{`"quarantine"`, "rule 1 of 2", "sourceIP", "10.0.0.5-10.0.0.9"},
			&PolicyRule{Name: "quarantine2", Action: ActionDrop, SourceIP: "10.0.0.5-10.0.0.9"}},
		{"sourceIP with a leading space",
			[]PolicyRule{good, {Name: "spacey", Priority: 1, Action: ActionDrop, SourceIP: " 10.0.0.5"}},
			[]string{`"spacey"`, "rule 2 of 2", "sourceIP"},
			&PolicyRule{Name: "spacey", Action: ActionDrop, SourceIP: " 10.0.0.5"}},
		{"duplicate name",
			[]PolicyRule{{Name: "dup", Priority: 1, Action: ActionAllow, DestFQDN: "a.example"}, {Name: "DUP", Priority: 2, Action: ActionDrop, DestFQDN: "a.example"}},
			[]string{`"DUP"`, "rule 2 of 2", "rule name already exists"}, nil},
		{"duplicate priority",
			[]PolicyRule{{Name: "one", Priority: 1, Action: ActionAllow, DestFQDN: "a.example"}, {Name: "two", Priority: 1, Action: ActionDrop, DestFQDN: "a.example"}},
			[]string{`"two"`, "priority 1 is already in use"}, nil},
		{"redirect without a URL",
			[]PolicyRule{{Name: "redir", Priority: 1, Action: ActionRedirect, DestFQDN: "r.example"}},
			[]string{`"redir"`, "redirectURL is required"},
			&PolicyRule{Name: "redir", Action: ActionRedirect, DestFQDN: "r.example"}},
		{"impossible schedule timezone",
			[]PolicyRule{{Name: "tz", Priority: 1, Action: ActionDrop, DestFQDN: "tz.example", Schedule: &PolicySchedule{Timezone: "../etc/passwd"}}},
			[]string{`"tz"`, "invalid schedule timezone"},
			&PolicyRule{Name: "tz", Action: ActionDrop, DestFQDN: "tz.example", Schedule: &PolicySchedule{Timezone: "../etc/passwd"}}},
		{"redirect that is not an absolute http URL",
			[]PolicyRule{{Name: "redir", Priority: 1, Action: ActionRedirect, DestFQDN: "r.example", RedirectURL: "javascript:alert(1)"}},
			[]string{`"redir"`, "redirectURL must be an absolute http/https URL"},
			&PolicyRule{Name: "redir", Action: ActionRedirect, DestFQDN: "r.example", RedirectURL: "javascript:alert(1)"}},
		{"named rule with no action",
			[]PolicyRule{{Name: "placeholder", Priority: 1}, {Name: "quarantine", Priority: 2, Action: ActionDrop, SourceIP: "10.0.0.5"}},
			[]string{`"placeholder"`, "action must be Allow, Drop, Block_Page, or Redirect"},
			&PolicyRule{Name: "placeholder"}},
		{"action in a spelling the API does not accept",
			[]PolicyRule{{Name: "lower", Priority: 1, Action: "drop", DestFQDN: "l.example"}},
			[]string{`"lower"`, "action must be Allow, Drop, Block_Page, or Redirect"},
			&PolicyRule{Name: "lower", Action: "drop", DestFQDN: "l.example"}},
		{"action this version does not know",
			[]PolicyRule{{Name: "future", Priority: 1, Action: "Quarantine", DestFQDN: "q.example"}},
			[]string{`"future"`, "action must be Allow, Drop, Block_Page, or Redirect"},
			&PolicyRule{Name: "future", Action: "Quarantine", DestFQDN: "q.example"}},
		{"rule with no name",
			[]PolicyRule{{Priority: 1, Action: ActionDrop, DestFQDN: "n.example"}},
			[]string{"rule 1 of 1", "name is required"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			path := ingressFixture(t)
			wantFile, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			version := storeVersion(policyStore)

			if tc.apiRefuses != nil {
				cw := httptest.NewRecorder()
				apiPolicyCreate(cw, jsonReq("POST", "/api/policy", tc.apiRefuses))
				if cw.Code != http.StatusBadRequest {
					t.Fatalf("premise: POST /api/policy = %d for this rule, want 400: %s", cw.Code, cw.Body.String())
				}
			}
			for _, q := range []string{"mode=replace", "mode=replace&dryRun=true"} {
				exportedAt := "ingress/" + t.Name() + "/" + q
				w := ingressImport(t, q, exportedAt, tc.rules)
				body := w.Body.String()
				if w.Code != http.StatusBadRequest {
					t.Fatalf("import %s = %d, want 400: %s", q, w.Code, body)
				}
				for _, want := range append([]string{"import refused", "nothing was changed"}, tc.wantInBody...) {
					if !strings.Contains(body, want) {
						t.Errorf("import %s: refusal lacks %q: %s", q, want, strings.TrimSpace(body))
					}
				}
				assertIngressUntouched(t, q, path, wantFile, version, exportedAt)
			}
		})
	}
}

// Control for the test above: a ruleset the policy API accepts imports in
// replace mode, is audited and versioned, and what the store exports imports
// back unchanged.
func TestRulesetIngress_ReplaceImportStillAcceptsAValidRuleset(t *testing.T) {
	ingressFixture(t)
	exportedAt := "ingress/" + t.Name()
	rules := []PolicyRule{
		{Name: "quarantine", Priority: 1, Action: ActionDrop, SourceIP: "10.0.0.0/24"},
		{Name: "single", Priority: 2, Action: ActionBlockPage, SourceIP: "2001:db8::1", DestFQDN: "b.example"},
		{Name: "unnumbered-a", Action: ActionAllow, DestFQDN: "c.example"},
		{Name: "unnumbered-b", Action: ActionAllow, DestFQDN: "d.example", Schedule: &PolicySchedule{Timezone: "UTC"}},
	}
	w := ingressImport(t, "mode=replace", exportedAt, rules)
	if w.Code != http.StatusOK {
		t.Fatalf("valid replace import = %d, want 200: %s", w.Code, w.Body.String())
	}
	if n := len(policyStore.List()); n != len(rules) {
		t.Fatalf("installed %d rule(s), want %d", n, len(rules))
	}
	if got := ingressVerdict("10.0.0.77", "anything.example"); got != "quarantine:Drop" {
		t.Errorf("10.0.0.77 verdict = %q, want quarantine:Drop", got)
	}
	if !auditHas("config.import", "from config exported "+exportedAt) || !configVersionSaved("config.import") {
		t.Error("an accepted import must be audited and versioned (the refusal-side controls would be vacuous)")
	}
}

// The consequence over a real socket: a Block rule scoped to the client's
// address stays in force when a replace import offers the same rule with a
// source form the matcher cannot match.
func TestRulesetIngress_E2E_RefusedReplaceImportKeepsTheBlockInForce(t *testing.T) {
	client, cb, target, host := pol004Setup(t)
	refGateSetup(t)
	t.Cleanup(func() { bl.Remove(ingressCanaryHost) })
	setDefaultPolicyAction("allow") // refGateSetup leaves the default action alone; pol004Setup restores it

	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "lkg-block", SourceIP: "127.0.0.1", DestFQDN: host, Action: ActionBlockPage}})
	version := storeVersion(policyStore)
	if status, hits := pol004Get(t, client, cb, target); status != http.StatusForbidden || hits != 0 {
		t.Fatalf("premise: the scoped Block gives status %d with %d backend hit(s), want 403 and 0", status, hits)
	}

	w := ingressImport(t, "mode=replace", "ingress/"+t.Name(), []PolicyRule{
		{Priority: 1, Name: "lkg-block", SourceIP: "127.0.0.1-127.0.0.9", DestFQDN: host, Action: ActionBlockPage},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replace import of an inert source form = %d, want 400: %s", w.Code, w.Body.String())
	}
	assertStillLastKnownGood(t, client, cb, target, version, "replace import")

	// Control: the same request with a form the matcher understands is applied
	// (and, with no rule matching any more, default allow forwards), so the 403
	// above is the refusal and not something else in the path.
	setDefaultPolicyAction("allow")
	cw := httptest.NewRecorder()
	apiConfigImport(cw, jsonReq("POST", "/api/config/import?mode=replace", &configBackup{Version: 1, PolicyRules: []PolicyRule{
		{Priority: 1, Name: "elsewhere", SourceIP: "192.0.2.0/24", DestFQDN: host, Action: ActionBlockPage},
	}}))
	if cw.Code != http.StatusOK {
		t.Fatalf("control: valid replace import = %d: %s", cw.Code, cw.Body.String())
	}
	if status, hits := pol004Get(t, client, cb, target); status != http.StatusOK || hits != 1 {
		t.Errorf("control: status %d with %d backend hit(s), want 200 and 1", status, hits)
	}
}

// Merge mode keeps its documented behaviour (a rule that fails validation is
// skipped and reported, the rest apply) but validates with the same per-rule
// core: an inert source form used to be installed without a word.
func TestRulesetIngress_MergeImportSkipsAndReportsAnInertSourceIP(t *testing.T) {
	ingressFixture(t)
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode=merge", &configBackup{Version: 1, PolicyRules: []PolicyRule{
		{Name: "quarantine", Action: ActionDrop, SourceIP: "10.0.0.5-10.0.0.9"}, // would overwrite the working rule
		{Name: "new-inert", Action: ActionDrop, SourceIP: "10.0.0.0/33"},
		{Name: "new-good", Action: ActionDrop, SourceIP: "10.0.1.0/24"},
	}}))
	if w.Code != http.StatusOK {
		t.Fatalf("merge import = %d, want 200: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(resp.Warnings, "\n")
	for _, want := range []string{`"quarantine" skipped`, `"new-inert" skipped`, "sourceIP"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings lack %q: %v", want, resp.Warnings)
		}
	}
	if got := ruleNamesOf(policyStore.List()); got != "quarantine,new-good" {
		t.Errorf("rules after merge = [%s], want [quarantine,new-good]", got)
	}
	if got := ingressVerdict("10.0.0.5", "anything.example"); got != "quarantine:Drop" {
		t.Errorf("10.0.0.5 verdict = %q, want quarantine:Drop (the working rule must not be overwritten by an inert one)", got)
	}
}

// The refusal names the rule by position and name and repeats untrusted values
// only sanitized and bounded.
func TestRulesetIngress_RefusalIsBoundedAndSanitized(t *testing.T) {
	long := strings.Repeat("n", 4096)
	_, err := validateIngressRuleset([]PolicyRule{
		{Name: "ok", Priority: 1, Action: ActionAllow},
		{Name: "evil\r\nname" + long, Priority: 2, Action: ActionDrop, SourceIP: "10.0.0.1-\r\n" + long},
	}, importRuleChecks{})
	if err == nil {
		t.Fatal("ruleset with an inert sourceIP accepted")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\r\n") {
		t.Errorf("refusal carries a raw line break: %q", msg)
	}
	if len(msg) > 1024 {
		t.Errorf("refusal is %d bytes: untrusted values are not bounded", len(msg))
	}
	for _, want := range []string{"rule 2 of 2", "evil", "sourceIP"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal lacks %q: %s", want, msg)
		}
	}
	if _, err := validateIngressRuleset(nil, importRuleChecks{}); err != nil {
		t.Errorf("an empty ruleset is a valid policy, got %v", err)
	}
}

// Stored and wire doors are NOT ingress doors. A ruleset holding shapes the
// policy API refuses but a store may legitimately hold (written by an older
// release, by hand in the policy file, or published by a control plane) still
// passes the pure gate at every one of them: a node must not fail to start,
// roll back or follow its control plane because of a write-time rule.
func TestRulesetIngress_StoredAndWireDoorsStayOnThePureGate(t *testing.T) {
	stored := []PolicyRule{
		{Name: "inert", Priority: 1, Action: ActionDrop, SourceIP: "10.0.0.1-10.0.0.9"},
		{Name: "folded", Priority: 2, Action: "drop", DestFQDN: "f.example"},
		{Name: "no-action", Priority: 3, DestFQDN: "n.example"},
		{Name: "redir", Priority: 4, Action: ActionRedirect, DestFQDN: "r.example"},
		{Name: "tz", Priority: 5, Action: ActionDrop, Schedule: &PolicySchedule{Timezone: "../nowhere"}},
		{Name: "tz", Priority: 5, Action: ActionDrop, DestFQDN: "dup.example"},
	}
	if _, err := validateIngressRuleset(stored, importRuleChecks{}); err == nil {
		t.Fatal("premise: the ingress validation must refuse this ruleset")
	}
	if err := storedRulesetError(stored); err != nil {
		t.Errorf("config-version rollback gate refuses a stored ruleset: %v", err)
	}
	if err := validateConfigSnapshot(ConfigSnapshot{PolicyRules: stored}); err != nil {
		t.Errorf("control-plane snapshot validation refuses it: %v", err)
	}
	data, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	ps := &PolicyStore{}
	if _, err := ps.decodePolicyFile(data); err != nil {
		t.Errorf("policy-file load refuses it: %v", err)
	}
	ps.ReplaceAll(stored)
	if n := len(ps.List()); n != len(stored) {
		t.Errorf("ReplaceAll kept %d of %d stored rules", n, len(stored))
	}
}
