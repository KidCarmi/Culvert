package main

// "Invalid" and "could not be verified on this node" are different findings
// (ruleCheck, ui_helpers.go). A ruleset import is the restore path: a backup of
// a healthy policy must not be refused because the node it is restored on
// cannot resolve a Redirect host or lacks a timezone file. Measured before
// this split, with the resolver answering "no such host":
//
//	POST /api/config/import?mode=replace   (export of an API-built policy)
//	  400 rule 2 of 7 ("redir") is not valid: redirectURL must be an absolute http/https URL

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// ingressResolver swaps the SSRF guard's resolver for the test.
func ingressResolver(t *testing.T, fn func(ctx context.Context, host string) ([]string, error)) {
	t.Helper()
	t.Cleanup(ssrf.SetLookupHostForTest(fn))
}

func resolverDown(_ context.Context, host string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func resolverPublic(_ context.Context, _ string) ([]string, error) {
	return []string{"93.184.216.34"}, nil
}

func resolverPrivate(_ context.Context, _ string) ([]string, error) {
	return []string{"10.1.2.3"}, nil
}

func redirectRule(name string) PolicyRule {
	return PolicyRule{Name: name, Priority: 2, Action: ActionRedirect, DestFQDN: "r.example", RedirectURL: "https://landing.corp.example/blocked"}
}

type ingressImportResp struct {
	OK       bool     `json:"ok"`
	Warnings []string `json:"warnings"`
	Sections []struct {
		Section string `json:"section"`
		Effect  string `json:"effect"`
	} `json:"sections"`
}

func ingressPost(t *testing.T, query string, b any) (code int, resp ingressImportResp, body string) {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?"+query, b))
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %q: %v", w.Body.String(), err)
		}
	}
	return w.Code, resp, w.Body.String()
}

func assertOneWarning(t *testing.T, label string, warnings []string, wants ...string) {
	t.Helper()
	if len(warnings) != 1 {
		t.Fatalf("%s: %d warning(s), want 1: %v", label, len(warnings), warnings)
	}
	for _, want := range wants {
		if !strings.Contains(warnings[0], want) {
			t.Errorf("%s: warning lacks %q: %s", label, want, warnings[0])
		}
	}
}

// A replace import of a healthy backup on a node whose resolver is down
// installs every rule, says which one it could not verify (dry run and commit
// alike), and persists it.
func TestRulesetIngress_ReplaceImportSurvivesAResolverOutage(t *testing.T) {
	path := ingressFixture(t)
	ingressResolver(t, resolverDown)
	backup := &configBackup{Version: 1, PolicyRules: []PolicyRule{
		{Name: "quarantine", Priority: 1, Action: ActionDrop, SourceIP: "10.0.0.5"},
		redirectRule("redir"),
	}}
	wants := []string{`"redir"`, "imported but NOT verified", "landing.corp.example", "could not be verified", "blocked until"}

	code, preview, body := ingressPost(t, "mode=replace&dryRun=true", backup)
	if code != http.StatusOK {
		t.Fatalf("dry run = %d, want 200: %s", code, body)
	}
	assertOneWarning(t, "dry run", preview.Warnings, wants...)
	if got := ruleNamesOf(policyStore.List()); got != "quarantine" {
		t.Fatalf("the dry run changed the policy: [%s]", got)
	}

	code, resp, body := ingressPost(t, "mode=replace", backup)
	if code != http.StatusOK || !resp.OK {
		t.Fatalf("replace import during a resolver outage = %d, want 200 ok: %s", code, body)
	}
	assertOneWarning(t, "commit", resp.Warnings, wants...)
	if strings.Contains(resp.Warnings[0], "absolute http") {
		t.Errorf("the warning calls a well-formed URL malformed: %s", resp.Warnings[0])
	}
	if got := ruleNamesOf(policyStore.List()); got != "quarantine,redir" {
		t.Errorf("running rules = [%s], want [quarantine,redir]", got)
	}
	disk := &PolicyStore{}
	if err := disk.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := ruleNamesOf(disk.List()); got != "quarantine,redir" {
		t.Errorf("persisted rules = [%s], want [quarantine,redir]", got)
	}
	if got := ingressVerdict("192.0.2.1", "r.example"); got != "redir:Redirect" {
		t.Errorf("the imported Redirect rule is not active: verdict %q", got)
	}

	// Why installing it is safe: the serve path re-checks the target on every
	// match. While the host does not resolve, the client gets 403, never a
	// redirect; once it resolves publicly, the redirect is served.
	serve := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://r.example/", http.NoBody)
		m := policyStore.Evaluate("192.0.2.1", "", "", "r.example", nil)
		applyPolicyDecision(w, r, "192.0.2.1", "r.example", "req-ingress", "", AuthLogFields{}, m)
		return w
	}
	if w := serve(); w.Code != http.StatusForbidden || w.Header().Get("Location") != "" {
		t.Errorf("unverifiable Redirect at serve time: status %d Location %q, want 403 and none", w.Code, w.Header().Get("Location"))
	}
	ingressResolver(t, resolverPublic)
	if w := serve(); w.Code != http.StatusFound {
		t.Errorf("once the host resolves publicly: status %d, want 302", w.Code)
	}
}

// A Redirect host that RESOLVES to a private address is invalid, not
// unverifiable: refused whole, and the message says so.
func TestRulesetIngress_ReplaceImportRefusesARedirectToAPrivateAddress(t *testing.T) {
	path := ingressFixture(t)
	wantFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	version := storeVersion(policyStore)
	ingressResolver(t, resolverPrivate)
	for _, q := range []string{"mode=replace", "mode=replace&dryRun=true"} {
		exportedAt := "ingress/" + t.Name() + "/" + q
		w := ingressImport(t, q, exportedAt, []PolicyRule{redirectRule("redir")})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("import %s = %d, want 400: %s", q, w.Code, w.Body.String())
		}
		for _, want := range []string{`"redir"`, "private or internal address", "landing.corp.example"} {
			if !strings.Contains(w.Body.String(), want) {
				t.Errorf("import %s: refusal lacks %q: %s", q, want, w.Body.String())
			}
		}
		assertIngressUntouched(t, q, path, wantFile, version, exportedAt)
	}
	// Merge mode: the same rule is skipped and reported, not installed.
	code, resp, body := ingressPost(t, "mode=merge", &configBackup{Version: 1, PolicyRules: []PolicyRule{redirectRule("redir")}})
	if code != http.StatusOK {
		t.Fatalf("merge = %d: %s", code, body)
	}
	assertOneWarning(t, "merge", resp.Warnings, `"redir" skipped`, "private or internal address")
	if got := ruleNamesOf(policyStore.List()); got != "quarantine" {
		t.Errorf("rules after merge = [%s], want [quarantine]", got)
	}
}

// The single-rule API is unchanged in what it accepts: it still refuses a rule
// it could not verify. The error is typed and says what happened.
func TestRulesetIngress_PolicyAPIStillRefusesAnUnverifiableRule(t *testing.T) {
	ingressFixture(t)
	ingressResolver(t, resolverDown)
	rule := redirectRule("api-redir")
	rule.Priority = 0

	check := checkRuleIngress(context.Background(), rule)
	if check.err != nil || len(check.unverifiable) != 1 {
		t.Fatalf("check = %+v, want valid with one unverifiable finding", check)
	}
	if err := validateRuleIngress(rule); !errors.Is(err, errRuleUnverifiable) {
		t.Fatalf("strict validation = %v, want errRuleUnverifiable", err)
	}
	w := httptest.NewRecorder()
	apiPolicyCreate(w, jsonReq("POST", "/api/policy", rule))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/policy during a resolver outage = %d, want 400: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "could not be verified") || strings.Contains(body, "must be an absolute") {
		t.Errorf("the 400 does not say the host could not be verified: %s", body)
	}
	if got := ruleNamesOf(policyStore.List()); got != "quarantine" {
		t.Errorf("rules = [%s], want [quarantine]", got)
	}

	// A timezone this node does not have: same split.
	tz := PolicyRule{Name: "tz", Action: ActionDrop, DestFQDN: "tz.example", Schedule: &PolicySchedule{Timezone: "Mars/Olympus"}}
	if err := validateRuleIngress(tz); !errors.Is(err, errRuleUnverifiable) {
		t.Errorf("unknown timezone: %v, want errRuleUnverifiable", err)
	}
	tz.Schedule.Timezone = "../etc/passwd"
	if err := validateRuleIngress(tz); err == nil || errors.Is(err, errRuleUnverifiable) {
		t.Errorf("impossible timezone name: %v, want a plain invalid-rule error", err)
	}
	// Positive control: a pure invalid finding is never typed unverifiable.
	if err := validateRuleIngress(PolicyRule{Name: "x", Action: ActionDrop, SourceIP: "1-2"}); err == nil || errors.Is(err, errRuleUnverifiable) {
		t.Errorf("inert sourceIP: %v, want a plain invalid-rule error", err)
	}
}

// A schedule timezone missing from this node's database does not lose the
// import in either mode; the warning names the zone and the consequence.
func TestRulesetIngress_ImportWarnsAboutATimezoneThisNodeLacks(t *testing.T) {
	for _, mode := range []string{"replace", "merge"} {
		t.Run(mode, func(t *testing.T) {
			ingressFixture(t)
			backup := &configBackup{Version: 1, PolicyRules: []PolicyRule{
				{Name: "quarantine", Priority: 1, Action: ActionDrop, SourceIP: "10.0.0.5"},
				{Name: "office-hours", Priority: 2, Action: ActionDrop, DestFQDN: "tz.example", Schedule: &PolicySchedule{Timezone: "Mars/Olympus"}},
			}}
			wants := []string{`"office-hours"`, "imported but NOT verified", "Mars/Olympus", "timezone database", "UTC"}
			for _, q := range []string{"mode=" + mode + "&dryRun=true", "mode=" + mode} {
				code, resp, body := ingressPost(t, q, backup)
				if code != http.StatusOK {
					t.Fatalf("import %s = %d, want 200: %s", q, code, body)
				}
				assertOneWarning(t, q, resp.Warnings, wants...)
			}
			if got := ruleNamesOf(policyStore.List()); got != "quarantine,office-hours" {
				t.Errorf("rules = [%s], want [quarantine,office-hours]", got)
			}
		})
	}
}

// A resolver that never answers costs the import its budget, not the OS
// resolver's: the lookups are abandoned and the rules reported as unverified.
func TestRulesetIngress_ImportVerificationIsTimeBounded(t *testing.T) {
	ingressFixture(t)
	prev := importVerifyBudget
	importVerifyBudget = 150 * time.Millisecond
	t.Cleanup(func() { importVerifyBudget = prev })
	ingressResolver(t, func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done() // wedged resolver
		return nil, ctx.Err()
	})
	rules := []PolicyRule{{Name: "quarantine", Priority: 1, Action: ActionDrop, SourceIP: "10.0.0.5"}}
	for i, name := range []string{"r1", "r2", "r3", "r4"} {
		r := redirectRule(name)
		r.Priority = i + 2
		r.RedirectURL = "https://" + name + ".corp.example/"
		rules = append(rules, r)
	}
	start := time.Now()
	code, resp, body := ingressPost(t, "mode=replace", &configBackup{Version: 1, PolicyRules: rules})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("import took %s against a wedged resolver with a 150ms budget", elapsed)
	}
	if code != http.StatusOK || len(resp.Warnings) != 4 {
		t.Fatalf("import = %d with %d warning(s), want 200 and 4: %s", code, len(resp.Warnings), body)
	}
}

// Merge mode: the dry run runs the merge itself, so it reports the skip the
// apply will make; and a warning repeats operator-supplied values bounded.
func TestRulesetIngress_MergePreviewAgreesWithApplyAndWarningsAreBounded(t *testing.T) {
	ingressFixture(t)
	long := strings.Repeat("n", 5000)
	backup := &configBackup{Version: 1, PolicyRules: []PolicyRule{
		{Name: "quarantine", Action: ActionDrop, SourceIP: "10.0.0.0/24"},          // update
		{Name: "fresh", Action: ActionDrop, SourceIP: "10.0.1.0/24"},               // add
		{Name: "bad" + long, Action: ActionDrop, SourceIP: "10.0.0.1-" + long},     // skipped
		{Name: "FRESH", Action: ActionAllow, DestFQDN: "second-of-a-name.example"}, // updates the rule added above
	}}
	code, preview, body := ingressPost(t, "mode=merge&dryRun=true", backup)
	if code != http.StatusOK {
		t.Fatalf("dry run = %d: %s", code, body)
	}
	effect := ""
	for _, s := range preview.Sections {
		if s.Section == "Policy Rules" {
			effect = s.Effect
		}
	}
	if want := "upsert 4: 2 update, 1 add, 1 skipped"; !strings.Contains(effect, want) {
		t.Errorf("preview effect = %q, want it to contain %q", effect, want)
	}
	if got := ruleNamesOf(policyStore.List()); got != "quarantine" {
		t.Fatalf("the dry run changed the policy: [%s]", got)
	}

	code, resp, body := ingressPost(t, "mode=merge", backup)
	if code != http.StatusOK {
		t.Fatalf("merge = %d: %s", code, body)
	}
	if strings.Join(resp.Warnings, "\n") != strings.Join(preview.Warnings, "\n") {
		t.Errorf("preview and apply disagree:\n preview %v\n apply   %v", preview.Warnings, resp.Warnings)
	}
	assertOneWarning(t, "merge", resp.Warnings, "skipped", "sourceIP")
	if n := len(resp.Warnings[0]); n > 600 {
		t.Errorf("a merge warning is %d bytes: the rule name and reason are not bounded", n)
	}
	if got := len(policyStore.List()); got != 2 {
		t.Errorf("%d rules after the merge, want 2 (1 updated, 1 added then updated)", got)
	}
}

// The backup version is checked before the rules: a file this version cannot
// read is not answered with advice to correct one of its rules.
func TestRulesetIngress_UnsupportedVersionIsReportedBeforeRuleValidation(t *testing.T) {
	ingressFixture(t)
	for _, q := range []string{"mode=replace", "mode=merge", "mode=replace&dryRun=true"} {
		w := httptest.NewRecorder()
		apiConfigImport(w, jsonReq("POST", "/api/config/import?"+q, &configBackup{
			Version: 99, PolicyRules: []PolicyRule{{Name: "x", Action: ActionDrop, SourceIP: "1-2"}},
		}))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "unsupported backup version") {
			t.Errorf("import %s of a version-99 file: %d %q, want 400 unsupported backup version", q, w.Code, w.Body.String())
		}
	}
}

// The system's own export of a policy built through the API imports back in
// replace mode, unchanged and without a warning: a Redirect, an auth rule with
// a subjectMatch, a non-UTC schedule, rules linked to a category group and a
// decryption profile, after the access rules were reordered.
func TestRulesetIngress_ExportOfAnAPIBuiltPolicyReimports(t *testing.T) {
	refGateSetup(t)
	ingressResolver(t, resolverPublic)

	post := func(h http.HandlerFunc, path string, body any) {
		t.Helper()
		w := httptest.NewRecorder()
		h(w, jsonReq("POST", path, body))
		if w.Code != http.StatusOK {
			t.Fatalf("POST %s %v = %d: %s", path, body, w.Code, w.Body.String())
		}
	}
	for _, rule := range []PolicyRule{
		{Name: "block-evil", Action: ActionDrop, SourceIP: "10.0.0.0/24", DestFQDN: "evil.example"},
		redirectRule("redir"),
		{Name: "office-hours", Action: ActionBlockPage, DestFQDN: "social.example",
			Schedule: &PolicySchedule{Days: []string{"Mon", "Tue"}, TimeStart: "09:00", TimeEnd: "17:00", Timezone: "Europe/Berlin"}},
		{Name: "by-group", Action: ActionDrop, DestCategoryGroup: "gate-group"},
		{Name: "by-category", Action: ActionBlockPage, DestCategory: "gate-cat"},
		{Name: "inspect", Action: ActionAllow, DestFQDN: "bank.example", SSLAction: SSLInspect, DecryptionProfile: "gate-prof"},
	} {
		rule.Priority = 0
		post(apiPolicyCreate, "/api/policy", rule)
	}
	auth := authRule()
	auth.Priority = 0
	post(apiAuthPolicy, "/api/authpolicy", auth)

	// Reorder the access rules: reverse them among their own slots.
	access := accessRulesIn(policyStore)
	pris := make([]int, 0, len(access))
	for i := len(access) - 1; i >= 0; i-- {
		pris = append(pris, access[i].Priority)
	}
	post(apiPolicyReorder, "/api/policy/reorder", map[string]any{"priorities": pris})
	if got := policyStore.List(); got[0].Name == "block-evil" {
		t.Fatalf("premise: the reorder did not move the first rule: %s", ruleNamesOf(got))
	}

	ew := httptest.NewRecorder()
	apiConfigExport(ew, getReq("/api/config/export"))
	if ew.Code != http.StatusOK {
		t.Fatalf("export = %d", ew.Code)
	}
	var exported map[string]any
	if err := json.Unmarshal(ew.Body.Bytes(), &exported); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if n := len(exported["policyRules"].([]any)); n != 7 {
		t.Fatalf("export holds %d rules, want 7", n)
	}
	before, _ := json.Marshal(policyStore.List())

	// Re-import only the policy section of the export, as exported.
	backup := map[string]any{"version": exported["version"], "policyRules": exported["policyRules"]}
	for _, q := range []string{"mode=replace&dryRun=true", "mode=replace", "mode=merge"} {
		code, resp, body := ingressPost(t, q, backup)
		if code != http.StatusOK {
			t.Fatalf("re-import (%s) of the system's own export = %d: %s", q, code, body)
		}
		if len(resp.Warnings) != 0 {
			t.Errorf("re-import (%s) warned: %v", q, resp.Warnings)
		}
		after, _ := json.Marshal(policyStore.List())
		if !bytes.Equal(after, before) {
			t.Errorf("re-import (%s) changed the rules:\n before %s\n after  %s", q, before, after)
		}
	}
}
