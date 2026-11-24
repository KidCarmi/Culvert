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

	// Positive control: a pure invalid finding is never typed unverifiable.
	if err := validateRuleIngress(PolicyRule{Name: "x", Action: ActionDrop, SourceIP: "1-2"}); err == nil || errors.Is(err, errRuleUnverifiable) {
		t.Errorf("inert sourceIP: %v, want a plain invalid-rule error", err)
	}
}

// assertMergeSkipsBoth merges two rules (dry run, then commit) and requires
// each to be skipped with a warning naming the zone.
func assertMergeSkipsBoth(t *testing.T, a, b PolicyRule) {
	t.Helper()
	for _, q := range []string{"mode=merge&dryRun=true", "mode=merge"} {
		code, resp, body := ingressPost(t, q, &configBackup{Version: 1, PolicyRules: []PolicyRule{a, b}})
		if code != http.StatusOK || len(resp.Warnings) != 2 {
			t.Fatalf("%s = %d with %d warning(s), want 200 and 2 skips: %s", q, code, len(resp.Warnings), body)
		}
		for _, w := range resp.Warnings {
			if !strings.Contains(w, "skipped") || !strings.Contains(w, "Mars/Olympus") {
				t.Errorf("%s: warning is not a skip naming the zone: %s", q, w)
			}
		}
	}
}

// noTimezoneDatabase stands in for an image built without zoneinfo.
func noTimezoneDatabase(t *testing.T) {
	t.Helper()
	prev := nodeHasTimezoneDatabase
	nodeHasTimezoneDatabase = func() bool { return false }
	t.Cleanup(func() { nodeHasTimezoneDatabase = prev })
}

// A schedule timezone this node cannot load is refused at every operator door,
// for every rule type, whether the cause is a typo (node has a database) or a
// node with no database. It is never installed with a warning: nothing
// downstream is fail-closed about it. The two causes stay distinguishable.
func TestRulesetIngress_UnloadableTimezoneIsRefusedNotInstalled(t *testing.T) {
	if !nodeHasTimezoneDatabase() {
		t.Fatal("premise: the test host has a timezone database (the probe is what noTimezoneDatabase replaces)")
	}
	access := PolicyRule{Name: "office-hours", Priority: 2, Action: ActionAllow, DestFQDN: "tz.example",
		Schedule: &PolicySchedule{TimeStart: "09:00", TimeEnd: "17:00", Timezone: "Mars/Olympus"}}
	auth := authRule()
	auth.Priority = 3
	auth.Schedule = &PolicySchedule{Timezone: "Mars/Olympus"}

	typo := validateRuleIngress(access)
	if typo == nil || errors.Is(typo, errNoTimezoneDatabase) || errors.Is(typo, errRuleUnverifiable) || !strings.Contains(typo.Error(), "not a known timezone") {
		t.Fatalf("node with tzdata: %v, want a plain 'not a known timezone' refusal", typo)
	}
	for _, tc := range []struct {
		label  string
		noDB   bool
		rule   PolicyRule
		wantIn string
	}{
		{"typo, access rule", false, access, "not a known timezone"},
		{"typo, auth rule", false, auth, "not a known timezone"},
		{"no database, access rule", true, access, "no timezone database"},
		{"no database, auth rule", true, auth, "no timezone database"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			path := ingressFixture(t)
			if tc.noDB {
				noTimezoneDatabase(t)
			}
			wantFile, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			version := storeVersion(policyStore)
			err = validateRuleIngress(tc.rule)
			if err == nil || errors.Is(err, errRuleUnverifiable) || errors.Is(err, errNoTimezoneDatabase) != tc.noDB {
				t.Fatalf("validateRuleIngress = %v; want a refusal, typed errNoTimezoneDatabase=%v, never unverifiable", err, tc.noDB)
			}
			for _, q := range []string{"mode=replace", "mode=replace&dryRun=true"} {
				exportedAt := "ingress/" + t.Name() + "/" + q
				w := ingressImport(t, q, exportedAt, []PolicyRule{tc.rule})
				if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.wantIn) || !strings.Contains(w.Body.String(), "Mars/Olympus") {
					t.Fatalf("import %s = %d %q, want 400 naming the zone and %q", q, w.Code, w.Body.String(), tc.wantIn)
				}
				assertIngressUntouched(t, q, path, wantFile, version, exportedAt)
			}
			code, resp, body := ingressPost(t, "mode=merge", &configBackup{Version: 1, PolicyRules: []PolicyRule{tc.rule}})
			if code != http.StatusOK {
				t.Fatalf("merge = %d: %s", code, body)
			}
			assertOneWarning(t, "merge", resp.Warnings, "skipped", tc.wantIn)
			if got := ruleNamesOf(policyStore.List()); got != "quarantine" {
				t.Errorf("rules after merge = [%s], want [quarantine]", got)
			}
		})
	}
}

// The Codex reproduction on PR #2094. A working CredentialRequired rule, the
// default auth outcome Exempt, and a merge import of the SAME rule carrying a
// timezone this node cannot load: the import used to overwrite the rule, the
// auth matcher then skipped it (authScheduleParseable), and the previously
// protected request fell to the Exempt default. The update is skipped and the
// existing rule stays exactly as it was. Same for an access Block rule.
func TestRulesetIngress_MergeNeverOverwritesAWorkingRuleWithAnUnloadableTimezone(t *testing.T) {
	for _, noDB := range []bool{false, true} {
		t.Run(map[bool]string{false: "typo on a node with tzdata", true: "node without tzdata"}[noDB], func(t *testing.T) {
			ingressFixture(t)
			cred := authRule()
			cred.Name, cred.Priority = "vendors-must-authenticate", 5
			cred.Auth = &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "secops", Reason: "vendor subnet must authenticate"}
			block := PolicyRule{Name: "block-social", Priority: 6, Action: ActionBlockPage, DestFQDN: "social.example"}
			policyStore.ReplaceAll([]PolicyRule{cred, block})
			before, _ := json.Marshal(policyStore.List())

			outcome := func() AuthOutcome {
				return resolveNoCredAuthOutcome(makeRequest("http://updates.example.com/", nil), "10.0.5.50", OutcomeExempt).Outcome
			}
			if got := outcome(); got != OutcomeCredentialRequired {
				t.Fatalf("premise: outcome before the import = %q, want CredentialRequired", got)
			}
			if noDB {
				noTimezoneDatabase(t)
			}
			credIn, blockIn := cred, block
			credIn.Schedule = &PolicySchedule{Timezone: "Mars/Olympus"}
			blockIn.Schedule = &PolicySchedule{TimeStart: "09:00", TimeEnd: "17:00", Timezone: "Mars/Olympus"}
			assertMergeSkipsBoth(t, credIn, blockIn)
			if after, _ := json.Marshal(policyStore.List()); !bytes.Equal(after, before) {
				t.Errorf("the merge changed existing rules:\n before %s\n after  %s", before, after)
			}
			if got := outcome(); got != OutcomeCredentialRequired {
				t.Errorf("auth outcome after the import = %q, want CredentialRequired (the requirement was lost)", got)
			}
			if got := ingressVerdict("192.0.2.1", "social.example"); got != "block-social:Block_Page" {
				t.Errorf("social.example verdict after the import = %q, want block-social:Block_Page", got)
			}
		})
	}
}

// On a node that HAS a timezone database an unknown zone is a typo, not
// something to wait for: refused on replace, skipped on merge, as merge always
// did. Installing it would put the rule live on UTC hours.
func TestRulesetIngress_TypoTimezoneIsInvalidOnANodeWithTzdata(t *testing.T) {
	for _, zone := range []string{"Europe/Pariss", "garbage", "a", "UTC+99", "-", "america/new_york_"} {
		t.Run(zone, func(t *testing.T) {
			path := ingressFixture(t)
			wantFile, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			version := storeVersion(policyStore)
			rule := PolicyRule{Name: "hours", Priority: 2, Action: ActionAllow, DestFQDN: "tz.example",
				Schedule: &PolicySchedule{TimeStart: "09:00", TimeEnd: "17:00", Timezone: zone}}
			if err := validateRuleIngress(rule); err == nil || errors.Is(err, errRuleUnverifiable) {
				t.Fatalf("validateRuleIngress = %v, want a plain invalid-rule error", err)
			}
			exportedAt := "ingress/" + t.Name()
			w := ingressImport(t, "mode=replace", exportedAt, []PolicyRule{rule})
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid schedule timezone") {
				t.Fatalf("replace = %d %q, want 400 invalid schedule timezone", w.Code, w.Body.String())
			}
			assertIngressUntouched(t, "replace", path, wantFile, version, exportedAt)

			code, resp, body := ingressPost(t, "mode=merge", &configBackup{Version: 1, PolicyRules: []PolicyRule{rule}})
			if code != http.StatusOK {
				t.Fatalf("merge = %d: %s", code, body)
			}
			assertOneWarning(t, "merge", resp.Warnings, `"hours" skipped`, "invalid schedule timezone")
			if got := ruleNamesOf(policyStore.List()); got != "quarantine" {
				t.Errorf("rules after merge = [%s], want [quarantine]", got)
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

// resolverMustNotBeCalled fails the test if a host reaches DNS.
func resolverMustNotBeCalled(t *testing.T) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, host string) ([]string, error) {
		t.Errorf("DNS lookup made for %q: an address literal is classified without one", host)
		return nil, errors.New("unexpected lookup")
	}
}

// Whether an address literal is internal is arithmetic: decided with no lookup
// and no context, so neither a dead context nor a resolver outage can turn it
// into "could not be verified". Numeric-looking hosts that are not canonical
// literals, and localhost in any spelling, are refused outright.
func TestRulesetIngress_RedirectAddressLiteralsAreClassifiedWithoutDNS(t *testing.T) {
	ingressResolver(t, resolverMustNotBeCalled(t))
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	refused := []string{
		"http://169.254.169.254/x", "http://10.0.0.1/", "http://127.0.0.1:8080/", "http://0.0.0.0/",
		"http://[::1]/", "http://[::1]:80/", "http://[fd00::1]/x", "http://[fe80::1%25eth0]:80/",
		"http://[::ffff:10.0.0.1]/", "http://[::]/",
		"http://2130706433/", "http://0x7f.1/", "http://127.1/", "http://0x7f000001/",
		"http://localhost/", "http://localhost./", "http://LOCALHOST:8080/", "http://app.localhost/",
	}
	for _, raw := range refused {
		for label, ctx := range map[string]context.Context{"live": context.Background(), "dead": dead} {
			unverifiable, invalid := checkRedirectURL(ctx, raw)
			if invalid == nil || unverifiable != nil {
				t.Errorf("%s (%s context): invalid=%v unverifiable=%v, want invalid", raw, label, invalid, unverifiable)
			}
		}
	}
	// The serve path is at least as strict: with a resolver that answers an IP
	// literal with itself and knows no names, none of them is redirected to.
	ingressResolver(t, func(_ context.Context, host string) ([]string, error) {
		if ip := net.ParseIP(host); ip != nil {
			return []string{host}, nil
		}
		return resolverDown(context.Background(), host)
	})
	for _, raw := range refused {
		if isSafeRedirectURL(raw) {
			t.Errorf("%s: refused at ingress but the serve path would redirect to it", raw)
		}
	}
	ingressResolver(t, resolverMustNotBeCalled(t))
	for _, raw := range []string{"https://93.184.216.34/", "http://[2606:2800:220:1::1]:8443/x"} {
		if unverifiable, invalid := checkRedirectURL(dead, raw); invalid != nil || unverifiable != nil {
			t.Errorf("%s: invalid=%v unverifiable=%v, want a public literal accepted without a lookup", raw, invalid, unverifiable)
		}
	}
	// Control: a DNS name does go to the resolver.
	called := false
	ingressResolver(t, func(context.Context, string) ([]string, error) { called = true; return []string{"93.184.216.34"}, nil })
	if u, inv := checkRedirectURL(context.Background(), "https://landing.corp.example/"); u != nil || inv != nil || !called {
		t.Errorf("DNS name: unverifiable=%v invalid=%v called=%v, want a lookup and acceptance", u, inv, called)
	}
}

// Reviewer's reproduction: with the REQUEST context cancelled and a resolver
// that answers "private", replace and merge both answered 200 and installed a
// Redirect to 169.254.169.254 and to a private-resolving host. A cancelled
// request now applies nothing.
func TestRulesetIngress_CancelledRequestAppliesNothing(t *testing.T) {
	path := ingressFixture(t)
	wantFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	version := storeVersion(policyStore)
	ingressResolver(t, resolverPrivate)
	meta := redirectRule("metadata")
	meta.RedirectURL = "http://169.254.169.254/x"
	internal := redirectRule("internal-name")
	internal.Priority = 3
	for _, rules := range [][]PolicyRule{{meta}, {internal}} {
		for _, q := range []string{"mode=replace", "mode=merge", "mode=replace&dryRun=true"} {
			exportedAt := "ingress/" + t.Name() + "/" + rules[0].Name + "/" + q
			req := jsonReq("POST", "/api/config/import?"+q, &configBackup{
				Version: 1, ExportedAt: exportedAt, PolicyRules: rules,
				Blocklist: []string{ingressCanaryHost}, DefaultAction: "deny",
			})
			ctx, cancel := context.WithCancel(req.Context())
			cancel()
			w := httptest.NewRecorder()
			apiConfigImport(w, req.WithContext(ctx))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s %s on a cancelled request = %d, want 400: %s", rules[0].Name, q, w.Code, w.Body.String())
			}
			assertIngressUntouched(t, rules[0].Name+" "+q, path, wantFile, version, exportedAt)
		}
	}
}

// Reviewer's second reproduction: one wedged host spends the verification
// budget, and the rules after it used to be waved through as unverifiable,
// including a private IP literal. A literal is still refused; a DNS name after
// the budget is reported as not verified, in words that say why.
func TestRulesetIngress_SpentBudgetDoesNotLaunderALiteral(t *testing.T) {
	ingressFixture(t)
	prev := importVerifyBudget
	importVerifyBudget = 100 * time.Millisecond
	t.Cleanup(func() { importVerifyBudget = prev })
	ingressResolver(t, func(ctx context.Context, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	wedged := redirectRule("wedged")
	meta := redirectRule("metadata")
	meta.Priority, meta.RedirectURL = 3, "http://169.254.169.254/x"
	later := redirectRule("later")
	later.Priority, later.RedirectURL = 4, "https://later.corp.example/"

	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode=replace", &configBackup{Version: 1, PolicyRules: []PolicyRule{wedged, meta}}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"metadata"`) {
		t.Fatalf("replace with a private literal after the budget = %d %q, want 400 naming it", w.Code, w.Body.String())
	}
	code, resp, body := ingressPost(t, "mode=merge", &configBackup{Version: 1, PolicyRules: []PolicyRule{wedged, meta, later}})
	if code != http.StatusOK || len(resp.Warnings) != 3 {
		t.Fatalf("merge = %d with %d warning(s), want 200 and 3: %s", code, len(resp.Warnings), body)
	}
	assertOneWarning(t, "literal", resp.Warnings[1:2], `"metadata" skipped`, "private, internal")
	assertOneWarning(t, "after budget", resp.Warnings[2:], `"later" imported but NOT verified`, "time allowed for verification ran out")
	if strings.Contains(resp.Warnings[2], "DNS lookup failed") {
		t.Errorf("a lookup that was never made is reported as failed: %s", resp.Warnings[2])
	}
	if got := ruleNamesOf(policyStore.List()); got != "quarantine,wedged,later" {
		t.Errorf("rules = [%s], want [quarantine,wedged,later]", got)
	}
}

// A dry run is read-only in every observable way: it writes no policy WARN
// line (its scratch store is silent), and the live store, its version, the
// policy file, the audit trail's import entry and the config versions are as
// they were.
func TestRulesetIngress_MergeDryRunIsSilentAndTouchesNothing(t *testing.T) {
	path := ingressFixture(t)
	wantFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	version := storeVersion(policyStore)
	backup := &configBackup{Version: 1, ExportedAt: "ingress/" + t.Name(), Blocklist: []string{ingressCanaryHost}, DefaultAction: "deny",
		PolicyRules: []PolicyRule{
			{Name: "shadowed-allow", Action: ActionAllow, SourceIP: "10.0.0.5"},   // conflicts with the running Drop
			{Name: "future", Action: "Quarantine", DestFQDN: "q.example"},         // skipped
			{Name: "another-conflict", Action: ActionAllow, SourceIP: "10.0.0.5"}, // conflicts again
		}}
	// Control: an ordinary store logs and records a refused ruleset; a silent
	// scratch store handed the same one does neither. (Rule-conflict lines are
	// gated the same way, but Add assigns unique priorities, so none arise.)
	control := captureAppLog(t)
	for _, silent := range []bool{false, true} {
		ps := &PolicyStore{staging: true, silent: silent}
		ps.ReplaceAll(scopedBlockRuleset("x.example"))
		logged := strings.Contains(control.String(), "REFUSED")
		if logged == silent || (checkPolicyRulesetRefused(ps) != nil) == silent {
			t.Fatalf("silent=%v: logged=%v row=%v", silent, logged, checkPolicyRulesetRefused(ps))
		}
		control.Reset()
	}

	logs := captureAppLog(t)
	code, resp, body := ingressPost(t, "mode=merge&dryRun=true", backup)
	if code != http.StatusOK || len(resp.Warnings) != 1 {
		t.Fatalf("dry run = %d with %d warning(s), want 200 and 1: %s", code, len(resp.Warnings), body)
	}
	if out := logs.String(); strings.Contains(out, "Policy:") || strings.Contains(out, "ConfigImport:") || strings.Contains(out, "REFUSED") {
		t.Errorf("the dry run wrote operator-facing policy log lines:\n%s", out)
	}
	if rows := checkPolicyRulesetRefused(policyStore); rows != nil {
		t.Errorf("the dry run left a Diagnostics refusal row: %+v", rows)
	}
	assertIngressUntouched(t, "dry run", path, wantFile, version, backup.ExportedAt)
}

// Verdicts are reused only for the rule set they were computed for.
func TestRulesetIngress_VerdictsAreNotReusedForAnotherRuleSet(t *testing.T) {
	good := []PolicyRule{{Name: "a", Priority: 1, Action: ActionDrop, SourceIP: "10.0.0.5"}}
	bad := []PolicyRule{{Name: "a", Priority: 1, Action: ActionDrop, SourceIP: "10.0.0.5-10.0.0.9"}}
	checks := checkImportRules(context.Background(), good)
	if _, err := validateIngressRuleset(good, checks); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, err := validateIngressRuleset(bad, checks); err == nil {
		t.Error("verdicts computed for one rule set were applied to another of the same length")
	}
	scratch := &PolicyStore{staging: true, silent: true}
	if out := mergeImportedRules(scratch, bad, checks); out.skipped != 1 || len(scratch.List()) != 0 {
		t.Errorf("merge reused another set's verdicts: %+v, %d rule(s) installed", out, len(scratch.List()))
	}
}
