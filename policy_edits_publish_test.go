package main

// policy_edits_publish_test.go — a committed change to the running policy
// rulebase on a control plane is published at commit (policy_publish.go).
//
// Every test drives the REAL admin handler and reads what a data plane would
// be served through the REAL GetConfig RPC handler. With the publish removed
// from the shared helper every "publishes" test below fails: the committed
// version stays put and the served rules stay the old ones.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── fixture ──────────────────────────────────────────────────────────────────

// ppSetRole sets this node's cluster role for the test.
func ppSetRole(t *testing.T, role string) {
	t.Helper()
	clusterRoleMu.Lock()
	orig := clusterRole.role
	clusterRole.role = role
	clusterRoleMu.Unlock()
	t.Cleanup(func() {
		clusterRoleMu.Lock()
		clusterRole.role = orig
		clusterRoleMu.Unlock()
	})
}

// ppControlPlane isolates the policy stores (refGateSetup: running policy,
// draft, category store, groups, decryption profiles), gives the test its own
// committed-snapshot store, makes this node a control plane and publishes its
// starting configuration.
func ppControlPlane(t *testing.T) {
	t.Helper()
	refGateSetup(t)
	orig := globalConfigStore
	globalConfigStore = &ConfigStore{}
	t.Cleanup(func() {
		globalConfigStore = orig
		gcMarshalCache.reset()
		gcDeltaRemainderCache.reset()
	})
	ppSetRole(t, "control-plane")
	if err := publishCurrentConfigSnapshot(); err != nil {
		t.Fatalf("starting publish: %v", err)
	}
}

// ppServedRules is the rule names a full GetConfig poll is answered with.
func ppServedRules(t *testing.T) string {
	t.Helper()
	raw, err := (&controlPlaneServer{}).GetConfig(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	var snap ConfigSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("decode served snapshot: %v", err)
	}
	return ppRuleSummary(snap.PolicyRules)
}

// ppRuleSummary renders the fields the doors under test change.
func ppRuleSummary(rules []PolicyRule) string {
	out := make([]string, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		out = append(out, fmt.Sprintf("%d:%s:%s:on=%v:grp=%s:prof=%s:fp=%s",
			r.Priority, r.Name, r.Action, ruleIsEnabled(r), r.DestCategoryGroup, r.DecryptionProfile, r.FileProfile))
	}
	return strings.Join(out, " | ")
}

func ppRunning() string { return ppRuleSummary(policyStore.List()) }

// ppDo runs one request against a handler and returns the response.
func ppDo(h func(http.ResponseWriter, *http.Request), method, path string, body any) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h(w, jsonReq(method, path, body))
	return w
}

// ppWantPublished runs edit and requires: it succeeded, it changed the running
// rulebase, the committed version advanced by EXACTLY one (one publish per
// request), and the served snapshot now carries the running rules.
func ppWantPublished(t *testing.T, door string, edit func() *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	before, v0 := ppRunning(), globalConfigStore.Version()
	w := edit()
	if w.Code >= 300 {
		t.Fatalf("%s: handler answered %d: %s", door, w.Code, w.Body.String())
	}
	after := ppRunning()
	if after == before {
		t.Fatalf("%s: control — the edit did not change the running rulebase (%s)", door, after)
	}
	if got := globalConfigStore.Version() - v0; got != 1 {
		t.Errorf("%s: committed version advanced by %d, want exactly 1 (running=[%s])", door, got, after)
	}
	if served := ppServedRules(t); served != after {
		t.Errorf("%s: data planes are served\n   [%s]\nbut the control plane runs\n   [%s]", door, served, after)
	}
	if strings.Contains(w.Body.String(), "cluster_publish_rejected") {
		t.Errorf("%s: an accepted publish was reported as rejected: %s", door, w.Body.String())
	}
	return w
}

// ppWantNotPublished runs edit and requires the committed version and the
// served rules to be exactly what they were.
func ppWantNotPublished(t *testing.T, door string, edit func() *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	v0, served0 := globalConfigStore.Version(), ppServedRules(t)
	w := edit()
	if got := globalConfigStore.Version(); got != v0 {
		t.Errorf("%s: published (version %d → %d), must not", door, v0, got)
	}
	if served := ppServedRules(t); served != served0 {
		t.Errorf("%s: served rules changed to [%s], must stay [%s]", door, served, served0)
	}
	return w
}

func ppRule(name string) map[string]any {
	return map[string]any{"name": name, "action": "Allow", "destFqdn": name + ".example.com"}
}

func ppCreate(t *testing.T, name string) PolicyRule {
	t.Helper()
	w := ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule(name))
	if w.Code >= 300 {
		t.Fatalf("create %s: %d %s", name, w.Code, w.Body.String())
	}
	var added PolicyRule
	if err := json.Unmarshal(w.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode created rule: %v", err)
	}
	return added
}

// ppPriorityOf is the CURRENT priority of the rule with this stable id.
func ppPriorityOf(t *testing.T, id string) int {
	t.Helper()
	rules := policyStore.List()
	for i := range rules {
		if rules[i].ID == id {
			return rules[i].Priority
		}
	}
	t.Fatalf("rule %s is not in the running rulebase", id)
	return 0
}

// ── rule handlers ────────────────────────────────────────────────────────────

// TestPolicyEditsPublish_RuleDoors: every access-rule door — create, update
// (by id and by priority), disable, reorder, move, delete (by id and by
// priority) and bulk delete — publishes once, and the served rules follow.
// This is the inverted form of the evidence test that showed creating a rule
// left "committed version unchanged, served rules=0".
func TestPolicyEditsPublish_RuleDoors(t *testing.T) {
	ppControlPlane(t)

	var a, b, c PolicyRule
	ppWantPublished(t, "create", func() *httptest.ResponseRecorder {
		w := ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule("pp-a"))
		_ = json.Unmarshal(w.Body.Bytes(), &a)
		return w
	})
	ppWantPublished(t, "create (second)", func() *httptest.ResponseRecorder {
		w := ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule("pp-b"))
		_ = json.Unmarshal(w.Body.Bytes(), &b)
		return w
	})
	ppWantPublished(t, "create (third)", func() *httptest.ResponseRecorder {
		w := ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule("pp-c"))
		_ = json.Unmarshal(w.Body.Bytes(), &c)
		return w
	})

	ppWantPublished(t, "update by id", func() *httptest.ResponseRecorder {
		body := ppRule("pp-a")
		body["action"] = "Drop"
		return ppDo(apiPolicyUpdate, "PUT", "/api/policy?id="+a.ID, body)
	})
	ppWantPublished(t, "update by priority", func() *httptest.ResponseRecorder {
		body := ppRule("pp-b")
		body["action"] = "Drop"
		return ppDo(apiPolicyUpdate, "PUT", fmt.Sprintf("/api/policy?priority=%d", ppPriorityOf(t, b.ID)), body)
	})
	ppWantPublished(t, "disable", func() *httptest.ResponseRecorder {
		body := ppRule("pp-c")
		body["enabled"] = false
		return ppDo(apiPolicyUpdate, "PUT", "/api/policy?id="+c.ID, body)
	})
	ppWantPublished(t, "reorder", func() *httptest.ResponseRecorder {
		cur := policyStore.List()
		prios := make([]int, 0, len(cur))
		for i := len(cur) - 1; i >= 0; i-- {
			prios = append(prios, cur[i].Priority)
		}
		return ppDo(apiPolicyReorder, "POST", "/api/policy/reorder", map[string]any{"priorities": prios})
	})
	ppWantPublished(t, "move", func() *httptest.ResponseRecorder {
		first := policyStore.List()[0]
		return ppDo(apiPolicyMove, "POST", "/api/policy/move", map[string]any{"priority": first.Priority, "position": "last"})
	})
	ppWantPublished(t, "delete by id", func() *httptest.ResponseRecorder {
		return ppDo(apiPolicyDelete, "DELETE", "/api/policy?id="+a.ID, nil)
	})
	d := ppCreate(t, "pp-d")
	ppWantPublished(t, "delete by priority", func() *httptest.ResponseRecorder {
		return ppDo(apiPolicyDelete, "DELETE", fmt.Sprintf("/api/policy?priority=%d", ppPriorityOf(t, d.ID)), nil)
	})
	ppWantPublished(t, "bulk delete (the last rules)", func() *httptest.ResponseRecorder {
		var prios []int
		for _, r := range policyStore.List() {
			prios = append(prios, r.Priority)
		}
		return ppDo(apiPolicyDelete, "DELETE", "/api/policy", map[string]any{"priorities": prios})
	})
	if n := policyStore.ConfiguredRuleCount(); n != 0 {
		t.Fatalf("control: %d rules left after the bulk delete", n)
	}
}

// TestPolicyEditsPublish_AuthRuleDoors: the auth-policy rule handlers share
// the running store and the same finalizer.
func TestPolicyEditsPublish_AuthRuleDoors(t *testing.T) {
	ppControlPlane(t)

	ppWantPublished(t, "auth create", func() *httptest.ResponseRecorder {
		return ppDo(apiAuthPolicyCreate, "POST", "/api/authpolicy", authRuleBody("pp-auth-a", "pp-auth-a.test"))
	})
	ppWantPublished(t, "auth create (second)", func() *httptest.ResponseRecorder {
		return ppDo(apiAuthPolicyCreate, "POST", "/api/authpolicy", authRuleBody("pp-auth-b", "pp-auth-b.test"))
	})
	rules := policyStore.List()
	ppWantPublished(t, "auth update", func() *httptest.ResponseRecorder {
		body := authRuleBody("pp-auth-a2", "pp-auth-a.test")
		return ppDo(apiAuthPolicyUpdate, "PUT", "/api/authpolicy?id="+rules[0].ID, body)
	})
	ppWantPublished(t, "auth reorder", func() *httptest.ResponseRecorder {
		return ppDo(apiAuthPolicyReorder, "POST", "/api/authpolicy/reorder",
			map[string]any{"priorities": []int{ppPriorityOf(t, rules[1].ID), ppPriorityOf(t, rules[0].ID)}})
	})
	ppWantPublished(t, "auth delete", func() *httptest.ResponseRecorder {
		return ppDo(apiAuthPolicyDelete, "DELETE", "/api/authpolicy?id="+rules[0].ID, nil)
	})
}

// ── draft: staging publishes nothing, the commit publishes once ──────────────

func TestPolicyEditsPublish_DraftStagesSilentlyAndCommitPublishesOnce(t *testing.T) {
	ppControlPlane(t)
	setRequireCommit(true)

	for _, name := range []string{"pp-staged-a", "pp-staged-b"} {
		w := ppWantNotPublished(t, "staged create "+name, func() *httptest.ResponseRecorder {
			return ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule(name))
		})
		if w.Code >= 300 {
			t.Fatalf("staged create: %d %s", w.Code, w.Body.String())
		}
	}
	if n := policyStore.ConfiguredRuleCount(); n != 0 {
		t.Fatalf("control: staging changed the running rulebase (%d rules)", n)
	}
	ppWantNotPublished(t, "commit refused (no comment)", func() *httptest.ResponseRecorder {
		w := ppDo(apiPolicyDraftCommit, "POST", "/api/policy/draft/commit", map[string]any{"comment": "  "})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("commit without a comment = %d, want 400", w.Code)
		}
		return w
	})
	ppWantPublished(t, "draft commit", func() *httptest.ResponseRecorder {
		return ppDo(apiPolicyDraftCommit, "POST", "/api/policy/draft/commit", map[string]any{"comment": "ship it"})
	})
	ppWantNotPublished(t, "draft revert", func() *httptest.ResponseRecorder {
		ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule("pp-staged-c"))
		return ppDo(apiPolicyDraftRevert, "POST", "/api/policy/draft/revert", nil)
	})
}

// ── refused and failed edits publish nothing ────────────────────────────────

func TestPolicyEditsPublish_RefusedOrFailedEditDoesNotPublish(t *testing.T) {
	ppControlPlane(t)
	a := ppCreate(t, "pp-a")

	cases := map[string]func() *httptest.ResponseRecorder{
		"malformed body": func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(context.Background(), "POST", "/api/policy", strings.NewReader("{not json"))
			apiPolicyCreate(w, adminCtx(r))
			return w
		},
		"duplicate name": func() *httptest.ResponseRecorder {
			return ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule("pp-a"))
		},
		"unknown id": func() *httptest.ResponseRecorder {
			return ppDo(apiPolicyDelete, "DELETE", "/api/policy?id=01ARZ3NDEKTSV4RRFFQ69G5FAV", nil)
		},
		"stale ifVersion": func() *httptest.ResponseRecorder {
			return ppDo(apiPolicyUpdate, "PUT", "/api/policy?id="+a.ID+"&ifVersion=999999", ppRule("pp-a"))
		},
		"viewer role": func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(context.Background(), "DELETE", "/api/policy?id="+a.ID, http.NoBody)
			apiPolicyDelete(w, r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleViewer)))
			return w
		},
	}
	for name, edit := range cases {
		w := ppWantNotPublished(t, name, edit)
		if w.Code < 400 {
			t.Errorf("%s: control — the handler accepted it (%d)", name, w.Code)
		}
	}

	// A persistence failure: the mutation is rolled back and answered 500.
	policyPath := filepath.Join(t.TempDir(), "policy_rules.json")
	policyStore.path = policyPath // refGateSetup restores the path
	blockPath(t, policyPath)
	w := ppWantNotPublished(t, "persist failure", func() *httptest.ResponseRecorder {
		return ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule("pp-undurable"))
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("control: a failed persist answered %d, want 500 (%s)", w.Code, w.Body.String())
	}
}

// ── only a control plane publishes ───────────────────────────────────────────

func TestPolicyEditsPublish_OnlyOnAControlPlane(t *testing.T) {
	for _, role := range []string{"standalone", "data-plane"} {
		t.Run(role, func(t *testing.T) {
			ppControlPlane(t)
			ppSetRole(t, role)
			v0 := globalConfigStore.Version()
			w := ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule("pp-local"))
			if w.Code >= 300 {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			if policyStore.ConfiguredRuleCount() != 1 {
				t.Fatal("control: the local edit did not apply")
			}
			if got := globalConfigStore.Version(); got != v0 {
				t.Errorf("a %s node published a policy edit (version %d → %d)", role, v0, got)
			}
		})
	}
}

// ── a rejected publish is reported, and the local edit stands ────────────────

func TestPolicyEditsPublish_RejectedPublishIsSurfaced(t *testing.T) {
	ppControlPlane(t)
	// The next publish is over a cluster-sync cap for a reason unrelated to
	// policy, so it is rejected at commit.
	feed := bl.FeedList()
	t.Cleanup(func() { bl.ReplaceFeedEntries(feed) })
	origExempt := rl.ListExemptions()
	t.Cleanup(func() { rl.ReplaceExemptions(origExempt) })
	over := make([]string, 0, maxSnapRateLimitExempt+1)
	for i := 0; i <= maxSnapRateLimitExempt; i++ {
		over = append(over, fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255))
	}
	rl.ReplaceExemptions(over)

	v0 := globalConfigStore.Version()
	w := ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule("pp-kept"))
	if w.Code >= 300 {
		t.Fatalf("the local edit must stand when the publish is rejected: %d %s", w.Code, w.Body.String())
	}
	if policyStore.ConfiguredRuleCount() != 1 || globalConfigStore.Version() != v0 {
		t.Fatalf("rules=%d version %d → %d; want the edit applied locally and nothing published",
			policyStore.ConfiguredRuleCount(), v0, globalConfigStore.Version())
	}
	if msg, _ := globalConfigStore.LastPublishError(); msg == "" {
		t.Error("a rejected policy publish left no LastPublishError for Diagnostics")
	}

	// A handler with a JSON-object response reports it inline.
	setRequireCommit(true)
	ppDo(apiPolicyCreate, "POST", "/api/policy", ppRule("pp-staged"))
	w = ppDo(apiPolicyDraftCommit, "POST", "/api/policy/draft/commit", map[string]any{"comment": "over cap"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "cluster_publish_rejected") {
		t.Errorf("draft commit with a rejected publish = %d %s; want 200 carrying cluster_publish_rejected", w.Code, w.Body.String())
	}
}

// ── object renames that rewrite running rules ───────────────────────────────

// TestPolicyEditsPublish_ObjectRenameCascade: renaming a category group, a
// decryption profile or a file profile rewrites the denormalized name on every
// running rule that references it — a change to the served rulebase, published
// once. Renaming an object NO rule references changes no rule and publishes
// nothing here (object edits themselves are not published; that gap is
// separate and recorded).
func TestPolicyEditsPublish_ObjectRenameCascade(t *testing.T) {
	ppControlPlane(t)
	dcProfileStoreIsolate(t)
	fp, err := globalProfileStore.Create("pp-fp", []string{".exe"})
	if err != nil {
		t.Fatalf("seed file profile: %v", err)
	}
	unused, err := globalCategoryGroups.Add("pp-unused-group", []string{"gate-cat"})
	if err != nil {
		t.Fatalf("seed unused group: %v", err)
	}
	group := globalCategoryGroups.GetByName("gate-group")
	prof := globalDecryptionProfiles.GetByName("gate-prof")
	if group == nil || unused == nil || prof == nil {
		t.Fatal("setup: seeded objects not found")
	}

	rule := ppRule("pp-ref")
	rule["destCategoryGroup"] = "gate-group"
	rule["decryptionProfile"] = "gate-prof"
	rule["sslAction"] = "Inspect"
	rule["fileProfile"] = fp.Name
	rule["fileFiltering"] = true
	if w := ppDo(apiPolicyCreate, "POST", "/api/policy", rule); w.Code >= 300 {
		t.Fatalf("create referencing rule: %d %s", w.Code, w.Body.String())
	}

	ppWantPublished(t, "category-group rename", func() *httptest.ResponseRecorder {
		return ppDo(apiCategoryGroups, "PUT", "/api/category-groups?id="+group.ID,
			map[string]any{"name": "gate-group-renamed", "categories": []string{"gate-cat"}})
	})
	ppWantPublished(t, "decryption-profile rename", func() *httptest.ResponseRecorder {
		return ppDo(apiDecryptionProfiles, "PUT", "/api/decryption-profiles?id="+prof.ID,
			map[string]any{"name": "gate-prof-renamed"})
	})
	ppWantPublished(t, "file-profile rename", func() *httptest.ResponseRecorder {
		return ppDo(apiFileblockProfiles, "PUT", "/api/fileblock/profiles?id="+fp.ID,
			map[string]any{"name": "pp-fp-renamed", "extensions": []string{".exe"}})
	})
	w := ppWantNotPublished(t, "rename of an unreferenced group", func() *httptest.ResponseRecorder {
		return ppDo(apiCategoryGroups, "PUT", "/api/category-groups?id="+unused.ID,
			map[string]any{"name": "pp-unused-renamed", "categories": []string{"gate-cat"}})
	})
	if w.Code >= 300 {
		t.Fatalf("control: the unreferenced rename failed: %d %s", w.Code, w.Body.String())
	}
}

// ── policy-file reload ──────────────────────────────────────────────────────

// TestPolicyEditsPublish_PolicyFileReload: a configuration reload (SIGHUP)
// that re-reads the policy file changes the running rulebase and publishes
// once, at the end of the reload. A refused file keeps the running rules and
// publishes nothing; so does a reload with no policy file configured.
func TestPolicyEditsPublish_PolicyFileReload(t *testing.T) {
	ppControlPlane(t)
	snapshotConnAndRateLimitGlobals(t)
	origDefault := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(origDefault) })
	ppCreate(t, "pp-before-reload")

	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	bad := filepath.Join(dir, "bad.json")
	writeJSON := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(good, `[{"priority":1,"name":"pp-reloaded","action":"Drop","destFqdn":"reloaded.example.com"}]`)
	writeJSON(bad, `[{"priority":1,"name":"pp-bad","ruleType":"no-such-type","action":"Allow"}]`)

	ppWantNotPublished(t, "reload with no policy file", func() *httptest.ResponseRecorder {
		applyHotReload(&FileConfig{})
		return httptest.NewRecorder()
	})
	ppWantNotPublished(t, "reload of a refused policy file", func() *httptest.ResponseRecorder {
		fc := &FileConfig{}
		fc.Proxy.PolicyFile = bad
		applyHotReload(fc)
		return httptest.NewRecorder()
	})
	if !strings.Contains(ppRunning(), "pp-before-reload") {
		t.Fatalf("control: the refused reload replaced the running rules: %s", ppRunning())
	}
	ppWantPublished(t, "reload of the policy file", func() *httptest.ResponseRecorder {
		fc := &FileConfig{}
		fc.Proxy.PolicyFile = good
		applyHotReload(fc)
		return httptest.NewRecorder()
	})
	if !strings.Contains(ppRunning(), "pp-reloaded") {
		t.Fatalf("control: the reload did not install the file's rules: %s", ppRunning())
	}
}
