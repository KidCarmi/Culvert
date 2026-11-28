//go:build policy_conformance

// Differential conformance of the Stage-2 access-policy decision against the
// INDEPENDENT reference model in internal/policyref.
//
// SHADOW / NON-BLOCKING. The `policy_conformance` build tag keeps this file and the
// reference model out of every existing gate; .github/workflows/policy-conformance-shadow.yml
// runs it. It changes no production behaviour and defines no contract: where the model's
// clauses leave a case unspecified, the product's answer is REPORTED as an open contract
// question, never asserted.
//
// Two production paths are compared with the model, because ADR-0026 says they share one
// evaluator core but they reach it differently:
//   - enforcement: PolicyStore.Evaluate (published rules with precomputed matchers);
//   - Policy Tester: evalAccessRules over List() clones (precomputes cleared, so the
//     allocating fallback matchers run), with a trace callback.
//
// Vectors are deterministic: an exhaustive single-rule grid over every condition value and
// request, then seeded multi-rule rule sets. A mismatch is reported with a minimised rule
// set (rules removed one by one while the mismatch persists).
package main

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/policyref"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// ───────────────────────── environment and value pools

var prefEnv = policyref.Env{
	Categories: map[string][]string{
		"News":         {"news.test"},
		"Shopping":     {"shop.test", "example.com"},
		"Social Media": {"social.test"},
		"Empty":        {},
	},
	Groups: map[string][]string{
		"grpref000001": {"News", "Social Media"},
		"grpref000002": {"Shopping"},
		"grpref000003": {"Nonexistent"},
	},
}

// installPrefEnv installs prefEnv as the live category environment (admin categories
// only: no signed-feed view, no community DB) and restores everything on cleanup.
func installPrefEnv(t *testing.T) {
	t.Helper()
	origCat, origGroups, origCommunity := catStore, globalCategoryGroups, communityDB
	t.Cleanup(func() { catStore, globalCategoryGroups, communityDB = origCat, origGroups, origCommunity })
	communityDB = nil
	names := make([]string, 0, len(prefEnv.Categories))
	for n := range prefEnv.Categories {
		names = append(names, n)
	}
	sort.Strings(names)
	entries := make([]*urlcat.Entry, 0, len(names))
	for _, n := range names {
		entries = append(entries, &urlcat.Entry{Name: n, Hosts: append([]string(nil), prefEnv.Categories[n]...)})
	}
	catStore = urlcat.New(entries)
	swapSaaSView(t, nil)
	ids := make([]string, 0, len(prefEnv.Groups))
	for id := range prefEnv.Groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	groups := make([]CategoryGroup, 0, len(ids))
	for _, id := range ids {
		groups = append(groups, CategoryGroup{ID: id, Name: "name-" + id, Categories: append([]string(nil), prefEnv.Groups[id]...)})
	}
	globalCategoryGroups = catgroup.New()
	globalCategoryGroups.ReplaceAll(groups)
}

// Condition pools: ordinary values plus boundary and adversarial spellings.
var (
	poolFQDN = []string{"*", "example.com", "*.example.com", "EXAMPLE.COM.", "www.example.com", "xample.com", "com",
		"*.com", "example.co", "news.test", "10.0.0.5", "2001:DB8::1", "[2001:db8::1]", "::ffff:10.0.0.5", "*.news.test"}
	poolSourceIP = []string{"10.0.0.5", "10.0.0.0/24", "10.0.0.0/8", "::ffff:10.0.0.5", "2001:db8::/32", "2001:DB8::10",
		"0.0.0.0/0", "10.0.0.5/32", "10.0.0.7/24", "::/0", "::ffff:10.0.0.0/120", "10.0.0.300", "10.0.0.0/33", "fe80::1%eth0"}
	poolIdentity   = []string{"alice", "ALICE", "bob"}
	poolGroup      = []string{"eng", " Eng ", "sales"}
	poolAuthSource = []string{"okta", "oidc:okta", "saml:okta", "OIDC:Okta", "ldap:corp", "local", "oidc:"}
	poolCategory   = []string{"Any", "any", "News", "news", "SHOPPING", "Social Media", "Empty", "Nonexistent"}
	poolGroupID    = []string{"grpref000001", "grpref000002", "grpref000003", "grprefXXXXXX"}

	reqHosts = []string{"example.com", "www.example.com", "EXAMPLE.com.", "a.b.example.com", "notexample.com",
		"example.com.evil.test", "xample.com", "news.test", "sub.news.test", "shop.test", "social.test", "10.0.0.5",
		"[2001:db8::1]", "2001:db8::1", "::ffff:10.0.0.5", "[::ffff:10.0.0.5]", "localhost", "example.co", "com"}
	reqClients    = []string{"10.0.0.5", "10.0.1.9", "192.168.1.1", "::ffff:10.0.0.5", "2001:db8::10", "fe80::1%eth0", "garbage"}
	reqIdentities = []string{"alice", "Alice", "bob", ""}
	reqGroups     = [][]string{nil, {"eng"}, {"ENG ", "x"}, {"sales"}}
	reqAuth       = []string{"okta", "oidc:okta", "saml:okta", "OKTA", "unauth", "local", "ldap:corp"}
)

func onPtr() *bool  { b := true; return &b }
func offPtr() *bool { b := false; return &b }

// requests is the full request cross product used by the single-rule grid (one varying
// dimension at a time keeps it small but still hits every value of every dimension).
func prefRequests() []policyref.Request {
	base := policyref.Request{ClientIP: "10.0.0.5", Identity: "alice", AuthSource: "okta", Host: "example.com", Groups: []string{"eng"}}
	var out []policyref.Request
	add := func(f func(r *policyref.Request)) {
		r := base
		r.Groups = append([]string(nil), base.Groups...)
		f(&r)
		out = append(out, r)
	}
	for _, h := range reqHosts {
		add(func(r *policyref.Request) { r.Host = h })
	}
	for _, c := range reqClients {
		add(func(r *policyref.Request) { r.ClientIP = c })
	}
	for _, id := range reqIdentities {
		add(func(r *policyref.Request) { r.Identity = id })
	}
	for _, g := range reqGroups {
		add(func(r *policyref.Request) { r.Groups = g })
	}
	for _, a := range reqAuth {
		add(func(r *policyref.Request) { r.AuthSource = a })
	}
	return out
}

// ───────────────────────── production adapters

func toPolicyRule(r *policyref.Rule) PolicyRule {
	pr := PolicyRule{Name: r.Name, Priority: r.Priority, Enabled: r.Enabled, RuleType: r.Type,
		Action: PolicyAction(r.Action), SourceIP: r.SourceIP, SourceIdentity: r.SourceIdentity,
		SourceGroup: r.SourceGroup, AuthSource: r.AuthSource, DestFQDN: r.DestFQDN, DestCategory: URLCategory(r.DestCategory)}
	if r.DestGroupID != "" {
		pr.DestCategoryGroupID, pr.DestCategoryGroup = r.DestGroupID, "name-"+r.DestGroupID
	}
	if r.Type == ruleTypeAuth {
		// A VALID, maximally broad Stage-1 rule, so the publication gate keeps it and the
		// scan really meets it: an invalid one is dropped on publish and would leave R4
		// untested. Stage-1 subjects live in SubjectMatch, not the access source fields.
		pr.SourceIP, pr.SourceIdentity, pr.SourceGroup, pr.AuthSource = "", "", "", ""
		pr.DestCategory, pr.DestCategoryGroup, pr.DestCategoryGroupID = "", "", ""
		pr.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{
			{Type: subjectPredicateCIDR, Values: []string{"0.0.0.0/0", "::/0"}}}}
		pr.Auth = &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "conformance", Reason: "reference vectors"}
	}
	return pr
}

// publishedAuthRules counts the Stage-1 rules a store actually published.
func publishedAuthRules(ps *PolicyStore) int {
	n := 0
	for _, r := range ps.List() {
		if ruleTypeOf(&r) == ruleTypeAuth {
			n++
		}
	}
	return n
}

func publish(rules []policyref.Rule) *PolicyStore {
	ps := &PolicyStore{}
	in := make([]PolicyRule, len(rules))
	for i := range rules {
		in[i] = toPolicyRule(&rules[i])
	}
	ps.ReplaceAll(in)
	return ps
}

// enforced is the enforcement path's decision: the deciding rule's name, "" = default.
func enforced(ps *PolicyStore, q *policyref.Request) string {
	m := ps.Evaluate(q.ClientIP, q.Identity, q.AuthSource, q.Host, q.Groups)
	if m == nil || m.Rule == nil {
		return ""
	}
	return m.Rule.Name
}

// tester is the Policy Tester path: the same core over List() clones, with a trace.
func tester(ps *PolicyStore, q *policyref.Request) string {
	list := ps.List()
	ptrs := make([]*PolicyRule, len(list))
	for i := range list {
		ptrs[i] = &list[i]
	}
	in := accessEvalInput{clientIP: q.ClientIP, identity: q.Identity, authSource: q.AuthSource, host: q.Host,
		normHost: normalizeHost(q.Host), groups: q.Groups}
	r := evalAccessRules(ptrs, nil, &in, time.Now, func(*PolicyRule, string) {})
	if r == nil {
		return ""
	}
	return r.Name
}

// ───────────────────────── comparison bookkeeping

type prefStats struct {
	mu         sync.Mutex
	Compared   int            `json:"compared"`
	Agreed     int            `json:"agreed"`
	RuleWins   int            `json:"decided_by_a_rule"`
	DefaultWin int            `json:"decided_by_default"`
	Mismatches int            `json:"mismatches"`
	Open       map[string]int `json:"unspecified_by_clause"`
	OpenSample []string       `json:"open_questions"`
	Repros     []string       `json:"minimal_counterexamples"`
}

func newPrefStats() *prefStats { return &prefStats{Open: map[string]int{}} }

func clauseOf(why string) string { c, _, _ := strings.Cut(why, ":"); return c }

func describe(rules []policyref.Rule, q *policyref.Request) string {
	b, _ := json.Marshal(struct {
		Rules   []policyref.Rule
		Request *policyref.Request
	}{rules, q})
	return string(b)
}

// minimise removes rules one at a time while the reference and the given path still disagree.
func minimise(rules []policyref.Rule, q *policyref.Request, path func(*PolicyStore, *policyref.Request) string) []policyref.Rule {
	disagree := func(rs []policyref.Rule) bool {
		ref := policyref.Evaluate(rs, prefEnv, *q)
		return ref.Specified && path(publish(rs), q) != ref.Rule
	}
	cur := append([]policyref.Rule(nil), rules...)
	for changed := true; changed; {
		changed = false
		for i := range cur {
			next := append(append([]policyref.Rule(nil), cur[:i]...), cur[i+1:]...)
			if disagree(next) {
				cur, changed = next, true
				break
			}
		}
	}
	return cur
}

// compare checks one (rule set, request) on both production paths.
func (st *prefStats) compare(t *testing.T, rules []policyref.Rule, ps *PolicyStore, q *policyref.Request) {
	t.Helper()
	ref := policyref.Evaluate(rules, prefEnv, *q)
	paths := []struct {
		name string
		f    func(*PolicyStore, *policyref.Request) string
	}{{"enforcement", enforced}, {"tester", tester}}
	for _, p := range paths {
		got := p.f(ps, q)
		st.mu.Lock()
		st.Compared++
		switch {
		case !ref.Specified:
			key := clauseOf(ref.Why)
			st.Open[key]++
			if st.Open[key] <= 3 && p.name == "enforcement" {
				st.OpenSample = append(st.OpenSample, fmt.Sprintf("%s -> product decided %q | %s", ref.Why, got, describe(rules, q)))
			}
		case got == ref.Rule:
			st.Agreed++
			if got == "" {
				st.DefaultWin++
			} else {
				st.RuleWins++
			}
		default:
			st.Mismatches++
			if len(st.Repros) < 10 {
				reduced := minimise(rules, q, p.f)
				repro := fmt.Sprintf("%s path: product %q, model %q | %s", p.name, got, ref.Rule, describe(reduced, q))
				st.Repros = append(st.Repros, repro)
				t.Errorf("MODEL/IMPLEMENTATION MISMATCH (minimised)\n %s", repro)
			}
		}
		st.mu.Unlock()
	}
}

func (st *prefStats) report(t *testing.T, name string) {
	t.Helper()
	t.Logf("%s: compared=%d agreed=%d rule=%d default=%d mismatches=%d unspecified=%v",
		name, st.Compared, st.Agreed, st.RuleWins, st.DefaultWin, st.Mismatches, st.Open)
	if st.Compared == 0 || st.RuleWins == 0 || st.DefaultWin == 0 {
		t.Errorf("VACUOUS: %s compared %d vectors (rule-decided %d, default-decided %d); refusing to pass",
			name, st.Compared, st.RuleWins, st.DefaultWin)
	}
	dir := os.Getenv("CULVERT_POLICY_CONFORMANCE_REPORT")
	if dir == "" {
		return
	}
	sort.Strings(st.OpenSample)
	b, err := json.MarshalIndent(st, "", " ")
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, "policy_"+name+".json"), b, 0o600) //nolint:gosec // G703: test-only report dir from the driver's environment; name is a literal
	}
	if err != nil {
		t.Errorf("report %s not written: %v", name, err)
	}
}

// ───────────────────────── suites

// Every condition value as the ONLY condition of a single rule, against every request:
// the boundary grid. Each dimension must produce both matches and non-matches.
func TestPolicyReference_SingleConditionGrid(t *testing.T) {
	installPrefEnv(t)
	st := newPrefStats()
	reqs := prefRequests()
	dims := []struct {
		name string
		vals []string
		set  func(r *policyref.Rule, v string)
	}{
		{"fqdn", poolFQDN, func(r *policyref.Rule, v string) { r.DestFQDN = v }},
		{"source_ip", poolSourceIP, func(r *policyref.Rule, v string) { r.SourceIP = v }},
		{"identity", poolIdentity, func(r *policyref.Rule, v string) { r.SourceIdentity = v }},
		{"group", poolGroup, func(r *policyref.Rule, v string) { r.SourceGroup = v }},
		{"auth_source", poolAuthSource, func(r *policyref.Rule, v string) { r.AuthSource = v }},
		{"category", poolCategory, func(r *policyref.Rule, v string) { r.DestCategory = v }},
		{"category_group", poolGroupID, func(r *policyref.Rule, v string) { r.DestGroupID = v }},
	}
	for _, d := range dims {
		hit, miss := 0, 0
		for _, v := range d.vals {
			rules := []policyref.Rule{{Name: "only", Priority: 1, Action: string(ActionDrop)}}
			d.set(&rules[0], v)
			ps := publish(rules)
			for i := range reqs {
				st.compare(t, rules, ps, &reqs[i])
				if o := policyref.Evaluate(rules, prefEnv, reqs[i]); o.Specified && o.Rule != "" {
					hit++
				} else if o.Specified {
					miss++
				}
			}
		}
		if hit == 0 || miss == 0 {
			t.Errorf("VACUOUS dimension %s: %d matches, %d non-matches", d.name, hit, miss)
		}
	}
	// R4 directly: a valid catch-all auth rule ahead of an access rule never decides.
	rules := []policyref.Rule{{Name: "auth-all", Priority: 1, Type: ruleTypeAuth, Action: string(ActionAllow), DestFQDN: "*"},
		{Name: "access-drop", Priority: 2, Action: string(ActionDrop), DestFQDN: "example.com"}}
	ps := publish(rules)
	if publishedAuthRules(ps) != 1 {
		t.Fatalf("VACUOUS R4: the auth rule was not published (%d)", publishedAuthRules(ps))
	}
	for i := range reqs {
		st.compare(t, rules, ps, &reqs[i])
	}
	st.report(t, "single_condition_grid")
}

// Seeded multi-rule rule sets: precedence, first match, disabled and auth rules, ANDed
// conditions, ties (unspecified; reported).
func TestPolicyReference_RandomRuleSets(t *testing.T) {
	installPrefEnv(t)
	st := newPrefStats()
	rng := rand.New(rand.NewPCG(20261123, 2006)) //nolint:gosec // deterministic test vectors, not security
	pick := func(xs []string) string {
		if rng.IntN(3) > 0 { // two thirds of conditions stay "any"
			return ""
		}
		return xs[rng.IntN(len(xs))]
	}
	actions := []string{string(ActionAllow), string(ActionDrop), string(ActionBlockPage)}
	const sets, perSet = 4000, 12
	authPublished := 0
	for s := 0; s < sets; s++ {
		n := 1 + rng.IntN(6)
		rules := make([]policyref.Rule, n)
		for i := range rules {
			r := &rules[i]
			r.Name = fmt.Sprintf("r%d", i)
			r.Priority = 1 + rng.IntN(8) // ties happen on purpose
			r.Action = actions[rng.IntN(len(actions))]
			switch rng.IntN(10) {
			case 0:
				r.Enabled = offPtr()
			case 1:
				r.Enabled = onPtr()
			}
			if rng.IntN(15) == 0 {
				r.Type = ruleTypeAuth
			}
			r.DestFQDN, r.SourceIP, r.SourceIdentity = pick(poolFQDN), pick(poolSourceIP), pick(poolIdentity)
			r.SourceGroup, r.AuthSource, r.DestCategory, r.DestGroupID = pick(poolGroup), pick(poolAuthSource),
				pick(poolCategory), pick(poolGroupID)
		}
		ps := publish(rules)
		authPublished += publishedAuthRules(ps)
		for k := 0; k < perSet; k++ {
			q := policyref.Request{Host: reqHosts[rng.IntN(len(reqHosts))], ClientIP: reqClients[rng.IntN(len(reqClients))],
				Identity: reqIdentities[rng.IntN(len(reqIdentities))], Groups: reqGroups[rng.IntN(len(reqGroups))],
				AuthSource: reqAuth[rng.IntN(len(reqAuth))]}
			st.compare(t, rules, ps, &q)
		}
	}
	if authPublished == 0 {
		t.Error("VACUOUS R4: no auth rule survived publication, so the stage filter was never exercised")
	}
	t.Logf("auth rules published and scanned past: %d", authPublished)
	st.report(t, "random_rule_sets")
}

// Publication: after every writer operation the published decision equals the model on
// the rule list the operation should produce.
func TestPolicyReference_PublicationSequence(t *testing.T) {
	installPrefEnv(t)
	st := newPrefStats()
	reqs := prefRequests()
	rules := []policyref.Rule{
		{Name: "drop-news", Priority: 10, Action: string(ActionDrop), DestGroupID: "grpref000001"},
		{Name: "allow-eng", Priority: 20, Action: string(ActionAllow), SourceGroup: "eng"},
		{Name: "drop-example", Priority: 30, Action: string(ActionDrop), DestFQDN: "example.com"},
	}
	ps := publish(rules)
	check := func(step string) {
		for i := range reqs {
			st.compare(t, rules, ps, &reqs[i])
		}
		if t.Failed() {
			t.Fatalf("diverged after %s", step)
		}
	}
	check("ReplaceAll")
	idOf := func(name string) string {
		for _, r := range ps.List() {
			if r.Name == name {
				return r.ID
			}
		}
		t.Fatalf("rule %s not published", name)
		return ""
	}
	// Disable via edit (priority kept by the edit itself).
	edited := rules[1]
	edited.Enabled = offPtr()
	if !ps.UpdateByID(idOf("allow-eng"), toPolicyRule(&edited)) {
		t.Fatal("UpdateByID refused")
	}
	rules[1] = edited
	check("UpdateByID disable")
	if !ps.DeleteByID(idOf("drop-news")) {
		t.Fatal("DeleteByID refused")
	}
	rules = rules[1:]
	check("DeleteByID") // Delete publishes without re-sorting: the slow snapshot path must agree
	rules = []policyref.Rule{{Name: "allow-all", Priority: 1, Action: string(ActionAllow), DestFQDN: "*"}}
	ps.ReplaceAll([]PolicyRule{toPolicyRule(&rules[0])})
	check("ReplaceAll again")
	rules = nil
	ps.ReplaceAll(nil)
	check("ReplaceAll empty")
	st.report(t, "publication_sequence")
}

// Snapshot atomicity: while a writer alternates two published revisions, every decision a
// reader sees is the model's decision for one revision or the other -- never a mix.
func TestPolicyReference_SnapshotAtomicity(t *testing.T) {
	installPrefEnv(t)
	revA := []policyref.Rule{
		{Name: "a-drop-example", Priority: 1, Action: string(ActionDrop), DestFQDN: "example.com"},
		{Name: "a-allow", Priority: 2, Action: string(ActionAllow)},
	}
	revB := []policyref.Rule{
		{Name: "b-allow-example", Priority: 1, Action: string(ActionAllow), DestFQDN: "*.example.com"},
		{Name: "b-drop-news", Priority: 2, Action: string(ActionDrop), DestCategory: "News"},
	}
	toPR := func(rs []policyref.Rule) []PolicyRule {
		out := make([]PolicyRule, len(rs))
		for i := range rs {
			out[i] = toPolicyRule(&rs[i])
		}
		return out
	}
	reqs := prefRequests()
	allowed := make([]map[string]bool, len(reqs))
	distinct := 0
	for i := range reqs {
		a, b := policyref.Evaluate(revA, prefEnv, reqs[i]), policyref.Evaluate(revB, prefEnv, reqs[i])
		if !a.Specified || !b.Specified {
			t.Fatalf("revisions must be fully specified: %+v %+v", a, b)
		}
		allowed[i] = map[string]bool{a.Rule: true, b.Rule: true}
		if a.Rule != b.Rule {
			distinct++
		}
	}
	if distinct == 0 {
		t.Fatal("VACUOUS: the two revisions decide every request the same way")
	}
	ps := &PolicyStore{}
	ps.ReplaceAll(toPR(revA))
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			if i%2 == 0 {
				ps.ReplaceAll(toPR(revB))
			} else {
				ps.ReplaceAll(toPR(revA))
			}
		}
	}()
	var bad atomic.Int64
	var readers sync.WaitGroup
	for g := 0; g < 4; g++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for n := 0; n < 3000; n++ {
				i := n % len(reqs)
				if got := enforced(ps, &reqs[i]); !allowed[i][got] {
					if bad.Add(1) <= 3 {
						t.Errorf("torn snapshot: request %+v decided %q, model allows only %v", reqs[i], got, allowed[i])
					}
				}
			}
		}()
	}
	readers.Wait()
	stop.Store(true)
	wg.Wait()
	t.Logf("snapshot atomicity: 12000 concurrent decisions, %d requests distinguish the revisions, %d torn", distinct, bad.Load())
}

// Startup default action, including the fail-open -> fail-closed transition when the
// first rule is configured (R15). Unspecified spellings are reported, not asserted.
func TestPolicyReference_StartupDefault(t *testing.T) {
	orig := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(orig) })
	for _, explicit := range []string{"", "allow", "deny", "Allow", "DENY", "block", " allow"} {
		for _, n := range []int{0, 1, 5} {
			loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{DefaultAction: explicit}, n)
			got := defaultPolicyAction()
			want, specified := policyref.StartupDefault(explicit, n)
			switch {
			case !specified:
				t.Logf("OPEN QUESTION R15: default_action %q with %d rule(s) -> product %q", explicit, n, got)
			case got != want:
				t.Errorf("MODEL/IMPLEMENTATION MISMATCH R15: default_action %q with %d rule(s): product %q, model %q", explicit, n, got, want)
			}
		}
	}
}
