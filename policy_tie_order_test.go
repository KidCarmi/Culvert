package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// pdqsortInsertionMax is the length up to which sort.Slice runs a plain
// strict-less insertion sort (sort/zsortfunc.go, pdqsort_func: length <= 12),
// so for these lengths the previous order was already stable.
const pdqsortInsertionMax = 12

// legacyPolicySortOrder is the previous publication order (sort.Slice with a
// priority-only comparator): the differential oracle for stored-order
// precedence. Test-only; production never computes it.
func legacyPolicySortOrder(input []*PolicyRule) []*PolicyRule {
	out := slices.Clone(input)
	sort.Slice(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// policy_tie_order_test.go — POL-001 (amended: equal priorities evaluate in
// stored order) and the publication-side evidence for it.

// tieRules builds n rules with the given priorities, named r0..r(n-1) in input
// order, as the pointer slice sortLocked orders.
func tieRules(pris []int) []*PolicyRule {
	out := make([]*PolicyRule, len(pris))
	for i, p := range pris {
		out[i] = &PolicyRule{Priority: p, Name: fmt.Sprintf("r%d", i)}
	}
	return out
}

func storedOrderSorted(in []*PolicyRule) []*PolicyRule {
	out := slices.Clone(in)
	orderPolicyRulesForPublication(out)
	return out
}

// isStoredOrder reports whether out is in from's priority order with every tie
// in from's relative order — the contract, checked without a sort.
func isStoredOrder(from, out []*PolicyRule) bool {
	pos := make(map[*PolicyRule]int, len(from))
	for i, r := range from {
		pos[r] = i
	}
	for i := 1; i < len(out); i++ {
		a, b := out[i-1], out[i]
		if a.Priority > b.Priority || (a.Priority == b.Priority && pos[a] > pos[b]) {
			return false
		}
	}
	return len(out) == len(from)
}

// TestPolicyTieOrder_StableSortMatchesLegacyWhereItMustAgree is the
// differential proof that stable stored-order precedence is byte-for-byte the
// previous sort.Slice publication order for every already-sorted input (any n)
// and for every input of n <= 12, and that the two differ ONLY for unsorted
// inputs with ties at n >= 13 (where the new result is the stored order).
func TestPolicyTieOrder_StableSortMatchesLegacyWhereItMustAgree(t *testing.T) {
	rng := rand.New(rand.NewSource(0x71E5)) //nolint:gosec // deterministic test corpus, not crypto
	sortedTrials := diffSortedInputs(t, rng)
	smallTrials := diffSmallInputs(t, rng)
	diffTieFreeInputs(t, rng)
	differ, total := diffUnsortedTiedInputs(t, rng)
	if differ == 0 {
		t.Fatal("expected the legacy pdqsort order to permute ties for some unsorted n >= 13 input; the differential found none")
	}
	t.Logf("sorted trials identical: %d; n<=12 arbitrary trials identical: %d; unsorted tied n>=13 differing: %d/%d",
		sortedTrials, smallTrials, differ, total)
}

// randomPriorities draws n priorities from 1..spread (many ties for a small
// spread).
func randomPriorities(rng *rand.Rand, n, spread int) []int {
	pris := make([]int, n)
	for i := range pris {
		pris[i] = 1 + rng.Intn(spread)
	}
	return pris
}

// diffSortedInputs: already sorted, with ties, many sizes and tie densities —
// both orders are the identity.
func diffSortedInputs(t *testing.T, rng *rand.Rand) int {
	t.Helper()
	sizes := []int{}
	for n := 0; n <= 300; n++ {
		sizes = append(sizes, n)
	}
	sizes = append(sizes, 511, 1000, 1024, 4096, 10000)
	trials := 0
	for _, n := range sizes {
		for _, spread := range []int{1, 2, 3, 7, n/2 + 1, n + 1} {
			pris := randomPriorities(rng, n, spread)
			slices.Sort(pris)
			in := tieRules(pris)
			got, legacy := storedOrderSorted(in), legacyPolicySortOrder(in)
			if !slices.Equal(got, in) || !slices.Equal(legacy, in) {
				t.Fatalf("sorted input n=%d spread=%d: stable identity=%v legacy identity=%v",
					n, spread, slices.Equal(got, in), slices.Equal(legacy, in))
			}
			trials++
		}
	}
	return trials
}

// diffSmallInputs: arbitrary (unsorted, tie-heavy) inputs with n <= 12 — the
// legacy insertion sort was already stable, so the orders are identical.
func diffSmallInputs(t *testing.T, rng *rand.Rand) int {
	t.Helper()
	trials := 0
	for n := 0; n <= pdqsortInsertionMax; n++ {
		for trial := 0; trial < 20000; trial++ {
			pris := randomPriorities(rng, n, 1+n/3)
			in := tieRules(pris)
			got, legacy := storedOrderSorted(in), legacyPolicySortOrder(in)
			if !slices.Equal(got, legacy) || !isStoredOrder(in, got) {
				t.Fatalf("n=%d priorities=%v: stable %v legacy %v", n, pris, names(got), names(legacy))
			}
			trials++
		}
	}
	return trials
}

// diffTieFreeInputs: unsorted inputs WITHOUT ties have a unique order, so the
// two agree at every n.
func diffTieFreeInputs(t *testing.T, rng *rand.Rand) {
	t.Helper()
	for _, n := range []int{13, 50, 51, 1000} {
		for trial := 0; trial < 200; trial++ {
			in := tieRules(rng.Perm(n))
			if !slices.Equal(storedOrderSorted(in), legacyPolicySortOrder(in)) {
				t.Fatalf("tie-free unsorted n=%d disagrees", n)
			}
		}
	}
}

// diffUnsortedTiedInputs: unsorted inputs WITH ties at n >= 13, the only region
// where the orders may differ. The new order is always the stored order; it
// returns how often the legacy order was something else.
func diffUnsortedTiedInputs(t *testing.T, rng *rand.Rand) (differ, total int) {
	t.Helper()
	for _, n := range []int{13, 14, 20, 50, 51, 100, 1000} {
		d := 0
		for trial := 0; trial < 300; trial++ {
			in := tieRules(randomPriorities(rng, n, 1+n/3))
			got := storedOrderSorted(in)
			if !isStoredOrder(in, got) {
				t.Fatalf("n=%d: stable result is not the stored order", n)
			}
			if !slices.Equal(got, legacyPolicySortOrder(in)) {
				d++
			}
		}
		differ += d
		total += 300
		t.Logf("unsorted tied n=%d: legacy order differs from stored order in %d/300", n, d)
	}
	return differ, total
}

func names(rs []*PolicyRule) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}

// tieTableRules is the m-rule rulebase the writer table starts from: a movable
// singleton "mover-b" at the front, m-2 middle rules (pairs tied at 100g+50,
// each followed by a singleton at 100g+70) and a movable singleton "mover-a"
// at the end. m < 2 yields m middle rules only.
func tieTableRules(m int) []PolicyRule {
	middle := func(i int) PolicyRule {
		p := 100*(i/3) + 50
		if i%3 == 2 {
			p = 100*(i/3) + 70
		}
		return PolicyRule{Priority: p, Name: fmt.Sprintf("t%d", i), Action: ActionAllow}
	}
	if m < 2 {
		rules := make([]PolicyRule, m)
		for i := range rules {
			rules[i] = middle(i)
		}
		return rules
	}
	rules := make([]PolicyRule, 0, m)
	rules = append(rules, PolicyRule{Priority: 5, Name: "mover-b", Action: ActionAllow})
	for i := 0; i < m-2; i++ {
		rules = append(rules, middle(i))
	}
	rules = append(rules, PolicyRule{Priority: 100*m + 90, Name: "mover-a", Action: ActionAllow})
	return rules
}

// tieGroupsByName maps every shared priority to its rule names in order.
func tieGroupsByName(rules []PolicyRule) map[int][]string {
	out := map[int][]string{}
	for _, tie := range policyPriorityTies(rules) {
		out[tie.Priority] = tie.Names
	}
	return out
}

func rulePtrs(rules []PolicyRule) []*PolicyRule {
	out := make([]*PolicyRule, len(rules))
	for i := range rules {
		out[i] = &rules[i]
	}
	return out
}

func priorityOf(rules []PolicyRule, name string) int {
	for i := range rules {
		if rules[i].Name == name {
			return rules[i].Priority
		}
	}
	return -1
}

// tieWriterOp is one writer of the table: apply mutates ps and returns the
// publication input the previous release's sortLocked would have sorted for
// the same operation (same sequence, same comparator).
type tieWriterOp struct {
	name  string
	grows int // rules the operation adds
	apply func(t *testing.T, ps *PolicyStore, before []PolicyRule) []*PolicyRule
}

// withPriorities returns a copy of rules with the named rules' priorities set.
func withPriorities(rules []PolicyRule, set map[string]int) []*PolicyRule {
	in := slices.Clone(rules)
	for i := range in {
		if p, ok := set[in[i].Name]; ok {
			in[i].Priority = p
		}
	}
	return rulePtrs(in)
}

func tieWriterOps() []tieWriterOp {
	return []tieWriterOp{
		{"gap add", 1, func(t *testing.T, ps *PolicyStore, before []PolicyRule) []*PolicyRule {
			added := ps.Add(PolicyRule{Priority: 1, Name: "added", Action: ActionDrop})
			if added.Priority != 1 {
				t.Fatalf("gap add landed at %d", added.Priority)
			}
			return rulePtrs(append(slices.Clone(before), added))
		}},
		{"priority update", 0, func(t *testing.T, ps *PolicyStore, before []PolicyRule) []*PolicyRule {
			if !ps.Update(priorityOf(before, "mover-a"), PolicyRule{Priority: 2, Name: "mover-a", Action: ActionDrop}) {
				t.Fatal("update failed")
			}
			return withPriorities(before, map[string]int{"mover-a": 2})
		}},
		{"move", 0, func(t *testing.T, ps *PolicyStore, before []PolicyRule) []*PolicyRule {
			a, b := priorityOf(before, "mover-a"), priorityOf(before, "mover-b")
			if !ps.PermutePriorities([]int{a, b}) { // mover-a takes the lower slot
				t.Fatal("permute failed")
			}
			return withPriorities(before, map[string]int{"mover-a": b, "mover-b": a})
		}},
	}
}

// firstTieOrderMismatch returns the first shared priority whose names in got
// differ from want, or false.
func firstTieOrderMismatch(got []PolicyRule, want map[int][]string) (priority int, names []string, found bool) {
	for p, group := range tieGroupsByName(got) {
		if !slices.Equal(group, want[p]) {
			return p, group, true
		}
	}
	return 0, nil, false
}

// runTieWriterCase applies one writer at publication size n, checks that the
// untouched ties kept their stored order, and reports whether the previous
// release would have permuted one of them for the same input.
func runTieWriterCase(t *testing.T, n int, o tieWriterOp) (legacyPermuted bool) {
	t.Helper()
	ps := &PolicyStore{}
	ps.ReplaceAll(tieTableRules(n - o.grows))
	before := ps.List()
	want := tieGroupsByName(before)
	if n-o.grows >= 4 && len(want) == 0 {
		t.Fatal("fixture has no tie")
	}
	legacyIn := o.apply(t, ps, before)
	if len(legacyIn) != n {
		t.Fatalf("publication input has %d rules, want %d", len(legacyIn), n)
	}
	after := ps.List()
	if !slices.IsSortedFunc(rulePtrs(after), policyRulePriorityCmp) {
		t.Fatal("published rules are not priority-sorted")
	}
	if p, names, bad := firstTieOrderMismatch(after, want); bad {
		t.Errorf("priority %d: tie order %v, want stored order %v", p, names, want[p])
	}
	legacy := legacyPolicySortOrder(legacyIn)
	prev := make([]PolicyRule, len(legacy))
	for i, r := range legacy {
		prev[i] = *r
	}
	p, names, bad := firstTieOrderMismatch(prev, want)
	if bad {
		t.Logf("previous release would have reordered priority %d to %v (stored %v)", p, names, want[p])
	}
	return bad
}

// TestPolicyTieOrder_UntouchedTiesKeepOrderAcrossWriters is the writer table:
// after a gap Add, a priority Update or a move, rules that share a priority and
// were not touched keep their relative (stored) order. For each case it also
// replays the SAME publication input through the previous sort.Slice order
// and records whether that would have permuted the untouched ties, which it
// does at n = 13, the first size past pdqsort's insertion-sort regime.
//
// n is the length of the publication input (what sortLocked orders): the
// rulebase holds n rules before an Update or move and n-1 before a gap Add.
func TestPolicyTieOrder_UntouchedTiesKeepOrderAcrossWriters(t *testing.T) {
	legacyPermuted := map[int]bool{}
	var permutedCases []string
	for _, n := range []int{2, 12, 13, 50, 51, 1000} {
		for _, o := range tieWriterOps() {
			t.Run(fmt.Sprintf("n=%d/%s", n, o.name), func(t *testing.T) {
				if runTieWriterCase(t, n, o) {
					legacyPermuted[n] = true
					permutedCases = append(permutedCases, fmt.Sprintf("n=%d/%s", n, o.name))
				}
			})
		}
	}
	t.Logf("cases the previous release would have reordered: %v", permutedCases)
	if !legacyPermuted[13] {
		t.Error("the previous sort.Slice order did not permute any untouched tie at n=13; the table no longer demonstrates the fixed failure")
	}
	for _, n := range []int{2, 12} {
		if legacyPermuted[n] {
			t.Errorf("legacy order permuted a tie at n=%d, inside pdqsort's stable insertion-sort regime", n)
		}
	}
}

// writeRuleFile writes rules to a policy file in the given order.
func writeRuleFile(t *testing.T, rules []PolicyRule) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// unsortedTiedFile returns n rules in a deterministic unsorted, tie-heavy
// order (seeded shuffle), with unique names.
func unsortedTiedFile(n int, seed int64) []PolicyRule {
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test corpus, not crypto
	rules := make([]PolicyRule, n)
	for i := range rules {
		rules[i] = PolicyRule{Priority: 10 * (1 + rng.Intn(1+n/4)), Name: fmt.Sprintf("f%d", i), Action: ActionAllow}
	}
	return rules
}

// loadTieCase loads one unsorted tied file and checks that every tie keeps
// the file's order, and that loading logs no tie-order notice (there is no
// upgrade comparison). It returns whether the previous sort would have
// reordered the file, so the corpus can prove it covers that region.
func loadTieCase(t *testing.T, n int, seed int64) (legacyWouldDiffer bool) {
	t.Helper()
	file := unsortedTiedFile(n, seed)
	ptrs := rulePtrs(slices.Clone(file)) // one pointer set, so the two orders are comparable
	legacyWouldDiffer = !slices.Equal(storedOrderSorted(slices.Clone(ptrs)), legacyPolicySortOrder(ptrs))
	ps := &PolicyStore{}
	out := captureLogger(t, func() {
		if err := ps.Load(writeRuleFile(t, file)); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})
	if p, names, bad := firstTieOrderMismatch(ps.List(), tieGroupsByName(file)); bad {
		t.Errorf("priority %d: loaded order %v, file order %v", p, names, tieGroupsByName(file)[p])
	}
	if strings.Contains(out, "evaluation order now follows stored order") {
		t.Errorf("load logged an upgrade tie-order notice; none should exist:\n%s", out)
	}
	return legacyWouldDiffer
}

// TestPolicyTieOrder_LoadUnsortedTiedFileKeepsStoredOrder: loading a
// hand-edited, unsorted file with ties publishes the file's order for every
// tie — including the files the previous unstable sort would have reordered.
func TestPolicyTieOrder_LoadUnsortedTiedFileKeepsStoredOrder(t *testing.T) {
	differ, same := 0, 0
	for _, tc := range []struct {
		n    int
		seed int64
	}{{12, 1}, {12, 2}, {13, 3}, {13, 4}, {20, 5}, {20, 6}, {64, 7}, {64, 8}, {300, 9}} {
		t.Run(fmt.Sprintf("n=%d/seed=%d", tc.n, tc.seed), func(t *testing.T) {
			if loadTieCase(t, tc.n, tc.seed) {
				differ++
			} else {
				same++
			}
		})
	}
	if differ == 0 || same == 0 {
		t.Fatalf("corpus must cover inputs the previous sort reordered and inputs it did not (differ=%d same=%d)", differ, same)
	}
}

// TestPolicyTieOrder_ReplaceAllAndSnapshotKeepTieOrder: a CP→DP snapshot (JSON
// round trip into ReplaceAll, the DP apply path) and a config-version rollback
// (ReplaceAll of a List()-derived snapshot) keep every tie in stored order and
// never renumber.
func TestPolicyTieOrder_ReplaceAllAndSnapshotKeepTieOrder(t *testing.T) {
	src := unsortedTiedFile(200, 42)
	cp := &PolicyStore{}
	cp.ReplaceAll(src)
	cpRules := cp.List()

	data, err := json.Marshal(ConfigSnapshot{PolicyRules: cpRules})
	if err != nil {
		t.Fatal(err)
	}
	var snap ConfigSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	dp := &PolicyStore{}
	dp.ReplaceAll(snap.PolicyRules)
	dpRules := dp.List()
	if len(dpRules) != len(cpRules) {
		t.Fatalf("DP has %d rules, CP %d", len(dpRules), len(cpRules))
	}
	for i := range cpRules {
		if dpRules[i].Name != cpRules[i].Name || dpRules[i].Priority != cpRules[i].Priority {
			t.Fatalf("index %d: DP %q@%d, CP %q@%d", i, dpRules[i].Name, dpRules[i].Priority, cpRules[i].Name, cpRules[i].Priority)
		}
	}
	for p, names := range tieGroupsByName(cpRules) {
		if want := tieGroupsByName(src)[p]; !slices.Equal(names, want) {
			t.Errorf("priority %d: %v, stored %v", p, names, want)
		}
	}
	if len(policyPriorityTies(dpRules)) == 0 {
		t.Fatal("fixture must carry ties (a faithful restore keeps them)")
	}
	// Rollback: restoring the List()-derived snapshot is the identity.
	dp.ReplaceAll(cpRules)
	for i, r := range dp.List() {
		if r.Name != cpRules[i].Name || r.Priority != cpRules[i].Priority {
			t.Fatalf("rollback index %d changed: %q@%d", i, r.Name, r.Priority)
		}
	}
}

// TestPolicyTieOrder_EvaluateUnchangedForSortedInputs: Evaluate over a host
// corpus gives the same decision (rule and action) as a store published in
// the previous release's order, for sorted tied rulebases of several sizes and
// for unsorted ones with n <= 12.
func TestPolicyTieOrder_EvaluateUnchangedForSortedInputs(t *testing.T) {
	rng := rand.New(rand.NewSource(0xE7A1)) //nolint:gosec // deterministic test corpus, not crypto
	hosts := []string{"example.com", "a.example.com", "b.example.com", "x.a.example.com", "other.test", "c.other.test", "nomatch.invalid"}
	patterns := []string{"", "example.com", "*.example.com", "a.example.com", "*.other.test", "other.test"}
	actions := []PolicyAction{ActionAllow, ActionDrop, ActionBlockPage}
	build := func(n int, sorted bool) []PolicyRule {
		rules := make([]PolicyRule, n)
		for i := range rules {
			rules[i] = PolicyRule{
				Priority: 1 + rng.Intn(1+n/4),
				Name:     fmt.Sprintf("e%d", i),
				DestFQDN: patterns[rng.Intn(len(patterns))],
				Action:   actions[rng.Intn(len(actions))],
			}
		}
		if sorted {
			slices.SortStableFunc(rules, func(a, b PolicyRule) int { return a.Priority - b.Priority })
		}
		return rules
	}
	decisions := 0
	check := func(rules []PolicyRule) {
		legacyOrder := legacyPolicySortOrder(rulePtrs(slices.Clone(rules)))
		legacyRules := make([]PolicyRule, len(legacyOrder))
		for i, r := range legacyOrder {
			legacyRules[i] = *r
		}
		now, was := &PolicyStore{}, &PolicyStore{}
		now.ReplaceAll(rules)
		was.ReplaceAll(legacyRules) // already sorted: published as given
		for _, h := range hosts {
			a := now.Evaluate("10.0.0.1", "", "unauth", h, nil)
			b := was.Evaluate("10.0.0.1", "", "unauth", h, nil)
			if (a == nil) != (b == nil) || (a != nil && (a.Rule.Name != b.Rule.Name || a.Action != b.Action)) {
				t.Fatalf("n=%d host %q: decision differs (now %+v, previous %+v)", len(rules), h, a, b)
			}
			decisions++
		}
	}
	for _, n := range []int{2, 12, 13, 50, 51, 200, 1000} {
		for trial := 0; trial < 5; trial++ {
			check(build(n, true))
		}
	}
	for n := 2; n <= pdqsortInsertionMax; n++ {
		for trial := 0; trial < 50; trial++ {
			check(build(n, false))
		}
	}
	t.Logf("%d identical decisions", decisions)
}

func TestPolicyTieOrder_GaugeAndDiagnosticsRow(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "solo", Action: ActionAllow},
		{Priority: 5, Name: "a", Action: ActionAllow},
		{Priority: 5, Name: "b", Action: ActionDrop},
		{Priority: 9, Name: "c", Action: ActionAllow},
		{Priority: 9, Name: "d", Action: ActionAllow},
		{Priority: 9, Name: "e", Action: ActionAllow},
	})
	var sb strings.Builder
	policyPriorityTiesWritePrometheus(&sb)
	if !strings.Contains(sb.String(), "# TYPE culvert_policy_priority_ties gauge\nculvert_policy_priority_ties 5\n") {
		t.Errorf("gauge:\n%s", sb.String())
	}
	row := checkPolicyPriorityTies()
	if row.Code != "policy_priority_ties" || row.Status != diagWarn || row.OperatorAction == "" ||
		!strings.Contains(row.Message, `priority 5: "a", "b"`) || !strings.Contains(row.Message, `priority 9: "c", "d", "e"`) {
		t.Errorf("row: %+v", row)
	}
	found := false
	for _, c := range buildOperatorContract().Checks {
		found = found || c.Code == "policy_priority_ties"
	}
	if !found {
		t.Error("policy_priority_ties missing from /api/diagnostics contract")
	}
	policyStore.Delete(9)
	policyStore.Delete(9)
	policyStore.Delete(5)
	sb.Reset()
	policyPriorityTiesWritePrometheus(&sb)
	if !strings.Contains(sb.String(), "culvert_policy_priority_ties 0\n") {
		t.Errorf("gauge after removing ties:\n%s", sb.String())
	}
	if row := checkPolicyPriorityTies(); row.Status != diagOK {
		t.Errorf("row after removing ties: %+v", row)
	}
}
