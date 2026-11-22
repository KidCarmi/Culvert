//go:build lifecycle_conformance

package lifecyclemodel

import (
	"errors"
	"io"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	budgetStates = 200_000
	budgetTime   = time.Minute
)

func mustParse(t *testing.T, raw string) []Property {
	t.Helper()
	props, _, err := ParseProperties([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return props
}

func checkOne(t *testing.T, raw string) Result {
	t.Helper()
	res, _, err := Check[State](Model{}, mustParse(t, raw), budgetStates, budgetTime)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want one result, got %d", len(res))
	}
	return res[0]
}

// A property whose precondition is unreachable must be VACUOUS, never PASS.
func TestCheck_VacuousPropertyIsNotAPass(t *testing.T) {
	for name, raw := range map[string]string{
		"state":      `[{"id":"V","status":"approved","kind":"state","if":[["pc","==","nowhere"]],"then":[["tag","==","T"]]}]`,
		"transition": `[{"id":"V","status":"approved","kind":"transition","on":["no_such_event"],"then":[["tag","==","T"]]}]`,
		"bounded": `[{"id":"V","status":"approved","kind":"bounded","trigger":[["pc","==","nowhere"]],
			"goal":[["stopped","==",true]],"within":3,"quantifier":"all"}]`,
	} {
		if r := checkOne(t, raw); r.Verdict != VerdictVacuous {
			t.Errorf("%s: verdict %s, want VACUOUS", name, r.Verdict)
		}
	}
}

// Hitting the state or time budget is an explicit Incomplete result with no verdicts.
func TestCheck_BudgetExhaustedIsIncomplete(t *testing.T) {
	props := mustParse(t, `[{"id":"P","status":"approved","kind":"state","if":[["terminal","==",true]],"then":[["jr","==","removed"]]}]`)
	res, _, err := Check[State](Model{}, props, 100, budgetTime)
	if !errors.Is(err, ErrIncomplete) || res != nil {
		t.Fatalf("tiny state budget: results=%v err=%v, want no results and ErrIncomplete", res, err)
	}
	res, _, err = Check[State](Model{}, props, budgetStates, -time.Second)
	if !errors.Is(err, ErrIncomplete) || res != nil {
		t.Fatalf("expired time budget: results=%v err=%v, want no results and ErrIncomplete", res, err)
	}
	opts := GateOptions{IncludeProposed: true, MaxStates: 100, MaxDuration: budgetTime}
	if code := RunGate(EmbeddedPropertiesJSON(), opts, io.Discard); code != ExitIncomplete {
		t.Fatalf("gate with a tiny state budget exits %d, want %d", code, ExitIncomplete)
	}
}

// chain is a toy system: 0 -a-> 1 -a-> 2 -a-> 3 and a shortcut 0 -b-> 3 listed AFTER
// the long way round, so a depth-first or last-wins search would report the long trace.
type chain struct{}

func (chain) Inits() []int { return []int{0} }
func (chain) Events(s int) []string {
	switch s {
	case 0:
		return []string{"a", "b"}
	case 1, 2:
		return []string{"a"}
	}
	return nil
}
func (chain) Step(s int, e string) int {
	if e == "b" {
		return 3
	}
	return s + 1
}
func (chain) Observe(s int) map[string]any { return map[string]any{"n": float64(s)} }

func TestCheck_FailureCarriesShortestTrace(t *testing.T) {
	props := mustParse(t, `[{"id":"F","status":"approved","kind":"state","then":[["n","<",3]]}]`)
	res, st, err := Check[int](chain{}, props, 10, budgetTime)
	if err != nil {
		t.Fatal(err)
	}
	if st != (Stats{States: 4, Transitions: 4}) {
		t.Errorf("stats %+v", st)
	}
	if r := res[0]; r.Verdict != VerdictFail || !reflect.DeepEqual(r.Trace, []string{"b"}) || r.State["n"] != float64(3) {
		t.Errorf("got %s trace=%v state=%v, want FAIL with the one-step trace [b] ending in n=3", r.Verdict, r.Trace, r.State)
	}

	// On the real model: no trace to a tag-ahead terminal state may be shorter than the
	// ten stages an operation needs to finish, and the reported one must replay.
	r := checkOne(t, `[{"id":"F","status":"approved","kind":"state","if":[["terminal","==",true]],"then":[["tag_ahead","==",false]]}]`)
	want := []string{"ok", "ok", "skip", "ok", "up_fail_stale", "skip", "skip", "skip", "skip", "ok"}
	if r.Verdict != VerdictFail || !reflect.DeepEqual(r.Trace, want) {
		t.Fatalf("got %s %v, want FAIL %v", r.Verdict, r.Trace, want)
	}
	if !replays(r.Trace, func(s State) bool { return s.PC == pcDone && tagAhead(s) }) {
		t.Errorf("reported trace %v does not reproduce the violation from any initial state", r.Trace)
	}
}

func replays(trace []string, violates func(State) bool) bool {
	m := Model{}
	inits := m.Inits()
	for i := range inits {
		s, ok := inits[i], true
		for _, e := range trace {
			if !contains(m.Events(s), e) {
				ok = false
				break
			}
			s = m.Step(s, e)
		}
		if ok && violates(s) {
			return true
		}
	}
	return false
}

func TestCheck_TransitionAndBoundedCounterexamples(t *testing.T) {
	r := checkOne(t, `[{"id":"T","status":"approved","kind":"transition","then":[["tag","==",{"prev":"tag"}]]}]`)
	if want := []string{"ok", "ok", "skip", "ok", "ok"}; r.Verdict != VerdictFail || !reflect.DeepEqual(r.Trace, want) || r.State["tag"] != "T" {
		t.Errorf("transition: %s %v tag=%v, want FAIL %v ending with tag=T", r.Verdict, r.Trace, r.State["tag"], want)
	}
	r = checkOne(t, `[{"id":"B","status":"approved","kind":"bounded","trigger":[["pc","==","capture_before"]],
		"goal":[["stopped","==",true]],"within":5,"quantifier":"all"}]`)
	if r.Verdict != VerdictFail || len(r.Trace) != 5 {
		t.Errorf("bounded all: %s %v, want FAIL with a 5-step witness that avoids the goal", r.Verdict, r.Trace)
	}
	r = checkOne(t, `[{"id":"B","status":"approved","kind":"bounded","trigger":[["pc","==","capture_before"]],
		"goal":[["stopped","==",true]],"within":12,"quantifier":"all"}]`)
	if r.Verdict != VerdictPass || r.Exercised != 64 {
		t.Errorf("bounded all within 12: %s exercised=%d, want PASS over the 64 initial states", r.Verdict, r.Exercised)
	}
	r = checkOne(t, `[{"id":"B","status":"approved","kind":"bounded","trigger":[["pc","==","rb_pull"],["rollback_armed","==",true],["ph","==",false]],
		"goal":[["rb_ok","==",true]],"within":4,"quantifier":"exists"}]`)
	if r.Verdict != VerdictFail {
		t.Errorf("bounded exists with an unhealthy prior: %s, want FAIL", r.Verdict)
	}
}

// The embedded property file parses, is well formed against the model's observation
// and references only fields Observe really produces.
func TestEmbeddedProperties_ParseAndReferenceObservedFields(t *testing.T) {
	props, sha, err := EmbeddedProperties()
	if err != nil {
		t.Fatal(err)
	}
	if len(props) == 0 || len(sha) != 64 {
		t.Fatalf("%d properties, sha %q", len(props), sha)
	}
	m := Model{}
	observed := map[string]bool{}
	for f := range m.Observe(m.Inits()[0]) {
		observed[f] = true
	}
	declared := append([]string(nil), ObservedFields...)
	var got []string
	for f := range observed {
		got = append(got, f)
	}
	sort.Strings(declared)
	sort.Strings(got)
	if !reflect.DeepEqual(declared, got) {
		t.Errorf("ObservedFields %v differs from what Observe produces %v", declared, got)
	}
	for i := range props {
		p := &props[i]
		if err := p.Validate(observed); err != nil {
			t.Errorf("%v", err)
		}
		for _, atoms := range [][]Atom{p.If, p.Then, p.Trigger, p.Goal} {
			for _, a := range atoms {
				for _, f := range []string{a.Field, a.RefField, a.RefPrev} {
					if f != "" && !observed[f] {
						t.Errorf("property %s references %q, which Observe does not produce", p.ID, f)
					}
				}
			}
		}
	}
}

func TestParseProperties_RejectsWhatWouldSilentlyNotBeChecked(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown status": `[{"id":"A","status":"aproved","kind":"state","then":[["tag","==","T"]]}]`,
		"duplicate id":   `[{"id":"A","status":"open","kind":"state","then":[]},{"id":"A","status":"open","kind":"state","then":[]}]`,
		"bad atom":       `[{"id":"A","status":"open","kind":"state","then":[["tag","=="]]}]`,
		"not json":       `[`,
	} {
		if _, _, err := ParseProperties([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, raw := range map[string]string{
		"unknown field":  `[{"id":"A","status":"approved","kind":"state","then":[["no_such_field","==","T"]]}]`,
		"unknown op":     `[{"id":"A","status":"approved","kind":"state","then":[["tag","~=","T"]]}]`,
		"prev in state":  `[{"id":"A","status":"approved","kind":"state","then":[["tag","==",{"prev":"tag"}]]}]`,
		"unknown kind":   `[{"id":"A","status":"approved","kind":"always","then":[["tag","==","T"]]}]`,
		"missing within": `[{"id":"A","status":"approved","kind":"bounded","trigger":[],"goal":[],"quantifier":"all"}]`,
	} {
		_, _, err := Check[State](Model{}, mustParse(t, raw), budgetStates, budgetTime)
		if err == nil || errors.Is(err, ErrIncomplete) {
			t.Errorf("%s: err=%v, want a validation error", name, err)
		}
		if code := RunGate([]byte(raw), GateOptions{MaxStates: budgetStates, MaxDuration: budgetTime}, io.Discard); code != ExitIncomplete {
			t.Errorf("%s: gate exits %d, want %d", name, code, ExitIncomplete)
		}
	}
}

const (
	propFailing = `{"id":"F","status":"%s","kind":"state","text":"fails","if":[["terminal","==",true]],"then":[["tag_ahead","==",false]]}`
	propVacuous = `{"id":"V","status":"%s","kind":"state","text":"unreachable trigger","if":[["pc","==","nowhere"]],"then":[["tag","==","T"]]}`
	propHolds   = `{"id":"P","status":"%s","kind":"state","text":"holds","if":[["terminal","==",true]],"then":[["jr","==","removed"]]}`
)

func propFile(entries ...string) []byte {
	return []byte("[" + strings.Join(entries, ",") + "]")
}

func withStatus(tmpl, status string) string {
	return strings.Replace(tmpl, "%s", status, 1)
}

// Exit-code policy. Incomplete/vacuous (2) takes precedence over fail (1) and is never
// downgraded; an unapproved failure is reported but, with FailOnlyApproved, not counted.
func TestRunGate_ExitCodes(t *testing.T) {
	cases := []struct {
		name             string
		props            []byte
		failOnlyApproved bool
		want             int
	}{
		{"all pass", propFile(withStatus(propHolds, StatusApproved)), true, ExitPass},
		{"proposed fails, strict", propFile(withStatus(propFailing, StatusProposed)), false, ExitFail},
		{"proposed fails, only approved count", propFile(withStatus(propFailing, StatusProposed)), true, ExitPass},
		{"approved fails", propFile(withStatus(propFailing, StatusApproved)), true, ExitFail},
		{"open fails", propFile(withStatus(propFailing, StatusOpen), withStatus(propHolds, StatusApproved)), false, ExitPass},
		{"approved vacuous", propFile(withStatus(propVacuous, StatusApproved)), true, ExitIncomplete},
		// Regression: a failing PROPOSED property must not mask a vacuous APPROVED one.
		// FAIL-before-VACUOUS precedence turned this into exit 1, which the
		// only-approved policy then reported as a pass.
		{"proposed fails + approved vacuous, only approved count",
			propFile(withStatus(propFailing, StatusProposed), withStatus(propVacuous, StatusApproved)), true, ExitIncomplete},
		{"proposed fails + approved vacuous, strict",
			propFile(withStatus(propFailing, StatusProposed), withStatus(propVacuous, StatusApproved)), false, ExitIncomplete},
		{"approved fails + approved vacuous",
			propFile(withStatus(propFailing, StatusApproved), withStatus(propVacuous, StatusApproved)), true, ExitIncomplete},
		{"approved fails + proposed vacuous",
			propFile(withStatus(propFailing, StatusApproved), withStatus(propVacuous, StatusProposed)), true, ExitIncomplete},
	}
	for _, c := range cases {
		var out strings.Builder
		opts := GateOptions{IncludeProposed: true, FailOnlyApproved: c.failOnlyApproved, MaxStates: budgetStates, MaxDuration: budgetTime}
		if got := RunGate(c.props, opts, &out); got != c.want {
			t.Errorf("%s: exit %d, want %d\n%s", c.name, got, c.want, out.String())
		}
		if strings.Contains(string(c.props), `"id":"F"`) && !strings.Contains(out.String(), "trace: ok -> ok") {
			t.Errorf("%s: a failing property must be printed with its trace even when it is not counted\n%s", c.name, out.String())
		}
	}
}

// The embedded properties on the real model, as run.sh runs them: complete, nothing
// vacuous, and no approved property fails.
func TestRunGate_EmbeddedPropertiesShadowPolicy(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	opts := GateOptions{IncludeProposed: true, FailOnlyApproved: true, MaxStates: budgetStates, MaxDuration: budgetTime, ReportDir: dir}
	if code := RunGate(EmbeddedPropertiesJSON(), opts, &out); code != ExitPass {
		t.Fatalf("exit %d, want %d\n%s", code, ExitPass, out.String())
	}
	var sum strings.Builder
	WriteSummary(dir, &sum)
	if s := sum.String(); !strings.Contains(s, "**Model check** — ") || !strings.Contains(s, "INCOMPLETE: fewer than three conformance suites") {
		t.Errorf("summary must show the model check and call the missing conformance reports INCOMPLETE:\n%s", s)
	}
	sum.Reset()
	WriteSummary(t.TempDir(), &sum)
	if s := sum.String(); !strings.Contains(s, "Treat this run as INCOMPLETE") || !strings.Contains(s, "This is not a pass") {
		t.Errorf("summary of an empty directory must say INCOMPLETE:\n%s", s)
	}
}

// The vectors are a pure function of the model: stable counts, deterministic order.
func TestVectors_Deterministic(t *testing.T) {
	a1, c1 := Vectors()
	a2, c2 := Vectors()
	if !reflect.DeepEqual(a1, a2) || !reflect.DeepEqual(c1, c2) {
		t.Fatal("two walks of the model produced different vectors")
	}
	if len(a1) == 0 || len(c1) == 0 {
		t.Fatalf("empty vector set: %d apply, %d crash", len(a1), len(c1))
	}
	rv := GenReconcileVectors()
	total := 1
	for _, d := range rv.Domains {
		total *= len(d.Values)
	}
	if total != len(rv.Expected) || total != 435456 {
		t.Fatalf("reconcile table: %d inputs, %d expectations", total, len(rv.Expected))
	}
	// Every input carries the model's action AND reason, not the reason alone.
	seen := map[byte]bool{}
	idx := make([]int, len(rv.Domains))
	for n := 0; n < total; n++ {
		seen[rv.Expected[n]] = true
		wantAction, wantReason := ReconcileSpec(ReconcileInputAt(idx))
		if action, reason := rv.Verdict(n); action != wantAction || reason != wantReason || action == "" {
			t.Fatalf("input %d: table says %s/%s, reference says %s/%s", n, action, reason, wantAction, wantReason)
		}
		if more := rv.Advance(idx); more != (n < total-1) {
			t.Fatalf("odometer ended at input %d of %d", n, total)
		}
	}
	if len(seen) != len(rv.Reasons) {
		t.Errorf("%d of %d reconcile verdicts are produced over the input space", len(seen), len(rv.Reasons))
	}
}

// stallSystem is state 0 with a self-loop ("wait") and a step to the goal state 1 ("advance").
type stallSystem struct{}

func (stallSystem) Inits() []int { return []int{0} }
func (stallSystem) Events(s int) []string {
	if s == 0 {
		return []string{"wait", "advance"}
	}
	return nil
}
func (stallSystem) Step(s int, e string) int {
	if e == "advance" {
		return 1
	}
	return s
}
func (stallSystem) Observe(s int) map[string]any { return map[string]any{"n": float64(s)} }

// A path that waits in a self-loop uses up the bound without reaching the goal. "Every path
// reaches the goal within k" must therefore FAIL, while "some path does" still passes.
func TestCheck_BoundedAllCountsSelfLoops(t *testing.T) {
	run := func(quantifier string) Result {
		props := mustParse(t, `[{"id":"B","status":"approved","kind":"bounded","trigger":[["n","==",0]],
			"goal":[["n","==",1]],"within":1,"quantifier":"`+quantifier+`"}]`)
		res, _, err := Check[int](stallSystem{}, props, budgetStates, budgetTime)
		if err != nil || len(res) != 1 {
			t.Fatalf("check: %v (%d results)", err, len(res))
		}
		return res[0]
	}
	if r := run("all"); r.Verdict != VerdictFail || !reflect.DeepEqual(r.Trace, []string{"wait"}) {
		t.Errorf("all: verdict %s trace %v, want FAIL via [wait]", r.Verdict, r.Trace)
	}
	if r := run("exists"); r.Verdict != VerdictPass {
		t.Errorf("exists: verdict %s, want PASS", r.Verdict)
	}
}
