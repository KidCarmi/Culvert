//go:build lifecycle_conformance

package lifecyclemodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Property kinds, verdicts and statuses.
const (
	KindState      = "state"
	KindTransition = "transition"
	KindBounded    = "bounded"

	VerdictPass    = "PASS"
	VerdictFail    = "FAIL"
	VerdictVacuous = "VACUOUS"

	StatusProposed = "proposed"
	StatusOpen     = "open"
	StatusApproved = "approved"
)

// System is what the checker explores. S must be comparable.
type System[S comparable] interface {
	Inits() []S
	Events(S) []string
	Step(S, string) S
	Observe(S) map[string]any
}

// Atom is one comparison: [field, op, const] | [field, op, {"field": g}] | [field, op, {"prev": g}].
// ops: == != < <= > >= in notin.
type Atom struct {
	Field string
	Op    string
	// Exactly one of the following describes the right-hand side.
	Const    any    // string, bool, float64 or []any
	RefField string // compare against another field of the same observation
	RefPrev  string // compare against a field of the pre-state (transition "then" only)
}

// UnmarshalJSON decodes the three-element array form.
func (a *Atom) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) != 3 {
		return fmt.Errorf("bad atom %s", b)
	}
	if json.Unmarshal(raw[0], &a.Field) != nil || json.Unmarshal(raw[1], &a.Op) != nil {
		return fmt.Errorf("bad atom %s", b)
	}
	var rhs any
	if err := json.Unmarshal(raw[2], &rhs); err != nil {
		return fmt.Errorf("bad atom %s", b)
	}
	ref, isRef := rhs.(map[string]any)
	if !isRef {
		a.Const = rhs
		return nil
	}
	if len(ref) != 1 {
		return fmt.Errorf("bad reference in %s", b)
	}
	for k, v := range ref {
		name, ok := v.(string)
		switch {
		case ok && k == "field":
			a.RefField = name
		case ok && k == "prev":
			a.RefPrev = name
		default:
			return fmt.Errorf("bad reference in %s", b)
		}
	}
	return nil
}

// Property is one checked property (plain JSON data; this package only READS property
// files, never writes them).
//
//	state      {"if": [atom..], "then": [atom..]}
//	transition {"on": [event..]|null, "if": [atom..] (pre-state), "then": [atom..] (post-state)}
//	bounded    {"trigger": [atom..], "goal": [atom..], "within": k, "quantifier": "all"|"exists"}
//	           all   : every path from a trigger state reaches the goal within k steps
//	           exists: some path does
type Property struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`
	Kind       string   `json:"kind"`
	Text       string   `json:"text"`
	Source     string   `json:"source"`
	If         []Atom   `json:"if"`
	Then       []Atom   `json:"then"`
	On         []string `json:"on"`
	Trigger    []Atom   `json:"trigger"`
	Goal       []Atom   `json:"goal"`
	Within     *int     `json:"within"`
	Quantifier string   `json:"quantifier"`
}

// ErrIncomplete reports that exploration could not be finished within the budget.
// It is never a pass.
var ErrIncomplete = errors.New("incomplete")

// Stats describes a completed exploration.
type Stats struct {
	States      int `json:"states"`
	Transitions int `json:"transitions"`
}

// Result is the verdict for one property. Trace is the SHORTEST event sequence from an
// initial state that reproduces a FAIL; State is the observation at its end.
type Result struct {
	ID        string
	Kind      string
	Status    string
	Text      string
	Verdict   string
	Trace     []string
	State     map[string]any
	Exercised int
}

// MarshalJSON keeps the report shape: verdict-specific keys only.
func (r Result) MarshalJSON() ([]byte, error) {
	m := map[string]any{"id": r.ID, "kind": r.Kind, "status": r.Status, "text": r.Text, "verdict": r.Verdict}
	switch r.Verdict {
	case VerdictFail:
		trace := r.Trace
		if trace == nil {
			trace = []string{}
		}
		m["trace"], m["state"] = trace, r.State
	case VerdictPass:
		m["exercised"] = r.Exercised
	}
	return json.Marshal(m)
}

// UnmarshalJSON reads a Result back from a report.
func (r *Result) UnmarshalJSON(b []byte) error {
	var v struct {
		ID        string         `json:"id"`
		Kind      string         `json:"kind"`
		Status    string         `json:"status"`
		Text      string         `json:"text"`
		Verdict   string         `json:"verdict"`
		Trace     []string       `json:"trace"`
		State     map[string]any `json:"state"`
		Exercised int            `json:"exercised"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*r = Result{v.ID, v.Kind, v.Status, v.Text, v.Verdict, v.Trace, v.State, v.Exercised}
	return nil
}

type edge struct {
	event string
	to    int
}

// graph is the complete reachable state space; node numbering is breadth-first
// discovery order, so "first violating node" always has a shortest path from an init.
type graph struct {
	parent []edge // parent[i].to == -1 for an initial state
	succ   [][]edge
	obs    []map[string]any
}

// explore is complete breadth-first reachability, or ErrIncomplete.
func explore[S comparable](m System[S], maxStates int, deadline time.Time) (*graph, error) {
	index := map[S]int{}
	var order []S
	g := &graph{}
	for _, s := range m.Inits() {
		if _, ok := index[s]; !ok {
			index[s] = len(order)
			order = append(order, s)
			g.parent = append(g.parent, edge{to: -1})
		}
	}
	for i := 0; i < len(order); i++ {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: time budget exhausted during exploration", ErrIncomplete)
		}
		s := order[i]
		events := m.Events(s)
		out := make([]edge, 0, len(events))
		for _, e := range events {
			t := m.Step(s, e)
			j, ok := index[t]
			if !ok {
				if len(order) >= maxStates {
					return nil, fmt.Errorf("%w: more than %d states", ErrIncomplete, maxStates)
				}
				j = len(order)
				index[t] = j
				order = append(order, t)
				g.parent = append(g.parent, edge{event: e, to: i})
			}
			out = append(out, edge{event: e, to: j})
		}
		g.succ = append(g.succ, out)
	}
	g.obs = make([]map[string]any, len(order))
	for i, s := range order {
		g.obs[i] = m.Observe(s)
	}
	return g, nil
}

func (g *graph) traceTo(i int) []string {
	var rev []string
	for g.parent[i].to >= 0 {
		rev = append(rev, g.parent[i].event)
		i = g.parent[i].to
	}
	out := make([]string, len(rev))
	for k, e := range rev {
		out[len(rev)-1-k] = e
	}
	return out
}

// Check explores m completely and evaluates props. It returns an error wrapping
// ErrIncomplete if the state space was not fully explored within the budget, and a
// plain error if a property is malformed. Neither is ever a pass.
func Check[S comparable](m System[S], props []Property, maxStates int, maxDuration time.Duration) ([]Result, Stats, error) {
	deadline := time.Now().Add(maxDuration)
	g, err := explore(m, maxStates, deadline)
	if err != nil {
		return nil, Stats{}, err
	}
	fields := map[string]bool{}
	if len(g.obs) > 0 {
		for f := range g.obs[0] {
			fields[f] = true
		}
	}
	results := make([]Result, 0, len(props))
	for i := range props {
		p := &props[i]
		if err := p.Validate(fields); err != nil {
			return nil, Stats{}, err
		}
		r := Result{ID: p.ID, Kind: p.Kind, Status: p.Status, Text: p.Text}
		if r.Status == "" {
			r.Status = StatusProposed
		}
		switch p.Kind {
		case KindState:
			g.checkState(p, &r)
		case KindTransition:
			g.checkTransition(p, &r)
		default:
			g.checkBounded(p, &r)
		}
		results = append(results, r)
		if time.Now().After(deadline) {
			return nil, Stats{}, fmt.Errorf("%w: time budget exhausted while checking properties", ErrIncomplete)
		}
	}
	st := Stats{States: len(g.obs)}
	for _, out := range g.succ {
		st.Transitions += len(out)
	}
	return results, st, nil
}

func (g *graph) verdict(r *Result, hit, bad int, tail []string, final int) {
	switch {
	case bad >= 0:
		r.Verdict = VerdictFail
		r.Trace = append(g.traceTo(bad), tail...)
		r.State = g.obs[final]
	case hit == 0:
		r.Verdict = VerdictVacuous
	default:
		r.Verdict = VerdictPass
		r.Exercised = hit
	}
}

func (g *graph) checkState(p *Property, r *Result) {
	hit, bad := 0, -1
	for i, o := range g.obs {
		if !allHold(p.If, o, nil) {
			continue
		}
		hit++
		if bad < 0 && !allHold(p.Then, o, nil) {
			bad = i
		}
	}
	g.verdict(r, hit, bad, nil, max(bad, 0))
}

func (g *graph) checkTransition(p *Property, r *Result) {
	hit, bad, final := 0, -1, 0
	var tail []string
	for i, o := range g.obs {
		if !allHold(p.If, o, nil) {
			continue
		}
		for _, e := range g.succ[i] {
			if p.On != nil && !contains(p.On, e.event) {
				continue
			}
			hit++
			if bad < 0 && !allHold(p.Then, g.obs[e.to], o) {
				bad, final, tail = i, e.to, []string{e.event}
			}
		}
	}
	g.verdict(r, hit, bad, tail, final)
}

func (g *graph) checkBounded(p *Property, r *Result) {
	goal := make([]bool, len(g.obs))
	for i, o := range g.obs {
		goal[i] = allHold(p.Goal, o, nil)
	}
	hit, bad := 0, -1
	var tail []string
	for i, o := range g.obs {
		if !allHold(p.Trigger, o, nil) {
			continue
		}
		hit++
		if bad >= 0 {
			continue
		}
		if t, escaped := g.escape(i, goal, *p.Within, p.Quantifier); escaped {
			bad, tail = i, t
		}
	}
	g.verdict(r, hit, bad, tail, max(bad, 0))
}

// escape reports whether the bounded property is violated from node s, with a witness
// path (event labels; empty for "exists", where the witness is the absence of a path).
func (g *graph) escape(s int, goal []bool, k int, quantifier string) ([]string, bool) {
	if quantifier == "exists" {
		return nil, !g.reachesGoal(s, goal, k)
	}
	return g.avoid(s, goal, k)
}

func (g *graph) reachesGoal(s int, goal []bool, k int) bool {
	seen := map[int]bool{s: true}
	frontier := []int{s}
	for step := 0; step <= k; step++ {
		var next []int
		for _, x := range frontier {
			if goal[x] {
				return true
			}
			for _, e := range g.succ[x] {
				if !seen[e.to] {
					seen[e.to] = true
					next = append(next, e.to)
				}
			}
		}
		frontier = next
	}
	return false
}

// avoid finds a path of at most left steps from x that never meets the goal.
func (g *graph) avoid(x int, goal []bool, left int) ([]string, bool) {
	if goal[x] {
		return nil, false
	}
	if left == 0 {
		return nil, true
	}
	moved := false
	for _, e := range g.succ[x] {
		if e.to == x {
			continue
		}
		moved = true
		if sub, ok := g.avoid(e.to, goal, left-1); ok {
			return append([]string{e.event}, sub...), true
		}
	}
	return nil, !moved
}

// Validate checks that the property is well formed and references only known fields.
func (p *Property) Validate(fields map[string]bool) error {
	var err error
	switch p.Kind {
	case KindState:
		err = errors.Join(validateAtoms(p.If, fields, false), validateAtoms(p.Then, fields, false), required(p.Then, "then"))
	case KindTransition:
		err = errors.Join(validateAtoms(p.If, fields, false), validateAtoms(p.Then, fields, true), required(p.Then, "then"))
	case KindBounded:
		err = errors.Join(validateAtoms(p.Trigger, fields, false), validateAtoms(p.Goal, fields, false),
			required(p.Trigger, "trigger"), required(p.Goal, "goal"))
		if p.Within == nil || (p.Quantifier != "all" && p.Quantifier != "exists") {
			err = errors.Join(err, errors.New("bad bounded property"))
		}
	default:
		err = fmt.Errorf("unknown kind %q", p.Kind)
	}
	if err != nil {
		return fmt.Errorf("property %s: %w", p.ID, err)
	}
	return nil
}

func required(atoms []Atom, name string) error {
	if atoms == nil {
		return fmt.Errorf("missing %q", name)
	}
	return nil
}

var knownOps = map[string]bool{"==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true, "in": true, "notin": true}

func validateAtoms(atoms []Atom, fields map[string]bool, allowPrev bool) error {
	for i := range atoms {
		a := &atoms[i]
		if !fields[a.Field] || !knownOps[a.Op] {
			return fmt.Errorf("bad atom [%s %s ...]", a.Field, a.Op)
		}
		if a.RefField != "" && !fields[a.RefField] {
			return fmt.Errorf("bad reference to field %q", a.RefField)
		}
		if a.RefPrev != "" && (!allowPrev || !fields[a.RefPrev]) {
			return fmt.Errorf("bad reference to previous field %q", a.RefPrev)
		}
	}
	return nil
}

func allHold(atoms []Atom, obs, prev map[string]any) bool {
	for i := range atoms {
		if !atoms[i].holds(obs, prev) {
			return false
		}
	}
	return true
}

func (a *Atom) holds(obs, prev map[string]any) bool {
	rhs := a.Const
	switch {
	case a.RefPrev != "":
		rhs = prev[a.RefPrev]
	case a.RefField != "":
		rhs = obs[a.RefField]
	}
	lhs := obs[a.Field]
	switch a.Op {
	case "==":
		return valueEqual(lhs, rhs)
	case "!=":
		return !valueEqual(lhs, rhs)
	case "in":
		return member(lhs, rhs)
	case "notin":
		return !member(lhs, rhs)
	}
	return ordered(a.Op, lhs, rhs)
}

// valueEqual compares two scalar observation values (string, bool or float64).
// Values of different types are unequal.
func valueEqual(a, b any) bool {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	}
	return false
}

func member(v, list any) bool {
	xs, _ := list.([]any)
	for _, x := range xs {
		if valueEqual(v, x) {
			return true
		}
	}
	return false
}

// ordered evaluates < <= > >= on numbers; any other operand type does not hold.
func ordered(op string, a, b any) bool {
	x, ok1 := a.(float64)
	y, ok2 := b.(float64)
	if !ok1 || !ok2 {
		return false
	}
	switch op {
	case "<":
		return x < y
	case "<=":
		return x <= y
	case ">":
		return x > y
	}
	return x >= y
}
