//go:build lifecycle_conformance

package lifecyclemodel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func currentBaseline(t *testing.T) Baseline {
	t.Helper()
	props, sha, err := EmbeddedProperties()
	if err != nil {
		t.Fatal(err)
	}
	res, st, err := Check[State](Model{}, props, budgetStates, budgetTime)
	if err != nil {
		t.Fatal(err)
	}
	return ComputeBaseline(sha, st, res)
}

// The committed baseline is the model's current behaviour. This is the same comparison
// run.sh makes; it is here too so a plain `go test -tags lifecycle_conformance` of the
// package reports drift, not only the shadow workflow.
func TestBaseline_EmbeddedMatchesModel(t *testing.T) {
	want, err := ParseBaseline(EmbeddedBaselineJSON())
	if err != nil {
		t.Fatal(err)
	}
	if d := CompareBaseline(want, currentBaseline(t)); d != nil {
		t.Fatalf("model drifted from baseline.json (run test/lifecycle-conformance/update-baseline.sh if intended):\n%s",
			strings.Join(d, "\n"))
	}
}

// Negative controls: every kind of change the baseline exists to expose is reported.
func TestCompareBaseline_ReportsEveryKindOfChange(t *testing.T) {
	base := currentBaseline(t)
	clone := func() Baseline {
		var b Baseline
		raw, _ := json.Marshal(base)
		_ = json.Unmarshal(raw, &b)
		return b
	}
	prop := func(b *Baseline, id string) *BaselineProperty {
		for i := range b.Properties {
			if b.Properties[i].ID == id {
				return &b.Properties[i]
			}
		}
		t.Fatalf("no property %s", id)
		return nil
	}
	// Each case edits the BASELINE side (want), so the arrow reads baseline -> now.
	cases := []struct {
		name, want string
		mutate     func(b *Baseline)
	}{
		{"verdict now PASS, baseline FAIL", "property S5 verdict FAIL -> PASS", func(b *Baseline) { prop(b, "S5").Verdict = VerdictFail }},
		{"verdict now FAIL, baseline PASS", "property C2 verdict PASS -> FAIL", func(b *Baseline) { prop(b, "C2").Verdict = VerdictPass }},
		{"status", "property S1 status", func(b *Baseline) { prop(b, "S1").Status = StatusApproved }},
		{"exercised", "property S2 exercised", func(b *Baseline) { prop(b, "S2").Exercised++ }},
		{"counterexample", "property O2 counterexample", func(b *Baseline) { prop(b, "O2").Trace = []string{"ok"} }},
		{"property new since the baseline", "property T1 is new", func(b *Baseline) {
			for i := range b.Properties {
				if b.Properties[i].ID == "T1" {
					b.Properties = append(b.Properties[:i], b.Properties[i+1:]...)
					return
				}
			}
		}},
		{"property no longer evaluated", "property ZZ (baseline verdict PASS) is no longer evaluated", func(b *Baseline) {
			b.Properties = append(b.Properties, BaselineProperty{ID: "ZZ", Verdict: VerdictPass})
		}},
		{"state space", "state space changed", func(b *Baseline) { b.Stats.States-- }},
		{"properties file", "properties.json changed", func(b *Baseline) { b.PropsSHA256 = "0" + b.PropsSHA256[1:] }},
		{"reconcile table", "reconcile decision table changed", func(b *Baseline) { b.Reconcile.SHA256 = "x" }},
		{"apply expectation", "apply vector set changed: 172 -> 172 vectors, 1 removed, 1 added", func(b *Baseline) {
			b.Apply[0] = strings.Replace(b.Apply[0], "op=succeeded", "op=failed", 1)
		}},
		{"crash vector new since the baseline", "crash vector set changed: 146 -> 147 vectors, 0 removed, 1 added", func(b *Baseline) {
			b.Crash = b.Crash[1:]
		}},
		{"vector dropped since the baseline (multiset)", "apply vector set changed: 173 -> 172 vectors, 1 removed, 0 added", func(b *Baseline) {
			b.Apply = append(b.Apply, b.Apply[0])
		}},
	}
	if d := CompareBaseline(clone(), base); d != nil {
		t.Fatalf("an identical baseline must not drift: %v", d)
	}
	for _, c := range cases {
		want := clone()
		c.mutate(&want)
		d := strings.Join(CompareBaseline(want, base), "\n")
		if !strings.Contains(d, c.want) {
			t.Errorf("%s: want drift line containing %q, got:\n%s", c.name, c.want, d)
		}
	}
}

// A baseline that cannot be read must never compare as "no drift".
func TestParseBaseline_RejectsWhatWouldHideDrift(t *testing.T) {
	for _, raw := range []string{"", "{}", "null", "[", `{"props_sha256":"x","stats":{"states":1}}`} {
		if _, err := ParseBaseline([]byte(raw)); err == nil {
			t.Errorf("baseline %q accepted", raw)
		}
	}
	var out strings.Builder
	opts := GateOptions{IncludeProposed: true, FailOnlyApproved: true, MaxStates: budgetStates, MaxDuration: budgetTime,
		Baseline: []byte("{}")}
	if code := RunGate(EmbeddedPropertiesJSON(), opts, &out); code != ExitIncomplete {
		t.Errorf("unusable baseline: exit %d, want %d\n%s", code, ExitIncomplete, out.String())
	}
}

// Drift turns a pass into ExitDrift, never masks INCOMPLETE, and is recorded in the report
// so the summary can say DRIFT (or NOT CHECKED) instead of silence.
func TestRunGate_DriftExitAndReport(t *testing.T) {
	stale := currentBaseline(t)
	for i := range stale.Properties {
		if stale.Properties[i].ID == "S5" {
			stale.Properties[i].Verdict = VerdictFail
		}
	}
	raw, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var out strings.Builder
	opts := GateOptions{IncludeProposed: true, FailOnlyApproved: true, MaxStates: budgetStates, MaxDuration: budgetTime,
		Baseline: raw, ReportDir: dir}
	if code := RunGate(EmbeddedPropertiesJSON(), opts, &out); code != ExitDrift {
		t.Fatalf("drift on an otherwise passing run: exit %d, want %d\n%s", code, ExitDrift, out.String())
	}
	if !strings.Contains(out.String(), "DRIFT   property S5 verdict FAIL -> PASS") {
		t.Errorf("drift line missing:\n%s", out.String())
	}
	var sum strings.Builder
	WriteSummary(dir, &sum)
	if !strings.Contains(sum.String(), "**Baseline: DRIFT.**") {
		t.Errorf("summary must show DRIFT:\n%s", sum.String())
	}

	opts.MaxStates, opts.ReportDir = 100, ""
	if code := RunGate(EmbeddedPropertiesJSON(), opts, &out); code != ExitIncomplete {
		t.Errorf("incomplete run with a baseline: exit %d, want %d", code, ExitIncomplete)
	}

	dir = t.TempDir()
	opts = GateOptions{IncludeProposed: true, FailOnlyApproved: true, MaxStates: budgetStates, MaxDuration: budgetTime, ReportDir: dir}
	_ = RunGate(EmbeddedPropertiesJSON(), opts, &out)
	sum.Reset()
	WriteSummary(dir, &sum)
	if !strings.Contains(sum.String(), "**Baseline: NOT CHECKED.**") {
		t.Errorf("a run without a baseline must say NOT CHECKED:\n%s", sum.String())
	}
}

// A baseline is never recorded from a run that is not a pass-or-fail verdict.
func TestRunGate_WriteBaselineRefusesIncompleteRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	opts := GateOptions{IncludeProposed: true, MaxStates: budgetStates, MaxDuration: budgetTime, WriteBaseline: path}
	if code := RunGate(propFile(withStatus(propVacuous, StatusProposed)), opts, &strings.Builder{}); code != ExitIncomplete {
		t.Errorf("vacuous run: exit %d, want %d", code, ExitIncomplete)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a baseline was written from a vacuous run")
	}
	if code := RunGate(EmbeddedPropertiesJSON(), opts, &strings.Builder{}); code != ExitPass {
		t.Fatalf("complete run: exit %d", code)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "\\u003e") {
		t.Error("baseline must not HTML-escape: reviewers read it as a diff")
	}
	if _, err := ParseBaseline(raw); err != nil {
		t.Errorf("written baseline does not parse back: %v", err)
	}
}
