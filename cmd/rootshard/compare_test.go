package main

import (
	"strings"
	"testing"
)

func results(pkg string, tests map[string]string, subs ...string) Results {
	p := &PkgResult{Status: statusPass, Tests: map[string]*TestResult{}, Subtests: map[string]string{}}
	for n, s := range tests {
		p.Tests[n] = &TestResult{Status: s, Reports: 1}
	}
	for _, s := range subs {
		p.Subtests[s] = statusPass
	}
	return Results{pkg: p}
}

func baseCompare(t *testing.T) compareRuns {
	t.Helper()
	prof := "mode: atomic\nm/a.go:1.1,2.2 2 3\nm/a.go:3.1,4.2 1 0\n"
	return compareRuns{
		pkg:       "m",
		inv:       mustList(t, "TestA", "TestB", "FuzzC"),
		ref:       results("m", map[string]string{"TestA": statusPass, "TestB": statusSkip, "FuzzC": statusPass}, "TestA/x"),
		pilot:     results("m", map[string]string{"TestA": statusPass, "TestB": statusSkip, "FuzzC": statusPass}, "TestA/x"),
		refProf:   mustProfile(t, prof),
		pilotProf: mustProfile(t, prof),
	}
}

func TestCompare_EquivalentRunsPass(t *testing.T) {
	c := compare(baseCompare(t))
	if !c.OK {
		t.Fatalf("problems: %v", c.Problems)
	}
	if len(c.ReferenceSkipped) != 1 || len(c.PilotSkipped) != 1 {
		t.Fatalf("legitimate skips must be reported on both sides: %v / %v", c.ReferenceSkipped, c.PilotSkipped)
	}
}

func TestCompare_RejectsLostExecution(t *testing.T) {
	cases := map[string]struct {
		mutate func(*compareRuns)
		want   string
	}{
		"entry missing from pilot": {func(in *compareRuns) { delete(in.pilot["m"].Tests, "FuzzC") }, "reference vs pilot"},
		"skip became pass":         {func(in *compareRuns) { in.pilot["m"].Tests["TestB"].Status = statusPass }, "TestB: reference skip, pilot pass"},
		"subtest missing":          {func(in *compareRuns) { in.pilot["m"].Subtests = map[string]string{} }, "subtest(s) ran in the reference but not in the pilot"},
		"subtest pass became skip": {func(in *compareRuns) { in.pilot["m"].Subtests["TestA/x"] = statusSkip }, "subtest TestA/x: reference pass, pilot skip"},
		"non-root entry outcome differs": {func(in *compareRuns) {
			in.ref["m/sub"] = &PkgResult{Status: statusPass, Tests: map[string]*TestResult{"TestS": {Status: statusPass, Reports: 1}}, Subtests: map[string]string{}}
			in.pilot["m/sub"] = &PkgResult{Status: statusPass, Tests: map[string]*TestResult{"TestS": {Status: statusSkip, Reports: 1}}, Subtests: map[string]string{}}
		}, "m/sub TestS: reference pass, pilot skip"},
		"inventory drift": {func(in *compareRuns) { in.inv = mustList(t, "TestA", "TestB", "FuzzC", "TestNew") }, "binary inventory"},
		"package missing": {func(in *compareRuns) {
			in.ref["m/sub"] = &PkgResult{Status: statusPass, Tests: map[string]*TestResult{}, Subtests: map[string]string{}}
		}, "package set"},
		"reference failed":                  {func(in *compareRuns) { in.ref["m"].Status = statusFail }, "no passing baseline"},
		"pilot root failed after its tests": {func(in *compareRuns) { in.pilot["m"].Status = statusFail }, "the pilot's root package result is \"fail\""},
		"universe differs": {func(in *compareRuns) {
			in.pilotProf = mustProfile(t, "mode: atomic\nm/a.go:1.1,2.2 2 3\n")
		}, "block universe"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := baseCompare(t)
			tc.mutate(&in)
			c := compare(in)
			if c.OK || !strings.Contains(strings.Join(c.Problems, "; "), tc.want) {
				t.Fatalf("problems = %v, want %q", c.Problems, tc.want)
			}
		})
	}
}

// Coverage-block differences are REPORTED with their locations but do not
// reject: counters and timing-dependent branches vary between any two runs,
// and the unchanged floors decide.
func TestCompare_ReportsCoverageDifferencesByBlock(t *testing.T) {
	in := baseCompare(t)
	in.pilotProf = mustProfile(t, "mode: atomic\nm/a.go:1.1,2.2 2 0\nm/a.go:3.1,4.2 1 5\n")
	c := compare(in)
	if !c.OK {
		t.Fatalf("problems: %v", c.Problems)
	}
	if strings.Join(c.BlocksLost, ",") != "m/a.go:1.1,2.2" || strings.Join(c.BlocksGained, ",") != "m/a.go:3.1,4.2" {
		t.Fatalf("lost %v gained %v", c.BlocksLost, c.BlocksGained)
	}
	if len(c.FilesChanged) != 1 || c.FilesChanged[0].Reference != 66.67 || c.FilesChanged[0].Pilot != 33.33 {
		t.Fatalf("files changed = %+v", c.FilesChanged)
	}
}
