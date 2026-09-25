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
	if strings.Join(c.BlocksLost, ",") != "m/a.go:1.1,2.2" || strings.Join(c.BlocksGained, ",") != "m/a.go:3.1,4.2" {
		t.Fatalf("lost %v gained %v", c.BlocksLost, c.BlocksGained)
	}
	if len(c.FilesChanged) != 1 || c.FilesChanged[0].Reference != 66.67 || c.FilesChanged[0].Pilot != 33.33 {
		t.Fatalf("files changed = %+v", c.FilesChanged)
	}
}

// TestCompare_CoverageLossFailsUnlessExcepted pins the stage-5B rule: a block
// the reference covered and the sharded run did not is a PROBLEM — rounded
// percentages and passing floors do not establish equivalence. Coverage the
// sharded run gained is only a note.
func TestCompare_CoverageLossFailsUnlessExcepted(t *testing.T) {
	lostOne := func(t *testing.T) compareRuns {
		in := baseCompare(t)
		in.pilotProf = mustProfile(t, "mode: atomic\nm/a.go:1.1,2.2 2 0\nm/a.go:3.1,4.2 1 0\n")
		return in
	}
	ok := CoverageException{Block: "m/a.go:1.1,2.2", Reason: "why", Evidence: "how we know"}
	for _, tc := range []struct {
		name   string
		ex     []CoverageException
		wantOK bool
		want   string
	}{
		{"unexplained loss", nil, false, "1 block(s) covered by the unsharded reference are NOT covered by the sharded run: 1 [m/a.go:1.1,2.2]"},
		{"justified exception", []CoverageException{ok}, true, ""},
		{"exception without evidence", []CoverageException{{Block: ok.Block, Reason: "why"}}, false, "is not explicit"},
		{"duplicated exception", []CoverageException{ok, ok}, false, "listed twice"},
		{"stale exception", []CoverageException{ok, {Block: "m/a.go:9.1,9.9", Reason: "r", Evidence: "e"}}, false, "is stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := lostOne(t)
			in.exceptions = CoverageExceptions{Schema: 1, Exceptions: tc.ex}
			c := compare(in)
			if c.OK != tc.wantOK || !strings.Contains(strings.Join(c.Problems, "\n"), tc.want) {
				t.Fatalf("ok=%v problems=%v, want ok=%v and %q", c.OK, c.Problems, tc.wantOK, tc.want)
			}
		})
	}

	// Pilot-only coverage never fails.
	in := baseCompare(t)
	in.pilotProf = mustProfile(t, "mode: atomic\nm/a.go:1.1,2.2 2 3\nm/a.go:3.1,4.2 1 7\n")
	if c := compare(in); !c.OK || len(c.BlocksGained) != 1 {
		t.Fatalf("gained coverage failed the comparison: %+v", c)
	}
}
