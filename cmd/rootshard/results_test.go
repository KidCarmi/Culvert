package main

import (
	"strings"
	"testing"
)

func ev(action, test string, extra ...string) string {
	s := `{"Action":"` + action + `","Package":"m"`
	if test != "" {
		s += `,"Test":"` + test + `"`
	}
	for _, e := range extra {
		s += "," + e
	}
	return s + "}"
}

func TestParseTestJSON_RecordsResultsSkipsAndSubtests(t *testing.T) {
	stream := strings.Join([]string{
		ev("start", ""),
		ev("run", "TestA"),
		ev("run", "TestA/sub"),
		ev("pass", "TestA/sub", `"Elapsed":0.1`),
		ev("pass", "TestA", `"Elapsed":0.5`),
		ev("run", "TestS"),
		ev("output", "TestS", `"Output":"=== RUN   TestS\n"`),
		ev("output", "TestS", `"Output":"    x_test.go:9: needs docker\n"`),
		ev("skip", "TestS", `"Elapsed":0`),
		ev("pass", "", `"Elapsed":2.5`),
	}, "\n")
	res, err := parseTestJSON(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	p := res["m"]
	if p.Status != statusPass || p.Elapsed != 2.5 {
		t.Fatalf("package = %q %.1f", p.Status, p.Elapsed)
	}
	if a := p.Tests["TestA"]; a == nil || a.Status != statusPass || a.Reports != 1 || a.Seconds != 0.5 {
		t.Fatalf("TestA = %+v", a)
	}
	if s := p.Tests["TestS"]; s == nil || s.Status != statusSkip || !strings.Contains(s.SkipNote, "needs docker") {
		t.Fatalf("skip was not recorded with its reason: %+v", s)
	}
	if p.Subtests["TestA/sub"] != statusPass || len(p.Tests) != 2 {
		t.Fatalf("subtest filed as a top-level entry: %v / %v", p.Subtests, sortedKeys(p.Tests))
	}
}

func TestParseTestJSON_RejectsACorruptStream(t *testing.T) {
	if _, err := parseTestJSON(strings.NewReader(ev("pass", "TestA") + "\n{\"Action\":\"pa")); err == nil {
		t.Fatal("a truncated event stream must not parse as a shorter passing one")
	}
}

const refLog = `2026-09-22T20:52:51.0000000Z === RUN   TestOther
2026-09-22T20:52:51.0000000Z --- PASS: TestOther (0.01s)
2026-09-22T20:52:51.0000000Z PASS
2026-09-22T20:52:51.0000000Z coverage: 80.0% of statements
2026-09-22T20:52:51.0000000Z ok  	example.com/m/sub	1.234s	coverage: 80.0% of statements
2026-09-22T20:52:51.0000000Z 	example.com/m/cmd/tool		coverage: 0.0% of statements
?   	example.com/m/gen	[no test files]
=== RUN   TestRoot
=== RUN   TestRoot/case_1
--- PASS: TestRoot (2.50s)
    --- PASS: TestRoot/case_1 (0.10s)
=== RUN   TestSkipped
    root_test.go:9: skipping
--- SKIP: TestSkipped (0.00s)
=== RUN   FuzzSeed
--- PASS: FuzzSeed (0.00s)
PASS
ok  	example.com/m	1445.123s	coverage: 62.3% of statements
FAIL	example.com/m/broken	0.5s
FAIL	example.com/m/nobuild [build failed]
`

func TestParseVerboseLog_AttributesResultsToPackages(t *testing.T) {
	res, err := parseVerboseLog(strings.NewReader(refLog))
	if err != nil {
		t.Fatal(err)
	}
	root := res["example.com/m"]
	if root == nil || root.Status != statusPass || root.Elapsed != 1445.123 {
		t.Fatalf("root = %+v", root)
	}
	if got := sortedKeys(root.Tests); strings.Join(got, ",") != "FuzzSeed,TestRoot,TestSkipped" {
		t.Fatalf("root entries = %v", got)
	}
	if root.Tests["TestRoot"].Seconds != 2.5 || root.Tests["TestSkipped"].Status != statusSkip {
		t.Fatalf("root results = %+v %+v", root.Tests["TestRoot"], root.Tests["TestSkipped"])
	}
	if root.Subtests["TestRoot/case_1"] != statusPass {
		t.Fatalf("subtests = %v", root.Subtests)
	}
	if s := res["example.com/m/sub"]; s == nil || len(s.Tests) != 1 || s.Elapsed != 1.234 {
		t.Fatalf("sub = %+v", s)
	}
	for _, p := range []string{"example.com/m/cmd/tool", "example.com/m/gen"} {
		if res[p] == nil || res[p].Status != statusPass {
			t.Fatalf("no-test package %s = %+v", p, res[p])
		}
	}
	for _, p := range []string{"example.com/m/broken", "example.com/m/nobuild"} {
		if res[p] == nil || res[p].Status != statusFail {
			t.Fatalf("failed package %s = %+v", p, res[p])
		}
	}
}

func TestParseVerboseLog_RejectsATruncatedLog(t *testing.T) {
	if _, err := parseVerboseLog(strings.NewReader("--- PASS: TestA (0.00s)\n")); err == nil {
		t.Fatal("result lines with no closing package line are a truncated log")
	}
}

func TestCheckChunkResults_FindsEveryLossShape(t *testing.T) {
	mk := func(pkgStatus string, tests map[string]*TestResult) Results {
		return Results{"m": {Status: pkgStatus, Tests: tests, Subtests: map[string]string{}}}
	}
	ok := func() map[string]*TestResult {
		return map[string]*TestResult{"TestA": {Status: statusPass, Reports: 1}, "TestB": {Status: statusSkip, Reports: 1}}
	}
	cases := map[string]struct {
		res  Results
		want string
	}{
		"clean":           {mk(statusPass, ok()), ""},
		"never ran":       {mk(statusPass, map[string]*TestResult{"TestA": {Status: statusPass, Reports: 1}}), "TestB has no result"},
		"ran twice":       {mk(statusPass, map[string]*TestResult{"TestA": {Status: statusPass, Reports: 2}, "TestB": {Status: statusPass, Reports: 1}}), "reported 2"},
		"failed":          {mk(statusFail, map[string]*TestResult{"TestA": {Status: statusFail, Reports: 1}, "TestB": {Status: statusPass, Reports: 1}}), "FAILED"},
		"package crashed": {mk(statusFail, ok()), `package result "fail"`},
		"unselected ran": {mk(statusPass, func() map[string]*TestResult {
			m := ok()
			m["TestC"] = &TestResult{Status: statusPass, Reports: 1}
			return m
		}()), "not selected"},
		"foreign package": {Results{"m": {Status: statusPass, Tests: ok()}, "x": {Status: statusPass}}, "unexpected package"},
		"no events":       {Results{}, "no events"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var probs []string
			checkChunkResults("m", "c", []string{"TestA", "TestB"}, tc.res, func(f string, a ...any) {
				probs = append(probs, strings.TrimSpace(sprintf(f, a...)))
			})
			got := strings.Join(probs, "; ")
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("problems = %q, want %q", got, tc.want)
			}
		})
	}
}
