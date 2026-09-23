package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Test/package outcomes, as `go test` and test2json spell them.
const (
	statusPass = "pass"
	statusFail = "fail"
	statusSkip = "skip"
)

// TestResult is one top-level entry's outcome within a package.
type TestResult struct {
	Status  string  `json:"status"`
	Seconds float64 `json:"seconds"`
	// Reports counts terminal results; anything other than 1 means the entry
	// ran twice or its result was lost, and is refused by the checks.
	Reports int `json:"reports"`
	// SkipNote carries the first output line of a skipped entry, so a
	// legitimate t.Skip is distinguishable from an entry that never ran (which
	// has no result at all).
	SkipNote string `json:"skipNote,omitempty"`
}

// PkgResult is one package's execution record.
type PkgResult struct {
	Status   string                 `json:"status"`
	Elapsed  float64                `json:"elapsed"`
	Tests    map[string]*TestResult `json:"tests"`
	Subtests map[string]string      `json:"subtests"`
}

// Results is keyed by import path.
type Results map[string]*PkgResult

func (r Results) pkg(name string) *PkgResult {
	p := r[name]
	if p == nil {
		p = &PkgResult{Tests: map[string]*TestResult{}, Subtests: map[string]string{}}
		r[name] = p
	}
	return p
}

// record files one terminal test result. Subtests (names with '/') run with
// their parent and are recorded for inventory comparison only.
func (p *PkgResult) record(test, status string, sec float64) {
	if strings.Contains(test, "/") {
		p.Subtests[test] = status
		return
	}
	tr := p.Tests[test]
	if tr == nil {
		tr = &TestResult{}
		p.Tests[test] = tr
	}
	tr.Reports++
	tr.Status = status
	tr.Seconds = sec
}

// merge folds o into r. A package reported by two sources keeps both sets of
// tests (a root package split across chunks is ONE package), and every test
// keeps its report count so a test run by two chunks is visible as 2.
func (r Results) merge(o Results) {
	for name, op := range o {
		p := r.pkg(name)
		p.Elapsed += op.Elapsed
		p.Status = worseStatus(p.Status, op.Status)
		for t, tr := range op.Tests {
			if cur := p.Tests[t]; cur != nil {
				cur.Reports += tr.Reports
				cur.Status = worseStatus(cur.Status, tr.Status)
				cur.Seconds += tr.Seconds
				continue
			}
			c := *tr
			p.Tests[t] = &c
		}
		for s, st := range op.Subtests {
			p.Subtests[s] = worseStatus(p.Subtests[s], st)
		}
	}
}

// worseStatus orders fail > "" (unknown) > skip > pass, so merging never hides
// a failure or a missing result behind a success.
func worseStatus(a, b string) string {
	rank := map[string]int{statusPass: 0, statusSkip: 1, "": 2, statusFail: 3}
	if a == "" && b != "" {
		return b
	}
	if b == "" {
		return a
	}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// testEvent is the subset of test2json's TestEvent this tool reads.
type testEvent struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Elapsed float64 `json:"Elapsed"`
	Output  string  `json:"Output"`
}

// parseTestJSON reads a test2json stream (`go test -json`, or a test binary's
// -test.v=test2json output converted by `go tool test2json`). A line that is
// not a JSON event is an error: a truncated or corrupted stream must not read
// as a shorter, passing one.
func parseTestJSON(r io.Reader) (Results, error) {
	res := Results{}
	lastOut := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for line := 1; sc.Scan(); line++ {
		b := sc.Bytes()
		if strings.TrimSpace(string(b)) == "" {
			continue
		}
		var ev testEvent
		if err := json.Unmarshal(b, &ev); err != nil {
			return nil, fmt.Errorf("test2json line %d is not an event: %w", line, err)
		}
		applyEvent(res, ev, lastOut)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read test2json: %w", err)
	}
	return res, nil
}

func applyEvent(res Results, ev testEvent, lastOut map[string]string) {
	if ev.Package == "" {
		return
	}
	p := res.pkg(ev.Package)
	key := ev.Package + "\x00" + ev.Test
	switch ev.Action {
	case "output":
		if ev.Test != "" && !strings.Contains(ev.Test, "/") {
			if s := strings.TrimSpace(ev.Output); s != "" && !strings.HasPrefix(s, "=== ") && !strings.HasPrefix(s, "--- ") {
				if _, ok := lastOut[key]; !ok {
					lastOut[key] = s
				}
			}
		}
	case statusPass, statusFail, statusSkip:
		if ev.Test == "" {
			p.Status = worseStatus(p.Status, ev.Action)
			p.Elapsed += ev.Elapsed
			return
		}
		p.record(ev.Test, ev.Action, ev.Elapsed)
		if ev.Action == statusSkip && !strings.Contains(ev.Test, "/") {
			p.Tests[ev.Test].SkipNote = lastOut[key]
		}
	}
}

var (
	ghTimestamp = regexp.MustCompile(`^\d{4}-\d\d-\d\dT[0-9:.]+Z `)
	vResult     = regexp.MustCompile(`^\s*--- (PASS|FAIL|SKIP): (\S+) \(([0-9.]+)s\)\s*$`)
	vPkgOK      = regexp.MustCompile(`^ok {2}\t(\S+)\t([0-9.]+)s`)
	vPkgFail    = regexp.MustCompile(`^FAIL\t(\S+)(?:\t([0-9.]+)s| \[)`)
	vPkgNoTests = regexp.MustCompile(`^\? {3}\t(\S+)\t\[no test files\]`)
	vPkgCovOnly = regexp.MustCompile(`^\t(\S+)\t\tcoverage: `)
)

// parseVerboseLog reads the unsharded reference's `go test -v ./...` text log
// (qa-logic's logic.log). With more than one package `go test` BUFFERS each
// package's output and prints it contiguously, ending with that package's
// ok/FAIL line, so result lines are attributed to the package whose terminal
// line closes their block. An optional Actions timestamp prefix is stripped so
// the same parser reads a downloaded job log.
func parseVerboseLog(r io.Reader) (Results, error) {
	res := Results{}
	type pending struct {
		test, status string
		sec          float64
	}
	var buf []pending
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for sc.Scan() {
		line := ghTimestamp.ReplaceAllString(sc.Text(), "")
		if m := vResult.FindStringSubmatch(line); m != nil {
			sec, _ := strconv.ParseFloat(m[3], 64)
			buf = append(buf, pending{m[2], strings.ToLower(m[1]), sec})
			continue
		}
		pkg, status, elapsed, ok := packageTerminal(line)
		if !ok {
			continue
		}
		p := res.pkg(pkg)
		p.Status = worseStatus(p.Status, status)
		p.Elapsed += elapsed
		for _, e := range buf {
			p.record(e.test, e.status, e.sec)
		}
		buf = nil
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read log: %w", err)
	}
	if len(buf) > 0 {
		return nil, fmt.Errorf("log ends with %d result line(s) not closed by a package line — truncated log", len(buf))
	}
	return res, nil
}

func packageTerminal(line string) (pkg, status string, elapsed float64, ok bool) {
	if m := vPkgOK.FindStringSubmatch(line); m != nil {
		e, _ := strconv.ParseFloat(m[2], 64)
		return m[1], statusPass, e, true
	}
	if m := vPkgFail.FindStringSubmatch(line); m != nil {
		e, _ := strconv.ParseFloat(m[2], 64)
		return m[1], statusFail, e, true
	}
	if m := vPkgNoTests.FindStringSubmatch(line); m != nil {
		return m[1], statusPass, 0, true
	}
	if m := vPkgCovOnly.FindStringSubmatch(line); m != nil {
		return m[1], statusPass, 0, true
	}
	return "", "", 0, false
}

// sortedKeys returns m's keys in order, for deterministic reports.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
