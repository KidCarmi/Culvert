//go:build lifecycle_conformance

package lifecyclemodel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Exit codes of the property gate.
const (
	ExitPass       = 0 // exploration complete, nothing vacuous, no counted failure
	ExitFail       = 1 // a counted property fails
	ExitIncomplete = 2 // incomplete exploration, a vacuous property or an unusable property file
	// ExitDrift: everything else passed, but the modelled behaviour differs from the reviewed
	// baseline (baseline.go). Never masks 1 or 2: drift is reported alongside them.
	ExitDrift = 3
)

// GateOptions configures RunGate.
type GateOptions struct {
	IncludeProposed  bool          // evaluate `proposed` properties as well as `approved` ones
	FailOnlyApproved bool          // a FAIL counts towards ExitFail only for an `approved` property
	MaxStates        int           // state budget
	MaxDuration      time.Duration // time budget
	ReportDir        string        // if set, write model_check.json here
	// Baseline, when non-nil, is a reviewed baseline.json to compare against. An empty or
	// unparsable baseline is INCOMPLETE, never "no drift".
	Baseline []byte
	// WriteBaseline, when set, writes the current baseline to this path instead of
	// comparing. Refused for an incomplete or vacuous run.
	WriteBaseline string
}

// Report is the content of model_check.json.
type Report struct {
	PropsSHA256 string   `json:"props_sha256"`
	Stats       Stats    `json:"stats"`
	Results     []Result `json:"results"`
	// BaselineChecked says whether the run was compared with a reviewed baseline at all, so
	// a summary can never present "no drift lines" from an unchecked run as "no drift".
	BaselineChecked bool     `json:"baseline_checked"`
	Drift           []string `json:"drift"`
}

// ModelCheckFile is the report file name inside a report directory.
const ModelCheckFile = "model_check.json"

// GateExit decides the exit code from the verdicts. INCOMPLETE and VACUOUS take
// precedence over FAIL and are never downgraded: a run with a failing unapproved
// property and a vacuous one is incomplete, not a pass and not a plain failure.
// `open` properties never count as failures; with failOnlyApproved neither do
// `proposed` ones.
func GateExit(results []Result, failOnlyApproved bool) int {
	exit := ExitPass
	for i := range results {
		r := &results[i]
		switch {
		case r.Verdict == VerdictVacuous:
			return ExitIncomplete
		case r.Verdict == VerdictFail && failCounts(r.Status, failOnlyApproved):
			exit = ExitFail
		}
	}
	return exit
}

func failCounts(status string, failOnlyApproved bool) bool {
	if failOnlyApproved {
		return status == StatusApproved
	}
	return status != StatusOpen
}

// outf prints to w. A failed write to the report stream cannot be reported anywhere
// more useful, and never changes the exit code.
func outf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// selectProperties returns the enforced properties followed by the open ones.
func selectProperties(all []Property, includeProposed bool) (enforced, open []Property) {
	for i := range all {
		switch s := all[i].Status; {
		case s == StatusApproved, s == StatusProposed && includeProposed:
			enforced = append(enforced, all[i])
		case s == StatusOpen:
			open = append(open, all[i])
		}
	}
	return enforced, open
}

// RunGate checks the apply-flow model against the properties in raw (a property file's
// bytes), prints one line per property to w and returns the exit code.
func RunGate(raw []byte, o GateOptions, w io.Writer) int {
	all, sha, err := ParseProperties(raw)
	if err != nil {
		outf(w, "INCOMPLETE: %v -- refusing to report a pass\n", err)
		return ExitIncomplete
	}
	enforced, open := selectProperties(all, o.IncludeProposed)
	results, stats, err := Check[State](Model{}, append(enforced, open...), o.MaxStates, o.MaxDuration)
	if err != nil {
		if !errors.Is(err, ErrIncomplete) {
			err = fmt.Errorf("%w: %w", ErrIncomplete, err)
		}
		outf(w, "INCOMPLETE: %v -- refusing to report a pass\n", strings.TrimPrefix(err.Error(), "incomplete: "))
		return ExitIncomplete
	}
	fail, uncounted, vac := printResults(w, results, o.FailOnlyApproved)
	if len(enforced) == 0 {
		outf(w, "NOTE: no property is enforced (none approved). Use -include-proposed to evaluate proposals.\n")
	}
	if uncounted > 0 {
		outf(w, "NOTE: %d PROPOSED (not owner-approved) propert(ies) fail; reported, not counted as a failure\n", uncounted)
	}
	outf(w, "%d states, %d transitions, %d enforced, %d open (reported, never gating), %d failed, %d vacuous; props sha256 %s\n",
		stats.States, stats.Transitions, len(enforced), len(open), fail, vac, sha[:16])
	exit := GateExit(results, o.FailOnlyApproved)
	rep := Report{PropsSHA256: sha, Stats: stats, Results: results, Drift: []string{}}
	if o.WriteBaseline != "" {
		return writeBaseline(w, o.WriteBaseline, exit, ComputeBaseline(sha, stats, results))
	}
	if o.Baseline != nil && !o.IncludeProposed {
		// The baseline is recorded with proposed properties evaluated; comparing a run that
		// skips them would report every one of them as drift.
		outf(w, "NOTE: baseline NOT CHECKED: it records proposed properties; compare with -include-proposed\n")
		o.Baseline = nil
	}
	if o.Baseline != nil {
		drift, err := baselineDrift(o.Baseline, ComputeBaseline(sha, stats, results))
		if err != nil {
			outf(w, "INCOMPLETE: %v -- refusing to report a pass\n", err)
			return ExitIncomplete
		}
		rep.BaselineChecked, rep.Drift = true, drift
		exit = driftExit(w, exit, drift)
	}
	if o.ReportDir != "" {
		if err := writeReport(o.ReportDir, rep); err != nil {
			outf(w, "INCOMPLETE: cannot write report: %v\n", err)
			return ExitIncomplete
		}
	}
	return exit
}

func baselineDrift(raw []byte, got Baseline) ([]string, error) {
	want, err := ParseBaseline(raw)
	if err != nil {
		return nil, err
	}
	d := CompareBaseline(want, got)
	if d == nil {
		d = []string{}
	}
	return d, nil
}

// driftExit prints the drift and folds it into the exit code: drift turns a pass into
// ExitDrift and leaves a failure or an incomplete run as it is.
func driftExit(w io.Writer, exit int, drift []string) int {
	if len(drift) == 0 {
		outf(w, "baseline: no drift from the reviewed baseline\n")
		return exit
	}
	for _, l := range drift {
		outf(w, "DRIFT   %s\n", l)
	}
	outf(w, "DRIFT: the modelled behaviour differs from the reviewed baseline. If the change is intended, run "+
		"test/lifecycle-conformance/update-baseline.sh in this pull request and review the baseline.json diff.\n")
	if exit == ExitPass {
		return ExitDrift
	}
	return exit
}

func writeBaseline(w io.Writer, path string, exit int, b Baseline) int {
	switch exit {
	case ExitIncomplete:
		outf(w, "INCOMPLETE: refusing to record a baseline from an incomplete or vacuous run\n")
		return ExitIncomplete
	case ExitFail:
		outf(w, "FAIL: refusing to record a baseline while a counted property fails\n")
		return ExitFail
	}
	if err := WriteBaselineFile(path, b); err != nil {
		outf(w, "INCOMPLETE: cannot write baseline: %v\n", err)
		return ExitIncomplete
	}
	outf(w, "baseline written to %s (%d properties, %d apply / %d crash vectors, %d reconcile inputs)\n",
		path, len(b.Properties), len(b.Apply), len(b.Crash), b.Reconcile.Inputs)
	return ExitPass
}

// printResults prints one line per property (plus the trace of each FAIL) and returns
// the number of counted failures, uncounted proposed failures and vacuous properties.
func printResults(w io.Writer, results []Result, failOnlyApproved bool) (fail, uncounted, vac int) {
	for i := range results {
		r := &results[i]
		tag := "ok     "
		switch {
		case r.Verdict == VerdictVacuous:
			tag = "VACUOUS"
			vac++
		case r.Verdict == VerdictFail && r.Status == StatusOpen:
			tag = "OPEN   "
		case r.Verdict == VerdictFail:
			tag = "FAIL   "
			if failCounts(r.Status, failOnlyApproved) {
				fail++
			} else {
				uncounted++
			}
		}
		outf(w, "%s %-5s [%-10s] %s\n", tag, r.ID, r.Kind, r.Text)
		if r.Verdict == VerdictFail {
			outf(w, "        trace: %s\n", strings.Join(r.Trace, " -> "))
		}
	}
	return fail, uncounted, vac
}

func writeReport(dir string, rep Report) error {
	b, err := json.MarshalIndent(rep, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ModelCheckFile), append(b, '\n'), 0o600)
}

// WriteSummary renders the shadow run in dir as Markdown for the GitHub step summary.
// A missing or unreadable report is stated as INCOMPLETE, never as a pass.
func WriteSummary(dir string, w io.Writer) {
	outf(w, "### Lifecycle conformance (shadow, non-blocking)\n\n")
	outf(w, "Verified against the real maintenance-agent code through a **fake** exec layer. "+
		"The model check alone verifies the abstraction, not the product.\n\n")
	if err := summarizeModelCheck(dir, w); err != nil {
		outf(w, "**Model check produced no usable result (%v). Treat this run as INCOMPLETE.**\n\n", err)
	}
	outf(w, "**Conformance against real code**\n\n")
	found := 0
	for _, name := range []string{"apply", "crash", "reconcile"} {
		var rep map[string]any
		if err := readJSON(filepath.Join(dir, "conformance_"+name+".json"), &rep); err != nil {
			outf(w, "- `%s`: **no report — suite did not complete**\n", name)
			continue
		}
		found++
		outf(w, "- `%s`: %s\n", name, scalarPairs(rep))
		if d, ok := rep["observed_drift"].([]any); ok && len(d) > 0 {
			outf(w, "  - **DRIFT (real code)** from the reviewed `observed.json`: %d line(s); see the job log\n", len(d))
		}
	}
	if found != 3 {
		outf(w, "\n**INCOMPLETE: fewer than three conformance suites reported. This is not a pass.**\n")
	}
}

func summarizeModelCheck(dir string, w io.Writer) error {
	var rep *Report
	if err := readJSON(filepath.Join(dir, ModelCheckFile), &rep); err != nil {
		return err
	}
	if rep == nil || rep.Results == nil {
		return errors.New("no results")
	}
	outf(w, "**Model check** — %d states, %d transitions\n\n", rep.Stats.States, rep.Stats.Transitions)
	outf(w, "| Property | Status | Verdict | Shortest counterexample |\n")
	outf(w, "|---|---|---|---|\n")
	for i := range rep.Results {
		x := &rep.Results[i]
		outf(w, "| %s %s | %s | %s | %s |\n", x.ID, x.Text, x.Status, x.Verdict, strings.Join(x.Trace, " → "))
	}
	outf(w, "\nA failing *proposed* or *open* property is reported for the owner; it does not fail this job.\n\n")
	switch {
	case !rep.BaselineChecked:
		outf(w, "**Baseline: NOT CHECKED.** This run says nothing about drift from the reviewed baseline.\n\n")
	case len(rep.Drift) == 0:
		outf(w, "**Baseline:** no drift from the reviewed `baseline.json`.\n\n")
	default:
		outf(w, "**Baseline: DRIFT.** The modelled behaviour differs from the reviewed `baseline.json`. "+
			"Intended? Regenerate it with `test/lifecycle-conformance/update-baseline.sh` and review the diff.\n\n```\n%s\n```\n\n",
			strings.Join(rep.Drift, "\n"))
	}
	return nil
}

func readJSON(path string, into any) error {
	b, err := os.ReadFile(path) //nolint:gosec // report directory chosen by the operator
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// scalarPairs renders the scalar members of a report as "k=v", sorted by key.
func scalarPairs(rep map[string]any) string {
	keys := make([]string, 0, len(rep))
	for k := range rep {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		switch v := rep[k].(type) {
		case float64:
			parts = append(parts, k+"="+strconv.FormatFloat(v, 'f', -1, 64))
		case string:
			parts = append(parts, k+"="+v)
		case bool:
			parts = append(parts, k+"="+strconv.FormatBool(v))
		}
	}
	return strings.Join(parts, ", ")
}
