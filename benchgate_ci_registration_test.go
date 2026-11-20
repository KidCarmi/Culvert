package main

// benchgate_ci_registration_test.go — the registration wall for the
// allocation-regression gates.
//
// ── WHY THIS EXISTS ─────────────────────────────────────────────────────────
//
// The `benchgate` build tag holds this repository's PERFORMANCE contracts: the
// per-op allocation and scaling bounds on the proxy, policy, admission, scan
// and session hot paths (TestBenchGate_* in //go:build benchgate files). They
// are deliberately OUTSIDE the default `go test ./...` build, so the only thing
// that ever executes them is an explicit, hand-written command in CI:
//
//	go test -tags benchgate -run 'TestBenchGate_' -count=1 -p 1 … . ./internal/admission …
//
// That command names its packages POSITIONALLY. Nothing in the Go toolchain
// relates the list to the set of packages that actually define a gate, so a new
// gate added to a package the list does not name compiles, passes locally under
// `go test -tags benchgate ./...`, and is then never executed by CI again.
//
// That failure is silent in the WORST direction. A dark allocation gate does
// not go red; it goes absent, while the tree still carries the gate file, the
// measured ns/op table in its doc comment and a PR check named `benchgate`
// reporting success. The team keeps believing the hot path is bounded, and the
// regression the gate was written to catch ships. An unprotected hot path is
// recoverable; an unprotected hot path that reports itself protected is not.
//
// TestAdmissionMigration_BenchgateSelectors (admission_contract_test.go) pins
// the SHAPE of that command — the tag, the -run selector, -count=1 — and pins
// two of its packages, `.` and `./internal/admission`, because those two are
// what the admission migration moved. It is not a registration check: the other
// nine packages in the list today are unpinned, so deleting one from all three
// workflows leaves every test in the tree green.
//
// This file closes that gap by DERIVING the expected list from the source
// instead of restating it. The precedent is in the same file as the test above:
// coverageFloorFixtureFiles was changed to read coverage-floor.sh's own FLOORS
// table for exactly this reason, after a restated copy drifted and two rows
// (internal/ssrf, internal/hostutil) measured 0.0% against a list that had
// moved on. The benchgate package list is the same hazard with a quieter
// failure, because a missing coverage row fails the build and a missing
// benchgate row does not.
//
// ── WHAT IT ASSERTS ─────────────────────────────────────────────────────────
//
// Set EQUALITY, in both directions, against all three shipped entry points:
//
//   - every package that defines a TestBenchGate_ in a benchgate-tagged file is
//     named by each command (a gate CI never runs), and
//   - every package each command names defines such a gate (a stale entry — a
//     package whose gate was deleted or moved, where `-run 'TestBenchGate_'`
//     matches nothing and reports ok with no tests to run).
//
// Both directions are real. The first is the dark-gate case above. The second
// is how a list stops meaning what it says: `go test -run` on a package with no
// matching test is a PASS, so a stale entry is indistinguishable from a
// satisfied one in the log.
//
// Adding a gate to a new package therefore requires one edit to each workflow,
// and this test names the exact command and package when it is forgotten. It
// asserts nothing about the gates' own bounds and changes no runtime behavior.

import (
	"fmt"
	"go/build/constraint"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// benchgateEntryPoints are the three shipped commands that execute the gates,
// as (workflow file, job name). The job names differ per workflow and are the
// same ones TestAdmissionMigration_BenchgateSelectors drives, so a renamed job
// fails here loudly (qaJobStepsIn rejects a job with no steps) rather than
// quietly checking nothing.
var benchgateEntryPoints = map[string]string{
	"pr-fast-gate.yml":        "benchgate",
	"qa-gate.yml":             "qa-bench",
	"proxy-weekly-stress.yml": "benchgate",
}

// benchgateGateFunc is the prefix the CI `-run` selector matches. Declared once
// so the discovery below and the selector stay the same string.
const benchgateGateFunc = "func TestBenchGate_"

// fileSelectedUnderBenchgate reports whether src — the contents of a Go file —
// is selected by the toolchain when `-tags benchgate` is passed, and NOT
// selected without it. The second half is what makes the answer meaningful: an
// untagged file is selected under `-tags benchgate` too, and such a file's
// tests already run in the default `go test ./...`, so its package needs no
// entry in the CI list.
//
// The constraint is evaluated with go/build/constraint rather than matched as
// text because the tree carries compound forms — `proxystress || proxybinload
// || benchgate`, `race && benchgate`, `race && (proxystress || … )` — where a
// substring test cannot tell a file that NEEDS the tag from one that merely
// mentions it, and cannot read a negation (`!benchgate`) at all.
//
// `race` is evaluated BOTH ways and either outcome counts. No shipped workflow
// currently runs the gates under -race, but the tree carries `race &&
// benchgate` companion files (internal/threatfeed/race_on_test.go, which lets
// the ns/op gate step aside under the detector), and a package whose gate lives
// behind that pairing must still be discovered. Pinning `race` to false would
// make this discovery depend on a CI flag that is free to change, which is the
// coupling this file exists to remove.
//
// Every other tag is false, which is the conservative direction: it can only
// under-report a file that requires a second tag nobody passes, and such a file
// is already dark for a reason this list cannot fix.
func fileSelectedUnderBenchgate(src string) bool {
	line, ok := buildConstraintLine(src)
	if !ok {
		return false // no constraint: selected either way, so not benchgate-only
	}
	expr, err := constraint.Parse(line)
	if err != nil {
		return false
	}
	eval := func(benchgate, race bool) bool {
		return expr.Eval(func(tag string) bool {
			switch tag {
			case "benchgate":
				return benchgate
			case "race":
				return race
			}
			return false
		})
	}
	withTag := eval(true, false) || eval(true, true)
	withoutTag := eval(false, false) || eval(false, true)
	return withTag && !withoutTag
}

// buildConstraintLine returns the file's //go:build line. Only the prologue —
// the lines before the package clause — is considered, because a `//go:build`
// string appearing later in a file is documentation (this tree has several,
// including in the test that pins tag handling) and not a constraint.
func buildConstraintLine(src string) (string, bool) {
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			return "", false
		}
		if constraint.IsGoBuild(trimmed) {
			return trimmed, true
		}
	}
	return "", false
}

// discoverBenchgatePackages walks the module and returns the `go test` package
// arguments — "." for the root, "./internal/x" below it — of every package that
// defines a TestBenchGate_ in a benchgate-tagged file.
//
// third_party is skipped because it is vendored code this repository does not
// gate, and testdata/ because the toolchain itself ignores it.
func discoverBenchgatePackages(t *testing.T) []string {
	t.Helper()
	root := pkgSourceDir()
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "third_party", "vendor", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		raw, rerr := os.ReadFile(path) // #nosec G304 G122 -- walking this repository's own checked-in sources; no untrusted symlinks
		if rerr != nil {
			return rerr
		}
		src := string(raw)
		if !strings.Contains(src, benchgateGateFunc) || !fileSelectedUnderBenchgate(src) {
			return nil
		}
		rel, rerr := filepath.Rel(root, filepath.Dir(path))
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			found["."] = true
		} else {
			found["./"+filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(found) == 0 {
		t.Fatal("no benchgate-tagged TestBenchGate_ packages discovered — the discovery is broken, not the tree")
	}
	return sortedKeys(found)
}

// benchgateCommandPackages extracts the package arguments from the single
// `go test … -tags benchgate … -run 'TestBenchGate_' …` command in body.
//
// A package argument is a field beginning with "." — the two shapes `go test`
// accepts here, "." and "./internal/x". That excludes every flag, and excludes
// the weekly workflow's trailing `2>&1 | tee benchgate.log`, whose fields begin
// with a digit and a pipe. Requiring EXACTLY one matching command is part of
// the assertion: a second one would mean a job runs the gates twice with two
// lists that can disagree, and zero means the selector this test navigates by
// has moved.
func benchgateCommandPackages(body string) ([]string, error) {
	var cmds [][]string
	for _, line := range strings.Split(body, "\n") {
		if !strings.Contains(line, "go test") || !strings.Contains(line, "-tags benchgate") {
			continue
		}
		if !strings.Contains(line, "'TestBenchGate_'") {
			continue
		}
		var pkgs []string
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, ".") {
				pkgs = append(pkgs, f)
			}
		}
		cmds = append(cmds, pkgs)
	}
	if len(cmds) != 1 {
		return nil, fmt.Errorf("want exactly 1 benchgate command, found %d", len(cmds))
	}
	if len(cmds[0]) == 0 {
		return nil, fmt.Errorf("benchgate command names no packages")
	}
	sort.Strings(cmds[0])
	return cmds[0], nil
}

// missingFrom returns the elements of want that are absent from got.
func missingFrom(want, got []string) []string {
	have := map[string]bool{}
	for _, g := range got {
		have[g] = true
	}
	var out []string
	for _, w := range want {
		if !have[w] {
			out = append(out, w)
		}
	}
	return out
}

// TestBenchgateRegistration_EveryGatedPackageIsRunByCI is the wall. It derives
// the package set from the source and requires each shipped command to name
// exactly that set.
func TestBenchgateRegistration_EveryGatedPackageIsRunByCI(t *testing.T) {
	discovered := discoverBenchgatePackages(t)
	for wf, job := range benchgateEntryPoints {
		t.Run(wf, func(t *testing.T) {
			var body string
			for _, step := range qaJobStepsIn(t, filepath.Join(pkgSourceDir(), ".github", "workflows", wf), job) {
				body += shellCodeOnly(toStr(step["run"])) + "\n"
			}
			listed, err := benchgateCommandPackages(body)
			if err != nil {
				t.Fatalf("%s job %q: %v", wf, job, err)
			}
			if dark := missingFrom(discovered, listed); len(dark) > 0 {
				t.Errorf("%s job %q does NOT run the allocation gate for %v.\n"+
					"Those packages define TestBenchGate_ in a benchgate-tagged file, so the gate exists, "+
					"compiles and passes locally — and CI never executes it. Add them to the `go test -tags benchgate` "+
					"command in .github/workflows/%s (and the other two entry points).",
					wf, job, dark, wf)
			}
			if stale := missingFrom(listed, discovered); len(stale) > 0 {
				t.Errorf("%s job %q names %v, which define no TestBenchGate_ in a benchgate-tagged file.\n"+
					"`go test -run` on a package with no matching test PASSES, so these entries report a gate "+
					"that is not there. Remove them, or restore the gate they were added for.",
					wf, job, stale)
			}
		})
	}
}

// TestBenchgateRegistration_DetectsDrift is the negative control, and it is the
// reason this file is worth its length: it proves the wall above would actually
// have caught the omission it is written against.
//
// It must NOT mutate the real workflows — the gates would stop running — so it
// perturbs a COPY of the command body in memory, exactly as
// TestAdmissionMigration_BenchgateSelectors perturbs its own.
func TestBenchgateRegistration_DetectsDrift(t *testing.T) {
	discovered := discoverBenchgatePackages(t)
	path := filepath.Join(pkgSourceDir(), ".github", "workflows", "pr-fast-gate.yml")
	var body string
	for _, step := range qaJobStepsIn(t, path, "benchgate") {
		body += shellCodeOnly(toStr(step["run"])) + "\n"
	}
	// Positive control: unperturbed, the real body agrees with the source.
	listed, err := benchgateCommandPackages(body)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if dark := missingFrom(discovered, listed); len(dark) > 0 {
		t.Fatalf("baseline already disagrees on %v — fix the registration first", dark)
	}

	// Drop each listed package in turn. Every one must be detected, not just
	// the two the admission test happens to pin.
	for _, pkg := range listed {
		if pkg == "." {
			continue // "." is a prefix of "./internal/…"; covered by the shape test below
		}
		t.Run("dropped "+pkg, func(t *testing.T) {
			broken := strings.ReplaceAll(body, " "+pkg+" ", " ")
			broken = strings.ReplaceAll(broken, " "+pkg+"\n", "\n")
			got, berr := benchgateCommandPackages(broken)
			if berr != nil {
				t.Fatalf("perturbed body no longer parses: %v", berr)
			}
			if len(missingFrom(discovered, got)) == 0 {
				t.Errorf("dropping %s from the command was NOT detected — the wall does not hold", pkg)
			}
		})
	}

	// A package that does not exist must be rejected too: a typo ("./internal/sessions")
	// silently gates nothing, because -run matches no test there.
	t.Run("bogus package", func(t *testing.T) {
		broken := strings.ReplaceAll(body, "-tags benchgate", "-tags benchgate ./internal/nosuchpkg")
		got, berr := benchgateCommandPackages(broken)
		if berr != nil {
			t.Fatalf("perturbed body no longer parses: %v", berr)
		}
		if len(missingFrom(got, discovered)) == 0 {
			t.Error("a package with no gate was accepted — stale entries would go unnoticed")
		}
	})

	// Stripping every package argument must be refused rather than read as an
	// empty, trivially satisfied set. Built by removing the packages the real
	// command names, so it cannot drift away from that command's spelling.
	noPackages := body
	for _, pkg := range listed {
		noPackages = strings.ReplaceAll(noPackages, " "+pkg+" ", " ")
		noPackages = strings.ReplaceAll(noPackages, " "+pkg+"\n", "\n")
	}

	// The command must still be found by its tag and selector: losing either is
	// how a job keeps its name and stops running the gates. "commented out" is
	// routed through shellCodeOnly because that is what the production reader
	// does — a commented command must vanish before parsing, not be parsed and
	// then excused.
	for name, broken := range map[string]string{
		"missing tag":        strings.ReplaceAll(body, "-tags benchgate", ""),
		"wrong selector":     strings.ReplaceAll(body, "'TestBenchGate_'", "'TestMissing_'"),
		"duplicated command": body + body,
		"commented out":      shellCodeOnly(strings.ReplaceAll(body, "go test -tags benchgate", "# go test -tags benchgate")),
		"no packages left":   noPackages,
	} {
		t.Run(name, func(t *testing.T) {
			if _, berr := benchgateCommandPackages(broken); berr == nil {
				t.Errorf("accepted %s", name)
			}
		})
	}
}

// TestBenchgateRegistration_ConstraintEvaluation pins the tag reasoning the
// discovery depends on, against the compound forms actually present in the tree.
// Without this, a discovery that silently stopped recognising `race &&
// benchgate` would report an empty-ish set and the wall would pass by finding
// nothing to check.
func TestBenchgateRegistration_ConstraintEvaluation(t *testing.T) {
	const body = "\npackage main\n\nfunc TestBenchGate_X(t *testing.T) {}\n"
	for name, tc := range map[string]struct {
		prologue string
		selected bool
	}{
		"plain benchgate":       {"//go:build benchgate", true},
		"race and benchgate":    {"//go:build race && benchgate", true},
		"or with stress tags":   {"//go:build proxystress || proxybinload || benchgate", true},
		"race and parenthesis":  {"//go:build race && (proxystress || proxybinload || benchgate)", true},
		"negated benchgate":     {"//go:build !benchgate", false},
		"unrelated tag only":    {"//go:build proxystress", false},
		"no constraint at all":  {"", false},
		"mentioned after code":  {"\npackage main\n// //go:build benchgate", false},
		"unsatisfiable without": {"//go:build benchgate && !benchgate", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := fileSelectedUnderBenchgate(tc.prologue + body); got != tc.selected {
				t.Errorf("fileSelectedUnderBenchgate(%q) = %v, want %v", tc.prologue, got, tc.selected)
			}
		})
	}
}
