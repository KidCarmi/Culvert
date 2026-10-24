package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── The one fixture for tests that reach the snapshot apply path ─────────────
//
// applySnapshotAdmission mutates the installed admission owners IN PLACE
// (RISK-030: it no longer swaps the ipf pointer): the filter's mode and entries
// are replaced through IPFilter.Replace, rl.Configure runs when the snapshot
// RPM differs from rl.Limit(), and rl.ReplaceExemptions runs when
// RateLimitExempt is non-nil. A test that saves the ipf/rl POINTERS, applies a
// snapshot and restores the pointers therefore restores the very objects the
// apply changed — a cleared filter, a zeroed limiter — into the shared root
// state, and a later test inherits them (order-dependent failures under
// -shuffle / -count). Codex review, PR #1635: one fixture did it right, the
// next did not; the class needs one helper and a wall, not per-file vigilance.

// bindFreshAdmissionOwners installs a fresh filter and a fresh limiter into the
// composition handles for the duration of the test and restores BOTH previous
// owners on cleanup. Every test that reaches the snapshot apply path — directly
// or through fetchAndApply, applyDeltaReply, applyHABundle or
// applyDPLastGoodConfigSnapshot — calls it before the first apply.
// TestSnapshotApplyFixture_Wall fails the build for one that does not.
func bindFreshAdmissionOwners(tb testing.TB) (filter *IPFilter, limiter *RateLimiter) {
	tb.Helper()
	oldIPF, oldRL := ipf, rl
	filter, limiter = newIPFilter(), newRateLimiter()
	ipf, rl = filter, limiter
	tb.Cleanup(func() { ipf, rl = oldIPF, oldRL })
	return filter, limiter
}

// snapshotApplyEntryPoints are the functions through which a test reaches
// applySnapshotAdmission: the apply slices themselves and every production
// caller of them that a root test can invoke.
var snapshotApplyEntryPoints = map[string]bool{
	"applyConfigSnapshot":                 true,
	"applySnapshotPolicyAndTraffic":       true,
	"applySnapshotTrafficExceptBlocklist": true,
	"applySnapshotAdmission":              true,
	"applyBlocklistDeltaSnapshot":         true,
	"fetchAndApply":                       true, // DataPlaneClient full/delta poll
	"applyDeltaReply":                     true, // DataPlaneClient delta reply
	"applyHABundle":                       true, // HA peer bundle apply
	"applyDPLastGoodConfigSnapshot":       true, // DP boot from last-good
}

const admissionFixtureName = "bindFreshAdmissionOwners"

// calleeNames reports the bare names of every function or method called
// anywhere inside fn, closures included.
func calleeNames(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			out[f.Name] = true
		case *ast.SelectorExpr:
			out[f.Sel.Name] = true
		}
		return true
	})
	return out
}

// testFuncCalls maps every function declared in files to the names it calls.
func testFuncCalls(files map[string]*ast.File) map[string]map[string]bool {
	calls := map[string]map[string]bool{}
	for _, file := range files {
		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				calls[fn.Name.Name] = calleeNames(fn)
			}
		}
	}
	return calls
}

// fixtureReachers is the set of declared functions that call the fixture,
// directly or through another declared function that does (a wrapper such as
// restoreBlAndIPF). Computed to a fixpoint.
func fixtureReachers(calls map[string]map[string]bool) map[string]bool {
	reach := map[string]bool{admissionFixtureName: true}
	for changed := true; changed; {
		changed = false
		for name, callees := range calls {
			if reach[name] {
				continue
			}
			for callee := range callees {
				if reach[callee] {
					reach[name] = true
					changed = true
					break
				}
			}
		}
	}
	return reach
}

// applyCallersWithoutFixture lists every declared function that calls a
// snapshot apply entry point without reaching the fixture.
func applyCallersWithoutFixture(calls map[string]map[string]bool) []string {
	reach := fixtureReachers(calls)
	var out []string
	for name, callees := range calls {
		if reach[name] {
			continue
		}
		for callee := range callees {
			if snapshotApplyEntryPoints[callee] {
				out = append(out, name+" → "+callee)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// parseRootTestFiles parses every _test.go file of package main, build tags
// included: a tagged lane's test leaks state exactly like a default one.
func parseRootTestFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	paths, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files[path] = file
	}
	if len(files) == 0 {
		t.Fatal("no root test files parsed; the wall is looking at the wrong directory")
	}
	return files
}

// TestSnapshotApplyFixture_Wall_EveryApplyCallerBindsFreshOwners fails the
// build for any root test function that reaches the snapshot apply path
// without binding fresh admission owners through bindFreshAdmissionOwners,
// directly or through a wrapper that does. The entry-point set covers the
// apply slices and every production caller a test can invoke.
func TestSnapshotApplyFixture_Wall_EveryApplyCallerBindsFreshOwners(t *testing.T) {
	calls := testFuncCalls(parseRootTestFiles(t))
	if _, ok := calls[admissionFixtureName]; !ok {
		t.Fatalf("%s is not declared in the root test files; the wall's anchor has gone stale", admissionFixtureName)
	}
	// Not-vacuous control: the production entry points must actually be
	// called somewhere in the suite, or the wall guards nothing.
	seen := 0
	for _, callees := range calls {
		for callee := range callees {
			if snapshotApplyEntryPoints[callee] {
				seen++
				break
			}
		}
	}
	if seen == 0 {
		t.Fatal("no root test calls a snapshot apply entry point; the wall's selector has gone stale")
	}
	if offenders := applyCallersWithoutFixture(calls); len(offenders) > 0 {
		t.Errorf("%d root test function(s) reach the snapshot apply path without %s: %v — the apply "+
			"mutates ipf and rl IN PLACE (RISK-030), so a saved pointer restores the mutated object and the "+
			"next test inherits a cleared filter or a zeroed limiter; call %s(t) before the first apply "+
			"(or route through a wrapper that does)", len(offenders), admissionFixtureName, offenders, admissionFixtureName)
	}
	assertApplyFixtureWallControls(t)
}

// assertApplyFixtureWallControls proves the predicate rejects the shapes it
// exists to reject and accepts the compliant ones, so a selector that matches
// nothing cannot pass forever.
func assertApplyFixtureWallControls(t *testing.T) {
	t.Helper()
	const src = `package main
func bindFreshAdmissionOwners(tb testing.TB) {}
func TestDirectNoFixture(t *testing.T) { applyConfigSnapshot(ConfigSnapshot{}) }
func TestDirectWithFixture(t *testing.T) { bindFreshAdmissionOwners(t); applyConfigSnapshot(ConfigSnapshot{}) }
func goodWrapper(t *testing.T) { bindFreshAdmissionOwners(t) }
func TestViaGoodWrapper(t *testing.T) { goodWrapper(t); applySnapshotAdmission(ConfigSnapshot{}) }
func badWrapper(t *testing.T) { _ = applyBlocklistDeltaSnapshot(ConfigSnapshot{}, nil, "") }
func TestViaBadWrapper(t *testing.T) { badWrapper(t) }
func TestIndirectMethod(t *testing.T) { c := &DataPlaneClient{}; c.fetchAndApply(nil) }
func TestClosure(t *testing.T) { go func() { _ = applyHABundle(nil, "") }() }
func TestUnrelated(t *testing.T) { _ = CurrentConfigSnapshot() }
`
	file, err := parser.ParseFile(token.NewFileSet(), "control_test.go", src, 0)
	if err != nil {
		t.Fatalf("parse control: %v", err)
	}
	got := applyCallersWithoutFixture(testFuncCalls(map[string]*ast.File{"control_test.go": file}))
	want := []string{
		"TestClosure → applyHABundle",
		"TestDirectNoFixture → applyConfigSnapshot",
		"TestIndirectMethod → fetchAndApply",
		"badWrapper → applyBlocklistDeltaSnapshot",
	}
	if strings.Join(got, ";") != strings.Join(want, ";") {
		t.Errorf("control: wall reported %v, want %v — the wall is matching the wrong thing", got, want)
	}
}
