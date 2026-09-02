//go:build benchgate

package main

// Performance-regression gate for the single-pass sanitizeLog (proxy.go).
//
// Correctness contracts live in proxy_sanitizelog_test.go and run in the
// normal suite; this file holds the PERFORMANCE contract only, in the
// repository's benchgate convention:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v .
//
// Two gates, deliberately of different kinds, and NEITHER is timing-based:
//
//   - The ALLOCATION gates are absolute and hardware-independent. They catch
//     the regression that matters most — a rewrite that starts allocating on
//     clean input, which is 100% of ordinary traffic.
//   - The SCAN-COUNT gate is STRUCTURAL: it reads sanitizeLog's AST and
//     requires exactly one strings.ReplaceAll, as the first statement. That is
//     what fails if someone re-adds the redundant \r / \t passes or the
//     separate containsControl scan.
//
// ── Why the scan-count gate is structural and not a timing ratio ─────────────
//
// It was FIRST written as a ratio against the pre-change implementation timed
// in the same run, on the reasoning that a same-run ratio cancels out the
// hardware. That reasoning is wrong, and CI falsified it immediately (PR #1299,
// first run): the ratio is a function of how expensive strings.ReplaceAll's
// per-call overhead is RELATIVE to the scalar control-byte scan, and that
// varies enormously by CPU. On the development box the two removed ReplaceAll
// calls cost ~24 ns each, on the CI runner ~3 ns each:
//
//	shape       dev box  CI runner
//	15 B          0.49      0.60
//	57 B          0.57      0.90   <- failed a 0.80 bound
//
// Same code, same binary, ratio moved 0.33. Any bound loose enough to be safe
// on both is too loose to catch a reintroduction (the CI control measured 1.00
// at 57 B). This repo has hit exactly this wall before and recorded the
// conclusion each time — see internal/connlimit, internal/threatfeed and the
// latency histogram, where scaling-ratio gates were built, rejected, and
// replaced with structural ones because "a gate that can flake gets muted."
// The structural form is strictly better here anyway: it is deterministic on
// any hardware, under any load, with or without -race, AND it pins the CodeQL
// barrier's POSITION, which no timing gate could ever observe.
//
// The before/after numbers live in the benchmarks (proxy_sanitizelog_bench_test.go),
// which is where a measurement belongs — reproducible on demand, not asserted
// against a threshold that means different things on different machines.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestBenchGate_SanitizeLogCleanPathAllocFree pins the property the request
// path depends on: ordinary log values — rule names, hostnames, identities,
// matched conditions — carry no control bytes, and sanitising them must cost
// no allocation at all. handleRequest passes five such values per proxied
// request, so an allocating clean path is five heap objects per request on
// 100% of allowed traffic.
func TestBenchGate_SanitizeLogCleanPathAllocFree(t *testing.T) {
	clean := []string{
		"",
		"allow-corp-saas",
		"www.example.com",
		"user@corp.example",
		"destFQDN=*.example.com destCat=Business destCountry=US,CA",
		"https://cdn.example.com/" + strings.Repeat("segment/", 30) + "asset.js",
		strings.Repeat("x", 4096),
	}
	for _, in := range clean {
		in := in
		got := testing.AllocsPerRun(200, func() {
			sanitizeLogSink = sanitizeLog(in)
		})
		if got != 0 {
			t.Errorf("sanitizeLog(%d-byte clean input): %.1f allocs/op, want 0", len(in), got)
		}
	}
}

// TestBenchGate_SanitizeLogControlPathAllocBound bounds the scrub path. The
// pre-change form built one intermediate string per replaced class and then a
// final copy (4 allocs measured); the single-pass form takes the []byte copy
// and the string conversion only.
//
// The bound is 2 — the measured value — with the legacy shape measured in the
// same run as the control, so this fails both if the scrub path regresses AND
// if the comparison stops being meaningful.
func TestBenchGate_SanitizeLogControlPathAllocBound(t *testing.T) {
	const dirty = "bad\nrule\rname\twith\x01controls"
	after := testing.AllocsPerRun(200, func() {
		sanitizeLogSink = sanitizeLog(dirty)
	})
	if after > 2 {
		t.Errorf("sanitizeLog on control-carrying input: %.1f allocs/op, want <= 2", after)
	}
	before := testing.AllocsPerRun(200, func() {
		sanitizeLogSink = legacySanitizeLog(dirty)
	})
	if after >= before {
		t.Errorf("scrub path did not improve: after %.1f allocs/op, before %.1f", after, before)
	}
}

// sanitizeLogSourceFile is the file the structural gate reads. Kept as a
// constant so a move renames one thing rather than leaving the gate silently
// looking for a function that is no longer there (the parse failure below is
// a hard error for the same reason).
const sanitizeLogSourceFile = "proxy.go"

// TestBenchGate_SanitizeLogScansInputOnce is the structural gate, and it is
// what actually locks the change in.
//
// The pre-change form scanned every string FOUR times (three
// strings.ReplaceAll plus containsControl). Reintroducing any of those passes
// is invisible to an allocation gate — they are all allocation-free on clean
// input — and, as the file header explains, is NOT reliably visible to a
// timing ratio either, because the cost of a ReplaceAll call relative to the
// scalar scan swings by an order of magnitude between CPUs.
//
// So it is asserted where it is actually decidable: in the source. Two
// properties, both load-bearing and neither observable at runtime.
//
//  1. EXACTLY ONE strings.ReplaceAll. Three is the pre-change shape; the
//     redundancy argument (\n, \r and \t are all < 0x20 and every branch maps
//     to the same byte '_') is what licenses removing two of them.
//  2. It is the FIRST statement, so it is on every return path. This is the
//     CWE-117 barrier CodeQL's go/log-injection query recognises, and CodeQL
//     runs on PRs touching proxy.go — a rewrite that returns the input from
//     above this line, or drops the call as "vestigial", risks turning every
//     logger.Printf(..., sanitizeLog(x)) in the tree into an alert.
//
// The repository already gates on ASTs where behaviour is not observable at
// runtime (ui_routes_meta_audit_test.go, C1.5), so this is the house pattern
// rather than a new one.
func TestBenchGate_SanitizeLogScansInputOnce(t *testing.T) {
	fn := parseFuncDecl(t, sanitizeLogSourceFile, "sanitizeLog")
	for _, problem := range singlePassSanitizerProblems(fn, "sanitizeLog", sanitizeLogSourceFile) {
		t.Error(problem)
	}
}

// TestBenchGate_SanitizeLogScanGateRejectsTheFourScanShape is the CONTROL: a
// gate that cannot fail is decorative, and a structural gate is especially
// prone to that failure mode (a selector typo makes it match nothing and pass
// forever). It runs the SAME predicate against legacySanitizeLog — the verbatim
// pre-change implementation kept in proxy_sanitizelog_test.go as the
// differential oracle — and requires it to be REJECTED.
//
// Using the real pre-change source rather than a hand-built fixture is the
// point: this proves the gate rejects the exact shape it exists to keep out.
func TestBenchGate_SanitizeLogScanGateRejectsTheFourScanShape(t *testing.T) {
	const oracleFile = "proxy_sanitizelog_test.go"
	fn := parseFuncDecl(t, oracleFile, "legacySanitizeLog")
	problems := singlePassSanitizerProblems(fn, "legacySanitizeLog", oracleFile)
	if len(problems) == 0 {
		t.Fatal("the scan-count gate accepts the four-scan implementation it exists to reject — " +
			"the predicate matches nothing and would pass on any code")
	}
	t.Logf("control rejected the pre-change shape as expected: %v", problems)
}

// parseFuncDecl returns the named top-level function's declaration from file.
func parseFuncDecl(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name {
			return fd
		}
	}
	t.Fatalf("%s: func %s not found — if it was renamed or moved, update this gate rather than deleting it", file, name)
	return nil
}

// singlePassSanitizerProblems checks the two structural properties described on
// TestBenchGate_SanitizeLogScansInputOnce and RETURNS what is wrong rather than
// failing directly, so the control test above can assert that the predicate
// rejects the pre-change shape.
func singlePassSanitizerProblems(fn *ast.FuncDecl, name, file string) []string {
	var problems []string
	if fn.Body == nil || len(fn.Body.List) == 0 {
		return []string{file + ": " + name + " has an empty body"}
	}

	// (1) Exactly one strings.ReplaceAll in the whole body.
	var replaceAlls []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ReplaceAll" {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "strings" {
				replaceAlls = append(replaceAlls, call)
			}
		}
		return true
	})
	if len(replaceAlls) != 1 {
		return append(problems, fmt.Sprintf("%s: %s makes %d strings.ReplaceAll calls, want exactly 1. "+
			"Three was the pre-change shape and scanned the input three extra times; "+
			"\\n, \\r and \\t are all < 0x20 and all map to '_', so the single control-byte "+
			"pass already covers them. Zero would drop the CWE-117 barrier CodeQL recognises.",
			file, name, len(replaceAlls)))
	}

	// (2) It is the first statement, so it is on every return path.
	first, ok := fn.Body.List[0].(*ast.AssignStmt)
	if !ok || len(first.Rhs) != 1 || first.Rhs[0] != replaceAlls[0] {
		problems = append(problems, fmt.Sprintf("%s: %s's first statement is not the strings.ReplaceAll assignment. "+
			"It must come first so every return path is downstream of it — that is what "+
			"keeps CodeQL's go/log-injection query recognising this function as a sanitiser.",
			file, name))
	}
	return problems
}
