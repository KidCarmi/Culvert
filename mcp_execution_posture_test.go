package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The MCP execution-posture wall.
//
// ADR-0024 ships the MCP Agent Security Gateway disabled by default, and the
// guarded-execution plane is the part that must stay off: an executing rollout
// mode (Shadow / Canary / Production) drives a real executor, a bounded upstream
// client, a credential broker and the inspection/DLP plane, and activating one
// against the shipped Observe-only composition would claim a contract the process
// cannot satisfy. Today three independent facts keep it off:
//
//  1. nothing calls markGatewayExecDepsReady / markManagementExecDepsReady, so
//     execDepsConfigured is false for both capabilities and every executing-mode
//     transition fails closed at the commit gate;
//  2. nothing assigns runtime.Deps.Executor, so the pipeline composes no executor;
//  3. nothing outside internal/mcp/execution imports that package at all.
//
// Each of those is an ABSENCE, and an absence is the one property no unit test
// observes: every package test passes just as well after the wiring is added.
// Arming execution is a deliberate, separately-reviewed activation — this file
// makes it impossible to do ACCIDENTALLY, by failing the build the moment any of
// the three facts stops holding.
//
// This is not a prohibition on ever shipping execution. It is the marker that
// doing so is a decision: whoever arms it must edit this wall, and that edit is
// what a reviewer sees.
//
// AST-based rather than grep-based, deliberately: a string search matches comments
// and test files, which is exactly how a documentation-only control passes for a
// real one (the DEBT-011 lesson from internal/mcp/runtime/limits_ownership_test.go).

// execArmingHooks are the registration hooks that switch guarded execution on.
var execArmingHooks = map[string]bool{
	"markGatewayExecDepsReady":    true,
	"markManagementExecDepsReady": true,
}

// execPackagePath is the guarded-execution plane. Nothing outside it may import it
// while the shipped posture is Observe-only.
const execPackagePath = "github.com/KidCarmi/Culvert/internal/mcp/execution"

// productionGoFiles yields every non-test .go file of the main module, with the
// vendored, generated and separately-moduled trees excluded.
func productionGoFiles(t *testing.T) []string {
	t.Helper()
	skipDirs := map[string]bool{
		".git": true, "node_modules": true, "vendor": true, "testdata": true,
		"frontend": true, // TypeScript/React; not part of this module
	}
	var out []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			// cmd/culvert-maint is a SEPARATE Go module with its own go.mod.
			if _, serr := os.Stat(filepath.Join(path, "go.mod")); serr == nil && path != "." {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(out) < 100 {
		// A walk that silently matched almost nothing would make every assertion below
		// vacuously true — the failure mode this whole file exists to prevent.
		t.Fatalf("only %d production files found; the wall is not scanning the tree", len(out))
	}
	return out
}

// parsedProductionFile is one parsed production source file, kept with the FileSet
// that owns its positions so an error message can still name a file and line.
type parsedProductionFile struct {
	path string
	fset *token.FileSet
	file *ast.File
}

// productionAST parses the module's production files ONCE for the whole package
// test binary and hands every gate the same trees.
//
// The three gates below are whole-module scans, and parsing the tree three times
// made this file the most expensive test in the root package for no added
// assurance: the parse is a pure function of files the test run never writes to,
// so a shared result is the same result. Comments are deliberately NOT parsed —
// none of the gates reads one, and the whole point of the AST approach is that a
// comment can never satisfy a check (see the note above).
//
// The walk's vacuity guard runs inside the once, and its outcome is replayed to
// every caller, so a tree that stops being scannable still fails all three gates
// rather than passing two of them vacuously.
var (
	productionASTOnce  sync.Once
	productionASTFiles []parsedProductionFile
	productionASTErr   error
)

func productionAST(t *testing.T) []parsedProductionFile {
	t.Helper()
	productionASTOnce.Do(func() {
		fset := token.NewFileSet()
		for _, path := range productionGoFiles(t) {
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				productionASTErr = fmt.Errorf("parse %s: %w", path, err)
				return
			}
			productionASTFiles = append(productionASTFiles, parsedProductionFile{path: path, fset: fset, file: f})
		}
	})
	if productionASTErr != nil {
		t.Fatal(productionASTErr)
	}
	return productionASTFiles
}

// TestExecPosture_ArmingHooksHaveNoProductionCaller pins fact (1).
//
// The hooks are defined in mcp_rollout_execdeps.go and documented as
// "intentionally UNCALLED in the current build". That is a comment; this is the
// check. A call from anywhere in production arms execDepsConfigured for that
// capability and makes every Shadow/Canary/Production transition succeed.
func TestExecPosture_ArmingHooksHaveNoProductionCaller(t *testing.T) {
	for _, pf := range productionAST(t) {
		fset := pf.fset
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			if execArmingHooks[name] {
				t.Errorf("%s: production code calls %s(), which arms guarded execution.\n"+
					"Guarded execution is disabled by default (ADR-0024) and arming it is a "+
					"separately-reviewed activation, not a side effect of another change. If this "+
					"call is intended, the activation review updates this wall.",
					fset.Position(call.Pos()), name)
			}
			return true
		})
	}
}

// TestExecPosture_NoProductionExecutorAssignment pins fact (2).
//
// runtime.Deps.Executor is the OPTIONAL guarded-execution provider; the pipeline
// composes an executor if and only if it is non-nil. Assigning it — as a struct
// field in a composite literal or by assignment — composes the execution plane
// regardless of rollout mode.
func TestExecPosture_NoProductionExecutorAssignment(t *testing.T) {
	report := func(fset *token.FileSet, pos token.Pos) {
		t.Errorf("%s: production code assigns Deps.Executor, composing the guarded-execution "+
			"plane. It must stay nil until execution is separately activated.", fset.Position(pos))
	}
	for _, pf := range productionAST(t) {
		// The field's own declaration and the pipeline's nil-guarded read are the two
		// legitimate mentions; neither is an assignment, so no exemption is needed.
		fset := pf.fset
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.KeyValueExpr:
				if k, ok := v.Key.(*ast.Ident); ok && k.Name == "Executor" {
					report(fset, v.Pos())
				}
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Executor" {
						report(fset, lhs.Pos())
					}
				}
			}
			return true
		})
	}
}

// TestExecPosture_ExecutionPackageHasNoProductionImporter pins fact (3).
//
// This is the broadest of the three and the one that cannot be worked around: an
// executor cannot be composed by code that cannot reference the package. It also
// catches an arming route the other two miss — a helper inside some other package
// that constructs and installs an executor itself.
func TestExecPosture_ExecutionPackageHasNoProductionImporter(t *testing.T) {
	for _, pf := range productionAST(t) {
		if strings.HasPrefix(filepath.ToSlash(pf.path), "internal/mcp/execution/") {
			continue // the package's own files
		}
		fset := pf.fset
		for _, imp := range pf.file.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if p == execPackagePath {
				t.Errorf("%s: production code imports %s.\nThe guarded-execution plane is "+
					"unwired by design (ADR-0024, Observe-only shipped composition); wiring it is a "+
					"separately-reviewed activation.", fset.Position(imp.Pos()), execPackagePath)
			}
		}
	}
}
