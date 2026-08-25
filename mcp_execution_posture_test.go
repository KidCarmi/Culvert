package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The MCP execution-posture wall (EVOLVED for controlled Shadow activation).
//
// ADR-0024 ships the MCP Agent Security Gateway disabled by default. After Layer B
// (#1226) the guarded plane splits into TWO capabilities with very different postures,
// and this wall now pins that split rather than a blanket "no executor":
//
//   - The NON-EXECUTING Shadow evaluator (*execution.ShadowEvaluator) MAY be composed
//     in production, as runtime.Deps.Executor, so a controlled node can EVALUATE real
//     traffic. It holds no upstream client and no materialize-capable broker (Layer B),
//     so it can never cross the side-effect boundary.
//   - LIVE execution — the *execution.Executor, the UpstreamCaller, credential
//     Materialize — must stay OFF. Nothing may construct a live executor, and the
//     live-execution arming hooks must stay uncalled, so every Canary/Production
//     transition fails closed at the commit gate.
//
// The wall therefore pins these facts (each an ABSENCE that no unit test observes, so
// the build must fail the moment one stops holding):
//
//  1. nothing calls markGatewayExecDepsReady / markManagementExecDepsReady (the LIVE
//     arming hooks), so liveExecDepsConfigured is false and Canary/Production fail
//     closed. (markGateway/ManagementShadowDepsReady — the SHADOW hooks — MAY be called;
//     they arm only the non-executing evaluation tier.)
//  2. no production code references a LIVE-execution symbol of the execution package —
//     execution.New (the live constructor), execution.Executor, execution.Config,
//     execution.UpstreamCaller — so no live executor is ever constructed.
//  3. exactly ONE production file (mcp_shadow_startup.go) imports internal/mcp/execution,
//     and it references only the Shadow symbols; nothing else may import the package.
//  4. runtime.Deps.Executor is assigned in exactly that one file — the Shadow
//     composition — and nowhere else.
//
// Arming LIVE execution is a deliberate, separately-reviewed activation: whoever does
// it must edit this wall, and that edit is what a reviewer sees.
//
// AST-based rather than grep-based, deliberately: a string search matches comments
// and test files, which is exactly how a documentation-only control passes for a
// real one (the DEBT-011 lesson from internal/mcp/runtime/limits_ownership_test.go).

// execArmingHooks are the LIVE-execution registration hooks. The SHADOW hooks
// (markGateway/ManagementShadowDepsReady) are deliberately NOT here — composing the
// non-executing evaluator is allowed.
var execArmingHooks = map[string]bool{
	"markGatewayExecDepsReady":    true,
	"markManagementExecDepsReady": true,
}

// liveExecutionSymbols are the execution-package identifiers that belong to LIVE
// execution ONLY. Referencing any of them from production constructs or names the live
// executor, which must stay unwired. The Shadow symbols (NewShadowEvaluator,
// ShadowEvaluator, ShadowConfig, CredentialPlanner) are deliberately absent so the
// Shadow composition is permitted.
var liveExecutionSymbols = map[string]bool{
	"New":            true, // the live Executor constructor (NewShadowEvaluator is allowed)
	"Executor":       true, // the live executor type (ShadowEvaluator is allowed)
	"Config":         true, // the live executor config (ShadowConfig is allowed)
	"UpstreamCaller": true, // the upstream side-effect capability — Shadow has none
}

// execPackagePath is the guarded-execution plane. Exactly one production file may import
// it (the Shadow composition); nothing else may.
const execPackagePath = "github.com/KidCarmi/Culvert/internal/mcp/execution"

// shadowCompositionFile is the SINGLE production file permitted to import the execution
// package and assign runtime.Deps.Executor. It composes only the non-executing Shadow
// evaluator (SHADOW-ACTIVATION.md §4).
const shadowCompositionFile = "mcp_shadow_startup.go"

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

// TestExecPosture_LiveArmingHooksHaveNoProductionCaller pins fact (1).
//
// The LIVE hooks are defined in mcp_rollout_execdeps.go and documented as
// "intentionally UNCALLED in the current build". That is a comment; this is the
// check. A call from anywhere in production arms liveExecDepsConfigured for that
// capability and makes every Canary/Production transition succeed. The SHADOW hooks
// are NOT in execArmingHooks, so composing the non-executing evaluator (which calls
// markGatewayShadowDepsReady) is permitted.
func TestExecPosture_LiveArmingHooksHaveNoProductionCaller(t *testing.T) {
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
				t.Errorf("%s: production code calls %s(), which arms LIVE guarded execution.\n"+
					"Live execution is disabled by default (ADR-0024) and arming it is a "+
					"separately-reviewed activation, not a side effect of another change. If this "+
					"call is intended, the activation review updates this wall.",
					fset.Position(call.Pos()), name)
			}
			return true
		})
	}
}

// TestExecPosture_NoLiveExecutorConstruction pins fact (2).
//
// A live executor is composed by NAMING it: execution.New (the live constructor),
// execution.Executor, execution.Config, or execution.UpstreamCaller. The Shadow
// evaluator uses disjoint symbols (NewShadowEvaluator / ShadowConfig), so this catches
// a live-executor composition while permitting the Shadow one. It resolves the local
// import name of the execution package per file, so an aliased import cannot evade it.
func TestExecPosture_NoLiveExecutorConstruction(t *testing.T) {
	for _, pf := range productionAST(t) {
		if strings.HasPrefix(filepath.ToSlash(pf.path), "internal/mcp/execution/") {
			continue // the package's own files define these symbols
		}
		local := localImportName(pf.file, execPackagePath)
		if local == "" {
			continue // this file does not import the execution package
		}
		fset := pf.fset
		ast.Inspect(pf.file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok || x.Name != local {
				return true
			}
			if liveExecutionSymbols[sel.Sel.Name] {
				t.Errorf("%s: production code references %s.%s — a LIVE-execution symbol.\n"+
					"The live executor (upstream client + credential materialization) must stay "+
					"unwired (ADR-0024). Only the non-executing Shadow evaluator may be composed; "+
					"arming live execution is a separately-reviewed activation.",
					fset.Position(sel.Pos()), local, sel.Sel.Name)
			}
			return true
		})
	}
}

// TestExecPosture_ExecutionImportedOnlyByShadowComposition pins fact (3).
//
// Exactly one production file — the Shadow composition — may import the execution
// package. An import from anywhere else is a route to construct an executor the other
// gates cannot see, so it is forbidden.
func TestExecPosture_ExecutionImportedOnlyByShadowComposition(t *testing.T) {
	for _, pf := range productionAST(t) {
		if strings.HasPrefix(filepath.ToSlash(pf.path), "internal/mcp/execution/") {
			continue // the package's own files
		}
		fset := pf.fset
		for _, imp := range pf.file.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil || p != execPackagePath {
				continue
			}
			if filepath.Base(pf.path) != shadowCompositionFile {
				t.Errorf("%s: production code imports %s.\nOnly %s (the non-executing Shadow "+
					"composition) may import the execution package; wiring it elsewhere is a "+
					"separately-reviewed activation.", fset.Position(imp.Pos()), execPackagePath, shadowCompositionFile)
			}
		}
	}
}

// TestExecPosture_ExecutorAssignedOnlyByShadowComposition pins fact (4).
//
// runtime.Deps.Executor is the OPTIONAL guarded-execution provider; the pipeline
// composes an executor iff it is non-nil. Assigning it composes the execution plane, so
// the assignment must live ONLY in the Shadow composition file (where it can only be a
// *ShadowEvaluator — fact (2) forbids constructing anything else). An assignment
// anywhere else is forbidden.
func TestExecPosture_ExecutorAssignedOnlyByShadowComposition(t *testing.T) {
	report := func(fset *token.FileSet, pos token.Pos, path string) {
		if filepath.Base(path) == shadowCompositionFile {
			return // the one permitted assignment site (the Shadow composition)
		}
		t.Errorf("%s: production code assigns Deps.Executor outside %s, composing the "+
			"guarded-execution plane. Only the non-executing Shadow composition may assign it.",
			fset.Position(pos), shadowCompositionFile)
	}
	for _, pf := range productionAST(t) {
		// The field's own declaration and the pipeline's nil-guarded read are the two
		// legitimate mentions; neither is an assignment, so no exemption is needed.
		fset := pf.fset
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.KeyValueExpr:
				if k, ok := v.Key.(*ast.Ident); ok && k.Name == "Executor" {
					report(fset, v.Pos(), pf.path)
				}
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Executor" {
						report(fset, lhs.Pos(), pf.path)
					}
				}
			}
			return true
		})
	}
}

// localImportName returns the identifier a file uses to reference the package at
// importPath — its explicit alias, or the default package name (the last path segment,
// which is correct for the execution package). Empty when the file does not import it.
func localImportName(file *ast.File, importPath string) string {
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != importPath {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				return "" // blank/dot import exposes no qualified selector to scan
			}
			return imp.Name.Name
		}
		return path.Base(importPath)
	}
	return ""
}
