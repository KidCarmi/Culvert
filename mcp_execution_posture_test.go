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

// The MCP execution-posture wall (EVOLVED for the LIVE-tier composition phase).
//
// Earlier the wall pinned "no live executor is composed anywhere." This phase COMPOSES the real
// live *execution.Executor (behind a disabled-by-default, node-readiness-gated arming lifecycle),
// so the wall no longer forbids composition — it now pins the exact SEPARATION the core principle
// requires (COMPOSED != ARMED != Canary ACTIVE) and STRENGTHENS the Shadow/Layer-B boundary now
// that live capabilities coexist in the same process:
//
//  1. The LIVE arming/disarming primitives (markGateway/ManagementExecDepsReady,
//     clearGateway/ManagementExecDepsReady) are called ONLY from mcp_rollout_execdeps.go — the
//     file that defines them and holds the single setLiveExecDepsArmed dispatcher. Nothing else may
//     toggle the live armed bit through them, so there is no startup convenience path and no
//     implicit arm.
//  2. setLiveExecDepsArmed — the single arm/disarm dispatcher — is called ONLY from the lifecycle
//     object (mcp_live_tier.go: arm / quiesce / disarmForRestart). The lifecycle object is the sole
//     authority that flips the armed bit, so arming is always the deliberate, gated act.
//  3. The LIVE-EXECUTOR construction symbols (execution.New, execution.Executor, execution.Config,
//     execution.UpstreamCaller) are referenced ONLY from the ONE live composition file
//     (mcp_live_startup.go). The Shadow composition file references NONE of them — a Canary
//     composition change can never collapse Layer B by naming the live executor in the shadow path.
//  4. internal/mcp/execution is imported ONLY by the permitted set: the Shadow composition, the
//     live composition, and the live gate. Nothing else may import it.
//  5. runtime.Deps.Executor is assigned ONLY in the two composition files (Shadow, live) — the two
//     legitimate executor-install sites — and nowhere else.
//
// Arming LIVE execution remains a deliberate, separately-reviewed activation, and DEPLOYING it (the
// production upstream/broker/KEK wiring) is a further separately-reviewed step. Whoever changes this
// separation must edit THIS wall, and that edit is what a reviewer sees.
//
// AST-based rather than grep-based, deliberately: a string search matches comments and test files,
// which is exactly how a documentation-only control passes for a real one.

// liveArmingHooks are the LIVE-tier arm/disarm primitives. They may be referenced ONLY inside
// mcp_rollout_execdeps.go (their defining file + the single dispatcher). The SHADOW hooks
// (markGateway/ManagementShadowDepsReady) are deliberately NOT here — composing the non-executing
// evaluator arms only the shadow tier and stays unrestricted.
var liveArmingHooks = map[string]bool{
	"markGatewayExecDepsReady":     true,
	"markManagementExecDepsReady":  true,
	"clearGatewayExecDepsReady":    true,
	"clearManagementExecDepsReady": true,
}

// armingHookFile is the ONLY file permitted to reference the live arming/disarming primitives.
const armingHookFile = "mcp_rollout_execdeps.go"

// armingDispatcher is the single arm/disarm dispatcher; only the lifecycle object may call it.
const armingDispatcher = "setLiveExecDepsArmed"

// armingDispatcherFile is the ONLY file permitted to call setLiveExecDepsArmed.
const armingDispatcherFile = "mcp_live_tier.go"

// liveExecutorSymbols are the execution-package identifiers that construct or name the LIVE
// executor. Referencing any of them composes the live executor, which is permitted ONLY in the one
// live composition file. The Shadow symbols (NewShadowEvaluator/ShadowEvaluator/ShadowConfig/
// CredentialPlanner) and the gate symbols (LiveExecutionGate/LiveGateInput/LiveGateDecision) are
// deliberately absent — the shadow composition and the gate file reference the package for those.
var liveExecutorSymbols = map[string]bool{
	"New":            true, // the live Executor constructor (NewShadowEvaluator is allowed)
	"Executor":       true, // the live executor type (ShadowEvaluator is allowed)
	"Config":         true, // the live executor config (ShadowConfig is allowed)
	"UpstreamCaller": true, // the upstream side-effect capability — Shadow has none
}

// execPackagePath is the guarded-execution plane.
const execPackagePath = "github.com/KidCarmi/Culvert/internal/mcp/execution"

// shadowCompositionFile composes the non-executing Shadow evaluator.
const shadowCompositionFile = "mcp_shadow_startup.go"

// liveCompositionFile composes the LIVE executor (the sole site that names the live-executor
// construction symbols and the second Deps.Executor assignment site).
const liveCompositionFile = "mcp_live_startup.go"

// liveGateFile implements the composition-layer side-effect gate (imports execution for the gate
// types only — never the live-executor construction symbols).
const liveGateFile = "mcp_live_gate.go"

// execImporters is the exact set of production files permitted to import the execution package.
var execImporters = map[string]bool{
	shadowCompositionFile: true,
	liveCompositionFile:   true,
	liveGateFile:          true,
}

// execAssigners is the exact set of production files permitted to assign runtime.Deps.Executor.
var execAssigners = map[string]bool{
	shadowCompositionFile: true,
	liveCompositionFile:   true,
}

// productionGoFiles yields every non-test .go file of the main module, with the vendored,
// generated and separately-moduled trees excluded.
func productionGoFiles(t *testing.T) []string {
	t.Helper()
	skipDirs := map[string]bool{
		".git": true, "node_modules": true, "vendor": true, "testdata": true,
		"frontend": true,
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
		t.Fatalf("only %d production files found; the wall is not scanning the tree", len(out))
	}
	return out
}

// parsedProductionFile is one parsed production source file.
type parsedProductionFile struct {
	path string
	fset *token.FileSet
	file *ast.File
}

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

// callName returns the called function's simple name for an *ast.CallExpr, or "".
func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// TestExecPosture_ArmingHooksContainedToDispatcher pins fact (1).
//
// The live arm/disarm primitives may be referenced ONLY inside mcp_rollout_execdeps.go. A call
// from anywhere else is a route to toggle the live armed bit outside the single dispatcher —
// forbidden.
func TestExecPosture_ArmingHooksContainedToDispatcher(t *testing.T) {
	for _, pf := range productionAST(t) {
		if filepath.Base(pf.path) == armingHookFile {
			continue // the defining file + dispatcher
		}
		fset := pf.fset
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if liveArmingHooks[callName(call)] {
				t.Errorf("%s: production code calls %s(), a LIVE arm/disarm primitive, outside %s.\n"+
					"The live armed bit may be toggled ONLY through setLiveExecDepsArmed in %s; arming is a "+
					"separately-reviewed, node-readiness-gated act, never a side effect of another change.",
					fset.Position(call.Pos()), callName(call), armingHookFile, armingHookFile)
			}
			return true
		})
	}
}

// TestExecPosture_ArmingDispatcherCalledOnlyByLifecycle pins fact (2).
//
// setLiveExecDepsArmed is the single arm/disarm dispatcher; only the lifecycle object
// (mcp_live_tier.go) may call it. A call from anywhere else bypasses the lifecycle state machine.
func TestExecPosture_ArmingDispatcherCalledOnlyByLifecycle(t *testing.T) {
	for _, pf := range productionAST(t) {
		base := filepath.Base(pf.path)
		if base == armingDispatcherFile || base == armingHookFile {
			continue // the lifecycle caller, and the definition site
		}
		fset := pf.fset
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if callName(call) == armingDispatcher {
				t.Errorf("%s: production code calls %s() outside %s.\nOnly the live-tier lifecycle "+
					"object may arm/disarm; routing the toggle elsewhere bypasses the composed/armed/"+
					"quiescing state machine.", fset.Position(call.Pos()), armingDispatcher, armingDispatcherFile)
			}
			return true
		})
	}
}

// TestExecPosture_LiveExecutorConstructedOnlyByLiveComposition pins fact (3).
//
// The live-executor construction symbols may be referenced ONLY from the one live composition file.
// This catches a live-executor composition anywhere else AND, crucially, in the SHADOW composition
// file — Layer B must never be collapsed by naming the live executor in the shadow path.
func TestExecPosture_LiveExecutorConstructedOnlyByLiveComposition(t *testing.T) {
	for _, pf := range productionAST(t) {
		if strings.HasPrefix(filepath.ToSlash(pf.path), "internal/mcp/execution/") {
			continue // the package's own files define these symbols
		}
		if filepath.Base(pf.path) == liveCompositionFile {
			continue // the one permitted live-composition site
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
			if liveExecutorSymbols[sel.Sel.Name] {
				t.Errorf("%s: %s references %s.%s — a LIVE-executor construction symbol.\n"+
					"Only %s may construct the live executor; the Shadow composition and the gate must "+
					"reference NEITHER (Layer B). Composing the live executor elsewhere is forbidden.",
					fset.Position(sel.Pos()), filepath.Base(pf.path), local, sel.Sel.Name, liveCompositionFile)
			}
			return true
		})
	}
}

// TestExecPosture_ExecutionImportedOnlyByCompositionSet pins fact (4).
//
// Only the permitted set (Shadow composition, live composition, live gate) may import the execution
// package. An import from anywhere else is a route to construct/name an executor the other gates
// cannot see.
func TestExecPosture_ExecutionImportedOnlyByCompositionSet(t *testing.T) {
	for _, pf := range productionAST(t) {
		if strings.HasPrefix(filepath.ToSlash(pf.path), "internal/mcp/execution/") {
			continue
		}
		fset := pf.fset
		for _, imp := range pf.file.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil || p != execPackagePath {
				continue
			}
			if !execImporters[filepath.Base(pf.path)] {
				t.Errorf("%s: production code imports %s.\nOnly the composition set (%s, %s, %s) may import "+
					"the execution package; wiring it elsewhere is a separately-reviewed activation.",
					fset.Position(imp.Pos()), execPackagePath, shadowCompositionFile, liveCompositionFile, liveGateFile)
			}
		}
	}
}

// TestExecPosture_ExecutorAssignedOnlyByCompositionFiles pins fact (5).
//
// runtime.Deps.Executor is the guarded-execution provider; assigning it composes the plane. It may
// be assigned ONLY in the two composition files (Shadow, live). An assignment anywhere else is
// forbidden.
func TestExecPosture_ExecutorAssignedOnlyByCompositionFiles(t *testing.T) {
	report := func(fset *token.FileSet, pos token.Pos, p string) {
		if execAssigners[filepath.Base(p)] {
			return
		}
		t.Errorf("%s: production code assigns Deps.Executor outside the composition files (%s, %s), "+
			"composing the guarded-execution plane elsewhere.", fset.Position(pos), shadowCompositionFile, liveCompositionFile)
	}
	for _, pf := range productionAST(t) {
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

// localImportName returns the identifier a file uses to reference the package at importPath.
func localImportName(file *ast.File, importPath string) string {
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != importPath {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				return ""
			}
			return imp.Name.Name
		}
		return path.Base(importPath)
	}
	return ""
}
