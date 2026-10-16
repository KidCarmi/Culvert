package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// ── SEC-ADMISSION-OWNER-1, round 3 ──────────────────────────────────────────
//
// The owner walls in admission_owner_wall_test.go resolve the limiter's
// binding at two syntactic hops: DataPlaneClient.Run must pass the
// package-level `rl`, and rateLimitGossipLoop must keep the parameter it was
// handed. Both reason INSIDE those functions.
//
// That leaves the package handle itself unguarded. `Run` captures the pointer
// value when it starts the gossip loop, while the request path reads the
// global on every request — so a reassignment anywhere else in production
// (`rl = newRateLimiter()` in a startup or reconfiguration helper) splits the
// owner after the fact: requests enforce with the new limiter, gossip keeps
// feeding the old one, the live budget is discarded, and the enforcing limiter
// is never armed. That is the same silent per-node degradation the other walls
// exist to prevent, reached from outside their scope.
//
// Reproduced before writing this: adding such a function to admission.go left
// every TestAdmissionOwner_ test passing (Codex P2, PR #1584).
//
// ADR-0038's boundary map already states the invariant — "No production
// reassignment of rl" — so this gate enforces a rule the design recorded and
// nothing checked. The package-level `var rl = newRateLimiter()` DECLARATION
// in admission.go is the one permitted write; tests may still rebind the
// handle through their own helpers, so only non-test files are scanned.
//
// It lives in its own file rather than beside the other walls so that it
// merges cleanly alongside concurrent edits to them.

// assignsPackageHandle reports the functions in file that assign to the
// package-level name, i.e. an `=` assignment to it from a function that does
// not bind that name locally. A short variable declaration (`rl := …`) creates
// a local and is somebody else's problem — the in-function walls cover it.
func assignsPackageHandle(file *ast.File, name string) []string {
	var out []string
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		local := false
		ast.Inspect(fn, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || as.Tok != token.DEFINE {
				return true
			}
			for _, lhs := range as.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
					local = true
				}
			}
			return true
		})
		if local {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || as.Tok != token.ASSIGN {
				return true
			}
			for _, lhs := range as.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
					out = append(out, fn.Name.Name)
				}
			}
			return true
		})
	}
	return out
}

// Nothing in production may reassign the admission composition handle.
func TestAdmissionOwner_Wall_NoProductionReassignmentOfTheOwner(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		scanned++
		for _, fn := range assignsPackageHandle(f, "rl") {
			t.Errorf("%s: %s reassigns the package-level admission handle `rl`. "+
				"DataPlaneClient.Run captured the previous pointer for the gossip loop, so after this "+
				"the request path enforces with one limiter while gossip feeds another — the split owner "+
				"is silent (an un-armed limiter is never reported stale) and the live budget is discarded. "+
				"ADR-0038 records this as 'No production reassignment of rl' (SEC-ADMISSION-OWNER-1)", n, fn)
		}
	}
	// Not-vacuous: the scan must actually have read the package.
	if scanned < 10 {
		t.Fatalf("only %d non-test files scanned; this gate's selector has gone stale", scanned)
	}

	// CONTROLS: the same predicate must REJECT the shapes this gate exists to
	// catch, and must ACCEPT the declaration and a local of the same name.
	for name, tc := range map[string]struct {
		src  string
		want bool
	}{
		"reassignment in a helper":  {"package main\nfunc reconfigure() { rl = newRateLimiter() }", true},
		"reassignment in a branch":  {"package main\nfunc reconfigure(b bool) { if b { rl = newRateLimiter() } }", true},
		"package declaration only":  {"package main\nvar rl = newRateLimiter()", false},
		"local of the same name":    {"package main\nfunc h() { rl := newRateLimiter(); rl = newRateLimiter(); _ = rl }", false},
		"unrelated global assigned": {"package main\nfunc h() { other = newRateLimiter() }", false},
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "control.go", tc.src, 0)
		if err != nil {
			t.Fatalf("parse %s control: %v", name, err)
		}
		if got := len(assignsPackageHandle(f, "rl")) > 0; got != tc.want {
			t.Errorf("control %q: flagged=%v, want %v — this gate is matching the wrong thing", name, got, tc.want)
		}
	}
}
