package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// allowedImports is the CLOSED set of direct imports the policy evaluation package
// may use. It is intentionally tiny: stdlib building blocks that do NO I/O plus the
// two leaf MCP packages (typed errors + the strict canonical decoder). Anything that
// could touch the network, filesystem, database, DNS, environment, clock source,
// secrets or a logger is absent BY CONSTRUCTION, so the "pure, I/O-free" contract is
// mechanically enforced — a new import here is a deliberate, reviewed decision.
var allowedImports = map[string]bool{
	"bytes":         true,
	"crypto/sha256": true, // deterministic snapshot hash (pure, in-memory)
	"encoding/hex":  true,
	"encoding/json": true, // strict in-memory decode only
	"sort":          true,
	"strconv":       true,
	"strings":       true,
	"sync":          true, // store publication mutex
	"sync/atomic":   true, // store lock-free read pointer
	"time":          true, // time.Time TYPE + Unix comparison only — never time.Now()
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr":    true,
	"github.com/KidCarmi/Culvert/internal/mcp/canonical": true,
}

// forbiddenCalls are package.selector pairs the evaluation package must never call.
// The headline is the clock: the evaluator takes an EXPLICIT EvalTime and must never
// read a wall clock. The rest are defense-in-depth against an accidental I/O import
// sneaking a live call in.
var forbiddenCalls = map[string]bool{
	"time.Now": true, "time.Since": true, "time.Until": true, "time.Tick": true,
	"time.After": true, "time.Sleep": true, "time.NewTimer": true, "time.NewTicker": true,
	"os.Getenv": true, "os.Open": true, "os.ReadFile": true,
	"rand.Read": true, "rand.Int": true,
	"log.Printf": true, "log.Println": true, "fmt.Println": true, "fmt.Printf": true,
}

// TestNoIO_ImportsAndClock statically proves the policy evaluation package performs
// no I/O and never reads a clock: every non-test file's imports are within the closed
// allowlist, and no forbidden call (headline: time.Now) appears anywhere in the
// package source.
func TestNoIO_ImportsAndClock(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse policy package: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("no non-test Go files found in the policy package")
	}
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if !allowedImports[p] {
					t.Errorf("%s imports %q which is NOT on the I/O-free allowlist", path, p)
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				name := pkgIdent.Name + "." + sel.Sel.Name
				if forbiddenCalls[name] {
					t.Errorf("%s calls %s — forbidden on the I/O-free / clock-free evaluation path", path, name)
				}
				return true
			})
		}
	}
}
