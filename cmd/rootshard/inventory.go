package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// laneBuildFlags are the build flags every test process in this tool uses
// (-race sets the `race` build tag), so `go list` resolves the same file set.
var laneBuildFlags = []string{"-race"}

// PkgInventory is the runnable surface of ONE package as `go test` would build
// it, enumerated from source under a given build configuration.
//
// Why a source enumerator exists at all: the root package's inventory comes
// from its compiled binary (-test.list), but the non-root lane runs ~110
// packages through `go test` directly, and nothing independent said which
// tests each package SHOULD have reported. Without it, a lane whose events for
// one test were lost would still show the package as `pass`. This enumerator
// is the independent expectation — and it is not trusted blindly: the verdict
// runs it over the ROOT package too and requires it to agree exactly with the
// root binary's own -test.list, so a divergence between these rules and
// cmd/go's fails the build instead of quietly under-counting.
type PkgInventory struct {
	ImportPath string `json:"importPath"`
	// Tests are the runnable top-level entries: Test*, Fuzz* (their seed
	// corpus runs as a test) and Example* with an output comment.
	Tests      []string `json:"tests"`
	Benchmarks []string `json:"benchmarks,omitempty"`
}

// listedPackage is the subset of `go list -json` this tool reads.
type listedPackage struct {
	ImportPath   string
	Dir          string
	TestGoFiles  []string
	XTestGoFiles []string
	Error        *struct{ Err string }
}

// sourceInventory enumerates every package in pkgs. buildFlags are passed to
// `go list` so build tags match the test run (the lane and the shards both
// build with -race, which sets the `race` tag).
func sourceInventory(ctx context.Context, goBin string, buildFlags []string, pkgs []string) (map[string]PkgInventory, error) {
	args := append(append([]string{"list", "-e", "-json"}, buildFlags...), pkgs...)
	// #nosec G204 -- fixed go subcommand over package paths from `go list`.
	c := exec.CommandContext(ctx, goBin, args...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w\n%s", err, stderr.String())
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	inv := map[string]PkgInventory{}
	for {
		var lp listedPackage
		if err := dec.Decode(&lp); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode go list: %w", err)
		}
		if lp.Error != nil {
			return nil, fmt.Errorf("go list %s: %s", lp.ImportPath, lp.Error.Err)
		}
		pi, err := enumeratePackage(lp)
		if err != nil {
			return nil, err
		}
		inv[lp.ImportPath] = pi
	}
	for _, p := range pkgs {
		if _, ok := inv[p]; !ok {
			return nil, fmt.Errorf("go list returned nothing for %s", p)
		}
	}
	return inv, nil
}

func enumeratePackage(lp listedPackage) (PkgInventory, error) {
	pi := PkgInventory{ImportPath: lp.ImportPath}
	seen := map[string]bool{}
	fset := token.NewFileSet()
	files := append(append([]string{}, lp.TestGoFiles...), lp.XTestGoFiles...)
	for _, name := range files {
		f, err := parser.ParseFile(fset, filepath.Join(lp.Dir, name), nil, parser.ParseComments)
		if err != nil {
			return pi, fmt.Errorf("parse %s: %w", name, err)
		}
		entries, benches, err := fileEntries(f)
		if err != nil {
			return pi, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		for _, e := range entries {
			if seen[e] {
				return pi, fmt.Errorf("%s: entry %s is declared twice", lp.ImportPath, e)
			}
			seen[e] = true
			pi.Tests = append(pi.Tests, e)
		}
		pi.Benchmarks = append(pi.Benchmarks, benches...)
	}
	sort.Strings(pi.Tests)
	sort.Strings(pi.Benchmarks)
	return pi, nil
}

// fileEntries applies cmd/go's rules (cmd/go/internal/load/test.go) to one
// test file: only receiver-less functions; a name that isTest() for a prefix
// must have exactly one *T / *F / *B parameter and no results; TestMain with
// a *M parameter is the harness, not an entry; examples run only when they
// carry an output comment (`// Output:` or `// Unordered output:`).
func fileEntries(f *ast.File) (entries, benches []string, err error) {
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		kind, err := entryKind(fn)
		switch {
		case err != nil:
			return nil, nil, err
		case kind == "B":
			benches = append(benches, fn.Name.Name)
		case kind != "":
			entries = append(entries, fn.Name.Name)
		}
	}
	for _, e := range doc.Examples(f) {
		if e.Output == "" && !e.EmptyOutput {
			continue // compiled, never run — and never listed
		}
		entries = append(entries, "Example"+e.Name)
	}
	return entries, benches, nil
}

// entryPrefixes maps a top-level function prefix to the parameter type cmd/go
// requires of it.
var entryPrefixes = []struct{ prefix, param string }{
	{"Test", "T"}, {"Benchmark", "B"}, {"Fuzz", "F"},
}

// entryKind reports the parameter type ("T", "B", "F") of a test-shaped
// function, "" for anything else (including TestMain, the harness), and an
// error for a test-shaped name with the wrong signature — which `go test`
// refuses to build, so the enumerator must not silently skip it.
func entryKind(fn *ast.FuncDecl) (string, error) {
	name := fn.Name.Name
	if name == "TestMain" && !isTestFunc(fn, "T") {
		if !isTestFunc(fn, "M") {
			return "", fmt.Errorf("TestMain has the wrong signature")
		}
		return "", nil
	}
	for _, e := range entryPrefixes {
		if !isTest(name, e.prefix) {
			continue
		}
		if !isTestFunc(fn, e.param) {
			return "", fmt.Errorf("%s has the wrong signature", name)
		}
		return e.param, nil
	}
	return "", nil
}

// isTest is cmd/go's rule: the prefix, then nothing or a non-lowercase rune
// (so "Testify" is not a test but "Test_x" and "TestX" are).
func isTest(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(r)
}

// isTestFunc is cmd/go's signature check: one parameter of type *X or *pkg.X,
// no results. Like cmd/go it cannot see how "testing" was imported, so it
// accepts any selector ending in X.
func isTestFunc(fn *ast.FuncDecl, arg string) bool {
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 ||
		fn.Type.Params.List == nil ||
		len(fn.Type.Params.List) != 1 ||
		len(fn.Type.Params.List[0].Names) > 1 {
		return false
	}
	ptr, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	if name, ok := ptr.X.(*ast.Ident); ok && name.Name == arg {
		return true
	}
	if sel, ok := ptr.X.(*ast.SelectorExpr); ok && sel.Sel.Name == arg {
		return true
	}
	return false
}

// agreesWithBinary cross-checks the enumerator against a compiled binary's own
// -test.list inventory. Any difference means these rules no longer match
// cmd/go's, and every lane expectation built from them is suspect.
func agreesWithBinary(src PkgInventory, bin Inventory) string {
	var binTests []string
	for _, e := range bin.Runnable {
		binTests = append(binTests, e.Name)
	}
	sort.Strings(binTests)
	var problems []string
	if d := diffNames(binTests, src.Tests); d != "" {
		problems = append(problems, "runnable entries (binary vs source): "+d)
	}
	benches := append([]string{}, bin.Benchmarks...)
	sort.Strings(benches)
	if d := diffNames(benches, src.Benchmarks); d != "" {
		problems = append(problems, "benchmarks (binary vs source): "+d)
	}
	return strings.Join(problems, "; ")
}

// cmdInventory prints the source-enumerated inventory of the given packages
// (default: every package of the module) under the lane's build flags. With
// -check-list it also cross-checks the ROOT package against a binary's
// -test.list output — the same agreement the verdict requires.
func cmdInventory(args []string, stdout io.Writer) error {
	fs := newFlags("inventory")
	out := fs.String("out", "", "write the inventory JSON here (default: stdout)")
	checkList := fs.String("check-list", "", "root binary -test.list output to cross-check the root package against")
	goBin := fs.String("go", "go", "go command")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	ctx := context.Background()
	pkgs := fs.Args()
	if len(pkgs) == 0 {
		pkgs = []string{"./..."}
	}
	listed, err := goOutput(ctx, *goBin, append([]string{"list"}, pkgs...)...)
	if err != nil {
		return err
	}
	inv, err := sourceInventory(ctx, *goBin, laneBuildFlags, strings.Fields(listed))
	if err != nil {
		return err
	}
	if *checkList != "" {
		bin, err := readInventory(*checkList)
		if err != nil {
			return err
		}
		root, err := goOutput(ctx, *goBin, "list", ".")
		if err != nil {
			return err
		}
		if d := agreesWithBinary(inv[strings.TrimSpace(root)], bin); d != "" {
			return fmt.Errorf("source enumerator disagrees with the binary: %s", d)
		}
		say(stdout, "source enumerator agrees with the binary: %d runnable, %d benchmarks\n", len(bin.Runnable), len(bin.Benchmarks))
	}
	if *out == "" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(inv)
	}
	return writeJSON(*out, inv)
}
