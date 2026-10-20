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

// TestWall_RosterRowFilesystemAccessIsOnlyInTheProbe pins Codex P2s
// 4319224642 and 4319224648 on PR #1601 at the source: every function the
// admin_roster_durability row reaches makes its filesystem calls only inside
// the probe (rosterProbeFuncs), which runs coalesced, bounded and
// lock-free (roster_probe.go). A stat or open added anywhere else on the
// row's path — per request, on the caller's goroutine — fails, as the
// negative control shows.

// rosterProbeFuncs are the probe: the only functions on the row's path that
// may touch the filesystem. They run on the probe goroutine only.
var rosterProbeFuncs = map[string]bool{"probeRosterTarget": true, "probeRosterIdentity": true, "probeRosterParent": true}

// rosterRowRoots are where the row is computed.
var rosterRowRoots = []string{"redactContractForRole", "readRosterDurabilityFacts", "adminRow", "viewerRow",
	"notDurableAdminRow", "targetProblemAdminRow"}

// rosterFSSeams are the package's filesystem seams for the probe: calling
// one is filesystem access.
var rosterFSSeams = map[string]bool{"rosterProbeStat": true, "rosterIdentityOpen": true,
	"rosterParentAccess": true, "rosterParentReadOnly": true, "statfsReadOnly": true, "rosterReplacementBlocked": true}

// fsCallPackages are packages whose function calls touch the filesystem
// (os's, other than the pure helpers below) or the kernel.
var fsCallPackages = map[string]bool{"os": true, "unix": true, "syscall": true, "ioutil": true, "fileutil": true}

// pureOSFuncs are os functions that do not touch the filesystem.
var pureOSFuncs = map[string]bool{"IsNotExist": true, "IsExist": true, "IsPermission": true, "Geteuid": true,
	"Getegid": true, "Getuid": true, "Getgid": true, "Getpid": true, "Getenv": true, "LookupEnv": true}

type rosterWallFunc struct {
	name string
	file string
	body *ast.BlockStmt
}

// parseRosterWallFuncs parses the root package's production .go files
// (srcs overrides a file's content, for negative controls).
func parseRosterWallFuncs(t *testing.T, srcs map[string]string) map[string][]rosterWallFunc {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(pkgSourceDir(), "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	funcs := map[string][]rosterWallFunc{}
	for _, full := range files {
		name := filepath.Base(full)
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		var src any
		if s, ok := srcs[name]; ok {
			src = s
		}
		f, err := parser.ParseFile(fset, full, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				key := rosterWallKey(fd)
				funcs[key] = append(funcs[key], rosterWallFunc{name: key, file: name, body: fd.Body})
			}
		}
	}
	return funcs
}

// rosterWallKey is a top-level function's name, or "Recv.method".
func rosterWallKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// rosterRowTypes are the receiver types whose methods the row calls; a method
// call x.m() is followed into these types' m, and into no other type's (an
// atomic counter's Load is not Config's).
var rosterRowTypes = []string{"Config", "rosterDurabilityFacts"}

// rosterWallCallee is the function or method name a call names.
func rosterWallCallee(call *ast.CallExpr) (pkg, name string) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return "", fn.Name
	case *ast.SelectorExpr:
		if id, ok := fn.X.(*ast.Ident); ok {
			return id.Name, fn.Sel.Name
		}
		return "", fn.Sel.Name
	}
	return "", ""
}

// rosterRowFSViolations walks the row's call graph — top-level functions by
// name, and methods of rosterRowTypes by method name (which over-approximates
// for those types) — and reports filesystem calls outside rosterProbeFuncs
// functions.
func rosterRowFSViolations(funcs map[string][]rosterWallFunc) []string {
	seen := map[string]bool{}
	var queue []string
	for _, r := range rosterRowRoots {
		queue = append(queue, r)
		queue = append(queue, rosterMethodKeys(r)...)
	}
	var out []string
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] || rosterProbeFuncs[name] {
			continue // the probe is where filesystem access belongs
		}
		seen[name] = true
		for _, fn := range funcs[name] {
			ast.Inspect(fn.body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					violation, follow := rosterWallClassify(call)
					if violation != "" {
						out = append(out, fn.file+": "+fn.name+" "+violation+" outside the probe")
					}
					queue = append(queue, follow...)
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out
}

// rosterMethodKeys are the keys of method m on every rosterRowTypes type.
func rosterMethodKeys(m string) []string {
	keys := make([]string, 0, len(rosterRowTypes))
	for _, typ := range rosterRowTypes {
		keys = append(keys, typ+"."+m)
	}
	return keys
}

// rosterWallClassify reports a filesystem call, or the keys a call may
// continue the row's call graph into.
func rosterWallClassify(call *ast.CallExpr) (violation string, follow []string) {
	pkg, callee := rosterWallCallee(call)
	_, isSel := call.Fun.(*ast.SelectorExpr)
	switch {
	case callee == "":
		return "", nil
	case fsCallPackages[pkg] && (pkg != "os" || !pureOSFuncs[callee]):
		return "calls " + pkg + "." + callee, nil
	case fsCallPackages[pkg]:
		return "", nil
	case pkg == "" && rosterFSSeams[callee]:
		return "calls filesystem seam " + callee, nil
	case pkg == "" && !isSel:
		return "", []string{callee}
	}
	// x.m(): a method of the row's types (an atomic counter's Load is not
	// Config's), or another package's function, which is not followed.
	return "", rosterMethodKeys(callee)
}

func TestWall_RosterRowFilesystemAccessIsOnlyInTheProbe(t *testing.T) {
	funcs := parseRosterWallFuncs(t, nil)
	for _, v := range rosterRowFSViolations(funcs) {
		t.Error(v)
	}
	// Not vacuous: the roots and the probe exist, and the row reaches it.
	for _, name := range []string{"probeRosterTarget", "probeRosterIdentity", "probeRosterParent",
		"redactContractForRole", "readRosterDurabilityFacts", "Config.sharedRosterProbe"} {
		if len(funcs[name]) == 0 {
			t.Errorf("%s not found: renamed without updating the wall", name)
		}
	}

	// Negative controls: a stat on the row's path outside the probe, a call
	// to a filesystem seam outside it, and a stat in a helper the row reaches.
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "diagnostics.go"))
	if err != nil {
		t.Fatal(err)
	}
	const anchor = "\tpath, loadErr := cfg.rosterPersistTarget()\n"
	if !strings.Contains(string(src), anchor) {
		t.Fatalf("negative-control anchor missing from diagnostics.go")
	}
	for name, inject := range map[string]string{
		"os.Stat in readRosterDurabilityFacts":          anchor + "\t_, _ = os.Stat(path)\n",
		"a seam call in readRosterDurabilityFacts":      anchor + "\t_, _ = rosterProbeStat(path)\n",
		"os.Lstat in a reached helper":                  anchor + "\t_ = fixtureRosterHelper(path)\n",
		"fileutil.ReplacementBlocked outside the probe": anchor + "\t_ = fileutil.ReplacementBlocked(path)\n",
	} {
		mutated := strings.Replace(string(src), anchor, inject, 1) +
			"\nfunc fixtureRosterHelper(p string) error { _, err := os.Lstat(p); return err }\n"
		if v := rosterRowFSViolations(parseRosterWallFuncs(t, map[string]string{"diagnostics.go": mutated})); len(v) == 0 {
			t.Errorf("%s passed the wall", name)
		}
	}
}
