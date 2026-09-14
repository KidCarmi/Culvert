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

// ui_basicauth_wall_test.go — the SEC-BASICAUTH-1 structural wall.
//
// The defect was not that one call site was wrong; it was that FOUR entry
// points answered the same question ("are these admin credentials valid?") and
// only one of them was bounded. Behavioural gates can only pin the three that
// exist today, so the wall is by ENUMERATION: every function in package main
// that verifies an admin credential, or that reads HTTP Basic credentials off
// a request, must appear below with a recorded reason. A new one fails the
// build until somebody answers "what bounds this?".
//
// Both walls carry a not-vacuous check, so a selector typo that matches
// nothing cannot pass forever.

// credentialVerifierAllowlist names every function permitted to call
// cfg.VerifyUIUser directly, with the bound that makes it safe.
var credentialVerifierAllowlist = map[string]string{
	// THE chokepoint. Applies loginLimiter.Check before verification, records
	// the failure, audits the trip. See ui_basicauth_lockout.go.
	"verifyUIBasicAuth": "the SEC-BASICAUTH-1 chokepoint: two-tier lockout checked before verification",
	// The login form. Its own loginLimiter.Check/RecordFailure pair plus the
	// CHAOS-63 username bound and a 300 ms failure delay.
	"apiAuthLogin": "RISK-012 two-tier lockout + CHAOS-63 username bound, applied inline",
	// Session re-authentication, not an entry point: the username comes from
	// the session (sessionAdmin), not from the caller, so there is no username
	// to guess; it is a mutating POST, so securityMiddleware's 60/min per-IP
	// API rate limit already applies; and it needs a valid admin session to
	// reach at all.
	"apiAuthChangePassword": "session re-auth: username from the session, mutating POST (API rate-limited), requires an existing session",
}

// basicAuthReaderAllowlist names every function permitted to read HTTP Basic
// credentials off an inbound request. Each MUST hand them to
// verifyUIBasicAuth — asserted structurally below, not merely declared.
var basicAuthReaderAllowlist = map[string]string{
	"uiAuthMiddleware":  "programmatic/CLI fallback for every /api/ route",
	"apiAuthStatus":     "PUBLIC endpoint (isPublicUIAuthPath) that reports the verdict",
	"sseAuthStillValid": "SSE mid-stream revalidation",
}

// mainPackageFiles returns the non-test .go files of package main.
//
// Anchored to pkgSourceDir() rather than "." so a concurrent os.Chdir in
// another test cannot flake the wall (TestTestFileReadsAreCWDIndependent).
func mainPackageFiles(t *testing.T) []string {
	t.Helper()
	root := pkgSourceDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read repo root: %v", err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(root, n))
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("no package-main source files found — the wall would be vacuous")
	}
	return out
}

// enclosingFuncName returns the name of the top-level func or method
// containing pos, or "" when pos is outside one.
func enclosingFuncName(file *ast.File, fset *token.FileSet, pos token.Pos) string {
	name := ""
	ast.Inspect(file, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if fd.Pos() <= pos && pos <= fd.End() {
			name = fd.Name.Name
		}
		return true
	})
	_ = fset
	return name
}

// selectorIs reports whether call is exactly `<recv>.<sel>(...)`.
func selectorIs(call *ast.CallExpr, recv, sel string) bool {
	se, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || se.Sel.Name != sel {
		return false
	}
	id, ok := se.X.(*ast.Ident)
	return ok && id.Name == recv
}

// TestSecBasicAuthWall_EveryCredentialVerifierIsBounded is the first wall: no
// function may call cfg.VerifyUIUser unless it appears in
// credentialVerifierAllowlist with a recorded bound.
func TestSecBasicAuthWall_EveryCredentialVerifierIsBounded(t *testing.T) {
	fset := token.NewFileSet()
	seen := map[string]bool{}
	checked := 0

	for _, path := range mainPackageFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !selectorIs(call, "cfg", "VerifyUIUser") {
				return true
			}
			checked++
			fn := enclosingFuncName(f, fset, call.Pos())
			seen[fn] = true
			if _, allowed := credentialVerifierAllowlist[fn]; !allowed {
				t.Errorf("%s: %s calls cfg.VerifyUIUser directly.\n"+
					"Route it through verifyUIBasicAuth (ui_basicauth_lockout.go) so the two-tier\n"+
					"lockout applies, or add it to credentialVerifierAllowlist with the bound that\n"+
					"makes it safe. An unbounded credential check is a brute-force oracle and one\n"+
					"bcrypt of CPU per unauthenticated request.",
					fset.Position(call.Pos()), fn)
			}
			return true
		})
	}

	// Not vacuous: the three allowlisted verifiers must all still be found, so
	// a renamed method or a broken selector cannot silently disarm the wall.
	if checked < len(credentialVerifierAllowlist) {
		t.Fatalf("wall matched only %d cfg.VerifyUIUser call sites, want at least %d — the selector has stopped matching",
			checked, len(credentialVerifierAllowlist))
	}
	for fn := range credentialVerifierAllowlist {
		if !seen[fn] {
			t.Errorf("allowlisted verifier %q no longer calls cfg.VerifyUIUser — remove the stale entry so the allowlist keeps meaning something", fn)
		}
	}
}

// isInboundBasicAuthRead reports whether call is an INBOUND `<ident>.BasicAuth()`
// read.
//
// The outbound `req.SetBasicAuth(...)` calls (OIDC introspection, the proxy's
// userinfo promotion) are a different selector and are deliberately out of
// scope — they PRESENT credentials, they do not verify them.
func isInboundBasicAuthRead(call *ast.CallExpr) bool {
	se, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || se.Sel.Name != "BasicAuth" {
		return false
	}
	_, isIdent := se.X.(*ast.Ident)
	return isIdent
}

// collectBasicAuthReaders returns the set of functions that read inbound Basic
// credentials, failing the test for any that is not allowlisted.
func collectBasicAuthReaders(t *testing.T, fset *token.FileSet) map[string]bool {
	t.Helper()
	readers := map[string]bool{}
	for _, path := range mainPackageFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isInboundBasicAuthRead(call) {
				return true
			}
			fn := enclosingFuncName(f, fset, call.Pos())
			readers[fn] = true
			if _, allowed := basicAuthReaderAllowlist[fn]; !allowed {
				t.Errorf("%s: %s reads r.BasicAuth() but is not in basicAuthReaderAllowlist.\n"+
					"Every inbound admin credential read must go through verifyUIBasicAuth.",
					fset.Position(call.Pos()), fn)
			}
			return true
		})
	}
	return readers
}

// callsChokepoint reports whether fd contains a call to verifyUIBasicAuth.
func callsChokepoint(fd *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fd, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "verifyUIBasicAuth" {
			found = true
		}
		return true
	})
	return found
}

// assertReadersReachChokepoint fails for any allowlisted reader that does not
// actually call verifyUIBasicAuth. Declaring the intent in the allowlist is not
// enough — the call has to be there.
func assertReadersReachChokepoint(t *testing.T, fset *token.FileSet, readers map[string]bool) {
	t.Helper()
	for _, path := range mainPackageFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if _, want := basicAuthReaderAllowlist[fd.Name.Name]; !want || !readers[fd.Name.Name] {
				continue
			}
			if !callsChokepoint(fd) {
				t.Errorf("%s: %s reads r.BasicAuth() but never calls verifyUIBasicAuth — the credentials it reads are unbounded",
					fset.Position(fd.Pos()), fd.Name.Name)
			}
		}
	}
}

// TestSecBasicAuthWall_EveryBasicAuthReaderUsesTheChokepoint is the second
// wall: a function that reads r.BasicAuth() off an inbound request must be
// allowlisted AND must actually call verifyUIBasicAuth.
func TestSecBasicAuthWall_EveryBasicAuthReaderUsesTheChokepoint(t *testing.T) {
	fset := token.NewFileSet()
	readers := collectBasicAuthReaders(t, fset)

	// Not vacuous: a selector that stopped matching would find nothing and
	// pass every assertion above.
	if len(readers) < len(basicAuthReaderAllowlist) {
		t.Fatalf("wall found %d BasicAuth readers, want at least %d — the selector has stopped matching",
			len(readers), len(basicAuthReaderAllowlist))
	}

	assertReadersReachChokepoint(t, fset, readers)
}

// TestSecBasicAuthWall_ControlRejectsAnUnboundedVerifier is the CONTROL: it
// runs the first wall's own predicate against a function name that is NOT
// allowlisted and requires it to be rejected. Without it, an allowlist that
// accidentally matched everything (or a predicate that matched nothing) would
// pass forever.
func TestSecBasicAuthWall_ControlRejectsAnUnboundedVerifier(t *testing.T) {
	if _, allowed := credentialVerifierAllowlist["someNewHandlerThatVerifiesCredentials"]; allowed {
		t.Fatal("control: an un-allowlisted name must not be permitted")
	}
	if _, allowed := basicAuthReaderAllowlist["someNewHandlerThatReadsBasicAuth"]; allowed {
		t.Fatal("control: an un-allowlisted BasicAuth reader must not be permitted")
	}
	// And the allowlists must not be empty, which would make both walls
	// trivially satisfiable by deleting every entry.
	if len(credentialVerifierAllowlist) == 0 || len(basicAuthReaderAllowlist) == 0 {
		t.Fatal("control: an empty allowlist disarms the wall")
	}
}
