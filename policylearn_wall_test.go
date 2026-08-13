package main

// ADR-0025 architecture wall: internal/policylearn is ADVISORY-ONLY and must be
// structurally incapable of importing or mutating enforcement state —
// PolicyStore, TLS/decryption, PAC, CDR, default-action, blocklist, threat
// feed, or any other enforcement subsystem. All of those live in package main
// or in internal packages OUTSIDE the allowlist below, so pinning the import
// surface proves the incapability at compile-graph level (the same wall style
// as the PEI serve-path wall). The clock ban additionally pins the
// injected-clock contract (deterministic engine).

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// policylearnAllowedImports is the FULL non-stdlib import allowlist for
// internal/policylearn. Growing it is an ADR-0025 review event, not a
// convenience edit.
var policylearnAllowedImports = map[string]bool{
	"github.com/KidCarmi/Culvert/internal/fileutil": true, // AtomicWrite persistence
	"github.com/KidCarmi/Culvert/internal/obs":      true, // leaf logging facade (ADR-0003)
}

func policylearnSourceFiles(t *testing.T, includeTests bool) []string {
	t.Helper()
	dir := filepath.Join("internal", "policylearn")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var files []string
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if !includeTests && strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	if len(files) == 0 {
		t.Fatal("no source files found — wall test is vacuous")
	}
	return files
}

// TestPolicyLearnWall_ImportSurface: every import in every non-test file is
// stdlib or on the explicit allowlist.
func TestPolicyLearnWall_ImportSurface(t *testing.T) {
	fset := token.NewFileSet()
	for _, file := range policylearnSourceFiles(t, false) {
		f, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if !strings.Contains(strings.SplitN(path, "/", 2)[0], ".") {
				continue // stdlib (first path element has no dot)
			}
			if !policylearnAllowedImports[path] {
				t.Errorf("%s imports %q — outside the ADR-0025 wall (stdlib + %v). "+
					"internal/policylearn must not reach enforcement state; inject a narrow func value from root wiring instead.",
					file, path, policylearnAllowedImports)
			}
		}
	}
}

// TestPolicyLearnWall_NoWallClock: the engine never reads the wall clock —
// time.Now is banned in non-test files (Config.Now is the injected clock).
func TestPolicyLearnWall_NoWallClock(t *testing.T) {
	for _, file := range policylearnSourceFiles(t, false) {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "time.Now(") {
			t.Errorf("%s calls time.Now() — the engine must use the injected Config.Now (deterministic-clock contract)", file)
		}
	}
}

// TestPolicyLearnWall_MainNeverEvaluatesThroughLearning: no enforcement-path
// file references the learning singleton. The learning engine is observed BY
// root wiring; nothing on the request path may consult it in M1 (it is dead
// infrastructure until M2's explicit observation wiring).
func TestPolicyLearnWall_RequestPathUntouched(t *testing.T) {
	for _, file := range []string{"proxy.go", "proxy_http.go", "proxy_tunnel.go", "proxy_tunnel_h2.go", "socks5.go", "policy.go", "store.go"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.Contains(string(raw), "policyLearn") || strings.Contains(string(raw), "policylearn") {
			t.Errorf("%s references the learning engine — M1 forbids any request-path or policy-engine coupling (observation wiring is M2)", file)
		}
	}
}
