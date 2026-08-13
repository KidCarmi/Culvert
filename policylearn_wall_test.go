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
	dir := filepath.Join(pkgSourceDir(), "internal", "policylearn")
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

// TestPolicyLearnWall_NoPolicyMutationTokens (M4): the import-surface wall
// already makes reaching enforcement state impossible at compile-graph level;
// this pins the intent at the identifier level too — recommendation generation
// must never grow a call path toward the policy write pipeline (ADR-0025: M5
// translates accepted recommendations into draft rules OUTSIDE this package,
// at the trust boundary). ProposedRule is an engine-owned DTO, never the root
// PolicyRule type.
func TestPolicyLearnWall_NoPolicyMutationTokens(t *testing.T) {
	forbidden := []string{
		"policyWriteStore", "PolicyStore", "PolicyRule",
		"commitDraft", "applyConfigBackup", "ReplaceAll(",
	}
	for _, file := range policylearnSourceFiles(t, false) {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		for _, tok := range forbidden {
			if strings.Contains(src, tok) {
				t.Errorf("%s references %q — recommendation generation must have no path toward policy mutation (ADR-0025 M4 wall)", file, tok)
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

// TestPolicyLearnWall_RequestPathOneWayTransport: the runtime→learning
// coupling is exactly ONE narrow adapter (M2). proxy.go may call
// learnObserveDecision and nothing else of the learning subsystem — never the
// singleton or the package directly; every other request-path/enforcement file
// references nothing of it. The transport is one-way: runtime → observation →
// learning. Learning has no path back into enforcement (the import-surface
// test above makes the reverse direction impossible at compile-graph level).
func TestPolicyLearnWall_RequestPathOneWayTransport(t *testing.T) {
	// proxy.go: the adapter call only.
	raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), "proxy.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "policyLearnEngine") || strings.Contains(string(raw), "policylearn.") {
		t.Error("proxy.go touches the learning singleton/package directly — only the learnObserveDecision adapter is permitted (M2)")
	}
	if !strings.Contains(string(raw), "learnObserveDecision(") {
		t.Error("proxy.go no longer emits the M2 observation — if deliberate, update this wall test with the design change")
	}
	// Every other enforcement/request-path file: zero learning references.
	for _, file := range []string{"proxy_http.go", "proxy_tunnel.go", "proxy_tunnel_h2.go", "socks5.go", "policy.go", "policy_draft.go", "store.go"} {
		raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		src := string(raw)
		for _, tok := range []string{"policyLearn", "policylearn", "learnObserve"} {
			if strings.Contains(src, tok) {
				t.Errorf("%s references the learning subsystem (%q) — only proxy.go's single adapter call is permitted", file, tok)
			}
		}
	}
}
