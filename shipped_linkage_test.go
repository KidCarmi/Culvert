package main

// shipped_linkage_test.go — a scanner finding whose code no shipped binary
// links is closed by a GATE, not by a note.
//
// GO-2026-5932 (Snyk, golang.org/x/crypto/openpgp, no fixed release) is
// reported at MODULE granularity: x/crypto is in go.mod, so the advisory
// matches whether or not the vulnerable package is compiled. It is not: no
// package of either Go module in this repository imports openpgp outside
// tests (the only importer is sigstore-go's pkg/testing/ca, a TEST helper,
// which ships in no binary). This test turns that statement into an
// invariant over the real build graph of both modules, so a dependency bump
// or a new import that starts linking openpgp fails here instead of
// silently making the disposition false.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// shippedGraph returns `go list -deps ./...` (no tests) for the module in dir.
func shippedGraph(t *testing.T, dir string) []string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "./...")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list in %s: %v\n%s", dir, err, out)
	}
	return strings.Fields(string(out))
}

func TestShippedBinariesDoNotLinkOpenPGP(t *testing.T) {
	if testing.Short() {
		t.Skip("go list over the modules is not a -short check")
	}
	const forbidden = "golang.org/x/crypto/openpgp"
	for _, mod := range []string{".", "cmd/culvert-maint"} {
		pkgs := shippedGraph(t, mod)
		// Not vacuous: x/crypto IS linked (ssh, bcrypt, …), only openpgp is not.
		sawCrypto := false
		for _, p := range pkgs {
			if strings.HasPrefix(p, "golang.org/x/crypto/") {
				sawCrypto = true
			}
			if p == forbidden || strings.HasPrefix(p, forbidden+"/") {
				t.Errorf("module %s links %s (GO-2026-5932, no fixed release) into a shipped binary", mod, p)
			}
		}
		if !sawCrypto {
			t.Errorf("module %s: no golang.org/x/crypto package in the graph — the check would pass against anything", mod)
		}
	}
}

// CVE-2026-37236 (SNYK-GOLANG-GITHUBCOMGRPCECOSYSTEMGRPCGATEWAYV2RUNTIME-19432132,
// no fixed release): grpc-gateway's runtime.(*ServeMux).ServeHTTP honours
// X-HTTP-Method-Override on form POSTs. Unlike openpgp, grpc-gateway/v2/runtime
// IS compiled in (sigstore-go -> rekor-tiles' generated protobuf package, whose
// .pb.gw.go server registration file imports it), so a package-level gate
// cannot close it. What the LINKER keeps can: neither shipped binary serves a
// gateway mux, so dead-code elimination drops ServeMux entirely and keeps only
// the package init, the route-pattern constructor its importer's init calls
// with compile-time constants, and scalar converters. This test builds each
// binary that links the package (without -s, so the symbol table survives;
// stripping happens after dead-code elimination and does not change it) and
// fails if any OTHER runtime function is linked — a new caller would put the
// vulnerable mux, its marshalers or its error handlers back in a binary.
var gatewayRuntimeAllowed = map[string]bool{
	"init": true, "NewPattern": true,
	"Bool": true, "Bytes": true, "String": true,
	"Float32": true, "Float64": true, "Int32": true, "Int64": true, "Uint32": true, "Uint64": true,
}

func TestShippedBinariesDoNotLinkGatewayServeMux(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the shipped binaries")
	}
	const pkg = "github.com/grpc-ecosystem/grpc-gateway/v2/runtime."
	for _, b := range []struct{ dir, target string }{{".", "."}, {"cmd/culvert-maint", "."}} {
		out := filepath.Join(t.TempDir(), "bin")
		build := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-o", out, b.target) // #nosec G204 -- fixed tool, test-owned temp path
		build.Dir = b.dir
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if msg, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b.dir, err, msg)
		}
		nm, err := exec.CommandContext(t.Context(), "go", "tool", "nm", out).Output() // #nosec G204 -- fixed tool, test-owned temp path
		if err != nil {
			t.Fatalf("nm %s: %v", b.dir, err)
		}
		sawInit := false
		for _, line := range strings.Split(string(nm), "\n") {
			f := strings.Fields(line)
			if len(f) < 3 || f[1] != "T" || !strings.HasPrefix(f[2], pkg) {
				continue
			}
			name := strings.TrimPrefix(f[2], pkg)
			base, _, _ := strings.Cut(name, ".") // init.func1 -> init
			if base == "init" {
				sawInit = true
			}
			if !gatewayRuntimeAllowed[base] {
				t.Errorf("%s links grpc-gateway runtime.%s — gateway serving code is reachable (CVE-2026-37236 has no fix)", b.dir, name)
			}
		}
		// Not vacuous: the package IS in the binary and nm reported it.
		if !sawInit {
			t.Errorf("%s: no grpc-gateway runtime symbols at all — the check would pass against anything (did the dependency go away? then update the disposition)", b.dir)
		}
	}
}
