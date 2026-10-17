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
	"os/exec"
	"path/filepath"
	"slices"
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
// X-HTTP-Method-Override on form POSTs. The package used to be COMPILED IN
// (sigstore-go -> rekor-tiles' generated protobuf package, whose server-side
// rekor_service.pb.gw.go imports it) even though nothing served a gateway mux.
// third_party/rekor-tiles is upstream v2.3.0 minus that one file
// (CULVERT-PATCH.md), so the vulnerable package is in no build graph. This
// test pins that for every module this repository ships or verifies with,
// and that the importer itself is still linked from the fork (not vacuous).
func TestNoModuleBuildsGrpcGatewayRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("go list over the modules is not a -short check")
	}
	const (
		forbidden = "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
		importer  = "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	)
	for _, mod := range []string{".", "cmd/culvert-maint", "pkg/releaseproof"} {
		pkgs := shippedGraph(t, mod)
		if !slices.Contains(pkgs, importer) {
			t.Errorf("module %s: %s is not linked — the check would pass against anything", mod, importer)
		}
		for _, p := range pkgs {
			if p == forbidden || strings.HasPrefix(p, forbidden+"/") {
				t.Errorf("module %s builds %s (CVE-2026-37236, no fixed release); is it still replaced by third_party/rekor-tiles?", mod, p)
			}
		}
		cmd := exec.CommandContext(t.Context(), "go", "list", "-m", "-f", "{{.Dir}}", "github.com/sigstore/rekor-tiles/v2")
		cmd.Dir = mod
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -m in %s: %v", mod, err)
		}
		if !strings.HasSuffix(filepath.ToSlash(strings.TrimSpace(string(out))), "third_party/rekor-tiles") {
			t.Errorf("module %s resolves rekor-tiles to %s, not the fork", mod, strings.TrimSpace(string(out)))
		}
	}
}
