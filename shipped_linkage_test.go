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
