//go:build mcpacceptance_live

// The live acceptance self-test builds the real culvert binary and spawns several
// processes. It is gated behind the mcpacceptance_live build tag so the standard
// `go test ./...`, `-race`, and determinism gates never spawn binaries. Run it
// explicitly: `go test -tags mcpacceptance_live -run TestObserveAcceptance_Live ./internal/mcpacceptance/`.
package mcpacceptance

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// builtBinary is the culvert binary built once for the live acceptance tests.
var builtBinary string

func TestMain(m *testing.M) {
	// Build the real culvert binary once (the artifact under acceptance). Skip the
	// build in -short mode; the live tests skip themselves too.
	if !testingShort() {
		tmp, err := os.MkdirTemp("", "mcp-acc-bin-")
		if err == nil {
			bin := filepath.Join(tmp, "culvert")
			cmd := exec.Command("go", "build", "-o", bin, "github.com/KidCarmi/Culvert")
			cmd.Stderr = os.Stderr
			if berr := cmd.Run(); berr == nil {
				builtBinary = bin
			}
			defer os.RemoveAll(tmp)
		}
	}
	os.Exit(m.Run())
}

// testingShort reports -short without importing the flag before m.Run; we parse it
// lazily via the testing package once flags are set in TestMain's caller. Since
// flag parsing happens in m.Run, approximate by checking the env the CI uses.
func testingShort() bool { return os.Getenv("MCP_ACC_SKIP_LIVE") == "1" }

// TestObserveAcceptance_Live builds the real binary and runs the full acceptance in
// dev (non-authoritative) mode, asserting the run produces a PASS bundle bound to
// the built artifact, proves non-execution, and leaks no secret.
func TestObserveAcceptance_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("live acceptance skipped in -short")
	}
	if builtBinary == "" {
		t.Skip("culvert binary was not built (build failed or -short); skipping live acceptance")
	}
	evDir := t.TempDir()
	spec := &Spec{
		Mode:        ModeDev,
		Artifact:    ArtifactSpec{BinaryPath: builtBinary},
		EvidenceDir: evDir,
		Run: RunControl{
			StartupTimeout:  Duration(60 * time.Second),
			RequestTimeout:  Duration(15 * time.Second),
			ShutdownTimeout: Duration(20 * time.Second),
		},
	}
	h, err := NewHarness(spec, Options{SourceSHA: "test"})
	if err != nil {
		t.Fatalf("new harness: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	summary, err := h.Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// Print every non-pass criterion for diagnosis.
	for _, c := range summary.Criteria {
		if c.Status != StatusPass {
			t.Logf("criterion %s [%s] required=%v observed=%q reason=%q", c.ID, c.Status, c.Required, c.Observed, c.Reason)
		}
	}
	for _, n := range summary.Notes {
		t.Logf("note: %s", n)
	}

	if summary.Authoritative {
		t.Fatal("dev run must never be authoritative")
	}
	if summary.Overall != StatusPass {
		t.Fatalf("overall acceptance = %s (want PASS)", summary.Overall)
	}
	if summary.NonExecution != StatusPass {
		t.Fatalf("non-execution = %s (want PASS)", summary.NonExecution)
	}
	if summary.RestartResult != StatusPass {
		t.Fatalf("restart = %s (want PASS)", summary.RestartResult)
	}
	if summary.EmergencyDisable != StatusPass {
		t.Fatalf("emergency disable = %s (want PASS)", summary.EmergencyDisable)
	}

	// Two-tenant matrix: 4 cells, cross-tenant denied, same-tenant reached policy.
	if len(summary.TenantMatrix) < 4 {
		t.Fatalf("tenant matrix has %d cells, want >=4", len(summary.TenantMatrix))
	}
	for _, cell := range summary.TenantMatrix {
		if cell.Status != StatusPass {
			t.Fatalf("tenant matrix cell %s->%s failed: %s", cell.Token, cell.Server, cell.Observed)
		}
	}

	// Evidence bundle exists and is tamper-manifested; no secret leak.
	mustExist(t, filepath.Join(evDir, "summary.json"))
	mustExist(t, filepath.Join(evDir, "manifest.json"))
	if _, err := os.Stat(filepath.Join(evDir, "secret_scan_violations.json")); err == nil {
		t.Fatal("secret scan reported violations in the evidence bundle")
	}

	// The artifact digest in the summary must equal a fresh hash of the binary.
	dig, _ := hashBinary(builtBinary)
	if summary.Artifact.Digest != dig {
		t.Fatalf("artifact digest %s != binary hash %s", summary.Artifact.Digest, dig)
	}
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected evidence file %s: %v", path, err)
	}
}
