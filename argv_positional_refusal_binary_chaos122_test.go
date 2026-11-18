//go:build proxybinload

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// argv_positional_refusal_binary_chaos122_test.go — CHAOS-122, real-binary half.
//
// The decision logic and the main() ordering invariant are gated untagged in
// argv_positional_refusal_chaos122_test.go. This file drives the SHIPPED BINARY
// as a separate process, which is the only way to prove the end-to-end
// behaviour the round is about: that the argv CHAOS-121a produced is refused
// rather than booted. It follows the same `proxybinload` convention as
// docker_compose_cli_no_second_proxy_test.go, the existing real-binary gate for
// this same class of deployment-argv defect.

// ─── The real binary: the refusal, and that it leaves the data dir alone ──────

// TestChaos122_RealBinaryRefusesTheComposeArgvAndWritesNothing runs the SHIPPED
// binary with the argv CHAOS-121a produced. Before this round the same
// invocation started a full proxy + admin UI with every flag at its default and
// passed its health check; the static compose gate cannot cover an orchestrator
// the repository does not ship, so this is the gate that holds for all of them.
func TestChaos122_RealBinaryRefusesTheComposeArgvAndWritesNothing(t *testing.T) {
	bin := buildOrFindBinary(t)
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}

	// The exact shape: `./culvert sh -c '<script>'`.
	//
	// The deadline is load-bearing, not boilerplate: WITHOUT the guard this
	// invocation does not exit at all — it becomes a running proxy + admin UI —
	// so an unbounded CombinedOutput would HANG here instead of failing. That
	// is how the mutation run of this gate behaved before the deadline was
	// added, and a gate that hangs under the defect it pins is not a gate.
	const budget = 25 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "sh", "-c", `ARGS="-port 8080 -ca-path /data/ca.bundle -policy /data/policy.json"; exec ./culvert $ARGS`)
	cmd.Env = append(os.Environ(), "CULVERT_DATA_DIR="+dataDir)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the binary did not refuse this argv: it was still running after %s, i.e. it became a "+
			"gateway with no persisted Root CA, no policy and no audit log while /health reported ok "+
			"(CHAOS-121a).\noutput:\n%s", budget, out)
	}
	if err == nil {
		t.Fatalf("the binary must REFUSE this argv; it exited 0.\noutput:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !asExitError(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Errorf("expected exit code 2 (the flag package's usage-error code); got %v", err)
	}
	if !strings.Contains(string(out), "refusing to start") {
		t.Errorf("expected the refusal on stderr; got:\n%s", out)
	}

	// The no-effect half of the contract.
	entries, rerr := os.ReadDir(dataDir)
	if rerr != nil {
		t.Fatalf("read data dir: %v", rerr)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("a refused argv must change nothing in the persisted-state root; found %v", names)
	}

	// Negative control: the same binary, a flags-only one-shot argv, still runs.
	backupDir := t.TempDir()
	ctl := exec.Command(bin, "--list-backups", "--backup-dir", backupDir)
	ctl.Env = append(os.Environ(), "CULVERT_DATA_DIR="+dataDir)
	if cout, cerr := ctl.CombinedOutput(); cerr != nil {
		t.Errorf("a flags-only argv must be unaffected by the guard; --list-backups failed: %v\n%s", cerr, cout)
	} else if !strings.Contains(string(cout), "[]") {
		t.Errorf("expected the empty JSON array from --list-backups; got %q", cout)
	}
}

// asExitError is errors.As specialised to *exec.ExitError, kept local so this
// file carries no import the gates above do not need.
func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}
