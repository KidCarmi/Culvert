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

// argv_guard_chaos122_test.go — CHAOS-122c.
//
// The maintenance agent shares the defect the round is about: Go's flag package
// stops at the first token that does not begin with "-" and silently discards
// every flag after it. Here the flag that would be discarded is --config, which
// selects the config file, and through it the journal, the compose path and the
// command allowlist this PRIVILEGED agent runs under. The systemd unit
// (packaging/systemd/culvert-maint.service) passes
// `--config /etc/culvert-maint/config.toml`, which happens to equal the
// built-in default, so the unit is unaffected either way; a deployment whose
// config lives anywhere else would have silently run against the default path
// instead of refusing.
//
// The agent takes no positional operands at all, so the contract is simply
// that any unparsed tail is refused before the config is read or the socket is
// bound. This is exec-based because the check lives in main().
func TestChaos122_AgentRefusesAPositionalTail(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "culvert-maint")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build culvert-maint: %v\n%s", err, out)
	}

	// A stray token ahead of --config: before this round the agent booted and
	// read the DEFAULT config path instead.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cfg := filepath.Join(t.TempDir(), "operator-config.toml")
	cmd := exec.CommandContext(ctx, bin, "stray", "--config", cfg)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the agent did not refuse the argv; it was still running after the budget.\noutput:\n%s", out)
	}
	if err == nil {
		t.Fatalf("a positional tail must be refused; the agent exited 0.\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "unexpected argument") {
		t.Errorf("expected an unexpected-argument refusal naming the cause; got:\n%s", out)
	}
	// The refusal must precede config handling: the operator's config does not
	// exist here, and the message must be about the argv, not about that file.
	if strings.Contains(string(out), cfg) && !strings.Contains(string(out), "unexpected argument") {
		t.Errorf("the argv refusal must come before the config is read; got:\n%s", out)
	}

	// Negative control: --version is a flags-only argv and must still work,
	// proving the guard did not simply break the binary.
	ctl := exec.CommandContext(ctx, bin, "--version")
	cout, cerr := ctl.CombinedOutput()
	if cerr != nil {
		t.Errorf("a flags-only argv must be unaffected by the guard; --version failed: %v\n%s", cerr, cout)
	}
	if strings.Contains(string(cout), "unexpected argument") {
		t.Errorf("--version must not trip the argv guard; got %q", cout)
	}
	_ = os.Remove(bin)
}
