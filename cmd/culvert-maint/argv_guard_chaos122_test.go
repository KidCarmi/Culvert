package main

import (
	"context"
	"os/exec"
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
// bound. This is exec-based because the check lives in main(). The argv is all
// constants (`go run .` rather than a built binary at a temp path) so gosec's
// G204 can resolve it without a suppression.

// argvTestConfig does not exist, which is the point: the refusal must come
// before any config is read, so the output must be about the argv, not the file.
const argvTestConfig = "/nonexistent/culvert-maint-chaos122/operator-config.toml"

func TestChaos122_AgentRefusesAPositionalTail(t *testing.T) {
	// The budget covers a cold `go run` compile. Without the guard the agent
	// does not exit at all, so the deadline is what turns that into a failure;
	// WaitDelay bounds the wait for the pipes once the go command is killed.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// A stray token ahead of --config: before this round the agent booted and
	// read the DEFAULT config path instead. The tail also carries an unknown
	// credential-shaped flag whose value must not be echoed to stderr.
	cmd := exec.CommandContext(ctx, "go", "run", ".", "stray", "--passphrase", "review-secret", "--config", argvTestConfig)
	cmd.WaitDelay = 5 * time.Second
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
	if !strings.Contains(string(out), `"stray"`) || !strings.Contains(string(out), "--config <value>") {
		t.Errorf("the refusal must name the stray token and the discarded flags; got:\n%s", out)
	}
	if strings.Contains(string(out), "review-secret") || strings.Contains(string(out), argvTestConfig) {
		t.Errorf("the refusal must not echo a discarded value (it may be a credential); got:\n%s", out)
	}

	// Negative control: --version is a flags-only argv and must still work,
	// proving the guard did not simply break the binary.
	ctl := exec.CommandContext(ctx, "go", "run", ".", "--version")
	ctl.WaitDelay = 5 * time.Second
	cout, cerr := ctl.CombinedOutput()
	if cerr != nil {
		t.Errorf("a flags-only argv must be unaffected by the guard; --version failed: %v\n%s", cerr, cout)
	}
	if strings.Contains(string(cout), "unexpected argument") {
		t.Errorf("--version must not trip the argv guard; got %q", cout)
	}
}
