package main

// install_runner_token_prompt_pipe_test.go — scripts/install-runner.sh must
// not read the runner token from the script's own stdin.
//
// The script's documented invocation is
//
//	curl -fsSL .../scripts/install-runner.sh | bash
//
// and when RUNNER_TOKEN is unset it prompts with a bare `read`. Under that
// invocation stdin IS the script: bash reads a piped script line by line and
// parses the whole `if ... fi` block before running it, so the `read` consumed
// the script's first line AFTER `fi` as the "token". That line is blank, so
// every interactive `curl | bash` run without RUNNER_TOKEN died at once with
// "Token cannot be empty." — the operator never got to paste a token — and a
// non-blank line there would instead have been swallowed as the token and
// silently skipped.
//
// The contract held here: with no RUNNER_TOKEN and no terminal to prompt on,
// the token section stops with an error naming RUNNER_TOKEN and nothing after
// it runs; with RUNNER_TOKEN set, the section passes it through unchanged.

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// runnerTokenSection returns scripts/install-runner.sh up to (not including)
// its Docker-install section: the config block, helpers and the token check.
func runnerTokenSection(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("scripts/install-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	const marker = "# 1. Install Docker"
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("marker %q not found in install-runner.sh", marker)
	}
	// Cut at the start of the banner line that precedes the marker.
	head := src[:i]
	if j := strings.LastIndex(strings.TrimRight(head, "\n"), "\n"); j >= 0 {
		head = head[:j+1]
	}
	return head
}

// pipeRunnerTokenSection feeds the token section, followed by a probe line,
// to `bash` on STDIN (the `curl | bash` shape) with no controlling terminal.
func pipeRunnerTokenSection(t *testing.T, env ...string) (string, error) {
	t.Helper()
	script := runnerTokenSection(t) + "printf 'PROBE token=<%s>\\n' \"$RUNNER_TOKEN\"\n"
	cmd := exec.CommandContext(t.Context(), "bash")
	cmd.Stdin = strings.NewReader(script)
	// No controlling terminal, as under cron/ssh -T/CI: /dev/tty cannot open.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestInstallRunner_PipedWithoutToken_DoesNotConsumeScriptAsToken(t *testing.T) {
	out, err := pipeRunnerTokenSection(t)
	if strings.Contains(out, "PROBE") {
		t.Fatalf("token section continued past the token check under `curl | bash` with no token:\n%s", out)
	}
	if err == nil {
		t.Fatalf("token section exited 0 with no token and no terminal:\n%s", out)
	}
	// The prompt read the script's own next line instead of a terminal; the
	// operator is told to set RUNNER_TOKEN, not that they typed nothing.
	if strings.Contains(out, "Token cannot be empty") || !strings.Contains(out, "RUNNER_TOKEN") {
		t.Fatalf("prompt read the piped script instead of a terminal; error must tell the operator to set RUNNER_TOKEN:\n%s", out)
	}
}

func TestInstallRunner_PipedWithToken_PassesThrough(t *testing.T) {
	out, err := pipeRunnerTokenSection(t, "RUNNER_TOKEN=AABBCC123")
	if err != nil {
		t.Fatalf("token section failed with RUNNER_TOKEN set: %v\n%s", err, out)
	}
	if !strings.Contains(out, "PROBE token=<AABBCC123>") {
		t.Fatalf("RUNNER_TOKEN not passed through unchanged:\n%s", out)
	}
}
