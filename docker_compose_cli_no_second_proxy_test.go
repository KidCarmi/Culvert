//go:build proxybinload

package main

// docker_compose_cli_no_second_proxy_test.go — deployment-artifact contract:
// the `cli` service's compose `command:` must never let the shipped binary
// fall through into normal proxy/admin-UI startup.
//
// docker-compose.yml's `cli` service shares the SAME image and the SAME
// proxy-data volume (rw) as the `proxy` service, is intentionally given no
// port mapping, and its comment claims:
//
//	"The Dockerfile ENTRYPOINT is `./culvert`; the empty command here clears
//	 the daemon CMD so an accidental `docker compose --profile cli up -d`
//	 would not start a second proxy."
//
// That claim does not hold. main.go's one-shot dispatch
// (handleOneShotCommands) only os.Exit()s when one of the backup/restore/
// list/cleanup/reset-password flags is set; with NO flags at all — exactly
// what an empty `command: []` produces — it returns normally and main()
// falls straight through loadFileConfigAndFlags → ... → buildAndStartProxyServer
// → startAdminUI, i.e. a full second Culvert proxy + admin UI, writing to the
// same /data the running `proxy` container owns (ca.bundle, policy.json,
// ui_users.json, audit.jsonl, cluster.json, ...). `docker compose --profile
// cli up -d` (a one-character slip from the documented `run --rm cli
// <flags>`) silently starts this second instance instead of doing nothing.
//
// This test runs the actual binary with the `cli` service's real `command:`
// args (parsed straight from docker-compose.yml, so it tracks the file) and
// requires it to exit on its own, quickly, rather than linger as a listening
// server.
import (
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// cliServiceCommandArgs extracts the `cli` service's flow-style `command:
// [...]` array from docker-compose.yml, mirroring the block-scoping approach
// in docker_compose_cli_ca_passphrase_test.go / install_script_compose_
// command_flags_scope_test.go.
func cliServiceCommandArgs(t *testing.T) []string {
	t.Helper()
	compose, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	s := string(compose)

	cliHeader := regexp.MustCompile(`(?m)^ {2}cli:`)
	loc := cliHeader.FindStringIndex(s)
	if loc == nil {
		t.Fatal("docker-compose.yml has no top-level `cli:` service")
	}
	rest := s[loc[1]:]
	nextKey := regexp.MustCompile(`(?m)^ {2}[a-zA-Z0-9_-]+:`)
	if end := nextKey.FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}

	cmdLine := regexp.MustCompile(`(?m)^\s*command:\s*(\[[^\]\n]*\])\s*$`)
	m := cmdLine.FindStringSubmatch(rest)
	if m == nil {
		t.Fatal("docker-compose.yml `cli` service has no flow-style `command: [...]` line")
	}
	var args []string
	for _, mm := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(m[1], -1) {
		args = append(args, mm[1])
	}
	return args
}

// TestDockerComposeCLIServiceCannotStartSecondProxy proves the `cli`
// service's compose `command:` causes the shipped binary to exit on its own
// (a genuine one-shot / usage-and-exit path) instead of falling through to
// full proxy+admin-UI startup — the failure mode an accidental `docker
// compose --profile cli up -d` would otherwise trigger against the shared
// proxy-data volume.
func TestDockerComposeCLIServiceCannotStartSecondProxy(t *testing.T) {
	ensureWritableDataDir(t)
	bin := buildOrFindBinary(t)
	args := cliServiceCommandArgs(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	proc := exec.CommandContext(ctx, bin, args...)
	var out strings.Builder
	proc.Stdout = &out
	proc.Stderr = &out
	proc.Dir = "."
	if err := proc.Start(); err != nil {
		t.Fatalf("start culvert %v: %v", args, err)
	}

	exited := make(chan error, 1)
	go func() { exited <- proc.Wait() }()

	deadline := time.After(8 * time.Second)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-exited:
			// Exited on its own within the budget — the safe, intended outcome.
			return
		case <-tick.C:
			conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:8080", 300*time.Millisecond)
			if dialErr == nil {
				conn.Close()
				_ = proc.Process.Kill()
				<-exited
				t.Fatalf("cli service `command: %v` started the culvert binary as a full proxy "+
					"listening on :8080 instead of exiting — an accidental `docker compose --profile "+
					"cli up -d` would run a SECOND proxy against the shared proxy-data volume.\noutput:\n%s",
					args, out.String())
			}
		case <-deadline:
			_ = proc.Process.Kill()
			<-exited
			t.Fatalf("cli service `command: %v` left the culvert binary running for >8s without "+
				"exiting or opening :8080 — expected an immediate one-shot exit.\noutput:\n%s",
				args, out.String())
		}
	}
}
