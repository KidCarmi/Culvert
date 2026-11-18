package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SEC-HA-TOKEN-ARGV-1. The HA standby join token is the AES-256-GCM
// key-wrapping passphrase for the CLUSTER CA private key in the HA state
// bundle (controlplane_server.go, CAKeyEncrypted), so whoever reads it can
// join as a standby and unwrap that key. -ha-token was its only channel, which
// put it in argv; /proc/<pid>/cmdline is readable by any account in the PID
// namespace, while /proc/<pid>/environ is restricted to the process owner
// (CWE-214). CULVERT_HA_TOKEN is the env channel, mirroring the two
// passphrases that already take this exception for the same reason.

// TestResolveHATokenInput_PrecedenceAndTrimming pins the resolver's whole
// contract, including the compatibility half: an existing deployment that
// passes -ha-token must behave EXACTLY as before, so the flag wins and its
// value is never rewritten.
func TestResolveHATokenInput_PrecedenceAndTrimming(t *testing.T) {
	for _, tc := range []struct {
		name            string
		flag, env, want string
	}{
		{"neither set", "", "", ""},
		{"flag only", "tok-flag", "", "tok-flag"},
		{"env only", "", "tok-env", "tok-env"},
		{"flag wins over env", "tok-flag", "tok-env", "tok-flag"},
		// Trimming is env-only: a token copied out of a deploy command or a
		// .env line easily picks up a trailing newline, and the failure it
		// causes (a standby that cannot authenticate) reads as a wrong token.
		{"env trailing newline trimmed", "", "tok-env\n", "tok-env"},
		{"env surrounding spaces trimmed", "", "  tok-env  ", "tok-env"},
		{"env tab and crlf trimmed", "", "\ttok-env\r\n", "tok-env"},
		{"env all whitespace becomes empty", "", "   \n", ""},
		// The flag is passed through verbatim — trimming it would change an
		// existing invocation's behaviour, which this fix must not do.
		{"flag whitespace preserved", " tok-flag ", "tok-env", " tok-flag "},
		{"flag whitespace-only still wins", " ", "tok-env", " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveHATokenInput(tc.flag, tc.env); got != tc.want {
				t.Errorf("resolveHATokenInput(%q, %q) = %q, want %q", tc.flag, tc.env, got, tc.want)
			}
		})
	}
}

// TestResolveHATokenInput_EmptyEnvCannotForgeAStandbyJoin is the negative
// control on the split-brain edge. haJoinMode() requires a NON-EMPTY token to
// treat a boot as a standby join, so a whitespace-only CULVERT_HA_TOKEN must
// resolve to "" and let that guard fire — not to " ", which would satisfy the
// non-empty test and send a blank token to the leader.
func TestResolveHATokenInput_EmptyEnvCannotForgeAStandbyJoin(t *testing.T) {
	for _, env := range []string{"", " ", "\n", "\t\r\n", "    "} {
		if got := resolveHATokenInput("", env); got != "" {
			t.Errorf("resolveHATokenInput(\"\", %q) = %q, want \"\": a blank token must not look like a "+
				"configured one to haJoinMode()", env, got)
		}
	}
	cfg := clusterStartupConfig{HAJoinAddr: "leader:50051", HAToken: resolveHATokenInput("", "   ")}
	if cfg.haJoinMode() {
		t.Error("a whitespace-only CULVERT_HA_TOKEN was accepted as a standby join token")
	}
}

// TestHATokenEnv_IsReadAndNotLogged pins the two properties of the env name
// itself: the startup path actually reads it, and neither the name's value nor
// the token is written to a log line. A secret that reaches the log has only
// moved from one world-readable place to another.
func TestHATokenEnv_IsReadAndNotLogged(t *testing.T) {
	if haTokenEnv != "CULVERT_HA_TOKEN" { // #nosec G101 -- env-var name, not a credential (same suppression as its declaration in main.go)
		t.Errorf("haTokenEnv = %q, want CULVERT_HA_TOKEN (the shipped compose names it literally)", haTokenEnv)
	}
	// os.Getenv(haTokenEnv) must be wired into the cluster config assembly.
	// Reads are anchored to pkgSourceDir() so a concurrent os.Chdir in another
	// test cannot flake them (static_read_wall_test.go).
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if !strings.Contains(string(src), "resolveHATokenInput(*s.haToken, os.Getenv(haTokenEnv))") {
		t.Error("main.go no longer resolves the HA token from haTokenEnv: the flag would be the only " +
			"channel again, putting the cluster-CA key-wrapping passphrase back into argv")
	}
	// No source file may log the resolved token.
	for _, f := range []string{"main.go", "cluster_startup_config.go", "cluster_startup.go"} {
		b, rerr := os.ReadFile(filepath.Join(pkgSourceDir(), f))
		if rerr != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, "HAToken") && !strings.Contains(line, "haToken") {
				continue
			}
			if strings.Contains(line, "logger.Printf") || strings.Contains(line, "obs.Printf") ||
				strings.Contains(line, "fmt.Print") {
				t.Errorf("%s logs the HA token: %q", f, strings.TrimSpace(line))
			}
		}
	}
}

// TestHADeployCommand_HandsTheTokenOverByEnvironment pins the operator-facing
// half of SEC-HA-TOKEN-ARGV-1. This string is generated by the leader's
// "Enable HA" panel for the admin to copy into a shell on the standby, so it
// decides what ends up in that node's argv for its whole lifetime. As
// `--ha-token <value>` it put the cluster-CA key-wrapping passphrase in
// /proc/<pid>/cmdline, readable by any account in the PID namespace; as a
// variable assignment prefixing the command the shell places it in the child's
// environment only, which /proc/<pid>/environ restricts to the process owner.
func TestHADeployCommand_HandsTheTokenOverByEnvironment(t *testing.T) {
	// Named for the sentinel it is, not for the credential it stands in for:
	// gosec G101 matches the IDENTIFIER against a credential-name pattern, and
	// a suppression here would conceal a match rather than avoid one
	// (conventions.md) — the same reasoning as haProbeSentinel.
	const deployProbeSentinel = "a3f8c1d2deadbeef"

	globalHA.mu.Lock()
	origToken, origPeer := globalHA.token, globalHA.peerAddr
	globalHA.token, globalHA.peerAddr = deployProbeSentinel, "leader.internal:50051"
	globalHA.mu.Unlock()
	t.Cleanup(func() {
		globalHA.mu.Lock()
		globalHA.token, globalHA.peerAddr = origToken, origPeer
		globalHA.mu.Unlock()
	})

	cmd := haDeployCommand()

	if strings.Contains(cmd, "--ha-token") || strings.Contains(cmd, "-ha-token ") {
		t.Errorf("the deploy command still passes the token as a flag, which puts it in the standby's "+
			"argv for the life of the process (CWE-214):\n%s", cmd)
	}
	if !strings.Contains(cmd, haTokenEnv+"="+deployProbeSentinel) {
		t.Errorf("the deploy command does not hand the token over in %s, so a standby pasting it would "+
			"never join:\n%s", haTokenEnv, cmd)
	}
	// The assignment must PREFIX the command, or the shell treats it as an
	// argument rather than an environment entry for the child.
	if !strings.HasPrefix(cmd, haTokenEnv+"=") {
		t.Errorf("the %s assignment must come first so the shell exports it to ./culvert rather than "+
			"passing it as an argv word:\n%s", haTokenEnv, cmd)
	}
	// The join target must still be there — removing the flag must not have
	// removed the pairing.
	if !strings.Contains(cmd, "--ha-join leader.internal:50051") {
		t.Errorf("the deploy command lost its --ha-join target:\n%s", cmd)
	}
}
