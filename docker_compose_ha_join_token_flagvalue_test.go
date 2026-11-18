package main

// docker_compose_ha_join_token_flagvalue_test.go — deployment-artifact
// contract for docker-compose.ha.yml's proxy `command:` shell script.
//
// Step 4 of the file's own header comment instructs an operator standing up
// the HA standby node to "set HA_JOIN + HA_TOKEN env vars, then:
// docker compose -f docker-compose.ha.yml up -d". The embedded shell script
// builds the culvert argv as a single ARGS string and hands it to the binary
// via an UNQUOTED `exec ./culvert $$ARGS` — word-splitting is what turns that
// string back into separate argv tokens. That is fine as long as every
// variable substituted into ARGS is non-empty, but `--ha-token $$HA_TOKEN`
// used to be appended unconditionally inside the `if [ -n "$$HA_JOIN" ]`
// guard, which checked HA_JOIN, never HA_TOKEN. If an operator set HA_JOIN
// but left HA_TOKEN empty/unset (a plausible copy-paste slip, since the
// GUI's deploy command names both but nothing stops setting just one), the
// shell's word-splitting dropped the empty $$HA_TOKEN expansion ENTIRELY
// rather than emitting an empty argv token — leaving a dangling `--ha-token`
// flag with no value as the last word handed to the binary. Go's flag
// package rejected that outright ("flag needs an argument: -ha-token") and,
// because main.go calls the top-level flag.Parse() (ExitOnError), the
// process os.Exit(2)ed before ever reaching the proxy listener — the
// standby node crash-looped under restart: unless-stopped instead of
// joining the cluster.
//
// The first fix made `--ha-token` well-formed via the `=value` form even
// when empty (`--ha-token=`) — which stopped the crash, but Codex review on
// PR #1337 caught the real regression that traded it for: an EMPTY but
// well-formed --ha-token satisfies flag.Parse, yet
// clusterStartupConfig.haJoinMode() (cluster_startup_config.go) requires
// BOTH --ha-join and --ha-token to be non-empty to treat the boot as a
// standby join. The same ARGS string also sets -cp-grpc-addr :50051, so an
// empty token makes loadCluster fall through to cpMode() instead — the
// container comes up HEALTHY as an independent, ACTIVE Control Plane that
// never joins or replicates from Server A (a silent split-brain, worse than
// the crash it replaced, and invisible on healthchecks). The script now
// fails fast (exit 1, explicit stderr message) when HA_JOIN is set and
// HA_TOKEN is empty, before ever building ARGS or execing culvert.
import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// extractHAProxyCommandScript isolates the proxy service's `command: >`
// folded shell script from docker-compose.ha.yml and mirrors Compose's own
// "$$" -> "$" escaping, so the returned script behaves exactly as it would
// inside the container.
func extractHAProxyCommandScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("docker-compose.ha.yml")
	if err != nil {
		t.Fatalf("read docker-compose.ha.yml: %v", err)
	}
	s := string(data)

	// Isolate the proxy service's shell script — a one-element `command:`
	// sequence holding a `|` literal block, from just after the "- |" line to
	// the next same-indent "healthcheck:" key that terminates it.
	//
	// CHAOS-121 changed this shape. The script used to be a `command: >`
	// folded scalar that began with its own `sh -c '` wrapper, which was
	// APPENDED to the image's exec-form `ENTRYPOINT ["./culvert"]` — so the
	// container really ran `./culvert sh -c '<script>'` and the shell never
	// executed at all. The service now overrides `entrypoint:` to
	// ["/bin/sh","-c"] and passes the bare script as the single argv token
	// that entrypoint consumes, which is exactly what this helper's own
	// `sh -c script` invocation below has always simulated.
	cmdRE := regexp.MustCompile(`(?s)\n {4}command:\n {6}- \|\n(.*?)\n {4}healthcheck:`)
	m := cmdRE.FindStringSubmatch(s)
	if m == nil {
		t.Fatal("docker-compose.ha.yml: could not isolate the proxy service's `command:` script block — update this test if the file's shape changed")
	}
	return strings.ReplaceAll(m[1], "$$", "$")
}

// runHAProxyCommandScript extracts docker-compose.ha.yml's proxy `command:`
// script, replaces its terminal `exec ./culvert $ARGS` with a diagnostic
// that prints the ACTUAL argv the shell would hand to the binary (one token
// per line, via `set --` — the same unquoted-word-splitting mechanism the
// real `exec` line relies on), and runs it under `sh` with the given
// environment layered on top of the current process's own (matching
// docker-compose.yml's own test helper convention in this package).
func runHAProxyCommandScript(t *testing.T, env ...string) (argv []string, stderr string, exitErr error) {
	t.Helper()
	script := extractHAProxyCommandScript(t)

	execRE := regexp.MustCompile(`exec \./culvert \$ARGS`)
	if !execRE.MatchString(script) {
		t.Fatal("docker-compose.ha.yml: could not find the terminal `exec ./culvert $ARGS` line in the proxy command script — update this test if the file's shape changed")
	}
	script = execRE.ReplaceAllLiteralString(script, `set -- $ARGS; for a in "$@"; do printf "%s\n" "$a"; done`)

	// script is extracted verbatim from docker-compose.ha.yml (a file in
	// this repo, not attacker/caller input) immediately above, and the
	// command name/args here are fixed literals — nothing external reaches
	// this exec.CommandContext call.
	cmd := exec.CommandContext(t.Context(), "sh", "-c", script) // #nosec G204 -- script is this repo's own docker-compose.ha.yml content, not external input
	cmd.Env = append(os.Environ(), env...)
	var stdout, errBuf strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &errBuf
	exitErr = cmd.Run()
	stderr = errBuf.String()
	out := strings.TrimRight(stdout.String(), "\n")
	if out == "" {
		return nil, stderr, exitErr
	}
	return strings.Split(out, "\n"), stderr, exitErr
}

// TestDockerComposeHA_JoinWithoutTokenFailsFast proves the fix Codex review
// on PR #1337 required: an operator setting HA_JOIN but leaving HA_TOKEN
// empty must be refused up front, not silently promoted to an independent,
// active Control Plane (see the package doc comment above). The script must
// exit non-zero, print an explanatory message naming HA_TOKEN on stderr,
// and never reach the point of building/execing an argv at all.
func TestDockerComposeHA_JoinWithoutTokenFailsFast(t *testing.T) {
	argv, stderr, runErr := runHAProxyCommandScript(t,
		"HA_JOIN=server-a.internal:50051", "HA_TOKEN=",
		"CP_CERT=", "CP_KEY=", "CP_CA=")

	if runErr == nil {
		t.Fatalf("expected the command script to exit non-zero when HA_JOIN is set and HA_TOKEN is empty "+
			"(refusing to silently start as an independent Control Plane instead of a standby); it exited "+
			"0 and produced argv: %v", argv)
	}
	if argv != nil {
		t.Fatalf("expected no argv to be produced when HA_TOKEN is empty (the script must exit before "+
			"reaching `exec ./culvert`), got: %v", argv)
	}
	if !strings.Contains(stderr, "HA_TOKEN") {
		t.Fatalf("expected an error message naming HA_TOKEN on stderr, got: %q", stderr)
	}
}

// TestDockerComposeHA_JoinWithTokenYieldsValidArgv is the control for the
// fail-fast test above: with BOTH HA_JOIN and a real HA_TOKEN set (the
// documented, correct step-4 usage), the script must still run to
// completion and produce a well-formed argv containing the join flags —
// the fail-fast guard must not false-positive on the working case.
func TestDockerComposeHA_JoinWithTokenYieldsValidArgv(t *testing.T) {
	argv, stderr, runErr := runHAProxyCommandScript(t,
		"HA_JOIN=server-a.internal:50051", "HA_TOKEN=a3f8c1d2",
		"CP_CERT=", "CP_KEY=", "CP_CA=")

	if runErr != nil {
		t.Fatalf("running the extracted proxy command script failed: %v\nstderr:\n%s", runErr, stderr)
	}
	if len(argv) == 0 {
		t.Fatalf("extracted no argv tokens from the command script; stderr:\n%s", stderr)
	}

	// A flag token is well-formed here either because it isn't the LAST word
	// (something follows it as its value) or because it carries its value
	// inline via `=`. A flag-looking token that is BOTH last AND has no `=`
	// is a dangling flag with nothing for flag.Parse to consume as its value.
	last := argv[len(argv)-1]
	if strings.HasPrefix(last, "-") && !strings.Contains(last, "=") {
		t.Fatalf("docker-compose.ha.yml: generated argv ends with a dangling flag %q that has no value; "+
			"full argv: %v", last, argv)
	}
	if !argvContains(argv, "--ha-join") || !argvContains(argv, "server-a.internal:50051") {
		t.Fatalf("expected --ha-join server-a.internal:50051 in argv, got: %v", argv)
	}
	// SEC-HA-TOKEN-ARGV-1. This assertion is the INVERSE of what it was: it
	// used to require --ha-token=<value> in argv. CHAOS-121 made this script
	// actually execute, which expanded the token into culvert's argv for the
	// first time — and /proc/<pid>/cmdline is readable by any account in the
	// PID namespace, while /proc/<pid>/environ is restricted to the process
	// owner. The token is the key-wrapping passphrase for the CLUSTER CA
	// private key in the HA state bundle (controlplane_server.go,
	// CAKeyEncrypted), so an unprivileged local reader could join as a standby
	// and unwrap it. It now travels in CULVERT_HA_TOKEN instead.
	//
	// The -ha-token FLAG still exists and still wins when set (operators
	// invoking culvert directly are unaffected); what is pinned here is that
	// the shipped compose does not use it.
	for _, a := range argv {
		if strings.Contains(a, "a3f8c1d2") {
			t.Errorf("the HA join token appears in argv as %q: it must reach culvert through "+
				"CULVERT_HA_TOKEN, never the command line (CWE-214). Full argv: %v", a, argv)
		}
		if strings.HasPrefix(a, "--ha-token") || strings.HasPrefix(a, "-ha-token") {
			t.Errorf("the compose still passes %q: the token must come from the environment", a)
		}
	}
}

// TestDockerComposeHA_TokenReachesCulvertThroughTheEnvironment is the other
// half of SEC-HA-TOKEN-ARGV-1: removing the flag is only safe if the value
// still arrives. The `proxy` service — the only one that joins; `dp` enrolls
// through ENROLL_URL instead — must export CULVERT_HA_TOKEN, the name
// haTokenEnv declares, from the same ${HA_TOKEN} the operator sets. Without it
// a standby silently stops joining and comes up as an independent Control
// Plane: the split-brain the fail-fast guard above exists to prevent, which
// that guard would NOT catch, because it only checks that HA_TOKEN is set in
// the environment, not that culvert is given it.
func TestDockerComposeHA_TokenReachesCulvertThroughTheEnvironment(t *testing.T) {
	raw, err := os.ReadFile("docker-compose.ha.yml")
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	body := string(raw)
	if haTokenEnv != "CULVERT_HA_TOKEN" { // #nosec G101 -- env-var name, not a credential (same suppression as its declaration in main.go)
		t.Fatalf("haTokenEnv = %q: this test and the compose name the variable literally", haTokenEnv)
	}
	want := haTokenEnv + "=${HA_TOKEN:-}"
	if n := strings.Count(body, want); n != 1 {
		t.Errorf("docker-compose.ha.yml exports %q %d time(s), want 1 (the proxy service): culvert reads "+
			"the token from %s, so without that export a standby cannot authenticate its join", want, n, haTokenEnv)
	}
}

func argvContains(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}
