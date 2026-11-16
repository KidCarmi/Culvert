package main

// install_script_env_put_required_test.go — a secret that env_put could not
// persist must FAIL the install, not warn and continue.
//
// env_put() degrades to success (warn + `return 0`) when it cannot take $file
// or "$file.lock" from another user. That trade is deliberate and right for a
// channel name, a catalog URL or a GID: install.sh calls
// `env_put CULVERT_INSTALL_CHANNEL …` unconditionally at top level under
// `set -euo pipefail`, so an abort there kills a whole re-run in a stack dir a
// first sudo/cloud-init install left root-owned.
//
// It is wrong for the three at-rest secrets. A CULVERT_CA_PASSPHRASE /
// CULVERT_LOG_PASSPHRASE / CULVERT_SESSION_SECRET that never reaches .env is
// not "unset until the operator fixes it": `docker compose up` resolves
// ${CULVERT_CA_PASSPHRASE:-} to EMPTY and the proxy persists the
// SSL-inspection Root CA private key, and saved request logs, UNENCRYPTED —
// while setup_at_rest_encryption goes on to print "Stored in: $envfile
// (chmod 600)" and "Encryption passphrase already configured". The operator is
// told at-rest encryption is on while it is off, and the CA key is the one
// secret a later re-run can never re-encrypt in place.
//
// install.sh already fails closed via error() on every OTHER way that intent
// could be dropped (a passphrase under the 12-character floor, a charset
// compose would re-interpolate, a degraded generator). env_put_required closes
// the remaining one by verifying, with the shared env_file_value_set
// predicate, that the write actually took effect.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// secretEnvVars are the values whose silent absence from .env downgrades
// security posture rather than merely leaving a setting unset.
var secretEnvVars = []string{
	"CULVERT_CA_PASSPHRASE",
	"CULVERT_LOG_PASSPHRASE",
	"CULVERT_SESSION_SECRET",
}

// installEnvPutFunctions returns env_put together with the env_put_required
// wrapper and the env_file_value_set predicate the wrapper verifies through.
// A harness that drives a SECRET-persisting path (setup_at_rest_encryption,
// persist_host_env_session_secret) must define all three, because those call
// sites go through the wrapper — extracting env_put alone leaves
// `env_put_required: command not found` and tests a script install.sh is not.
func installEnvPutFunctions(t *testing.T) string {
	t.Helper()
	return strings.Join([]string{
		extractShellFunction(t, "scripts/install.sh", "env_put"),
		extractShellFunction(t, "scripts/install.sh", "env_put_required"),
		extractShellFunction(t, "scripts/install.sh", "env_file_value_set"),
	}, "\n")
}

// envPutRequiredHarness returns a bash program that defines install.sh's real
// env_put, env_put_required and env_file_value_set plus the log helpers, with
// `sudo` stubbed to the behaviour named by sudoWorks: a stub that can chmod the
// file into reach (the operator's real sudo on a root-owned .env), or one that
// always fails (sudo genuinely denied).
func envPutRequiredHarness(t *testing.T, sudoWorks bool, body string) string {
	t.Helper()
	sudoStub := `sudo() { return 1; }`
	if sudoWorks {
		sudoStub = `sudo() { if [[ "$1" == chown ]]; then chmod 600 "$3"; else return 1; fi; }`
	}
	return strings.Join([]string{
		"set -euo pipefail",
		`envfile="$1/.env"`,
		`info() { :; }`,
		`warn() { echo "WARN: $*" >&2; }`,
		`error() { echo -e "[x] $*" >&2; exit 1; }`,
		sudoStub,
		installEnvPutFunctions(t),
		body,
	}, "\n")
}

// runEnvPutRequired runs the harness against stack. drop asks for uid 65534,
// which the unwritable-directory scenarios need when the test itself is root:
// root ignores the directory mode they depend on. The writable-directory
// controls must NOT drop — t.TempDir() is 0700 and owned by the test user.
func runEnvPutRequired(t *testing.T, script, stack, tmpdir string, drop bool) (string, error) {
	t.Helper()
	args := []string{"-c", script, "install_script_env_put_required_test", stack}
	var cmd *exec.Cmd
	if drop && os.Getuid() == 0 {
		cmd = exec.CommandContext(t.Context(), "setpriv", append([]string{"--reuid=65534", "--regid=65534", "--clear-groups", "bash"}, args...)...) // #nosec G204 -- fixed test script content
	} else {
		cmd = exec.CommandContext(t.Context(), "bash", args...) // #nosec G204 -- fixed test script content
	}
	cmd.Env = append(os.Environ(), "TMPDIR="+tmpdir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// seedUnwritableStack builds a stack dir nothing can be created in, with no
// .env yet: the state in which env_put's lock-file degrade returns success
// without writing anything at all.
func seedUnwritableStack(t *testing.T) (stack, tmpdir string) {
	t.Helper()
	base := t.TempDir()
	stack = filepath.Join(base, "stack")
	tmpdir = filepath.Join(base, "tmp")
	for _, d := range []string{stack, tmpdir} {
		if err := os.Mkdir(d, 0o755); err != nil { // #nosec G301 -- must stay traversable by the dropped uid
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	t.Cleanup(func() { _ = os.Chmod(stack, 0o755) }) // #nosec G302 -- restore so t.TempDir can remove it
	if os.Getuid() != 0 {
		if err := os.Chmod(stack, 0o555); err != nil { // #nosec G302 -- deliberately unwritable test dir
			t.Fatalf("chmod stack: %v", err)
		}
		return stack, tmpdir
	}
	for _, p := range []string{filepath.Dir(base), base} {
		if err := os.Chmod(p, 0o755); err != nil { // #nosec G302 -- must be traversable by the dropped uid
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
	// stack stays root-owned 0755 — unwritable for uid 65534.
	if err := os.Chown(tmpdir, 65534, 65534); err != nil {
		t.Fatalf("chown tmpdir: %v", err)
	}
	return stack, tmpdir
}

func requireSetprivWhenRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		return
	}
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("setpriv unavailable: cannot drop root to make the stack dir unwritable")
	}
}

// TestInstallScript_EnvPutRequired_UnpersistedSecretFailsClosed is the
// regression test. env_put degrades to exit 0 here (that is its contract);
// env_put_required must still fail, because continuing means `docker compose
// up` starts the proxy with an EMPTY CA passphrase and the Root CA private key
// is written to the data volume unencrypted.
func TestInstallScript_EnvPutRequired_UnpersistedSecretFailsClosed(t *testing.T) {
	requireSetprivWhenRoot(t)
	stack, tmpdir := seedUnwritableStack(t)

	const marker = "REACHED-PAST-THE-SECRET"
	script := envPutRequiredHarness(t, false, `
env_put_required CULVERT_CA_PASSPHRASE "SuperSecretPassphrase123" "$envfile"
echo "`+marker+`"
`)
	out, err := runEnvPutRequired(t, script, stack, tmpdir, true)
	if err == nil {
		t.Fatalf("env_put_required reported SUCCESS for a CA passphrase that never reached .env — the "+
			"stack would start with the SSL-inspection Root CA key unencrypted while the installer "+
			"reports encryption at rest as configured.\noutput:\n%s", out)
	}
	if strings.Contains(out, marker) {
		t.Fatalf("env_put_required let the install continue past an unpersisted secret.\noutput:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(stack, ".env")); statErr == nil {
		t.Fatalf("precondition broken: .env exists, so this is not the no-write degrade path.\noutput:\n%s", out)
	}
	if !strings.Contains(out, "CULVERT_CA_PASSPHRASE") {
		t.Fatalf("the failure must name the variable the operator has to set by hand.\noutput:\n%s", out)
	}
}

// TestInstallScript_EnvPutRequired_PersistsAndReplaces is the positive control:
// on a writable stack dir the wrapper is exactly env_put — the value is
// replaced (not appended twice), unrelated lines survive, and it exits 0.
func TestInstallScript_EnvPutRequired_PersistsAndReplaces(t *testing.T) {
	stack := t.TempDir()
	envFile := filepath.Join(stack, ".env")
	const seeded = "CULVERT_LOG_PASSPHRASE=keep-this-passphrase\nCULVERT_CA_PASSPHRASE=stale-value\n"
	if err := os.WriteFile(envFile, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}
	script := envPutRequiredHarness(t, false, `
env_put_required CULVERT_CA_PASSPHRASE "FreshPassphrase456" "$envfile"
echo "PERSISTED"
`)
	out, err := runEnvPutRequired(t, script, stack, t.TempDir(), false)
	if err != nil {
		t.Fatalf("env_put_required failed on a writable stack dir: %v\n%s", err, out)
	}
	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	if !strings.Contains(string(got), "CULVERT_CA_PASSPHRASE=FreshPassphrase456\n") ||
		strings.Contains(string(got), "stale-value") {
		t.Fatalf("want exactly the fresh CA passphrase; .env now:\n%s", got)
	}
	if !strings.Contains(string(got), "CULVERT_LOG_PASSPHRASE=keep-this-passphrase\n") {
		t.Fatalf("env_put_required lost an unrelated .env line; .env now:\n%s", got)
	}
}

// TestInstallScript_EnvPutRequired_ForeignOwnedStackDirStillPersists keeps the
// fix from reintroducing the abort #1886 removed: when the stack dir is
// root-owned but sudo CAN take .env and .env.lock, env_put stages in TMPDIR and
// rewrites .env in place, so the secret lands and the wrapper must exit 0.
func TestInstallScript_EnvPutRequired_ForeignOwnedStackDirStillPersists(t *testing.T) {
	requireSetprivWhenRoot(t)
	root := os.Getuid() == 0
	envFile, scratch := seedForeignOwnedStack(t, root)
	stack := filepath.Dir(envFile)

	script := envPutRequiredHarness(t, true, `
env_put_required CULVERT_CA_PASSPHRASE "SuperSecretPassphrase123" "$envfile"
env_put CULVERT_INSTALL_CHANNEL lts "$envfile"
echo "PERSISTED"
`)
	out, err := runEnvPutRequired(t, script, stack, scratch, true)
	if err != nil {
		t.Fatalf("env_put_required aborted a re-run whose secret DID land (regressing #1886's fix): %v\n%s", err, out)
	}
	if err := os.Chmod(envFile, 0o600); err != nil {
		t.Fatalf("chmod .env for read-back: %v", err)
	}
	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	for _, want := range []string{
		"CULVERT_CA_PASSPHRASE=SuperSecretPassphrase123\n",
		"CULVERT_LOG_PASSPHRASE=keep-this-passphrase\n",
		"CULVERT_INSTALL_CHANNEL=lts\n",
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("missing %q after the in-place rewrite; .env now:\n%s\noutput:\n%s", want, got, out)
		}
	}
	leftovers, globErr := filepath.Glob(filepath.Join(scratch, "*"))
	if globErr != nil {
		t.Fatalf("glob scratch: %v", globErr)
	}
	if len(leftovers) != 0 {
		t.Fatalf("staging files holding .env secrets were left behind: %v", leftovers)
	}
}

// TestInstallScript_EnvPutRequired_EmptyResolvingValueFailsClosed is the
// boundary case: env_put writes the line, but a value docker compose resolves
// to the empty string configures nothing. env_file_value_set is the predicate
// install.sh already trusts for "is this configured", so an entry it calls
// unset must not pass as persisted.
func TestInstallScript_EnvPutRequired_EmptyResolvingValueFailsClosed(t *testing.T) {
	stack := t.TempDir()
	script := envPutRequiredHarness(t, false, `
env_put_required CULVERT_LOG_PASSPHRASE "" "$envfile"
echo "REACHED-PAST-THE-SECRET"
`)
	out, err := runEnvPutRequired(t, script, stack, t.TempDir(), false)
	if err == nil {
		t.Fatalf("an empty CULVERT_LOG_PASSPHRASE passed as persisted; compose resolves it to the empty "+
			"string and saved logs are written unencrypted.\noutput:\n%s", out)
	}
	if strings.Contains(out, "REACHED-PAST-THE-SECRET") {
		t.Fatalf("the install continued past an empty-resolving secret.\noutput:\n%s", out)
	}
}

// TestInstallScript_EverySecretIsWrittenThroughEnvPutRequired holds the
// invariant from source, so a future round that adds another secret write — or
// reverts one of these call sites to the degrading env_put — fails here rather
// than shipping a silently unencrypted install.
func TestInstallScript_EverySecretIsWrittenThroughEnvPutRequired(t *testing.T) {
	raw, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	// \benv_put[ \t]+ cannot match inside "env_put_required" (the next
	// character there is "_", not a blank), so this finds only bare calls.
	bare := regexp.MustCompile(`\benv_put[ \t]+(CULVERT_[A-Z0-9_]+)`)
	required := regexp.MustCompile(`\benv_put_required[ \t]+(CULVERT_[A-Z0-9_]+)`)

	secret := map[string]bool{}
	for _, v := range secretEnvVars {
		secret[v] = true
	}
	for _, m := range bare.FindAllStringSubmatch(string(raw), -1) {
		if secret[m[1]] {
			t.Errorf("%s is written through the DEGRADING env_put: it returns success without writing "+
				"when it cannot take .env or .env.lock, and the stack then starts with this secret empty "+
				"(the CA key and saved logs unencrypted) while the installer reports it as stored. Use "+
				"env_put_required.", m[1])
		}
	}
	// Negative control: the gate must actually be looking at call sites, not
	// passing because its pattern matches nothing.
	found := map[string]bool{}
	for _, m := range required.FindAllStringSubmatch(string(raw), -1) {
		found[m[1]] = true
	}
	for _, v := range secretEnvVars {
		if !found[v] {
			t.Errorf("no env_put_required call site for %s — either the secret is no longer persisted "+
				"here (drop it from secretEnvVars) or this gate is no longer reading the real call sites", v)
		}
	}
}
