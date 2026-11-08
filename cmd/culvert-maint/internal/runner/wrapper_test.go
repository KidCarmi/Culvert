package runner

// wrapper_test.go runs the REAL privileged wrapper
// (packaging/culvert-maint/compose-cli) that the sudoers file grants for
// every variable-argument compose `cli` operation. It is the argument
// boundary that replaced the sudoers wildcards sudo-rs rejects, so these
// tests pin both directions:
//
//   - every argv the runner emits in privilege_mode=sudoers is ACCEPTED,
//     and the wrapper execs byte-for-byte the docker argv the runner would
//     run without sudo (the runner and the wrapper cannot drift apart);
//   - every other shape is REFUSED (exit 64) before docker runs: paths
//     outside /backup, traversal, extra or reordered flags, non-numeric or
//     out-of-range counts and durations, shell metacharacters, newlines.
//
// The wrapper under test is the shipped template with exactly two lines
// rewritten by the harness: the compose-path placeholder (as install.sh
// renders it) and DOCKER_BIN, pointed at the argv-printing fake from
// runner_test.go. The wrapper has no test mode or environment override; the
// installed copy cannot be redirected at run time.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	wrapperTemplateRel     = "packaging/culvert-maint/compose-cli"
	wrapperComposePathLine = "COMPOSE_PATH='{compose_path}'"
	wrapperDockerBinLine   = "DOCKER_BIN=/usr/bin/docker"
	wrapperTestComposePath = "/srv/culvert/docker-compose.yml"
	wrapperRefusedExitCode = 64
)

// findRepoFile walks up from the test's working directory to the first
// ancestor that contains rel.
func findRepoFile(t *testing.T, rel string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 12; i++ {
		candidate := filepath.Join(dir, filepath.FromSlash(rel))
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate %s from %s", rel, wd)
	return ""
}

// readWrapperTemplate returns the shipped wrapper template's source.
func readWrapperTemplate(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(findRepoFile(t, wrapperTemplateRel))
	if err != nil {
		t.Fatalf("read wrapper template: %v", err)
	}
	return string(data)
}

// replaceExactlyOneLine swaps the single line equal to old for repl, failing
// the test if old is not present exactly once.
func replaceExactlyOneLine(t *testing.T, src, old, repl string) string {
	t.Helper()
	lines := strings.Split(src, "\n")
	hits := 0
	for i, ln := range lines {
		if ln == old {
			lines[i] = repl
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("wrapper template must contain the line %q exactly once, found %d", old, hits)
	}
	return strings.Join(lines, "\n")
}

// writeWrapper renders the template for the harness and writes it to a temp
// file. renderComposePath=false leaves the compose path unrendered.
func writeWrapper(t *testing.T, dockerBin string, renderComposePath bool) string {
	t.Helper()
	src := readWrapperTemplate(t)
	if renderComposePath {
		src = replaceExactlyOneLine(t, src, wrapperComposePathLine, "COMPOSE_PATH='"+wrapperTestComposePath+"'")
	}
	src = replaceExactlyOneLine(t, src, wrapperDockerBinLine, "DOCKER_BIN="+dockerBin)
	path := filepath.Join(t.TempDir(), "compose-cli")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}
	return path
}

// wrapperHarness executes the rendered wrapper through the production
// runner (so the child gets the runner's scrubbed env, cwd and timeout).
type wrapperHarness struct {
	wrapper string
	fake    string
	exec    *Runner
	// shells are the distinct POSIX shells available here. /bin/sh is dash
	// on Debian/Ubuntu but bash on RHEL/Amazon Linux, so every invocation
	// runs under each one and the outcomes must agree.
	shells []string
}

// wrapperShells returns the distinct shells (by resolved path) to run the
// wrapper under; /bin/sh first.
func wrapperShells() []string {
	var out []string
	seen := map[string]bool{}
	for _, sh := range []string{"/bin/sh", "/bin/dash", "/bin/bash"} {
		resolved, err := filepath.EvalSymlinks(sh)
		if err != nil || seen[resolved] {
			continue
		}
		seen[resolved] = true
		out = append(out, sh)
	}
	return out
}

func newWrapperHarness(t *testing.T) *wrapperHarness {
	t.Helper()
	shells := wrapperShells()
	if len(shells) == 0 || shells[0] != "/bin/sh" {
		t.Skip("/bin/sh not available")
	}
	fake := fakeBin(t)
	r, err := New(Options{
		ComposeProjectDir: t.TempDir(),
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      30 * time.Second,
		EnvAllow:          []string{EnvCulvertBackupPassphrase},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &wrapperHarness{wrapper: writeWrapper(t, fake, true), fake: fake, exec: r, shells: shells}
}

// wrapperRun is one wrapper invocation's observable outcome.
type wrapperRun struct {
	exitCode int
	ran      bool     // the fake docker was exec'd
	argv     []string // fake docker argv, argv[0] included
	env      []string
	stderr   string
}

// run executes the wrapper under every harness shell, requires the outcomes
// to agree, and returns the /bin/sh outcome.
func (h *wrapperHarness) run(t *testing.T, wrapper string, args []string, overlay map[string]string) wrapperRun {
	t.Helper()
	first := h.runShell(t, h.shells[0], wrapper, args, overlay)
	for _, sh := range h.shells[1:] {
		other := h.runShell(t, sh, wrapper, args, overlay)
		if other.exitCode != first.exitCode || other.ran != first.ran || !reflect.DeepEqual(other.argv, first.argv) ||
			other.hasEnvName(EnvCulvertBackupPassphrase) != first.hasEnvName(EnvCulvertBackupPassphrase) {
			t.Errorf("wrapper behaves differently under %s than under %s for %q:\n %s: exit=%d argv=%q\n %s: exit=%d argv=%q",
				sh, h.shells[0], args, h.shells[0], first.exitCode, first.argv, sh, other.exitCode, other.argv)
		}
	}
	return first
}

func (h *wrapperHarness) runShell(t *testing.T, shell, wrapper string, args []string, overlay map[string]string) wrapperRun {
	t.Helper()
	argv := append([]string{shell, wrapper}, args...)
	res, err := h.exec.runWithEnv(context.Background(), argv, overlay)
	if res == nil {
		t.Fatalf("wrapper did not run: %v", err)
	}
	out := wrapperRun{exitCode: res.ExitCode, stderr: string(res.Stderr)}
	for _, ln := range strings.Split(string(res.Stdout), "\n") {
		switch {
		case strings.HasPrefix(ln, "ARG:"):
			out.argv = append(out.argv, strings.TrimPrefix(ln, "ARG:"))
		case strings.HasPrefix(ln, "ENV:"):
			out.env = append(out.env, strings.TrimPrefix(ln, "ENV:"))
		}
	}
	out.ran = len(out.argv) > 0
	return out
}

func (w wrapperRun) hasEnvName(name string) bool {
	for _, e := range w.env {
		if strings.HasPrefix(e, name+"=") {
			return true
		}
	}
	return false
}

// runnerCall is one typed runner method invocation.
type runnerCall struct {
	name       string
	passphrase bool // the docker command forwards -e CULVERT_BACKUP_PASSPHRASE
	call       func(r *Runner) (*Result, error)
}

// everyWrapperRoutedCall enumerates every argv shape the runner can send to
// the wrapper: both backups, all 3 modes × 4 flag sets × {dryrun, commit}
// restores (the 24 combinations the old sudoers file enumerated), and the
// cleanup dryrun/commit across representative durations and counts.
func everyWrapperRoutedCall() []runnerCall {
	ctx := context.Background()
	calls := []runnerCall{
		{"backup-encrypted", true, func(r *Runner) (*Result, error) {
			return r.ComposeBackupEncrypted(ctx, "culvert-2026-11-08.tar.gz.enc", "pw")
		}},
		{"backup", false, func(r *Runner) (*Result, error) {
			return r.ComposeBackupUnencrypted(ctx, "-dash_LEADING.v1.tgz")
		}},
	}
	for _, mode := range []RestoreMode{RestoreModeFull, RestoreModeTrustRootOnly, RestoreModeStateOnly} {
		// bit 0: --accept-dp-reenrollment, bit 1: --allow-counter-rollback,
		// bit 2: commit (--confirm).
		for combo := 0; combo < 8; combo++ {
			calls = append(calls, restoreCall(mode, combo&1 != 0, combo&2 != 0, combo&4 != 0))
		}
	}
	for _, dur := range []string{"1h", "168h", "720h", "8760h", "60m", "3600s", "1.5h", "3600000ms", "3600000000us", "3600000000µs", "3600000000000ns"} {
		for _, keep := range []int{0, 1, 9, 10, 99, 100} {
			calls = append(calls,
				runnerCall{"cleanup/" + dur, false, func(r *Runner) (*Result, error) {
					return r.ComposeCleanupDryRun(ctx, dur, keep)
				}},
				runnerCall{"cleanup-commit/" + dur, false, func(r *Runner) (*Result, error) {
					return r.ComposeCleanupCommit(ctx, dur, keep)
				}},
			)
		}
	}
	return calls
}

// restoreCall is one restore dryrun/commit invocation with the given flags.
func restoreCall(mode RestoreMode, acceptDP, allowCounter, commit bool) runnerCall {
	ctx := context.Background()
	name := "restore/" + string(mode)
	if acceptDP {
		name += "/accept-dp"
	}
	if allowCounter {
		name += "/allow-counter"
	}
	if commit {
		name += "/commit"
	}
	return runnerCall{name, true, func(r *Runner) (*Result, error) {
		if commit {
			return r.ComposeRestoreCommit(ctx, "snap.tar.gz", mode, acceptDP, allowCounter, "pw")
		}
		return r.ComposeRestoreDryRun(ctx, "snap.tar.gz", mode, acceptDP, allowCounter, "")
	}}
}

// captureArgv returns the argv a runner method would exec.
func captureArgv(t *testing.T, useSudo bool, c runnerCall) []string {
	t.Helper()
	r, err := New(Options{
		ComposeProjectDir: filepath.Dir(wrapperTestComposePath),
		ComposeFile:       filepath.Base(wrapperTestComposePath),
		StageTimeout:      5 * time.Second,
		EnvAllow:          []string{EnvCulvertBackupPassphrase},
		DockerBinary:      "/usr/bin/docker",
		UseSudo:           useSudo,
		SudoBinary:        "sudo",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var argv []string
	r.execStartFn = func(cmd *exec.Cmd) error {
		argv = append([]string(nil), cmd.Args...)
		return nil
	}
	r.execWaitFn = func(_ *exec.Cmd) error { return nil }
	if _, err := c.call(r); err != nil {
		t.Fatalf("%s: runner call: %v", c.name, err)
	}
	return argv
}

// TestWrapper_AcceptsEveryRunnerArgvAndExecsTheDockerForm is the
// runner↔wrapper parity oracle: for every wrapper-routed call, the argv the
// runner hands sudo is accepted by the real wrapper, and the wrapper execs
// exactly the docker argv the same call produces without sudo.
func TestWrapper_AcceptsEveryRunnerArgvAndExecsTheDockerForm(t *testing.T) {
	h := newWrapperHarness(t)
	calls := everyWrapperRoutedCall()
	if got := len(calls); got != 2+24+11*6*2 {
		t.Fatalf("expected 158 wrapper-routed calls, enumerated %d", got)
	}
	for _, c := range calls {
		sudoArgv := captureArgv(t, true, c)
		dockerArgv := captureArgv(t, false, c)
		if len(sudoArgv) < 4 || sudoArgv[0] != "sudo" || sudoArgv[1] != "-n" || sudoArgv[2] != ComposeCLIWrapperPath {
			t.Fatalf("%s: sudo argv does not invoke the wrapper: %q", c.name, sudoArgv)
		}
		got := h.run(t, h.wrapper, sudoArgv[3:], nil)
		if got.exitCode != 0 || !got.ran {
			t.Errorf("%s: wrapper refused a runner-emitted argv %q (exit %d): %s", c.name, sudoArgv[3:], got.exitCode, got.stderr)
			continue
		}
		want := append([]string{h.fake}, dockerArgv[1:]...)
		if !reflect.DeepEqual(got.argv, want) {
			t.Errorf("%s: wrapper exec'd a different docker argv\n got: %q\nwant: %q", c.name, got.argv, want)
		}
		if argvHas(got.argv, EnvCulvertBackupPassphrase) != c.passphrase {
			t.Errorf("%s: `-e %s` forwarding = %v, want %v", c.name, EnvCulvertBackupPassphrase, !c.passphrase, c.passphrase)
		}
	}
}

// TestWrapper_PassphraseForwardedOnlyWhereTheOldAliasKeptIt pins the env
// contract. sudoers now keeps CULVERT_BACKUP_PASSPHRASE for the wrapper as a
// whole, so the wrapper itself must drop it for the subcommands whose docker
// command never carried `-e CULVERT_BACKUP_PASSPHRASE` (unencrypted backup,
// cleanup) and keep it for those that did (encrypted backup, restore).
func TestWrapper_PassphraseForwardedOnlyWhereTheOldAliasKeptIt(t *testing.T) {
	h := newWrapperHarness(t)
	overlay := map[string]string{EnvCulvertBackupPassphrase: "s3cret-value"}
	cases := []struct {
		args []string
		keep bool
	}{
		{[]string{"backup-encrypted", "/backup/a.tar.gz"}, true},
		{[]string{"restore", "/backup/a.tar.gz", "--mode", "full"}, true},
		{[]string{"restore", "/backup/a.tar.gz", "--mode", "state-only", "--confirm"}, true},
		{[]string{"backup", "/backup/a.tar.gz"}, false},
		{[]string{"cleanup", "--older-than", "168h", "--keep-last", "2"}, false},
		{[]string{"cleanup", "--older-than", "168h", "--keep-last", "2", "--confirm"}, false},
	}
	for _, c := range cases {
		got := h.run(t, h.wrapper, c.args, overlay)
		if got.exitCode != 0 || !got.ran {
			t.Fatalf("%q: wrapper refused (exit %d): %s", c.args, got.exitCode, got.stderr)
		}
		if has := got.hasEnvName(EnvCulvertBackupPassphrase); has != c.keep {
			t.Errorf("%q: %s present=%v, want %v", c.args, EnvCulvertBackupPassphrase, has, c.keep)
		}
		if c.keep != argvHas(got.argv, EnvCulvertBackupPassphrase) {
			t.Errorf("%q: `-e %s` in docker argv must match env forwarding (%v): %q", c.args, EnvCulvertBackupPassphrase, c.keep, got.argv)
		}
	}
}

func argvHas(argv []string, tok string) bool {
	for _, a := range argv {
		if a == tok {
			return true
		}
	}
	return false
}

// TestWrapper_RefusesEverythingElse is the negative wall: each shape exits 64
// and docker never runs.
func TestWrapper_RefusesEverythingElse(t *testing.T) {
	h := newWrapperHarness(t)
	long := "/backup/" + strings.Repeat("a", 256)
	cases := map[string][]string{
		// subcommand
		"no subcommand":       {},
		"empty subcommand":    {""},
		"unknown subcommand":  {"shell"},
		"help flag":           {"--help"},
		"docker passthrough":  {"compose", "-f", "/etc/evil.yml", "up"},
		"list is not routed":  {"list-backups"},
		"case-folded command": {"BACKUP", "/backup/a"},

		// backup path: outside /backup
		"absolute elsewhere":   {"backup", "/etc/shadow"},
		"prefix lookalike":     {"backup", "/backupx/a"},
		"relative path":        {"backup", "backup/a"},
		"bare /backup":         {"backup", "/backup"},
		"empty name":           {"backup", "/backup/"},
		"double slash":         {"backup", "//backup/a"},
		"subdirectory":         {"backup", "/backup/sub/a"},
		"name too long":        {"backup", long},
		"traversal up":         {"backup", "/backup/../etc/shadow"},
		"traversal dotdot":     {"backup-encrypted", "/backup/.."},
		"dot":                  {"backup", "/backup/."},
		"hidden file":          {"backup", "/backup/.ssh"},
		"embedded traversal":   {"restore", "/backup/a/../../etc/passwd", "--mode", "full"},
		"newline":              {"backup", "/backup/a\nb"},
		"carriage return":      {"backup", "/backup/a\rb"},
		"space":                {"backup", "/backup/a b"},
		"tab":                  {"backup", "/backup/a\tb"},
		"semicolon":            {"backup", "/backup/a;id"},
		"command substitution": {"backup", "/backup/$(id)"},
		"backtick":             {"backup", "/backup/a`id`"},
		"glob star":            {"backup", "/backup/*"},
		"glob question":        {"backup", "/backup/a?"},
		"pipe":                 {"backup", "/backup/a|b"},
		"ampersand":            {"backup", "/backup/a&b"},
		"redirect":             {"backup", "/backup/a>b"},
		"single quote":         {"backup", "/backup/a'b"},
		"double quote":         {"backup", "/backup/a\"b"},
		"backslash":            {"backup", "/backup/a\\b"},
		"non-ascii":            {"backup", "/backup/café"},
		"bell control char":    {"backup", "/backup/a\x07b"},

		// backup arity
		"backup no path":          {"backup"},
		"backup extra arg":        {"backup", "/backup/a", "--confirm"},
		"encrypted extra flag":    {"backup-encrypted", "/backup/a", "-e", "FOO"},
		"encrypted path as flag":  {"backup-encrypted", "--backup", "/backup/a"},
		"backup option injection": {"backup", "--rm"},

		// restore
		"restore missing mode":         {"restore", "/backup/a"},
		"restore mode flag only":       {"restore", "/backup/a", "--mode"},
		"restore equals form":          {"restore", "/backup/a", "--mode=full"},
		"restore bad mode":             {"restore", "/backup/a", "--mode", "everything"},
		"restore mode case":            {"restore", "/backup/a", "--mode", "FULL"},
		"restore mode injection":       {"restore", "/backup/a", "--mode", "full;id"},
		"restore wrong keyword":        {"restore", "/backup/a", "--mod", "full"},
		"restore path after mode":      {"restore", "--mode", "full", "/backup/a"},
		"restore flags reordered":      {"restore", "/backup/a", "--mode", "full", "--allow-counter-rollback", "--accept-dp-reenrollment"},
		"restore confirm not last":     {"restore", "/backup/a", "--mode", "full", "--confirm", "--accept-dp-reenrollment"},
		"restore duplicate flag":       {"restore", "/backup/a", "--mode", "full", "--accept-dp-reenrollment", "--accept-dp-reenrollment"},
		"restore duplicate confirm":    {"restore", "/backup/a", "--mode", "full", "--confirm", "--confirm"},
		"restore unknown flag":         {"restore", "/backup/a", "--mode", "full", "--force"},
		"restore env injection":        {"restore", "/backup/a", "--mode", "full", "-e", "FOO"},
		"restore second mode":          {"restore", "/backup/a", "--mode", "full", "--mode", "state-only"},
		"restore trailing positional":  {"restore", "/backup/a", "--mode", "full", "/backup/b"},
		"restore all flags plus extra": {"restore", "/backup/a", "--mode", "full", "--accept-dp-reenrollment", "--allow-counter-rollback", "--confirm", "--confirm"},

		// cleanup: structure
		"cleanup no args":         {"cleanup"},
		"cleanup missing count":   {"cleanup", "--older-than", "168h"},
		"cleanup reordered":       {"cleanup", "--keep-last", "1", "--older-than", "168h"},
		"cleanup wrong flag":      {"cleanup", "--newer-than", "168h", "--keep-last", "1"},
		"cleanup equals form":     {"cleanup", "--older-than=168h", "--keep-last", "1", "x"},
		"cleanup extra arg":       {"cleanup", "--older-than", "168h", "--keep-last", "1", "--confirm", "x"},
		"cleanup bad 5th arg":     {"cleanup", "--older-than", "168h", "--keep-last", "1", "--force"},
		"cleanup confirm first":   {"cleanup", "--confirm", "--older-than", "168h", "--keep-last", "1"},
		"cleanup upstream spell":  {"cleanup-restore-leftovers", "--older-than", "168h", "--keep-last", "1"},
		"cleanup keep-last empty": {"cleanup", "--older-than", "168h", "--keep-last", ""},
	}
	// cleanup: --keep-last values that are not 0..100 canonical decimal
	for _, n := range []string{"-1", "101", "1000", "007", "01", "1.0", "1e2", "+1", "abc", " 1", "1 ", "1\n", "9;id"} {
		cases["keep-last "+n] = []string{"cleanup", "--older-than", "168h", "--keep-last", n}
	}
	// cleanup: --older-than values outside the agent's shape or range
	for _, d := range wrapperRejectedDurations {
		cases["older-than "+d] = []string{"cleanup", "--older-than", d, "--keep-last", "1"}
	}

	for name, args := range cases {
		got := h.run(t, h.wrapper, args, map[string]string{EnvCulvertBackupPassphrase: "pw"})
		if got.ran {
			t.Errorf("%s: wrapper exec'd docker for refused argv %q: %q", name, args, got.argv)
		}
		if got.exitCode != wrapperRefusedExitCode {
			t.Errorf("%s: exit code %d, want %d (argv %q, stderr %q)", name, got.exitCode, wrapperRefusedExitCode, args, got.stderr)
		}
		for _, a := range args {
			if a != "" && len(a) > 3 && strings.Contains(got.stderr, a) && strings.ContainsAny(a, "/;$`\n") {
				t.Errorf("%s: refusal echoed an untrusted argument %q into stderr: %q", name, a, got.stderr)
			}
		}
	}
}

// wrapperRejectedDurations are --older-than values the wrapper must refuse:
// wrong shape (whitespace, metacharacters, units Go has but the agent's regex
// does not, signs, exponents, hex, dangling dots) or out of the 1h..8760h range.
var wrapperRejectedDurations = []string{
	"", "h", "abc", "1d", "1w", "1y", "-1h", "+1h", "1e3h", "0x10h", "1.h", ".5h", "1..5h", "1.5.0h",
	" 168h", "168h ", "168 h", "168h\n", "168h;id", "168h$(id)", "1h30m", "168H", "168hh",
	"1μs", // Greek mu: Go's ParseDuration accepts it, the agent's olderThanRE does not
	"0h", "59m", "3599s", "3599999ms", "3599999999us", "3599999999µs", "3599999999999ns", "0.5h", "0.99h",
	"8761h", "8760.5h", "8760.0000001h", "525601m", "31536001s", "31536000001ms", "31536000000001us",
	"31536000000000001ns", "99999999999999999999h", "000000000000000000000000009000h",
}

// TestWrapper_DurationVerdictIsNeverLooserThanTheAgent is a differential
// oracle against the agent's own validator: anything the wrapper accepts,
// validateOlderThan accepts too (so the wrapper never widens what reaches
// docker), and every value the agent accepts in the curated list is accepted
// by the wrapper (so no ordinary operator request starts failing at sudo).
func TestWrapper_DurationVerdictIsNeverLooserThanTheAgent(t *testing.T) {
	h := newWrapperHarness(t)
	accepted := []string{
		"1h", "01h", "0001h", "1.0h", "1.5h", "24h", "168h", "720h", "8760h", "8760.0h", "8760.000h",
		"60m", "61m", "525600m", "3600s", "31536000s", "3600000ms", "31536000000ms",
		"3600000000us", "3600000000µs", "31536000000000us", "3600000000000ns", "31536000000000000ns",
		"8759.999999h",
	}
	verdict := func(d string) bool {
		got := h.run(t, h.wrapper, []string{"cleanup", "--older-than", d, "--keep-last", "1"}, nil)
		return got.exitCode == 0 && got.ran
	}
	for _, d := range accepted {
		if err := validateOlderThan(d); err != nil {
			t.Fatalf("curated accept %q is rejected by the agent itself: %v", d, err)
		}
		if !verdict(d) {
			t.Errorf("wrapper refused %q, which the agent accepts", d)
		}
	}
	for _, d := range wrapperRejectedDurations {
		if verdict(d) {
			t.Errorf("wrapper accepted %q", d)
			if err := validateOlderThan(d); err != nil {
				t.Errorf("  and it is LOOSER than the agent, which rejects it: %v", err)
			}
		}
	}
}

// TestWrapper_UnrenderedTemplateRefuses proves the shipped template cannot
// reach docker before install.sh renders the compose path.
func TestWrapper_UnrenderedTemplateRefuses(t *testing.T) {
	h := newWrapperHarness(t)
	raw := writeWrapper(t, h.fake, false)
	got := h.run(t, raw, []string{"backup", "/backup/a.tar.gz"}, nil)
	if got.ran || got.exitCode != wrapperRefusedExitCode {
		t.Errorf("unrendered wrapper must refuse (exit %d) without running docker; got exit %d ran=%v", wrapperRefusedExitCode, got.exitCode, got.ran)
	}
}

// TestWrapper_SourceHardening pins the static properties the privilege
// boundary relies on, so a later edit cannot quietly loosen them.
func TestWrapper_SourceHardening(t *testing.T) {
	src := readWrapperTemplate(t)
	if !strings.HasPrefix(src, "#!/bin/sh\n") {
		t.Error("wrapper must start with #!/bin/sh")
	}
	for _, want := range []string{
		"\nset -eu\n",
		"\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n",
		"\nexport PATH\n",
		"\nLC_ALL=C\n",
		"\n" + wrapperComposePathLine + "\n",
		"\n" + wrapperDockerBinLine + "\n",
		"\nreadonly COMPOSE_PATH DOCKER_BIN\n",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("wrapper source missing %q", strings.TrimSpace(want))
		}
	}
	code := stripShellComments(src)
	for _, banned := range []string{"eval", "`", "$(", "$*", "source ", ". /", "bash", "sudo"} {
		if strings.Contains(code, banned) {
			t.Errorf("wrapper code must not contain %q", banned)
		}
	}
	if n := strings.Count(src, "{compose_path}"); n != 1 {
		t.Errorf("the compose-path placeholder must appear exactly once (install.sh renders every occurrence), found %d", n)
	}
	for _, ln := range strings.Split(code, "\n") {
		if strings.Contains(ln, "exec ") && !strings.Contains(ln, `exec "$DOCKER_BIN" compose -f "$COMPOSE_PATH" --profile cli run --rm`) {
			t.Errorf("every exec must be the fixed docker compose cli prefix, got: %s", strings.TrimSpace(ln))
		}
	}
}

// stripShellComments drops full-line comments (the wrapper has no trailing
// comments on code lines).
func stripShellComments(src string) string {
	var b strings.Builder
	for _, ln := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return b.String()
}
