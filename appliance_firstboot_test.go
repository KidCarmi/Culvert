package main

// Qualification of the appliance first-boot script and its sudo-policy
// helper (owner review on PR #1528, findings 4 and 5). The script is
// sourced in LIBRARY mode (CULVERT_FIRSTBOOT_LIBRARY=1) with every system
// path redirected (CULVERT_FB_*) and every account/system tool replaced by a
// PATH stub that records its invocation — so the DECISION logic runs for
// real while nothing touches this host. The one live test (sudoers
// last-match precedence) is opt-in and needs root; it is what turns the
// "95- sorts after 90-" claim into evidence.
//
// Why these shapes: (a) a key-only import must leave the operator a usable
// sudo credential — the SSH key is the credential, so a NOPASSWD drop-in is
// the policy; (b) an interrupted password mint must re-mint, because a
// password that landed in /etc/shadow but was never shown is not a credential
// anyone holds; (c) the agent step may only ever CLAIM an install it
// verified, and the repair verb must succeed after a transient trust-service
// failure and still refuse to claim success after a persistent one.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Anchored to the package source dir (static_read_wall_test.go): a
// concurrent os.Chdir in another test must not flake these reads.
var (
	fbScript         = filepath.Join(pkgSourceDir(), "appliance", "provision", "culvert-firstboot.sh")
	sudoPolicyScript = filepath.Join(pkgSourceDir(), "appliance", "provision", "culvert-sudo-policy")
	statusScript     = filepath.Join(pkgSourceDir(), "appliance", "provision", "culvert-status")
	buildOVAScript   = filepath.Join(pkgSourceDir(), "appliance", "build", "build-ova.sh")
)

// fbHarness is one isolated first-boot world: state dir, stack dir, sudoers
// dir, home dir, a stub bin dir on PATH and a record of every stubbed call.
type fbHarness struct {
	t                                             *testing.T
	root, state, stack, sudoers, home, bin, stubs string
	calls                                         string
}

func newFBHarness(t *testing.T) *fbHarness {
	t.Helper()
	root := t.TempDir()
	h := &fbHarness{t: t, root: root,
		state:   filepath.Join(root, "appliance"),
		stack:   filepath.Join(root, "srv"),
		sudoers: filepath.Join(root, "sudoers.d"),
		home:    filepath.Join(root, "home"),
		bin:     filepath.Join(root, "applbin"),
		stubs:   filepath.Join(root, "stubs"),
		calls:   filepath.Join(root, "calls.log"),
	}
	for _, d := range []string{filepath.Join(h.state, "state"), h.stack, h.sudoers, filepath.Join(h.home, ".ssh"), h.bin, h.stubs} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// main() sources the build manifest (image repo/tag) before any verb.
	if err := os.WriteFile(filepath.Join(h.state, "manifest.env"), []byte("APP_IMAGE_REPO=ghcr.io/kidcarmi/culvert\nAPP_IMAGE_TAG=v0.0.0-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// culvert-issue-update is invoked best-effort by the finish/repair paths.
	h.writeExec(filepath.Join(h.bin, "culvert-issue-update"), "#!/usr/bin/env bash\nexit 0\n")
	h.writeExec(filepath.Join(h.bin, "culvert-status"), "#!/usr/bin/env bash\necho 'stub status'\n")
	// Account/system tools: record and succeed. getent answers from a file
	// the test controls (the simulated shadow field).
	h.stub("chpasswd", `cat > "$FB_HARNESS/chpasswd.in"`)
	h.stub("passwd", `:`)
	h.stub("chage", `:`)
	h.stub("visudo", `f="${!#}"; [[ -s "$f" ]]`)
	h.stub("systemctl", `if [[ "$*" == *is-enabled*culvert-maint* ]]; then [[ -f "$FB_HARNESS/agent.enabled" ]]; else exit 0; fi`)
	h.stub("getent", `[[ "$1" == shadow ]] && { printf '%s:%s:19000:0:99999:7:::\n' "$2" "$(cat "$FB_HARNESS/shadow" 2>/dev/null || echo '!')"; exit 0; }; exit 2`)
	// install(1) with -o root -g root fails for an unprivileged runner; the
	// stub drops the ownership flags and keeps the mode + copy semantics.
	h.stub("install", `args=(); while (($#)); do case "$1" in -o|-g) shift 2;; *) args+=("$1"); shift;; esac; done; exec /usr/bin/install "${args[@]}"`)
	return h
}

func (h *fbHarness) writeExec(path, body string) {
	h.t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		h.t.Fatal(err)
	}
}

// stub installs a PATH shim that appends its argv to calls.log, then runs body.
func (h *fbHarness) stub(name, body string) {
	h.writeExec(filepath.Join(h.stubs, name), "#!/usr/bin/env bash\nprintf '%s %s\\n' \""+name+"\" \"$*\" >> \"$FB_HARNESS/calls.log\"\n"+body+"\n")
}

func (h *fbHarness) setShadow(field string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.root, "shadow"), []byte(field), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fbHarness) setKey(present bool) {
	h.t.Helper()
	p := filepath.Join(h.home, ".ssh", "authorized_keys")
	if !present {
		_ = os.Remove(p)
		return
	}
	if err := os.WriteFile(p, []byte("ssh-ed25519 AAAATEST operator@example\n"), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fbHarness) env() []string {
	return append(os.Environ(),
		"FB_HARNESS="+h.root,
		"PATH="+h.stubs+":"+os.Getenv("PATH"),
		"CULVERT_FIRSTBOOT_LIBRARY=1",
		"CULVERT_FB_STATE_DIR="+h.state,
		"CULVERT_FB_STACK_DIR="+h.stack,
		"CULVERT_FB_SUDOERS_DIR="+h.sudoers,
		"CULVERT_FB_CONSOLE_USER=culvert",
		"CULVERT_FB_CONSOLE_HOME="+h.home,
		"CULVERT_FB_BIN_DIR="+h.bin,
		"CULVERT_FB_INSTALL_SH="+filepath.Join(h.root, "install.sh"),
		"CULVERT_FB_LOG="+filepath.Join(h.root, "firstboot.log"),
		"CULVERT_FB_MAINT_UNIT="+filepath.Join(h.root, "culvert-maint.service"),
		"APP_IMAGE_REPO=ghcr.io/kidcarmi/culvert", "APP_IMAGE_TAG=v0.0.0-test",
	)
}

// run sources the script in library mode and evaluates cmd. It returns the
// combined output and the exit status (0 on success).
func (h *fbHarness) run(cmd string) (output string, code int) {
	h.t.Helper()
	abs, _ := filepath.Abs(fbScript)
	// #nosec G204 -- program is the literal "bash"; abs is the checked-in
	// script's path and cmd a test-constant snippet, never external input.
	c := exec.CommandContext(h.t.Context(), "bash", "-c", ". "+abs+"; "+cmd)
	c.Env = h.env()
	out, err := c.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if ok := errorsAs(err, &ee); ok {
			code = ee.ExitCode()
		} else {
			h.t.Fatalf("bash: %v", err)
		}
	}
	return string(out), code
}

func errorsAs(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

func (h *fbHarness) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(h.root, rel))
	return err == nil
}

func (h *fbHarness) calledCount(tool string) int {
	b, _ := os.ReadFile(h.calls)
	return strings.Count(string(b), tool+" ")
}

func (h *fbHarness) chpasswdInput() string {
	b, _ := os.ReadFile(filepath.Join(h.root, "chpasswd.in"))
	return string(b)
}

// installSHStub writes the install.sh stand-in. It persists the setup token
// exactly as the real installer's env_put does (never overwriting), lays down
// the two files step_install checks for, and — when the agent flag file
// exists — "installs" the agent (unit + enabled marker + binary on PATH).
func (h *fbHarness) installSHStub(persistToken bool) {
	h.t.Helper()
	body := `#!/usr/bin/env bash
set -euo pipefail
printf 'install.sh %s\n' "DEFAULT_ACTION=$CULVERT_INSTALL_DEFAULT_ACTION ASSUME_DOCKER=$CULVERT_INSTALL_ASSUME_DOCKER SEED=$CULVERT_PROXY_SEED_REF TOKEN=$CULVERT_INSTALL_SETUP_TOKEN" >> "$FB_HARNESS/calls.log"
mkdir -p "$CULVERT_DIR"
touch "$CULVERT_DIR/docker-compose.yml"
touch "$CULVERT_DIR/.env"
`
	if persistToken {
		body += `grep -q '^CULVERT_SETUP_TOKEN=' "$CULVERT_DIR/.env" || printf 'CULVERT_SETUP_TOKEN=%s\n' "$CULVERT_INSTALL_SETUP_TOKEN" >> "$CULVERT_DIR/.env"
`
	}
	body += `if [[ -f "$FB_HARNESS/agent.available" ]]; then
  printf '[Unit]\nDescription=stub\n' > "$FB_HARNESS/culvert-maint.service"
  touch "$FB_HARNESS/agent.enabled"
  printf '#!/usr/bin/env bash\necho culvert-maint v0-test\n' > "$FB_HARNESS/stubs/culvert-maint"; chmod 0755 "$FB_HARNESS/stubs/culvert-maint"
else
  echo "install.sh: maintenance agent NOT installed (cosign: Sigstore unreachable — stub)" >&2
fi
`
	h.writeExec(filepath.Join(h.root, "install.sh"), body)
}

// ── console_policy: the pure decision ───────────────────────────────────────

func TestFirstBoot_ConsolePolicyDecision(t *testing.T) {
	h := newFBHarness(t)
	cases := []struct{ shadow, keys, minted, want string }{
		{"!", "0", "0", "mint"},             // locked, no key  → mint a console password
		{"*", "0", "0", "mint"},             // absent, no key  → mint
		{"", "0", "0", "mint"},              // empty field     → mint
		{"!", "1", "0", "keyonly"},          // locked, key     → passwordless sudo
		{"$6$x$hash", "0", "0", "password"}, // password set    → password-gated sudo
		{"$6$x$hash", "1", "0", "password"}, // both supplied   → password wins
		{"$6$x$hash", "0", "1", "remint"},   // our mint landed but was never shown
		{"!", "1", "1", "keyonly"},          // marker but still locked (chpasswd never ran) → key wins
	}
	for _, c := range cases {
		out, code := h.run("console_policy '" + c.shadow + "' " + c.keys + " " + c.minted)
		if code != 0 || strings.TrimSpace(out) != c.want {
			t.Errorf("console_policy(%q,%s,%s) = %q (exit %d), want %q", c.shadow, c.keys, c.minted, strings.TrimSpace(out), code, c.want)
		}
	}
}

// ── step_console: the four provisioning shapes + the interrupted mint ───────

func TestFirstBoot_StepConsole_KeyOnlyInstallsPasswordlessSudo(t *testing.T) {
	h := newFBHarness(t)
	h.setShadow("!")
	h.setKey(true)
	out, code := h.run("step_console")
	if code != 0 {
		t.Fatalf("step_console failed (%d):\n%s", code, out)
	}
	drop, err := os.ReadFile(filepath.Join(h.sudoers, "95-culvert-keyonly"))
	if err != nil {
		t.Fatalf("key-only drop-in not written: %v\n%s", err, out)
	}
	if string(drop) != "culvert ALL=(ALL:ALL) NOPASSWD: ALL\n" {
		t.Fatalf("drop-in content %q", drop)
	}
	st, _ := os.Stat(filepath.Join(h.sudoers, "95-culvert-keyonly"))
	if st.Mode().Perm() != 0o440 {
		t.Fatalf("drop-in mode %o, want 0440", st.Mode().Perm())
	}
	if h.calledCount("visudo") != 1 {
		t.Fatalf("visudo must validate the drop-in before install; calls=%d", h.calledCount("visudo"))
	}
	if h.calledCount("chpasswd") != 0 {
		t.Fatal("a key-only import must not mint a password")
	}
	if !h.exists("appliance/state/console.done") {
		t.Fatal("console step not marked done")
	}
}

func TestFirstBoot_StepConsole_PasswordSuppliedLeavesSudoPasswordGated(t *testing.T) {
	h := newFBHarness(t)
	h.setShadow("$6$salt$hash")
	h.setKey(true) // both supplied: the password governs sudo
	out, code := h.run("step_console")
	if code != 0 {
		t.Fatalf("step_console failed (%d):\n%s", code, out)
	}
	if h.exists("sudoers.d/95-culvert-keyonly") {
		t.Fatal("a supplied password must keep sudo password-gated (no NOPASSWD drop-in)")
	}
	if h.calledCount("chpasswd") != 0 || h.calledCount("visudo") != 0 {
		t.Fatalf("nothing to change: chpasswd=%d visudo=%d", h.calledCount("chpasswd"), h.calledCount("visudo"))
	}
}

func TestFirstBoot_StepConsole_NeitherSuppliedMintsOneTimePassword(t *testing.T) {
	h := newFBHarness(t)
	h.setShadow("!")
	h.setKey(false)
	out, code := h.run("step_console")
	if code != 0 {
		t.Fatalf("step_console failed (%d):\n%s", code, out)
	}
	in := h.chpasswdInput()
	m := regexp.MustCompile(`^culvert:([A-HJ-NP-Za-km-z2-9]{16})\n$`).FindStringSubmatch(in)
	if m == nil {
		t.Fatalf("chpasswd input %q: want culvert:<16 unambiguous chars>", in)
	}
	if h.calledCount("chage") != 1 {
		t.Fatal("chage -d 0 (force change at first login) was not applied")
	}
	if h.exists("sudoers.d/95-culvert-keyonly") {
		t.Fatal("a minted password must not come with passwordless sudo")
	}
	if h.exists("appliance/state/console.minting") {
		t.Fatal("minting marker must be cleared after the console print")
	}
	if !h.exists("appliance/state/console.done") {
		t.Fatal("console step not marked done")
	}
}

// Interrupted credential initialisation: chpasswd landed the password, the
// run died before the console print (simulated by chage failing). The next
// run sees a SET password AND the minting marker → it must re-mint and show
// a NEW password rather than treating the never-shown one as a credential.
func TestFirstBoot_StepConsole_InterruptedMintIsRedone(t *testing.T) {
	h := newFBHarness(t)
	h.setShadow("!")
	h.setKey(false)
	h.stub("chage", `exit 1`) // the interruption point
	out, code := h.run("step_console")
	if code == 0 {
		t.Fatalf("first run must fail at the simulated interruption:\n%s", out)
	}
	first := h.chpasswdInput()
	if !h.exists("appliance/state/console.minting") {
		t.Fatal("minting marker must survive the interruption")
	}
	if h.exists("appliance/state/console.done") {
		t.Fatal("an interrupted mint must not mark the step done")
	}
	// Now the shadow field carries OUR (never shown) password.
	h.setShadow("$6$ours$neverShown")
	h.stub("chage", `:`)
	out, code = h.run("step_console")
	if code != 0 {
		t.Fatalf("resumed run failed (%d):\n%s", code, out)
	}
	second := h.chpasswdInput()
	if second == first || second == "" {
		t.Fatalf("resumed run must mint a NEW password; first=%q second=%q", first, second)
	}
	if !strings.Contains(out, "re-minted after an interrupted run") {
		t.Fatalf("log must say the mint was redone:\n%s", out)
	}
	if h.exists("appliance/state/console.minting") || !h.exists("appliance/state/console.done") {
		t.Fatal("marker must be cleared and the step marked done after the resumed mint")
	}
}

// CONTROL: a password set by cloud-init (no marker) is never replaced.
func TestFirstBoot_StepConsole_ControlSuppliedPasswordIsNeverReplaced(t *testing.T) {
	h := newFBHarness(t)
	h.setShadow("$6$cloudinit$hash")
	h.setKey(false)
	if _, code := h.run("step_console"); code != 0 {
		t.Fatal("step_console failed")
	}
	if h.calledCount("chpasswd") != 0 {
		t.Fatal("a cloud-init password must not be replaced")
	}
}

// ── step_install: setup token minted once, persisted, reused ────────────────

func TestFirstBoot_StepInstall_MintsAndPersistsSetupToken(t *testing.T) {
	h := newFBHarness(t)
	h.installSHStub(true)
	out, code := h.run("step_install")
	if code != 0 {
		t.Fatalf("step_install failed (%d):\n%s", code, out)
	}
	envb, _ := os.ReadFile(filepath.Join(h.stack, ".env"))
	m := regexp.MustCompile(`(?m)^CULVERT_SETUP_TOKEN=([a-f0-9]{32})$`).FindStringSubmatch(string(envb))
	if m == nil {
		t.Fatalf(".env must carry a 32-hex setup token:\n%s", envb)
	}
	calls, _ := os.ReadFile(h.calls)
	if !strings.Contains(string(calls), "TOKEN="+m[1]) || !strings.Contains(string(calls), "DEFAULT_ACTION=deny") || !strings.Contains(string(calls), "ASSUME_DOCKER=1") {
		t.Fatalf("install.sh must receive the token, default-deny and assume-docker:\n%s", calls)
	}
	st, _ := os.Stat(filepath.Join(h.stack, ".env"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf(".env mode %o, want 0600 (the token lives there)", st.Mode().Perm())
	}
	// A second run after an interruption (install.done absent) reuses the
	// persisted token: the one the console may already have shown.
	_ = os.Remove(filepath.Join(h.state, "state", "install.done"))
	if _, code := h.run("step_install"); code != 0 {
		t.Fatal("re-run failed")
	}
	calls, _ = os.ReadFile(h.calls)
	if strings.Count(string(calls), "TOKEN="+m[1]) != 2 {
		t.Fatalf("re-run must pass the SAME persisted token, not mint another:\n%s", calls)
	}
}

func TestFirstBoot_StepInstall_RefusesWhenTokenNotPersisted(t *testing.T) {
	h := newFBHarness(t)
	h.installSHStub(false)
	out, code := h.run("step_install")
	if code == 0 {
		t.Fatalf("step_install must fail when install.sh did not persist the token:\n%s", out)
	}
	if !strings.Contains(out, "did not persist the setup token") {
		t.Fatalf("log must name the cause:\n%s", out)
	}
	if h.exists("appliance/state/install.done") {
		t.Fatal("install must not be marked done without the token persisted — the wizard would be open to the network")
	}
}

// ── step_agent / --repair-agent: verify, never claim ────────────────────────

func TestFirstBoot_StepAgent_RecordsDegradedWhenNotInstalled(t *testing.T) {
	h := newFBHarness(t)
	out, code := h.run("step_agent")
	if code != 0 {
		t.Fatalf("step_agent must never be fatal (%d):\n%s", code, out)
	}
	pend, err := os.ReadFile(filepath.Join(h.state, "state", "agent.pending"))
	if err != nil {
		t.Fatal("agent.pending must record the degraded state")
	}
	if !strings.Contains(string(pend), "unit_absent") {
		t.Fatalf("pending record must carry the reason: %q", pend)
	}
	if h.exists("appliance/state/agent.done") {
		t.Fatal("agent.done must not be claimed")
	}
	if !strings.Contains(out, "--repair-agent") {
		t.Fatalf("log must name the repair path:\n%s", out)
	}
}

func TestFirstBoot_StepAgent_ReasonsAreSpecific(t *testing.T) {
	h := newFBHarness(t)
	unit := filepath.Join(h.root, "culvert-maint.service")
	// unit present, not enabled
	_ = os.WriteFile(unit, []byte("[Unit]\n"), 0o600)
	if out, _ := h.run("agent_state"); strings.TrimSpace(out) != "missing:unit_not_enabled" {
		t.Fatalf("got %q", out)
	}
	// enabled, binary absent
	_ = os.WriteFile(filepath.Join(h.root, "agent.enabled"), nil, 0o600)
	if out, _ := h.run("agent_state"); strings.TrimSpace(out) != "missing:binary_absent" {
		t.Fatalf("got %q", out)
	}
	h.stub("culvert-maint", `echo culvert-maint v0-test`)
	if out, _ := h.run("agent_state"); strings.TrimSpace(out) != "installed" {
		t.Fatalf("got %q", out)
	}
}

// Transient trust-service failure at first boot, then recovery: the repair
// verb re-runs install.sh under the first boot's exact environment, and only
// the VERIFIED install clears the pending record.
func TestFirstBoot_RepairAgent_TransientFailureThenRecovery(t *testing.T) {
	h := newFBHarness(t)
	h.installSHStub(true)
	if out, code := h.run("step_install && step_agent"); code != 0 {
		t.Fatalf("first boot failed (%d):\n%s", code, out)
	}
	if !h.exists("appliance/state/agent.pending") || h.exists("appliance/state/agent.done") {
		t.Fatal("first boot with an unreachable trust service must leave the agent pending")
	}
	envBefore, _ := os.ReadFile(filepath.Join(h.stack, ".env"))

	// Still failing: repair must refuse to claim success and keep the record.
	out, code := h.run("main --repair-agent")
	if code == 0 {
		t.Fatalf("repair must fail while the agent still cannot be installed:\n%s", out)
	}
	if !h.exists("appliance/state/agent.pending") || h.exists("appliance/state/agent.done") {
		t.Fatal("a failed repair must leave the pending record in place")
	}

	// Trust service back: repair installs, verifies, clears.
	_ = os.WriteFile(filepath.Join(h.root, "agent.available"), nil, 0o600)
	out, code = h.run("main --repair-agent")
	if code != 0 {
		t.Fatalf("repair after recovery failed (%d):\n%s", code, out)
	}
	if h.exists("appliance/state/agent.pending") || !h.exists("appliance/state/agent.done") {
		t.Fatal("a verified repair must clear agent.pending and record agent.done")
	}
	envAfter, _ := os.ReadFile(filepath.Join(h.stack, ".env"))
	if !bytes.Equal(envAfter, envBefore) {
		t.Fatalf("repair must not rewrite the stack's .env (token/secrets):\n%s\n---\n%s", envBefore, envAfter)
	}
	calls, _ := os.ReadFile(h.calls)
	tok := regexp.MustCompile(`CULVERT_SETUP_TOKEN=([a-f0-9]{32})`).FindStringSubmatch(string(envBefore))
	if len(tok) < 2 || strings.Count(string(calls), "TOKEN="+tok[1]) != 3 {
		t.Fatalf("every install.sh run (boot + 2 repairs) must carry the same persisted token:\n%s", calls)
	}
}

func TestFirstBoot_RepairAgent_RefusesBeforeInstallStep(t *testing.T) {
	h := newFBHarness(t)
	h.installSHStub(true)
	out, code := h.run("main --repair-agent")
	if code == 0 || !strings.Contains(out, "install step has not completed") {
		t.Fatalf("repair before the install step must refuse (exit %d):\n%s", code, out)
	}
	if h.calledCount("install.sh") != 0 {
		t.Fatal("install.sh must not run from a repair on an unprovisioned appliance")
	}
}

// ── culvert-sudo-policy: never lock the operator out ────────────────────────

func (h *fbHarness) runSudoPolicy(args ...string) (output string, code int) {
	h.t.Helper()
	abs, _ := filepath.Abs(sudoPolicyScript)
	// #nosec G204 -- program is the literal "bash"; abs is the checked-in
	// script's path and args are test constants.
	c := exec.CommandContext(h.t.Context(), "bash", append([]string{abs}, args...)...)
	c.Env = h.env()
	out, err := c.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errorsAs(err, &ee) {
			code = ee.ExitCode()
		} else {
			h.t.Fatal(err)
		}
	}
	return string(out), code
}

func TestSudoPolicy_RequirePasswordRefusesWithoutAPassword(t *testing.T) {
	h := newFBHarness(t)
	h.setShadow("!")
	h.setKey(true)
	_ = os.WriteFile(filepath.Join(h.sudoers, "95-culvert-keyonly"), []byte("culvert ALL=(ALL:ALL) NOPASSWD: ALL\n"), 0o400)
	out, code := h.runSudoPolicy("require-password")
	if code == 0 || !strings.Contains(out, "no usable password") {
		t.Fatalf("must refuse (exit %d):\n%s", code, out)
	}
	if !h.exists("sudoers.d/95-culvert-keyonly") {
		t.Fatal("the drop-in must survive a refused switch — removing it would lock the operator out")
	}
	h.setShadow("$6$set$hash")
	out, code = h.runSudoPolicy("require-password")
	if code != 0 || h.exists("sudoers.d/95-culvert-keyonly") {
		t.Fatalf("with a password set the drop-in must be removed (exit %d):\n%s", code, out)
	}
}

func TestSudoPolicy_PasswordlessRefusesWithoutAKey(t *testing.T) {
	h := newFBHarness(t)
	h.setShadow("$6$set$hash")
	h.setKey(false)
	out, code := h.runSudoPolicy("passwordless")
	if code == 0 || !strings.Contains(out, "no SSH authorized key") {
		t.Fatalf("must refuse (exit %d):\n%s", code, out)
	}
	h.setKey(true)
	out, code = h.runSudoPolicy("passwordless")
	if code != 0 || !h.exists("sudoers.d/95-culvert-keyonly") {
		t.Fatalf("with a key the drop-in must be installed (exit %d):\n%s", code, out)
	}
	out, _ = h.runSudoPolicy("status")
	if !strings.Contains(out, "passwordless") || !strings.Contains(out, "ssh authorized key: present") {
		t.Fatalf("status:\n%s", out)
	}
}

// ── culvert-status: describes degraded capability and the setup token ───────

func TestApplianceStatus_ReportsAgentSudoAndToken(t *testing.T) {
	h := newFBHarness(t)
	_ = os.WriteFile(filepath.Join(h.state, "state", "agent.pending"), []byte("2026-10-03T00:00:00Z unit_absent\n"), 0o600)
	_ = os.WriteFile(filepath.Join(h.sudoers, "95-culvert-keyonly"), []byte("culvert ALL=(ALL:ALL) NOPASSWD: ALL\n"), 0o400)
	_ = os.WriteFile(filepath.Join(h.stack, ".env"), []byte("CULVERT_SETUP_TOKEN=0123456789abcdef0123456789abcdef\n"), 0o600)
	abs, _ := filepath.Abs(statusScript)
	// #nosec G204 -- program is the literal "bash"; abs is the checked-in script's path.
	c := exec.CommandContext(t.Context(), "bash", abs)
	c.Env = h.env()
	out, _ := c.CombinedOutput() // the loopback probes fail here: no services
	s := string(out)
	for _, want := range []string{"Maintenance agent:  NOT installed (unit_absent)", "--repair-agent", "Console sudo:       passwordless"} {
		if !strings.Contains(s, want) {
			t.Errorf("status output lacks %q:\n%s", want, s)
		}
	}
	// With no services the setup state is unknown, so the token row is
	// withheld; it appears only while the wizard reports needsSetup=true.
	if strings.Contains(s, "0123456789abcdef") {
		t.Errorf("token must not be printed while setup state is unknown:\n%s", s)
	}
	c = exec.CommandContext(t.Context(), "bash", abs, "--json") // #nosec G204 -- same script, fixed flag
	c.Env = h.env()
	out, _ = c.CombinedOutput()
	if !strings.Contains(string(out), `"maintenance_agent": "NOT installed (unit_absent)`) || !strings.Contains(string(out), `"sudo_policy": "passwordless`) {
		t.Errorf("--json lacks the new fields:\n%s", out)
	}
}

// A full root filesystem stops the proxy (BadgerDB writes SIGBUS — readiness
// report F-DISK-1), so the console summary must say when the disk is low, and
// must NOT cry wolf on a healthy one (the control).
func TestApplianceStatus_ReportsRootDiskPressure(t *testing.T) {
	abs, _ := filepath.Abs(statusScript)
	run := func(availKB, pct int, args ...string) string {
		t.Helper()
		h := newFBHarness(t)
		h.writeExec(filepath.Join(h.stubs, "df"), fmt.Sprintf(
			"#!/usr/bin/env bash\necho 'Filesystem 1024-blocks Used Available Capacity Mounted on'\necho '/dev/sda1 41943040 0 %d %d%%%% /'\n", availKB, pct))
		// #nosec G204 -- program is the literal "bash"; abs is the checked-in script's path.
		c := exec.CommandContext(t.Context(), "bash", append([]string{abs}, args...)...)
		c.Env = h.env()
		out, _ := c.CombinedOutput()
		return string(out)
	}
	low := run(1<<20, 97)
	if !strings.Contains(low, "Root disk:          LOW: 97% used, 1024 MiB free") {
		t.Fatalf("a 97%%-full disk is not reported as low:\n%s", low)
	}
	if b := run(1<<20, 97, "--brief"); !strings.Contains(b, "Disk:        LOW:") {
		t.Fatalf("--brief must surface a low disk:\n%s", b)
	}
	if j := run(1<<20, 97, "--json"); !strings.Contains(j, `"root_disk_low": true`) {
		t.Fatalf("--json must carry root_disk_low:\n%s", j)
	}
	ok := run(30<<20, 25)
	if strings.Contains(ok, "LOW") || !strings.Contains(ok, "Root disk:          25% used, 30720 MiB free") {
		t.Fatalf("a healthy disk is misreported:\n%s", ok)
	}
	if b := run(30<<20, 25, "--brief"); strings.Contains(b, "Disk:") {
		t.Fatalf("--brief must stay quiet on a healthy disk:\n%s", b)
	}
}

// ── live: sudoers last-match precedence (opt-in, root) ──────────────────────
//
// The whole key-only design rests on one claim: sudo takes the LAST matching
// rule, so 95-culvert-keyonly (NOPASSWD) must override 90-cloud-init-users
// (password). This test proves it with the real sudo on a throwaway account,
// and proves the reverse (drop-in removed ⇒ password demanded). Run it with:
//
//	CULVERT_SUDO_POLICY_LIVE=1 go test -run TestSudoPolicy_Live ./ -v
func TestSudoPolicy_LiveLastMatchPrecedence(t *testing.T) {
	if os.Getenv("CULVERT_SUDO_POLICY_LIVE") != "1" {
		t.Skip("set CULVERT_SUDO_POLICY_LIVE=1 (needs root + sudo) to run the live sudoers precedence proof")
	}
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	for _, tool := range []string{"sudo", "useradd", "userdel", "visudo", "su"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	user := "cvsudotest" + strconv.Itoa(os.Getpid()%10000)
	// #nosec G204 -- fixed argv; user is the throwaway account name this test generates.
	if out, err := exec.CommandContext(t.Context(), "useradd", "-m", "-s", "/bin/bash", user).CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v %s", err, out)
	}
	// t.Context() is already cancelled when Cleanup runs; the account removal
	// must not be cut short by it.
	t.Cleanup(func() { _ = exec.CommandContext(context.Background(), "userdel", "-r", user).Run() }) // #nosec G204 -- fixed argv + the generated account name
	cloudInit := "/etc/sudoers.d/90-cloud-init-users-" + user
	keyOnly := "/etc/sudoers.d/95-culvert-keyonly-" + user
	write := func(path, rule string) {
		t.Helper()
		// Written private, then given the real sudoers.d mode (0440): the
		// proof must run against the file shape an appliance ships.
		if err := os.WriteFile(path, []byte(rule), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o440); err != nil {
			t.Fatal(err)
		}
		// #nosec G204 -- fixed argv; path is one of the two sudoers drop-ins this test writes.
		if out, err := exec.CommandContext(t.Context(), "visudo", "-c", "-q", "-f", path).CombinedOutput(); err != nil {
			t.Fatalf("visudo rejects %s: %v %s", path, err, out)
		}
	}
	write(cloudInit, user+" ALL=(ALL:ALL) ALL\n")
	t.Cleanup(func() { _ = os.Remove(cloudInit); _ = os.Remove(keyOnly) })
	sudoN := func() (string, error) {
		// #nosec G204 -- fixed argv + the generated account name.
		out, err := exec.CommandContext(t.Context(), "su", "-", user, "-c", "sudo -n true").CombinedOutput()
		return string(out), err
	}
	// Password rule alone: sudo -n must refuse (no password can be supplied).
	if out, err := sudoN(); err == nil || !strings.Contains(out, "password") {
		t.Fatalf("control: password-gated sudo must refuse -n (err=%v):\n%s", err, out)
	}
	// Drop-in that sorts AFTER the cloud-init rule wins: passwordless.
	write(keyOnly, user+" ALL=(ALL:ALL) NOPASSWD: ALL\n")
	if out, err := sudoN(); err != nil {
		t.Fatalf("95-… NOPASSWD must override 90-…: %v\n%s", err, out)
	}
	// The same rule sorting BEFORE the cloud-init rule must LOSE — this is
	// what pins the file NAME as load-bearing.
	early := "/etc/sudoers.d/10-culvert-keyonly-" + user
	_ = os.Remove(keyOnly)
	write(early, user+" ALL=(ALL:ALL) NOPASSWD: ALL\n")
	t.Cleanup(func() { _ = os.Remove(early) })
	if out, err := sudoN(); err == nil {
		t.Fatalf("a NOPASSWD rule sorting before the password rule must lose (last match wins):\n%s", out)
	}
	_ = os.Remove(early)
	// Policy switch back: drop-in removed ⇒ password demanded again.
	if out, err := sudoN(); err == nil {
		t.Fatalf("after removing the drop-in sudo must be password-gated again:\n%s", out)
	}
	t.Logf("live sudoers precedence proven on %s: 90-password refuses -n; 95-NOPASSWD overrides; 10-NOPASSWD loses", user)
}

// ── candidate builds: the agent break-glass is exported ONLY when labelled ──
//
// build-ova.sh --candidate-image-tar appends CANDIDATE_BUILD=1 to the guest
// manifest; install.sh's cosign gate cannot admit a bundled agent from an
// unsigned CI artifact, so first boot passes the candidate-scoped
// CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1. The control half matters more: a
// release OVA (no CANDIDATE_BUILD) must never export it.
func TestFirstBoot_CandidateBuildExportsScopedAgentTrustOnly(t *testing.T) {
	h := newFBHarness(t)
	h.writeExec(filepath.Join(h.root, "install.sh"), "#!/usr/bin/env bash\nprintf 'install.sh TRUST=%s\\n' \"${CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE:-unset}\" >> \"$FB_HARNESS/calls.log\"\n")
	if out, code := h.run("run_install_sh tok"); code != 0 {
		t.Fatalf("release shape failed (%d):\n%s", code, out)
	}
	calls, _ := os.ReadFile(h.calls)
	if !strings.Contains(string(calls), "install.sh TRUST=unset") {
		t.Fatalf("a release build must NOT export the agent break-glass:\n%s", calls)
	}
	out, code := h.run("CANDIDATE_BUILD=1 CANDIDATE_SOURCE_SHA=abcdef0123456789 run_install_sh tok")
	if code != 0 {
		t.Fatalf("candidate shape failed (%d):\n%s", code, out)
	}
	calls, _ = os.ReadFile(h.calls)
	if !strings.Contains(string(calls), "install.sh TRUST=1") {
		t.Fatalf("a candidate build must export the candidate-scoped break-glass:\n%s", calls)
	}
	if !strings.Contains(out, "CANDIDATE build") || !strings.Contains(out, "NOT a production posture") {
		t.Fatalf("the candidate trust decision must be logged loudly:\n%s", out)
	}
}

// build-ova.sh's candidate contract, pinned structurally: no bypass flag is
// ever written for a release build, the candidate overrides are appended
// (later keys win on source) rather than substituted, and the OVF/full
// version names the candidate.
func TestBuildOVA_CandidateModeIsLabelledAndScoped(t *testing.T) {
	b, err := os.ReadFile(buildOVAScript)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, want := range []string{
		`[[ "$CANDIDATE_SOURCE" =~ ^[0-9a-f]{40}$ ]] || die`,
		`echo "CANDIDATE_BUILD=1"`,
		`-candidate.${CANDIDATE_SOURCE:0:12}`,
		`NOT FOR PRODUCTION`,
		`"not_for_production": True`,
		`if [[ "$CANDIDATE" -eq 0 && "$SKIP_COSIGN" -eq 0 ]]; then`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("build-ova.sh lacks %q", want)
		}
	}
	if strings.Contains(src, "export CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE") || strings.Contains(src, "-e CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE") {
		t.Error("build-ova.sh must not set the agent break-glass itself; only culvert-firstboot does, keyed on the guest manifest")
	}
	fb, err := os.ReadFile(fbScript)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(fb), "export CULVERT_MAINT_TRUST_UNVERIFIED_IMAGE=1"); n != 1 {
		t.Fatalf("culvert-firstboot must export the break-glass in exactly one place (got %d)", n)
	}
	if !strings.Contains(string(fb), `if [[ "${CANDIDATE_BUILD:-0}" == 1 ]]; then`) {
		t.Fatal("the export must be guarded by CANDIDATE_BUILD=1")
	}
}
