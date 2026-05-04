package runner

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// d16bRunner returns a Runner wired with the typical D1.6b allowlist
// and a fake exec layer that captures the argv + child env without
// actually exec'ing anything.
//
// captured[0].Argv is the full argv (sudo prefix + binary + args) as
// the runner would have invoked. The fake exits cleanly with no
// stdout/stderr.
func d16bRunner(t *testing.T) (*Runner, *capturedExec) {
	t.Helper()
	capE := &capturedExec{}
	r, err := New(Options{
		ComposeProjectDir: "/srv/culvert",
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      5 * time.Second,
		EnvAllow:          []string{EnvCulvertBackupPassphrase},
		DockerBinary:      "/usr/bin/docker",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.execStartFn = func(cmd *exec.Cmd) error {
		capE.Argv = append([]string(nil), cmd.Args...)
		capE.Env = append([]string(nil), cmd.Env...)
		capE.Dir = cmd.Dir
		return nil
	}
	r.execWaitFn = func(_ *exec.Cmd) error { return nil }
	return r, capE
}

type capturedExec struct {
	Argv []string
	Env  []string
	Dir  string
}

func (c *capturedExec) HasEnv(name, value string) bool {
	for _, e := range c.Env {
		if e == name+"="+value {
			return true
		}
	}
	return false
}

func (c *capturedExec) HasEnvName(name string) bool {
	for _, e := range c.Env {
		if strings.HasPrefix(e, name+"=") {
			return true
		}
	}
	return false
}

// ─── argv-shape tests (exact match per template) ────────────────────

func TestComposeBackupEncrypted_Argv(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeBackupEncrypted(context.Background(), "culvert-2026-05-04T120000Z.tar.gz.enc", "secret"); err != nil {
		t.Fatalf("ComposeBackupEncrypted: %v", err)
	}
	want := []string{
		"/usr/bin/docker", "compose", "-f", "/srv/culvert/docker-compose.yml",
		"--profile", "cli", "run", "--rm",
		"-e", "CULVERT_BACKUP_PASSPHRASE",
		"cli", "--encrypt", "--backup", "/backup/culvert-2026-05-04T120000Z.tar.gz.enc",
	}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
}

func TestComposeBackupEncrypted_PassphraseInEnvNotArgv(t *testing.T) {
	r, capE := d16bRunner(t)
	const secret = "correct-horse-battery-staple"
	if _, err := r.ComposeBackupEncrypted(context.Background(), "x.enc", secret); err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, a := range capE.Argv {
		if strings.Contains(a, secret) {
			t.Errorf("passphrase value leaked into argv at %q", a)
		}
	}
	if !capE.HasEnv(EnvCulvertBackupPassphrase, secret) {
		t.Errorf("passphrase missing from child env (overlay broken)")
	}
}

func TestComposeBackupUnencrypted_Argv(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeBackupUnencrypted(context.Background(), "x.tar.gz"); err != nil {
		t.Fatalf("err: %v", err)
	}
	want := []string{
		"/usr/bin/docker", "compose", "-f", "/srv/culvert/docker-compose.yml",
		"--profile", "cli", "run", "--rm",
		"cli", "--backup", "/backup/x.tar.gz",
	}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
}

func TestComposeBackupUnencrypted_PassphraseSuppressedFromEnv(t *testing.T) {
	r, capE := d16bRunner(t)
	t.Setenv(EnvCulvertBackupPassphrase, "host-side-leak")
	if _, err := r.ComposeBackupUnencrypted(context.Background(), "x.tar.gz"); err != nil {
		t.Fatalf("err: %v", err)
	}
	if capE.HasEnvName(EnvCulvertBackupPassphrase) {
		t.Errorf("unencrypted backup must SUPPRESS host-side passphrase; child env=%v", capE.Env)
	}
}

func TestComposeBackupList_Argv(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeBackupList(context.Background()); err != nil {
		t.Fatalf("err: %v", err)
	}
	want := []string{
		"/usr/bin/docker", "compose", "-f", "/srv/culvert/docker-compose.yml",
		"--profile", "cli", "run", "--rm",
		"cli", "--list-backups", "--backup-dir", "/backup",
	}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
	if capE.HasEnvName(EnvCulvertBackupPassphrase) {
		t.Errorf("backup-list does not need passphrase; child env should not contain it")
	}
}

func TestComposeRestoreDryRun_Argv_AllFlagsOff(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeRestoreDryRun(context.Background(), "x.enc", RestoreModeFull, false, false, "secret"); err != nil {
		t.Fatalf("err: %v", err)
	}
	want := []string{
		"/usr/bin/docker", "compose", "-f", "/srv/culvert/docker-compose.yml",
		"--profile", "cli", "run", "--rm",
		"-e", "CULVERT_BACKUP_PASSPHRASE",
		"cli", "--restore", "/backup/x.enc",
		"--mode", "full",
	}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
}

func TestComposeRestoreDryRun_NoConfirm(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeRestoreDryRun(context.Background(), "x.enc", RestoreModeFull, true, true, "secret"); err != nil {
		t.Fatalf("err: %v", err)
	}
	for _, a := range capE.Argv {
		if a == "--confirm" {
			t.Errorf("dryrun must NEVER include --confirm; argv=%v", capE.Argv)
		}
	}
}

func TestComposeRestoreCommit_Argv_AllFlagsOn_TerminatesWithConfirm(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeRestoreCommit(context.Background(), "x.enc", RestoreModeStateOnly, true, true, "secret"); err != nil {
		t.Fatalf("err: %v", err)
	}
	want := []string{
		"/usr/bin/docker", "compose", "-f", "/srv/culvert/docker-compose.yml",
		"--profile", "cli", "run", "--rm",
		"-e", "CULVERT_BACKUP_PASSPHRASE",
		"cli", "--restore", "/backup/x.enc",
		"--mode", "state-only",
		"--accept-dp-reenrollment",
		"--allow-counter-rollback",
		"--confirm",
	}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
	if capE.Argv[len(capE.Argv)-1] != "--confirm" {
		t.Errorf("--confirm must be the LAST argv token; got %v", capE.Argv)
	}
}

func TestComposeRestoreCanonicalFlagOrder(t *testing.T) {
	// allowCounter=true, acceptDP=true must STILL place
	// --accept-dp-reenrollment before --allow-counter-rollback —
	// canonical alphabetical order, not the order params were
	// passed to the function.
	r, capE := d16bRunner(t)
	if _, err := r.ComposeRestoreDryRun(context.Background(), "x", RestoreModeFull, true, true, "p"); err != nil {
		t.Fatalf("err: %v", err)
	}
	idxAccept, idxAllow := -1, -1
	for i, a := range capE.Argv {
		switch a {
		case "--accept-dp-reenrollment":
			idxAccept = i
		case "--allow-counter-rollback":
			idxAllow = i
		}
	}
	if idxAccept == -1 || idxAllow == -1 {
		t.Fatalf("expected both flags present; argv=%v", capE.Argv)
	}
	if idxAccept >= idxAllow {
		t.Errorf("canonical order: --accept-dp-reenrollment must precede --allow-counter-rollback; got accept@%d allow@%d", idxAccept, idxAllow)
	}
}

func TestComposeRestore_RejectsBadMode(t *testing.T) {
	r, _ := d16bRunner(t)
	if _, err := r.ComposeRestoreDryRun(context.Background(), "x", RestoreMode("partial"), false, false, ""); err == nil {
		t.Error("expected error for bogus mode")
	}
	if _, err := r.ComposeRestoreCommit(context.Background(), "x", RestoreMode(""), false, false, ""); err == nil {
		t.Error("expected error for empty mode")
	}
}

func TestComposeDown_Argv(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeDown(context.Background()); err != nil {
		t.Fatalf("err: %v", err)
	}
	want := []string{"/usr/bin/docker", "compose", "-f", "/srv/culvert/docker-compose.yml", "down"}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
}

func TestComposeUp_Argv(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeUp(context.Background()); err != nil {
		t.Fatalf("err: %v", err)
	}
	want := []string{"/usr/bin/docker", "compose", "-f", "/srv/culvert/docker-compose.yml", "up", "-d"}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
}

func TestComposeCleanupDryRun_Argv(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeCleanupDryRun(context.Background(), "168h", 3); err != nil {
		t.Fatalf("err: %v", err)
	}
	want := []string{
		"/usr/bin/docker", "compose", "-f", "/srv/culvert/docker-compose.yml",
		"--profile", "cli", "run", "--rm",
		"cli", "--cleanup-restore-leftovers",
		"--older-than", "168h", "--keep-last", "3",
	}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
	for _, a := range capE.Argv {
		if a == "--confirm" {
			t.Errorf("dryrun must NEVER include --confirm")
		}
	}
}

func TestComposeCleanupCommit_TerminatesWithConfirm(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeCleanupCommit(context.Background(), "720h", 5); err != nil {
		t.Fatalf("err: %v", err)
	}
	if capE.Argv[len(capE.Argv)-1] != "--confirm" {
		t.Errorf("commit must end with --confirm; argv=%v", capE.Argv)
	}
}

// ─── validator tests ────────────────────────────────────────────────

func TestValidateBackupFilename_Rejects(t *testing.T) {
	bad := []string{
		"",
		".",
		"..",
		".hidden",
		"a/b",
		"a\\b",
		"../../etc/passwd",
		"a b.tar",                // space
		"a;rm -rf.tar",           // shell meta
		"a$(whoami).tar",         // shell expansion
		"a\nb.tar",               // newline
		strings.Repeat("a", 256), // too long
	}
	for _, name := range bad {
		if err := validateBackupFilename(name); err == nil {
			t.Errorf("validateBackupFilename(%q) should have errored", name)
		}
	}
}

func TestValidateBackupFilename_Accepts(t *testing.T) {
	good := []string{
		"a.tar.gz",
		"a-1.tar.gz",
		"a_b.tar.gz",
		"culvert-2026-05-04T120000Z.tar.gz.enc",
		strings.Repeat("a", 255),
	}
	for _, name := range good {
		if err := validateBackupFilename(name); err != nil {
			t.Errorf("validateBackupFilename(%q): want nil, got %v", name, err)
		}
	}
}

func TestValidateOlderThan_Rejects(t *testing.T) {
	bad := []string{"", "1m", "59m", "8761h", "1y", "abc", "1.5x"}
	for _, d := range bad {
		if err := validateOlderThan(d); err == nil {
			t.Errorf("validateOlderThan(%q) should have errored", d)
		}
	}
}

func TestValidateOlderThan_Accepts(t *testing.T) {
	for _, d := range []string{"1h", "24h", "168h", "720h", "8760h"} {
		if err := validateOlderThan(d); err != nil {
			t.Errorf("validateOlderThan(%q): %v", d, err)
		}
	}
}

func TestValidateKeepLast(t *testing.T) {
	for _, n := range []int{-1, 101, 9999} {
		if err := validateKeepLast(n); err == nil {
			t.Errorf("validateKeepLast(%d) should have errored", n)
		}
	}
	for _, n := range []int{0, 1, 5, 100} {
		if err := validateKeepLast(n); err != nil {
			t.Errorf("validateKeepLast(%d): %v", n, err)
		}
	}
}

// ─── env-overlay enforcement ────────────────────────────────────────

func TestRunWithEnv_RejectsNonAllowedOverlayName(t *testing.T) {
	r, _ := d16bRunner(t)
	_, err := r.runWithEnv(context.Background(), []string{"/bin/echo"}, map[string]string{"FOO_NOT_IN_ALLOWLIST": "x"})
	if err == nil {
		t.Error("overlay with name outside EnvAllow must fail before exec")
	}
	if !strings.Contains(err.Error(), "EnvAllow") {
		t.Errorf("error should mention EnvAllow; got %v", err)
	}
}

func TestEncryptedBackup_RequiresNonEmptyPassphrase(t *testing.T) {
	r, _ := d16bRunner(t)
	if _, err := r.ComposeBackupEncrypted(context.Background(), "x.enc", ""); err == nil {
		t.Error("encrypted backup with empty resolved passphrase must error")
	}
}

func TestRestoreOnUnencryptedArchive_DoesNotForwardPassphrase(t *testing.T) {
	// Empty resolvedPassphrase signals "archive is unencrypted; cli
	// will detect and ignore". The runner suppresses
	// CULVERT_BACKUP_PASSPHRASE in the child env so a host-side leak
	// can't accidentally surface.
	r, capE := d16bRunner(t)
	t.Setenv(EnvCulvertBackupPassphrase, "host-side-leak")
	if _, err := r.ComposeRestoreDryRun(context.Background(), "x.tar.gz", RestoreModeFull, false, false, ""); err != nil {
		t.Fatalf("err: %v", err)
	}
	if capE.HasEnvName(EnvCulvertBackupPassphrase) {
		t.Errorf("empty resolvedPassphrase must suppress host-side env value; got env=%v", capE.Env)
	}
}

// ─── parity-derived: enumerated sudoers count ───────────────────────

func TestEnumerateRestoreSudoersLines_Count(t *testing.T) {
	dryrun := enumerateRestoreSudoersLines("PFX", false)
	commit := enumerateRestoreSudoersLines("PFX", true)
	if len(dryrun) != 12 {
		t.Errorf("dryrun: want 12 lines, got %d", len(dryrun))
	}
	if len(commit) != 12 {
		t.Errorf("commit: want 12 lines, got %d", len(commit))
	}
	for _, line := range dryrun {
		if strings.Contains(line, "--confirm") {
			t.Errorf("dryrun line must not contain --confirm: %q", line)
		}
	}
	for _, line := range commit {
		if !strings.HasSuffix(line, "--confirm") {
			t.Errorf("commit line must terminate with --confirm: %q", line)
		}
	}
	// Modes covered exactly once each per flag combo.
	for _, mode := range []string{"full", "trust-root-only", "state-only"} {
		count := 0
		for _, line := range dryrun {
			if strings.Contains(line, "--mode "+mode+" ") || strings.HasSuffix(line, "--mode "+mode) {
				count++
			}
		}
		if count != 4 {
			t.Errorf("mode %q must appear in 4 lines (4 flag combos); got %d", mode, count)
		}
	}
}

// ensure exec.ExitError import doesn't break (helper used by other tests).
var _ = errors.New
