package main

// install_script_session_secret_empty_env_test.go — SEC-INSTALL-SESSKEY-1.
//
// Two functions in scripts/install.sh decide "is this secret already
// configured in .env?", and they disagreed about what counts as configured.
//
// secret_already_set() (the at-rest passphrases) was taught the docker compose
// truth: `VAR=`, `VAR=""`, `VAR=''`, `VAR=` + an inline comment and a CRLF-only
// value all resolve to the EMPTY string, so none of them configures anything
// (install_script_secret_already_set_empty_test.go pins that table).
// persist_host_env_session_secret() kept its own `grep -Eq '^VAR=.+'`, which
// matches every one of those shapes — the quote characters, the `#`, the lone
// CR are all `.+` — and so reported "already configured" for an entry that
// configures nothing.
//
// The consequence is the one that function's own header comment exists to
// prevent. An operator following docs/OPERATIONS.md §3 exports
// CULVERT_SESSION_SECRET and runs the installer; `sudo docker compose` does not
// forward the host environment, so the value must be persisted into
// $INSTALL_DIR/.env or it never reaches the container. With an empty entry
// already in .env the installer declined to persist it, compose interpolated
// ${CULVERT_SESSION_SECRET:-} to "", and every node fell back to its own random
// per-process signing key (session.InitRandomKey, session.go) instead of the
// shared cluster key — admin sessions silently stop validating across nodes,
// with no error and no log line. (The fallback is a fresh random 32-byte key,
// so this is a cluster-availability failure, not a weak-key one.)
//
// The fix routes both callers through one predicate, env_file_value_set, so the
// two cannot drift again. An EMPTY entry is not a key to protect, so it is
// overwritten; a non-empty one is still never touched, and an UNREADABLE .env
// still leaves the file alone rather than overwriting a key it could not read.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// installSharedEnvPredicate returns env_file_value_set, the shared "is VAR
// non-empty in this file?" predicate that both secret_already_set and
// persist_host_env_session_secret delegate to. Every test that assembles
// either of those functions out of scripts/install.sh must include it.
func installSharedEnvPredicate(t *testing.T) string {
	t.Helper()
	return extractShellFunction(t, "scripts/install.sh", "env_file_value_set")
}

const testSessionSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestInstallScript_PersistHostEnvSessionSecret_EmptyEntryIsReplaced is the
// regression table: every shape docker compose resolves to empty must be
// treated as absent, so the host-environment key is persisted over it.
func TestInstallScript_PersistHostEnvSessionSecret_EmptyEntryIsReplaced(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"no entry at all", "OTHER=x\n"},
		{"bare empty", "CULVERT_SESSION_SECRET=\n"},
		{"empty double quotes", "CULVERT_SESSION_SECRET=\"\"\n"},
		{"empty single quotes", "CULVERT_SESSION_SECRET=''\n"},
		{"whitespace only", "CULVERT_SESSION_SECRET=   \n"},
		{"empty CRLF", "CULVERT_SESSION_SECRET=\r\n"},
		{"empty with inline comment", "CULVERT_SESSION_SECRET= # not set yet\n"},
		{"empty quotes with inline comment", "CULVERT_SESSION_SECRET=\"\" # not set yet\n"},
		{"commented out", "# CULVERT_SESSION_SECRET=deadbeef\n"},
		{"empty before another set var", "CULVERT_SESSION_SECRET=\r\nCULVERT_CA_PASSPHRASE=abcdef123456\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			out, code, env := runPersistHostEnvSessionSecret(t, dir,
				`export CULVERT_SESSION_SECRET=`+testSessionSecret)
			if code != 0 {
				t.Fatalf("exit %d, want 0\n%s", code, out)
			}
			if !strings.Contains(env, "CULVERT_SESSION_SECRET="+testSessionSecret) {
				t.Errorf("the operator's shared signing key was not persisted over an entry that\n"+
					"docker compose resolves to the empty string — every node would fall back to its own\n"+
					"random key.\n.env before: %q\n.env after: %q", tc.content, env)
			}
		})
	}
}

// TestInstallScript_PersistHostEnvSessionSecret_NonEmptyEntryIsNeverTouched is
// the never-overwrite control. It must keep holding for every spelling of a
// real value, including the multiline and inline-comment forms the shared
// predicate accepts, because overwriting one of these invalidates every admin
// session in the cluster.
func TestInstallScript_PersistHostEnvSessionSecret_NonEmptyEntryIsNeverTouched(t *testing.T) {
	existing := strings.Repeat("f", 64)
	cases := []struct {
		name    string
		content string
	}{
		{"plain value", "CULVERT_SESSION_SECRET=" + existing + "\n"},
		{"double-quoted value", "CULVERT_SESSION_SECRET=\"" + existing + "\"\n"},
		{"single-quoted value", "CULVERT_SESSION_SECRET='" + existing + "'\n"},
		{"CRLF value", "CULVERT_SESSION_SECRET=" + existing + "\r\n"},
		{"value with inline comment", "CULVERT_SESSION_SECRET=\"" + existing + "\" # shared\n"},
		{"multiline double-quoted value", "CULVERT_SESSION_SECRET=\"\n" + existing + "\n\"\n"},
		{"multiline single-quoted value", "CULVERT_SESSION_SECRET='\n" + existing + "\n'\n"},
		{"set after an empty unrelated var", "CULVERT_CA_PASSPHRASE=\r\nCULVERT_SESSION_SECRET=" + existing + "\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			out, code, env := runPersistHostEnvSessionSecret(t, dir,
				`export CULVERT_SESSION_SECRET=`+testSessionSecret)
			if code != 0 {
				t.Fatalf("exit %d, want 0\n%s", code, out)
			}
			if env != tc.content {
				t.Errorf("an existing non-empty signing key was modified — this invalidates every "+
					"admin session in the cluster.\nbefore: %q\nafter: %q", tc.content, env)
			}
			if strings.Contains(env, testSessionSecret) {
				t.Errorf("the host-environment value overwrote a configured key: %q", env)
			}
		})
	}
}

// TestInstallScript_EnvFileValueSet_ReportsUnreadableSeparately pins the third
// exit code the session-secret path depends on. "Could not read" must not
// collapse into "no entry, safe to add": that is what turns an unreadable
// root-owned .env into an overwritten signing key.
func TestInstallScript_EnvFileValueSet_ReportsUnreadableSeparately(t *testing.T) {
	fn := installSharedEnvPredicate(t)
	dir := t.TempDir()
	envfile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envfile, []byte("CULVERT_SESSION_SECRET="+strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	empty := filepath.Join(dir, "empty.env")
	if err := os.WriteFile(empty, []byte("CULVERT_SESSION_SECRET=\"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		file string
		want int
	}{
		{"set", envfile, 0},
		{"present but empty", empty, 1},
		{"unreadable or absent file", filepath.Join(dir, "missing.env"), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// `|| rc=$?` under `set -e`, exactly as the caller reads it.
			script := "set -euo pipefail\n" + fn +
				"\nrc=0\nenv_file_value_set CULVERT_SESSION_SECRET \"$1\" || rc=$?\nexit \"$rc\"\n"
			cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "bash", tc.file) // #nosec G204 -- fixed test script
			out, err := cmd.CombinedOutput()
			got := 0
			if err != nil {
				ee, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatalf("script failed to run: %v\n%s", err, out)
				}
				got = ee.ExitCode()
			}
			if got != tc.want {
				t.Fatalf("env_file_value_set exit = %d, want %d (output %q)", got, tc.want, out)
			}
		})
	}
}
