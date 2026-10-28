package main

// install_script_env_file_value_set_export_test.go — docker compose's dotenv
// parser accepts an optional `export ` prefix and leading blanks before a
// KEY=VALUE line. env_file_value_set() must agree, or setup_at_rest_encryption()
// believes an operator-supplied passphrase is absent, generates a second one and
// appends it; compose then resolves the LAST entry, so the CA key encrypted with
// the original passphrase can no longer be decrypted.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript_EnvFileValueSet_ExportPrefixAndIndent(t *testing.T) {
	fn := installSharedEnvPredicate(t)
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"export prefix", "export CULVERT_CA_PASSPHRASE=abcdef123456\n", true},
		{"export prefix quoted", "export CULVERT_CA_PASSPHRASE=\"abcdef123456\"\n", true},
		{"leading spaces", "  CULVERT_CA_PASSPHRASE=abcdef123456\n", true},
		{"leading tab", "\tCULVERT_CA_PASSPHRASE=abcdef123456\n", true},
		{"export empty", "export CULVERT_CA_PASSPHRASE=\n", false},
		{"export empty quotes", "export CULVERT_CA_PASSPHRASE=\"\"\n", false},
		{"commented export", "# export CULVERT_CA_PASSPHRASE=abcdef123456\n", false},
		{"different var with export", "export XCULVERT_CA_PASSPHRASE=abcdef123456\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := envFileValueSetVerdict(t, fn, tc.content); got != tc.want {
				t.Fatalf("env_file_value_set(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

// envFileValueSetVerdict runs the real env_file_value_set (fn) for
// CULVERT_CA_PASSPHRASE against a .env holding content and reports exit 0.
func envFileValueSetVerdict(t *testing.T, fn, content string) bool {
	t.Helper()
	envfile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envfile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fn + "\nenv_file_value_set CULVERT_CA_PASSPHRASE \"$1\"\n"
	err := exec.CommandContext(t.Context(), "bash", "-c", script, "bash", envfile).Run() // #nosec G204 -- fixed test script
	return err == nil
}

// The CA-reuse branch of setup_at_rest_encryption() must read the log
// passphrase in every form env_file_value_set() accepts; otherwise the branch is
// entered but finds no value and leaves CULVERT_CA_PASSPHRASE unset, so the
// proxy persists the CA key unencrypted.
func TestInstallScript_SetupAtRestEncryption_ReuseBranchReadsExportedLogPassphrase(t *testing.T) {
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := installSharedEnvPredicate(t) + "\n" + extractShellFunction(t, "scripts/install.sh", "secret_already_set")

	for _, line := range []string{
		"export CULVERT_LOG_PASSPHRASE=already-set-log-passphrase-1234",
		"  CULVERT_LOG_PASSPHRASE=already-set-log-passphrase-1234",
	} {
		t.Run(line, func(t *testing.T) {
			dir := t.TempDir()
			envFile := filepath.Join(dir, ".env")
			if err := os.WriteFile(envFile, []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			stubs := "info() { :; }\nwarn() { :; }\nerror() { echo \"ERROR: $*\" >&2; exit 7; }\n" +
				"is_fresh_deployment() { return 0; }\nunset CULVERT_LOG_PASSPHRASE CULVERT_CA_PASSPHRASE\nINSTALL_DIR=" + dir + "\n"
			script := stubs + secretFn + "\n" + envPutFn + "\n" + setupFn + "\nsetup_at_rest_encryption\n"
			cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script
			cmd.Stdin = bytes.NewReader(nil)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("setup_at_rest_encryption failed: %v\n%s", err, out)
			}
			got, _ := os.ReadFile(envFile)
			if !strings.Contains(string(got), "CULVERT_CA_PASSPHRASE=already-set-log-passphrase-1234") {
				t.Fatalf("CA passphrase not derived from the existing log passphrase; .env:\n%s", got)
			}
		})
	}
}

// composeResolvedEnvValue returns what docker compose resolves for key from a
// .env body: the LAST `[blanks][export ]key=` line wins, and one matching pair
// of surrounding quotes is removed. ok is false when no line assigns key.
func composeResolvedEnvValue(envContent, key string) (val string, ok bool) {
	for _, line := range strings.Split(envContent, "\n") {
		s := strings.TrimLeft(line, " \t")
		if rest, found := strings.CutPrefix(s, "export"); found && rest != strings.TrimLeft(rest, " \t") {
			s = strings.TrimLeft(rest, " \t")
		}
		if v, found := strings.CutPrefix(s, key+"="); found {
			val, ok = v, true
		}
	}
	if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
		val = val[1 : len(val)-1]
	}
	return val, ok
}

// Compose keeps the LAST assignment of a key. Matching the first non-empty
// line instead let `export CULVERT_CA_PASSPHRASE=x` followed by
// `CULVERT_CA_PASSPHRASE=` read as configured, so the installer never repaired
// the value and the CA key was written with an empty passphrase. Before the
// export form was accepted, that file read as unset and was regenerated.
func TestInstallScript_EnvFileValueSet_LastAssignmentWins(t *testing.T) {
	fn := installSharedEnvPredicate(t)
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"export set then plain empty", "export CULVERT_CA_PASSPHRASE=abcdef123456\nCULVERT_CA_PASSPHRASE=\n", false},
		{"plain set then export quoted empty", "CULVERT_CA_PASSPHRASE=abcdef123456\nexport CULVERT_CA_PASSPHRASE=\"\"\n", false},
		{"indented set then indented empty", "  CULVERT_CA_PASSPHRASE=abcdef123456\n\tCULVERT_CA_PASSPHRASE=''\n", false},
		{"plain set then plain empty", "CULVERT_CA_PASSPHRASE=abcdef123456\nCULVERT_CA_PASSPHRASE=\n", false},
		{"export empty then plain set", "export CULVERT_CA_PASSPHRASE=\"\"\nCULVERT_CA_PASSPHRASE=abcdef123456\n", true},
		{"set then commented empty", "export CULVERT_CA_PASSPHRASE=abcdef123456\n# CULVERT_CA_PASSPHRASE=\n", true},
		{"set then other key empty", "export CULVERT_CA_PASSPHRASE=abcdef123456\nCULVERT_LOG_PASSPHRASE=\n", true},
		{"set then prefixed key empty", "CULVERT_CA_PASSPHRASE=abcdef123456\nXCULVERT_CA_PASSPHRASE=\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := envFileValueSetVerdict(t, fn, tc.content); got != tc.want {
				t.Fatalf("env_file_value_set(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

// End to end for the case above: a fresh install whose .env ends in an empty
// CA assignment must leave a non-empty CA passphrase as the last assignment.
func TestInstallScript_SetupAtRestEncryption_TrailingEmptyCAAssignmentIsRegenerated(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"),
		[]byte("export CULVERT_CA_PASSPHRASE=operator-ca-passphrase-1\nCULVERT_CA_PASSPHRASE=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	genFn := extractShellFunction(t, "scripts/install.sh", "gen_passphrase")
	out, code, env := runSetupAtRestEncryptionWithHostEnv(t, dir,
		"unset CULVERT_LOG_PASSPHRASE CULVERT_CA_PASSPHRASE\n"+genFn)
	if code != 0 {
		t.Fatalf("setup_at_rest_encryption failed (exit %d):\n%s", code, out)
	}
	if ca, _ := composeResolvedEnvValue(env, "CULVERT_CA_PASSPHRASE"); len(ca) < 12 {
		t.Fatalf("compose resolves CULVERT_CA_PASSPHRASE to %q, so the CA key is stored unencrypted; .env:\n%s", ca, env)
	}
}

// A host-environment passphrase must be persisted over an .env entry that
// compose resolves to empty, in every assignment form env_file_value_set
// accepts. The guard's own `=.+` test counted `export VAR=""` as configured,
// so the empty entry stayed and the CA key lost its passphrase.
func TestInstallScript_SetupAtRestEncryption_HostPassphraseReplacesQuotedEmptyEntry(t *testing.T) {
	const hostPass = "host-supplied-passphrase-1234"
	cases := []struct {
		name, key, content string
	}{
		{"log export double", "CULVERT_LOG_PASSPHRASE", "export CULVERT_LOG_PASSPHRASE=\"\"\n"},
		{"log export single", "CULVERT_LOG_PASSPHRASE", "export CULVERT_LOG_PASSPHRASE=''\n"},
		{"log indented double", "CULVERT_LOG_PASSPHRASE", "  CULVERT_LOG_PASSPHRASE=\"\"\n"},
		{"log plain double", "CULVERT_LOG_PASSPHRASE", "CULVERT_LOG_PASSPHRASE=\"\"\n"},
		{"ca export double", "CULVERT_CA_PASSPHRASE", "export CULVERT_CA_PASSPHRASE=\"\"\n"},
		{"ca export single", "CULVERT_CA_PASSPHRASE", "export CULVERT_CA_PASSPHRASE=''\n"},
		{"ca indented double", "CULVERT_CA_PASSPHRASE", "\tCULVERT_CA_PASSPHRASE=\"\"\n"},
		{"ca plain double", "CULVERT_CA_PASSPHRASE", "CULVERT_CA_PASSPHRASE=\"\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			out, code, env := runSetupAtRestEncryptionWithHostEnv(t, dir,
				"unset CULVERT_LOG_PASSPHRASE CULVERT_CA_PASSPHRASE\nexport "+tc.key+"="+hostPass)
			if code != 0 {
				t.Fatalf("setup_at_rest_encryption failed (exit %d):\n%s", code, out)
			}
			if got, _ := composeResolvedEnvValue(env, tc.key); got != hostPass {
				t.Fatalf("compose resolves %s to %q, want the host value; .env:\n%s", tc.key, got, env)
			}
			if got, _ := composeResolvedEnvValue(env, "CULVERT_CA_PASSPHRASE"); got != hostPass {
				t.Fatalf("compose resolves CULVERT_CA_PASSPHRASE to %q, want %q; .env:\n%s", got, hostPass, env)
			}
		})
	}

	// Negative control: a non-empty on-disk value is never overwritten.
	for _, key := range []string{"CULVERT_LOG_PASSPHRASE", "CULVERT_CA_PASSPHRASE"} {
		t.Run("keeps on-disk "+key, func(t *testing.T) {
			dir := t.TempDir()
			const onDisk = "on-disk-passphrase-12345"
			if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("export "+key+"=\""+onDisk+"\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out, code, env := runSetupAtRestEncryptionWithHostEnv(t, dir,
				"unset CULVERT_LOG_PASSPHRASE CULVERT_CA_PASSPHRASE\nexport "+key+"="+hostPass)
			if code != 0 {
				t.Fatalf("setup_at_rest_encryption failed (exit %d):\n%s", code, out)
			}
			if got, _ := composeResolvedEnvValue(env, key); got != onDisk {
				t.Fatalf("compose resolves %s to %q, want the on-disk %q; .env:\n%s", key, got, onDisk, env)
			}
		})
	}
}

// The CA-reuse branch read a quoted log passphrase with its quote characters,
// so the charset guard rejected it and the CA passphrase stayed unset. One
// matching pair is stripped; anything the guard rejects inside it still
// leaves the CA passphrase unset.
func TestInstallScript_SetupAtRestEncryption_ReuseBranchStripsOneQuotePair(t *testing.T) {
	const quotedValue = "quoted-log-passphrase-1234"
	accepted := []string{
		"export CULVERT_LOG_PASSPHRASE=\"" + quotedValue + "\"",
		"export CULVERT_LOG_PASSPHRASE='" + quotedValue + "'",
		"  CULVERT_LOG_PASSPHRASE=\"" + quotedValue + "\"",
		"CULVERT_LOG_PASSPHRASE='" + quotedValue + "'",
		"export CULVERT_LOG_PASSPHRASE=" + quotedValue,
	}
	for _, line := range accepted {
		t.Run(line, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out, code, env := runSetupAtRestEncryptionWithHostEnv(t, dir, "unset CULVERT_LOG_PASSPHRASE CULVERT_CA_PASSPHRASE")
			if code != 0 {
				t.Fatalf("setup_at_rest_encryption failed (exit %d):\n%s", code, out)
			}
			if got, _ := composeResolvedEnvValue(env, "CULVERT_CA_PASSPHRASE"); got != quotedValue {
				t.Fatalf("compose resolves CULVERT_CA_PASSPHRASE to %q, want %q; .env:\n%s", got, quotedValue, env)
			}
		})
	}

	rejected := []string{
		"export CULVERT_LOG_PASSPHRASE=\"has-dollar-$HOME-1234\"",
		"export CULVERT_LOG_PASSPHRASE=\"back\\slash-passphrase-1234\"",
		"export CULVERT_LOG_PASSPHRASE=\"inner\"quote-passphrase-1234\"",
		"export CULVERT_LOG_PASSPHRASE=\"single'quote-passphrase-1234\"",
		"export CULVERT_LOG_PASSPHRASE='mismatched-quotes-1234\"",
	}
	for _, line := range rejected {
		t.Run(line, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out, code, env := runSetupAtRestEncryptionWithHostEnv(t, dir, "unset CULVERT_LOG_PASSPHRASE CULVERT_CA_PASSPHRASE")
			if code != 0 {
				t.Fatalf("setup_at_rest_encryption failed (exit %d):\n%s", code, out)
			}
			if ca, ok := composeResolvedEnvValue(env, "CULVERT_CA_PASSPHRASE"); ok {
				t.Fatalf("unsafe log passphrase was reused as CULVERT_CA_PASSPHRASE=%q; .env:\n%s", ca, env)
			}
		})
	}
}
