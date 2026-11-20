package main

// install_script_env_put_privileged_create_test.go — env_put's privileged
// create of a missing .env (the stack-dir-not-writable branch) must never
// clobber a file that appeared after its existence check.
//
// Two installers can both see .env absent and both reach that branch before
// either takes the transaction lock. The first can create and fill .env; the
// second's privileged create then runs against an existing file. The old
// `sudo touch` left it alone. A create that copies over the destination (for
// example `install … /dev/null "$file"`) wipes the first installer's secrets,
// with both calls succeeding and no warning (SEC-INSTALL-ENVUMASK-1).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript_EnvPut_PrivilegedCreateDoesNotClobberAConcurrentWriter(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "env_put")
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	mark := filepath.Join(dir, "dirname.mark")
	// The lock already exists and is ours, so only the .env create needs sudo.
	if err := os.WriteFile(envFile+".lock", nil, 0o600); err != nil {
		t.Fatalf("seed lock: %v", err)
	}

	// dirname: the FIRST call is the stack-dir writability check, which a
	// root test process would always pass. Answer it with a path that is not
	// writable for anyone, so the privileged-create branch runs whatever the
	// test's uid; every later call is the real dirname.
	//
	// sudo: runs the command as-is, but first plays the concurrent installer
	// that won the race — it creates .env and writes its secret into it, after
	// env_put's existence check and before env_put's own create.
	prelude := `dirname() { if [[ ! -e '` + mark + `' ]]; then : > '` + mark + `'; echo /nonexistent-unwritable-stack-dir; return 0; fi; command dirname "$@"; }
sudo() { if [[ "$1" != chown ]]; then printf 'RACER_SECRET=from-the-other-installer\n' > '` + envFile + `'; fi; "$@"; }`

	out, err := runEnvPutProcessWith(t, prelude, "", fn, envFile, "CULVERT_INSTALL_CHANNEL", "lts")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mark); err != nil {
		t.Fatalf("the privileged-create branch never ran (dirname stub unused): %v\noutput:\n%s", err, out)
	}
	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	if !strings.Contains(string(got), "RACER_SECRET=from-the-other-installer\n") {
		t.Fatalf("the privileged create clobbered a .env another installer had just written; .env now:\n%s\noutput:\n%s", got, out)
	}
	if !strings.Contains(string(got), "CULVERT_INSTALL_CHANNEL=lts\n") {
		t.Fatalf("env_put did not record its own value; .env now:\n%s\noutput:\n%s", got, out)
	}
}
