package main

// install_script_docker_apt_key_rerun_test.go — the Debian/Ubuntu branch of
// scripts/install.sh must recover from a failed download of Docker's apt
// signing key on the next run.
//
// The branch fetched the key with
//
//	if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
//	  curl -fsSL .../gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
//
// `gpg --dearmor -o FILE` creates FILE before it has read any input. When the
// download fails (DNS blip, proxy 5xx, connection reset — measured with GnuPG
// 2.4.4: empty or truncated input exits 2 and leaves a ZERO-byte FILE), the
// script aborts under `set -euo pipefail` and the empty keyring stays behind.
// Every later run then sees `-f` true, skips the download, writes docker.list
// with signed-by= pointing at the empty keyring, and dies on `apt-get update`
// ("NO_PUBKEY … The repository … is not signed"). A transient network failure
// became a permanently wedged installer until the operator found and deleted
// the file by hand.
//
// The tests run the real fragment against the real gpg, with curl shimmed.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// dockerAptKeyCurlShim fails like `curl -f` on a transport/HTTP error when
// $FIXTURE_CURL_FAIL is 1 (exit 22, nothing on stdout); otherwise it prints
// the armored key at $FIXTURE_KEY_ASC. Every call is appended to $CURL_LOG.
const dockerAptKeyCurlShim = `#!/bin/bash
echo "curl $*" >>"$CURL_LOG"
if [[ "$FIXTURE_CURL_FAIL" == 1 ]]; then
  echo "curl: (22) The requested URL returned error: 503" >&2
  exit 22
fi
cat "$FIXTURE_KEY_ASC"
`

type dockerAptKeyFixture struct {
	t        *testing.T
	harness  string
	dir      string
	keyring  string
	curlLog  string
	keyASC   string
	wantKey  []byte
	basePath string
}

func newDockerAptKeyFixture(t *testing.T) *dockerAptKeyFixture {
	t.Helper()
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed; this test measures the installer against the real gpg --dearmor")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	keyrings := filepath.Join(dir, "keyrings")
	gnupgHome := filepath.Join(dir, "gnupg")
	for _, d := range []string{bin, gnupgHome} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GNUPGHOME", gnupgHome)
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(dockerAptKeyCurlShim), 0o700); err != nil { //nolint:gosec // test-owned shim
		t.Fatal(err)
	}

	// An armored blob gpg --dearmor accepts; its payload is what a correct
	// keyring must contain byte for byte.
	want := []byte("culvert-test-docker-apt-key-payload")
	enarmor := exec.CommandContext(t.Context(), gpg, "--enarmor") //nolint:gosec // fixed argv
	enarmor.Stdin = bytes.NewReader(want)
	asc, err := enarmor.Output()
	if err != nil {
		t.Fatalf("gpg --enarmor: %v", err)
	}
	keyASC := filepath.Join(dir, "docker.asc")
	if err := os.WriteFile(keyASC, asc, 0o600); err != nil {
		t.Fatal(err)
	}

	// The key-install part of the `debian)` arm: from the keyrings directory
	// creation up to (not including) the docker.list line.
	body := extractShellLines(t, "scripts/install.sh",
		"sudo install -m 0755 -d /etc/apt/keyrings", `echo "deb [arch=`)
	body = strings.ReplaceAll(body, "/etc/apt/keyrings", keyrings)
	harness := "set -euo pipefail\nsudo() { \"$@\"; }\nerror() { echo \"ERR $*\" >&2; exit 1; }\n" +
		"DISTRO_ID=ubuntu\n" + body + "\necho FRAGMENT_OK\n"

	return &dockerAptKeyFixture{
		t: t, harness: harness, dir: dir,
		keyring:  filepath.Join(keyrings, "docker.gpg"),
		curlLog:  filepath.Join(dir, "curl.log"),
		keyASC:   keyASC,
		wantKey:  want,
		basePath: bin + string(os.PathListSeparator) + os.Getenv("PATH"),
	}
}

// run executes the fragment once and reports whether it ran to completion.
func (f *dockerAptKeyFixture) run(curlFails bool) (ok bool, out string) {
	f.t.Helper()
	fail := "0"
	if curlFails {
		fail = "1"
	}
	cmd := exec.CommandContext(f.t.Context(), "bash", "-c", f.harness) //nolint:gosec // fixed harness built from repo script
	cmd.Env = append(os.Environ(),
		"PATH="+f.basePath,
		"FIXTURE_CURL_FAIL="+fail,
		"FIXTURE_KEY_ASC="+f.keyASC,
		"CURL_LOG="+f.curlLog,
	)
	cmd.Stdin = nil // no tty: gpg must never be left waiting on an overwrite prompt
	b, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(string(b), "FRAGMENT_OK"), string(b)
}

func (f *dockerAptKeyFixture) assertKeyringValid(context string, out string) {
	f.t.Helper()
	got, err := os.ReadFile(f.keyring)
	if err != nil || !bytes.Equal(got, f.wantKey) {
		f.t.Fatalf("%s: Docker apt keyring is not the downloaded key (len %d, err %v); apt-get update "+
			"would fail with NO_PUBKEY on every run.\nfragment output:\n%s", context, len(got), err, out)
	}
	st, err := os.Stat(f.keyring)
	if err != nil {
		f.t.Fatal(err)
	}
	if st.Mode().Perm()&0o044 != 0o044 {
		f.t.Fatalf("%s: keyring mode %v is not world-readable; apt's _apt user could not read it", context, st.Mode().Perm())
	}
}

func TestInstallScript_DockerAptKey_RerunAfterFailedDownloadRecovers(t *testing.T) {
	f := newDockerAptKeyFixture(t)

	// Run 1: the key download fails. The install is expected to abort here.
	if ok, out := f.run(true); ok {
		t.Fatalf("fragment continued although the key download failed:\n%s", out)
	}
	// It must not leave a keyring behind that a later run would trust.
	if st, err := os.Stat(f.keyring); err == nil {
		t.Errorf("failed download left a %d-byte keyring at %s", st.Size(), f.keyring)
	}

	// Run 2: the network is back. The re-run must fetch and install the key.
	ok, out := f.run(false)
	if !ok {
		t.Fatalf("re-run aborted after the network recovered:\n%s", out)
	}
	f.assertKeyringValid("re-run after a failed download", out)
}

// A host already wedged by the earlier installer has the zero-byte keyring on
// disk; the fixed installer must heal it rather than require a manual delete.
func TestInstallScript_DockerAptKey_HealsEmptyKeyringFromEarlierRun(t *testing.T) {
	f := newDockerAptKeyFixture(t)
	if err := os.MkdirAll(filepath.Dir(f.keyring), 0o755); err != nil { //nolint:gosec // mirrors /etc/apt/keyrings
		t.Fatal(err)
	}
	if err := os.WriteFile(f.keyring, nil, 0o644); err != nil { //nolint:gosec // mirrors the leftover file
		t.Fatal(err)
	}
	ok, out := f.run(false)
	if !ok {
		t.Fatalf("install aborted on a leftover empty keyring:\n%s", out)
	}
	f.assertKeyringValid("leftover empty keyring", out)
}

// Negative control: a keyring that already holds a key is left exactly as it
// is and nothing is downloaded (the operator may have provisioned it offline).
func TestInstallScript_DockerAptKey_ExistingKeyringUntouched(t *testing.T) {
	f := newDockerAptKeyFixture(t)
	if err := os.MkdirAll(filepath.Dir(f.keyring), 0o755); err != nil { //nolint:gosec // mirrors /etc/apt/keyrings
		t.Fatal(err)
	}
	existing := []byte("operator-provisioned-keyring")
	if err := os.WriteFile(f.keyring, existing, 0o644); err != nil { //nolint:gosec // mirrors the real mode
		t.Fatal(err)
	}
	ok, out := f.run(true) // a download attempt would fail the fragment
	if !ok {
		t.Fatalf("fragment aborted although a keyring was already present:\n%s", out)
	}
	got, err := os.ReadFile(f.keyring)
	if err != nil || !bytes.Equal(got, existing) {
		t.Fatalf("existing keyring was modified (got %q, err %v)", got, err)
	}
	if calls, _ := os.ReadFile(f.curlLog); len(calls) != 0 {
		t.Fatalf("curl was called although a keyring was already present:\n%s", calls)
	}
}
