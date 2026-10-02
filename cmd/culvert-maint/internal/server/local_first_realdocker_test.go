// Real-docker proof of the local-first rollback floor (RISK-022 PR-E §4).
//
// Opt-in ONLY (CULVERT_MAINT_REAL_DOCKER=1): it needs a working docker daemon
// and the registry:2 image. It pushes a tiny image to a throwaway local
// registry, pulls it back BY DIGEST (so the local store records the exact
// repo@sha256 RepoDigest), STOPS the registry, and proves through the REAL
// *runner.Runner (real exec, the exact argv the sudoers wildcard admits):
//
//   - imagePresentLocally(ref) is true while the image is local;
//   - ComposePullDigest(ref) now FAILS (registry down);
//   - the shared rollback_pull stage therefore SKIPS the pull and succeeds;
//   - after `docker rmi`, imagePresentLocally is false and the stage falls
//     back to the pull, which fails — i.e. the pre-change behaviour when the
//     image is genuinely absent.
package server

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/runner"
)

func TestRealDocker_LocalFirstRollbackSurvivesRegistryOutage(t *testing.T) {
	if os.Getenv("CULVERT_MAINT_REAL_DOCKER") != "1" {
		t.Skip("set CULVERT_MAINT_REAL_DOCKER=1 to run against a real daemon")
	}
	dk := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() //nolint:gosec // test-only, fixed args
		return string(out), err
	}
	const (
		regName = "culvert-maint-proof-registry"
		repoRef = "127.0.0.1:5055/culvert-proof/proxy"
	)
	_, _ = dk("rm", "-f", regName)
	if out, err := dk("run", "-d", "--name", regName, "-p", "127.0.0.1:5055:5000", "registry:2"); err != nil {
		t.Fatalf("start registry: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = dk("rm", "-f", regName); _, _ = dk("rmi", "-f", repoRef+":t") })
	// A tiny image: one layer from a tar of a single file.
	tmp := t.TempDir()
	tarPath := tmp + "/rootfs.tar"
	if err := os.WriteFile(tmp+"/hello", []byte("proof\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(context.Background(), "tar", "-cf", tarPath, "-C", tmp, "hello").CombinedOutput(); err != nil { //nolint:gosec // test-only, temp paths
		t.Fatalf("tar: %v\n%s", err, out)
	}
	if out, err := dk("import", tarPath, repoRef+":t"); err != nil {
		t.Fatalf("import: %v\n%s", err, out)
	}
	// Wait for the registry to accept pushes.
	var pushOut string
	var pushErr error
	for i := 0; i < 20; i++ {
		pushOut, pushErr = dk("push", repoRef+":t")
		if pushErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if pushErr != nil {
		t.Fatalf("push: %v\n%s", pushErr, pushOut)
	}
	m := regexp.MustCompile(`digest: (sha256:[0-9a-f]{64})`).FindStringSubmatch(pushOut)
	if m == nil {
		t.Fatalf("no digest in push output:\n%s", pushOut)
	}
	ref := repoRef + "@" + m[1]
	// Drop the local copy and pull it back BY DIGEST so the local store records
	// exactly the repo@sha256 RepoDigest a rollback target carries.
	if out, err := dk("rmi", "-f", repoRef+":t"); err != nil {
		t.Fatalf("rmi: %v\n%s", err, out)
	}
	if out, err := dk("pull", ref); err != nil {
		t.Fatalf("pull by digest: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = dk("rmi", "-f", ref) })

	// Same shape as main.newRunner (the inspect template explicitly unsets the
	// backup passphrase, so the name must be in the closed allowlist).
	rn, err := runner.New(runner.Options{
		ComposeProjectDir: tmp, ComposeFile: "docker-compose.yml", StageTimeout: 60 * time.Second, ProxyRepo: repoRef,
		EnvAllow: []string{runner.EnvCulvertBackupPassphrase}, EnvOverlayOnly: []string{runner.EnvCulvertBackupPassphrase},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{opts: Options{Runner: rn}}
	ctx := context.Background()
	if !srv.imagePresentLocally(ctx, ref) {
		res, ierr := rn.ComposeImageInspect(ctx, ref)
		var stdout, stderr string
		if res != nil {
			stdout, stderr = string(res.Stdout), string(res.Stderr)
		}
		t.Fatalf("image pulled by digest must be present locally: %s; runner err=%v stdout=%q stderr=%q", ref, ierr, stdout, stderr)
	}

	// Registry outage.
	if out, err := dk("stop", regName); err != nil {
		t.Fatalf("stop registry: %v\n%s", err, out)
	}
	if _, perr := rn.ComposePullDigest(ctx, ref); perr == nil {
		t.Fatal("control: the pull must FAIL with the registry down")
	}
	acc := &rollbackAccumulator{}
	out, _, serr := srv.rollbackPull(func() string { return ref }, acc)(ctx)
	if serr != nil || !strings.Contains(string(out), "skipped (image present locally)") || !acc.pullSkippedLocal {
		t.Fatalf("rollback_pull must skip the dead registry when the image is local: err=%v out=%s", serr, out)
	}

	// Absent image ⇒ falls back to the pull, which fails (pre-change behaviour).
	if o, rerr := dk("rmi", "-f", ref); rerr != nil {
		t.Fatalf("rmi: %v\n%s", rerr, o)
	}
	if srv.imagePresentLocally(ctx, ref) {
		t.Fatal("removed image must not be reported present")
	}
	if _, _, serr = srv.rollbackPull(func() string { return ref }, &rollbackAccumulator{})(ctx); serr == nil {
		t.Fatal("absent image + dead registry must fail the pull stage")
	}
	t.Logf("PROOF: %s present-locally → pull skipped with registry stopped; absent → pull attempted and failed", ref)
}
