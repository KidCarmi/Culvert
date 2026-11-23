package runner

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const readImageID = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// readRunner answers `compose ps` with ps (psErr makes it exit non-zero) and
// every inspect with readImageID; it records every argv.
func readRunner(t *testing.T, ps string, psErr bool) (r *Runner, calls *[][]string) {
	t.Helper()
	r, err := New(Options{ComposeProjectDir: "/srv/culvert", ComposeFile: "docker-compose.yml", StageTimeout: 5 * time.Second,
		EnvAllow: []string{EnvCulvertBackupPassphrase}, EnvOverlayOnly: []string{EnvCulvertBackupPassphrase}, DockerBinary: "/usr/bin/docker"})
	if err != nil {
		t.Fatal(err)
	}
	var seen [][]string
	r.SetExecHooksForTest(func(cmd *exec.Cmd) error {
		seen = append(seen, append([]string(nil), cmd.Args...))
		args := strings.Join(cmd.Args, " ")
		switch {
		case strings.Contains(args, " ps "):
			_, _ = cmd.Stdout.Write([]byte(ps))
		case strings.Contains(args, "{{json .Image}}"):
			_, _ = cmd.Stdout.Write([]byte(`"` + readImageID + `"`))
		case strings.Contains(args, "image inspect"):
			_, _ = cmd.Stdout.Write([]byte(`[{"Id":"` + readImageID + `","RepoDigests":["r.example/x@sha256:` + strings.Repeat("d", 64) + `"]}]`))
		}
		return nil
	}, func(cmd *exec.Cmd) error {
		if psErr && strings.Contains(strings.Join(cmd.Args, " "), " ps ") {
			return errors.New("Cannot connect to the Docker daemon")
		}
		return nil
	})
	return r, &seen
}

// TestReadProxyContainer_TellsDaemonDownFromNoContainer: a failed `compose ps`
// is an error (Docker unreadable); an empty or proxy-less listing is a fact
// (no container). Capture conflates the two; the reconcile must not.
func TestReadProxyContainer_TellsDaemonDownFromNoContainer(t *testing.T) {
	ctx := context.Background()
	{
		r, _ := readRunner(t, "", true)
		if pc, err := r.ReadProxyContainer(ctx); err == nil {
			t.Errorf("daemon down: got %+v, want an error", pc)
		}
	}
	for name, ps := range map[string]string{
		"empty":    "",
		"no proxy": `{"Service":"db","State":"running","ID":"aaaaaaaaaaaa"}`,
		"array":    `[]`,
	} {
		r, _ := readRunner(t, ps, false)
		pc, err := r.ReadProxyContainer(ctx)
		if err != nil || pc.Present {
			t.Errorf("%s: got %+v err=%v, want Present=false and no error", name, pc, err)
		}
	}
	r, _ := readRunner(t, `{"Service":"proxy","State":"running","ID":"aaaaaaaaaaaa"}`+"\n"+`{"Service":"proxy","State":"running","ID":"bbbbbbbbbbbb"}`, false)
	if _, err := r.ReadProxyContainer(ctx); err == nil {
		t.Error("two proxy containers must be an error, not a guess")
	}
}

// TestReadProxyContainer_StateAndIdentity: the container's state is read, not
// assumed; a container that is not running is reported as such.
func TestReadProxyContainer_StateAndIdentity(t *testing.T) {
	ctx := context.Background()
	for state, running := range map[string]bool{"running": true, "restarting": false, "exited": false} {
		r, calls := readRunner(t, `{"Service":"proxy","State":"`+state+`","ID":"aaaaaaaaaaaa"}`, false)
		pc, err := r.ReadProxyContainer(ctx)
		if err != nil || !pc.Present || pc.Running != running || pc.ImageID != readImageID || len(pc.RepoDigests) != 1 {
			t.Errorf("%s: got %+v err=%v", state, pc, err)
		}
		for _, argv := range *calls {
			for _, a := range argv {
				if a == "tag" || a == "up" || a == "pull" || a == "down" {
					t.Errorf("a read issued a state-changing command: %v", argv)
				}
			}
		}
	}
}

// TestLocalImageID_ReadsTheRefAndNeverPulls: the id comes from `docker image
// inspect <ref>`; an unshaped ref never reaches argv.
func TestLocalImageID_ReadsTheRefAndNeverPulls(t *testing.T) {
	r, calls := readRunner(t, "", false)
	ref := "ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("e", 64)
	id, err := r.LocalImageID(context.Background(), ref)
	if err != nil || id != readImageID {
		t.Fatalf("got %q err=%v", id, err)
	}
	if last := (*calls)[len(*calls)-1]; last[len(last)-1] != ref || !strings.Contains(strings.Join(last, " "), "image inspect") {
		t.Errorf("argv = %v", last)
	}
	if _, err := r.LocalImageID(context.Background(), "bad ref; rm -rf /"); err == nil {
		t.Error("an unshaped ref was accepted")
	}
}
