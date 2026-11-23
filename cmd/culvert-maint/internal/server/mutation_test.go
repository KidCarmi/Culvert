package server

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"culvert-maint/internal/journal"
)

func markerPending(t *testing.T, stateDir string) bool {
	t.Helper()
	_, at, err := journal.OpenMutationLog(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	return at.Pending
}

// TestMutation_MarkerLifecycle: the marker is gone after a compose command
// that returned success and stays after one that returned an error (it may
// have been killed after it asked dockerd to stop the proxy; a docker CLI that
// handles SIGTERM exits with an ordinary error status).
func TestMutation_MarkerLifecycle(t *testing.T) {
	r := newReconRig(t, true)
	dir := r.srv.opts.StateDir
	if _, err := r.srv.composeUp(context.Background()); err != nil {
		t.Fatalf("up: %v", err)
	}
	if markerPending(t, dir) {
		t.Error("a marker is left after `up` returned success")
	}
	if r.srv.mutationCutAt.Load() != nil {
		t.Error("a successful `up` was recorded as cut")
	}

	r.world.down = true
	if _, err := r.srv.composeDown(context.Background()); err == nil {
		t.Fatal("precondition: `down` should fail with Docker down")
	}
	if !markerPending(t, dir) {
		t.Error("no marker is left after `down` ended in an error")
	}
	if r.srv.mutationCutAt.Load() == nil {
		t.Error("a failed `down` did not restart the in-process window")
	}
}

// TestMutation_NoMarkerNoCommand: record before effect. If the marker cannot
// be written, the command is not run.
func TestMutation_NoMarkerNoCommand(t *testing.T) {
	r := newReconRig(t, true)
	mdir := filepath.Join(r.srv.opts.StateDir, "mutation")
	if err := os.RemoveAll(mdir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mdir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.srv.composeUp(context.Background()); err == nil {
		t.Fatal("`up` ran although its marker could not be written")
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("docker was called without a marker: %v", c)
	}
}

// TestMutation_OnlyTheWrappersRunComposeUpDown: every `compose up` / `compose
// down` of the server goes through composeUp / composeDown, or a command could
// be in flight with no marker and the next start would not wait for it.
func TestMutation_OnlyTheWrappersRunComposeUpDown(t *testing.T) {
	direct := regexp.MustCompile(`Runner\.Compose(Up|Down)\(`)
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files found: %v", err)
	}
	seenWrapper := false
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(f) // #nosec G304 -- file names from a fixed glob in the package directory
		if rerr != nil {
			t.Fatal(rerr)
		}
		n := len(direct.FindAll(src, -1))
		if f == "mutation.go" {
			seenWrapper = n == 2
			continue
		}
		if n != 0 {
			t.Errorf("%s calls Runner.ComposeUp/ComposeDown directly (%d); use s.composeUp / s.composeDown", f, n)
		}
	}
	if !seenWrapper {
		t.Error("mutation.go no longer holds exactly the two wrapped calls; this test would pass vacuously")
	}
}
