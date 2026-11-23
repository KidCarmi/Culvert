package server

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

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
	r.srv.startedAt = time.Now().Add(-time.Hour) // the first-use window is long over
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

// TestMutation_ALaterSuccessDoesNotClearAnOpenWindow: a restore whose `compose
// down` was cut goes straight on to `compose up`. That `up` finds the proxy
// still running (dockerd is still stopping it), changes nothing and exits 0.
// The marker must survive it, name the down, and make the next agent start
// wait; otherwise the next start would be told nothing was left unfinished.
func TestMutation_ALaterSuccessDoesNotClearAnOpenWindow(t *testing.T) {
	r := newReconRig(t, true)
	r.srv.opts.Cfg.InterruptedSettle = 30 * time.Second
	r.srv.startedAt = time.Now().Add(-time.Hour)
	if _, err := r.srv.composeUp(context.Background()); err != nil { // clears the first-use marker
		t.Fatalf("up: %v", err)
	}
	dir := r.srv.opts.StateDir
	if markerPending(t, dir) {
		t.Fatal("precondition: the state directory should be clean")
	}

	r.world.down = true
	if _, err := r.srv.composeDown(context.Background()); err == nil {
		t.Fatal("precondition: `down` should fail")
	}
	r.world.down = false
	if _, err := r.srv.composeUp(context.Background()); err != nil {
		t.Fatalf("up: %v", err)
	}

	_, at, err := journal.OpenMutationLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !at.Pending {
		t.Fatal("the successful `up` removed the marker of the cut `down` inside its settle window")
	}
	if at.OnlyUp {
		t.Error("the marker no longer names the `compose down`: the next start could end its wait early")
	}
	if !r.srv.mutations.Pending() {
		t.Error("the marker is not reported as pending in this process")
	}
}

// TestMutation_NeverClearedAfterACutInThisProcess: a compose command of this
// process that was cut may still be alive behind sudo long after any window,
// and send its stop then. Only the next agent start ends it. So however long
// ago the cut was, this process leaves the marker for its successor.
func TestMutation_NeverClearedAfterACutInThisProcess(t *testing.T) {
	r := newReconRig(t, true)
	r.srv.opts.Cfg.InterruptedSettle = 30 * time.Second
	r.srv.startedAt = time.Now().Add(-time.Hour)
	r.world.down = true
	if _, err := r.srv.composeUp(context.Background()); err == nil {
		t.Fatal("precondition: `up` should fail")
	}
	r.world.down = false
	long := time.Now().Add(-time.Hour)
	r.srv.mutationCutAt.Store(&long) // the in-process window is long over
	if rem := r.srv.settleRemaining(); rem > 0 {
		t.Fatalf("precondition: remaining = %v", rem)
	}
	if _, err := r.srv.composeUp(context.Background()); err != nil {
		t.Fatalf("up: %v", err)
	}
	if !markerPending(t, r.srv.opts.StateDir) {
		t.Fatal("a process that had a cut compose command cleared the marker")
	}
}

// TestMutation_SuccessInsideThePredecessorsWindowKeepsTheMarker: the window
// opened by what the previous process left (not by a cut of this one) also
// keeps a success from clearing the marker; once that window is over, a
// success clears it. And the question is asked when the command STARTS: a
// command that outlasts the window does not clear what it could not vouch for.
func TestMutation_SuccessInsideThePredecessorsWindowKeepsTheMarker(t *testing.T) {
	r := newReconRig(t, true) // first use: an "unknown" marker, hazard open
	r.srv.opts.Cfg.InterruptedSettle = 400 * time.Millisecond
	r.srv.startedAt = time.Now()
	dir := r.srv.opts.StateDir

	// Starts inside the window, returns after it.
	r.world.onUp = func() { time.Sleep(600 * time.Millisecond) }
	if _, err := r.srv.composeUp(context.Background()); err != nil {
		t.Fatalf("up: %v", err)
	}
	if !markerPending(t, dir) {
		t.Fatal("a success that started inside the predecessor's window cleared the marker")
	}
	r.world.onUp = nil
	if _, err := r.srv.composeUp(context.Background()); err != nil {
		t.Fatalf("up: %v", err)
	}
	if markerPending(t, dir) {
		t.Fatal("a success that started after the window did not clear the marker")
	}
}

// TestMutation_ZeroSettleStillKeepsHonestMarkers: interrupted_settle = "0s"
// turns the wait off, not the bookkeeping. A cut `down` followed at once by a
// successful `up` must leave the marker, so that turning the wait back on
// later does not start from a lie.
func TestMutation_ZeroSettleStillKeepsHonestMarkers(t *testing.T) {
	r := newReconRig(t, true)
	r.srv.opts.Cfg.InterruptedSettle = 0
	r.srv.startedAt = time.Now().Add(-time.Hour)
	r.world.down = true
	if _, err := r.srv.composeDown(context.Background()); err == nil {
		t.Fatal("precondition: `down` should fail")
	}
	r.world.down = false
	if _, err := r.srv.composeUp(context.Background()); err != nil {
		t.Fatalf("up: %v", err)
	}
	if !markerPending(t, r.srv.opts.StateDir) {
		t.Fatal("with the wait off, a success right after a cut cleared the marker")
	}
}

// TestMutation_NewWiresWhatTheMarkerSaid: the server acts on what the marker
// on disk named, not on a default. A marker naming a `compose down` must not
// allow the early end; one naming only `compose up` does, and arms the retry.
func TestMutation_NewWiresWhatTheMarkerSaid(t *testing.T) {
	for _, tc := range []struct {
		cmds   []string
		onlyUp bool
	}{
		{[]string{journal.MutationComposeUp}, true},
		{[]string{journal.MutationComposeDown, journal.MutationComposeUp}, false},
	} {
		r := newReconRig(t, true)
		dir := r.srv.opts.StateDir
		ml, _, err := journal.OpenMutationLog(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := ml.End(); err != nil {
			t.Fatal(err)
		}
		for _, c := range tc.cmds {
			if err := ml.Begin(c); err != nil {
				t.Fatal(err)
			}
		}
		opts := r.srv.opts
		srv, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		if !srv.startHazard || srv.startOnlyUp != tc.onlyUp || !srv.startMarkerLive.Load() {
			t.Errorf("marker %v: startHazard=%v startOnlyUp=%v startMarkerLive=%v, want true/%v/true",
				tc.cmds, srv.startHazard, srv.startOnlyUp, srv.startMarkerLive.Load(), tc.onlyUp)
		}
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
