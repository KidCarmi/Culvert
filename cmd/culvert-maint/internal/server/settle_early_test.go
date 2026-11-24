package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/journal"
)

// earlyRig: an agent that has just started after a predecessor that left a
// compose command unfinished, with a settle window far longer than the test.
func earlyRig(t *testing.T) *reconRig {
	t.Helper()
	r := newReconRig(t, true)
	r.srv.opts.Cfg.InterruptedSettle = 30 * time.Second
	r.srv.startedAt = time.Now()
	r.srv.startHazard = true
	r.srv.startOnlyUp = true // the marker found at start named only `compose up`
	r.srv.settlePoll = 40 * time.Millisecond
	return r
}

// settleWithin runs the wait under a deadline and reports whether it returned
// on its own (true) or was still waiting when the deadline came (false).
func settleWithin(t *testing.T, r *reconRig, d time.Duration) (note string, returned bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	n, err := r.srv.settleInterrupted(ctx)
	return string(n), err == nil
}

// TestSettleEarly_NoProxyContainerEndsTheWait: the proxy is down. A container
// stop can only be pending on a running container, so two reads that list no
// proxy container establish that nothing is pending, and the wait ends there
// instead of prolonging the outage by the rest of the window.
func TestSettleEarly_NoProxyContainerEndsTheWait(t *testing.T) {
	r := earlyRig(t)
	r.world.running = ""
	began := time.Now()
	note, returned := settleWithin(t, r, 5*time.Second)
	if !returned {
		t.Fatal("the wait did not end although no proxy container was running")
	}
	if took := time.Since(began); took < r.srv.settlePoll {
		t.Errorf("ended after %v: two reads one poll (%v) apart are required", took, r.srv.settlePoll)
	}
	if !strings.Contains(note, "no proxy container is running") {
		t.Errorf("the note does not say why the wait ended early: %q", note)
	}
	if rem := r.srv.settleRemaining(); rem > 0 {
		t.Errorf("after the early end: remaining = %v, want none (established once, for this start)", rem)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("the wait made mutating calls: %v", c)
	}
}

// TestSettleEarly_RunningProxyWaitsTheWindow: a running proxy container may be
// the one dockerd is stopping (Docker says `running` until the process is
// gone). That is ambiguous, and ambiguity waits.
func TestSettleEarly_RunningProxyWaitsTheWindow(t *testing.T) {
	r := earlyRig(t)
	if _, returned := settleWithin(t, r, 600*time.Millisecond); returned {
		t.Fatal("the wait ended early with a proxy container running")
	}
	if r.srv.startSettled.Load() {
		t.Error("the start hazard was marked settled")
	}
}

// TestSettleEarly_DockerUnreadableWaitsTheWindow: no answer is not "no
// container".
func TestSettleEarly_DockerUnreadableWaitsTheWindow(t *testing.T) {
	r := earlyRig(t)
	r.world.running = ""
	r.world.down = true
	if _, returned := settleWithin(t, r, 600*time.Millisecond); returned {
		t.Fatal("the wait ended early although Docker could not be read")
	}
}

// TestSettleEarly_OneQuietReadIsNotEnough: a container that a request still in
// flight starts between the reads must be seen. The first read lists nothing,
// every later one lists a running proxy: the wait must go on.
func TestSettleEarly_OneQuietReadIsNotEnough(t *testing.T) {
	r := earlyRig(t)
	r.world.running = ""
	r.world.onPS = func(n int) {
		if n == 1 { // after the first read was issued, the container appears
			go func() {
				r.world.mu.Lock()
				r.world.running = cfgOld
				r.world.mu.Unlock()
			}()
		}
	}
	if _, returned := settleWithin(t, r, 600*time.Millisecond); returned {
		t.Fatal("the wait ended on a single quiet read")
	}
}

// TestSettleEarly_QuietReadsMustBeConsecutive: no proxy, then a proxy, then no
// proxy again is two quiet reads that are not consecutive. Something started a
// container in between; the count starts over.
func TestSettleEarly_QuietReadsMustBeConsecutive(t *testing.T) {
	r := earlyRig(t)
	r.srv.settlePoll = 150 * time.Millisecond
	r.world.running = ""
	r.world.onPS = func(n int) {
		r.world.mu.Lock()
		defer r.world.mu.Unlock()
		switch n {
		case 2:
			r.world.running = cfgOld // the second read lists a proxy
		case 3:
			r.world.running = "" // the third lists none again
		case 4:
			r.world.running = cfgOld // and from the fourth on one is running
		}
	}
	// Reads 1 (quiet), 2 (listed), 3 (quiet) happen within ~300ms; a count
	// that was not reset would end the wait at read 3.
	if _, returned := settleWithin(t, r, 700*time.Millisecond); returned {
		t.Fatal("the wait ended on two quiet reads that were not consecutive")
	}
}

// TestSettleEarly_NotAfterACutCommandOfThisProcess: when a compose command of
// THIS process ended in an error, its CLI may still be alive behind sudo and
// send further requests. "No container right now" proves nothing then; the
// window is waited out.
func TestSettleEarly_NotAfterACutCommandOfThisProcess(t *testing.T) {
	r := earlyRig(t)
	r.world.running = ""
	r.srv.noteMutationCut()
	if _, returned := settleWithin(t, r, 600*time.Millisecond); returned {
		t.Fatal("the wait ended early inside the window of a cut command of this process")
	}
}

// TestSettleEarly_NotAfterAComposeDown: a `compose down` stops every service
// of the project. "No proxy container" says nothing about a stop still pending
// on another one, so a marker that names a down (or names nothing readable, or
// no marker at all: first use, a journal record alone) is never ended early.
func TestSettleEarly_NotAfterAComposeDown(t *testing.T) {
	r := earlyRig(t)
	r.world.running = ""
	r.srv.startOnlyUp = false
	if _, returned := settleWithin(t, r, 600*time.Millisecond); returned {
		t.Fatal("the wait ended early although the predecessor's unfinished command was not known to be only `compose up`")
	}
}

// TestSettle_UnreadableJournalIsAHazard: doubt counts as yes.
func TestSettle_UnreadableJournalIsAHazard(t *testing.T) {
	r := earlyRig(t)
	r.srv.startHazard = false
	if err := os.WriteFile(filepath.Join(r.jnl.Dir(), testOpULID+".json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rem := r.srv.settleRemaining(); rem < 25*time.Second {
		t.Errorf("with an unreadable journal: remaining = %v, want about the whole window", rem)
	}
}

// TestSettle_InterruptedRecordIsAHazardWithoutAMarker: belt and braces. An
// interrupted journal record opens the window even when no marker was found
// (an agent version that wrote none ran in between).
func TestSettle_InterruptedRecordIsAHazardWithoutAMarker(t *testing.T) {
	r := earlyRig(t)
	r.srv.startHazard = false
	if rem := r.srv.settleRemaining(); rem != 0 {
		t.Fatalf("precondition: remaining = %v with no marker and no record", rem)
	}
	now := time.Now().UTC()
	_ = now
	r.seed(t, journal.PhaseRestarting, nil) // even without the best-effort interrupted_at mark
	if rem := r.srv.settleRemaining(); rem < 25*time.Second {
		t.Errorf("with an interrupted record: remaining = %v, want about the whole window", rem)
	}
}
