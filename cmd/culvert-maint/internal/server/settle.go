// Waiting out what a dead agent left running in dockerd.
//
// When the agent dies, the shipped unit's control-group kill guarantees that
// no docker command it started is still alive when the next agent starts
// (packaging/systemd/culvert-maint.service). It guarantees nothing about
// dockerd, which finishes the last request it was sent. A tag is done in
// milliseconds. A container stop is not: it lasts as long as the proxy takes
// to exit, up to its stop_grace_period, and during that time the container is
// `running`, serves, and — for every image that answers /ready while it
// drains — passes a health gate.
//
// Measured on real Docker: an upgrade killed while Compose was stopping the
// old proxy; a rollback started six seconds later found that container
// running on the right image, changed nothing, passed its health gate,
// reported success and retired the record; the container then exited.
//
// So the rule: nothing tags and recreates, and nothing is called converged,
// while a stop the previous agent process requested can still be pending.
//
// The bound is counted from THIS process's start, not from a journal record.
// Every request of the previous process was sent before this one started, and
// Docker bounds a stop by the container's stop timeout, so start +
// interrupted_settle is a time after which no such request is left. Tying the
// bound to records would miss the stops that leave none behind or leave one
// of another class: `compose down` in a restore (not journaled) or a data
// rollback, and the `up` of a startup reconcile killed in mid-flight. It would
// also depend on a best-effort journal write having succeeded.
//
// The same applies inside one process when a `compose up` / `compose down` it
// ran ends in an error (noteMutationCut): the window starts again from there.
//
// The window applies after a start only when the previous process may have
// left such a command unfinished: it writes a durable marker before every
// compose up/down and removes it only on a success with nothing earlier in
// doubt (mutation.go, markerMayBeCleared, journal.MutationLog). And it is
// ended early when Docker shows that no stop can be pending and the marker
// names only `compose up` (settleInterrupted). Whenever either is in doubt,
// the whole window is waited out.
//
// Waiting BEFORE `tag` + `up` means `up` sees the container as the stale stop
// left it and starts or recreates it, and the health gate that follows judges
// a container no outstanding request can touch.
package server

import (
	"context"
	"fmt"
	"time"
)

// settleRemaining returns how long is left until no request an earlier compose
// up/down left in dockerd can still be pending. Zero or negative: nothing to
// wait for. time.Since uses the monotonic clock, so a wall-clock step in
// either direction changes nothing.
//
// Two things can start the window:
//
//   - the previous agent process may have left such a command unfinished
//     (startHazardOpen): counted from this process's start;
//   - a compose up/down of this process ended in an error: counted from then.
func (s *Server) settleRemaining() time.Duration {
	window := s.opts.Cfg.InterruptedSettle
	if window <= 0 {
		return 0
	}
	var from time.Time
	if s.startHazardOpen() {
		from = s.startedAt
	}
	if cut := s.mutationCutAt.Load(); cut != nil && cut.After(from) {
		from = *cut
	}
	if from.IsZero() {
		return 0
	}
	return window - time.Since(from)
}

// startHazardOpen reports whether the previous agent process may have left a
// compose up/down unfinished, and Docker has not yet shown that it is over.
//
// The durable marker (journal.MutationLog) answers the first part: it is on
// disk before such a command starts and is removed only by a success with
// nothing earlier in doubt. No marker at start means there is no stop for
// dockerd to be finishing, and the ordinary restart (package upgrade, reboot, a
// clean stop) pays no wait. The first start that keeps markers finds the
// "unknown" one it has just written.
//
// One addition keeps doubt on the waiting side: a journal record that no
// running operation owns, or a journal that cannot be read, is a hazard
// whatever the marker says. It costs nothing when the marker agrees and covers
// a marker lost to an agent version change in between.
func (s *Server) startHazardOpen() bool {
	if s.startSettled.Load() {
		return false
	}
	return s.startHazard || s.staleRecordOrUnreadable()
}

// noteMutationCut records that a `compose up` or `compose down` of THIS
// process ended in an error. The same hazard as a dead predecessor, inside one
// process: the docker command may have been killed (stage timeout, the unit
// being stopped, the OOM killer) after it asked dockerd to stop the proxy, and
// dockerd carries on. Whatever tags and recreates next — the upgrade's own
// inline rollback first of all — must not judge that container until the
// window has passed again.
//
// Every error counts, not only a kill: a docker CLI that handles SIGTERM exits
// with an ordinary status, so the two cannot be told apart from here. The cost
// is that a rollback after a failed `up` starts one window later.
func (s *Server) noteMutationCut() {
	now := time.Now()
	s.mutationCutAt.Store(&now)
	s.everCut.Store(true)
}

// clearWindow is the window used to decide whether a marker may be removed. It
// is never zero: interrupted_settle = "0s" turns the WAIT off (lab), not the
// bookkeeping, so that turning the wait back on later finds honest markers.
func (s *Server) clearWindow() time.Duration {
	if w := s.opts.Cfg.InterruptedSettle; w > 0 {
		return w
	}
	return defaultClearWindow
}

// defaultClearWindow mirrors the shipped interrupted_settle default.
const defaultClearWindow = 75 * time.Second

// markerMayBeCleared reports, for a compose command about to start, whether
// its success may remove the marker. Both must hold:
//
//   - no compose up/down of this process has ever ended in an error. A CLI
//     that was cut through sudo may outlive any window and send its stop
//     later; only the next agent start, whose unit kills the control group,
//     ends that. So such a process leaves its marker for its successor.
//   - whatever the previous process left is over: there was nothing, or Docker
//     showed so (early advance), or the window since this start has passed.
func (s *Server) markerMayBeCleared() bool {
	if s.everCut.Load() {
		return false
	}
	if !s.startHazardOpen() {
		return true
	}
	return time.Since(s.startedAt) >= s.clearWindow()
}

// defaultSettlePoll is how often Docker is asked, while waiting, whether the
// stop is over.
const defaultSettlePoll = 2 * time.Second

// settleQuietReads is how many consecutive reads must show no proxy container
// before the wait is ended early. Two, one poll apart: a container that a
// request still in flight is about to start shows up on the second read.
const settleQuietReads = 2

// settleInterrupted blocks until nothing an earlier compose up/down left in
// dockerd can still be pending, and returns a note for the operation log (nil
// when it did not have to wait). It fails only if ctx ends first: the caller
// then fails without having tagged or recreated anything.
//
// It ends in one of two ways.
//
// Established: `compose ps` lists no proxy container on two consecutive reads.
// A stop can only be pending on a running container, so with none running the
// stop is over, and whatever `up` starts next is not a container a stale
// request named. This is the case that matters: the proxy is down, and the
// wait would only prolong the outage.
//
// Fallback: the window runs out. That is the answer whenever a proxy container
// is running (it may be the one being stopped: Docker reports `running` until
// the process is gone) or Docker cannot be read.
//
// The early end applies only to what the PREVIOUS PROCESS left. Its docker
// commands are dead before this process starts (the unit's control-group kill,
// TestShippedUnit_CrashFence), so only single requests are left in dockerd. A
// command of this process that ended in an error is different: if it was
// killed through sudo, the CLI itself may still be running and send further
// requests, and "no container right now" proves nothing. Then the window is
// waited out as before.
func (s *Server) settleInterrupted(ctx context.Context) ([]byte, error) {
	total := s.settleRemaining()
	if total <= 0 {
		return nil, nil
	}
	began := time.Now()
	quiet := 0
	for {
		wait := s.settleRemaining()
		if wait <= 0 {
			return []byte(fmt.Sprintf("settle: waited %s before tag+up (a container stop left in dockerd by an interrupted compose command may still have been pending; interrupted_settle=%s)\n",
				time.Since(began).Round(time.Millisecond), s.opts.Cfg.InterruptedSettle)), nil
		}
		if s.onlyPredecessorPending() {
			if listed, err := s.proxyListed(ctx); err == nil && !listed {
				quiet++
			} else {
				quiet = 0
			}
			if quiet >= settleQuietReads {
				s.startSettled.Store(true)
				return []byte(fmt.Sprintf("settle: no proxy container is running (%d reads, %s apart), so no container stop is pending; went on after %s instead of interrupted_settle=%s\n",
					settleQuietReads, s.settlePoll, time.Since(began).Round(time.Millisecond), s.opts.Cfg.InterruptedSettle)), nil
			}
		}
		step := s.settlePoll
		if step <= 0 || wait < step {
			step = wait
		}
		t := time.NewTimer(step)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return nil, fmt.Errorf("settle: gave up waiting for the settle window (interrupted_settle=%s): %w", s.opts.Cfg.InterruptedSettle, ctx.Err())
		}
	}
}

// proxyListed is one read of Docker, bounded so that a `compose ps` that hangs
// cannot hold the wait past its window.
func (s *Server) proxyListed(ctx context.Context) (bool, error) {
	budget := 10 * time.Second
	if rem := s.settleRemaining(); rem > 0 && rem < budget {
		budget = rem
	}
	rctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return s.opts.Runner.ProxyContainerListed(rctx)
}

// onlyPredecessorPending reports whether the wait may be ended early: the
// window in effect comes from the previous process alone, and what that
// process left unfinished is known to be nothing but `compose up`.
//
//   - A marker was actually found and read at start, and it names only
//     `compose up`. A `compose down` stops every service of the project, and
//     "no proxy container" says nothing about a stop still pending on another
//     one. An `up` stops only a container it is replacing, and the `up` that
//     follows the wait replaces that same container anyway. A hazard that
//     rests on first use, on an unreadable marker or on a journal record alone
//     names no command, so it is never ended early.
//   - No compose up/down of this process ended in an error within the window.
func (s *Server) onlyPredecessorPending() bool {
	if s.opts.Runner == nil || !s.startOnlyUp || !s.startHazardOpen() {
		return false
	}
	cut := s.mutationCutAt.Load()
	return cut == nil || time.Since(*cut) >= s.opts.Cfg.InterruptedSettle
}
