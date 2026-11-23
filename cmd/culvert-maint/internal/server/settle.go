// Waiting out what a dead operation left running in dockerd.
//
// A journal record found at startup is "an operation with no process behind
// it": the shipped unit's control-group kill guarantees no docker command of
// the dead agent is still alive (packaging/systemd/culvert-maint.service). It
// guarantees nothing about dockerd, which finishes the last request it was
// sent. A tag is done in milliseconds. A container stop is not: it lasts as
// long as the proxy takes to exit, up to its stop_grace_period, and during
// that time the container is `running`, serves, and — for every image that
// answers /ready while it drains — passes a health gate.
//
// Measured on real Docker: an upgrade killed while Compose was stopping the
// old proxy; a rollback started six seconds later found that container
// running on the right image, changed nothing, passed its health gate,
// reported success and retired the record; the container then exited.
//
// So the rule: nothing tags and recreates while a stop from an interrupted
// image change can still be pending. The record's InterruptedAt is no earlier
// than the moment the dead agent's last request was sent, and Docker bounds a
// stop by the container's stop timeout, so InterruptedAt + interrupted_settle
// is a time after which no such request is left. Waiting until then BEFORE
// `tag` + `up` means `up` sees the container as the stale stop left it and
// starts or recreates it, and the health gate that follows judges a container
// no outstanding request can touch.
package server

import (
	"context"
	"fmt"
	"time"
)

// settleDeadline returns the time after which no request from an interrupted
// image change can still be pending in dockerd, and the operation that sets
// it. The zero time means there is nothing to wait for.
//
// Only records startup marked count (InterruptedAt set, no operation of this
// process behind them), and only those whose journal phase says Docker may
// have been changed: an operation that stopped before the write-ahead barrier
// never reached `up`.
func (s *Server) settleDeadline(now time.Time) (deadline time.Time, opID string, err error) {
	window := s.opts.Cfg.InterruptedSettle
	if s.opts.Journal == nil || window <= 0 {
		return time.Time{}, "", nil
	}
	recs, err := s.opts.Journal.List()
	if err != nil {
		// What was interrupted, and when, is unknown. Assume the worst case
		// that is still bounded: something was interrupted just now.
		return now.Add(window), "", fmt.Errorf("journal unreadable")
	}
	for i := range recs {
		rec := &recs[i]
		if rec.InterruptedAt == nil || s.opts.Ops.IsRunning(rec.OpID) {
			continue
		}
		if DescribeInterrupted(rec, s.opts.Cfg.ProxyRepo).DockerState != DockerStateIndeterminate {
			continue
		}
		at := *rec.InterruptedAt
		if at.After(now) {
			at = now // the clock went back; never wait longer than one window
		}
		if d := at.Add(window); d.After(deadline) {
			deadline, opID = d, rec.OpID
		}
	}
	return deadline, opID, nil
}

// settleInterrupted blocks until settleDeadline has passed and returns a note
// for the operation log (nil when it did not have to wait). It fails only if
// ctx ends first: the stage then fails without having tagged or recreated
// anything.
func (s *Server) settleInterrupted(ctx context.Context) ([]byte, error) {
	now := time.Now()
	deadline, opID, lerr := s.settleDeadline(now)
	wait := deadline.Sub(now)
	if deadline.IsZero() || wait <= 0 {
		return nil, nil
	}
	why := "interrupted operation " + opID
	if lerr != nil {
		why = "the crash-recovery journal could not be read"
	}
	note := []byte(fmt.Sprintf("settle: waited %s before tag+up (%s; a container stop it left in dockerd may still be pending, interrupted_settle=%s)\n",
		wait.Round(time.Millisecond), why, s.opts.Cfg.InterruptedSettle))
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return note, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("settle: gave up waiting for %s: %w", why, ctx.Err())
	}
}
