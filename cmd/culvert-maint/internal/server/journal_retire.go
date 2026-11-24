// Retiring journal records that a later, successful image change has made
// obsolete.
//
// A record left by an interrupted operation is kept across restarts on
// purpose: it is the only durable sign that the fixed tag may be on an image
// that never passed the health gate. It stops being true the moment a later
// operation re-pins the tag, recreates the proxy and passes the health gate
// and the digest verification — the tag and the container are then both on a
// known image, whatever the earlier operation left behind. From then on the
// record is not merely useless but wrong: every start would report a failure
// that has been dealt with, and a reconciler reading it would compare today's
// Docker against a "prior" image from an upgrade long since replaced.
//
// So the success of such an operation retires every OTHER record, each with
// an audit entry. Nothing else removes an interrupted record; there is no
// timer and no automatic expiry.
//
// A restore is the second, narrower retirer (ADR-0061 addendum, 2026-11-24).
// A restore-class operation — restore.commit, or rollbacks.create mode=data —
// that committed and passed its health check has put the data directory in a
// known state with the proxy serving on it: its commit command first undoes any
// earlier restore that never committed, and the proxy started on the result.
// The record of an EARLIER interrupted restore then describes a data state that
// no longer exists, and it is retired the same way: audit entry first, then the
// record. It retires restore-class records ONLY. A restore moves no image tag,
// so it establishes nothing about what an interrupted upgrade or image rollback
// left behind, and such a record outlives any number of restores.
package server

import (
	"errors"
	"log"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// auditKindSuperseded is the audit sub-action recorded against an interrupted
// operation when a later operation retires its journal record.
const auditKindSuperseded = ":interrupted_superseded"

// resultFnRetiringInterrupted wraps the op's result computer so that, when the
// op is one that establishes a new health-gated image state and it succeeded,
// stale journal records are retired BEFORE the op becomes terminal — a caller
// that sees "succeeded" then also sees the journal already drained. Returns
// cfg.resultFn unchanged for every other op.
func (s *Server) resultFnRetiringInterrupted(opID, actor string, cfg *startCfg) ops.ResultFn {
	if (cfg.retiresInterrupted == nil && cfg.retiresRestoreRecords == nil) || s.opts.Journal == nil {
		return cfg.resultFn
	}
	inner := cfg.resultFn
	establishes, restored := cfg.retiresInterrupted, cfg.retiresRestoreRecords
	return func(state ops.State, reason ops.FailureReason) map[string]interface{} {
		var result map[string]interface{}
		if inner != nil {
			result = inner(state, reason)
		}
		if state != ops.StateSucceeded {
			return result
		}
		var retired []string
		switch {
		case establishes != nil && establishes():
			retired = s.retireSupersededRecords(opID, actor)
		case restored != nil && restored():
			retired = s.retireSupersededRestoreRecords(opID, actor)
		}
		if len(retired) > 0 {
			if result == nil {
				result = map[string]interface{}{}
			}
			ids := make([]interface{}, len(retired))
			for i, id := range retired {
				ids[i] = id
			}
			result["superseded_interrupted_ops"] = ids
		}
		return result
	}
}

// retireSupersededRecords removes every journal record other than byOpID's own
// and returns the op ids retired. A record is removed only after its audit
// entry has been written, so a record never disappears without a trace; on any
// failure it is left in place and reported again at the next start. An
// unreadable journal retires nothing.
func (s *Server) retireSupersededRecords(byOpID, actor string) []string {
	return s.retireRecords(byOpID, actor, "an image change", func(*journal.Record) bool { return true })
}

// retireSupersededRestoreRecords is retireSupersededRecords for a restore that
// committed and passed its health check: it retires the records of earlier
// interrupted restore-class operations and no other. The kind and mode are read
// from the record as written; a record whose kind this build does not know is
// not a restore record and is kept.
func (s *Server) retireSupersededRestoreRecords(byOpID, actor string) []string {
	return s.retireRecords(byOpID, actor, "a restore", func(rec *journal.Record) bool {
		return isRestoreRecord(rec.Kind, rec.Mode)
	})
}

// retireRecords retires every record retire accepts, other than byOpID's own.
// what names the retiring operation's class in the log.
func (s *Server) retireRecords(byOpID, actor, what string, retire func(*journal.Record) bool) []string {
	recs, err := s.opts.Journal.List()
	if err != nil {
		// The error can quote a corrupt record; classify it, do not print it.
		reason := "read error"
		if errors.Is(err, journal.ErrCorruptRecord) {
			reason = "corrupt record"
		}
		log.Printf("culvert-maint: WARN: journal not readable (%s) after %s succeeded; interrupted records kept", reason, what)
		return nil
	}
	var retired []string
	for i := range recs {
		rec := &recs[i]
		// The succeeding op's own record is retired by the orchestrator. A
		// record whose op is running in this process is not stale (cannot
		// happen while the maintenance lock admits one op at a time).
		// A record a newer agent wrote is never retired here (ADR-0062): the
		// journal refuses to remove it, and auditing it as superseded first
		// would record a retirement that did not happen.
		if rec.OpID == byOpID || s.opts.Ops.IsRunning(rec.OpID) || rec.FromNewerAgent() || !retire(rec) {
			continue
		}
		now := time.Now().UTC()
		desc := DescribeInterrupted(rec, s.opts.Cfg.ProxyRepo)
		params := desc.AuditParams()
		params["superseded_by"] = byOpID
		if werr := s.opts.Audit.Write(audit.Event{
			Actor:     actor,
			OpID:      rec.OpID,
			Kind:      desc.Kind + auditKindSuperseded,
			Params:    params,
			Outcome:   audit.OutcomeSucceeded,
			OutcomeAt: &now,
		}); werr != nil {
			log.Printf("culvert-maint: WARN: could not audit the retirement of interrupted op %s; record kept: %v", rec.OpID, werr)
			continue
		}
		if rerr := s.opts.Journal.Remove(rec.OpID); rerr != nil {
			log.Printf("culvert-maint: WARN: could not remove the journal record of interrupted op %s: %v", rec.OpID, rerr)
			continue
		}
		retired = append(retired, rec.OpID)
	}
	return retired
}
