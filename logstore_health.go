package main

// logstore_health.go — CHAOS-57: observability for the request-history store's
// open outcome.
//
// The history store is the second BadgerDB on the data volume, and until this
// change it was the one that could still kill the process: a corrupt `.sst`
// panics out of a goroutine badger spawns, and this store is opened both at
// boot (replaying the durable `LogStoreEnabled` admin setting) and at RUNTIME
// from `POST /api/logs/retention`. internal/logstore/resilient.go now stops the
// death; this file is the other half, because a degradation nobody can see is
// the failure mode the register's §1 theme is about.
//
// Surfaces, all of which already exist so no new operator vocabulary is
// introduced:
//
//   - `/api/diagnostics` — the `history_store` operator-contract row.
//   - `/metrics` — culvert_logstore_recovered / _quarantines_total /
//     _quarantined_copies.
//   - alerts — the existing `state_file_corrupt` event (CHAOS-05/07), which
//     already means "corrupt state was quarantined and there is evidence on
//     disk to reconcile". A second event name for the same operator action
//     would be drift, and — because Store.HasSubscriber matches names exactly —
//     a new name would arrive unsubscribed on every webhook already configured.
//   - the audit log, for a quarantine only. This is the one place this file
//     diverges from its catdb sibling (catfeeddb_health.go), and deliberately:
//     that store is a re-downloadable cache, whereas resetting the searchable
//     request history is an evidence-affecting act. It belongs in the record
//     that already carries `logstore.purge` and `logstore.cleanup`.
//
// Deliberately NOT wired into /readyz. History is an enhancement over the
// in-memory ring and over the durable request-log JSONL; a node without it
// serves traffic identically to one started with history switched off, so
// failing readiness would pull a healthy gateway out of rotation over a
// degraded index.
//
// One deliberate improvement on the catdb precedent: the residual-copy count is
// read LIVE off the disk rather than snapshotted at open. catdb's store opens
// once per boot, so a snapshot is the only thing available there; this store
// can be opened and closed repeatedly by an admin, and a snapshot would leave
// the contract row warning until the next restart even after the operator had
// already reclaimed the disk. Keying the row on evidence that is still present
// is the same rule ca_health.go follows for its persistence warning: report the
// degraded STATE, never a cumulative counter that can no longer clear.

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/logstore"
)

// logStoreQuarantines counts damaged history stores this process has moved
// aside. Cumulative and monotonic — it is the alerting signal ("did this ever
// happen?"), which is exactly why it must NOT be what the contract row keys on.
var logStoreQuarantines atomic.Int64

// logStoreOpenHealth is the record of the most recent open attempt. Written on
// every enable and read by the diagnostics and metrics surfaces, so it is
// mutex-guarded rather than atomic-per-field: readers need a consistent view.
type logStoreOpenHealth struct {
	// Attempted is false until an enable has been tried in this process (the
	// store is off and nothing is known about the directory).
	Attempted bool
	// Path is the store directory the attempt used.
	Path string
	// Recovered is true when the most recent attempt moved a damaged store
	// aside. It describes THAT attempt, not the lifetime of the process — the
	// lifetime signal is logStoreQuarantines plus the residual copies on disk.
	Recovered bool
	// QuarantinePath is where the damaged copy was moved to.
	QuarantinePath string
	// Failure is the operator-facing reason the most recent attempt failed,
	// empty when it succeeded.
	Failure string
}

var (
	logStoreOpenMu     sync.RWMutex
	logStoreOpenRecord logStoreOpenHealth
)

// noteLogStoreOpen records one open attempt and raises the operator-facing
// surfaces for it. Called from enableLogStore for BOTH the boot path and the
// admin-API path, because the fault it reports is reachable from both.
//
// The outcome is reported ONCE, after it is known. A quarantine that succeeded
// followed by a replacement that would not open (the volume went full or
// read-only in between) is a FAILURE, not a recovery: reporting the quarantine
// first would queue "re-created empty" and then contradict it.
func noteLogStoreOpen(path string, rec logstore.Recovery, openErr error) {
	h := logStoreOpenHealth{
		Attempted:      true,
		Path:           path,
		Recovered:      rec.Quarantined,
		QuarantinePath: rec.QuarantinePath,
	}
	if openErr != nil {
		h.Failure = openErr.Error()
	}
	if rec.Quarantined {
		logStoreQuarantines.Add(1)
	}

	logStoreOpenMu.Lock()
	logStoreOpenRecord = h
	logStoreOpenMu.Unlock()

	reportLogStoreOpen(path, rec, openErr)
}

// logStoreOpenState returns a copy of the recorded outcome.
func logStoreOpenState() logStoreOpenHealth {
	logStoreOpenMu.RLock()
	defer logStoreOpenMu.RUnlock()
	return logStoreOpenRecord
}

// resetLogStoreHealthForTest clears the record and the counter. Test isolation
// only — both are process-global.
func resetLogStoreHealthForTest() {
	logStoreOpenMu.Lock()
	logStoreOpenRecord = logStoreOpenHealth{}
	logStoreOpenMu.Unlock()
	logStoreQuarantines.Store(0)
}

// logStoreResidualQuarantines counts `.corrupt.*` copies of the history store
// still on the volume. Read live (a single glob) so the signal clears as soon
// as the operator reclaims the disk — see the file header.
func logStoreResidualQuarantines() int {
	if logStoreDir == "" {
		return 0
	}
	return len(logstore.QuarantinedCopies(logStoreDir))
}

// reportLogStoreOpen emits the log line, the alert and the audit event for one
// open attempt.
//
// A recovery that was TRIGGERED but skipped, on a store that then opened fine,
// is log-only. The commonest reason to skip is a live lock holder — a
// concurrent open — where alerting would page somebody about a benign race.
// Alert on evidence or on impact, never on a suspicion that resolved itself.
func reportLogStoreOpen(path string, rec logstore.Recovery, openErr error) {
	switch {
	case openErr != nil:
		reportLogStoreUnavailable(path, rec, openErr)
	case rec.Quarantined:
		detail := fmt.Sprintf("request-history store at %s was damaged (%s: %s) — quarantined to %s and re-created empty. Saved history is reset; the durable request log (JSONL) is unaffected. Delete the quarantined copy once reconciled to reclaim disk",
			path, rec.Trigger, rec.Cause, rec.QuarantinePath)
		logger.Printf("LogStore: %q", sanitizeLog(detail))
		deferStartupAlert("state_file_corrupt", AlertPayload{Source: "storage", Detail: detail})
		// Audited because resetting searchable history is an evidence-affecting
		// act, unlike the community category cache its sibling recovers.
		auditSystem("logstore.quarantine", "history", detail)
	case rec.Trigger != logstore.TriggerNone:
		logger.Printf("LogStore: %q", sanitizeLog(fmt.Sprintf(
			"request-history store at %s looked damaged (%s: %s) but was NOT quarantined (%s); it opened normally",
			path, rec.Trigger, rec.Cause, rec.Skipped)))
	}
}

// reportLogStoreUnavailable emits the SINGLE alert for a store that did not come
// up, folding in the quarantine (or the reason one was not attempted) so the
// operator gets one coherent account instead of two that disagree.
func reportLogStoreUnavailable(path string, rec logstore.Recovery, openErr error) {
	recoveryNote := ""
	switch {
	case rec.Quarantined:
		recoveryNote = fmt.Sprintf(" A damaged copy was quarantined to %s first, so the failure is with the REPLACEMENT store — check the volume for space, permissions, and mount state.", rec.QuarantinePath)
	case rec.Trigger != logstore.TriggerNone:
		recoveryNote = fmt.Sprintf(" It looked damaged (%s) but could not be quarantined (%s).", rec.Trigger, rec.Skipped)
	}
	detail := fmt.Sprintf("request-history store at %s could not be opened (%v) — saved history is off; the in-memory ring and the durable request log (JSONL) are unaffected.%s",
		path, openErr, recoveryNote)
	logger.Printf("LogStore: %q", sanitizeLog(detail))
	deferStartupAlert("state_file_corrupt", AlertPayload{Source: "storage", Detail: detail})
}

// checkHistoryStore is the `history_store` operator-contract row.
//
// Severity policy:
//   - the last enable failed → warn, never fail. History is an enhancement;
//     a fail row here would report a fully-serving gateway as broken.
//   - quarantined copies still present → warn, worded differently depending on
//     whether THIS process did the quarantining. The gateway is serving
//     correctly; the operator has evidence to inspect and disk to reclaim.
//   - anything else → ok, reporting whether a store is actually published.
//
// **Every warn is keyed on evidence that is still on disk**, never on the fact
// that a recovery once happened. A recovery always leaves a copy behind, so
// nothing is lost by keying on the copy — and it is what lets the row clear the
// moment the operator does what OperatorAction asked, with no restart and no
// history toggle. Keying the recovered branch on the historical flag instead
// (as the first draft did) left the row warning after the copies were gone,
// claiming "0 quarantined copy/copies on disk" and contradicting its own
// advice. Same rule as ca_health.go's persistence warning: report the degraded
// STATE, never a latch that can no longer clear.
func checkHistoryStore() OperatorContractCheck {
	h := logStoreOpenState()
	residual := logStoreResidualQuarantines()

	if h.Attempted && h.Failure != "" {
		return OperatorContractCheck{
			Code:           "history_store",
			Status:         diagWarn,
			Message:        "request-history store unavailable — saved-log search is off; the in-memory ring and the durable request log are unaffected",
			OperatorAction: "Check the data volume for the history store (space, permissions, mount). If the passphrase changed, purge saved logs and enable history again. See server logs for the cause.",
		}
	}
	if residual > 0 {
		if h.Recovered {
			return OperatorContractCheck{
				Code:   "history_store",
				Status: diagWarn,
				Message: fmt.Sprintf("request-history store was damaged and re-created (%d quarantined copy/copies on disk); saved history was reset, the durable request log is unaffected",
					residual),
				OperatorAction: "Confirm the data volume is healthy, then delete the quarantined .corrupt.* copy to reclaim disk.",
			}
		}
		return OperatorContractCheck{
			Code:   "history_store",
			Status: diagWarn,
			Message: fmt.Sprintf("request-history store is healthy, but %d quarantined copy/copies from an earlier incident remain on disk",
				residual),
			OperatorAction: "Delete the quarantined .corrupt.* copy of the request-history store to reclaim disk.",
		}
	}
	// "Open" is a claim about right now, so it is read from the published
	// store rather than from the fact that an enable was once attempted —
	// otherwise every disable (a runtime toggle, or persisted admin settings
	// switching off a YAML-seeded store) left the row insisting history was
	// still open.
	if globalLogStore.Load() == nil {
		return OperatorContractCheck{
			Code:    "history_store",
			Status:  diagOK,
			Message: "request-history store not enabled",
		}
	}
	return OperatorContractCheck{
		Code:    "history_store",
		Status:  diagOK,
		Message: "request-history store open",
	}
}
