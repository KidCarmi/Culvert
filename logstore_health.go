package main

// logstore_health.go — CHAOS-57: observability for the request-history store's
// open outcome.
//
// The history store used to be able to kill this process: badger.Open panics
// from a goroutine it spawns on a corrupt table, so no recover() at the call
// site could contain it. Because the enable toggle is durable in
// admin_settings.json and re-applied on every boot, one damaged table turned
// into an unattended crash loop; because the toggle is also reachable from the
// live admin API, it could take down a gateway carrying production traffic the
// moment an admin flipped a switch. `logstore.OpenResilientTTL` degrades or
// self-heals instead, and this file is the other half of that change — a
// degradation nobody can see is the failure mode the register's §1 theme is
// about.
//
// Surfaces, all of which already exist so no new operator vocabulary is
// introduced:
//
//   - `/api/diagnostics` — the `request_history` operator-contract row.
//   - `/metrics` — culvert_logstore_available / _recovered /
//     _quarantined_copies, mirroring the culvert_catfeeddb_* triple.
//   - alerts — the existing `state_file_corrupt` event (CHAOS-05/07), which
//     already means "corrupt state quarantined, there is evidence on disk";
//     a second event name for the same operator action would be drift.
//   - logs.
//
// Deliberately NOT wired into /readyz. A node with history saving degraded is
// fully able to serve traffic — it is exactly the posture of a node that never
// had the toggle switched on — so failing readiness would take a healthy
// gateway out of a load-balancer rotation over a query convenience.
//
// Unlike the community category store, this record is NOT boot-only: the store
// can be enabled, disabled and re-enabled at runtime, so every transition
// rewrites it.

import (
	"fmt"
	"sync"

	"github.com/KidCarmi/Culvert/internal/storeguard"
)

// logStoreHealthRecord is the process-wide record of how the history store came
// up. Written on every lifecycle transition and read by the diagnostics +
// metrics surfaces, so it is mutex-guarded rather than atomic-per-field: the
// readers need a consistent view across all of it.
type logStoreHealthRecord struct {
	// SaveRequested is true when an open was ATTEMPTED for this path — a boot
	// applying the durable setting, or an admin turning the toggle on.
	//
	// It deliberately does NOT claim the persisted configuration is "enabled"
	// (Codex review, PR #1257). A runtime enable that fails to open returns an
	// error BEFORE adminSettingsSave runs, so the saved setting stays off; a
	// record asserting "enabled" would make diagnostics report a configuration
	// that was never written, and keep reporting it until the next lifecycle
	// action. What this half of the record actually knows is that an open was
	// attempted and how it went — which is true on both the boot path and the
	// admin path, and is what the operator needs either way.
	SaveRequested bool
	// Available is true when the store opened and is serving queries.
	Available bool
	// Path is the store directory.
	Path string
	// Detail is the operator-facing reason the store is unavailable, or the
	// recovery that was performed. Empty on a clean, unremarkable open.
	Detail string
	// Recovered is true when this open moved a damaged store aside and
	// re-created it.
	Recovered bool
	// ResidualCopies is the number of `.corrupt.*` directories present after the
	// open — including any this open created. Non-zero is the operator's cue
	// that there is disk to reclaim and an incident to reconcile.
	ResidualCopies int
}

var (
	logStoreHealthMu sync.RWMutex
	logStoreHealthy  logStoreHealthRecord
)

// logStoreHealthState returns a copy of the recorded outcome.
func logStoreHealthState() logStoreHealthRecord {
	logStoreHealthMu.RLock()
	defer logStoreHealthMu.RUnlock()
	return logStoreHealthy
}

func setLogStoreHealth(h logStoreHealthRecord) {
	logStoreHealthMu.Lock()
	logStoreHealthy = h
	logStoreHealthMu.Unlock()
}

// resetLogStoreHealthForTest clears the record. Test isolation only.
func resetLogStoreHealthForTest() {
	setLogStoreHealth(logStoreHealthRecord{})
}

// noteLogStoreOpened records — and reports — a store that came up.
//
// The alert reuses the CHAOS-05/07 `state_file_corrupt` event rather than
// inventing a second name: the operator action is precisely the one that event
// already means.
//
// A recovery that was TRIGGERED but skipped, on a store that then opened fine,
// is log-only. The commonest reason to skip is a live lock holder, i.e. a
// concurrent opener, where alerting would page somebody about a benign race.
// Alert on evidence or on impact, never on a suspicion that resolved itself.
func noteLogStoreOpened(path string, rec storeguard.Recovery) {
	setLogStoreHealth(logStoreHealthRecord{
		SaveRequested:  true,
		Available:      true,
		Path:           path,
		Recovered:      rec.Quarantined,
		ResidualCopies: len(rec.ResidualQuarantines),
	})
	if !rec.Quarantined {
		if rec.Trigger != storeguard.TriggerNone {
			logger.Printf("LogStore: %q", sanitizeLog(fmt.Sprintf(
				"request-history store at %s looked damaged (%s: %s) but was NOT quarantined (%s); it opened normally",
				path, rec.Trigger, rec.Cause, rec.Skipped)))
		}
		return
	}
	detail := fmt.Sprintf("request-history store at %s was damaged (%s: %s) — quarantined to %s and re-created empty; saved history from before this point is in the quarantined copy, which remains readable with the existing %s.salt sidecar. Delete it once reconciled to reclaim disk",
		path, rec.Trigger, rec.Cause, rec.QuarantinePath, path)
	logger.Printf("LogStore: %q", sanitizeLog(detail))
	deferStartupAlert("state_file_corrupt", AlertPayload{Source: "storage", Detail: detail})
}

// noteLogStoreOpenFailed emits the SINGLE alert for a store that did not come
// up, folding in the quarantine (or the reason one was not attempted) so the
// operator gets one coherent account instead of two that disagree.
//
// The outcome is reported ONCE, after it is known: a quarantine that succeeded
// followed by a replacement that would not open (volume went full or read-only
// in between) is a FAILURE, not a recovery.
func noteLogStoreOpenFailed(path string, rec storeguard.Recovery, openErr error) {
	setLogStoreHealth(logStoreHealthRecord{
		SaveRequested:  true,
		Available:      false,
		Path:           path,
		Detail:         openErr.Error(),
		ResidualCopies: len(rec.ResidualQuarantines),
	})
	recoveryNote := ""
	switch {
	case rec.Quarantined:
		recoveryNote = fmt.Sprintf(" A damaged copy was quarantined to %s first, so the failure is with the REPLACEMENT store — check the volume for space, permissions, and mount state.", rec.QuarantinePath)
	case rec.Trigger != storeguard.TriggerNone:
		recoveryNote = fmt.Sprintf(" It looked damaged (%s) but could not be quarantined (%s).", rec.Trigger, rec.Skipped)
	}
	detail := fmt.Sprintf("request-history store at %s could not be opened (%v) — request history is NOT being saved; live traffic, policy enforcement and the audit log are unaffected.%s",
		path, openErr, recoveryNote)
	logger.Printf("LogStore: %q", sanitizeLog(detail))
	deferStartupAlert("state_file_corrupt", AlertPayload{Source: "storage", Detail: detail})
}

// noteLogStoreDisabled records the admin turning history saving off. Data stays
// on disk, so any unreconciled quarantine stays worth reporting.
func noteLogStoreDisabled(path string) {
	residual := 0
	if path != "" {
		residual = len(logstoreQuarantinedCopies(path))
	}
	setLogStoreHealth(logStoreHealthRecord{Path: path, ResidualCopies: residual})
}

// checkRequestHistory is the `request_history` operator-contract row.
//
// Severity policy:
//   - saving off, or on and healthy → ok.
//   - self-healed this run, or unreconciled quarantined copies on disk → warn.
//     The gateway is serving correctly; the operator has evidence to inspect
//     and disk to reclaim.
//   - on but unavailable → warn, never fail. History is a queryable convenience
//     over traffic that is ALSO written to the request log and the audit log
//     (both independent of this store), and the node is fully able to serve; a
//     fail row here would report a healthy gateway as broken.
func checkRequestHistory() OperatorContractCheck {
	h := logStoreHealthState()
	if !h.SaveRequested {
		if h.ResidualCopies > 0 {
			return OperatorContractCheck{
				Code:   "request_history",
				Status: diagWarn,
				Message: fmt.Sprintf("history saving is off, but %d quarantined copy/copies of a damaged history store remain on disk",
					h.ResidualCopies),
				OperatorAction: "Delete the quarantined .corrupt.* copy of the history store to reclaim disk.",
			}
		}
		return OperatorContractCheck{
			Code:    "request_history",
			Status:  diagOK,
			Message: "request-history saving is off",
		}
	}
	if !h.Available {
		return OperatorContractCheck{
			Code:           "request_history",
			Status:         diagWarn,
			Message:        "request-history saving was requested but its store could not be opened — searchable history is not being saved",
			OperatorAction: "Check the data volume for the history store (space, permissions, mount) and re-enable; see server logs for the cause. If the store is encrypted, confirm the .salt sidecar next to it is intact before purging.",
		}
	}
	if h.Recovered {
		return OperatorContractCheck{
			Code:   "request_history",
			Status: diagWarn,
			Message: fmt.Sprintf("request-history store was damaged and re-created (%d quarantined copy/copies on disk); history from before the incident is in the quarantined copy",
				h.ResidualCopies),
			OperatorAction: "Confirm the data volume is healthy, retrieve anything needed from the quarantined .corrupt.* copy, then delete it to reclaim disk.",
		}
	}
	if h.ResidualCopies > 0 {
		return OperatorContractCheck{
			Code:   "request_history",
			Status: diagWarn,
			Message: fmt.Sprintf("request-history store is healthy, but %d quarantined copy/copies from an earlier incident remain on disk",
				h.ResidualCopies),
			OperatorAction: "Delete the quarantined .corrupt.* copy of the history store to reclaim disk.",
		}
	}
	return OperatorContractCheck{
		Code:    "request_history",
		Status:  diagOK,
		Message: "request-history store loaded",
	}
}
