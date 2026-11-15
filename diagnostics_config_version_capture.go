package main

// diagnostics_config_version_capture.go — operator-contract row for
// configuration changes that were applied without a rollback point.
//
// Every versioned configuration mutation ends in saveConfigVersion, which is
// best-effort: when the capture is refused (rewrite identity not durable) or
// the version file cannot be written, the change itself stays applied and the
// only trace is one process-log line. The admin UI reports the save as
// successful, Config Versions simply does not gain an entry, and every
// config_versions_* row stays OK because the versions already on disk are
// intact. The operator learns the rollback point is missing only when a
// rollback is needed.
//
// Report-only: the capture outcome is recorded in memory by the one function
// every capture goes through; capture, refusal, logging and the mutation paths
// are unchanged. Contributes nothing until a capture is missed and clears on the
// next successful one, which records the full current configuration. The state
// is per-process, so the row also clears on restart. It names a count, a time
// and a fixed cause class only: never the error text, which can carry
// filesystem paths (viewer-readable).

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// configVersionCaptureGap is the run of consecutive missed captures since the
// last successful one. The zero value means the latest capture succeeded (or
// none has been attempted).
type configVersionCaptureGap struct {
	missed  int
	since   time.Time // first missed capture of the run
	refused bool      // latest miss was a documented refusal, not a write failure
}

var (
	configVersionCaptureMu       sync.Mutex
	configVersionCaptureGapState configVersionCaptureGap
)

// noteConfigVersionCapture records the outcome of one capture attempt.
func noteConfigVersionCapture(err error) {
	configVersionCaptureMu.Lock()
	defer configVersionCaptureMu.Unlock()
	if err == nil {
		configVersionCaptureGapState = configVersionCaptureGap{}
		return
	}
	if configVersionCaptureGapState.missed == 0 {
		configVersionCaptureGapState.since = time.Now()
	}
	configVersionCaptureGapState.missed++
	configVersionCaptureGapState.refused = errors.Is(err, errConfigVersionRefused)
}

// checkConfigVersionCapture returns zero or one row for configuration changes
// applied since the last successfully recorded version.
func checkConfigVersionCapture() []OperatorContractCheck {
	configVersionCaptureMu.Lock()
	gap := configVersionCaptureGapState
	configVersionCaptureMu.Unlock()
	return configVersionCaptureRows(gap)
}

func configVersionCaptureRows(gap configVersionCaptureGap) []OperatorContractCheck {
	if gap.missed == 0 {
		return nil
	}
	cause := "the version file could not be written to the config versions directory"
	action := "Check the storage row of this report and the free space and permissions of the data volume, " +
		"then save any configuration change again."
	if gap.refused {
		cause = "version capture is refused while rewrite-rule management identity is not durable"
		action = "Resolve the rewrite_identity row of this report (fix the settings file or volume and restart this node), " +
			"then save any configuration change."
	}
	return []OperatorContractCheck{{
		Code:   "config_version_capture",
		Status: diagWarn,
		Message: fmt.Sprintf("%d configuration change(s) since %s were applied without a rollback point — %s. "+
			"Config Versions does not list them; rolling back to the latest listed version would also undo these changes",
			gap.missed, gap.since.UTC().Format(time.RFC3339), cause),
		OperatorAction: action + " The next recorded version captures the full current configuration and clears this warning. " +
			"The Audit Log lists the changes made since the time above. Until then, export the configuration " +
			"(Settings → Config Export / Import) if a copy of the current state is needed. Traffic and policy enforcement are not affected.",
	}}
}
