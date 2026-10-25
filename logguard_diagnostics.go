package main

// checkLogDiskProtection surfaces the log disk guard's degraded states on the
// Diagnostics report. Both states were already tracked (logGuard.warning) and
// shown on the Logs panel, but an operator reading the Diagnostics verdict saw
// "healthy" while access/traffic logging was stopped or retention was being
// overridden. It reads the in-memory guard state only and contributes nothing
// when the guard has not intervened.
func checkLogDiskProtection() []OperatorContractCheck {
	logGuard.mu.Lock()
	warning := logGuard.warning
	logGuard.mu.Unlock()
	if minimalMode() {
		return []OperatorContractCheck{{
			Code:   "log_disk_protection",
			Status: diagWarn,
			Message: "emergency minimal logging is active — access/traffic logs are NOT being recorded " +
				"(security events still are) because the disk is above the critical threshold",
			OperatorAction: "Free disk space on the Culvert data volume or expand it; normal logging resumes automatically once usage drops below the threshold.",
		}}
	}
	if warning != "" {
		return []OperatorContractCheck{{
			Code:   "log_disk_protection",
			Status: diagWarn,
			Message: "disk pressure forced log cleanup before the configured retention period — " +
				"older logs were deleted early (see the logstore.cleanup audit entries)",
			OperatorAction: "Expand the Culvert data volume or reduce the log retention age and maximum log storage in the log retention settings.",
		}}
	}
	return nil
}
