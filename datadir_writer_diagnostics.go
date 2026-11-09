package main

// checkDataDirWriterPosture surfaces the boot-time single-writer lock outcome.
// Until now it reached the operator only as a one-shot startup log line, so an
// appliance running with CULVERT_ALLOW_MULTIPLE_WRITERS=1 (two processes that
// overwrite each other's roster, policy and settings) looked healthy. Report
// only: the guard itself is unchanged. Contributes nothing when the lock is held.
func checkDataDirWriterPosture() []OperatorContractCheck {
	state, _ := dataDirWriterPosture.Load().(string)
	switch state {
	case dataDirPostureOverride:
		return []OperatorContractCheck{{
			Code:   "datadir_multiple_writers_override",
			Status: diagWarn,
			Message: "another Culvert process holds this data directory and " + allowMultipleWritersEnv + " is set, so this process started anyway — " +
				"the two processes overwrite each other's roster, policy, admin settings and config versions, and the first-run setup window stays open",
			OperatorAction: "Treat this as break-glass. Stop the other process or give each its own data directory (CULVERT_DATA_DIR), remove " +
				allowMultipleWritersEnv + " from the proxy environment and restart; the row clears at the next start.",
		}}
	case dataDirPostureUnverified:
		return []OperatorContractCheck{{
			Code:   "datadir_writer_lock_unverified",
			Status: diagWarn,
			Message: "the single-writer lock on the data directory could not be established at startup, so a second Culvert process on the same " +
				"directory would not be detected",
			OperatorAction: "Confirm only one Culvert process uses this data directory. Check that the volume is writable and supports file locking " +
				"(some network filesystems do not); the startup log names the cause. The row clears at the next start once the lock is held.",
		}}
	}
	return nil
}
