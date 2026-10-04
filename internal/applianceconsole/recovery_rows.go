package applianceconsole

func verificationRows(r Recovery) []Row {
	files, applied, access := "unknown", "unknown", "NOT VERIFIED"
	if r.Verification.Files == "verified" {
		files = "verified"
	}
	if r.Verification.Files == "unverified" {
		files = "NOT VERIFIED"
	}
	if r.Verification.Apply == "succeeded" {
		applied = "succeeded"
	}
	if r.Verification.ClientAccess == "operator_confirmed" {
		access = "operator confirmed (historical)"
	}
	return []Row{
		{"Configuration files: " + files, ""},
		{"Apply command: " + applied, ""},
		{"Client access: " + access, "warning"},
		{"Addresses/routes above are current observations, not rollback proof.", ""},
	}
}

func failureRows(f *RecoveryFailure) []Row {
	if f == nil {
		return nil
	}
	hint := "Inspect the recovery worker; preserve the pending backup."
	switch f.Code {
	case "no_space":
		hint = "Check free bytes/inodes. Preserve recovery files before freeing space."
	case "read_only":
		hint = "Check filesystem health; do not discard the recovery backup."
	case "permission_denied":
		hint = "Check root ownership and permissions through authenticated recovery."
	case "configuration_changed":
		hint = "External edits detected. Reconcile the conflict in Network [E]."
	case "timeout", "cancelled":
		hint = "Inspect worker and network state; command completion is unverified."
	}
	return []Row{{"Retained failure: " + Clean(f.Stage, 40) + " / " + Clean(f.Code, 40), "warning"}, {hint, ""}}
}
