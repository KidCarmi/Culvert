package main

import "github.com/KidCarmi/Culvert/internal/fileblock"

// File-type blocking moved to internal/fileblock (ADR-0002, unblocked by the
// ADR-0003 seam). package main keeps the process-wide singletons here so the
// many fileBlocker.*/globalProfileStore.* call sites stay unchanged.
//
// The type aliases are transitional churn-minimisers: they let existing
// package main code (controlplane ConfigSnapshot, cluster tests) keep
// referencing FileBlocker/FileProfileStore/FileExtProfile unqualified while the
// engine lives in internal/fileblock. They add no new exported API.
type (
	FileBlocker      = fileblock.FileBlocker
	FileProfileStore = fileblock.FileProfileStore
	FileExtProfile   = fileblock.FileExtProfile
)

var (
	fileBlocker        = fileblock.NewBlocker()
	globalProfileStore = &fileblock.FileProfileStore{}

	// validateFileProfiles is the canonical profile-set validation seam
	// (2D-C final §14), aliased for the ConfigSnapshot preflight.
	validateFileProfiles = fileblock.ValidateProfiles
)
