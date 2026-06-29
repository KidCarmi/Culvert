package main

// fileblock_startup.go — startup-time loader for the file-blocking slice
// (PR3 follow-up pilot, Phase 1).
//
// Responsibility:
//   - read an already-resolved fileBlockStartupConfig
//   - populate the package-global fileBlocker store (extensions + persistence path)
//   - populate the package-global globalProfileStore (named file-type profiles)
//   - return a non-fatal error for the one recoverable failure path; callers
//     decide whether to surface or suppress
//
// The two stores remain package-global for this pilot. Movement into a
// subpackage is a follow-up decision dependent on pilot outcomes.

import (
	"fmt"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/fileblock"
)

// loadFileBlocking initialises fileBlocker (extension list + persistence
// path) and globalProfileStore (named file-type profiles) from cfg. Returns
// an error for the one recoverable failure path — globalProfileStore.Load —
// which the caller may log as a warning without aborting startup.
//
// Behaviour matches the pre-pilot init body byte-for-byte: extensions are
// seeded from config or defaults, then SetPath overrides with the persisted
// file if present; profiles are loaded from the resolved path.
func loadFileBlocking(cfg fileBlockStartupConfig) error {
	loadFileBlockerExtensions(cfg.Extensions)
	logger.Printf("FileBlock: %d extension(s) in profile", fileBlocker.Count())

	if err := globalProfileStore.Load(cfg.ProfilesPath); err != nil {
		// Non-fatal: original code falls back to in-memory defaults.
		return fmt.Errorf("profile store %q: %w", cfg.ProfilesPath, err)
	}
	logger.Printf("FileProfiles: %d profile(s) loaded from %s", len(globalProfileStore.List()), cfg.ProfilesPath)
	return nil
}

// loadFileBlockerExtensions populates fileBlocker from the explicit
// extension list or defaults, then wires the persistence path. SetPath
// loads the on-disk file if present, overriding the in-memory seed so
// UI-added extensions survive restarts.
func loadFileBlockerExtensions(exts []string) {
	if len(exts) > 0 {
		for _, ext := range exts {
			fileBlocker.Add(ext)
		}
	} else {
		for _, ext := range fileblock.DefaultBlockedExts {
			fileBlocker.Add(ext)
		}
	}
	fileBlocker.SetPath(filepath.Join(dataDir, "fileblock.json"))
}
