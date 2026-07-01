package main

// fileblock_startup_config.go — resolved configuration for the file-blocking
// startup slice (PR3 follow-up pilot, Phase 1).
//
// Pilot scope (do not widen without approval):
//   - owns: fc.FileBlock.Extensions and fc.Proxy.FileProfilesFile during
//     startup, plus the --fileprofiles-file CLI flag override
//   - does NOT own: the fileBlocker / globalProfileStore package globals, or
//     the runtime UI handlers / config-import paths that also touch them
//
// Mirrors the shape of inspection_rules_config.go: value-type DTO, single
// resolver, unexported symbols.

// fileBlockStartupConfig carries the resolved configuration needed to
// populate the file-extension blocker and the named file-type profile
// store. "Resolved" means CLI-flag precedence has already been applied.
type fileBlockStartupConfig struct {
	// Extensions is the admin-declared list of file extensions to block.
	// Empty ⇒ fall back to fileblock.DefaultBlockedExts.
	Extensions []string
	// ProfilesPath is the persistence file for globalProfileStore.
	// Always non-empty after resolution (default "fileprofiles.json" if
	// neither CLI flag nor FileConfig provided a path).
	ProfilesPath string
}

// resolveFileBlockStartupConfig is the single startup-time reader of
// fc.FileBlock.Extensions and fc.Proxy.FileProfilesFile. fileProfilesFlag is
// the already-dereferenced --fileprofiles-file CLI override (pass the empty
// string when the flag is unset).
//
// Resolution precedence for ProfilesPath: CLI flag > FileConfig > default.
func resolveFileBlockStartupConfig(fc *FileConfig, fileProfilesFlag string) fileBlockStartupConfig {
	profilesPath := firstStr(fileProfilesFlag, fc.Proxy.FileProfilesFile)
	if profilesPath == "" {
		profilesPath = "fileprofiles.json"
	}
	return fileBlockStartupConfig{
		Extensions:   fc.FileBlock.Extensions,
		ProfilesPath: profilesPath,
	}
}
