package main

// blocklist_startup_config.go — resolved config for the blocklist slice
// (P4.1 / S1). Pure DTO + a single side-effect-free resolver invoked
// from the initBlocklist shim. No globals are read or written here.

import "time"

// blocklistStartupConfig carries the resolved blocklist init inputs:
// the on-disk file path, the optional auto-sync feed URL, and the
// normalized sync interval. The loader consumes this struct and owns
// the actual store / syncer side effects.
type blocklistStartupConfig struct {
	// Path is the local blocklist file. "" disables the file load
	// (the in-memory bl store stays empty until the admin API or a
	// feed sync populates it).
	Path string

	// FeedURL is the remote one-domain-per-line auto-sync URL. ""
	// disables the auto-sync goroutine; blFeedSyncer is still
	// constructed (UI handlers depend on it being non-nil) but
	// .Start(ctx) is not called.
	FeedURL string

	// FeedInterval is the sync cadence. Resolver always returns a
	// strictly-positive value: "" / unparseable / non-positive
	// inputs all collapse to blFeedDefaultInterval (24h).
	FeedInterval time.Duration
}

// resolveBlocklistStartupConfig is the single startup-time reader of
// fc.Proxy.Blocklist*. resolvedPath is the already-resolved s.blPath
// (CLI / FileConfig precedence handled upstream by
// loadFileConfigAndFlags) — passing it through keeps a single source
// of truth for the path. Pure and deterministic; safe on a
// zero-value *FileConfig.
func resolveBlocklistStartupConfig(fc *FileConfig, resolvedPath string) blocklistStartupConfig {
	interval := blFeedDefaultInterval
	if iv := fc.Proxy.BlocklistFeedInterval; iv != "" {
		if d, err := time.ParseDuration(iv); err == nil && d > 0 {
			interval = d
		}
	}
	return blocklistStartupConfig{
		Path:         resolvedPath,
		FeedURL:      fc.Proxy.BlocklistFeedURL,
		FeedInterval: interval,
	}
}
