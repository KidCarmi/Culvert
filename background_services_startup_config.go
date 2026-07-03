package main

// background_services_startup_config.go — resolved config for the
// background-services slice (SSE broadcaster, alert retry queue, Docker
// self-update wiring, cluster-update recovery). Pure DTO + a single
// side-effect-free resolver invoked from the initBackgroundServices shim.
// The CLI flag values and the build-time version are passed IN so the
// resolver stays pure (slice convention pinned by
// startup_slice_contract_test.go).

import "strings"

// backgroundServicesStartupConfig carries the resolved inputs for the
// background-services loader.
type backgroundServicesStartupConfig struct {
	// UpdaterURLAllowlist is the merged operator-curated allowlist:
	// config update.url_allowlist entries first, then the CLI
	// comma-separated additions (trimmed, empties dropped). Installed
	// BEFORE the updater URL is validated (H4) — validateUpdaterURL
	// consults it.
	UpdaterURLAllowlist []string

	// UpdaterURLCandidate is the configured updater URL (CLI wins over
	// config). "" = keep the built-in default. Validation is a loader
	// concern (it consults the installed allowlist).
	UpdaterURLCandidate string

	// VersionFileBody is the clean semver written to the shared volume for
	// the updater sidecar (git-describe suffixes stripped, e.g.
	// "v0.0.19-4-g8ac6d14" → "v0.0.19"). "" = skip the write (dev builds).
	VersionFileBody string
}

// resolveBackgroundServicesStartupConfig is the single startup-time reader of
// fc.Update.* for this slice. cliAllow is the raw comma-separated CLI
// allowlist flag; cliURL the CLI updater-URL flag; versionVal the build-time
// version string. Pure and deterministic; safe on a zero-value *FileConfig.
func resolveBackgroundServicesStartupConfig(fc *FileConfig, cliAllow, cliURL, versionVal string) backgroundServicesStartupConfig {
	allowlist := append([]string(nil), fc.Update.URLAllowlist...)
	if cli := strings.TrimSpace(cliAllow); cli != "" {
		for _, entry := range strings.Split(cli, ",") {
			if e := strings.TrimSpace(entry); e != "" {
				allowlist = append(allowlist, e)
			}
		}
	}

	versionBody := ""
	if cv := cleanSemver(versionVal); cv != "" && cv != "dev" {
		versionBody = cv
	}

	return backgroundServicesStartupConfig{
		UpdaterURLAllowlist: allowlist,
		UpdaterURLCandidate: firstStr(cliURL, fc.Update.UpdaterURL),
		VersionFileBody:     versionBody,
	}
}
