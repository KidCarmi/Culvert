package main

// background_services_startup_config.go — resolved config for the
// background-services slice (SSE broadcaster, alert retry queue). Pure DTO +
// a single side-effect-free resolver invoked from the initBackgroundServices
// shim. The slice convention (pure, deterministic resolver per startup slice)
// is pinned by startup_slice_contract_test.go.
//
// The legacy Docker self-update wiring (updater URL/allowlist, version-file
// write, update-checker, cluster-update recovery) was removed with the updater
// sidecar. The DTO is intentionally empty: the loader now only starts the SSE
// broadcaster and the alert-retry queue, both parented to the lifecycle ctx.
// FileConfig.Update and the -updater-url* CLI flags are retained as inert,
// parse-only surface so an operator upgrading with a legacy config file or
// launch command is not silently bricked (strict YAML + Go flag parsing both
// fail closed on unknown input).

// backgroundServicesStartupConfig carries the resolved inputs for the
// background-services loader. Empty by design — see the file comment.
type backgroundServicesStartupConfig struct{}

// resolveBackgroundServicesStartupConfig is the startup-time resolver for this
// slice. It reads nothing (the loader is config-free) and is trivially pure and
// deterministic. Retained for slice uniformity (startup_slice_contract_test.go).
func resolveBackgroundServicesStartupConfig(_ *FileConfig) backgroundServicesStartupConfig {
	return backgroundServicesStartupConfig{}
}
