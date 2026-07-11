package main

import "context"

// resolveLifecycleCtx returns the process lifecycle context (appLifecycleCtx,
// declared in main.go), or context.Background() before it is wired. Used by
// background stores to stop cleanly on shutdown. Relocated here from the
// now-removed update_cluster.go.
func resolveLifecycleCtx() context.Context {
	if appLifecycleCtx == nil {
		return context.Background()
	}
	return appLifecycleCtx
}

// registrySettingsFile is the on-disk path for custom registry configuration
// (air-gapped/enterprise image mirrors). Read by internal/bootstrap when
// rendering DP enrollment artifacts. Retained after the legacy updater removal
// (the /api/update/registry writer is gone; the file is still read as an
// optional override, falling back to the default registry when absent).
const registrySettingsFile = "/data/registry_settings.json"
