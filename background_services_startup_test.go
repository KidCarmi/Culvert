package main

// background_services_startup_test.go — per-slice tests for the
// background-services startup slice. The loader's collaborators (SSE, alert
// retry) are owned and tested by their own subsystems' suites. The resolver is
// config-free (the legacy updater wiring it used to resolve was removed with
// the updater sidecar), so the remaining contract is just purity/determinism —
// covered by startup_slice_contract_test.go.

import "testing"

func TestResolveBackgroundServices_Empty(t *testing.T) {
	// The resolver reads nothing and returns the zero DTO regardless of input.
	fc := &FileConfig{}
	fc.Update.UpdaterURL = "https://legacy.example/ignored"
	fc.Update.URLAllowlist = []string{"https://a.example"}

	got := resolveBackgroundServicesStartupConfig(fc)
	if got != (backgroundServicesStartupConfig{}) {
		t.Errorf("resolveBackgroundServicesStartupConfig = %+v, want zero value (config-free slice)", got)
	}
}
