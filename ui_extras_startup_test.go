package main

// ui_extras_startup_test.go — PR3 expansion Batch 1 coverage.

import "testing"

// resetUIExtrasGlobals snapshots/restores the two globals touched by the
// loader so tests stay isolated under -shuffle.
func resetUIExtrasGlobals(t *testing.T) {
	t.Helper()
	origSANs := uiExtraSANs
	origTFH := trustForwardedHeaders
	t.Cleanup(func() {
		uiExtraSANs = origSANs
		trustForwardedHeaders = origTFH
	})
}

func TestResolveUIExtrasStartupConfig_MergesCLIAndFileSANs(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.UISANs = []string{"fc-san.example", "other.example"}
	got := resolveUIExtrasStartupConfig(fc, "cli-san.example, , whitespace.example ", false)

	// CLI SANs come first (in order), then FileConfig SANs appended.
	want := []string{"cli-san.example", "whitespace.example", "fc-san.example", "other.example"}
	if len(got.ExtraSANs) != len(want) {
		t.Fatalf("ExtraSANs count = %d, want %d: %v", len(got.ExtraSANs), len(want), got.ExtraSANs)
	}
	for i := range want {
		if got.ExtraSANs[i] != want[i] {
			t.Errorf("ExtraSANs[%d] = %q, want %q", i, got.ExtraSANs[i], want[i])
		}
	}
}

func TestResolveUIExtrasStartupConfig_EmptyCLISANsDropped(t *testing.T) {
	fc := &FileConfig{}
	got := resolveUIExtrasStartupConfig(fc, ",,  ,", false)
	if len(got.ExtraSANs) != 0 {
		t.Errorf("whitespace/empty CLI tokens should be dropped; got %v", got.ExtraSANs)
	}
}

func TestResolveUIExtrasStartupConfig_TrustFwdDisjunction(t *testing.T) {
	cases := []struct {
		cliFlag, fcFlag, want bool
	}{
		{false, false, false},
		{false, true, true},
		{true, false, true},
		{true, true, true},
	}
	for _, c := range cases {
		fc := &FileConfig{}
		fc.Proxy.TrustForwardedHeaders = c.fcFlag
		got := resolveUIExtrasStartupConfig(fc, "", c.cliFlag)
		if got.TrustForwardedHeaders != c.want {
			t.Errorf("cli=%v fc=%v → got %v, want %v", c.cliFlag, c.fcFlag, got.TrustForwardedHeaders, c.want)
		}
	}
}

func TestLoadUIExtras_WritesBothGlobals(t *testing.T) {
	resetUIExtrasGlobals(t)
	cfg := uiExtrasStartupConfig{
		ExtraSANs:             []string{"a.example", "b.example"},
		TrustForwardedHeaders: true,
	}
	loadUIExtras(cfg)
	if len(uiExtraSANs) != 2 || uiExtraSANs[0] != "a.example" {
		t.Errorf("uiExtraSANs not written; got %v", uiExtraSANs)
	}
	if !trustForwardedHeaders {
		t.Error("trustForwardedHeaders not written")
	}
}
