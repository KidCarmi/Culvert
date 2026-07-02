package main

// background_services_startup_test.go — per-slice tests for the
// background-services startup slice (resolver merge/precedence/normalisation
// rules). The loader's collaborators (SSE, alert retry, updater, cluster
// recovery) are owned and tested by their own subsystems' suites.

import (
	"reflect"
	"testing"
)

func TestResolveBackgroundServices_AllowlistMerge(t *testing.T) {
	fc := &FileConfig{}
	fc.Update.URLAllowlist = []string{"https://a.example", "https://b.example"}

	got := resolveBackgroundServicesStartupConfig(fc, " https://c.example , ,https://d.example ", "", "")
	want := []string{"https://a.example", "https://b.example", "https://c.example", "https://d.example"}
	if !reflect.DeepEqual(got.UpdaterURLAllowlist, want) {
		t.Errorf("allowlist = %v, want %v (config first, CLI appended, trimmed, empties dropped)", got.UpdaterURLAllowlist, want)
	}
}

func TestResolveBackgroundServices_UpdaterURLPrecedence(t *testing.T) {
	fc := &FileConfig{}
	fc.Update.UpdaterURL = "https://config.example/update"
	if got := resolveBackgroundServicesStartupConfig(fc, "", "https://cli.example/update", ""); got.UpdaterURLCandidate != "https://cli.example/update" {
		t.Errorf("UpdaterURLCandidate = %q, want the CLI value (CLI wins)", got.UpdaterURLCandidate)
	}
	if got := resolveBackgroundServicesStartupConfig(fc, "", "", ""); got.UpdaterURLCandidate != "https://config.example/update" {
		t.Errorf("UpdaterURLCandidate = %q, want the config fallback", got.UpdaterURLCandidate)
	}
}

func TestResolveBackgroundServices_VersionFileBody(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"v0.0.19-4-g8ac6d14", "v0.0.19"}, // git-describe suffix stripped
		{"v1.2.3", "v1.2.3"},              // clean semver passes through
		{"dev", ""},                       // dev builds skip the write
		{"", ""},                          // empty skips the write
	}
	for _, c := range cases {
		got := resolveBackgroundServicesStartupConfig(&FileConfig{}, "", "", c.in)
		if got.VersionFileBody != c.want {
			t.Errorf("VersionFileBody(%q) = %q, want %q", c.in, got.VersionFileBody, c.want)
		}
	}
}
