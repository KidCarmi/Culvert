package applianceconsole

import (
	"strings"
	"testing"
)

func TestBootstrapGuidanceUsesCurrentAddressAndLocalReadiness(t *testing.T) {
	for _, tt := range []struct {
		name, phase, ip, url, want, absent string
		available                          bool
	}{
		{"starting", "running", "192.0.2.10", "https://192.0.2.10:9090", "local management is not ready", "create the administrator", false},
		{"setup-ready", "provisioned", "192.0.2.10", "https://192.0.2.10:9090", "create the administrator", "not ready", true},
		{"no-ip", "running", "", "https://192.0.2.10:9090", "URL unavailable", "https://", true},
		{"stale-url", "running", "192.0.2.20", "https://192.0.2.10:9090", "URL unavailable", "https://", true},
		{"ipv6", "provisioned", "2001:db8::10", "https://[2001:db8::10]:9090", "https://[2001:db8::10]:9090", "not ready", true},
		{"injected-url", "running", "192.0.2.10", "https://192.0.2.10:9090/?token=do-not-show", "URL unavailable", "do-not-show", true},
		{"failed", "failed", "192.0.2.10", "https://192.0.2.10:9090", "[BLOCKED] Provisioning failed.", "[SETUP AVAILABLE]", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := Snapshot{Phase: tt.phase, SetupStatus: "pending", ManagementAvailable: tt.available, Addresses: []string{tt.ip}, ManagementURLs: []string{tt.url}}
			got := Render(BootstrapGuidance(s), false)
			if !strings.Contains(got, tt.want) || strings.Contains(got, tt.absent) {
				t.Fatalf("guidance mismatched: %s", got)
			}
		})
	}
}

func TestBootstrapGuidanceCheckpointsAreNotEstimatedProgress(t *testing.T) {
	s := visualFixture()
	s.Steps = append(s.Steps, s.Steps[0], Step{ID: "unknown", State: "recorded"}, Step{ID: "console", State: "not_recorded"})
	got := Render(BootstrapGuidance(s), false)
	if !strings.Contains(got, "1/7 (not a progress estimate)") {
		t.Fatalf("duplicate or unknown checkpoint counted: %s", got)
	}
	s.SetupStatus = "completed"
	got = Render(BootstrapGuidance(s), false)
	if !strings.Contains(got, "use your web sign-in") || strings.Contains(got, "create the administrator") {
		t.Fatalf("completed setup offered onboarding: %s", got)
	}
}
