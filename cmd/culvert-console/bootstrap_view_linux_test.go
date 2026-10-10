//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
)

// This is deliberately a fixture, never a real credential or host observation.
const viewFixtureCredential = "Fixture23456789A"

func TestBootstrapFullFrameHasSetupAndCredentialGuidance(t *testing.T) {
	for _, phase := range []string{"running", "failed", "provisioned"} {
		s := applianceconsole.Snapshot{Phase: phase, SetupStatus: "pending", ManagementAvailable: phase == "provisioned", Addresses: []string{"192.0.2.10"}, ManagementURLs: []string{"https://192.0.2.10:9090"}}
		if phase == "provisioned" {
			for _, id := range []string{"ovf", "console", "access", "images", "install", "agent", "complete"} {
				s.Steps = append(s.Steps, applianceconsole.Step{ID: id, State: "recorded"})
			}
		}
		got := applianceconsole.Render(bootstrapRows(s, viewFixtureCredential, 25, 80), false)
		if phase == "provisioned" {
			t.Log("80x25 fixture only (synthetic password):\n" + got)
		}
		for _, want := range []string{"https://192.0.2.10:9090", "Checkpoints recorded:", viewFixtureCredential, "L/F2 Sign in", "DIFFERENT credential", "[2] Setup access, then [S]", "3 Diagnostics"} {
			if !strings.Contains(got, want) {
				t.Errorf("phase %s omitted %q", phase, want)
			}
		}
	}
}

func TestBootstrapFrameDimensionsAndNoPartialCredentialOrURL(t *testing.T) {
	ip := "2001:db8:1234:5678:abcd:1234:5678:abcd"
	address := "https://[" + ip + "]:9090"
	s := applianceconsole.Snapshot{Phase: "running", Addresses: []string{ip}, ManagementURLs: []string{address}}
	for _, size := range [][2]int{{25, 80}, {24, 80}, {25, 60}, {12, 40}, {6, 18}, {5, 17}, {0, 0}, {-1, -1}, {200, 300}} {
		rows := bootstrapRows(s, viewFixtureCredential, size[0], size[1])
		if len(rows) > max(0, min(size[0], 25)-1) {
			t.Fatalf("too many rows at %v", size)
		}
		for _, row := range rows {
			if len(row.Text) > max(0, min(size[1], 80)-1) || strings.ContainsAny(row.Text, "\x1b\r\n") {
				t.Fatalf("unsafe row at %v", size)
			}
			if strings.Contains(row.Text, "https://") && row.Text != address {
				t.Fatalf("partial URL row at %v", size)
			}
		}
		got := applianceconsole.Render(rows, false)
		if size[0] >= 6 && size[1] >= 18 && !strings.Contains(got, viewFixtureCredential) {
			t.Fatalf("whole credential missing at %v", size)
		}
		if size[0] < 6 || size[1] < 18 {
			if strings.Contains(got, viewFixtureCredential[:8]) {
				t.Fatalf("partial credential on undersized terminal %v", size)
			}
		}
	}
}

func TestBootstrapIPv6URLIsOneWholeRowOrOmitted(t *testing.T) {
	ip := "2001:db8:1234:5678:abcd:1234:5678:abcd"
	address := "https://[" + ip + "]:9090"
	for _, setup := range []string{"pending", "completed"} {
		for _, width := range []int{40, 44, len(address), len(address) + 1, 60, 80} {
			s := applianceconsole.Snapshot{Phase: "ready", SetupStatus: setup, ManagementAvailable: true, Addresses: []string{ip}, ManagementURLs: []string{address}}
			rows := bootstrapRows(s, viewFixtureCredential, 25, width)
			seen := false
			for _, row := range rows {
				if strings.Contains(row.Text, "https://") {
					seen = true
					if row.Text != address {
						t.Fatalf("setup %s width %d split or clipped URL", setup, width)
					}
				}
			}
			got := applianceconsole.Render(rows, false)
			if !strings.Contains(got, viewFixtureCredential) {
				t.Fatalf("setup %s width %d lost full local credential", setup, width)
			}
			if width <= len(address) && (seen || !strings.Contains(got, "Resize")) {
				t.Fatalf("setup %s width %d did not give resize guidance", setup, width)
			}
		}
	}
}

func TestBootstrapFrameHandlesUnavailableAndCompletedSetup(t *testing.T) {
	s := applianceconsole.Snapshot{Phase: "running"}
	got := applianceconsole.Render(bootstrapRows(s, viewFixtureCredential, 25, 80), false)
	if !strings.Contains(got, "URL unavailable") || strings.Contains(got, "https://") {
		t.Fatal("missing address invented a URL")
	}
	s.SetupStatus = "completed"
	got = applianceconsole.Render(bootstrapRows(s, viewFixtureCredential, 25, 80), false)
	if strings.Contains(got, "Show token") || !strings.Contains(got, "separate from your web administrator") {
		t.Fatal("completed browser setup offered a new setup token")
	}
}

// The first screen reminds the operator to save the recovery secrets and says
// where they are, on a standard 80x25 console in both setup states, and never
// carries a passphrase itself (this view is shown BEFORE authentication).
func TestBootstrapRemindsToSaveRecoverySecrets(t *testing.T) {
	for _, setup := range []string{"pending", "completed"} {
		s := applianceconsole.Snapshot{Phase: "ready", SetupStatus: setup, ManagementAvailable: true, Addresses: []string{"192.0.2.10"}, ManagementURLs: []string{"https://192.0.2.10:9090"}}
		got := applianceconsole.Render(bootstrapRows(s, viewFixtureCredential, 25, 80), false)
		if !strings.Contains(got, "SAVE RECOVERY SECRETS: after sign-in, [0] Recovery, [4].") || !strings.Contains(got, "Neither this password nor the token replaces them.") {
			t.Errorf("setup %s: recovery-secret reminder missing at 80x25:\n%s", setup, got)
		}
		if strings.Contains(got, "PASSPHRASE=") {
			t.Errorf("setup %s: the pre-authentication screen must never carry a passphrase", setup)
		}
	}
}
