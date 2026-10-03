package applianceconsole

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodReady = `{"checks":{"policy_loaded":{"status":"ok"},"policy_posture":{"status":"ok"},"ca":{"status":"ok"},"setup_complete":{"status":"ok"}}}` + "\n200"

func TestStatusTruthTable(t *testing.T) {
	for _, tt := range []struct {
		name, active, result, health, setup, ready, want string
		complete                                         bool
	}{
		{"unit_absent", "", "", "", "", "", "FIRSTBOOT_UNKNOWN", false},
		{"ordering_cycle", "inactive", "success", "", "", "", "FIRSTBOOT_NOT_RUNNING", false},
		{"running", "activating", "success", "", "", "", "FIRSTBOOT_RUNNING", false},
		{"auto_retry_failure", "activating", "exit-code", "", "", "", "FIRSTBOOT_FAILED", false},
		{"stale_marker_failed_unit", "failed", "", "200", "", "", "FIRSTBOOT_FAILED", true},
		{"marker_without_service", "active", "success", "", "", "", "APPLICATION_UNAVAILABLE", true},
		{"unknown_enrollment", "active", "success", "200", "", "", "SETUP_UNKNOWN", true},
		{"pending_enrollment", "active", "success", "200", "{\"needsSetup\":true}\n200", "", "SETUP_REQUIRED", true},
		{"enrolled_not_ready", "active", "success", "200", "{\"needsSetup\":false}\n200", "", "READINESS_INCOMPLETE", true},
		{"healthy_not_traffic_verified", "active", "success", "200", "{\"needsSetup\":false}\n200", goodReady, "HEALTH_CHECKS_PASSED", true},
		{"false_body_on_http_error", "active", "success", "200", "{\"needsSetup\":false}\n403", goodReady, "SETUP_UNKNOWN", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := Snapshot{Firstboot: map[string]string{"ActiveState": tt.active, "Result": tt.result}}
			if tt.complete {
				s.Steps = []Step{{ID: "complete", State: "recorded"}}
			}
			s.summarize(tt.health, tt.setup, tt.ready)
			if s.Reason != tt.want || s.TrafficVerified {
				t.Fatalf("unexpected summary: %+v", s)
			}
		})
	}
}

func TestEnrollmentNeedsExplicitBooleanAndHTTP200(t *testing.T) {
	for _, value := range []string{"null", "0", `"false"`, "[]", "{}"} {
		s := Snapshot{}
		s.summarize("200", `{"needsSetup":`+value+"}\n200", goodReady)
		if s.AdministratorEnrolled {
			t.Errorf("accepted %s", value)
		}
	}
}

func TestEveryReadinessRowAndHTTPRequired(t *testing.T) {
	for _, key := range []string{"policy_loaded", "policy_posture", "ca", "setup_complete"} {
		t.Run(key, func(t *testing.T) {
			body, _ := httpBody(goodReady)
			var ready readyStatus
			if err := json.Unmarshal([]byte(body), &ready); err != nil {
				t.Fatal(err)
			}
			delete(ready.Checks, key)
			data, err := json.Marshal(ready)
			if err != nil {
				t.Fatal(err)
			}
			s := Snapshot{Steps: []Step{{ID: "complete", State: "recorded"}}}
			s.summarize("200", "{\"needsSetup\":false}\n200", string(data)+"\n200")
			if s.Phase == "ready" {
				t.Fatal("missing check became ready")
			}
		})
	}
	for _, raw := range []string{strings.ReplaceAll(goodReady, "\n200", "\n503"), "null\n200", "[]\n200", "{\n200", "{\"checks\":null}\n200", "{\"checks\":{\"ca\":\"ok\"}}\n200"} {
		s := Snapshot{Steps: []Step{{ID: "complete", State: "recorded"}}}
		s.summarize("200", "{\"needsSetup\":false}\n200", raw)
		if s.Phase == "ready" {
			t.Errorf("accepted malformed readiness %s", raw)
		}
	}
}

func fixture(t *testing.T) (collector Collector, observations map[string]string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ovf.done", "")
	write("console.done", "")
	write(".env", "CULVERT_SETUP_TOKEN=NEVER_DISPLAY")
	write("build.json", `{"appliance":{"version":"test"},"candidate":{"candidate":true},"secret":"NEVER_DISPLAY"}`)
	if err := os.MkdirAll(filepath.Join(dir, "net", "eth0", "device"), 0o700); err != nil {
		t.Fatal(err)
	}
	raw := map[string]string{
		"unit":    "ActiveState=failed\nResult=exit-code\nExecMainStatus=1\nSECRET=NEVER_DISPLAY",
		"network": `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"},{"family":"inet","local":"127.0.0.1"},{"family":"inet","local":"169.254.1.1"}]},{"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1"}]}]`,
	}
	c := NewCollector(Sources{StateDir: dir, BuildFile: filepath.Join(dir, "build.json"), NetDir: filepath.Join(dir, "net")})
	c.sources.Probe = func(_ context.Context, args []string) string {
		if strings.Contains(strings.Join(args, " "), "docker") {
			t.Error("Docker dependency")
		}
		switch args[0] {
		case "/usr/bin/systemctl":
			return raw["unit"]
		case "/usr/sbin/ip":
			return raw["network"]
		default:
			return ""
		}
	}
	return c, raw
}

func TestCollectionWithoutApplicationExcludesCredentialsAndBridge(t *testing.T) {
	c, _ := fixture(t)
	s := c.Collect(context.Background())
	if s.Reason != "FIRSTBOOT_FAILED" || !s.Candidate || !s.recorded("ovf") || s.recorded("images") {
		t.Fatalf("unexpected state: %+v", s)
	}
	if strings.Join(s.ManagementURLs, ",") != "https://192.0.2.10:9090" {
		t.Fatalf("incorrect management addresses: %v", s.ManagementURLs)
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "NEVER_DISPLAY") {
		t.Fatal("secret escaped allowlist")
	}
}

func TestMissingAndMalformedObservations(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", "[null]", "{", `[{"ifname":"eth0","addr_info":null}]`, `[{"ifname":"../eth0","addr_info":[]}]`} {
		t.Run(raw, func(t *testing.T) {
			c, _ := fixture(t)
			c.sources.StateDir = filepath.Join(c.sources.StateDir, "absent")
			c.sources.BuildFile = filepath.Join(c.sources.StateDir, "absent.json")
			c.sources.Probe = func(context.Context, []string) string { return raw }
			s := c.Collect(context.Background())
			if s.Phase != "unknown" || len(s.ManagementURLs) != 0 {
				t.Fatalf("malformed observation accepted: %+v", s)
			}
		})
	}
}

func TestTerminalTextAndMetadataAreSanitized(t *testing.T) {
	c, _ := fixture(t)
	if err := os.WriteFile(c.sources.BuildFile, []byte(`{"appliance":{"version":"\u001b[2J\nBAD\u202e"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := c.Collect(context.Background())
	if strings.ContainsAny(s.Version, "\x1b\n\u202e") {
		t.Fatalf("unsafe version: %q", s.Version)
	}
	if Clean("abcdef", 3) != "abc" || Clean("x", 0) != "" {
		t.Fatal("output not bounded")
	}
}

func TestOversizedBuildInfoRejected(t *testing.T) {
	c, _ := fixture(t)
	data := `{"appliance":{"version":"` + strings.Repeat("x", maxOutput) + `"}}`
	if err := os.WriteFile(c.sources.BuildFile, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := c.Collect(context.Background()).Version; got != "unknown" {
		t.Fatal("oversized build info accepted")
	}
}

func TestCollectorProbesConcurrent(t *testing.T) {
	c, _ := fixture(t)
	started := make(chan struct{}, 7)
	release := make(chan struct{})
	c.sources.Probe = func(context.Context, []string) string { started <- struct{}{}; <-release; return "" }
	done := make(chan struct{})
	go func() { c.Collect(context.Background()); close(done) }()
	defer func() { close(release); <-done }()
	for range 7 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("probes serialized")
		}
	}
}

func TestReadOnlyStatusDoesNotChangeFiles(t *testing.T) {
	c, _ := fixture(t)
	before, err := os.ReadDir(c.sources.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Collect(context.Background())
	after, err := os.ReadDir(c.sources.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("collector wrote state")
	}
	f, err := os.Open(filepath.Join(c.sources.StateDir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "CULVERT_SETUP_TOKEN=NEVER_DISPLAY" {
		t.Fatal("credential state changed")
	}
}
