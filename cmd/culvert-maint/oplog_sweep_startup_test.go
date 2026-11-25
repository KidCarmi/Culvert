package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRun_RefusedStartStillSweepsExpiredOpLogs: a start that initJournal
// refuses (here: a corrupt journal record; in the field usually a full disk)
// has already run the op-log retention sweep, so the agent frees its own
// expired transcripts and a later restart is not refused for want of space.
// Before, the sweep ran only after initJournal, so a refused start never swept.
func TestRun_RefusedStartStillSweepsExpiredOpLogs(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	opsDir := filepath.Join(state, "operations")
	recDir := filepath.Join(state, "reconcile")
	for _, d := range []string{filepath.Join(dir, "compose"), opsDir, recDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// A record that does not parse: List fails, initJournal refuses to serve.
	if err := os.WriteFile(filepath.Join(recDir, "01JD0000000000000000000000.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	expired := filepath.Join(opsDir, "01JD0000000000000000000001.log")
	fresh := filepath.Join(opsDir, "01JD0000000000000000000002.log")
	for _, p := range []string{expired, fresh} {
		if err := os.WriteFile(p, []byte("transcript\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-3 * 24 * time.Hour)
	if err := os.Chtimes(expired, old, old); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "agent.toml")
	cfg := fmt.Sprintf(`compose_project_dir = %q
compose_file = "docker-compose.yml"
socket_path = %q
state_dir = %q
privilege_mode = "docker_group_lab"
health_base_url = "http://127.0.0.1:1"
allowed_backup_dir = "/backup"
image_allowlist = '^registry\.test/proxy(:[A-Za-z0-9._-]+)$'
proxy_repo = "registry.test/proxy"
log_retention_days = 1
allow_peers = [%q]
`, filepath.Join(dir, "compose"), filepath.Join(dir, "agent.sock"), state, strconv.Itoa(os.Geteuid()))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	err := run(cfgPath)
	if err == nil || !strings.Contains(err.Error(), "refusing to serve") {
		t.Fatalf("run = %v, want the journal to refuse the start", err)
	}
	if _, serr := os.Stat(expired); !os.IsNotExist(serr) {
		t.Errorf("the refused start did not sweep the expired op log (stat: %v)", serr)
	}
	if _, serr := os.Stat(fresh); serr != nil {
		t.Errorf("the sweep removed a log inside the retention window: %v", serr)
	}
}
