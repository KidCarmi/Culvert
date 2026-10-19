//go:build linux

package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"culvert-maint/internal/config"
)

func recoveryConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		StateDir:           state,
		SocketPath:         filepath.Join(dir, "agent.sock"),
		ProxyRepo:          "ghcr.io/kidcarmi/culvert",
		ReleaseCatalogRepo: "ghcr.io/kidcarmi/culvert",
	}
}

func TestRecoverReleaseTrust_RequiresRoot(t *testing.T) {
	orig := recoverGeteuid
	t.Cleanup(func() { recoverGeteuid = orig })
	recoverGeteuid = func() int { return 1000 }
	err := runRecoverReleaseTrust("/nonexistent/config.toml", recoverFlags{confirm: true}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "as root") {
		t.Fatalf("non-root recovery not refused: %v", err)
	}
}

func TestRecoverReleaseTrust_RefusesWhileAgentServes(t *testing.T) {
	cfg := recoveryConfig(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", cfg.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	err = recoverReleaseTrust(cfg, recoverFlags{confirm: true}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "stop it first") {
		t.Fatalf("recovery ran beside a live agent: %v", err)
	}
}

func TestRecoverReleaseTrust_RefusesWhileHostLockHeld(t *testing.T) {
	cfg := recoveryConfig(t)
	release, busy, err := acquireRecoveryHostLock(cfg.StateDir)
	if err != nil || busy {
		t.Fatalf("first lock: busy=%v err=%v", busy, err)
	}
	t.Cleanup(release)
	err = recoverReleaseTrust(cfg, recoverFlags{confirm: true}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "lock is held") {
		t.Fatalf("recovery ran under a held maintenance lock: %v", err)
	}
}

func TestRecoverReleaseTrust_NoLedgerIsNoOp(t *testing.T) {
	cfg := recoveryConfig(t)
	var out bytes.Buffer
	if err := recoverReleaseTrust(cfg, recoverFlags{confirm: true}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "action: none") {
		t.Fatalf("unexpected report: %s", out.String())
	}
	// The lock file it created is owned like the state dir (agent-openable).
	fi, err := os.Stat(filepath.Join(cfg.StateDir, "host-maintenance.lock"))
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("lock file: %v %v", fi, err)
	}
}

func TestRecoverFlags_FloorPairing(t *testing.T) {
	for _, f := range []recoverFlags{
		{floorVersion: 3},
		{floorAt: "2026-01-02T03:04:05Z"},
		{floorVersion: -1, floorAt: "2026-01-02T03:04:05Z"},
		{floorVersion: 3, floorAt: "yesterday"},
	} {
		if _, err := f.options(); err == nil {
			t.Fatalf("invalid floor flags accepted: %+v", f)
		}
	}
	opt, err := recoverFlags{floorVersion: 3, floorAt: "2026-01-02T03:04:05+02:00"}.options()
	if err != nil || opt.FloorVersion != 3 || opt.FloorGenerated.Hour() != 1 {
		t.Fatalf("valid floor flags: %+v %v", opt, err)
	}
}
