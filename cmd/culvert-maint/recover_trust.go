package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"culvert-maint/internal/config"
	"culvert-maint/internal/releasetrust"
)

// recoverFlags are the operator inputs of `culvert-maint --recover-release-trust`.
type recoverFlags struct {
	confirm      bool
	floorVersion int
	floorAt      string // RFC 3339; empty = not stated
}

// recoverGeteuid is a test seam for the root requirement.
var recoverGeteuid = os.Geteuid

// recoverHostLock is a test seam over the shared host maintenance flock.
var recoverHostLock = acquireRecoveryHostLock

func (f recoverFlags) options() (releasetrust.RecoverOptions, error) {
	opt := releasetrust.RecoverOptions{Confirm: f.confirm, FloorVersion: f.floorVersion}
	if f.floorAt != "" {
		t, err := time.Parse(time.RFC3339, f.floorAt)
		if err != nil {
			return opt, fmt.Errorf("--floor-generated-at must be RFC 3339: %w", err)
		}
		opt.FloorGenerated = t.UTC()
	}
	if (opt.FloorVersion != 0) != !opt.FloorGenerated.IsZero() || opt.FloorVersion < 0 {
		return opt, errors.New("--floor-catalog-version (>= 1) and --floor-generated-at must be supplied together")
	}
	return opt, nil
}

// runRecoverReleaseTrust is the offline, root-only repair of a refused
// release-trust ledger. Startup itself stays fail-closed; this is the explicit
// way back (docs/appliance/signed-update-agent-boundary.md).
func runRecoverReleaseTrust(configPath string, f recoverFlags, out io.Writer) error {
	if recoverGeteuid() != 0 {
		return errors.New("--recover-release-trust must be run as root (sudo culvert-maint --recover-release-trust ...)")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	return recoverReleaseTrust(cfg, f, out)
}

func recoverReleaseTrust(cfg *config.Config, f recoverFlags, out io.Writer) error {
	opt, err := f.options()
	if err != nil {
		return err
	}
	policy, err := releaseTrustPolicy(cfg)
	if err != nil {
		return fmt.Errorf("release trust policy: %w", err)
	}
	if agentSocketLive(cfg.SocketPath) {
		return fmt.Errorf("an agent is serving %s — stop it first (systemctl stop culvert-maint); recovery runs offline only", cfg.SocketPath)
	}
	release, busy, err := recoverHostLock(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("host maintenance lock: %w", err)
	}
	if busy {
		return errors.New("host maintenance lock is held (an agent operation, OS update or pending shutdown) — retry once it is released")
	}
	defer release()
	rep, err := releasetrust.Recover(cfg.StateDir, policy, opt)
	if rep != nil {
		printRecoverReport(out, rep)
	}
	return err
}

// agentSocketLive reports whether something accepts connections on the agent
// socket. A stale socket file (connection refused) is not a live agent.
func agentSocketLive(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func printRecoverReport(out io.Writer, rep *releasetrust.RecoverReport) {
	w := func(format string, a ...any) { _, _ = fmt.Fprintf(out, format, a...) }
	reason := string(rep.Reason)
	if reason == "" {
		reason = "none"
	}
	w("release-trust ledger: %s\nrefusal reason: %s\naction: %s\n", rep.Path, reason, rep.Action)
	if rep.OldFloorKnown {
		w("recorded floor: catalog_version=%d generated_at=%s\n", rep.OldFloorVersion, rep.OldFloorTime.UTC().Format(time.RFC3339))
	}
	if rep.FloorVersion > 0 {
		w("resulting floor: catalog_version=%d generated_at=%s\n", rep.FloorVersion, rep.FloorTime.UTC().Format(time.RFC3339))
	}
	for _, k := range rep.Kept {
		w("keep: %s\n", k)
	}
	for _, d := range rep.Dropped {
		w("drop: %s (%s)\n", d.Ref, d.Reason)
	}
	if rep.Quarantine != "" {
		w("previous ledger preserved as: %s\n", rep.Quarantine)
	}
	if rep.Action == "dry-run" {
		w("dry run: nothing changed; repeat with --confirm to apply\n")
	}
}
