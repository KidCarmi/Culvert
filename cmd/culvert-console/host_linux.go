//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
	"github.com/KidCarmi/Culvert/internal/appliancehost"
	"golang.org/x/sys/unix"
)

const hostDirectory = "/var/lib/culvert-console/private"
const hostPublic = "/var/lib/culvert-console/status.json"

func hostIdentity() (appliancehost.Identity, error) {
	boot, err := appliancehost.ReadIdentity("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return appliancehost.Identity{}, err
	}
	machine, err := appliancehost.ReadIdentity("/etc/machine-id")
	if err != nil {
		return appliancehost.Identity{}, err
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return appliancehost.Identity{}, err
	}
	id := appliancehost.Identity{Boot: strings.TrimSpace(string(boot)), Machine: strings.TrimSpace(string(machine)), Uptime: time.Duration(now.Nano())}
	if len(id.Boot) != 36 || len(id.Machine) != 32 {
		return id, errors.New("boot/machine identity unavailable")
	}
	return id, nil
}

func hostNetplan() appliancehost.Netplan {
	return appliancehost.Netplan{Target: "/etc/netplan/60-culvert.yaml", Directories: []string{"/etc/netplan", "/lib/netplan", "/run/netplan"}, Run: func(ctx context.Context) error {
		if err := hostCommand(ctx, "/usr/sbin/netplan", "generate"); err != nil {
			return appliancehost.AtStage("netplan_generate", err)
		}
		return appliancehost.AtStage("netplan_apply", hostCommand(ctx, "/usr/sbin/netplan", "apply"))
	}}
}

func hostCommand(parent context.Context, path string, args ...string) error {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	// #nosec G204 -- private adapter called only with fixed commands in this file.
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = probeEnvironment()
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return unix.Kill(-cmd.Process.Pid, unix.SIGKILL) }
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s %s: %w", filepath.Base(path), args[0], ctx.Err())
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("%s %s failed with exit %d", filepath.Base(path), args[0], exit.ExitCode())
		}
		return fmt.Errorf("%s %s could not start", filepath.Base(path), args[0])
	}
	return nil
}

func hostSession(fn func(*appliancehost.Session) error) error {
	if os.Geteuid() != 0 {
		return errors.New("host recovery requires existing sudo/root authorization")
	}
	store := appliancehost.Store{Directory: hostDirectory}
	return store.WithLock(func(s *appliancehost.Session) error {
		id, err := hostIdentity()
		if err != nil {
			return err
		}
		s.Identity = id
		s.Host = hostNetplan()
		err = fn(s)
		return errors.Join(err, store.PublishCurrent(hostPublic))
	})
}

func runHost(ctx context.Context, mode string, c applianceconsole.Collector) error {
	if os.Geteuid() != 0 {
		return errors.New("host recovery requires root")
	}
	switch mode {
	case "worker":
		return hostWorker(ctx, c)
	case "network":
		return networkDialog(ctx)
	case "reboot", "poweroff", "retry-reset", "retry-start":
		return hostAction(ctx, mode, c)
	default:
		return errors.New("unknown host action")
	}
}

func hostAction(ctx context.Context, mode string, c applianceconsole.Collector) error {
	return hostSession(func(s *appliancehost.Session) error {
		snapshot := c.Collect(ctx)
		if strings.HasPrefix(mode, "retry-") && !applianceconsole.RetryAllowed(snapshot) {
			return errors.New("retry refused: provisioning is running, complete, or unknown")
		}
		if s.State.Network != nil && s.State.Network.Pending() {
			return errors.New("resolve the pending network transaction before power or provisioning actions")
		}
		id, err := s.Append(mode, "intent", checkpoint(snapshot))
		if err != nil {
			return err
		}
		args := []string{mode}
		switch mode {
		case "retry-reset":
			args = []string{"reset-failed", "culvert-firstboot.service"}
		case "retry-start":
			args = []string{"start", "--no-block", "culvert-firstboot.service"}
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(err, s.Finish(id, "cancelled"))
		}
		err = hostCommand(ctx, "/usr/bin/systemctl", args...)
		phase := "submitted"
		if err != nil {
			phase = "failed"
		}
		return errors.Join(err, s.Finish(id, phase))
	})
}

func checkpoint(s applianceconsole.Snapshot) string {
	var recorded []string
	for _, step := range s.Steps {
		if step.State == "recorded" {
			recorded = append(recorded, step.ID)
		}
	}
	return applianceconsole.Clean(fmt.Sprintf("%s/%s result=%s exit=%s markers=%s", s.Firstboot["ActiveState"], s.Firstboot["SubState"], s.Firstboot["Result"], s.Firstboot["ExecMainStatus"], strings.Join(recorded, ",")), 240)
}

func hostWorker(ctx context.Context, c applianceconsole.Collector) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var nextObservation time.Time
	var retryDelay time.Duration
	for {
		var observed *applianceconsole.Snapshot
		if time.Now().After(nextObservation) {
			snapshot := c.Collect(ctx)
			observed = &snapshot
			nextObservation = time.Now().Add(15 * time.Second)
		}
		err := hostSession(func(s *appliancehost.Session) error {
			if observed != nil {
				if err := observeBoot(s, *observed); err != nil {
					return err
				}
			}
			return s.Tick(ctx)
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "Host recovery needs attention:", err)
			retryDelay = min(max(2*time.Second, retryDelay*2), 30*time.Second)
		} else {
			retryDelay = 0
		}
		tick.Reset(max(time.Second, retryDelay))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func observeBoot(s *appliancehost.Session, snapshot applianceconsole.Snapshot) error {
	observation := checkpoint(snapshot)
	for i := len(s.State.Records) - 1; i >= 0; i-- {
		r := s.State.Records[i]
		if r.Action != "firstboot_observation" {
			continue
		}
		if r.Boot == s.Identity.Boot && r.Observation == observation {
			return nil
		}
		break
	}
	_, err := s.Append("firstboot_observation", "observed", observation)
	return err
}
