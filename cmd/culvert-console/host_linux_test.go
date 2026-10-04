//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
	"github.com/KidCarmi/Culvert/internal/appliancehost"
	"golang.org/x/sys/unix"
)

func TestConsolePowerUsesMaintenanceOwnerAndPropagatesRefusal(t *testing.T) {
	refused := errors.New("maintenance operation in progress")
	for _, mode := range []string{"reboot", "poweroff"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			err := dispatchHostAction(context.Background(), mode, func(_ context.Context, budget time.Duration, path string, args ...string) error {
				calls++
				if path != maintenanceCommand || !slices.Equal(args, []string{mode}) || budget < 2*time.Minute {
					t.Fatalf("unsafe power dispatch: %s %v (budget %s)", path, args, budget)
				}
				return refused
			})
			if calls != 1 || !errors.Is(err, refused) {
				t.Fatalf("refusal must reach operator without retry or systemctl fallback: calls=%d, error=%v", calls, err)
			}
		})
	}
	if err := dispatchHostAction(context.Background(), "reboot --force", func(context.Context, time.Duration, string, ...string) error {
		t.Fatal("unrecognized action dispatched")
		return nil
	}); err == nil {
		t.Fatal("unrecognized action accepted")
	}
}

func TestHostPowerCancellationAllowsRecoveryAndBoundsIgnoredSignals(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "recovered")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := hostCommandWithGrace(ctx, time.Minute, 2*time.Second, "/bin/sh", "-c",
		`trap 'printf recovered > "$1"; exit 1' TERM; while :; do sleep 1; done`, "recovery-fixture", marker)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "recovered" {
		t.Fatalf("helper killed before recovery: %q, %v", got, err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	started := time.Now()
	err = hostCommandWithGrace(ctx2, time.Minute, 200*time.Millisecond, "/bin/sh", "-c", `trap '' TERM; sleep 60 & wait`)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second {
		t.Fatalf("ignored termination escaped bound: %v", err)
	}
}

func TestHostCancellationCleansDescendantWhenLeaderExitsFirst(t *testing.T) {
	dir := t.TempDir()
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- hostCommandWithGrace(ctx, 5*time.Second, 5*time.Second, "/bin/sh", "-c", `
exec 9>"$1/lock"
flock -x 9 || exit 2
trap 'exit 1' TERM
/bin/sh -c 'trap "" TERM; printf ready > "$1/ready"; exec sleep 30' child "$1" </dev/null >/dev/null 2>&1 &
printf '%s' "$$" > "$1/group"
wait "$!"
`, "leader-first-fixture", dir)
	}()
	waitHostFixtureFile(t, filepath.Join(dir, "ready"))
	groupText := waitHostFixtureFile(t, filepath.Join(dir, "group"))
	group, err := strconv.Atoi(string(groupText))
	if err != nil || group <= 1 {
		t.Fatalf("invalid fixture process group: %q", groupText)
	}
	// The inherited lock pins the surviving fixture group if the regression
	// returns; cleanup cannot target a subsequently reused, unrelated group.
	t.Cleanup(func() {
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); errors.Is(err, unix.EWOULDBLOCK) {
			_ = unix.Kill(-group, unix.SIGKILL)
		}
	})
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("fixture did not acquire its inherited lock: %v", err)
	}
	started := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("leader exit waited for the full cancellation grace")
	}
	for time.Since(started) < 3*time.Second {
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return
		} else if !errors.Is(err, unix.EWOULDBLOCK) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("TERM-ignoring descendant retained the maintenance lock after its leader exited")
}

func waitHostFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) != 0 {
			return data
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("host fixture did not publish %s", filepath.Base(path))
	return nil
}

func TestHostModesRequireRootBeforeObservationsOrMutation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("exercise the unprivileged entry point")
	}
	for _, mode := range []string{"bootstrap-record", "bootstrap-commit", "worker", "network", "reboot", "poweroff", "retry-reset", "retry-start"} {
		if err := runHost(context.Background(), mode, applianceconsole.Collector{}); err == nil {
			t.Fatalf("unprivileged host mode %s accepted", mode)
		}
	}
}

func TestHostCommandFailureIsCoarseAndCancellationBounded(t *testing.T) {
	err := hostCommand(context.Background(), "/bin/sh", "-c", "printf PRIVATE_OUTPUT_CANARY >&2; exit 7")
	if err == nil || !strings.Contains(err.Error(), "exit 7") || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("unexpected failure evidence: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = hostCommand(ctx, "/bin/sh", "-c", "sleep 60 & wait")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second {
		t.Fatalf("host process group did not stop promptly: %v", err)
	}
}

func TestBootObservationsPreservePreviousIdentity(t *testing.T) {
	s := appliancehost.Session{State: appliancehost.State{Version: 1}, Identity: appliancehost.Identity{Boot: "before", Machine: "stable"}, Save: func(appliancehost.State) error { return nil }}
	snapshot := applianceconsole.Snapshot{Firstboot: map[string]string{"ActiveState": "failed", "SubState": "failed", "Result": "exit-code", "ExecMainStatus": "1"}}
	if err := observeBoot(&s, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := observeBoot(&s, snapshot); err != nil {
		t.Fatal(err)
	}
	if len(s.State.Records) != 1 {
		t.Fatal("unchanged observation consumed history")
	}
	s.Identity.Boot = "after"
	if err := observeBoot(&s, snapshot); err != nil {
		t.Fatal(err)
	}
	if len(s.State.Records) != 2 || s.State.Records[0].Boot != "before" || s.State.Records[1].Boot != "after" || s.State.Records[0].Machine != s.State.Records[1].Machine {
		t.Fatal("boot identity continuity lost")
	}
}
