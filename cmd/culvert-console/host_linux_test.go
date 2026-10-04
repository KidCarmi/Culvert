//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
	"github.com/KidCarmi/Culvert/internal/appliancehost"
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

func TestHostModesRequireRootBeforeObservationsOrMutation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("exercise the unprivileged entry point")
	}
	for _, mode := range []string{"worker", "network", "reboot", "poweroff", "retry-reset", "retry-start"} {
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
