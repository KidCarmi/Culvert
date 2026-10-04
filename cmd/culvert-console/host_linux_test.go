//go:build linux

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
	"github.com/KidCarmi/Culvert/internal/appliancehost"
)

func TestHostCommandFailureIsCoarseAndCancellationBounded(t *testing.T) {
	err := hostCommand(context.Background(), "/bin/sh", "-c", "printf PRIVATE_OUTPUT_CANARY >&2; exit 7")
	if err == nil || !strings.Contains(err.Error(), "exit 7") || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("unexpected failure evidence: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = hostCommand(ctx, "/bin/sh", "-c", "sleep 60 & wait")
	if err == nil || time.Since(started) > 3*time.Second {
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
