package applianceconsole

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func actionFixture() (actions Actions, recorded *[][]string) {
	calls := [][]string{}
	a := NewActions(ActionDependencies{Authorized: func() bool { return true }, Collect: func(context.Context) Snapshot { return retrySnapshot("failed") },
		Run: func(args []string) error { calls = append(calls, args); return nil }, Confirm: func(string) (string, error) { return "RETRY", nil }, Out: io.Discard})
	return a, &calls
}

func retrySnapshot(state string) Snapshot {
	return Snapshot{Firstboot: map[string]string{"LoadState": "loaded", "ActiveState": state}, Steps: []Step{{ID: "complete", State: "not_recorded"}}}
}

func TestActionsRequireEffectiveIdentity(t *testing.T) {
	a, calls := actionFixture()
	a.deps.Authorized = func() bool { return false }
	for _, choice := range []string{"1", "2", "4", "5", "6", "7"} {
		if a.Apply(context.Background(), choice) == nil {
			t.Fatal("unauthenticated action accepted")
		}
	}
	if len(*calls) != 0 {
		t.Fatal("command dispatched")
	}
}

func TestRetryRejectsRunningUnknownAndComplete(t *testing.T) {
	for _, state := range []string{"active", "activating", "unknown", ""} {
		a, calls := actionFixture()
		a.deps.Collect = func(context.Context) Snapshot { return Snapshot{Firstboot: map[string]string{"ActiveState": state}} }
		if a.Apply(context.Background(), "4") == nil || len(*calls) != 0 {
			t.Errorf("retry accepted %s", state)
		}
	}
	a, calls := actionFixture()
	a.deps.Collect = func(context.Context) Snapshot {
		return Snapshot{Firstboot: map[string]string{"ActiveState": "inactive"}, Steps: []Step{{ID: "complete", State: "recorded"}}}
	}
	if a.Apply(context.Background(), "4") == nil || len(*calls) != 0 {
		t.Fatal("completed provisioning rerun")
	}
}

func TestRetryRechecksAfterConfirmation(t *testing.T) {
	a, calls := actionFixture()
	count := 0
	a.deps.Collect = func(context.Context) Snapshot {
		count++
		state := "failed"
		if count > 1 {
			state = "active"
		}
		return retrySnapshot(state)
	}
	if a.Apply(context.Background(), "4") == nil || len(*calls) != 0 {
		t.Fatal("state change ignored")
	}
}

func TestRetryUsesStartNotRestartAndHonorsSudoFailure(t *testing.T) {
	a, calls := actionFixture()
	if err := a.Apply(context.Background(), "4"); err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/sudo", "--", "/opt/culvert-appliance/bin/culvert-console", "--host=retry-start"}
	if len(*calls) != 2 || !reflect.DeepEqual((*calls)[1], want) {
		t.Fatalf("wrong commands %v", *calls)
	}
	a, calls = actionFixture()
	a.deps.Run = func(args []string) error { *calls = append(*calls, args); return errors.New("sudo refused") }
	if a.Apply(context.Background(), "4") == nil || len(*calls) != 1 {
		t.Fatal("sudo failure ignored")
	}
}

func TestRetryRechecksAfterClearingFailure(t *testing.T) {
	for _, change := range []string{"running", "complete", "unknown", "unloaded", "marker_unknown", "identity"} {
		t.Run(change, func(t *testing.T) {
			a, calls := actionFixture()
			s := retrySnapshot("failed")
			authorized := true
			a.deps.Authorized = func() bool { return authorized }
			a.deps.Collect = func(context.Context) Snapshot { return s }
			a.deps.Run = func(args []string) error {
				*calls = append(*calls, args)
				switch change {
				case "running":
					s.Firstboot["ActiveState"] = "activating"
				case "complete":
					s.Steps[0].State = "recorded"
				case "unknown":
					s.Firstboot = nil
				case "unloaded":
					s.Firstboot["LoadState"] = "not-found"
				case "marker_unknown":
					s.Steps[0].State = "unknown"
				case "identity":
					authorized = false
				}
				return nil
			}
			if err := a.Apply(context.Background(), "4"); err == nil || len(*calls) != 1 {
				t.Fatalf("start dispatched after %s: calls=%v err=%v", change, *calls, err)
			}
		})
	}
}

func TestConfirmationCannotInjectCommands(t *testing.T) {
	for _, choice := range []string{"4", "5"} {
		a, calls := actionFixture()
		a.deps.Confirm = func(string) (string, error) { return "REBOOT; anything", nil }
		if err := a.Apply(context.Background(), choice); err != nil {
			t.Fatal(err)
		}
		if len(*calls) != 0 {
			t.Fatal("inexact confirmation accepted")
		}
	}
	for _, answer := range []string{"REBOOT", "POWEROFF"} {
		a, calls := actionFixture()
		a.deps.Confirm = func(string) (string, error) { return answer, nil }
		if err := a.Apply(context.Background(), "5"); err != nil {
			t.Fatal(err)
		}
		if len(*calls) != 1 || !strings.EqualFold((*calls)[0][3], "--host="+answer) {
			t.Fatal("wrong power action")
		}
	}
}
