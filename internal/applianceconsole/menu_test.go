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
	a := NewActions(ActionDependencies{Authorized: func() bool { return true }, Collect: func(context.Context) Snapshot { return Snapshot{Firstboot: map[string]string{"ActiveState": "failed"}} },
		Run: func(args []string) error { calls = append(calls, args); return nil }, Confirm: func(string) (string, error) { return "RETRY", nil }, Out: io.Discard})
	return a, &calls
}

func TestActionsRequireEffectiveIdentity(t *testing.T) {
	a, calls := actionFixture()
	a.deps.Authorized = func() bool { return false }
	for _, choice := range []string{"1", "2", "4", "5", "6"} {
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
		return Snapshot{Firstboot: map[string]string{"ActiveState": state}}
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
	want := []string{"/usr/bin/sudo", "--", "/usr/bin/systemctl", "start", "--no-block", "culvert-firstboot.service"}
	if len(*calls) != 2 || !reflect.DeepEqual((*calls)[1], want) {
		t.Fatalf("wrong commands %v", *calls)
	}
	a, calls = actionFixture()
	a.deps.Run = func(args []string) error { *calls = append(*calls, args); return errors.New("sudo refused") }
	if a.Apply(context.Background(), "4") == nil || len(*calls) != 1 {
		t.Fatal("sudo failure ignored")
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
		if len(*calls) != 1 || !strings.EqualFold((*calls)[0][3], answer) {
			t.Fatal("wrong power action")
		}
	}
}
