package applianceconsole

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestPublicMenuCannotDispatchRecovery(t *testing.T) {
	for _, key := range []string{"1", "3", "5", "6", "Q", "EXIT", "REBOOT"} {
		if choice := Choice(key, false); choice != "" {
			t.Errorf("public key %s became %s", key, choice)
		}
	}
	for _, key := range []string{"2", "F2"} {
		if Choice(key, false) != "login" {
			t.Fatal("missing login")
		}
	}
	if Choice("4", false) != "diagnostics" || Choice("4", true) != "4" {
		t.Fatal("wrong privilege boundary")
	}
}

func TestFunctionKeysAndMalformedEscapes(t *testing.T) {
	for _, raw := range []string{"\x1b[[B", "\x1bOQ", "\x1b[12~"} {
		if DecodeKey(raw) != "F2" {
			t.Errorf("%q", raw)
		}
	}
	for _, raw := range []string{"\x1b[[D", "\x1bOS", "\x1b[14~"} {
		if DecodeKey(raw) != "F4" {
			t.Errorf("%q", raw)
		}
	}
	for _, raw := range []string{"\x1b", "\x1b[12", "\x1b[99~", "\x1b2", "24", "\n"} {
		if DecodeKey(raw) != "" {
			t.Errorf("accepted %q", raw)
		}
	}
	if DecodeKey("q") != "Q" || Choice("EXIT", true) != "logout" {
		t.Fatal("logout missing")
	}
}

func TestDisplayFitsVGAKeepsActionsAndSanitizes(t *testing.T) {
	s := Snapshot{Version: "test\x1b[2J", Message: "hello", Firstboot: map[string]string{}, Steps: []Step{}}
	for range 30 {
		s.Steps = append(s.Steps, Step{ID: "x", Label: strings.Repeat("z", 100), State: "recorded"})
	}
	for _, size := range [][2]int{{25, 80}, {8, 20}, {1, 1}} {
		lines := Display(s, true, false, size[0], size[1])
		if len(lines) >= size[0] {
			t.Fatal("screen overflow")
		}
		for _, line := range lines {
			if len(line) >= size[1] || strings.Contains(line, "\x1b") {
				t.Fatal("unsafe rendering")
			}
		}
		if size[0] == 25 && !strings.Contains(strings.Join(lines, "\n"), "[Q] Log out") {
			t.Fatal("actions clipped")
		}
	}
}

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
