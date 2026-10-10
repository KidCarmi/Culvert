//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
)

func TestBootstrapReadOnlyNavigationKeepsPAMBoundary(t *testing.T) {
	d := menuDisplay{password: viewFixtureCredential, view: applianceconsole.NewView(false)}
	for _, tt := range []struct{ key, heading, privileged string }{
		{"1", "NETWORK / OBSERVED STATE", "E"},
		{"2", "SETUP ACCESS / BROWSER HANDOFF", "S"},
		{"3", "DIAGNOSE READINESS", ""},
		{"4", "INSTALLATION REPORT", ""},
		{"F4", "DIAGNOSE READINESS", ""},
	} {
		if action := d.handle(tt.key); action != "" || !d.bootstrapDetail {
			t.Fatalf("public navigation %s returned %q", tt.key, action)
		}
		frame := applianceconsole.Render(d.view.Frame(applianceconsole.Snapshot{}, 25, 80), false)
		if !strings.Contains(frame, tt.heading) || strings.Contains(frame, viewFixtureCredential) {
			t.Fatalf("wrong public detail view for %s", tt.key)
		}
		if tt.privileged != "" && d.handle(tt.privileged) != "login" {
			t.Fatalf("%s bypassed PAM or hid sign-in", tt.privileged)
		}
		if d.handle("B") != "" || d.bootstrapDetail {
			t.Fatal("Back did not restore credential panel")
		}
	}
	if d.handle("R") != "refresh" || d.handle("L") != "login" || d.handle("F2") != "login" {
		t.Fatal("refresh/sign-in unavailable at bootstrap")
	}
	for _, key := range []string{"0", "Q", "EXIT", "S", "E", "ENTER"} {
		if action := d.handle(key); action != "" {
			t.Fatalf("bootstrap dispatch %s = %s", key, action)
		}
	}
}

func TestBootstrapPublicDetailsNeverDispatchPrivilegedActions(t *testing.T) {
	keys := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "E", "S", "Q", "EXIT", "ENTER", "UP", "DOWN", "TAB", "PAGEUP", "PAGEDOWN", "F4", "B", "ESC", "R", "L", "F2"}
	for _, screen := range []string{"1", "2", "3", "4"} {
		for _, key := range keys {
			t.Run(screen+"/"+key, func(t *testing.T) {
				// Recreate the public state for every key: navigation in one
				// case must not change the authorization surface of another.
				d := menuDisplay{password: viewFixtureCredential, view: applianceconsole.NewView(false)}
				if action := d.handle(screen); action != "" || !d.bootstrapDetail {
					t.Fatalf("public detail setup returned %q", action)
				}
				switch action := d.handle(key); action {
				case "", "refresh", "login":
				default:
					t.Fatalf("pre-login detail dispatched forbidden action %q", action)
				}
			})
		}
	}
}
