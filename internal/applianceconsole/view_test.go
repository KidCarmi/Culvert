package applianceconsole

import (
	"strings"
	"testing"
)

func visualFixture() Snapshot {
	return Snapshot{Hostname: "culvert-demo", Version: "fixture", ObservedAt: "2026-10-04T00:00:00Z", Candidate: true,
		Addresses: []string{"192.0.2.10"}, ManagementURLs: []string{"https://192.0.2.10:9090"},
		Interfaces: []Interface{{Name: "ens160", Link: "UP", Addresses: []string{"192.0.2.10/24"}}},
		Gateway:    "192.0.2.1 (ens160)", DNS: []string{"192.0.2.53"}, SetupStatus: "pending", ManagementAvailable: true,
		Phase: "provisioned", Reason: "SETUP_REQUIRED", Message: "Open setup", Steps: []Step{{ID: "ovf", Label: "Network", State: "recorded"}}}
}

func TestViewOnlyDispatchesAuthenticatedActions(t *testing.T) {
	for _, screen := range []string{"home", "network", "access", "diagnostics", "report", "recovery"} {
		for _, key := range []string{"0", "1", "2", "3", "4", "E", "S", "ENTER", "Q", "EXIT"} {
			v := NewView(false)
			v.screen = screen
			action := v.Handle(key)
			if action != "" && action != "login" && action != "refresh" {
				t.Fatalf("%s/%s dispatched %s", screen, key, action)
			}
		}
	}
	for _, tt := range []struct{ screen, key, action string }{{"access", "S", "2"}, {"network", "E", "7"}, {"recovery", "1", "4"}, {"recovery", "2", "5"}, {"recovery", "3", "6"}, {"recovery", "4", "8"}, {"home", "Q", "logout"}} {
		v := NewView(true)
		v.screen = tt.screen
		if got := v.Handle(tt.key); got != tt.action {
			t.Errorf("%+v got %s", tt, got)
		}
	}
}

func TestSelectionWrapsOnlyVisibleRowsAndNumbersOpen(t *testing.T) {
	v := NewView(false)
	for range 20 {
		v.Handle("UP")
		if v.selected < 1 || v.selected > 4 {
			t.Fatal("invisible selection")
		}
	}
	for range 20 {
		v.Handle("DOWN")
		if v.selected < 1 || v.selected > 4 {
			t.Fatal("invisible selection")
		}
	}
	v.Handle("1")
	if v.screen != "network" {
		t.Fatal("number did not open")
	}
	v.Handle("ESC")
	v.Handle("TAB")
	v.Handle("ENTER")
	if v.screen != "access" {
		t.Fatal("tab/enter did not open selected row")
	}
	v.Handle("B")
	if v.Handle("0") != "login" || v.screen != "home" {
		t.Fatal("public recovery bypass")
	}
}

func TestKeysDoNotInterpretPartialEscapeAsAction(t *testing.T) {
	for _, raw := range []string{"\x1b", "\x1b[12", "\x1b[99~", "\x1b2", "24", "\x1b[200~"} {
		if DecodeKey(raw) != "" {
			t.Fatalf("accepted %q", raw)
		}
	}
	for raw, want := range map[string]string{"\x1b[[B": "F2", "\x1b[12~": "F2", "\x1bOS": "F4", "\x1b[A": "UP", "\x1b[B": "DOWN", "\r": "ENTER", "\t": "TAB"} {
		if DecodeKey(raw) != want {
			t.Errorf("%q", raw)
		}
	}
}

func TestLayoutMatrixFitsAndKeepsSelection(t *testing.T) {
	for _, size := range [][2]int{{25, 80}, {24, 80}, {12, 40}, {7, 20}, {1, 1}} {
		for _, screen := range []string{"home", "network", "access", "diagnostics", "report", "recovery"} {
			v := NewView(true)
			v.screen = screen
			s := visualFixture()
			s.Hostname = strings.Repeat("x", 253) + "\x1b[2J"
			s.Message = strings.Repeat("bad", 100)
			rows := v.Frame(s, size[0], size[1])
			if len(rows) >= size[0] {
				t.Fatal("scrolling at bottom margin")
			}
			for _, row := range rows {
				if len(row.Text) >= size[1] || strings.ContainsRune(row.Text, '\x1b') {
					t.Fatalf("unsafe/overflow row: %q", row.Text)
				}
			}
			if screen == "home" && size[0] >= 7 && !strings.Contains(Render(rows, false), "> [2]") {
				t.Fatal("selected row hidden")
			}
		}
	}
}

func TestSetupLabelRequiresLocalEndpointAndNoBroadReadyLabel(t *testing.T) {
	s := visualFixture()
	v := NewView(false)
	text := Render(v.Frame(s, 25, 80), false)
	if !strings.Contains(text, "[SETUP AVAILABLE]") || strings.Contains(text, "[READY]") {
		t.Fatal(text)
	}
	s.ManagementAvailable = false
	text = Render(v.Frame(s, 25, 80), false)
	if strings.Contains(text, "https://") || strings.Contains(text, "SETUP AVAILABLE") {
		t.Fatal("address implied listener readiness")
	}
	s.ManagementAvailable = true
	s.Phase = "failed"
	label, _, _ := headline(s)
	if !strings.Contains(label, "BLOCKED") {
		t.Fatal("failure did not win")
	}
}

func TestStoppingProvisioningIsNotLabeledStarting(t *testing.T) {
	s := provisionedSnapshot()
	s.Firstboot["ActiveState"] = "deactivating"
	s.Addresses = []string{"192.0.2.10"}
	s.summarize("", "", "")
	v := NewView(false)
	text := Render(v.Frame(s, 25, 80), false)
	if !strings.Contains(text, "[STOPPING]") || strings.Contains(text, "[STARTING]") {
		t.Fatal(text)
	}
}

func TestReportLongFieldsCanBeReadAcrossPages(t *testing.T) {
	s := visualFixture()
	s.Hostname = strings.Repeat("abcdef", 30) + "END"
	v := NewView(false)
	v.screen = "report"
	seen := ""
	for range 40 {
		seen += Render(v.Frame(s, 12, 40), false)
		v.Handle("PAGEDOWN")
	}
	if !strings.Contains(seen, "END") || !strings.Contains(seen, "NOT VERIFIED") {
		t.Fatal("long report inaccessible")
	}
	for range 40 {
		v.Handle("PAGEUP")
	}
	if v.offset != 0 {
		t.Fatal("cannot return to start")
	}
}

func TestRenderSanitizesBeforeApplyingKnownColors(t *testing.T) {
	rows := []Row{{Text: "bad\x1b[2J\nvalue", Style: "cyan"}, {Text: "text", Style: "\x1b[2J"}}
	plain := Render(rows, false)
	if strings.ContainsRune(plain, '\x1b') {
		t.Fatal("terminal injection")
	}
	color := Render(rows, true)
	if strings.Contains(color, "\x1b[2J") || !strings.Contains(color, "\x1b[36m") {
		t.Fatal("unsafe color")
	}
}
