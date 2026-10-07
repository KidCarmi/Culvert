//go:build esxi_keyboard_tool

package main

import "testing"

func TestRedrawIsExactlyControlL(t *testing.T) {
	events, err := keys(keyboardInput{Code: "KEY_CTRL_L"})
	if err != nil || len(events) != 1 {
		t.Fatalf("redraw event count/error: %d %v", len(events), err)
	}
	event := events[0]
	if event.UsbHidCode != 0x0f0007 || event.Modifiers == nil ||
		event.Modifiers.LeftControl == nil || !*event.Modifiers.LeftControl ||
		event.Modifiers.LeftShift == nil || *event.Modifiers.LeftShift {
		t.Fatal("redraw must be one unshifted Control-L event")
	}
}

func TestOtherKeysNeverAcquireControlModifier(t *testing.T) {
	for _, input := range []keyboardInput{{Code: "KEY_ENTER"}, {Code: "KEY_F2"}, {Text: "lL"}} {
		events, err := keys(input)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if event.Modifiers.LeftControl != nil && *event.Modifiers.LeftControl {
				t.Fatal("ordinary key acquired Control")
			}
		}
	}
}

func TestRedrawDoesNotAllowOtherControlKeys(t *testing.T) {
	for _, input := range []keyboardInput{{Code: "KEY_CTRL_C"}, {Code: "KEY_CTRL_D"},
		{Code: "KEY_CTRL_L", Text: "x"}, {Text: "\x0c"}} {
		if _, err := keys(input); err == nil {
			t.Fatal("unsupported control input accepted")
		}
	}
}

func TestVisualKeysAreExactSingleEvents(t *testing.T) {
	for _, item := range []struct {
		name string
		code int32
		alt  bool
	}{
		{"KEY_ESC", 0x290007, false}, {"KEY_ALT_F12", 0x450007, true}, {"KEY_ALT_F1", 0x3a0007, true},
	} {
		events, err := keys(keyboardInput{Code: item.name})
		if err != nil || len(events) != 1 {
			t.Fatalf("key %s: %v", item.name, err)
		}
		e := events[0]
		if e.UsbHidCode != item.code || e.Modifiers == nil {
			t.Fatal("wrong event")
		}
		alt := e.Modifiers.LeftAlt != nil && *e.Modifiers.LeftAlt
		if alt != item.alt || (e.Modifiers.LeftControl != nil && *e.Modifiers.LeftControl) || *e.Modifiers.LeftShift {
			t.Fatal("wrong modifier")
		}
	}
	for _, input := range []keyboardInput{{Code: "KEY_ALT_F2"}, {Code: "KEY_ESC", Text: "x"}} {
		if _, err := keys(input); err == nil {
			t.Fatal("unapproved visual input")
		}
	}
}
