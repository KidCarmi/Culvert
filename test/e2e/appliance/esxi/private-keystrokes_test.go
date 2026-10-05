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
