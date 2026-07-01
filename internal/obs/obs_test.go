package obs

import (
	"sync"
	"testing"
)

func TestSetSink_RoutesAndOverrides(t *testing.T) {
	// Capture lines through a custom sink; verify Printf/Warnf route to it and
	// that SetSink replaces the destination atomically.
	var mu sync.Mutex
	var got []string
	SetSink(func(line string) { mu.Lock(); got = append(got, line); mu.Unlock() })
	t.Cleanup(func() { SetSink(nil) }) // nil is ignored; leaves last sink in place

	Printf("hello %s", "world")
	Warnf("careful %d", 7)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("got %d lines, want 2: %v", len(got), got)
	}
	if got[0] != "hello world" {
		t.Errorf("Printf line = %q, want %q", got[0], "hello world")
	}
	if got[1] != "WARN careful 7" {
		t.Errorf("Warnf line = %q, want %q", got[1], "WARN careful 7")
	}
}

func TestSetSink_NilIgnored(t *testing.T) {
	// A nil sink must be ignored (not panic, not blank the destination).
	hits := 0
	SetSink(func(string) { hits++ })
	t.Cleanup(func() { SetSink(nil) })
	SetSink(nil) // must be a no-op
	Printf("x")
	if hits != 1 {
		t.Fatalf("nil SetSink must not replace the live sink; hits=%d want 1", hits)
	}
}

func TestSanitize_StripsControlBytes(t *testing.T) {
	// CWE-117: every C0 control byte and DEL must be replaced; printable UTF-8
	// content must survive. Mirrors the package main sanitizeLog contract.
	in := "ok\x00nul\x07bel\x1besc\x7fdel line\nbreak\r\tother"
	got := Sanitize(in)
	for i := 0; i < len(got); i++ {
		if c := got[i]; c < 0x20 || c == 0x7F {
			t.Fatalf("Sanitize leaked control byte 0x%02X at %d: %q", c, i, got)
		}
	}
	if !contains(got, "ok") || !contains(got, "other") {
		t.Fatalf("Sanitize dropped printable content: %q", got)
	}
}

func TestSanitize_FastPathUnchanged(t *testing.T) {
	in := "GET /api/policy HTTP/1.1 host=example.com"
	if got := Sanitize(in); got != in {
		t.Fatalf("control-free string mutated: got %q want %q", got, in)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
