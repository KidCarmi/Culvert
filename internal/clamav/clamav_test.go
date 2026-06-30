package clamav

import (
	"strings"
	"testing"
	"time"
)

func TestParseClamResponse_OK(t *testing.T) {
	name, found, err := parseClamResponse("stream: OK")
	if err != nil || found || name != "" {
		t.Errorf("parseClamResponse OK: got name=%q found=%v err=%v", name, found, err)
	}
}

func TestParseClamResponse_Found(t *testing.T) {
	name, found, err := parseClamResponse("stream: Eicar-Test-Signature FOUND")
	if err != nil {
		t.Errorf("parseClamResponse FOUND error: %v", err)
	}
	if !found {
		t.Error("parseClamResponse FOUND: expected found=true")
	}
	if name != "Eicar-Test-Signature" {
		t.Errorf("parseClamResponse FOUND name = %q, want Eicar-Test-Signature", name)
	}
}

func TestParseClamResponse_Error(t *testing.T) {
	_, _, err := parseClamResponse("stream: Access denied ERROR")
	if err == nil {
		t.Error("parseClamResponse ERROR: expected error")
	}
}

func TestParseClamResponse_Empty(t *testing.T) {
	_, _, err := parseClamResponse("")
	if err == nil {
		t.Error("parseClamResponse empty: expected error")
	}
}

func TestParseClamResponse_Unexpected(t *testing.T) {
	_, _, err := parseClamResponse("unexpected response")
	if err == nil {
		t.Error("parseClamResponse unexpected: expected error")
	}
}

// Q10: ClamAV connection failure.
func TestClient_ScanConnectionRefused(t *testing.T) {
	c := New("tcp:127.0.0.1:19999") // port that's not listening
	c.timeout = 500 * time.Millisecond
	_, _, err := c.Scan([]byte("test"))
	if err == nil {
		t.Fatal("expected connection error for unreachable daemon")
	}
	if !strings.Contains(err.Error(), "connect") {
		t.Errorf("expected connect error, got: %v", err)
	}
}

// Q10: parseClamResponse with FOUND but no "stream: " prefix (malformed).
func TestParseClamResponse_MalformedFound(t *testing.T) {
	// Has " FOUND" suffix but no ": " separator → returns "Unknown".
	name, found, err := parseClamResponse("virus FOUND")
	if err != nil {
		t.Errorf("malformed FOUND should not error, got: %v", err)
	}
	if !found {
		t.Error("should still detect FOUND suffix")
	}
	if name != "Unknown" {
		t.Errorf("malformed FOUND should return 'Unknown', got %q", name)
	}
}

// FuzzParseClamResponse ensures the ClamAV response parser never panics on
// malformed or truncated daemon output.
func FuzzParseClamResponse(f *testing.F) {
	seeds := []string{
		"stream: OK",
		"stream: Eicar-Test-Signature FOUND",
		"stream: ERROR",
		"stdin: Win.Test.EICAR_HDB-1 FOUND",
		"",
		"FOUND",
		"OK",
		": FOUND",
		"stream: some.virus.name FOUND",
		"stream: \x00\xff FOUND",
		"a: b: FOUND",
		"stream: OK\nstream: FOUND",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, resp string) {
		_, _, _ = parseClamResponse(resp)
	})
}
