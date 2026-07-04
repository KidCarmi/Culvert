package clamav

import (
	"context"
	"net"
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

// ── VERSION parsing + protocol ──────────────────────────────────────────────

func TestParseClamVersion_FullReply(t *testing.T) {
	v := parseClamVersion("ClamAV 0.103.8/26982/Wed Apr 12 09:30:00 2023")
	if v.Engine != "ClamAV 0.103.8" {
		t.Errorf("Engine = %q, want %q", v.Engine, "ClamAV 0.103.8")
	}
	if v.DBVersion != "26982" {
		t.Errorf("DBVersion = %q, want 26982", v.DBVersion)
	}
	if v.DBDate != "Wed Apr 12 09:30:00 2023" {
		t.Errorf("DBDate = %q, want the build date", v.DBDate)
	}
	if v.Raw != "ClamAV 0.103.8/26982/Wed Apr 12 09:30:00 2023" {
		t.Errorf("Raw not preserved: %q", v.Raw)
	}
}

func TestParseClamVersion_EngineOnly(t *testing.T) {
	v := parseClamVersion("ClamAV 0.103.8")
	if v.Engine != "ClamAV 0.103.8" {
		t.Errorf("Engine = %q", v.Engine)
	}
	if v.DBVersion != "" || v.DBDate != "" {
		t.Errorf("engine-only reply must leave DB fields empty, got %q/%q", v.DBVersion, v.DBDate)
	}
}

func TestParseClamVersion_EngineAndDBOnly(t *testing.T) {
	v := parseClamVersion("ClamAV 1.0.0/27000")
	if v.Engine != "ClamAV 1.0.0" || v.DBVersion != "27000" {
		t.Errorf("got Engine=%q DBVersion=%q, want ClamAV 1.0.0 / 27000", v.Engine, v.DBVersion)
	}
	if v.DBDate != "" {
		t.Errorf("DBDate should be empty with no third field, got %q", v.DBDate)
	}
}

func TestClient_Version_MockDaemon(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close() //nolint:errcheck // test cleanup
		buf := make([]byte, 32)
		if _, rerr := conn.Read(buf); rerr != nil {
			return
		}
		_, _ = conn.Write([]byte("ClamAV 0.103.8/26982/Wed Apr 12 09:30:00 2023\x00"))
	}()

	c := New("tcp:" + ln.Addr().String())
	c.timeout = 2 * time.Second
	v, err := c.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v.Engine != "ClamAV 0.103.8" || v.DBVersion != "26982" {
		t.Errorf("parsed %+v, want engine ClamAV 0.103.8 / db 26982", v)
	}
}

func TestClient_Version_ConnectionRefused(t *testing.T) {
	c := New("tcp:127.0.0.1:19998")
	c.timeout = 500 * time.Millisecond
	if _, err := c.Version(); err == nil {
		t.Fatal("expected connection error for unreachable daemon")
	}
}
