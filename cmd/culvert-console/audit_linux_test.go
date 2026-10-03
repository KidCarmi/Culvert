//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditPairsEventsWithoutSensitiveErrors(t *testing.T) {
	for _, fail := range []bool{false, true} {
		var events []commandRecord
		sink := func(_ context.Context, record commandRecord) error { events = append(events, record); return nil }
		failure := errors.New("PRIVATE_OUTPUT_MUST_NOT_LOG")
		err := auditCommand(context.Background(), "setup_access", func() error {
			if fail {
				return failure
			}
			return nil
		}, sink, &bytes.Buffer{})
		if fail != errors.Is(err, failure) {
			t.Fatal(err)
		}
		if len(events) != 2 || events[0].ID == "" || events[0].ID != events[1].ID || events[0].Phase != "attempt" || events[1].Phase != "result" {
			t.Fatal(events)
		}
		want := "returned"
		if fail {
			want = "failed"
		}
		if events[1].Outcome != want || events[1].At == "" {
			t.Fatal(events)
		}
		data, marshalErr := json.Marshal(events)
		if marshalErr != nil || strings.Contains(string(data), "PRIVATE") {
			t.Fatal("raw error reached audit")
		}
	}
}

func TestAuditFailureDoesNotRepeatOrSuppressRecovery(t *testing.T) {
	runs := 0
	var warnings bytes.Buffer
	err := auditCommand(context.Background(), "reboot", func() error { runs++; return nil },
		func(context.Context, commandRecord) error { return errors.New("PRIVATE_TRANSPORT_ERROR") }, &warnings)
	if err != nil || runs != 1 || !strings.Contains(warnings.String(), "coverage is incomplete") || strings.Contains(warnings.String(), "PRIVATE") {
		t.Fatal("audit failure changed recovery or leaked error")
	}
}

func TestAuditCancellationBeforeDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []commandRecord
	err := auditCommand(ctx, "retry_start", func() error { t.Fatal("cancelled command ran"); return nil },
		func(ctx context.Context, record commandRecord) error {
			if ctx.Err() != nil {
				t.Fatal("completion audit inherited cancellation")
			}
			events = append(events, record)
			cancel()
			return nil
		}, &bytes.Buffer{})
	if !errors.Is(err, context.Canceled) || len(events) != 2 || events[1].Outcome != "cancelled_before_dispatch" {
		t.Fatal(events, err)
	}
}

func TestJournalDatagramEscapesUntrustedText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	socket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sendJournal(ctx, path, commandRecord{Action: "test\nPRIORITY=0\x00"}); err != nil {
		t.Fatal(err)
	}
	if err := socket.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	n, _, err := socket.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(buffer[:n]), "\n"), "\n")
	if len(lines) != 3 || lines[0] != "PRIORITY=5" || strings.ContainsRune(string(buffer[:n]), 0) {
		t.Fatal(lines)
	}
	var record commandRecord
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[2], "MESSAGE=")), &record); err != nil {
		t.Fatal(err)
	}
	if record.Action != "test\nPRIORITY=0\x00" {
		t.Fatal(record)
	}
}

func TestJournalBackpressureIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	socket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	for range 100 {
		if sendJournal(ctx, path, commandRecord{}) != nil {
			if time.Since(started) > 2*time.Second {
				t.Fatal("journal blocked action")
			}
			return
		}
	}
	t.Fatal("fixture did not reach socket backpressure")
}
