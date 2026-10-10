//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// No argv, input, output or raw errors are included in the audit schema.
type commandRecord struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	Phase   string `json:"phase"`
	Outcome string `json:"outcome"`
	UID     int    `json:"uid"`
	At      string `json:"at"`
}

type recordSink func(context.Context, commandRecord) error

func auditCommand(ctx context.Context, name string, run func() error, sink recordSink, warnings io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	record := commandRecord{ID: rand.Text(), Action: name, Phase: "attempt", UID: os.Geteuid()}
	reportRecord(ctx, record, sink, warnings)
	if err := ctx.Err(); err != nil {
		record.Phase, record.Outcome = "result", "cancelled_before_dispatch"
		reportRecord(context.WithoutCancel(ctx), record, sink, warnings)
		return err
	}
	err := run()
	record.Phase, record.Outcome = "result", "returned"
	switch {
	case ctx.Err() != nil:
		record.Outcome = "cancelled"
	case err != nil:
		record.Outcome = "failed"
	}
	// Bound completion logging independently, including after cancellation.
	reportRecord(context.WithoutCancel(ctx), record, sink, warnings)
	return err
}

func reportRecord(parent context.Context, record commandRecord, sink recordSink, warnings io.Writer) {
	ctx, cancel := context.WithTimeout(parent, 300*time.Millisecond)
	defer cancel()
	record.At = time.Now().UTC().Format(time.RFC3339Nano)
	if sink(ctx, record) != nil {
		// Recovery stays available when journald is unavailable. Do not suggest a
		// retry: a result record may fail after a command has already succeeded.
		_, _ = fmt.Fprintln(warnings, "Console audit delivery unavailable; journal coverage is incomplete.")
	}
}

func journalRecord(ctx context.Context, record commandRecord) error {
	return sendJournal(ctx, "/run/systemd/journal/socket", record)
}

func sendJournal(ctx context.Context, path string, record commandRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode console audit: %w", err)
	}
	// JSON escapes controls; only fixed field names precede its single-line value.
	payload := append([]byte("PRIORITY=5\nSYSLOG_IDENTIFIER=culvert-console\nMESSAGE="), data...)
	payload = append(payload, '\n')
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unixgram", path)
	if err != nil {
		return fmt.Errorf("connect console journal: %w", err)
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(300 * time.Millisecond)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("bound console journal write: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write console journal: %w", err)
	}
	return nil
}
