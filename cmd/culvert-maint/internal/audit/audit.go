// Package audit writes append-only audit events to audit.jsonl with the
// stable schema documented in roadmap/D1.6-maintenance-agent-
// implementation-plan.md § 4.8.
//
// The schema is locked from D1.6a; future slices may add optional fields
// but cannot rename or remove existing ones. Secrets never appear in
// audit — params carry secret references only (e.g.
// "passphrase_ref": "env:CULVERT_BACKUP_PASSPHRASE").
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Outcome captures terminal state of an operation request, plus an
// admission marker.
type Outcome string

// Outcome values are part of the stable audit schema (D1.6 plan § 4.8).
const (
	OutcomeStarted   Outcome = "started"
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeCancelled Outcome = "cancelled"
)

// Event is the on-disk shape. Field ordering is for human grep-ability;
// JSON encoding does not depend on field order.
type Event struct {
	TS             time.Time              `json:"ts"`
	Actor          string                 `json:"actor"`
	OpID           string                 `json:"op_id"`
	Kind           string                 `json:"kind"`
	Params         map[string]interface{} `json:"params"`
	Outcome        Outcome                `json:"outcome"`
	OutcomeAt      *time.Time             `json:"outcome_at,omitempty"`
	FailureReason  string                 `json:"failure_reason,omitempty"`
	IdempotencyKey string                 `json:"idempotency_key,omitempty"`
}

// Logger is a goroutine-safe append-only writer over audit.jsonl.
type Logger struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// New opens (or creates) an audit log at path. The parent directory is
// created if missing. File mode is 0640. Returns the Logger or an error.
func New(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil { //nolint:gosec // 0750 is intentional for state dir
		return nil, fmt.Errorf("audit: mkdir parent of %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640) // #nosec G302 -- 0640 is the documented audit mode
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &Logger{path: path, f: f}, nil
}

// Path returns the audit log path.
func (l *Logger) Path() string {
	return l.path
}

// Close releases the file handle.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// Write appends an event. The TS field is set to time.Now().UTC() if
// zero. The event is fsynced before Write returns.
func (l *Logger) Write(ev Event) error {
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	if ev.OpID == "" || ev.Kind == "" || ev.Actor == "" || ev.Outcome == "" {
		return fmt.Errorf("audit: required fields missing (op_id=%q kind=%q actor=%q outcome=%q)",
			ev.OpID, ev.Kind, ev.Actor, ev.Outcome)
	}
	if ev.Params == nil {
		ev.Params = map[string]interface{}{}
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return fmt.Errorf("audit: logger closed")
	}
	if _, err := l.f.Write(line); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("audit: sync: %w", err)
	}
	return nil
}

// Recent reads the last n events from path. Used by GET /v1/audit.
// Returns events in chronological order (oldest first within the
// returned window).
//
// The read is TAIL-BOUNDED: it seeks from EOF and reads only enough
// trailing blocks to cover the last n lines, so the endpoint's allocation
// is O(n events), NOT O(file size). Without this a long-lived agent's
// unbounded audit.jsonl would allocate the whole file per /v1/audit call
// and eventually OOM the agent. Corruption detection stays intact for the
// complete lines WITHIN the window (a full-file integrity scan was never
// the purpose of a "recent N" tail read).
func Recent(path string, n int) ([]Event, error) {
	if n <= 0 {
		return nil, nil
	}
	f, err := os.Open(path) // #nosec G304 -- agent state dir, owner-controlled
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	tail, err := tailBytes(f, n)
	if err != nil {
		return nil, fmt.Errorf("audit: read %s: %w", path, err)
	}
	events, err := parseTail(tail, n)
	if err != nil {
		return nil, fmt.Errorf("audit: parse %s: %w", path, err)
	}
	return events, nil
}

// tailBytes returns a byte slice containing at least the last n newline-
// terminated lines of f, read by seeking backward from EOF in blocks so the
// whole file is never loaded. If the accumulated window does not start at the
// file head, its leading partial line (a mid-file cut) is dropped so parseTail
// never sees a fragment as a "complete" (corrupt) line.
func tailBytes(f *os.File, n int) ([]byte, error) {
	const block = 64 * 1024
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	var buf []byte
	newlines := 0
	pos := size
	for pos > 0 && newlines <= n {
		readSize := int64(block)
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		chunk := make([]byte, readSize)
		if _, rerr := f.ReadAt(chunk, pos); rerr != nil && rerr != io.EOF {
			return nil, rerr
		}
		buf = append(chunk, buf...)
		newlines = bytes.Count(buf, []byte{'\n'})
	}
	// Dropped only when we stopped before the file head: the first line in the
	// window was cut mid-record and is not a torn trailing write.
	if pos > 0 {
		if idx := bytes.IndexByte(buf, '\n'); idx >= 0 {
			buf = buf[idx+1:]
		}
	}
	return buf, nil
}

// parseTail parses a JSONL byte buffer and returns the last n events,
// or an error if a complete line fails to decode (audit corruption).
//
// Tolerated: a malformed *trailing* line that has no terminating
// newline — that's the expected shape during a torn write. Such a line
// is silently dropped.
//
// Rejected: any complete line (one that ends with \n) that fails JSON
// decode. Audit corruption is a real signal and silently skipping
// would hide tampering or filesystem damage. The caller surfaces the
// error to the operator.
func parseTail(data []byte, n int) ([]Event, error) {
	var events []Event
	start := 0
	lineNum := 0
	for i := 0; i < len(data); i++ {
		if data[i] != '\n' {
			continue
		}
		lineNum++
		if i > start {
			var ev Event
			if jerr := json.Unmarshal(data[start:i], &ev); jerr != nil {
				// Complete line (terminated with \n) that fails decode
				// is corruption — fail closed.
				return nil, fmt.Errorf("audit: malformed line %d: %w", lineNum, jerr)
			}
			events = append(events, ev)
		}
		start = i + 1
	}
	if start < len(data) {
		// Trailing line without terminating newline. Expected shape
		// during a torn write; tolerate by silently dropping if it
		// fails decode. Successfully-decoded trailing line is admitted.
		var ev Event
		if jerr := json.Unmarshal(data[start:], &ev); jerr == nil {
			events = append(events, ev)
		}
	}
	if len(events) > n {
		events = events[len(events)-n:]
	}
	return events, nil
}
