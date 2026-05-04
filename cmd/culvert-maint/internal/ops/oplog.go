package ops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// OpLog is an append-only writer for the per-operation log file at
// <state_dir>/operations/<op_id>.log. The file is the operator-facing
// transcript for one async operation: GET /v1/operations/{op_id}/logs
// streams it back verbatim. The agent's HTTP path is read-only; the
// orchestrator that runs the op is the sole writer.
//
// DURABILITY: this is a BEST-EFFORT operator transcript, NOT a
// durable audit record. Writes are NOT fsync'd. A torn write at
// agent restart can leave a half-line in the file, and the
// orchestrator is unable to detect or recover from that. Operators
// reading /v1/operations/{op_id}/logs may see a truncated last line.
// For the durable, fsync'd audit-of-record, see audit.jsonl
// (internal/audit) — every state transition the operator cares
// about (started, succeeded, failed, with op_id, kind, actor,
// failure_reason) is recorded there. The op-log is for diagnostic
// stage-by-stage detail (captured stdout/stderr, intermediate
// notes) that would bloat the audit JSONL if recorded with the
// same durability guarantees.
//
// Schema: a free-form append-only text stream, NOT JSON. Each call
// writes a self-contained line prefixed with a UTC RFC3339 timestamp
// and the calling stage name. Truncation is not supported — operators
// rotate or drop log files out of band; the agent cannot reason about
// torn writes anyway.
//
// Mode 0640 matches audit.jsonl. The parent operations/ dir is
// created on demand with mode 0750.
//
// Concurrency: a single OpLog instance is safe for concurrent calls
// from the orchestrator goroutine and (e.g.) a captured-output tee.
// Different ops get different OpLog instances; there is no cross-op
// shared state.
type OpLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// OpenOpLog opens (creating if missing) the per-op log file for opID
// under stateDir/operations/. opID must be a strict ULID. Returns the
// writer and an error; callers MUST Close() when done so the underlying
// file descriptor is released.
//
// The function refuses to traverse outside <stateDir>/operations/ —
// opID is validated as a strict ULID before any path is built, so
// there is no way for a caller to inject ".." or "/".
func OpenOpLog(stateDir, opID string) (*OpLog, error) {
	if stateDir == "" {
		return nil, errors.New("ops: OpenOpLog requires stateDir")
	}
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("ops: stateDir must be absolute")
	}
	if _, err := ulid.ParseStrict(opID); err != nil {
		return nil, fmt.Errorf("ops: OpenOpLog rejected non-ULID op_id %q: %w", opID, err)
	}
	dir := filepath.Join(stateDir, "operations")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("ops: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, opID+".log")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640) //nolint:gosec // path constructed from validated ULID, cannot escape
	if err != nil {
		return nil, fmt.Errorf("ops: open %s: %w", path, err)
	}
	return &OpLog{path: path, f: f}, nil
}

// Path returns the absolute path of the log file. Useful for tests.
func (l *OpLog) Path() string {
	return l.path
}

// Close releases the file descriptor. Safe to call multiple times.
func (l *OpLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// StageStart appends a "stage start" marker for stageName.
func (l *OpLog) StageStart(stageName string) error {
	return l.write(stageName, "START", "")
}

// StageEnd appends a "stage end" marker for stageName with the
// terminal stage state (succeeded/failed) and an optional one-line
// note. note is sanitized: control characters are stripped, and the
// length is capped at 1 KiB so a CLI that vomits megabytes into its
// last error string can't bloat the per-op log.
func (l *OpLog) StageEnd(stageName string, state State, note string) error {
	return l.write(stageName, "END "+string(state), sanitizeOneLine(note, 1024))
}

// Capture appends a multi-line block of captured stdout/stderr from a
// runner Result. Each line is prefixed with the stage name + "out:" or
// "err:". Total bytes captured per call are capped at maxBytes; longer
// streams are truncated with a "...<truncated>..." marker on the last
// line.
//
// Sanitization: NUL and other ASCII control bytes (range 0x00-0x08,
// 0x0B-0x0C, 0x0E-0x1F, plus 0x7F DEL) are REPLACED with '?' — they
// are NOT stripped (that would shift the byte offsets of surrounding
// content and confuse anyone diffing CLI output against the captured
// log). Tab (0x09), newline (0x0A), and CR (0x0D) are preserved so
// the line structure of the captured stream stays intact and `tail
// -f` of the operator log remains readable.
func (l *OpLog) Capture(stageName, stream string, body []byte, maxBytes int) error {
	if len(body) == 0 {
		return nil
	}
	if maxBytes > 0 && len(body) > maxBytes {
		body = append(body[:maxBytes], []byte("\n...<truncated>...")...)
	}
	clean := sanitizeMultiLine(string(body))
	prefix := stageName + " " + stream + ":"
	// Split into lines so each gets the timestamp+prefix; keeps
	// `tail -f` of the operator log readable.
	lines := strings.Split(clean, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		if err := l.write(stageName, stream, line); err != nil {
			return err
		}
		_ = prefix // kept for symmetry; the actual prefix lives in write()
	}
	return nil
}

// Note writes a single free-form line (e.g. "validation OK", "skipped
// stage X because Y"). The body is sanitized to one line and capped at
// 1 KiB.
func (l *OpLog) Note(stageName, body string) error {
	return l.write(stageName, "NOTE", sanitizeOneLine(body, 1024))
}

// write is the single Fprintf path. All public methods funnel here so
// the format stays consistent and the lock scope is small.
func (l *OpLog) write(stageName, kind, body string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return errors.New("ops: OpLog already closed")
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if body == "" {
		_, err := fmt.Fprintf(l.f, "%s\t%s\t%s\n", ts, stageName, kind)
		return err
	}
	_, err := fmt.Fprintf(l.f, "%s\t%s\t%s\t%s\n", ts, stageName, kind, body)
	return err
}

// sanitizeOneLine trims the input to a single line and caps its
// length at maxBytes. Control bytes (other than tab) are REPLACED
// with '?' — they are not stripped, so the log keeps the original
// length structure of the input. Used for human notes / error
// strings — never for raw command output (use sanitizeMultiLine
// instead).
func sanitizeOneLine(s string, maxBytes int) string {
	// Drop everything from the first newline onward so a multi-line
	// error message becomes a single log entry.
	if i := strings.IndexAny(s, "\n\r"); i >= 0 {
		s = s[:i]
	}
	s = replaceCtrl(s)
	if maxBytes > 0 && len(s) > maxBytes {
		s = s[:maxBytes-1] + "…"
	}
	return s
}

// sanitizeMultiLine REPLACES control bytes (except tab/newline/CR)
// with '?', preserving the line structure of captured stdout/stderr.
// "Sanitize" — not "strip"; the byte length of the output equals the
// input.
func sanitizeMultiLine(s string) string {
	return replaceCtrl(s)
}

// replaceCtrl replaces ASCII control bytes (0x00-0x08, 0x0B-0x0C,
// 0x0E-0x1F, 0x7F) with '?'. Tab (0x09) and newline (0x0A) are
// preserved. Carriage return (0x0D) is preserved so caller's
// CRLF-terminated stdout doesn't lose its line endings (we split on
// \n later anyway).
//
// Naming note: this used to be called stripCtrl, but the function
// REPLACES rather than strips — output length equals input length.
// The new name reflects the actual behavior.
func replaceCtrl(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 0x09 || c == 0x0A || c == 0x0D:
			b.WriteByte(c)
		case c < 0x20 || c == 0x7F:
			b.WriteByte('?')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
