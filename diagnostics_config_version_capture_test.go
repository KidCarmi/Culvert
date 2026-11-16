package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// resetConfigVersionCaptureForTest clears the process-wide capture state now
// and restores the pre-test value at cleanup.
func resetConfigVersionCaptureForTest(t *testing.T) {
	t.Helper()
	configVersionCaptureMu.Lock()
	prev := configVersionCaptureGapState
	configVersionCaptureGapState = configVersionCaptureGap{}
	configVersionCaptureMu.Unlock()
	t.Cleanup(func() {
		configVersionCaptureMu.Lock()
		configVersionCaptureGapState = prev
		configVersionCaptureMu.Unlock()
	})
}

func TestConfigVersionCaptureRows(t *testing.T) {
	if rows := configVersionCaptureRows(configVersionCaptureGap{}); len(rows) != 0 {
		t.Fatalf("latest capture succeeded: want no rows, got %+v", rows)
	}
	since := time.Date(2026, 11, 15, 9, 30, 0, 0, time.UTC)
	rows := configVersionCaptureRows(configVersionCaptureGap{missed: 3, since: since})
	if len(rows) != 1 || rows[0].Code != "config_version_capture" || rows[0].Status != diagWarn || rows[0].OperatorAction == "" {
		t.Fatalf("want one config_version_capture WARN row, got %+v", rows)
	}
	for _, want := range []string{"3 configuration change(s)", "2026-11-15T09:30:00Z", "could not be written"} {
		if !strings.Contains(rows[0].Message, want) {
			t.Errorf("message should contain %q, got %q", want, rows[0].Message)
		}
	}
	refused := configVersionCaptureRows(configVersionCaptureGap{missed: 1, since: since, refused: true})
	if len(refused) != 1 || !strings.Contains(refused[0].OperatorAction, "rewrite_identity") {
		t.Fatalf("a refused capture should point at the rewrite_identity row, got %+v", refused)
	}
}

// A failed write is counted from the first miss, and the next successful
// capture clears the row. The row never carries the error text or a path.
func TestConfigVersionCapture_WriteFailureThenRecovery(t *testing.T) {
	resetConfigVersionCaptureForTest(t)
	origDir, origSeq := configVersions.Dir(), configVersions.Seq()
	t.Cleanup(func() {
		configVersions.SetDirForTest(origDir)
		configVersions.SetSeqForTest(origSeq)
	})
	// A regular file where the directory should be: every version write fails.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	configVersions.SetDirForTest(blocked)

	saveConfigVersion("capture-test", "first-change")
	saveConfigVersion("capture-test", "second-change")
	rows := checkConfigVersionCapture()
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "2 configuration change(s)") {
		t.Fatalf("want one row counting 2 missed captures, got %+v", rows)
	}
	if text := rows[0].Message + rows[0].OperatorAction; strings.Contains(text, blocked) || strings.Contains(text, "not-a-directory") {
		t.Errorf("row must not carry a filesystem path: %q", text)
	}

	configVersions.SetDirForTest(t.TempDir())
	saveConfigVersion("capture-test", "third-change")
	if rows := checkConfigVersionCapture(); len(rows) != 0 {
		t.Fatalf("a successful capture should clear the row, got %+v", rows)
	}
}

func TestConfigVersionCapture_RefusedIsClassified(t *testing.T) {
	resetConfigVersionCaptureForTest(t)
	noteConfigVersionCapture(errors.New("config version write: disk full"))
	noteConfigVersionCapture(errConfigVersionRefused)
	rows := checkConfigVersionCapture()
	if len(rows) != 1 || !strings.Contains(rows[0].Message, "2 configuration change(s)") ||
		!strings.Contains(rows[0].Message, "refused") {
		t.Fatalf("want the latest (refused) cause over 2 missed captures, got %+v", rows)
	}
}
