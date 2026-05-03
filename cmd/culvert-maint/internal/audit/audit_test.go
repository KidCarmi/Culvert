package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNew_CreatesParentDirAndFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "subdir", "audit.jsonl")
	l, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = l.Close() }()

	if _, err := os.Stat(p); err != nil {
		t.Fatalf("audit log file missing: %v", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o640 {
		t.Errorf("audit file mode: got %o want 0640", mode)
	}
}

func TestWrite_AppendsValidJSONLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = l.Close() }()

	ev := Event{
		Actor:   "uid=1000,user=test",
		OpID:    "01J0X3F",
		Kind:    "test.kind",
		Outcome: OutcomeStarted,
	}
	if err := l.Write(ev); err != nil {
		t.Fatalf("Write: %v", err)
	}
	t2 := time.Now().UTC()
	ev2 := Event{
		Actor:     "uid=1000,user=test",
		OpID:      "01J0X3F",
		Kind:      "test.kind",
		Outcome:   OutcomeSucceeded,
		OutcomeAt: &t2,
	}
	if err := l.Write(ev2); err != nil {
		t.Fatalf("Write: %v", err)
	}

	body, err := os.ReadFile(p) //nolint:gosec // test temp path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), string(body))
	}
	for i, line := range lines {
		var got Event
		if jerr := json.Unmarshal([]byte(line), &got); jerr != nil {
			t.Fatalf("line %d not valid JSON: %v\n%q", i, jerr, line)
		}
	}
}

func TestWrite_RejectsRequiredFieldMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = l.Close() }()

	cases := []Event{
		{OpID: "x", Kind: "k", Outcome: OutcomeStarted},  // no actor
		{Actor: "a", Kind: "k", Outcome: OutcomeStarted}, // no op_id
		{Actor: "a", OpID: "x", Outcome: OutcomeStarted}, // no kind
		{Actor: "a", OpID: "x", Kind: "k"},               // no outcome
	}
	for i, c := range cases {
		if err := l.Write(c); err == nil {
			t.Errorf("case %d: expected error for missing required field, got nil", i)
		}
	}
}

func TestWrite_NoSecretsInOutput(t *testing.T) {
	// Build an event whose params include only references and benign
	// values. We assert the JSON does NOT contain any of the strings
	// callers would mistakenly use for raw secrets.
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = l.Close() }()

	if err := l.Write(Event{
		Actor:   "uid=0,user=culvert-cp",
		OpID:    "01J0",
		Kind:    "backup.create",
		Outcome: OutcomeStarted,
		Params: map[string]interface{}{
			"encrypt":        true,
			"passphrase_ref": "env:CULVERT_BACKUP_PASSPHRASE",
			"filename":       "culvert-2026-05-03.tar.gz.enc",
		},
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	body, _ := os.ReadFile(p) //nolint:gosec // test temp path
	for _, banned := range []string{"correct-horse-battery-staple", "hunter2", "passphrase\":\"env"} {
		// Only check that we never serialise a known plaintext sample.
		// passphrase_ref serialisation is the legit form: "passphrase_ref": "env:..."
		if strings.Contains(string(body), banned) {
			t.Errorf("audit output unexpectedly contains %q", banned)
		}
	}
	// Positive: passphrase_ref reference IS present.
	if !strings.Contains(string(body), "passphrase_ref") {
		t.Errorf("audit output missing passphrase_ref")
	}
}

func TestRecent_ReturnsLastNInOrder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Write(Event{
			Actor:   "a",
			OpID:    "id-x",
			Kind:    "k",
			Outcome: OutcomeStarted,
			Params:  map[string]interface{}{"i": i},
		}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	_ = l.Close()

	got, err := Recent(p, 3)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 events, got %d", len(got))
	}
	// Last three should have i=2,3,4
	for j, want := range []float64{2, 3, 4} {
		gotI := got[j].Params["i"].(float64) //nolint:errcheck // JSON decodes ints as float64
		if gotI != want {
			t.Errorf("event[%d].i: got %v want %v", j, gotI, want)
		}
	}
}

func TestRecent_EmptyAndMissingFile(t *testing.T) {
	// Missing → nil, no error.
	got, err := Recent(filepath.Join(t.TempDir(), "no-such.jsonl"), 5)
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if got != nil {
		t.Errorf("missing file: want nil, got %v", got)
	}

	// Empty → nil, no error.
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(p, nil, 0o600); err != nil { //nolint:gosec // test temp path
		t.Fatalf("write: %v", err)
	}
	got, err = Recent(p, 5)
	if err != nil {
		t.Fatalf("empty file should not error: %v", err)
	}
	if got != nil {
		t.Errorf("empty file: want nil, got %v", got)
	}
}

func TestRecent_HandlesPartialTrailingLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	// Two complete events + a malformed half-line at the end.
	body := "" +
		`{"ts":"2026-05-03T00:00:00Z","actor":"a","op_id":"1","kind":"k","outcome":"started","params":{}}` + "\n" +
		`{"ts":"2026-05-03T00:00:01Z","actor":"a","op_id":"2","kind":"k","outcome":"started","params":{}}` + "\n" +
		`{"ts":"2026-05-03T00:00:02Z","actor":"a","op_id":"3","ki` // truncated mid-write
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil { //nolint:gosec // test temp path
		t.Fatalf("write: %v", err)
	}
	got, err := Recent(p, 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 valid events (ignoring partial trailing), got %d", len(got))
	}
}
