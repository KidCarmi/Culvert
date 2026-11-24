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
		Params: map[string]interface{}{ // #nosec G101 -- test fixture: passphrase_ref is an env-var reference, not a credential
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
		`{"ts":"2026-05-03T00:00:02Z","actor":"a","op_id":"3","ki` // truncated mid-write (no trailing \n)
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

// TestRecent_FailsOnMalformedCompleteLine ensures audit corruption is
// surfaced rather than silently skipped. Tolerated case: torn write
// without a trailing newline. Rejected case: a complete line ending
// with \n that fails JSON decode (real corruption signal).
func TestRecent_FailsOnMalformedCompleteLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	body := "" +
		`{"ts":"2026-05-03T00:00:00Z","actor":"a","op_id":"1","kind":"k","outcome":"started","params":{}}` + "\n" +
		"this-is-not-json-at-all\n" + // complete line — must error
		`{"ts":"2026-05-03T00:00:02Z","actor":"a","op_id":"3","kind":"k","outcome":"started","params":{}}` + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil { //nolint:gosec // test temp path
		t.Fatalf("write: %v", err)
	}
	_, err := Recent(p, 10)
	if err == nil {
		t.Fatal("expected error on malformed complete line — silent skip would hide corruption")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("error should mention 'malformed', got: %v", err)
	}
}

// TestRecent_TailBoundedAcrossBlocks writes far more than the 64 KiB read block
// so Recent must seek backward across multiple blocks and drop the partial
// leading line — the last n events must still come back correct and in order.
func TestRecent_TailBoundedAcrossBlocks(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const total = 2000 // ~150 bytes each ≫ 64 KiB, forcing multi-block backward reads
	for i := 0; i < total; i++ {
		if err := l.Write(Event{
			Actor:   "actor-with-some-length-to-grow-the-line",
			OpID:    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			Kind:    "backup.create",
			Outcome: OutcomeSucceeded,
			Params:  map[string]interface{}{"i": i, "pad": "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
		}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	_ = l.Close()

	got, err := Recent(p, 5)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 events, got %d", len(got))
	}
	// The last five must be i=1995..1999, in order — proving the multi-block
	// tail read + partial-leading-line drop reassembled the tail correctly.
	for j, want := range []float64{1995, 1996, 1997, 1998, 1999} {
		gotI := got[j].Params["i"].(float64) //nolint:errcheck // JSON decodes ints as float64
		if gotI != want {
			t.Errorf("event[%d].i = %v, want %v", j, gotI, want)
		}
	}
}

// TestRecent_TailWindowLargerThanFile: n bigger than the number of events must
// return all events (window reaches the file head, no partial-line drop).
func TestRecent_TailWindowLargerThanFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := New(p)
	for i := 0; i < 3; i++ {
		_ = l.Write(Event{Actor: "a", OpID: "id", Kind: "k", Outcome: OutcomeStarted, Params: map[string]interface{}{"i": i}})
	}
	_ = l.Close()
	got, err := Recent(p, 100)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want all 3 events, got %d", len(got))
	}
	if got[0].Params["i"].(float64) != 0 { //nolint:errcheck // test
		t.Error("first event should be i=0 (window reached file head)")
	}
}

func TestHasSucceeded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if found, err := HasSucceeded(path, "op1", "k:reconciled"); err != nil || found {
		t.Fatalf("missing log: found=%v err=%v, want false, nil", found, err)
	}
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []Event{
		{Actor: "a", OpID: "op1", Kind: "k:reconciled", Outcome: OutcomeFailed},    // wrong outcome
		{Actor: "a", OpID: "op2", Kind: "k:reconciled", Outcome: OutcomeSucceeded}, // other op
		{Actor: "a", OpID: "op1", Kind: "k:other", Outcome: OutcomeSucceeded},      // other kind
	} {
		if err := l.Write(ev); err != nil {
			t.Fatal(err)
		}
	}
	if found, err := HasSucceeded(path, "op1", "k:reconciled"); err != nil || found {
		t.Fatalf("no matching entry yet: found=%v err=%v", found, err)
	}
	if err := l.Write(Event{Actor: "a", OpID: "op1", Kind: "k:reconciled", Outcome: OutcomeSucceeded}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	// A torn final line (crash mid-append) mentioning the op is skipped, not fatal.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"op_id":"op1","kind":"k:reconc`)
	_ = f.Close()
	if found, err := HasSucceeded(path, "op1", "k:reconciled"); err != nil || !found {
		t.Fatalf("matching entry: found=%v err=%v, want true, nil", found, err)
	}
	// An unreadable log is an error, so the caller writes rather than skips.
	if _, err := HasSucceeded(dir, "op1", "k:reconciled"); err == nil {
		t.Error("reading a directory as the log must return an error")
	}
	if _, err := HasSucceeded(path, "", "k"); err == nil {
		t.Error("empty op id must be rejected")
	}
}

// TestFindTerminal: the lookup that makes an operation's terminal audit entry
// idempotent across a crash (ADR-0062 slice 1). Only a terminal outcome under
// the exact op id AND kind counts: "started", an inline rollback's own kind and
// a retirement entry under the same op id never do.
func TestFindTerminal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if ev, err := FindTerminal(path, "op1", "upgrades.apply"); err != nil || ev != nil {
		t.Fatalf("missing log: ev=%v err=%v, want nil, nil", ev, err)
	}
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []Event{
		{Actor: "a", OpID: "op1", Kind: "upgrades.apply", Outcome: OutcomeStarted},
		{Actor: "a", OpID: "op1", Kind: "upgrades.apply:rollback", Outcome: OutcomeFailed, FailureReason: "rollback_failed"},
		{Actor: "a", OpID: "op1", Kind: "upgrades.apply:interrupted_superseded", Outcome: OutcomeSucceeded},
		{Actor: "a", OpID: "op2", Kind: "upgrades.apply", Outcome: OutcomeFailed, FailureReason: "health_failed"},
	} {
		if err := l.Write(ev); err != nil {
			t.Fatal(err)
		}
	}
	if ev, err := FindTerminal(path, "op1", "upgrades.apply"); err != nil || ev != nil {
		t.Fatalf("no terminal entry of op1's own kind yet: ev=%+v err=%v", ev, err)
	}
	if err := l.Write(Event{Actor: "a", OpID: "op1", Kind: "upgrades.apply", Outcome: OutcomeFailed, FailureReason: "health_failed"}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	ev, err := FindTerminal(path, "op1", "upgrades.apply")
	if err != nil || ev == nil || ev.Outcome != OutcomeFailed || ev.FailureReason != "health_failed" {
		t.Fatalf("FindTerminal = %+v, %v; want the failed(health_failed) entry", ev, err)
	}
	if ok, _ := HasSucceeded(path, "op1", "upgrades.apply"); ok { //nolint:errcheck // asserted via ok
		t.Error("HasSucceeded matched a failed entry")
	}
	if _, err := FindTerminal(dir, "op1", "k"); err == nil {
		t.Error("reading a directory as the log must return an error")
	}
	if _, err := FindTerminal(path, "op1", ""); err == nil {
		t.Error("empty kind must be rejected")
	}
}

// TestNew_TerminatesATornTail (Codex review on #2102): a crash during an
// append can leave a partial JSON line without its newline. New ends it, so
// the next entry — e.g. a terminal entry re-written at startup — is its own
// readable line instead of being glued onto the fragment and lost.
func TestNew_TerminatesATornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	torn := `{"ts":"2026-11-24T10:00:00Z","actor":"a","op_id":"op1","kind":"upgrades.apply","outcome":"star` // no newline
	if err := os.WriteFile(path, []byte(`{"ts":"2026-11-24T09:00:00Z","actor":"a","op_id":"op0","kind":"upgrades.apply","outcome":"started"}`+"\n"+torn), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if err := l.Write(Event{Actor: "a", OpID: "op1", Kind: "upgrades.apply", Outcome: OutcomeSucceeded}); err != nil {
		t.Fatal(err)
	}
	ev, err := FindTerminal(path, "op1", "upgrades.apply")
	if err != nil || ev == nil || ev.Outcome != OutcomeSucceeded {
		t.Fatalf("entry written after a torn tail is not readable: ev=%+v err=%v", ev, err)
	}
	// A clean file is left as it is: no stray blank line.
	clean := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(clean, []byte(`{"op_id":"x"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l2, err := New(clean)
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Close()
	if b, _ := os.ReadFile(clean); string(b) != `{"op_id":"x"}`+"\n" { // #nosec G304 -- test temp file
		t.Errorf("a clean log was changed: %q", b)
	}
}
