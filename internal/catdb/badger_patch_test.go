package catdb

// badger_patch_test.go — the scanner fixes in third_party/badger (see its
// CULVERT-PATCH.md) are behaviour, not just CodeQL shape: a hostile or
// damaged file name is "not a table" instead of a fatal AssertTrue, and a
// log argument cannot start a new log line.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/table"
)

func TestBadgerFork_TableFileIDIsUnsigned32(t *testing.T) {
	for name, want := range map[string]struct {
		id uint64
		ok bool
	}{
		"000001.sst":     {1, true},
		"4294967294.sst": {4294967294, true},
		"4294967295.sst": {0, false}, // MaxUint32 is reserved by blockCacheKey
		// Upstream: Atoi accepts "-1", then y.AssertTrue(id >= 0) is log.Fatalf.
		"-1.sst":         {0, false},
		"4294967296.sst": {0, false}, // would not fit the 4-byte block-cache key
		"abc.sst":        {0, false},
		"000001.vlog":    {0, false},
	} {
		id, ok := table.ParseFileID(name)
		if id != want.id || ok != want.ok {
			t.Errorf("ParseFileID(%q) = (%d, %v), want (%d, %v)", name, id, ok, want.id, want.ok)
		}
	}
}

type captureLogger struct{ lines []string }

func (c *captureLogger) add(f string, v ...interface{}) {
	c.lines = append(c.lines, fmt.Sprintf(f, v...))
}
func (c *captureLogger) Errorf(f string, v ...interface{})   { c.add(f, v...) }
func (c *captureLogger) Warningf(f string, v ...interface{}) { c.add(f, v...) }
func (c *captureLogger) Infof(f string, v ...interface{})    { c.add(f, v...) }
func (c *captureLogger) Debugf(f string, v ...interface{})   { c.add(f, v...) }

func TestBadgerFork_LogArgumentsCannotForgeLines(t *testing.T) {
	c := &captureLogger{}
	opt := badger.DefaultOptions("").WithLogger(c)
	key := "evil.example\nbadger ERROR: forged\r"
	opt.Errorf("Unable to read: Key: %v", key)
	opt.Warningf("w %s", key)
	opt.Infof("i %s", key)
	opt.Debugf("d %s", key)
	if len(c.lines) != 4 {
		t.Fatalf("got %d lines, want 4", len(c.lines))
	}
	for _, l := range c.lines {
		if strings.ContainsAny(l, "\r\n") {
			t.Errorf("CR/LF reached the logger: %q", l)
		}
		if !strings.Contains(l, `evil.example\nbadger ERROR: forged\r`) {
			t.Errorf("escaped value not preserved (the log must still name the key): %q", l)
		}
	}
}

// A memtable id becomes the WAL's uint32 fid. Upstream parsed it as 64 bits
// and truncated (4294967297 opened as fid 1); the fork refuses the name.
func TestBadgerFork_MemtableIDOutOfRangeIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "4294967297.mem"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := badger.Open(badger.DefaultOptions(dir).WithLogger(nil))
	if err == nil {
		_ = db.Close()
		t.Fatal("opened a store whose memtable id does not fit the WAL fid")
	}
	if !strings.Contains(err.Error(), "Unable to parse log id") {
		t.Fatalf("unexpected error: %v", err)
	}
}
