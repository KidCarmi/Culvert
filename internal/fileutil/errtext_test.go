package fileutil

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// A write error must not carry a raw CR/LF from the path — neither in the
// quoted path nor in the wrapped *os.PathError — or a logged error could forge
// a log line (CWE-117). The original cause must stay reachable via errors.Is.
func TestWriteErrors_EscapeControlCharsInPath(t *testing.T) {
	dir := t.TempDir() + string(filepath.Separator) + "missing\nINJECTED\r"
	path := filepath.Join(dir, "cfg.json")

	for name, write := range map[string]func() error{
		"AtomicWrite":        func() error { return AtomicWrite(path, []byte("x"), 0o600) },
		"WriteFileExclusive": func() error { return WriteFileExclusive(path, []byte("x"), 0o600) },
	} {
		err := write()
		if err == nil {
			t.Fatalf("%s: want an error writing under a missing directory", name)
		}
		if msg := err.Error(); strings.ContainsAny(msg, "\r\n") {
			t.Errorf("%s: error text carries a raw CR/LF: %q", name, msg)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: errors.Is(err, fs.ErrNotExist) = false; the wrapped cause was lost: %v", name, err)
		}
	}
}
