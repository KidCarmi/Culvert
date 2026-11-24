package catgroup

import (
	"os"
	"path/filepath"
	"testing"
)

// Load must tell "there is no file" (a first run: nil, empty store) from "there
// is a file and it could not be used" (an error). The second used to be
// reported as the first whenever the READ failed, so a groups file the process
// could not read left an empty store and no error.
func TestLoad_DistinguishesAMissingFileFromAnUnusableOne(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := New().Load(filepath.Join(dir, "absent.json")); err != nil {
		t.Errorf("a missing file is a first run and must load as empty: %v", err)
	}
	if err := New().Load(""); err != nil {
		t.Errorf("no path configured must load as empty: %v", err)
	}
	// A path that exists but cannot be read as a file. A directory is used
	// because permission bits do not stop root, which CI runs as.
	asDir := filepath.Join(dir, "is-a-directory.json")
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := New().Load(asDir); err == nil {
		t.Error("an unreadable groups path was reported as a first run")
	}
	for label, body := range map[string]string{
		"corrupt JSON":            `{"schema_version":1,"groups":[`,
		"newer envelope schema":   `{"schema_version":2,"version":1,"groups":[]}`,
		"negative stored version": `{"schema_version":1,"version":-1,"groups":[]}`,
	} {
		s := New()
		if err := s.Load(write(label+".json", body)); err == nil {
			t.Errorf("%s: loaded without error", label)
		}
		if n := len(s.List()); n != 0 {
			t.Errorf("%s: %d group(s) installed from an unusable file", label, n)
		}
	}
	good := New()
	if err := good.Load(write("good.json", `{"schema_version":1,"version":3,"groups":[{"id":"g1","name":"g","categories":["News"]}]}`)); err != nil {
		t.Errorf("a well-formed file failed to load: %v", err)
	}
	if n := len(good.List()); n != 1 {
		t.Errorf("a well-formed file installed %d group(s), want 1", n)
	}
}
