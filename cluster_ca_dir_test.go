package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The cluster CA is stored beside the cluster state file. A state file
// directly under the filesystem root (e.g. -cluster-db /cluster.json in a
// container) must put the CA in "/", not silently in the working directory.
// legacyClusterCADir keeps the directory earlier releases used, so an
// upgrade can still find a CA they created.
func TestClusterCADir(t *testing.T) {
	cases := []struct{ in, want, legacy string }{
		{"cluster.json", ".", "."},
		{"/data/cluster.json", "/data", "/data"},
		{"data/cluster.json", "data", "data"},
		{"/cluster.json", "/", "."},
	}
	for _, c := range cases {
		if got := clusterCADir(filepath.FromSlash(c.in)); got != filepath.FromSlash(c.want) {
			t.Errorf("clusterCADir(%q) = %q, want %q", c.in, got, c.want)
		}
		if got := legacyClusterCADir(c.in); got != c.legacy {
			t.Errorf("legacyClusterCADir(%q) = %q, want %q", c.in, got, c.legacy)
		}
	}
}

// isolateClusterCAGlobal gives the test a fresh globalClusterCA, restores
// the original afterwards, and pins key-at-rest encryption off so a load
// never migrates (rewrites) the key under test.
func isolateClusterCAGlobal(t *testing.T) {
	t.Helper()
	t.Setenv(clusterCAEncryptEnvVar, "")
	orig := globalClusterCA
	globalClusterCA = &clusterCA{}
	t.Cleanup(func() { globalClusterCA = orig })
}

// seedClusterCADir bootstraps a real CA pair in dir and returns its cert PEM.
func seedClusterCADir(t *testing.T, dir string) []byte {
	t.Helper()
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("seed CA in %s: %v", dir, err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "cluster-ca.crt"))
	if err != nil {
		t.Fatalf("read seeded cert: %v", err)
	}
	return certPEM
}

func loadedClusterCACertPEM(t *testing.T) []byte {
	t.Helper()
	globalClusterCA.mu.RLock()
	defer globalClusterCA.mu.RUnlock()
	if globalClusterCA.cert == nil {
		t.Fatal("no cluster CA loaded")
	}
	return globalClusterCA.certPEM
}

func assertNoClusterCAFiles(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"cluster-ca.crt", "cluster-ca.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s exists in %s (stat err %v); no CA may be created there", name, dir, err)
		}
	}
}

// Upgrade regression: an install whose CA exists only at the legacy
// location must keep that CA (same certificate, key untouched) instead of
// bootstrapping a new one beside the state file, which would orphan every
// enrolled Data Plane's mTLS trust.
func TestInitClusterCA_LegacyDirFallback_KeepsExistingCA(t *testing.T) {
	isolateClusterCAGlobal(t)
	newDir, legacyDir := t.TempDir(), t.TempDir()
	seeded := seedClusterCADir(t, legacyDir)
	keyPath := filepath.Join(legacyDir, "cluster-ca.key")
	if err := os.Chmod(keyPath, 0o400); err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	initClusterCAIn(newDir, legacyDir)

	if got := loadedClusterCACertPEM(t); !bytes.Equal(got, seeded) {
		t.Fatal("loaded a different cluster CA than the one at the legacy location (a new CA was generated)")
	}
	if got := globalClusterCA.KeyDir(); got != filepath.Clean(legacyDir) {
		t.Errorf("CA dir = %q, want legacy %q", got, legacyDir)
	}
	assertNoClusterCAFiles(t, newDir)
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o400 {
		t.Errorf("legacy key mode = %o, want unchanged 0400", perm)
	}
	if keyAfter, err := os.ReadFile(keyPath); err != nil || !bytes.Equal(keyAfter, keyBefore) {
		t.Errorf("legacy key file changed (err %v)", err)
	}
}

// Control: a fresh install (no CA anywhere) bootstraps beside the state file.
func TestInitClusterCA_FreshInstall_GeneratesInNewDir(t *testing.T) {
	isolateClusterCAGlobal(t)
	newDir, legacyDir := t.TempDir(), t.TempDir()

	initClusterCAIn(newDir, legacyDir)

	loaded := loadedClusterCACertPEM(t)
	onDisk, err := os.ReadFile(filepath.Join(newDir, "cluster-ca.crt"))
	if err != nil {
		t.Fatalf("no CA generated in the new dir: %v", err)
	}
	if !bytes.Equal(loaded, onDisk) {
		t.Error("loaded CA differs from the one written to the new dir")
	}
	assertNoClusterCAFiles(t, legacyDir)
}

// Control: once a CA exists beside the state file it wins over a legacy one.
func TestInitClusterCA_NewDirCAWinsOverLegacy(t *testing.T) {
	isolateClusterCAGlobal(t)
	newDir, legacyDir := t.TempDir(), t.TempDir()
	current := seedClusterCADir(t, newDir)
	seedClusterCADir(t, legacyDir)

	initClusterCAIn(newDir, legacyDir)

	if got := loadedClusterCACertPEM(t); !bytes.Equal(got, current) {
		t.Fatal("did not load the CA beside the state file")
	}
}

// A partial pair at the legacy location is still a CA that exists: fail
// closed on it rather than generating a replacement in the new dir.
func TestInitClusterCA_LegacyPartialPair_FailsClosed(t *testing.T) {
	isolateClusterCAGlobal(t)
	newDir, legacyDir := t.TempDir(), t.TempDir()
	seedClusterCADir(t, legacyDir)
	if err := os.Remove(filepath.Join(legacyDir, "cluster-ca.key")); err != nil {
		t.Fatal(err)
	}

	initClusterCAIn(newDir, legacyDir)

	globalClusterCA.mu.RLock()
	loaded := globalClusterCA.cert != nil
	globalClusterCA.mu.RUnlock()
	if loaded {
		t.Error("a CA was loaded or generated despite the partial legacy pair")
	}
	assertNoClusterCAFiles(t, newDir)
}

// End to end through the path derivation: a root-level state file with the
// CA in the working directory (where earlier releases put it) resolves to
// the working directory; with no CA there it resolves to "/". Nothing is
// written; the test only stats "/".
func TestChooseClusterCADir_RootLevelStateFile(t *testing.T) {
	const db = "/cluster.json"
	if filepath.Separator != '/' {
		t.Skip("root-level POSIX path")
	}
	if clusterCAFilePresent("/") {
		t.Skip("host has a cluster CA in /")
	}
	cwd := t.TempDir()
	t.Chdir(cwd)

	if dir, legacy := chooseClusterCADir(clusterCADir(db), legacyClusterCADir(db)); dir != "/" || legacy {
		t.Fatalf("no CA anywhere: got (%q, %v), want (\"/\", false)", dir, legacy)
	}
	seedClusterCADir(t, cwd)
	if dir, legacy := chooseClusterCADir(clusterCADir(db), legacyClusterCADir(db)); dir != "." || !legacy {
		t.Fatalf("CA in working dir: got (%q, %v), want (\".\", true)", dir, legacy)
	}
}

// Control: a nested state path has identical new and legacy dirs, so a CA in
// the working directory is never picked up.
func TestChooseClusterCADir_NestedPathUnaffected(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	seedClusterCADir(t, cwd)
	db := filepath.Join(t.TempDir(), "data", "cluster.json")

	if dir, legacy := chooseClusterCADir(clusterCADir(db), legacyClusterCADir(db)); dir != filepath.Dir(db) || legacy {
		t.Fatalf("got (%q, %v), want (%q, false)", dir, legacy, filepath.Dir(db))
	}
}
