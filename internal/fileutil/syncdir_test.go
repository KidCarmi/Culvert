package fileutil

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// IM-022: one owner for the directory-fsync rule. These gates pin the rule
// against frozen copies of the code it replaced, so a later edit to the
// shared rule that changes what any former copy returned fails here.

// frozenRootFsyncDir is the decision half of root's fsyncDir exactly as it
// stood on main c5674f200 (saas_feed_genstore.go), with the opened handle
// passed in. Do not edit: it is the oracle.
func frozenRootFsyncDir(d dirHandle) error {
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil && !frozenIsBenignDirSyncErr(syncErr) {
		return syncErr
	}
	if closeErr != nil && syncErr == nil {
		return closeErr
	}
	return nil
}

// frozenIsBenignDirSyncErr is root's isBenignDirSyncErr from the same
// revision. Do not edit.
func frozenIsBenignDirSyncErr(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP)
}

// frozenSyncDirTolerant is the decision half of this package's
// syncDirTolerant as it stood on main c5674f200. Do not edit.
func frozenSyncDirTolerant(d dirHandle) error {
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil &&
		!errors.Is(syncErr, syscall.EINVAL) &&
		!errors.Is(syncErr, syscall.ENOTSUP) &&
		!errors.Is(syncErr, syscall.EOPNOTSUPP) {
		return syncErr
	}
	if syncErr == nil && closeErr != nil {
		return closeErr
	}
	return nil
}

type fakeDir struct {
	syncErr, closeErr error
	synced, closed    int
}

func (f *fakeDir) Sync() error  { f.synced++; return f.syncErr }
func (f *fakeDir) Close() error { f.closed++; return f.closeErr }

func dirSyncOutcomes() map[string]error {
	return map[string]error{
		"nil":                nil,
		"EINVAL":             syscall.EINVAL,
		"ENOTSUP":            syscall.ENOTSUP,
		"EOPNOTSUPP":         syscall.EOPNOTSUPP,
		"EIO":                syscall.EIO,
		"ENOSPC":             syscall.ENOSPC,
		"EROFS":              syscall.EROFS,
		"EBADF":              syscall.EBADF,
		"path EINVAL":        &os.PathError{Op: "sync", Path: "d", Err: syscall.EINVAL},
		"path ENOTSUP":       &os.PathError{Op: "sync", Path: "d", Err: syscall.ENOTSUP},
		"path EIO":           &os.PathError{Op: "sync", Path: "d", Err: syscall.EIO},
		"wrapped EOPNOTSUPP": fmt.Errorf("sync: %w", syscall.EOPNOTSUPP),
		"opaque":             errors.New("boom"),
		"closed":             os.ErrClosed,
	}
}

// TestIM022_SyncRuleMatchesBothFrozenCopies runs every (sync, close) pair
// through the shared rule and both frozen copies. The returned error must be
// the identical value (not merely equal text), and the handle must be synced
// and closed exactly once.
func TestIM022_SyncRuleMatchesBothFrozenCopies(t *testing.T) {
	outcomes := dirSyncOutcomes()
	pairs := 0
	for sn, se := range outcomes {
		for cn, ce := range outcomes {
			pairs++
			got := &fakeDir{syncErr: se, closeErr: ce}
			gotErr := syncAndClose(got)
			if got.synced != 1 || got.closed != 1 {
				t.Errorf("sync=%s close=%s: synced %d closed %d, want 1 and 1", sn, cn, got.synced, got.closed)
			}
			if want := frozenRootFsyncDir(&fakeDir{syncErr: se, closeErr: ce}); gotErr != want {
				t.Errorf("sync=%s close=%s: got %v, root fsyncDir returned %v", sn, cn, gotErr, want)
			}
			if want := frozenSyncDirTolerant(&fakeDir{syncErr: se, closeErr: ce}); gotErr != want {
				t.Errorf("sync=%s close=%s: got %v, syncDirTolerant returned %v", sn, cn, gotErr, want)
			}
		}
	}
	if pairs != len(outcomes)*len(outcomes) || pairs < 190 {
		t.Fatalf("compared %d pairs", pairs)
	}
}

// TestIM022_SyncRuleVerdicts states the rule in the open, so the differential
// test above cannot pass merely because rule and oracle drifted together.
func TestIM022_SyncRuleVerdicts(t *testing.T) {
	closeBoom := errors.New("close boom")
	for _, tc := range []struct {
		name            string
		syncErr, closeE error
		want            error
	}{
		{"both fine", nil, nil, nil},
		{"real sync failure is returned", syscall.EIO, nil, syscall.EIO},
		{"real sync failure wins over close", syscall.EIO, closeBoom, syscall.EIO},
		{"close failure after a good sync is returned", nil, closeBoom, closeBoom},
		{"unsupported sync is success", syscall.EINVAL, nil, nil},
		{"unsupported sync hides the close error", syscall.ENOTSUP, closeBoom, nil},
		{"unsupported sync, EOPNOTSUPP", syscall.EOPNOTSUPP, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := syncAndClose(&fakeDir{syncErr: tc.syncErr, closeErr: tc.closeE}); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIM022_DirSyncUnsupported(t *testing.T) {
	for name, err := range dirSyncOutcomes() {
		want := strings.Contains(name, "EINVAL") || strings.Contains(name, "ENOTSUP") || strings.Contains(name, "EOPNOTSUPP")
		if got := DirSyncUnsupported(err); got != want {
			t.Errorf("%s: DirSyncUnsupported = %v, want %v", name, got, want)
		}
	}
}

// TestIM022_OpenFailureIsTheCallersDecision is the one real difference between
// the former copies, and the reason they were not blindly merged: the strict
// form returns the open error unwrapped (the generation store fails the
// persist), the tolerant form reports success (the data is already in place).
func TestIM022_OpenFailureIsTheCallersDecision(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")

	err := SyncDir(missing)
	var pe *fs.PathError
	if !errors.As(err, &pe) || !errors.Is(err, fs.ErrNotExist) || pe.Op != "open" || pe.Path != missing {
		t.Fatalf("SyncDir(missing) = %#v, want the *PathError os.Open returned", err)
	}
	_, openErr := os.Open(missing)
	if err.Error() != openErr.Error() {
		t.Fatalf("SyncDir wrapped the open error: %q vs %q", err, openErr)
	}
	if got := syncDirTolerant(missing); got != nil {
		t.Fatalf("syncDirTolerant(missing) = %v, want nil", got)
	}
	// WriteFileExclusive's seam still resolves to the tolerant form.
	if got := exclusiveSyncDir(missing); got != nil {
		t.Fatalf("exclusiveSyncDir(missing) = %v, want nil", got)
	}
}

func TestIM022_SyncDirOnRealDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "entry"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SyncDir(dir); err != nil {
		t.Fatalf("SyncDir = %v", err)
	}
	if err := syncDirTolerant(dir); err != nil {
		t.Fatalf("syncDirTolerant = %v", err)
	}
}

// syncDirFileViolations is the boundary for syncdir.go: the rule is a leaf
// over the standard library, holds no package-level variable (so no test seam
// and no shared state can be added to it quietly) and has no init.
func syncDirFileViolations(name string, source []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return []string{err.Error()}
	}
	allowed := map[string]bool{"errors": true, "os": true, "syscall": true}
	var v []string
	for _, imp := range f.Imports {
		if p := strings.Trim(imp.Path.Value, `"`); !allowed[p] {
			v = append(v, "dependency: "+p)
		}
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
			v = append(v, "implicit initialization")
		}
		if g, ok := decl.(*ast.GenDecl); ok && g.Tok == token.VAR {
			for _, s := range g.Specs {
				for _, n := range s.(*ast.ValueSpec).Names {
					v = append(v, "package state: "+n.Name)
				}
			}
		}
	}
	return v
}

func TestIM022_SyncDirBoundary(t *testing.T) {
	src, err := os.ReadFile("syncdir.go")
	if err != nil {
		t.Fatal(err)
	}
	if got := syncDirFileViolations("syncdir.go", src); len(got) != 0 {
		t.Fatalf("syncdir.go: %v", got)
	}
	// The errno set has one owner in this package: no other production file
	// may spell it again.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || n == "syncdir.go" {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		if strings.Contains(string(b), "syscall.EOPNOTSUPP") {
			t.Errorf("%s spells the unsupported-directory-fsync codes again; use DirSyncUnsupported", n)
		}
	}
	if checked < 3 {
		t.Fatalf("inspected %d other production files", checked)
	}
}

func TestIM022_SyncDirBoundary_RejectsRegressions(t *testing.T) {
	for name, src := range map[string]string{
		"root import":    `package fileutil; import "github.com/KidCarmi/Culvert"`,
		"sibling import": `package fileutil; import "github.com/KidCarmi/Culvert/internal/obs"`,
		"logging":        `package fileutil; import "log"`,
		"test seam":      "package fileutil; var openDir = os.Open",
		"package state":  "package fileutil; var synced int",
		"implicit init":  "package fileutil; func init() {}",
	} {
		t.Run(name, func(t *testing.T) {
			if len(syncDirFileViolations("r.go", []byte(src))) == 0 {
				t.Fatal("boundary accepted regression")
			}
		})
	}
	ok := `package fileutil; import ("errors"; "os"; "syscall"); func f() { _ = errors.Is; _ = os.Open; _ = syscall.EINVAL }`
	if got := syncDirFileViolations("ok.go", []byte(ok)); len(got) != 0 {
		t.Fatalf("the allowed imports were rejected: %v", got)
	}
}
