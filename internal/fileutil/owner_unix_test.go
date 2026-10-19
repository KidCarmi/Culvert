//go:build unix

package fileutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestRewriteInPlace_PreservesOwnerWherePermitted: a privileged process keeps
// the original owner and group; an unprivileged one cannot give a file away,
// so the rewrite still succeeds and the file carries the process's own uid,
// exactly as an AtomicWrite of the same target would.
func TestRewriteInPlace_PreservesOwnerWherePermitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ui_users.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	const otherID = 65534 // nobody/nogroup
	privileged := os.Geteuid() == 0
	if privileged {
		if err := os.Chown(path, otherID, otherID); err != nil {
			t.Fatalf("chown fixture: %v", err)
		}
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := RewriteInPlace(path, []byte("{}"), before); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := after.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no Stat_t on this platform: %T", after.Sys())
	}
	wantUID, wantGID := uint32(os.Geteuid()), uint32(os.Getegid()) // #nosec G115 -- ids are non-negative
	if privileged {
		wantUID, wantGID = otherID, otherID
	}
	if st.Uid != wantUID || st.Gid != wantGID {
		t.Errorf("owner %d:%d after rewrite, want %d:%d (privileged=%v)", st.Uid, st.Gid, wantUID, wantGID, privileged)
	}
}
