package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// IM-022: the generation store and its collector take their directory fsync
// from internal/fileutil. Both must bind the STRICT form: a generations
// directory that cannot be opened is a failed sync, not a skipped one.
// Binding either to a best-effort sync (open failure swallowed) fails here.
func TestSaaSFeedDirSyncBinding_UnopenableDirectoryIsAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	for name, syncDir := range map[string]func(string) error{
		"generation store": osGenFS().syncDir,
		"collector":        osGCFS().syncDir,
	} {
		if err := syncDir(missing); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: syncDir(missing dir) = %v, want the open error", name, err)
		}
		if err := syncDir(t.TempDir()); err != nil {
			t.Errorf("%s: syncDir(existing dir) = %v, want nil", name, err)
		}
	}
}
