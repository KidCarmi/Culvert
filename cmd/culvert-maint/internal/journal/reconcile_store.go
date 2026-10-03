// Reconcile-side journal extensions (RISK-022 PR-E, slice E3):
//
//   - ListQuarantining: the boot-path reader. Unlike List (fail-closed, used
//     by the orchestrator-era wiring), it MOVES ASIDE a record it cannot read
//     and keeps going, so one rotted file can never crash-loop the agent under
//     systemd Restart=. A quarantined record is NEVER acted on (it is renamed
//     out of the live set, surfaced loudly, and left for the operator) — the
//     fail-closed property that matters ("never act on what you cannot read")
//     is preserved; only "refuse to serve at all" is dropped (design §0 P1
//     "quarantine junk records; do not brick boot").
//   - Verdict sidecar: a durable per-op classification written by the startup
//     reconciler beside the record, under <reconcile>/verdicts/<op_id>.json.
//     It lives in a SUBDIRECTORY so the record reader (which keys on the .json
//     suffix) never mistakes a verdict for a record; List/ListQuarantining skip
//     directories.
//   - Quarantined: the list of moved-aside names, so /v1/status can keep the
//     operator's attention on them until they are inspected and removed.
package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	verdictsSubdir   = "verdicts"
	quarantineMarker = ".corrupt."
)

// ListQuarantining returns every readable live record. A record that is
// present but unreadable (malformed JSON, unknown phase, non-ULID name) is
// renamed to <name>.corrupt.<unixnano> and its ORIGINAL name is appended to
// quarantined; the walk continues. Only a readdir failure or a failed rename is
// returned as an error (a rename failure means the unreadable file stays live,
// and the caller must not pretend it was handled).
func (j *Journal) ListQuarantining(now time.Time) (recs []Record, quarantined []string, err error) {
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("journal: readdir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), fileExt) {
			continue
		}
		opID := strings.TrimSuffix(e.Name(), fileExt)
		rec, found, rerr := j.Read(opID)
		if rerr == nil {
			if found {
				recs = append(recs, *rec)
			}
			continue
		}
		if qerr := j.quarantine(e.Name(), now); qerr != nil {
			return nil, quarantined, qerr
		}
		quarantined = append(quarantined, e.Name())
	}
	return recs, quarantined, nil
}

// quarantine renames one live entry out of the record namespace. The suffix is
// a unix-nano stamp (never ".json"), so the moved file is invisible to every
// record reader and cannot collide with a later rename of the same name.
func (j *Journal) quarantine(name string, now time.Time) error {
	src := filepath.Join(j.dir, name)
	dst := src + quarantineMarker + strconv.FormatInt(now.UnixNano(), 10)
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("journal: quarantine %s: %w", name, err)
	}
	return fsyncDir(j.dir)
}

// Quarantined lists the names of every moved-aside file currently in the
// reconcile directory (sorted by os.ReadDir). Empty when none.
func (j *Journal) Quarantined() ([]string, error) {
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("journal: readdir: %w", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.Contains(e.Name(), quarantineMarker) {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// verdictPath builds <reconcile>/verdicts/<op_id>.json, ULID-validated.
func (j *Journal) verdictPath(opID string) (string, error) {
	if _, err := j.pathFor(opID); err != nil {
		return "", err
	}
	return filepath.Join(j.dir, verdictsSubdir, opID+fileExt), nil
}

// WriteVerdict persists an opaque JSON verdict document for opID atomically
// and durably (same writer discipline as Write). The verdicts directory is
// created on first use.
func (j *Journal) WriteVerdict(opID string, v interface{}) error {
	path, err := j.verdictPath(opID)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("journal: mkdir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("journal: marshal verdict: %w", err)
	}
	return atomicWrite(path, data, fileMode)
}

// ReadVerdict decodes opID's verdict into dst. found=false (nil error) when no
// verdict exists; a present-but-unparseable verdict is an error (the caller
// treats it as "no trustworthy verdict" and recomputes).
func (j *Journal) ReadVerdict(opID string, dst interface{}) (found bool, err error) {
	path, err := j.verdictPath(opID)
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is ULID-validated under the verdicts dir
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("journal: read verdict %s: %w", filepath.Base(path), err)
	}
	if uerr := json.Unmarshal(data, dst); uerr != nil {
		return true, fmt.Errorf("%w %s: verdict: %v", ErrCorruptRecord, filepath.Base(path), uerr)
	}
	return true, nil
}

// RemoveVerdict deletes opID's verdict (idempotent) and fsyncs its directory.
func (j *Journal) RemoveVerdict(opID string) error {
	path, err := j.verdictPath(opID)
	if err != nil {
		return err
	}
	if rerr := os.Remove(path); rerr != nil {
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("journal: remove verdict %s: %w", filepath.Base(path), rerr)
	}
	return fsyncDir(filepath.Dir(path))
}
