// Package filetxn provides recoverable all-old/all-new publication for a
// small set of files. Callers serialize transactions and publish memory only
// after Commit succeeds.
package filetxn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

const formatVersion = 1

var ErrSimulatedCrash = errors.New("simulated file transaction crash")

type Write struct {
	Path string
	Data []byte
	Mode fs.FileMode
}

type artifact struct {
	Path         string      `json:"path"`
	BeforeExists bool        `json:"before_exists"`
	BeforeMode   fs.FileMode `json:"before_mode,omitempty"`
	Before       []byte      `json:"before,omitempty"`
	BeforeSHA256 string      `json:"before_sha256,omitempty"`
	AfterSHA256  string      `json:"after_sha256"`
	AfterMode    fs.FileMode `json:"after_mode"`
}

type record struct {
	Format    int        `json:"format"`
	Kind      string     `json:"kind"`
	Committed bool       `json:"committed"`
	Files     []artifact `json:"files"`
	Checksum  string     `json:"checksum"`
}

type boundaryHook func(string) error

type options struct{ hook boundaryHook }

type Option func(*options)

func WithBoundaryHook(h func(string) error) Option {
	return func(o *options) { o.hook = h }
}

type Txn struct {
	journal string
	writes  []Write
	record  record
	hook    boundaryHook
}

func Begin(journalPath, kind string, writes []Write, opts ...Option) (*Txn, error) {
	if journalPath == "" || kind == "" || len(writes) == 0 {
		return nil, errors.New("file transaction requires journal, kind, and writes")
	}
	journalPath, err := filepath.Abs(filepath.Clean(journalPath))
	if err != nil {
		return nil, fmt.Errorf("resolve journal path: %w", err)
	}
	if _, err := os.Stat(journalPath); err == nil {
		if err := Recover(journalPath); err != nil {
			return nil, fmt.Errorf("recover prior transaction: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat journal: %w", err)
	}

	cfg := options{}
	for _, opt := range opts {
		opt(&cfg)
	}
	t := &Txn{journal: journalPath, writes: make([]Write, len(writes)), hook: cfg.hook}
	t.record = record{Format: formatVersion, Kind: kind, Files: make([]artifact, len(writes))}
	seen := make(map[string]struct{}, len(writes))
	for i, write := range writes {
		if write.Path == "" || write.Mode.Perm() == 0 {
			return nil, fmt.Errorf("invalid write %d", i)
		}
		path, err := filepath.Abs(filepath.Clean(write.Path))
		if err != nil {
			return nil, fmt.Errorf("resolve artifact %d path: %w", i, err)
		}
		if path == journalPath {
			return nil, fmt.Errorf("artifact path collides with journal: %q", path)
		}
		if _, ok := seen[path]; ok {
			return nil, fmt.Errorf("duplicate artifact path %q", path)
		}
		seen[path] = struct{}{}
		candidate := append([]byte(nil), write.Data...)
		t.writes[i] = Write{Path: path, Data: candidate, Mode: write.Mode}
		a := artifact{Path: path, AfterSHA256: digest(candidate), AfterMode: write.Mode.Perm()}
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			info, statErr := os.Stat(path)
			if statErr != nil {
				return nil, fmt.Errorf("stat artifact %s: %w", path, statErr)
			}
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("artifact %s is not a regular file", path)
			}
			a.BeforeExists, a.Before, a.BeforeMode, a.BeforeSHA256 = true, data, info.Mode().Perm(), digest(data)
		case errors.Is(err, os.ErrNotExist):
		default:
			return nil, fmt.Errorf("snapshot artifact %s: %w", path, err)
		}
		t.record.Files[i] = a
	}
	if err := t.writeRecord(); err != nil {
		return nil, err
	}
	if err := t.boundary("after-journal"); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Txn) Apply() error {
	for i, write := range t.writes {
		if err := t.boundary(fmt.Sprintf("before-write-%d", i)); err != nil {
			return t.handleApplyError(err)
		}
		if err := durableWrite(write.Path, write.Data, write.Mode); err != nil {
			return t.handleApplyError(fmt.Errorf("write artifact %s: %w", write.Path, err))
		}
		if err := t.boundary(fmt.Sprintf("after-write-%d", i)); err != nil {
			return t.handleApplyError(err)
		}
	}
	return nil
}

func (t *Txn) Commit() error {
	if err := t.boundary("before-commit"); err != nil {
		return t.handleApplyError(err)
	}
	t.record.Committed = true
	if err := t.writeRecord(); err != nil {
		t.record.Committed = false
		return errors.Join(err, t.Abort())
	}
	return t.boundary("after-commit")
}

func (t *Txn) Abort() error {
	t.record.Committed = false
	if err := t.writeRecord(); err != nil {
		return fmt.Errorf("mark transaction uncommitted: %w", err)
	}
	if err := restore(t.record.Files); err != nil {
		return err
	}
	return durableRemove(t.journal)
}

func (t *Txn) Finish() error {
	if !t.record.Committed {
		return errors.New("finish uncommitted file transaction")
	}
	if err := t.boundary("before-finish"); err != nil {
		return err
	}
	return durableRemove(t.journal)
}

func Recover(journalPath string, opts ...Option) error {
	data, err := os.ReadFile(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read journal: %w", err)
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return fmt.Errorf("parse journal: %w", err)
	}
	if rec.Format != formatVersion || rec.Kind == "" || len(rec.Files) == 0 {
		return errors.New("invalid file transaction journal")
	}
	wantChecksum, err := recordChecksum(rec)
	if err != nil || !validDigest(rec.Checksum) || rec.Checksum != wantChecksum {
		return errors.New("file transaction journal checksum mismatch")
	}
	seen := make(map[string]struct{}, len(rec.Files))
	for _, a := range rec.Files {
		if a.Path == "" || !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path || !validDigest(a.AfterSHA256) || a.AfterMode.Perm() == 0 {
			return errors.New("invalid file transaction artifact")
		}
		if a.BeforeExists {
			if a.BeforeMode.Perm() == 0 || !validDigest(a.BeforeSHA256) || digest(a.Before) != a.BeforeSHA256 {
				return fmt.Errorf("invalid before-image for %s", a.Path)
			}
		} else if a.BeforeMode.Perm() != 0 || len(a.Before) != 0 || a.BeforeSHA256 != "" {
			return fmt.Errorf("unexpected before-image for missing artifact %s", a.Path)
		}
		if _, ok := seen[a.Path]; ok {
			return fmt.Errorf("duplicate journal artifact %q", a.Path)
		}
		seen[a.Path] = struct{}{}
	}
	if rec.Committed {
		for _, a := range rec.Files {
			current, err := os.ReadFile(a.Path)
			if err != nil {
				return fmt.Errorf("verify committed artifact %s: %w", a.Path, err)
			}
			if digest(current) != a.AfterSHA256 {
				return fmt.Errorf("committed artifact digest mismatch: %s", a.Path)
			}
			info, err := os.Stat(a.Path)
			if err != nil {
				return fmt.Errorf("stat committed artifact %s: %w", a.Path, err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != a.AfterMode.Perm() {
				return fmt.Errorf("committed artifact mode mismatch: %s", a.Path)
			}
		}
	} else if err := restore(rec.Files); err != nil {
		return err
	}
	return durableRemove(journalPath)
}

func (t *Txn) handleApplyError(err error) error {
	if errors.Is(err, ErrSimulatedCrash) {
		return err
	}
	return errors.Join(err, t.Abort())
}

func (t *Txn) writeRecord() error {
	checksum, err := recordChecksum(t.record)
	if err != nil {
		return err
	}
	t.record.Checksum = checksum
	data, err := json.Marshal(t.record)
	if err != nil {
		return fmt.Errorf("marshal journal: %w", err)
	}
	if err := durableWrite(t.journal, data, 0o600); err != nil {
		return fmt.Errorf("write journal: %w", err)
	}
	return nil
}

func (t *Txn) boundary(point string) error {
	if t.hook == nil {
		return nil
	}
	return t.hook(point)
}

func restore(files []artifact) error {
	var errs []error
	for _, a := range files {
		if a.BeforeExists {
			if err := durableWrite(a.Path, a.Before, a.BeforeMode); err != nil {
				errs = append(errs, fmt.Errorf("restore %s: %w", a.Path, err))
			}
		} else if err := durableRemove(a.Path); err != nil {
			errs = append(errs, fmt.Errorf("remove new artifact %s: %w", a.Path, err))
		}
	}
	return errors.Join(errs...)
}

func durableWrite(path string, data []byte, mode fs.FileMode) error {
	if err := fileutil.AtomicWrite(path, data, mode); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func durableRemove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func recordChecksum(rec record) (string, error) {
	rec.Checksum = ""
	data, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("marshal journal checksum: %w", err)
	}
	return digest(data), nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
