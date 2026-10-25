package main

// history_archive.go — request-history export/import (#1528, ASTRA closeout:
// historical encrypted-log recovery).
//
// The history store (internal/logstore) is encrypted under a NODE-LOCAL key
// (log passphrase + <dir>.salt) and is deliberately not in the application
// backup, so before this its records were lost on a full restore, a volume
// loss, or any change of log passphrase (the store cannot be re-keyed in
// place). The archive moves the records out under a key the OPERATOR holds:
//
//   - Export: POST /api/logs/history/export (admin, audited) streams the
//     history sealed in the backupcrypt streaming envelope under an
//     operator-supplied archive passphrase. Online: the proxy holds the
//     store's lock, so only the proxy can read it.
//   - Import: `culvert --history-import <file> [--confirm]` (via the compose
//     `cli` service) verifies the archive and, with --confirm, writes the
//     records into the store under THAT store's current key. Offline, like a
//     restore commit: the store's lock is held by a running proxy.
//
// Export → purge → change CULVERT_LOG_PASSPHRASE → import is therefore also
// the supported key-rotation path, and import into a fresh appliance is the
// recovery path when the source volumes are gone.
//
// Plaintext layout (JSON lines inside the envelope): a header, one line per
// record (logstore.ExportRecord), and a trailer carrying the record count and
// the SHA-256 of every record line. The envelope already authenticates every
// chunk and its end; the trailer exists because an export that FAILED midway
// must not leave an archive that authenticates as complete — without a
// matching trailer an import refuses it.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/KidCarmi/Culvert/internal/backupcrypt"
	"github.com/KidCarmi/Culvert/internal/logstore"
)

const (
	historyArchiveKind   = "culvert-request-history"
	historyArchiveFormat = 1
	// historyPassphraseEnv carries the ARCHIVE passphrase to the import CLI
	// (never the store's own passphrase).
	historyPassphraseEnv = "CULVERT_HISTORY_PASSPHRASE" // #nosec G101 -- env-var NAME, not a credential
	// historyArchivePhraseMinLen is enforced (not just warned) on export: the
	// archive leaves the appliance and is only as strong as this.
	historyArchivePhraseMinLen = 12
	// historyMaxRecord bounds one exported entry. Stored entries are a few KB,
	// but an inspected request's URI is not length-bounded upstream (PX-22),
	// so a client behind a LogFullURI rule could store one large enough to
	// break the recovery path. Export skips and COUNTS such records (trailer
	// "skipped", audit detail) so whatever exports also imports.
	historyMaxRecord = 4 << 20
	// historyMaxLine bounds one JSON line on import: a record of up to
	// historyMaxRecord bytes plus its key/expiry framing.
	historyMaxLine = historyMaxRecord + 4096
)

type historyArchiveHeader struct {
	Kind      string `json:"kind"`
	Format    int    `json:"format"`
	CreatedAt string `json:"createdAt"`
	// SourceEncrypted records whether the exported store was encrypted at
	// rest (informational; the archive itself is always encrypted).
	SourceEncrypted bool `json:"sourceEncrypted"`
}

type historyArchiveTrailer struct {
	End     bool   `json:"end"`
	Count   int64  `json:"count"`
	RecHash string `json:"sha256"`
	// Skipped counts stored entries larger than historyMaxRecord that the
	// export left out (reported, never silent).
	Skipped int64 `json:"skipped,omitempty"`
}

// historyExportResult is what an export wrote.
type historyExportResult struct {
	Records int64
	Skipped int64
}

// writeHistoryArchive seals the whole store into w. On any error it returns
// WITHOUT closing the envelope, so the partial output cannot authenticate.
func writeHistoryArchive(w io.Writer, s *logStore, phrase string, now time.Time) (historyExportResult, error) {
	var res historyExportResult
	sw, err := backupcrypt.NewStreamWriter(w, phrase)
	if err != nil {
		return res, err
	}
	bw := bufio.NewWriterSize(sw, 64<<10)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(historyArchiveHeader{Kind: historyArchiveKind, Format: historyArchiveFormat,
		CreatedAt: now.UTC().Format(time.RFC3339), SourceEncrypted: s.Encrypted()}); err != nil {
		return res, err
	}
	h := sha256.New()
	var line bytes.Buffer
	lenc := json.NewEncoder(&line)
	lenc.SetEscapeHTML(false)
	_, err = s.Export(func(rec logstore.ExportRecord) error {
		if len(rec.Entry) > historyMaxRecord {
			res.Skipped++
			return nil
		}
		line.Reset()
		if err := lenc.Encode(rec); err != nil {
			return err
		}
		h.Write(line.Bytes())
		res.Records++
		_, err := bw.Write(line.Bytes())
		return err
	})
	if err != nil {
		return res, err
	}
	if err := enc.Encode(historyArchiveTrailer{End: true, Count: res.Records, RecHash: hex.EncodeToString(h.Sum(nil)), Skipped: res.Skipped}); err != nil {
		return res, err
	}
	if err := bw.Flush(); err != nil {
		return res, err
	}
	return res, sw.Close()
}

// historyArchiveReader yields the records of an archive and verifies its
// trailer at the end: Next returns ok=false only after the trailer matched.
type historyArchiveReader struct {
	sc      *bufio.Scanner
	h       hash.Hash
	n       int64
	lastKey string // keys must be strictly ascending, as Export writes them
	Header  historyArchiveHeader
	Trailer historyArchiveTrailer
}

var errHistoryArchive = errors.New("not a valid request-history archive")

func openHistoryArchive(r io.Reader, phrase string) (*historyArchiveReader, error) {
	sr, err := backupcrypt.NewStreamReader(r, phrase)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(sr)
	sc.Buffer(make([]byte, 0, 64<<10), historyMaxLine)
	a := &historyArchiveReader{sc: sc, h: sha256.New()}
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: empty", errHistoryArchive)
	}
	if err := json.Unmarshal(sc.Bytes(), &a.Header); err != nil || a.Header.Kind != historyArchiveKind {
		return nil, fmt.Errorf("%w: bad header", errHistoryArchive)
	}
	if a.Header.Format != historyArchiveFormat {
		return nil, fmt.Errorf("%w: unsupported format %d", errHistoryArchive, a.Header.Format)
	}
	return a, nil
}

// Next returns the next record, or ok=false once the trailer was read and
// verified. Any authentication failure, truncation, trailer mismatch or data
// after the trailer is an error.
func (a *historyArchiveReader) Next() (logstore.ExportRecord, bool, error) {
	var rec logstore.ExportRecord
	if !a.sc.Scan() {
		if err := a.sc.Err(); err != nil {
			return rec, false, err
		}
		return rec, false, fmt.Errorf("%w: no trailer (incomplete export)", errHistoryArchive)
	}
	b := a.sc.Bytes()
	var t historyArchiveTrailer
	if json.Unmarshal(b, &t) == nil && t.End {
		if t.Count != a.n || t.RecHash != hex.EncodeToString(a.h.Sum(nil)) {
			return rec, false, fmt.Errorf("%w: trailer does not match the records (%d read, %d recorded)", errHistoryArchive, a.n, t.Count)
		}
		if a.sc.Scan() {
			return rec, false, fmt.Errorf("%w: data after the trailer", errHistoryArchive)
		}
		if err := a.sc.Err(); err != nil {
			return rec, false, err
		}
		a.Trailer = t
		return rec, false, nil
	}
	if err := json.Unmarshal(b, &rec); err != nil || rec.Key == "" {
		// A truncated or tampered stream hands the scanner a partial last
		// line before the read error: report the stream's error, not a
		// misleading "malformed record".
		if !a.sc.Scan() && a.sc.Err() != nil {
			return rec, false, a.sc.Err()
		}
		return rec, false, fmt.Errorf("%w: malformed record line %d", errHistoryArchive, a.n+1)
	}
	if rec.Key <= a.lastKey {
		return rec, false, fmt.Errorf("%w: record %d is not in ascending key order (duplicate or reordered)", errHistoryArchive, a.n+1)
	}
	a.lastKey = rec.Key
	a.h.Write(b)
	a.h.Write([]byte{'\n'})
	a.n++
	return rec, true, nil
}

// historyImportTarget is the store an import writes into, resolved the way
// the proxy resolves it (the one-shot runs before normal startup).
type historyImportTarget struct {
	Dir      string
	Phrase   string // the store's own key material (log, else CA passphrase)
	Days     int
	MaxGB    float64
	Source   string // where the retention came from, for the operator
	explicit bool   // Dir came from --history-store
}

// resolveHistoryImportTarget mirrors initLogStore + applyAdminLogStore:
// config.yaml log_store_path (else <data>/logstore) unless --history-store is
// given; retention from admin_settings.json when the GUI saved it (either
// sentinel), else from config.yaml log_retention_*.
func resolveHistoryImportTarget(dataDirVal, configPath, storeFlag, logPass, caPass string) (historyImportTarget, error) {
	fc := &FileConfig{}
	if configPath != "" {
		loaded, err := loadFileConfig(configPath)
		if err != nil {
			return historyImportTarget{}, fmt.Errorf("config %s: %w", configPath, err)
		}
		fc = loaded
	}
	sc := resolveLogStoreStartupConfig(fc, dataDirVal, logPass, caPass)
	t := historyImportTarget{Dir: sc.Dir, Phrase: sc.Passphrase, Days: sc.RetentionDays, MaxGB: sc.RetentionMaxGB, Source: "config.yaml"}
	if configPath == "" {
		t.Source = "defaults (no --config)"
	}
	if storeFlag != "" {
		t.Dir, t.explicit = storeFlag, true
	}
	b, err := os.ReadFile(filepath.Join(dataDirVal, "admin_settings.json")) // #nosec G304 -- fixed name under the data dir
	switch {
	case errors.Is(err, os.ErrNotExist):
		return t, nil
	case err != nil:
		return t, err
	}
	var as struct {
		EnabledSaved   bool    `json:"log_store_enabled_saved"`
		RetentionSaved bool    `json:"log_retention_saved"`
		Days           int     `json:"log_retention_days"`
		GB             float64 `json:"log_retention_max_gb"`
	}
	if err := json.Unmarshal(b, &as); err != nil {
		return t, fmt.Errorf("admin_settings.json: %w", err)
	}
	if as.EnabledSaved || as.RetentionSaved {
		t.Days, t.MaxGB, t.Source = as.Days, as.GB, "admin settings (GUI)"
	}
	return t, nil
}

func (t historyImportTarget) describe() string {
	return fmt.Sprintf("store %s, keep %d days (0 = no limit), max %.1f GB (0 = no limit) [retention from %s]", t.Dir, t.Days, t.MaxGB, t.Source)
}

// drainHistoryArchive reads every record and verifies the trailer.
func drainHistoryArchive(a *historyArchiveReader) error {
	for {
		_, ok, err := a.Next()
		if err != nil || !ok {
			return err
		}
	}
}

// verifyHistoryArchiveFile is the full verification pass: every chunk
// authenticated, keys ascending, trailer count and hash matched.
func verifyHistoryArchiveFile(path, phrase string) (*historyArchiveReader, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied one-shot input path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	a, err := openHistoryArchive(f, phrase)
	if err != nil {
		return nil, err
	}
	return a, drainHistoryArchive(a)
}

// openHistoryImportTarget opens the target store under its own key with the
// resolved retention, so imported records obey the age limit and size cap.
// Each failure names its own cause: a wrong passphrase is not a lock.
func openHistoryImportTarget(t historyImportTarget) (*logStore, error) {
	var ttl time.Duration
	if t.Days > 0 {
		ttl = time.Duration(t.Days) * 24 * time.Hour
	}
	var maxBytes int64
	if t.MaxGB > 0 {
		maxBytes = int64(t.MaxGB * (1 << 30))
	}
	// The salt sidecar lives beside the store, so its parent must exist.
	if err := os.MkdirAll(filepath.Dir(t.Dir), 0o700); err != nil {
		return nil, err
	}
	key, err := logstore.EncKey(t.Dir, t.Phrase)
	if errors.Is(err, logstore.ErrSaltUnusable) {
		return nil, fmt.Errorf("history store %s has content but its salt sidecar (%s.salt) is missing or damaged: restore that file first (docs/operator/request-history-recovery.md): %w", t.Dir, t.Dir, err)
	}
	if err != nil {
		return nil, fmt.Errorf("history store key: %w", err)
	}
	s, err := logstore.OpenTTL(t.Dir, ttl, maxBytes, key, nil)
	switch {
	case errors.Is(err, logstore.ErrEncMismatch):
		return nil, fmt.Errorf("history store %s does not open with this passphrase: set CULVERT_LOG_PASSPHRASE (or CULVERT_CA_PASSPHRASE) to the value the proxy uses: %w", t.Dir, err)
	case err != nil:
		return nil, fmt.Errorf("open history store %s: %w", t.Dir, err)
	}
	return s, nil
}

// runHistoryImportCommand verifies an archive (dry-run) or imports it
// (confirm). A confirm run VERIFIES THE WHOLE ARCHIVE FIRST and writes only
// after every chunk authenticated and the trailer matched — an incomplete or
// tampered archive writes nothing. It then holds the data-dir lock the proxy
// holds for its lifetime, so "stop the proxy first" is enforced, not advised
// (the store's own lock is only held while history saving is on). An import
// into an unencrypted store is refused: the archive is encrypted, and writing
// it into a plaintext store would silently downgrade the records.
func runHistoryImportCommand(path string, t historyImportTarget, dataDirVal, archivePhrase string, confirm bool, out io.Writer) error {
	if archivePhrase == "" {
		return fmt.Errorf("set %s to the archive passphrase used at export", historyPassphraseEnv)
	}
	v, err := verifyHistoryArchiveFile(path, archivePhrase)
	if err != nil {
		return err
	}
	if !t.explicit && t.Source == "defaults (no --config)" {
		_, _ = fmt.Fprintln(out, "note: no --config given; if config.yaml sets log_store_path, pass --config or --history-store")
	}
	if !confirm {
		_, _ = fmt.Fprintf(out, "history archive OK: %d records, %d skipped at export, created %s\ntarget: %s\ndry-run: nothing written — re-run with --confirm to import\n",
			v.Trailer.Count, v.Trailer.Skipped, v.Header.CreatedAt, t.describe())
		return nil
	}
	if t.Phrase == "" {
		return errors.New("refusing to import into an UNENCRYPTED history store: set CULVERT_LOG_PASSPHRASE (or CULVERT_CA_PASSPHRASE) as the proxy has it")
	}
	release, err := acquireOfflineDataDirLock(dataDirVal)
	if err != nil {
		return err
	}
	defer release()
	f, err := os.Open(path) // #nosec G304 -- operator-supplied one-shot input path
	if err != nil {
		return err
	}
	defer f.Close()
	a, err := openHistoryArchive(f, archivePhrase)
	if err != nil {
		return err
	}
	s, err := openHistoryImportTarget(t)
	if err != nil {
		return err
	}
	st, ierr := s.Import(a.Next, time.Now())
	cerr := s.Close()
	_, _ = fmt.Fprintf(out, "imported=%d duplicate=%d rekeyed=%d expired=%d invalid=%d\ntarget: %s\n",
		st.Imported, st.Duplicate, st.Rekeyed, st.Expired, st.Invalid, t.describe())
	if ierr != nil {
		return fmt.Errorf("import stopped (records above are written; re-running is idempotent): %w", ierr)
	}
	if cerr != nil {
		return fmt.Errorf("close history store: %w", cerr)
	}
	_, _ = fmt.Fprintf(out, "history archive verified: %d records (%d skipped at export), created %s\n", a.Trailer.Count, a.Trailer.Skipped, a.Header.CreatedAt)
	return nil
}
