package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/sha256"

	"github.com/KidCarmi/Culvert/internal/backupcrypt"
	"github.com/KidCarmi/Culvert/internal/logstore"
)

const (
	haArchivePhrase = "archive passphrase 1"
	haOldStore      = "old store passphrase"
	haNewStore      = "new store passphrase"
)

// haSeededStore opens a keyed store and fills it with n records via Import
// (deterministic; Add is asynchronous).
func haSeededStore(t *testing.T, dir, phrase string, n int) *logStore {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := logstore.EncKey(dir, phrase)
	if err != nil {
		t.Fatal(err)
	}
	s, err := logstore.OpenTTL(dir, 0, 0, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour).UnixMilli()
	recs := make([]logstore.ExportRecord, 0, n)
	for i := 0; i < n; i++ {
		e := LogEntry{TS: base + int64(i), Host: fmt.Sprintf("site-%d.example", i), Method: "GET", Level: "INFO", Status: "OK"}
		b, _ := json.Marshal(e)
		key := make([]byte, 12)
		ts := uint64(e.TS) // #nosec G115 -- positive test ts
		for j := 0; j < 8; j++ {
			key[j] = byte(ts >> (56 - 8*j))
		}
		key[11] = byte(i)
		key[10] = byte(i >> 8)
		recs = append(recs, logstore.ExportRecord{Key: fmt.Sprintf("%x", key), Entry: b})
	}
	i := 0
	if st, err := s.Import(func() (logstore.ExportRecord, bool, error) {
		if i == len(recs) {
			return logstore.ExportRecord{}, false, nil
		}
		i++
		return recs[i-1], true, nil
	}, time.Now()); err != nil || st.Imported != int64(n) {
		t.Fatalf("seed: %+v %v", st, err)
	}
	return s
}

func haTarget(dataDir, phrase string) historyImportTarget {
	return historyImportTarget{Dir: filepath.Join(dataDir, "logstore"), Phrase: phrase, Source: "test", explicit: true}
}

func haHosts(t *testing.T, s *logStore) []string {
	t.Helper()
	got, _, err := s.Query(0, 0, 0, 100000, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(got))
	for i := range got {
		out = append(out, got[i].Host)
	}
	return out
}

// The recovery the archive exists for: history from a store under one key is
// exported, the source is GONE, and the import lands it in a fresh store under
// a different key — verified, dry-run first, then confirmed.
func TestHistoryArchive_RecoversIntoAFreshStoreUnderANewKey(t *testing.T) {
	root := t.TempDir()
	src := haSeededStore(t, filepath.Join(root, "src", "logstore"), haOldStore, 500)
	want := haHosts(t, src)
	var buf bytes.Buffer
	res, err := writeHistoryArchive(&buf, src, haArchivePhrase, time.Now())
	if err != nil || res.Records != 500 || res.Skipped != 0 {
		t.Fatalf("export: %+v err=%v", res, err)
	}
	_ = src.Close()
	if err := os.RemoveAll(filepath.Join(root, "src")); err != nil { // source volume unavailable
		t.Fatal(err)
	}
	arch := filepath.Join(root, "history.cvst")
	if err := os.WriteFile(arch, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "new-data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	storeDir := filepath.Join(dataDir, "logstore")
	tgt := haTarget(dataDir, haNewStore)

	var out bytes.Buffer
	if err := runHistoryImportCommand(arch, tgt, dataDir, haArchivePhrase, false, &out); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(out.String(), "500 records") || !strings.Contains(out.String(), "dry-run") || !strings.Contains(out.String(), storeDir) {
		t.Fatalf("dry-run output: %q", out.String())
	}
	if _, err := os.Stat(storeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run touched the store dir: %v", err)
	}

	out.Reset()
	if err := runHistoryImportCommand(arch, tgt, dataDir, haArchivePhrase, true, &out); err != nil {
		t.Fatalf("import: %v (%s)", err, out.String())
	}
	if !strings.Contains(out.String(), "imported=500 ") {
		t.Fatalf("import output: %q", out.String())
	}
	key, _ := logstore.EncKey(storeDir, haNewStore)
	dst, err := logstore.OpenTTL(storeDir, 0, 0, key, nil)
	if err != nil {
		t.Fatalf("new store does not open under the NEW key: %v", err)
	}
	if got := haHosts(t, dst); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("recovered history differs (%d vs %d)", len(got), len(want))
	}
	_ = dst.Close()

	// Idempotent: a second import of the same archive adds nothing.
	out.Reset()
	if err := runHistoryImportCommand(arch, tgt, dataDir, haArchivePhrase, true, &out); err != nil || !strings.Contains(out.String(), "imported=0 duplicate=500") {
		t.Fatalf("re-import: %v %q", err, out.String())
	}
}

type failAfterWriter struct {
	w    io.Writer
	left int
}

func (f *failAfterWriter) Write(p []byte) (int, error) {
	if f.left <= 0 {
		return 0, errors.New("disk full")
	}
	if len(p) > f.left {
		p = p[:f.left]
	}
	n, err := f.w.Write(p)
	f.left -= n
	if f.left <= 0 && err == nil {
		return n, errors.New("disk full")
	}
	return n, err
}

// An export that fails midway must not leave something an import accepts.
func TestHistoryArchive_FailedExportIsNeverImportable(t *testing.T) {
	src := haSeededStore(t, filepath.Join(t.TempDir(), "logstore"), haOldStore, 3000)
	defer src.Close()
	var buf bytes.Buffer
	if _, err := writeHistoryArchive(&failAfterWriter{w: &buf, left: 150 << 10}, src, haArchivePhrase, time.Now()); err == nil {
		t.Fatal("export into a failing writer reported success")
	}
	a, err := openHistoryArchive(bytes.NewReader(buf.Bytes()), haArchivePhrase)
	if err != nil {
		return // refused at the header: fine
	}
	for {
		_, ok, err := a.Next()
		if err != nil {
			return
		}
		if !ok {
			t.Fatal("a partial export verified as complete")
		}
	}
}

// A sealed archive whose trailer does not match its records is refused, even
// though every chunk authenticates (the writer contract above prevents it;
// this pins the reader's half).
func TestHistoryArchive_TrailerMismatchAndTrailingDataRefused(t *testing.T) {
	seal := func(lines ...string) []byte {
		var buf bytes.Buffer
		w, err := backupcrypt.NewStreamWriter(&buf, haArchivePhrase)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range lines {
			_, _ = io.WriteString(w, l+"\n")
		}
		_ = w.Close()
		return buf.Bytes()
	}
	hdr := `{"kind":"culvert-request-history","format":1,"createdAt":"2026-10-08T00:00:00Z"}`
	rec := `{"k":"00000000000000010000000a","e":{"ts":1}}`
	cases := map[string][]byte{
		"count mismatch":   seal(hdr, rec, `{"end":true,"count":2,"sha256":"00"}`),
		"no trailer":       seal(hdr, rec),
		"data after end":   seal(hdr, `{"end":true,"count":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`, rec),
		"wrong kind":       seal(`{"kind":"something-else","format":1}`),
		"future format":    seal(`{"kind":"culvert-request-history","format":2}`),
		"malformed record": seal(hdr, `{"nope":1}`, `{"end":true,"count":1,"sha256":"00"}`),
	}
	for name, b := range cases {
		a, err := openHistoryArchive(bytes.NewReader(b), haArchivePhrase)
		for err == nil {
			var ok bool
			_, ok, err = a.Next()
			if err == nil && !ok {
				t.Errorf("%s: accepted", name)
				break
			}
		}
	}
	// The empty-but-valid archive (count 0) IS accepted.
	a, err := openHistoryArchive(bytes.NewReader(seal(hdr, `{"end":true,"count":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`)), haArchivePhrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := a.Next(); ok || err != nil {
		t.Fatalf("empty archive: ok=%v err=%v", ok, err)
	}
}

func haArchiveFile(t *testing.T, dir string, n int) string {
	t.Helper()
	src := haSeededStore(t, filepath.Join(dir, "src", "logstore"), haOldStore, n)
	var buf bytes.Buffer
	if _, err := writeHistoryArchive(&buf, src, haArchivePhrase, time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = src.Close()
	arch := filepath.Join(dir, "a.cvst")
	if err := os.WriteFile(arch, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return arch
}

func TestHistoryImport_RefusesUnsafeOrIncompleteInputs(t *testing.T) {
	root := t.TempDir()
	arch := haArchiveFile(t, root, 5)
	dataDir := filepath.Join(root, "d")
	_ = os.MkdirAll(dataDir, 0o700)
	tgt := haTarget(dataDir, haNewStore)
	if err := runHistoryImportCommand(arch, tgt, dataDir, "", true, io.Discard); err == nil {
		t.Error("missing archive passphrase accepted")
	}
	if err := runHistoryImportCommand(arch, tgt, dataDir, "wrong archive phrase", true, io.Discard); !errors.Is(err, backupcrypt.ErrDecryptOpaque) {
		t.Errorf("wrong archive passphrase: %v", err)
	}
	if err := runHistoryImportCommand(arch, haTarget(dataDir, ""), dataDir, haArchivePhrase, true, io.Discard); err == nil || !strings.Contains(err.Error(), "UNENCRYPTED") {
		t.Errorf("unencrypted target accepted: %v", err)
	}
	if _, err := os.Stat(tgt.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused import created the store")
	}
	// Wrong STORE passphrase is named as such, not blamed on a lock.
	if err := runHistoryImportCommand(arch, tgt, dataDir, haArchivePhrase, true, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := runHistoryImportCommand(arch, haTarget(dataDir, "not the store key"), dataDir, haArchivePhrase, true, io.Discard); err == nil || !strings.Contains(err.Error(), "does not open with this passphrase") {
		t.Errorf("wrong store passphrase: %v", err)
	}
}

// Review finding: --confirm wrote the authenticated prefix of a failed export
// before discovering the missing trailer. It must write NOTHING.
func TestHistoryImport_IncompleteArchiveWritesNothing(t *testing.T) {
	root := t.TempDir()
	src := haSeededStore(t, filepath.Join(root, "src", "logstore"), haOldStore, 3000)
	var buf bytes.Buffer
	if _, err := writeHistoryArchive(&failAfterWriter{w: &buf, left: 450 << 10}, src, haArchivePhrase, time.Now()); err == nil {
		t.Fatal("export into a failing writer reported success")
	}
	_ = src.Close()
	arch := filepath.Join(root, "partial.cvst")
	_ = os.WriteFile(arch, buf.Bytes(), 0o600)
	dataDir := filepath.Join(root, "d")
	_ = os.MkdirAll(dataDir, 0o700)
	tgt := haTarget(dataDir, haNewStore)
	if err := runHistoryImportCommand(arch, tgt, dataDir, haArchivePhrase, true, io.Discard); err == nil {
		t.Fatal("a partial archive imported")
	}
	if _, err := os.Stat(tgt.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a partial archive created/wrote the store: %v", err)
	}
}

// Review finding: with history saving OFF the store lock is free, so "stop the
// proxy first" was only advice. The data-dir lock the proxy holds for its
// lifetime must refuse the import.
func TestHistoryImport_RefusedWhileTheDataDirIsHeld(t *testing.T) {
	root := t.TempDir()
	arch := haArchiveFile(t, root, 5)
	dataDir := filepath.Join(root, "d")
	_ = os.MkdirAll(dataDir, 0o700)
	release, err := acquireOfflineDataDirLock(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := runHistoryImportCommand(arch, haTarget(dataDir, haNewStore), dataDir, haArchivePhrase, true, io.Discard); !errors.Is(err, errDataDirLocked) {
		t.Fatalf("import with the data dir held: %v", err)
	}
	// The dry-run only reads the archive and stays allowed.
	if err := runHistoryImportCommand(arch, haTarget(dataDir, haNewStore), dataDir, haArchivePhrase, false, io.Discard); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
}

// Review finding (HIGH): a rekey used the process sequence counter, which
// restarts at 0 in every process, so a collision was "rekeyed" straight onto
// the existing record and destroyed it. Both must survive.
func TestHistoryImport_CollisionNeverOverwritesALiveRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logstore")
	_ = os.MkdirAll(filepath.Dir(dir), 0o700)
	ts := time.Now().Add(-time.Minute).UnixMilli()
	mk := func(seq uint32, host string) logstore.ExportRecord {
		b, _ := json.Marshal(LogEntry{TS: ts, Host: host, Method: "GET", Level: "INFO", Status: "OK"})
		key := make([]byte, 12)
		for j := 0; j < 8; j++ {
			key[j] = byte(uint64(ts) >> (56 - 8*j)) // #nosec G115 -- positive test ts
		}
		key[11] = byte(seq)
		return logstore.ExportRecord{Key: fmt.Sprintf("%x", key), Entry: b}
	}
	one := func(r ...logstore.ExportRecord) func() (logstore.ExportRecord, bool, error) {
		i := 0
		return func() (logstore.ExportRecord, bool, error) {
			if i == len(r) {
				return logstore.ExportRecord{}, false, nil
			}
			i++
			return r[i-1], true, nil
		}
	}
	key, _ := logstore.EncKey(dir, haNewStore)
	s, err := logstore.OpenTTL(dir, 0, 0, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The existing records hold seq 1..3 — exactly what a fresh process's
	// counter would hand a rekey.
	if _, err := s.Import(one(mk(1, "existing-1"), mk(2, "existing-2"), mk(3, "existing-3")), time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err = logstore.OpenTTL(dir, 0, 0, key, nil) // a NEW process: counter back at 0
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st, err := s.Import(one(mk(1, "incoming-1"), mk(2, "incoming-2")), time.Now())
	if err != nil || st.Rekeyed != 2 {
		t.Fatalf("%+v %v", st, err)
	}
	hosts := strings.Join(haHosts(t, s), ",")
	for _, h := range []string{"existing-1", "existing-2", "existing-3", "incoming-1", "incoming-2"} {
		if !strings.Contains(hosts, h) {
			t.Errorf("%s lost (have %s)", h, hosts)
		}
	}
}

// Review finding: an archive that repeats or reorders keys is refused (an
// export never does either; the last copy must not silently win).
func TestHistoryArchive_KeysMustAscend(t *testing.T) {
	rec := `{"k":"00000000000000010000000a","e":{"ts":1}}`
	h := sha256.Sum256([]byte(rec + "\n" + rec + "\n"))
	var buf bytes.Buffer
	w, _ := backupcrypt.NewStreamWriter(&buf, haArchivePhrase)
	_, _ = io.WriteString(w, `{"kind":"culvert-request-history","format":1}`+"\n"+rec+"\n"+rec+"\n"+
		fmt.Sprintf(`{"end":true,"count":2,"sha256":"%x"}`, h)+"\n")
	_ = w.Close()
	a, err := openHistoryArchive(bytes.NewReader(buf.Bytes()), haArchivePhrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := drainHistoryArchive(a); err == nil || !strings.Contains(err.Error(), "ascending") {
		t.Fatalf("duplicate key accepted: %v", err)
	}
}

// Review finding: a stored entry too large for the import's line bound made a
// valid export unimportable. Export skips and COUNTS it; the rest imports.
func TestHistoryArchive_OversizeRecordsAreSkippedAndCounted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logstore")
	s := haSeededStore(t, dir, haOldStore, 3)
	defer s.Close()
	ts := time.Now().Add(-time.Minute).UnixMilli()
	big, _ := json.Marshal(LogEntry{TS: ts, Host: "big", URI: strings.Repeat("a", historyMaxRecord+1)})
	key := make([]byte, 12)
	for j := 0; j < 8; j++ {
		key[j] = byte(uint64(ts) >> (56 - 8*j)) // #nosec G115 -- positive test ts
	}
	done := false
	if _, err := s.Import(func() (logstore.ExportRecord, bool, error) {
		if done {
			return logstore.ExportRecord{}, false, nil
		}
		done = true
		return logstore.ExportRecord{Key: fmt.Sprintf("%x", key), Entry: big}, true, nil
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := writeHistoryArchive(&buf, s, haArchivePhrase, time.Now())
	if err != nil || res.Records != 3 || res.Skipped != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	a, err := openHistoryArchive(bytes.NewReader(buf.Bytes()), haArchivePhrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := drainHistoryArchive(a); err != nil || a.Trailer.Skipped != 1 || a.Trailer.Count != 3 {
		t.Fatalf("trailer %+v err %v", a.Trailer, err)
	}
}

// The CLI resolves the store and retention as the proxy does.
func TestResolveHistoryImportTarget(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(cfgPath, []byte("log_store_path: /custom/history\nlog_retention_days: 30\n"), 0o600)
	tg, err := resolveHistoryImportTarget(dir, cfgPath, "", "", "ca-pass")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Dir != "/custom/history" || tg.Days != 30 || tg.Phrase != "ca-pass" || tg.Source != "config.yaml" {
		t.Fatalf("%+v", tg)
	}
	if def, _ := resolveHistoryImportTarget(dir, "", "", "log-pass", "ca-pass"); def.Dir != filepath.Join(dir, "logstore") || def.Phrase != "log-pass" {
		t.Fatalf("default: %+v", def)
	}
	if ex, _ := resolveHistoryImportTarget(dir, "", "/x/y", "", "p"); ex.Dir != "/x/y" || !ex.explicit {
		t.Fatalf("explicit: %+v", ex)
	}
	_ = os.WriteFile(filepath.Join(dir, "admin_settings.json"), []byte(`{"log_store_enabled_saved":true,"log_retention_days":7,"log_retention_max_gb":2}`), 0o600)
	gui, err := resolveHistoryImportTarget(dir, "", "", "", "p")
	if err != nil || gui.Days != 7 || gui.MaxGB != 2 || !strings.Contains(gui.Source, "admin") {
		t.Fatalf("gui: %+v %v", gui, err)
	}
	_ = os.WriteFile(filepath.Join(dir, "admin_settings.json"), []byte(`{`), 0o600)
	if _, err := resolveHistoryImportTarget(dir, "", "", "", "p"); err == nil {
		t.Error("unreadable admin_settings ignored")
	}
}

func haExportRequest(t *testing.T, role UIRole, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/logs/history/export", strings.NewReader(body))
	r = withRole(r, role)
	w := httptest.NewRecorder()
	apiLogsHistoryExport(w, r)
	return w
}

func TestAPIHistoryExport(t *testing.T) {
	prev := globalLogStore.Load()
	t.Cleanup(func() { globalLogStore.Store(prev) })
	globalLogStore.Store(nil)

	good := `{"archivePhrase":"` + haArchivePhrase + `"}`
	if w := haExportRequest(t, RoleOperator, good); w.Code != http.StatusForbidden {
		t.Fatalf("operator: %d", w.Code)
	}
	if w := haExportRequest(t, RoleAdmin, good); w.Code != http.StatusConflict {
		t.Fatalf("no store: %d", w.Code)
	}
	src := haSeededStore(t, filepath.Join(t.TempDir(), "logstore"), haOldStore, 40)
	defer src.Close()
	globalLogStore.Store(src)
	if w := haExportRequest(t, RoleAdmin, `{"archivePhrase":"short"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("short phrase: %d", w.Code)
	}
	if w := haExportRequest(t, RoleAdmin, `not json`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", w.Code)
	}
	historyExportBusy.Store(true)
	if w := haExportRequest(t, RoleAdmin, good); w.Code != http.StatusConflict {
		t.Fatalf("concurrent export: %d", w.Code)
	}
	historyExportBusy.Store(false)

	w := haExportRequest(t, RoleAdmin, good)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/octet-stream" || !strings.Contains(w.Header().Get("Content-Disposition"), ".cvst") {
		t.Fatalf("export: %d %v", w.Code, w.Header())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("site-1.example")) {
		t.Fatal("archive carries plaintext history")
	}
	a, err := openHistoryArchive(bytes.NewReader(w.Body.Bytes()), haArchivePhrase)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		_, ok, err := a.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		n++
	}
	if n != 40 || historyExportBusy.Load() {
		t.Fatalf("records %d, busy %v", n, historyExportBusy.Load())
	}
	found := false
	for _, e := range auditGet() {
		if e.Action == "logstore.export" && strings.Contains(e.Detail, "40 records") {
			found = true
		}
	}
	if !found {
		t.Fatal("export not audited")
	}
}

type haFailingResponse struct {
	*httptest.ResponseRecorder
	left int
}

func (f *haFailingResponse) Write(p []byte) (int, error) {
	if f.left <= 0 {
		return 0, errors.New("client went away")
	}
	f.left -= len(p)
	return f.ResponseRecorder.Write(p)
}

// The admin UI posts a form (so the browser streams the download); a failure
// after streaming started must ABORT the response, never end it cleanly.
func TestAPIHistoryExport_FormAndAbort(t *testing.T) {
	prev := globalLogStore.Load()
	t.Cleanup(func() { globalLogStore.Store(prev) })
	src := haSeededStore(t, filepath.Join(t.TempDir(), "logstore"), haOldStore, 3000)
	defer src.Close()
	globalLogStore.Store(src)

	form := "archivePhrase=" + strings.ReplaceAll(haArchivePhrase, " ", "+")
	r := withRole(httptest.NewRequest(http.MethodPost, "/api/logs/history/export", strings.NewReader(form)), RoleAdmin)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	apiLogsHistoryExport(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("form export: %d %s", w.Code, w.Body.String())
	}
	if a, err := openHistoryArchive(bytes.NewReader(w.Body.Bytes()), haArchivePhrase); err != nil || drainHistoryArchive(a) != nil {
		t.Fatalf("form export did not verify: %v", err)
	}

	r = withRole(httptest.NewRequest(http.MethodPost, "/api/logs/history/export", strings.NewReader(`{"archivePhrase":"`+haArchivePhrase+`"}`)), RoleAdmin)
	fw := &haFailingResponse{ResponseRecorder: httptest.NewRecorder(), left: 100 << 10}
	func() {
		defer func() {
			if rec := recover(); rec != http.ErrAbortHandler {
				t.Fatalf("mid-stream failure: recovered %v, want http.ErrAbortHandler", rec)
			}
		}()
		apiLogsHistoryExport(fw, r)
	}()
	if historyExportBusy.Load() {
		t.Fatal("busy flag left set after an aborted export")
	}
	failed := false
	for _, e := range auditGet() {
		if e.Action == "logstore.export.failed" {
			failed = true
		}
	}
	if !failed {
		t.Fatal("failed export not audited")
	}
}
