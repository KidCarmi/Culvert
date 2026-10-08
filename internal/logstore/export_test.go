package logstore

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func exportAll(t *testing.T, s *Store) []ExportRecord {
	t.Helper()
	var out []ExportRecord
	n, err := s.Export(func(r ExportRecord) error { out = append(out, r); return nil })
	if err != nil || int(n) != len(out) {
		t.Fatalf("Export: n=%d len=%d err=%v", n, len(out), err)
	}
	return out
}

func sliceSource(recs []ExportRecord) func() (ExportRecord, bool, error) {
	i := 0
	return func() (ExportRecord, bool, error) {
		if i == len(recs) {
			return ExportRecord{}, false, nil
		}
		i++
		return recs[i-1], true, nil
	}
}

func openKeyed(t *testing.T, dir, pass string, ttl time.Duration, maxBytes int64) *Store {
	t.Helper()
	key, err := EncKey(dir, pass)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenTTL(dir, ttl, maxBytes, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func unixU64(t *testing.T, tm time.Time) uint64 {
	t.Helper()
	u := tm.Unix()
	if u <= 0 {
		t.Fatalf("time %v before the epoch", tm)
	}
	return uint64(u)
}

func genRecord(ts int64, seq uint32, host string, exp uint64) ExportRecord {
	b, _ := json.Marshal(Entry{TS: ts, Host: host, Method: "GET", Level: "INFO", Status: "OK"})
	return ExportRecord{Key: hex.EncodeToString(storeKey(ts, seq)), ExpiresAt: exp, Entry: b}
}

// The point of the feature: history written under one key survives into a
// store with a DIFFERENT key (rotation, or a fresh appliance), byte for byte,
// and the new store is encrypted under the new key only.
func TestExportImport_SurvivesAKeyChange(t *testing.T) {
	root := t.TempDir()
	srcDir, dstDir := filepath.Join(root, "src"), filepath.Join(root, "dst")
	src := openKeyed(t, srcDir, "old passphrase", 0, 0)
	base := time.Now().Add(-time.Hour).UnixMilli()
	for i := 0; i < 300; i++ {
		src.Add(Entry{TS: base + int64(i), Host: fmt.Sprintf("h%d.example", i), Method: "GET", Level: "INFO", Status: "OK"})
	}
	drainLogStore(t, src, 300)
	recs := exportAll(t, src)
	if len(recs) != 300 {
		t.Fatalf("exported %d, want 300", len(recs))
	}
	want, _, _ := src.Query(0, 0, 0, 1000, nil)
	_ = src.Close()

	dst := openKeyed(t, dstDir, "new passphrase", 0, 0)
	st, err := dst.Import(sliceSource(recs), time.Now())
	if err != nil || st.Imported != 300 || st.Duplicate+st.Rekeyed+st.Expired+st.Invalid != 0 {
		t.Fatalf("Import: %+v err=%v", st, err)
	}
	got, total, _ := dst.Query(0, 0, 0, 1000, nil)
	if total != 300 || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("imported history differs: total %d", total)
	}
	again := exportAll(t, dst)
	for i := range recs {
		if again[i].Key != recs[i].Key || string(again[i].Entry) != string(recs[i].Entry) {
			t.Fatalf("record %d changed in transit", i)
		}
	}
	_ = dst.Close()
	// The destination is encrypted under the NEW key, not the old one.
	key, _ := EncKey(dstDir, "old passphrase")
	if s, err := OpenTTL(dstDir, 0, 0, key, nil); !errors.Is(err, ErrEncMismatch) {
		if s != nil {
			_ = s.Close()
		}
		t.Fatalf("old key opened the re-keyed store: %v", err)
	}
}

// Re-importing the same archive must not duplicate history.
func TestImport_IsIdempotent(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	recs := []ExportRecord{genRecord(now.Add(-time.Minute).UnixMilli(), 1, "a", 0), genRecord(now.Add(-time.Minute).UnixMilli(), 2, "b", 0)}
	if st, err := s.Import(sliceSource(recs), now); err != nil || st.Imported != 2 {
		t.Fatalf("first: %+v %v", st, err)
	}
	st, err := s.Import(sliceSource(recs), now)
	if err != nil || st.Imported != 0 || st.Duplicate != 2 {
		t.Fatalf("second: %+v %v", st, err)
	}
	if _, total, _ := s.Query(0, 0, 0, 100, nil); total != 2 {
		t.Fatalf("total %d after re-import", total)
	}
}

// A key collision with DIFFERENT content never overwrites what is there.
func TestImport_CollisionIsRekeyedNotOverwritten(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	ts := now.Add(-time.Minute).UnixMilli()
	if _, err := s.Import(sliceSource([]ExportRecord{genRecord(ts, 7, "existing", 0)}), now); err != nil {
		t.Fatal(err)
	}
	st, err := s.Import(sliceSource([]ExportRecord{genRecord(ts, 7, "incoming", 0)}), now)
	if err != nil || st.Rekeyed != 1 || st.Imported != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	got, total, _ := s.Query(0, 0, 0, 100, nil)
	hosts := map[string]bool{}
	for _, e := range got {
		hosts[e.Host] = true
	}
	if total != 2 || !hosts["existing"] || !hosts["incoming"] {
		t.Fatalf("total %d hosts %v", total, hosts)
	}
}

func TestImport_ExpiryAndAgeLimit(t *testing.T) {
	now := time.Now()
	s := openKeyed(t, filepath.Join(t.TempDir(), "s"), "", 24*time.Hour, 0)
	defer s.Close()
	old := now.Add(-48 * time.Hour).UnixMilli() // older than this store's 24h age limit
	fresh := now.Add(-time.Hour).UnixMilli()    // within it
	past := unixU64(t, now.Add(-time.Minute))   // original expiry already passed
	recs := []ExportRecord{genRecord(old, 1, "old", 0), genRecord(fresh, 2, "expired", past), genRecord(fresh, 3, "kept", 0)}
	st, err := s.Import(sliceSource(recs), now)
	if err != nil || st.Expired != 2 || st.Imported != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	out := exportAll(t, s)
	if len(out) != 1 {
		t.Fatalf("%d records", len(out))
	}
	// The kept record expires at its own ts + 24h, not 24h from import.
	if want := unixU64(t, time.UnixMilli(fresh).Add(24*time.Hour)); out[0].ExpiresAt != want {
		t.Fatalf("expiry %d, want %d", out[0].ExpiresAt, want)
	}
}

func TestImport_InvalidRecordsAreCountedNotWritten(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	ts := now.Add(-time.Minute).UnixMilli()
	good := genRecord(ts, 1, "ok", 0)
	mismatch := genRecord(ts, 2, "x", 0)
	mismatch.Key = hex.EncodeToString(storeKey(ts+5, 2)) // key ts != entry ts
	recs := []ExportRecord{
		good,
		{Key: "zz", Entry: good.Entry},
		{Key: hex.EncodeToString([]byte("short")), Entry: good.Entry},
		{Key: hex.EncodeToString(storeKey(ts, 3)), Entry: json.RawMessage(`{"ts":`)},
		mismatch,
	}
	st, err := s.Import(sliceSource(recs), now)
	if err != nil || st.Imported != 1 || st.Invalid != 4 {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestImport_RefusesToExceedSizeCap(t *testing.T) {
	s := openKeyed(t, filepath.Join(t.TempDir(), "s"), "", 0, 2000)
	defer s.Close()
	now := time.Now()
	var recs []ExportRecord
	for i := 0; i < 100; i++ {
		recs = append(recs, genRecord(now.Add(-time.Minute).UnixMilli(), uint32(i), "h", 0)) // #nosec G115 -- small
	}
	st, err := s.Import(sliceSource(recs), now)
	if !errors.Is(err, ErrImportSizeCap) || st.Imported != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	if n := len(exportAll(t, s)); n != 0 {
		t.Fatalf("%d records written from a refused batch", n)
	}
}

// More than one export page, imported back: nothing lost or repeated at the
// page seams, and order is ascending.
func TestExport_PagesAreContiguous(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	const n = 2*exportPage + 37
	recs := make([]ExportRecord, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, genRecord(now.Add(-time.Hour).UnixMilli()+int64(i/3), uint32(i), "h", 0)) // #nosec G115 -- small
	}
	if st, err := s.Import(sliceSource(recs), now); err != nil || st.Imported != n {
		t.Fatalf("%+v %v", st, err)
	}
	out := exportAll(t, s)
	if len(out) != n {
		t.Fatalf("exported %d, want %d", len(out), n)
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].Key >= out[i].Key {
			t.Fatalf("not strictly ascending at %d", i)
		}
	}
}

func TestExportImport_ClosedAndNilStores(t *testing.T) {
	var nilStore *Store
	if _, err := nilStore.Export(func(ExportRecord) error { return nil }); err == nil {
		t.Error("nil Export succeeded")
	}
	if _, err := nilStore.Import(sliceSource(nil), time.Now()); err == nil {
		t.Error("nil Import succeeded")
	}
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := s.Export(func(ExportRecord) error { return nil }); err == nil {
		t.Error("closed Export succeeded")
	}
	if _, err := s.Import(sliceSource([]ExportRecord{genRecord(time.Now().UnixMilli(), 1, "h", 0)}), time.Now()); err == nil {
		t.Error("closed Import succeeded")
	}
	// The callback's error stops the export and is returned.
	s2 := newTestStore(t)
	_, _ = s2.Import(sliceSource([]ExportRecord{genRecord(time.Now().Add(-time.Minute).UnixMilli(), 1, "h", 0)}), time.Now())
	stop := errors.New("stop")
	if _, err := s2.Export(func(ExportRecord) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("callback error: %v", err)
	}
}
