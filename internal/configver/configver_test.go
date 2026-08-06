package configver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeVersion(t *testing.T, dir string, ver int, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("v%d.json", ver)), []byte(body), 0o600); err != nil {
		t.Fatalf("write v%d.json: %v", ver, err)
	}
}

// ─── Init: sequence resume ───────────────────────────────────────────────────

func TestInit_CreatesDirAndResumesSeq(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "versions")
	s := New(dir, 0)
	s.Init()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("Init did not create dir: %v", err)
	}
	if s.Seq() != 0 {
		t.Fatalf("fresh dir seq = %d, want 0", s.Seq())
	}

	writeVersion(t, dir, 3, "{}")
	writeVersion(t, dir, 12, "{}")
	writeVersion(t, dir, 7, "{}")
	s2 := New(dir, 0)
	s2.Init()
	if s2.Seq() != 12 {
		t.Fatalf("seq after resume = %d, want 12 (highest existing)", s2.Seq())
	}
}

func TestInit_IgnoresNonVersionFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"vX.json", "notaversion.json", "v5.txt", "readme"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := New(dir, 0)
	s.Init()
	if s.Seq() != 0 {
		t.Fatalf("seq = %d, want 0 (no valid vN.json present)", s.Seq())
	}
}

// ─── Save: naming, mode, envelope, seq consumption ───────────────────────────

func TestListMeta_MatchesListMetadataWithoutConfig(t *testing.T) {
	s := New(t.TempDir(), 0)
	s.Init()
	if _, err := s.Save("alice", "policy.update", "2026-01-01T00:00:00Z", json.RawMessage(`{"blocklist":["a","b","c"]}`)); err != nil {
		t.Fatalf("Save v1: %v", err)
	}
	if _, err := s.Save("bob", "rollback", "2026-01-02T00:00:00Z", json.RawMessage(`{"defaultAction":"deny"}`)); err != nil {
		t.Fatalf("Save v2: %v", err)
	}
	full, meta := s.List(), s.ListMeta()
	if len(meta) != len(full) {
		t.Fatalf("ListMeta len=%d, List len=%d", len(meta), len(full))
	}
	for i := range full {
		if meta[i] != full[i] {
			t.Fatalf("ListMeta[%d]=%+v != List[%d]=%+v", i, meta[i], i, full[i])
		}
	}
	// Descending order preserved (v2 before v1).
	if len(meta) != 2 || meta[0].Version != 2 || meta[1].Version != 1 {
		t.Fatalf("ListMeta ordering/content wrong: %+v", meta)
	}
	if meta[0].Actor != "bob" || meta[0].Action != "rollback" {
		t.Fatalf("ListMeta metadata wrong: %+v", meta[0])
	}
}

func TestSave_WritesEnvelopeAtomically(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0)
	s.Init()

	raw := json.RawMessage(`{"defaultAction":"deny"}`)
	ver, err := s.Save("tester", "unit.save", "2026-01-01T00:00:00Z", raw)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if ver != 1 {
		t.Fatalf("version = %d, want 1", ver)
	}

	path := filepath.Join(dir, "v1.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("file mode = %o, want 0o600", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("tmp file leaked: %s", e.Name())
		}
	}

	meta, gotRaw, err := s.Load(1)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if meta.Actor != "tester" || meta.Action != "unit.save" || meta.Version != 1 || meta.CreatedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("meta round-trip = %+v", meta)
	}
	var cfg map[string]any
	if err := json.Unmarshal(gotRaw, &cfg); err != nil {
		t.Fatalf("config half unparseable: %v", err)
	}
	if cfg["defaultAction"] != "deny" {
		t.Errorf("config round-trip = %v", cfg)
	}
}

func TestSave_SequenceIncrements(t *testing.T) {
	s := New(t.TempDir(), 0)
	s.Init()
	for want := 1; want <= 3; want++ {
		got, err := s.Save("a", "b", "t", json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("Save %d: %v", want, err)
		}
		if got != want {
			t.Fatalf("version = %d, want %d", got, want)
		}
	}
	if s.Seq() != 3 {
		t.Fatalf("Seq() = %d, want 3", s.Seq())
	}
}

// ─── Prune ───────────────────────────────────────────────────────────────────

func TestSave_PrunesBeyondMax(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 3)
	s.Init()
	for i := 0; i < 5; i++ {
		if _, err := s.Save("a", "b", "t", json.RawMessage(`{}`)); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	metas := s.List()
	if len(metas) != 3 {
		t.Fatalf("retained = %d, want 3 (max)", len(metas))
	}
	// Oldest (v1, v2) pruned; newest retained in descending order.
	if metas[0].Version != 5 || metas[2].Version != 3 {
		t.Errorf("retained versions = %v, want [5 4 3]", []int{metas[0].Version, metas[1].Version, metas[2].Version})
	}
}

// ─── List: skip + sort contract ──────────────────────────────────────────────

func TestList_MissingDirReturnsEmptyNonNil(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "nonexistent"), 0)
	metas := s.List()
	if metas == nil {
		t.Fatal("List must return non-nil even when the dir is missing")
	}
	if len(metas) != 0 {
		t.Fatalf("len = %d, want 0", len(metas))
	}
}

func TestList_SkipsCorruptAndSortsDescending(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0)
	s.Init()
	writeVersion(t, dir, 1, `{"meta":{"version":1,"actor":"a"}}`)
	writeVersion(t, dir, 2, "this is not json") // D1.2-flag-F5: silently skipped
	writeVersion(t, dir, 3, `{"meta":{"version":3,"actor":"c"}}`)

	metas := s.List()
	if len(metas) != 2 {
		t.Fatalf("len = %d, want 2 (corrupt v2 skipped)", len(metas))
	}
	if metas[0].Version != 3 || metas[1].Version != 1 {
		t.Errorf("order = [%d %d], want [3 1] (descending)", metas[0].Version, metas[1].Version)
	}
}

// ─── Integrity: present vs readable ──────────────────────────────────────────

func TestIntegrity_AllReadable(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0)
	s.Init()
	writeVersion(t, dir, 1, `{"meta":{"version":1,"actor":"a"}}`)
	writeVersion(t, dir, 2, `{"meta":{"version":2,"actor":"b"}}`)

	present, readable := s.Integrity()
	if present != 2 || readable != 2 {
		t.Fatalf("present=%d readable=%d, want 2, 2", present, readable)
	}
}

func TestIntegrity_FlagsHiddenCorruptFileNotJustLatest(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0)
	s.Init()
	// v2 is corrupt but is NOT the latest version — a check that only
	// inspects the latest file would miss this entirely.
	writeVersion(t, dir, 1, `{"meta":{"version":1,"actor":"a"}}`)
	writeVersion(t, dir, 2, "this is not json")
	writeVersion(t, dir, 3, `{"meta":{"version":3,"actor":"c"}}`)

	present, readable := s.Integrity()
	if present != 3 {
		t.Fatalf("present = %d, want 3", present)
	}
	if readable != 2 {
		t.Fatalf("readable = %d, want 2 (v2 is corrupt)", readable)
	}
}

func TestIntegrity_MissingDirReturnsZeroZero(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "nonexistent"), 0)
	present, readable := s.Integrity()
	if present != 0 || readable != 0 {
		t.Fatalf("present=%d readable=%d, want 0, 0", present, readable)
	}
}

// TestIntegrity_MalformedEnvelopeNotReadable pins that a file which is valid
// JSON but carries no populated meta block (version 0) is counted present but
// NOT readable, and is hidden from the rollback list — the same Meta.Version<=0
// invariant the latest-only summarizer enforces. Before the fix it decoded to a
// zero-valued Meta and was silently counted as a usable version.
func TestIntegrity_MalformedEnvelopeNotReadable(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0)
	s.Init()
	writeVersion(t, dir, 1, `{"meta":{"version":1,"actor":"a"}}`)
	writeVersion(t, dir, 2, `{"config":{}}`) // valid JSON, no meta → version 0

	present, readable := s.Integrity()
	if present != 2 || readable != 1 {
		t.Fatalf("present=%d readable=%d, want 2, 1 (v2 is a malformed envelope)", present, readable)
	}
	if metas := s.List(); len(metas) != 1 || metas[0].Version != 1 {
		t.Fatalf("List = %+v, want only v1 (malformed v2 hidden from rollback list)", metas)
	}
}

// TestIntegrity_CachedUntilSaveInvalidates pins the DoS guard: Integrity reads
// and parses every retained snapshot, so it must be cached and recomputed only
// when a version is written — a viewer hammering /api/diagnostics must not be
// able to force a full re-read of every snapshot per request.
func TestIntegrity_CachedUntilSaveInvalidates(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0)
	s.Init()
	if _, err := s.Save("t", "seed", "2026-01-01T00:00:00Z", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("Save v1: %v", err)
	}
	if p, r := s.Integrity(); p != 1 || r != 1 {
		t.Fatalf("first Integrity = %d,%d, want 1,1", p, r)
	}
	// Corrupt an out-of-band file (high version so Save's sequential counter
	// never reuses it). Without a Save the cache must serve the prior result.
	writeVersion(t, dir, 99, "not json")
	if p, r := s.Integrity(); p != 1 || r != 1 {
		t.Fatalf("cached Integrity = %d,%d, want 1,1 (served from cache, no rescan)", p, r)
	}
	// A Save invalidates the cache; the rescan now sees v1 + v2 + the corrupt v99.
	if _, err := s.Save("t", "change", "2026-01-01T00:00:00Z", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("Save v2: %v", err)
	}
	if p, r := s.Integrity(); p != 3 || r != 2 {
		t.Fatalf("post-Save Integrity = %d,%d, want 3,2 (cache invalidated, rescanned)", p, r)
	}
}

// ─── Load: not-found vs corrupt ──────────────────────────────────────────────

func TestLoad_NotFoundIsOSError(t *testing.T) {
	s := New(t.TempDir(), 0)
	_, _, err := s.Load(99)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("err = %v, want os.IsNotExist-checkable (API maps it to 404)", err)
	}
	if errors.Is(err, ErrCorrupt) {
		t.Fatal("missing file must NOT be ErrCorrupt")
	}
}

func TestLoad_CorruptEnvelopeIsErrCorrupt(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0)
	writeVersion(t, dir, 4, "not json at all")
	_, _, err := s.Load(4)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt (API maps it to 500)", err)
	}
}

func TestLoad_EnvelopeMissingConfigHalf(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0)
	writeVersion(t, dir, 7, `{"meta":{"version":7,"actor":"test"}}`)
	meta, raw, err := s.Load(7)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if meta.Version != 7 || meta.Actor != "test" {
		t.Errorf("meta = %+v", meta)
	}
	if len(raw) != 0 {
		t.Errorf("config half = %q, want empty (absent field)", raw)
	}
}

// ─── Test hooks ──────────────────────────────────────────────────────────────

func TestSetDirAndSeqForTest(t *testing.T) {
	s := New(t.TempDir(), 0)
	s.Init()
	other := t.TempDir()
	s.SetDirForTest(other)
	if s.Dir() != other {
		t.Fatalf("Dir() = %q, want %q", s.Dir(), other)
	}
	s.SetSeqForTest(41)
	if v, err := s.Save("a", "b", "t", json.RawMessage(`{}`)); err != nil || v != 42 {
		t.Fatalf("Save after SetSeqForTest(41) = (%d, %v), want (42, nil)", v, err)
	}
}
