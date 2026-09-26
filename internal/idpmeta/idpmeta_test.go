package idpmeta

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return New(t.TempDir())
}

func TestPutGet_RoundTrips(t *testing.T) {
	s := newTestStore(t)
	if err := s.Put("corp", KindSAMLMetadata, "https://idp.example/md", []byte("<EntityDescriptor/>")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	doc, age, err := s.Get("corp", KindSAMLMetadata, "https://idp.example/md")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(doc) != "<EntityDescriptor/>" {
		t.Fatalf("doc = %q", doc)
	}
	if age < 0 || age > time.Minute {
		t.Fatalf("age = %s, want a small non-negative value", age)
	}
}

// The key binds a document to its SOURCE. Re-pointing a profile at a different
// IdP must never be answered from the previous IdP's document — otherwise a
// deliberate migration could be served by the provider being migrated away
// from, which is a trust decision, not a caching one.
func TestGet_IsBoundToTheSourceURL(t *testing.T) {
	s := newTestStore(t)
	if err := s.Put("corp", KindSAMLMetadata, "https://old-idp.example/md", []byte("<old/>")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, _, err := s.Get("corp", KindSAMLMetadata, "https://new-idp.example/md"); err != ErrNoEntry {
		t.Fatalf("a re-pointed profile must have NO cache, got err=%v", err)
	}
}

// Kinds must not collide for one profile id.
func TestGet_IsBoundToTheKind(t *testing.T) {
	s := newTestStore(t)
	const src = "https://idp.example/doc"
	if err := s.Put("corp", KindSAMLMetadata, src, []byte("<saml/>")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, _, err := s.Get("corp", KindOIDCDiscovery, src); err != ErrNoEntry {
		t.Fatalf("a different Kind must not resolve, got err=%v", err)
	}
}

// THE SECURITY CONTROL. Serving a cached document forever would keep trusting
// an IdP signing key the IdP may have withdrawn — withdrawing a key from
// published metadata is the IdP's revocation lever. Past StaleMaxAge the entry
// is refused and the caller fails exactly as it did before this package.
func TestGet_RefusesPastTheStalenessCeiling(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.SetClockForTest(func() time.Time { return now })
	if err := s.Put("corp", KindSAMLMetadata, "https://idp.example/md", []byte("<md/>")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	s.SetClockForTest(func() time.Time { return now.Add(StaleMaxAge - time.Minute) })
	if _, _, err := s.Get("corp", KindSAMLMetadata, "https://idp.example/md"); err != nil {
		t.Fatalf("inside the ceiling must still serve: %v", err)
	}
	s.SetClockForTest(func() time.Time { return now.Add(StaleMaxAge) })
	if _, _, err := s.Get("corp", KindSAMLMetadata, "https://idp.example/md"); err != ErrNoEntry {
		t.Fatalf("AT the ceiling must refuse, got err=%v", err)
	}
	s.SetClockForTest(func() time.Time { return now.Add(StaleMaxAge + time.Hour) })
	if _, _, err := s.Get("corp", KindSAMLMetadata, "https://idp.example/md"); err != ErrNoEntry {
		t.Fatalf("past the ceiling must refuse, got err=%v", err)
	}
}

// A NEGATIVE age — a document stamped in the future, which a clock rollback
// produces — is UNUSABLE, not maximally fresh. Reading a future stamp as fresh
// would extend the trust window by however far the clock moved. Same rule
// CHAOS-61 established for cluster rate-limit broadcast freshness.
func TestGet_FutureStampIsStaleNotFresh(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.SetClockForTest(func() time.Time { return now })
	if err := s.Put("corp", KindSAMLMetadata, "https://idp.example/md", []byte("<md/>")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s.SetClockForTest(func() time.Time { return now.Add(-24 * time.Hour) }) // clock rolled back
	if _, _, err := s.Get("corp", KindSAMLMetadata, "https://idp.example/md"); err != ErrNoEntry {
		t.Fatalf("a future-stamped entry must be refused, got err=%v", err)
	}
}

// An inert store (no directory) must degrade to exactly the pre-CHAOS-71
// behaviour: Get finds nothing and Put is a silent no-op. The cache is an
// availability aid, never a correctness dependency, so a node with no writable
// state root must not have its compiles FAIL because of it.
func TestInertStore_IsANoOpNotAFailure(t *testing.T) {
	s := New("")
	if s.Enabled() {
		t.Fatal("empty-dir store must report disabled")
	}
	if err := s.Put("corp", KindSAMLMetadata, "src", []byte("x")); err != nil {
		t.Fatalf("inert Put must be a silent no-op, got %v", err)
	}
	if _, _, err := s.Get("corp", KindSAMLMetadata, "src"); err != ErrNoEntry {
		t.Fatalf("inert Get must report ErrNoEntry, got %v", err)
	}
	if s.Len() != 0 {
		t.Fatalf("inert Len = %d", s.Len())
	}
}

// A nil store must behave like an inert one rather than panic: the compile
// path calls through it on every provider construction.
func TestNilStore_IsSafe(t *testing.T) {
	var s *Store
	if err := s.Put("a", KindSAMLMetadata, "b", []byte("c")); err != nil {
		t.Fatalf("nil Put: %v", err)
	}
	if _, _, err := s.Get("a", KindSAMLMetadata, "b"); err != ErrNoEntry {
		t.Fatalf("nil Get: %v", err)
	}
	if s.Enabled() || s.Len() != 0 {
		t.Fatal("nil store must look empty and disabled")
	}
}

func TestPut_RefusesEmptyAndOversizeDocuments(t *testing.T) {
	s := newTestStore(t)
	if err := s.Put("corp", KindSAMLMetadata, "src", nil); err == nil {
		t.Fatal("an empty document must be refused — it would cache a successful-looking nothing")
	}
	if err := s.Put("corp", KindSAMLMetadata, "src", make([]byte, MaxDocumentBytes+1)); err == nil {
		t.Fatal("an oversize document must be refused")
	}
}

// The store survives a corrupt or truncated index without failing a boot: it
// caches a remote resource, so the correct response is to start empty and
// re-fetch, never to take the appliance down.
func TestLoad_CorruptIndexStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, indexFile), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s := New(dir)
	if _, _, err := s.Get("corp", KindSAMLMetadata, "src"); err != ErrNoEntry {
		t.Fatalf("corrupt index must read as empty, got %v", err)
	}
	if err := s.Put("corp", KindSAMLMetadata, "src", []byte("<md/>")); err != nil {
		t.Fatalf("Put after corrupt index: %v", err)
	}
	if _, _, err := s.Get("corp", KindSAMLMetadata, "src"); err != nil {
		t.Fatalf("Get after recovery: %v", err)
	}
}

// A document file that disappeared or was truncated under the index must read
// as ErrNoEntry, never as a short document the caller would then parse.
func TestGet_TruncatedDocumentIsRefused(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Put("corp", KindSAMLMetadata, "src", []byte("<md>full</md>")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".doc" {
			if err := os.WriteFile(filepath.Join(dir, e.Name()), []byte("<md>"), 0o600); err != nil {
				t.Fatalf("truncate: %v", err)
			}
		}
	}
	if _, _, err := New(dir).Get("corp", KindSAMLMetadata, "src"); err != ErrNoEntry {
		t.Fatalf("truncated document must be refused, got %v", err)
	}
}

// Eviction is bounded and DETERMINISTIC (oldest fetch first, ties by key) so
// which entry is dropped never depends on Go map iteration order.
func TestPut_EvictsOldestFirstAndStaysBounded(t *testing.T) {
	s := newTestStore(t)
	base := time.Now()
	for i := 0; i < MaxEntries+5; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		s.SetClockForTest(func() time.Time { return at })
		src := "https://idp.example/md/" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		if err := s.Put("corp", KindSAMLMetadata, src, []byte("<md/>")); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	if got := s.Len(); got != MaxEntries {
		t.Fatalf("Len = %d, want the %d cap", got, MaxEntries)
	}
	// The oldest source must be gone and the newest present.
	s.SetClockForTest(func() time.Time { return base.Add(time.Hour) })
	if _, _, err := s.Get("corp", KindSAMLMetadata, "https://idp.example/md/aa"); err != ErrNoEntry {
		t.Fatalf("oldest entry should have been evicted, got %v", err)
	}
	// Evicted document files must be removed too, so the directory cannot
	// outgrow the index.
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	docs := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".doc" {
			docs++
		}
	}
	if docs > MaxEntries {
		t.Fatalf("%d document files on disk, want <= %d", docs, MaxEntries)
	}
}

// Durability: a fresh Store over the same directory sees what an earlier one
// wrote. This is what makes the cache survive the restart it exists for.
func TestStore_SurvivesProcessRestart(t *testing.T) {
	dir := t.TempDir()
	if err := New(dir).Put("corp", KindOIDCDiscovery, "https://issuer.example/.well-known/openid-configuration", []byte(`{"issuer":"x"}`)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	doc, _, err := New(dir).Get("corp", KindOIDCDiscovery, "https://issuer.example/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if string(doc) != `{"issuer":"x"}` {
		t.Fatalf("doc = %q", doc)
	}
}

// ── Bounded cache reads (Codex review round 11) ──────────────────────────────

// docPathFor returns the on-disk document path for an entry, so a test can
// corrupt the cache the way corruption, a malformed restore or a local
// modification would — which is the only way to reach the branches below.
func docPathFor(s *Store, profileID string, kind Kind, source string) string {
	return filepath.Join(s.dir, docFileName(key(profileID, kind, source)))
}

// TestGet_OversizeDocumentIsAMiss is the defect gate, and the divergence it
// reproduces is stronger than "allocates before rejecting": the pre-fix Get
// SERVED the over-cap document. os.ReadFile sized its buffer from the FILE, so
// when the file and the recorded length AGREE the only surviving check
// (len(b) != e.Bytes) passes and the document is returned — MaxDocumentBytes
// bounded Put and bounded nothing on the read path, which is the boot path and
// every profile compile.
//
// The file is therefore grown to match the over-cap recorded length. An earlier
// version of this gate set only the recorded length and left the file small, so
// the pre-fix shape rejected it on the length comparison and the gate PASSED
// against the defect — vacuous, which this repo holds to be worse than no gate.
// Mutation-verified against the reintroduced os.ReadFile shape.
func TestGet_OversizeDocumentIsAMiss(t *testing.T) {
	s := newTestStore(t)
	if err := s.Put("corp", KindSAMLMetadata, "https://idp.example/md", []byte("<EntityDescriptor/>")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	oversize := MaxDocumentBytes + 1
	p := docPathFor(s, "corp", KindSAMLMetadata, "https://idp.example/md")
	if err := os.WriteFile(p, make([]byte, oversize), 0o600); err != nil {
		t.Fatalf("grow the cached document: %v", err)
	}
	// Make the index agree with the file, as a corrupt or hand-edited index can,
	// so that ONLY the range check can reject it.
	s.mu.Lock()
	s.entries[key("corp", KindSAMLMetadata, "https://idp.example/md")].Bytes = oversize
	s.mu.Unlock()

	doc, _, err := s.Get("corp", KindSAMLMetadata, "https://idp.example/md")
	if err != ErrNoEntry {
		t.Fatalf("Get on an over-cap document = %v, want ErrNoEntry", err)
	}
	if doc != nil {
		t.Fatalf("Get returned %d bytes for an over-cap document; the cap is not a backstop on the read path", len(doc))
	}
}

// TestGet_ZeroOrNegativeRecordedLengthIsAMiss covers the other end of the range
// check. A zero length would otherwise allocate nothing and hand a parser an
// empty document, which Put refuses to create in the first place.
func TestGet_ZeroOrNegativeRecordedLengthIsAMiss(t *testing.T) {
	for _, n := range []int{0, -1} {
		s := newTestStore(t)
		if err := s.Put("corp", KindSAMLMetadata, "https://idp.example/md", []byte("<EntityDescriptor/>")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		s.mu.Lock()
		k := key("corp", KindSAMLMetadata, "https://idp.example/md")
		e := s.entries[k]
		e.Bytes = n
		s.entries[k] = e
		s.mu.Unlock()
		if _, _, err := s.Get("corp", KindSAMLMetadata, "https://idp.example/md"); err != ErrNoEntry {
			t.Fatalf("Get with recorded length %d = %v, want ErrNoEntry", n, err)
		}
	}
}

// TestGet_LongerThanRecordedIsRefused pins the half of the replaced
// `len(b) != e.Bytes` check that the new bounded read does NOT get for free.
//
// io.ReadFull stops at the recorded length and cannot see trailing bytes, so
// without the one-byte probe a file LONGER than the index says would be accepted
// and a PREFIX of it handed to a parser as though it were the whole document.
// Mutation-verified: removing the probe fails this test.
//
// The SHORTER direction is already covered by TestGet_TruncatedDocumentIsRefused
// above, so it is deliberately not repeated here.
func TestGet_LongerThanRecordedIsRefused(t *testing.T) {
	s := newTestStore(t)
	if err := s.Put("corp", KindSAMLMetadata, "https://idp.example/md", []byte("<EntityDescriptor/>")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	p := docPathFor(s, "corp", KindSAMLMetadata, "https://idp.example/md")
	if err := os.WriteFile(p, []byte("<EntityDescriptor/>trailing"), 0o600); err != nil {
		t.Fatalf("append to the cached document: %v", err)
	}
	if _, _, err := s.Get("corp", KindSAMLMetadata, "https://idp.example/md"); err != ErrNoEntry {
		t.Fatalf("a document longer than its recorded length = %v, want ErrNoEntry", err)
	}
}

// TestGet_HealthyDocumentStillRoundTripsAfterTheBound is the CONTROL. The
// cheapest way to pass every gate above is a Get that refuses everything, which
// would silently delete the entire last-known-good fallback this package exists
// to provide.
func TestGet_HealthyDocumentStillRoundTripsAfterTheBound(t *testing.T) {
	s := newTestStore(t)
	doc := []byte("<EntityDescriptor id=\"exactly-this\"/>")
	if err := s.Put("corp", KindSAMLMetadata, "https://idp.example/md", doc); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, _, err := s.Get("corp", KindSAMLMetadata, "https://idp.example/md")
	if err != nil {
		t.Fatalf("Get on a healthy entry: %v", err)
	}
	if !bytes.Equal(got, doc) {
		t.Fatalf("doc = %q, want %q", got, doc)
	}
}
