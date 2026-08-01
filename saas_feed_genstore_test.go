package main

// F3b-2 immutable-generation-store tests. Required-test classes: 20 (golden layout),
// 21 (write/sync/rename/dir-sync/read-back failure injection), 22 (exact-generation
// idempotency), 23 (same-version/different-digest conflict), 24 (deterministic
// concurrent acquisition), 25 (cancellation at every persistence stage), 26 (no
// committed directory after partial failure).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// candFromGen builds a persist candidate from a generated feed (as the client does).
func candFromGen(g feedGen) generationCandidate {
	return generationCandidate{
		FeedVersion:    g.Manifest.FeedVersion,
		GenerationID:   feedVersionID(g.Manifest.FeedVersion),
		GeneratedAt:    g.Manifest.GeneratedAt,
		ExpiresAt:      g.Manifest.ExpiresAt,
		ManifestSHA256: sha256Hex(g.EnvelopeBytes),
		ArtifactSHA256: g.Manifest.ArtifactSHA256,
		ArtifactSize:   g.Manifest.ArtifactSize,
		CategoryCount:  g.Manifest.CategoryCount,
		HostCount:      g.Manifest.HostCount,
		EnvelopeBytes:  g.EnvelopeBytes,
		ArtifactBytes:  g.ArtifactBytes,
		BundleBytes:    g.BundleBytes,
		SnapshotBytes: []byte(fmt.Sprintf(
			`{"schema_version":1,"feed":"url-categories/saas","feed_version":%d,"generated_at":%q,"categories":[]}`,
			g.Manifest.FeedVersion, g.Manifest.GeneratedAt)),
	}
}

// ── 20. immutable generation golden layout ───────────────────────────────────────

func TestF3b2_Gen_GoldenLayout(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	root := filepath.Join(t.TempDir(), "generations")
	store, err := newGenerationStore(root)
	if err != nil {
		t.Fatalf("newGenerationStore: %v", err)
	}
	res, err := store.Persist(context.Background(), candFromGen(g))
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if res.Outcome != genPersistCommitted {
		t.Fatalf("outcome = %s; want committed", res.Outcome)
	}
	dir := filepath.Join(root, "42")
	if res.Dir != dir {
		t.Fatalf("dir = %q; want %q", res.Dir, dir)
	}
	// Exactly the four immutable files, each with the exact wire bytes.
	entries, _ := os.ReadDir(dir)
	got := []string{}
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	want := []string{genFileArtifact, genFileArtifactBundle, genFileSnapshotNormalized, genFileMeta, genFileManifestEnvelope}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("dir entries = %v; want %v", got, want)
	}
	assertFileBytes(t, filepath.Join(dir, genFileManifestEnvelope), g.EnvelopeBytes)
	assertFileBytes(t, filepath.Join(dir, genFileArtifact), g.ArtifactBytes)
	assertFileBytes(t, filepath.Join(dir, genFileArtifactBundle), g.BundleBytes)

	// The metadata record round-trips and binds the digests + version.
	metaBytes, _ := os.ReadFile(filepath.Join(dir, genFileMeta))
	var meta generationMeta
	if err := strictDecodeJSON(metaBytes, &meta); err != nil {
		t.Fatalf("meta decode: %v", err)
	}
	if meta.FeedVersion != 42 || meta.GenerationID != "42" ||
		meta.ManifestSHA256 != sha256Hex(g.EnvelopeBytes) ||
		meta.ArtifactSHA256 != g.Manifest.ArtifactSHA256 ||
		meta.Protocol != urlcatfeed.Protocol || meta.Feed != urlcatfeed.FeedID {
		t.Fatalf("meta record does not bind the generation: %+v", meta)
	}
	// Directory + files carry the tightened permissions.
	assertPerm(t, dir, 0o700)
	assertPerm(t, filepath.Join(dir, genFileMeta), 0o600)
	// No staging directory left behind.
	assertNoStaging(t, root)
}

// ── 22. exact-generation idempotency ─────────────────────────────────────────────

func TestF3b2_Gen_Idempotent(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	store, _ := newGenerationStore(filepath.Join(t.TempDir(), "generations"))
	if _, err := store.Persist(context.Background(), candFromGen(g)); err != nil {
		t.Fatalf("first persist: %v", err)
	}
	res, err := store.Persist(context.Background(), candFromGen(g))
	if err != nil {
		t.Fatalf("second persist: %v", err)
	}
	if res.Outcome != genPersistIdempotent {
		t.Fatalf("outcome = %s; want idempotent", res.Outcome)
	}
}

// ── 23. same-version / different-digest conflict ─────────────────────────────────

func TestF3b2_Gen_Conflict(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	store, _ := newGenerationStore(filepath.Join(t.TempDir(), "generations"))
	if _, err := store.Persist(context.Background(), candFromGen(g)); err != nil {
		t.Fatalf("first persist: %v", err)
	}
	// A DIFFERENT generation claiming the same id (same feed_version, different bytes).
	g2 := buildFeedGen(t, feedGenOpts{feedVersion: 42, validity: 10 * 24 * 60 * 60 * 1e9})
	cand2 := candFromGen(g2)
	// Force a genuinely different artifact so the digests differ while keeping the id.
	cand2 = mutateArtifact(cand2)
	_, err := store.Persist(context.Background(), cand2)
	if !errors.Is(err, errGenConflict) {
		t.Fatalf("err = %v; want errGenConflict", err)
	}
	// The original generation is untouched.
	assertFileBytes(t, filepath.Join(store.root, "42", genFileArtifact), g.ArtifactBytes)
}

// ── 21 + 26. failure injection at each stage ⇒ no committed dir ───────────────────

func TestF3b2_Gen_FailureInjection(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	cand := candFromGen(g)

	// PRE-commit (pre-rename) stages: an injected failure leaves NO committed dir.
	stages := map[string]func(fs *fakeGenFS){
		"mkdirAll":    func(fs *fakeGenFS) { fs.failMkdirAll = true },
		"mkdirTemp":   func(fs *fakeGenFS) { fs.failMkdirTemp = true },
		"atomicWrite": func(fs *fakeGenFS) { fs.failWriteOn = genFileArtifact },
		"readBack":    func(fs *fakeGenFS) { fs.corruptReadBackOn = genFileArtifact },
		"syncStage":   func(fs *fakeGenFS) { fs.failSyncDir = 1 }, // first syncDir = staging
		"rename":      func(fs *fakeGenFS) { fs.failRename = true },
	}
	for name, brk := range stages {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "generations")
			inner := osGenFS()
			fs := newFakeGenFS(inner)
			brk(fs)
			store, err := newGenerationStoreFS(fs.seam(), root)
			if err != nil {
				t.Fatalf("store: %v", err)
			}
			_, err = store.Persist(context.Background(), cand)
			if err == nil {
				t.Fatalf("%s: expected a failure", name)
			}
			// No committed generation directory exists (a temporary/partial state never
			// appears as committed).
			if _, statErr := os.Stat(filepath.Join(root, "42")); statErr == nil {
				t.Fatalf("%s: a committed dir exists after an injected failure", name)
			}
			// No staging directory leaked (owned-path cleanup ran).
			assertNoStaging(t, root)
		})
	}
}

// A parent-dir sync failure happens AFTER the commit rename: the generation is
// physically committed (all files were written + read-back verified before the
// rename), so Persist returns an error for the durability lapse but the dir exists and
// a retry is idempotent — never a partial/torn state.
func TestF3b2_Gen_ParentSyncFailurePostCommit(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	cand := candFromGen(g)
	root := filepath.Join(t.TempDir(), "generations")
	fs := newFakeGenFS(osGenFS())
	fs.failSyncDir = 2 // 1 = staging (ok), 2 = parent (fail, post-rename)
	store, _ := newGenerationStoreFS(fs.seam(), root)
	if _, err := store.Persist(context.Background(), cand); err == nil {
		t.Fatal("expected an error on parent-dir sync failure")
	}
	// The committed dir exists and is intact (all four files, exact bytes).
	assertFileBytes(t, filepath.Join(root, "42", genFileArtifact), g.ArtifactBytes)
	// A retry (with a healthy FS) reconciles to idempotent — no overwrite, no conflict.
	store2, _ := newGenerationStore(root)
	res, err := store2.Persist(context.Background(), cand)
	if err != nil || res.Outcome != genPersistIdempotent {
		t.Fatalf("retry: outcome=%s err=%v; want idempotent", res.Outcome, err)
	}
}

// ── 25. cancellation at every persistence stage ⇒ no committed dir ───────────────

func TestF3b2_Gen_CancelEachStage(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	cand := candFromGen(g)
	// Cancel BEFORE each ctx checkpoint by injecting a hook that cancels at a chosen
	// filesystem step.
	steps := []string{"before", "afterFirstWrite", "beforeRename"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "generations")
			inner := osGenFS()
			fs := newFakeGenFS(inner)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel() // idempotent; hooks may also call it — silences vet lostcancel
			switch step {
			case "before":
				cancel()
			case "afterFirstWrite":
				fs.afterWrite = func(name string) {
					if name == genFileManifestEnvelope {
						cancel()
					}
				}
			case "beforeRename":
				// Cancel right after the staging sync so the pre-rename ctx check fires.
				fs.afterSyncDir = func(n int64) {
					if n == 1 {
						cancel()
					}
				}
			}
			store, _ := newGenerationStoreFS(fs.seam(), root)
			_, err := store.Persist(ctx, cand)
			if err == nil {
				t.Fatalf("%s: expected cancellation", step)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s: err = %v; want context.Canceled", step, err)
			}
			if _, statErr := os.Stat(filepath.Join(root, "42")); statErr == nil {
				t.Fatalf("%s: committed dir exists after cancellation", step)
			}
			assertNoStaging(t, root)
		})
	}
}

// ── 24. deterministic concurrent acquisition of the SAME generation ──────────────

func TestF3b2_Gen_ConcurrentSameGeneration(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	store, _ := newGenerationStore(filepath.Join(t.TempDir(), "generations"))

	const n = 8
	var wg sync.WaitGroup
	results := make([]genPersistResult, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = store.Persist(context.Background(), candFromGen(g))
		}(i)
	}
	close(start)
	wg.Wait()

	committed := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		switch results[i].Outcome {
		case genPersistCommitted:
			committed++
		case genPersistIdempotent:
		default:
			t.Fatalf("goroutine %d: unexpected outcome %s", i, results[i].Outcome)
		}
	}
	if committed != 1 {
		t.Fatalf("committed = %d; want exactly one committer (rest idempotent)", committed)
	}
	// The single committed directory holds the exact bytes.
	assertFileBytes(t, filepath.Join(store.root, "42", genFileArtifact), g.ArtifactBytes)
}

// ── conflicting concurrent candidates cannot overwrite each other ────────────────

func TestF3b2_Gen_ConcurrentConflict(t *testing.T) {
	g1 := buildFeedGen(t, feedGenOpts{feedVersion: 7})
	g2 := buildFeedGen(t, feedGenOpts{feedVersion: 7, validity: 20 * 24 * 60 * 60 * 1e9})
	cand2 := mutateArtifact(candFromGen(g2))
	store, _ := newGenerationStore(filepath.Join(t.TempDir(), "generations"))

	var wg sync.WaitGroup
	var err1, err2 error
	start := make(chan struct{})
	wg.Add(2)
	go func() { defer wg.Done(); <-start; _, err1 = store.Persist(context.Background(), candFromGen(g1)) }()
	go func() { defer wg.Done(); <-start; _, err2 = store.Persist(context.Background(), cand2) }()
	close(start)
	wg.Wait()

	// Exactly one succeeds; the other is a hard conflict (never a silent overwrite).
	ok1, ok2 := err1 == nil, err2 == nil
	if ok1 == ok2 {
		t.Fatalf("expected exactly one success: err1=%v err2=%v", err1, err2)
	}
	loser := err1
	if ok1 {
		loser = err2
	}
	if !errors.Is(loser, errGenConflict) {
		t.Fatalf("loser err = %v; want errGenConflict", loser)
	}
}

// ── invalid candidate is rejected before any filesystem action ───────────────────

func TestF3b2_Gen_InvalidCandidate(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	store, _ := newGenerationStore(filepath.Join(t.TempDir(), "generations"))
	cand := candFromGen(g)
	cand.ArtifactSHA256 = strings.Repeat("a", 64) // wrong digest for the bytes
	if _, err := store.Persist(context.Background(), cand); !errors.Is(err, errGenNotVerified) {
		t.Fatalf("err = %v; want errGenNotVerified", err)
	}
	if _, statErr := os.Stat(filepath.Join(store.root, "42")); statErr == nil {
		t.Fatal("committed dir exists for an unverified candidate")
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────────

func mutateArtifact(c generationCandidate) generationCandidate {
	// Produce a genuinely different artifact byte stream + consistent digest/size so
	// the candidate is self-consistent but differs from the id's existing content.
	c.ArtifactBytes = append(append([]byte(nil), c.ArtifactBytes...), []byte("  ")...)
	c.ArtifactSHA256 = sha256Hex(c.ArtifactBytes)
	c.ArtifactSize = int64(len(c.ArtifactBytes))
	return c
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: bytes differ (got %d, want %d)", path, len(got), len(want))
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if fi.Mode().Perm() != want {
		t.Fatalf("%s perm = %o; want %o", path, fi.Mode().Perm(), want)
	}
}

func assertNoStaging(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("readdir %s: %v", root, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), genStagePrefix) {
			t.Fatalf("leaked staging dir %q", e.Name())
		}
	}
}
