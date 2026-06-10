// Release Catalog Distribution — P1.5 Slice b (Refresher + last-good cache +
// staleness).
//
// The Refresher orchestrates stage → verify → publish on top of the P1.5a
// CatalogHolder, adds a last-good on-disk cache (restart durability), single-
// flight, refresh metadata, and staleness. It still uses a LOCAL directory as
// the source — the HTTP provider and air-gap bundle are later slices.
//
// Scope (roadmap/D1.6d-P1.5-catalog-distribution-plan.md — Slice b): refresher +
// cache + staleness + single-flight + an OPTIONAL (default-off) interval ticker.
// NO HTTP provider, NO air-gap bundle, NO GUI/API, NO agent/dispatch, NO
// metrics/alert wiring. Every publish still goes through LoadVerifiedCatalog
// (the P1.3 trust boundary); the cache is re-verified on load.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	// errRefreshInFlight is returned by a trigger that arrives while another
	// refresh is already running (single-flight; the in-flight one wins).
	errRefreshInFlight = errors.New("release catalog: refresh already in flight")
	// errNoCatalog is recorded when neither the cache nor the source yields a
	// verifiable catalog at startup.
	errNoCatalog = errors.New("release catalog: no verifiable catalog (cache or source)")
)

// RefreshMeta is an immutable snapshot of the refresher's bookkeeping.
type RefreshMeta struct {
	LastAttempt time.Time // wall clock of the last refresh attempt (success or fail)
	LastSuccess time.Time // wall clock of the last successful publish (zero if none)
	LastError   string    // last error text ("" after a success)
	GeneratedAt time.Time // GeneratedAt of the currently-published catalog (zero if none)
	HasCatalog  bool      // whether a catalog is currently published
}

// Refresher loads + verifies a catalog from a local source dir, publishes it via
// the holder, persists the last-good copy to a cache dir, and tracks refresh
// metadata + staleness. All publishes are verified (the cache too, on load).
type Refresher struct {
	holder   *CatalogHolder
	source   string // local source directory (P1.5b)
	cacheDir string // last-good cache directory
	trust    TrustStore

	interval time.Duration // 0 ⇒ the optional ticker is DISABLED (default)
	jitter   time.Duration // max jitter added to interval

	now func() time.Time // injectable clock (tests)

	mu       sync.Mutex
	inflight bool
	meta     RefreshMeta
}

// NewRefresher builds a refresher over a local source dir and a cache dir. The
// interval ticker is disabled by default (SetSchedule to enable).
func NewRefresher(source, cacheDir string, trust TrustStore) *Refresher {
	return &Refresher{
		holder:   NewCatalogHolder(source, trust),
		source:   source,
		cacheDir: cacheDir,
		trust:    trust,
		now:      time.Now,
	}
}

// SetSchedule enables the optional interval ticker (interval > 0) with up to
// jitter of added delay per tick. interval == 0 keeps it disabled.
func (r *Refresher) SetSchedule(interval, jitter time.Duration) {
	r.interval = interval
	r.jitter = jitter
}

// GetCatalog returns the currently-published catalog (nil ⇒ no-catalog state).
func (r *Refresher) GetCatalog() *Catalog { return r.holder.GetCatalog() }

// Meta returns a snapshot of the refresh bookkeeping.
func (r *Refresher) Meta() RefreshMeta {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.meta
}

// Staleness reports how old the published catalog is. catalogAge = now -
// GeneratedAt (content age); sinceRefresh = now - last successful refresh. ok is
// false when no catalog is published. Staleness never invalidates a catalog —
// it is an operator signal (plan §12).
func (r *Refresher) Staleness() (catalogAge, sinceRefresh time.Duration, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.meta.HasCatalog {
		return 0, 0, false
	}
	now := r.now()
	return now.Sub(r.meta.GeneratedAt), now.Sub(r.meta.LastSuccess), true
}

// ─── single-flight ───────────────────────────────────────────────────────────

func (r *Refresher) begin() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inflight {
		return false
	}
	r.inflight = true
	return true
}

func (r *Refresher) end() {
	r.mu.Lock()
	r.inflight = false
	r.mu.Unlock()
}

// ─── triggers ────────────────────────────────────────────────────────────────

// Start performs the startup load: it re-verifies BOTH the cache and the source
// and publishes the NEWEST verified one by GeneratedAt (so a fresh signed seed
// after an upgrade is not masked by a stale cache — plan §7). If neither
// verifies, it leaves the no-catalog state. Returns the error only when nothing
// could be published (the caller may treat that as a soft, boot-anyway state).
func (r *Refresher) Start() error {
	if !r.begin() {
		return errRefreshInFlight
	}
	defer r.end()
	return r.startup()
}

// Refresh runs one source → verify → persist → publish cycle (the manual /
// ticker trigger). Single-flight: a concurrent trigger returns errRefreshInFlight
// without starting a second refresh. A failed refresh keeps the current catalog.
func (r *Refresher) Refresh() error {
	if !r.begin() {
		return errRefreshInFlight
	}
	defer r.end()
	return r.refreshFromSource()
}

// RunTicker blocks, refreshing on the configured interval (+ jitter) until ctx
// is cancelled. It is a no-op when the ticker is disabled (interval <= 0). The
// CALLER decides whether to run it in a goroutine; the Refresher spawns none
// itself.
func (r *Refresher) RunTicker(ctx context.Context) {
	if r.interval <= 0 {
		return
	}
	for {
		timer := time.NewTimer(r.interval + r.jitterDur())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			_ = r.Refresh() // errors are recorded in meta; keep ticking
		}
	}
}

func (r *Refresher) jitterDur() time.Duration {
	if r.jitter <= 0 {
		return 0
	}
	// Non-security jitter: spread ticks without a PRNG dependency.
	return time.Duration(r.now().UnixNano()) % r.jitter
}

// ─── core ────────────────────────────────────────────────────────────────────

func (r *Refresher) verifyDir(dir string) (*Catalog, error) {
	return LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, r.trust)
}

// startup re-verifies cache + source and publishes the newest verified by
// GeneratedAt (tie → source, the upgrade-shipped floor).
func (r *Refresher) startup() error {
	r.recordAttempt()

	cacheCat, _ := r.verifyDir(r.cacheDir)  // corrupt/absent cache → skipped
	srcCat, srcErr := r.verifyDir(r.source) // source error is the reportable one

	chosen, fromSource := pickNewerCatalog(cacheCat, srcCat)
	if chosen == nil {
		if srcErr != nil {
			r.recordError(srcErr)
			return srcErr
		}
		r.recordError(errNoCatalog)
		return errNoCatalog
	}
	if fromSource {
		// The newest verified came from the source — refresh the cache to match.
		if perr := r.persistCache(r.source); perr != nil && logger != nil {
			logger.Printf("release catalog: cache persist failed: %v (publishing in-memory anyway)", perr)
		}
	}
	r.holder.store(chosen)
	r.recordSuccess(chosen)
	return nil
}

func (r *Refresher) refreshFromSource() error {
	r.recordAttempt()
	cat, err := r.verifyDir(r.source)
	if err != nil {
		r.recordError(err) // keep the current catalog
		return err
	}
	if perr := r.persistCache(r.source); perr != nil && logger != nil {
		logger.Printf("release catalog: cache persist failed: %v (publishing in-memory anyway)", perr)
	}
	r.holder.store(cat)
	r.recordSuccess(cat)
	return nil
}

// pickNewerCatalog returns the non-nil catalog with the newer GeneratedAt, and
// whether it was the source. Tie or only-source → source; only-cache → cache.
func pickNewerCatalog(cacheCat, srcCat *Catalog) (chosen *Catalog, fromSource bool) {
	switch {
	case cacheCat == nil && srcCat == nil:
		return nil, false
	case cacheCat == nil:
		return srcCat, true
	case srcCat == nil:
		return cacheCat, false
	case srcCat.GeneratedAt().Before(cacheCat.GeneratedAt()):
		return cacheCat, false
	default: // source newer or equal ⇒ prefer source
		return srcCat, true
	}
}

// ─── metadata (mutex-guarded) ────────────────────────────────────────────────

func (r *Refresher) recordAttempt() {
	r.mu.Lock()
	r.meta.LastAttempt = r.now()
	r.mu.Unlock()
}

func (r *Refresher) recordError(err error) {
	r.mu.Lock()
	r.meta.LastError = err.Error()
	r.mu.Unlock()
}

func (r *Refresher) recordSuccess(cat *Catalog) {
	r.mu.Lock()
	r.meta.LastSuccess = r.now()
	r.meta.LastError = ""
	r.meta.GeneratedAt = cat.GeneratedAt()
	r.meta.HasCatalog = true
	r.mu.Unlock()
}

// ─── last-good on-disk cache (stage → atomic rename) ─────────────────────────

// persistCache copies the verified catalog files from srcDir into a fresh
// staging dir and atomically renames it onto cacheDir (plan §9.1). The rename
// requires cacheDir to be absent, so the previous cache is removed first; a
// crash in that brief window simply leaves no cache (startup re-verifies the
// source), never a partial one — the in-memory catalog stays authoritative.
func (r *Refresher) persistCache(srcDir string) (err error) {
	parent := filepath.Dir(r.cacheDir)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".catalog-cache-stage-*")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stage)
		}
	}()

	if err := os.MkdirAll(filepath.Join(stage, "manifests"), 0o750); err != nil {
		return err
	}
	if err := copyCatalogFile(filepath.Join(srcDir, "index.json"), filepath.Join(stage, "index.json")); err != nil {
		return err
	}
	// The signature is optional only under permissive/unsigned; copy it when present.
	if err := copyCatalogFileOptional(filepath.Join(srcDir, "index.json.sig"), filepath.Join(stage, "index.json.sig")); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(srcDir, "manifests"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
			continue // defense: ReadDir yields base names, but never copy a non-base
		}
		if err := copyCatalogFile(filepath.Join(srcDir, "manifests", name), filepath.Join(stage, "manifests", name)); err != nil {
			return err
		}
	}

	if err := os.RemoveAll(r.cacheDir); err != nil {
		return err
	}
	if err := os.Rename(stage, r.cacheDir); err != nil {
		return err
	}
	committed = true
	return nil
}

func copyCatalogFileOptional(srcPath, dstPath string) error {
	if _, err := os.Lstat(srcPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return copyCatalogFile(srcPath, dstPath)
}

// copyCatalogFile copies one file. Paths are built from the operator-configured
// catalog/cache dirs with fixed names or validated base entries — not external
// input — so the G304 reads are safe.
func copyCatalogFile(srcPath, dstPath string) (err error) {
	in, err := os.Open(srcPath) // #nosec G304 -- path under the operator-configured catalog dir (fixed/validated names)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- dst under the cache staging dir
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", filepath.Base(dstPath), cerr)
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return nil
}
