// Release Catalog Distribution — P1.5 Slice a (CatalogHolder + atomic publish).
//
// The CatalogHolder owns the live, atomically-swappable verified *Catalog that
// the rest of the Control Plane reads. It is the swap component P1.2 deferred
// ("reload = construct a new *Catalog; the refresh slice will own swap
// semantics; not here"): this slice loads + verifies from a single local
// directory, publishes atomically, exposes an explicit no-catalog state, and a
// manual reload that keeps the current catalog on any failure.
//
// Scope (roadmap/D1.6d-P1.5-catalog-distribution-plan.md — Slice a): holder +
// atomic publish + local-dir reload only. NO goroutine, NO HTTP provider, NO
// cache persistence, NO staleness, NO GUI/API, NO agent/dispatch/air-gap. The
// only path to a published catalog is LoadVerifiedCatalog (the P1.3 trust
// boundary) — there is deliberately no "publish raw *Catalog" entry point.
package main

import "sync/atomic"

// CatalogHolder holds the current verified *Catalog behind an atomic pointer and
// rebuilds it from a local directory on demand. Reads (GetCatalog) are lock-free;
// a publish is a single atomic store of an already-built, already-verified,
// IMMUTABLE *Catalog (P1.2), so a concurrent reader always observes either the
// whole previous catalog, the whole new one, or nil — never a partial one.
type CatalogHolder struct {
	cur   atomic.Pointer[Catalog]
	dir   string
	trust TrustStore
}

// NewCatalogHolder returns a holder that loads/verifies from dir using trust. It
// does NOT load yet: until the first successful Reload, GetCatalog returns nil
// (the explicit no-catalog state).
func NewCatalogHolder(dir string, trust TrustStore) *CatalogHolder {
	return &CatalogHolder{dir: dir, trust: trust}
}

// GetCatalog returns the currently-published catalog, or nil if none is
// published. The returned *Catalog is immutable; to observe the freshest
// catalog, call GetCatalog again (do not retain it across a refresh point).
func (h *CatalogHolder) GetCatalog() *Catalog { return h.cur.Load() }

// HasCatalog reports whether a catalog is currently published (vs the explicit
// no-catalog state).
func (h *CatalogHolder) HasCatalog() bool { return h.cur.Load() != nil }

// store atomically publishes an already-verified, immutable *Catalog. It is the
// single publish primitive: every caller (Reload here, the Refresher in P1.5b)
// MUST have run the bytes through LoadVerifiedCatalog first. Kept unexported so
// no external caller can publish an unverified catalog (the trust boundary).
func (h *CatalogHolder) store(cat *Catalog) { h.cur.Store(cat) }

// Reload builds and VERIFIES a catalog from the holder's local dir via
// LoadVerifiedCatalog (the P1.3 trust boundary) and, on success, atomically
// publishes it. On ANY failure (read/parse/verify) it returns the error and
// leaves the current catalog untouched — a failed reload never clears or
// partially replaces a good catalog.
//
// It serves both the startup load (the caller treats an error as the no-catalog
// state and continues — the catalog is not on the proxy hot path) and a manual
// reload.
func (h *CatalogHolder) Reload() error {
	// A *dirCatalogSource satisfies SignedCatalogSource (ReadIndex/ReadManifest
	// from P1.2 + ReadSignature from P1.3): symlink-refusing and size-bounded.
	src := &dirCatalogSource{dir: h.dir}
	cat, err := LoadVerifiedCatalog(src, h.trust)
	if err != nil {
		return err // keep the current catalog (which may be nil)
	}
	h.store(cat)
	return nil
}
