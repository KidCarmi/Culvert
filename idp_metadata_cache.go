package main

// idp_metadata_cache.go — CHAOS-66 composition root for internal/idpmeta.
//
// This file owns the singleton last-known-good document store and the two
// wrappers the IdP compile path uses in place of a bare fetch. Everything that
// decides WHAT a document means stays in auth_saml.go / auth_oidc_flow.go: the
// store returns raw bytes and this file never parses them.
//
// THE INVARIANT, stated here because it is the one a future change is most
// likely to break: **cached bytes must go through the identical parser and
// validator as network bytes.** `acquireIdPDocument` returns bytes and an
// origin; the caller then runs its existing parse/validate on the result
// regardless of where it came from. If a cached document were ever parsed by a
// laxer path — or trusted structurally because "we fetched it once" — anything
// with write access to dataDir could widen a trust decision by editing a file,
// and the OIDC discovery document in particular names the authorization and
// token endpoints this appliance will send users and credentials to.

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/idpmeta"
)

// idpMetaDirName is the store's directory under dataDir. Like every other
// persisted-state path it is rebound by the CULVERT_DATA_DIR override.
const idpMetaDirName = "idp_metadata_cache"

var (
	idpMetaStore   *idpmeta.Store
	idpMetaStoreMu sync.RWMutex
)

// idpMetadataStore returns the process-wide document cache, constructing it on
// first use against the effective dataDir.
//
// Deliberately NOT a sync.Once: swapIdPMetadataStore restores the PREVIOUS
// value, which on the first swap is nil, and a consumed Once would then leave
// every later caller with a nil (inert) store for the rest of the process —
// a test-only seam silently disabling the production path it exists to test.
// Lazy-under-lock has no such trapdoor.
func idpMetadataStore() *idpmeta.Store {
	idpMetaStoreMu.RLock()
	if s := idpMetaStore; s != nil {
		idpMetaStoreMu.RUnlock()
		return s
	}
	idpMetaStoreMu.RUnlock()

	idpMetaStoreMu.Lock()
	defer idpMetaStoreMu.Unlock()
	if idpMetaStore == nil {
		idpMetaStore = idpmeta.New(filepath.Join(dataDir, idpMetaDirName))
	}
	return idpMetaStore
}

// swapIdPMetadataStore installs a store for tests and returns a restore func.
// Mirrors swapAutoExclude: the singleton is process-global, so a test that
// does not isolate it leaks cached documents into unrelated tests (the PR3d
// fence-pollution class).
func swapIdPMetadataStore(s *idpmeta.Store) func() {
	idpMetaStoreMu.Lock()
	prev := idpMetaStore
	idpMetaStore = s
	idpMetaStoreMu.Unlock()
	return func() {
		idpMetaStoreMu.Lock()
		idpMetaStore = prev
		idpMetaStoreMu.Unlock()
	}
}

func idpmetaStaleMaxAgeString() string {
	return (idpmeta.StaleMaxAge).String()
}

// acquireIdPDocument is the ONE entry point the IdP compile path uses to get a
// remote document.
//
// Order, and why it is this order:
//
//  1. Try the network. A healthy appliance is byte-identical to the pre-fix
//     one — same client, same timeout, same SSRF guard, same limits — and
//     always prefers what the IdP is publishing NOW. The cache is a fallback,
//     never a first choice, so an IdP-side key rotation is picked up at the
//     first compile after it happens exactly as before.
//
//  2. On success, persist the raw bytes as last-known-good. A persist failure
//     is logged and IGNORED: the fetch succeeded, so the only cost is that a
//     future outage has no fallback, and failing a working compile because a
//     cache write failed would be strictly worse than not having the cache.
//
//  3. On failure, fall back to the last-known-good document if one exists
//     within idpmeta.StaleMaxAge. Past the ceiling — or with nothing cached —
//     the original fetch error is returned unchanged and the caller fails
//     exactly as it did before this package existed.
//
// The `fetch` seam takes no arguments and returns raw bytes so this function
// stays protocol-agnostic and so tests can drive every branch without a
// network. Where the bytes came from is reported through
// noteIdPMetadataOutcome rather than returned: the caller's job is identical
// either way (parse and validate them), and a returned origin nobody consults
// is an invitation to start treating cached bytes differently.
func acquireIdPDocument(profileID string, kind idpmeta.Kind, source string, fetch func() ([]byte, error)) ([]byte, error) {
	store := idpMetadataStore()

	doc, err := fetch()
	if err == nil && len(doc) > 0 {
		if putErr := store.Put(profileID, kind, source, doc); putErr != nil {
			// Not fatal — see (2) above. Rate-limiting is unnecessary: this
			// line is emitted only on a SUCCESSFUL fetch, which is bounded by
			// the compile rate, and a persistently failing write is already
			// carried by the storage-health plane.
			logger.Printf("IdP[%s]: metadata cached document could not be persisted (%v); a future IdP outage will have no fallback on this node",
				sanitizeLog(profileID), putErr)
		}
		noteIdPMetadataOutcome(profileID, idpMetaFresh, nil)
		return doc, nil
	}
	if err == nil {
		err = fmt.Errorf("IdP returned an empty document")
	}

	cached, age, cacheErr := store.Get(profileID, kind, source)
	if cacheErr != nil {
		noteIdPMetadataOutcome(profileID, idpMetaUnavailable, err)
		return nil, err
	}
	noteIdPMetadataOutcome(profileID, idpMetaStale, err)
	logger.Printf("IdP[%s]: metadata fetch failed (%v) — continuing from the cached document fetched %s ago (refused past %s)",
		sanitizeLog(profileID), sanitizeLog(fmt.Sprint(err)), age.Round(time.Second), idpmetaStaleMaxAgeString())
	return cached, nil
}
