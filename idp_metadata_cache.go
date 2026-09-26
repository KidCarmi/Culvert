package main

// idp_metadata_cache.go — CHAOS-71 composition root for internal/idpmeta.
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

// resolveIdPDocument adjudicates ONE document acquisition: the caller has
// already attempted the network fetch and hands over its result, and this
// function decides what the compile proceeds with.
//
// It takes the fetch RESULT rather than a fetch CLOSURE on purpose. A closure
// seam would put this file between the profile config and the outbound
// request, which is how CHAOS-71's first two attempts moved the SAML metadata
// URL through an extra parse -> String() -> parameter -> re-parse hop and
// raised a critical go/request-forgery alert: the taint reached the request
// through a function boundary instead of being parsed and guarded where it is
// used. Adjudicating a result keeps every outbound request in the same
// function as its own guard, exactly as it was before this sweep, and this
// file never touches a URL that is about to be dialled.
//
// Order, and why it is this order:
//
//  1. A successful fetch WINS, always. The cache is a fallback, never a first
//     choice, so an IdP-side key rotation is picked up at the first compile
//     after it happens exactly as before.
//
//  2. A fetched document is persisted as last-known-good — and reported
//     FRESH — only after `validate` (the caller's own parser/validator, the
//     one it runs on the result either way) accepts it. An IdP answering 200
//     with a malformed or invalid document is NOT an answer: persisting it
//     first overwrote the valid last-known-good copy, so a later outage fell
//     back to the broken bytes and the provider could never recover from the
//     cache (Codex review). An invalid document is therefore treated like a
//     failed fetch and falls through to (3). A persist
//     failure is logged and IGNORED: the fetch succeeded, so the only cost is
//     that a FUTURE outage has no fallback, and failing a working compile
//     because a cache write failed would be strictly worse than no cache.
//
//  3. On failure, fall back to the last-known-good document if one exists
//     within idpmeta.StaleMaxAge. Past the ceiling — or with nothing cached —
//     the original fetch error is returned unchanged and the caller fails
//     exactly as it did before this package existed.
func resolveIdPDocument(profileID string, kind idpmeta.Kind, source string, doc []byte, fetchErr error, validate func([]byte) error) ([]byte, error) {
	store := idpMetadataStore()

	if fetchErr == nil && len(doc) > 0 && validate != nil {
		if vErr := validate(doc); vErr != nil {
			fetchErr = fmt.Errorf("IdP returned an invalid document: %w", vErr)
		}
	}
	if fetchErr == nil && len(doc) > 0 {
		if putErr := store.Put(profileID, kind, source, doc); putErr != nil {
			// Not fatal — see (2) above. Rate-limiting is unnecessary: this
			// line is emitted only on a SUCCESSFUL fetch, which is bounded by
			// the compile rate, and a persistently failing write is already
			// carried by the storage-health plane.
			logger.Printf("IdP[%s]: metadata cached document could not be persisted (%v); a future IdP outage will have no fallback on this node",
				sanitizeLog(profileID), putErr)
		}
		noteIdPMetadataOutcome(profileID, source, idpMetaFresh, nil)
		return doc, nil
	}
	if fetchErr == nil {
		fetchErr = fmt.Errorf("IdP returned an empty document")
	}

	cached, age, cacheErr := store.Get(profileID, kind, source)
	if cacheErr != nil {
		noteIdPMetadataOutcome(profileID, source, idpMetaUnavailable, fetchErr)
		return nil, fetchErr
	}
	// The CACHED bytes go through the caller's validator too, BEFORE this is
	// reported as a stale-but-usable service (Codex review round 3). Validating
	// only the fetched bytes made the stale path claim a compile that did not
	// happen: same-length disk corruption, or a validator tightened across an
	// upgrade, yields bytes the caller then rejects, while
	// culvert_idp_metadata_stale_served_total had already counted a success and
	// the log line had already said compilation was continuing. A cached
	// document the caller cannot use is not a fallback, so it is reported as
	// UNAVAILABLE and the original fetch error is returned unchanged — the same
	// verdict as having nothing cached at all.
	if validate != nil {
		if vErr := validate(cached); vErr != nil {
			noteIdPMetadataOutcome(profileID, source, idpMetaUnavailable, fetchErr)
			logger.Printf("IdP[%s]: metadata fetch failed (%v) AND the cached document fetched %s ago is no longer usable (%v) — this profile cannot be compiled",
				sanitizeLog(profileID), sanitizeLog(fmt.Sprint(fetchErr)), age.Round(time.Second), sanitizeLog(fmt.Sprint(vErr)))
			return nil, fetchErr
		}
	}
	noteIdPMetadataOutcome(profileID, source, idpMetaStale, fetchErr)
	// Record WHEN this document was fetched, so the ceiling stays enforceable
	// after the compile returns. Store.Get owns idpmeta.StaleMaxAge, but it is
	// reached only from a compile, and a steady-state node never recompiles —
	// see noteIdPStaleDocumentServed (Codex review round 8).
	noteIdPStaleDocumentServed(profileID, source, time.Now().Add(-age))
	logger.Printf("IdP[%s]: metadata fetch failed (%v) — continuing from the cached document fetched %s ago (refused past %s)",
		sanitizeLog(profileID), sanitizeLog(fmt.Sprint(fetchErr)), age.Round(time.Second), idpmetaStaleMaxAgeString())
	return cached, nil
}
