package main

// idp_metadata_cache.go — CHAOS-87 composition root for internal/idpmeta.
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
	"errors"
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
// request, which is how CHAOS-87's first two attempts moved the SAML metadata
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
//  3. On failure, fall back to the last-known-good document ONLY when the
//     failure is an AVAILABILITY failure (idpFetchStaleEligible: a transport
//     error or an HTTP 5xx — RFC 5861 stale-if-error semantics), and only
//     within idpmeta.StaleMaxAge. An IdP that ANSWERED — a 4xx, any other
//     non-200 status, an empty body, or a document the validator refuses —
//     has given an answer, not an outage, and the cache is not consulted.
//     Past the ceiling, with nothing cached, or on an answer, the original
//     fetch error is returned unchanged and the caller fails exactly as it
//     did before this package existed. An unreachable IdP is degraded
//     availability; an IdP that says "no" is not something the cache may
//     paper over.
//
//  4. A cached document is served only within min(idpmeta.StaleMaxAge, the
//     document's own expiry). `expiry` reports that expiry (SAML metadata
//     validUntil); nil, or a zero time, means the document declares none. A
//     cached document whose expiry has passed is refused exactly like one past
//     the seven-day ceiling.
//
// The second result is WHEN the returned document was fetched from the IdP if it
// came from the cache, and zero if it was fetched now. It is handed back to the
// caller rather than recorded here because a fetch is not a publication: only
// the site that PUBLISHES the provider built from this document may record it as
// the served generation (Codex review round 14 — see idpNotePublishedGeneration).
//
// gen is the profile's cache retirement epoch, taken by the caller BEFORE it
// dialled the IdP (idpmeta.Store.Generation). A fetched document is recorded
// only if no committed deletion retired the profile's documents while the fetch
// was in flight (register row IDP-18): otherwise a late fetch would write the
// deleted generation's metadata back, and a profile recreated under the same id
// and source during an outage would compile from it. Taking the epoch here,
// after the network call, could not see a deletion that landed during it.
func resolveIdPDocument(profileID string, kind idpmeta.Kind, source string, gen idpmeta.Generation, doc []byte, fetchErr error, validate func([]byte) error, expiry func([]byte) time.Time) ([]byte, time.Time, error) {
	store := idpMetadataStore()

	if fetchErr == nil && len(doc) > 0 && validate != nil {
		if vErr := validate(doc); vErr != nil {
			fetchErr = idpFetchDefinitive(fmt.Errorf("IdP returned an invalid document: %w", vErr))
		}
	}
	if fetchErr == nil && len(doc) > 0 {
		if putErr := store.PutIfCurrent(profileID, kind, source, doc, gen); errors.Is(putErr, idpmeta.ErrRetired) {
			// The profile was deleted while this fetch was on the wire. The
			// document is still returned — the publication site refuses a
			// deleted profile on its own — but it must not re-enter the cache
			// the committed deletion just emptied (IDP-18).
			logger.Printf("IdP[%q]: fetched metadata not cached: the profile was deleted while the fetch was in flight",
				sanitizeLog(profileID))
		} else if putErr != nil {
			// Not fatal — see (2) above. Rate-limiting is unnecessary: this
			// line is emitted only on a SUCCESSFUL fetch, which is bounded by
			// the compile rate, and a persistently failing write is already
			// carried by the storage-health plane.
			logger.Printf("IdP[%q]: metadata cached document could not be persisted (%q); a future IdP outage will have no fallback on this node",
				sanitizeLog(profileID), sanitizeLog(putErr.Error()))
		}
		noteIdPMetadataOutcome(profileID, idpDocRef{Kind: kind, Source: source}, idpMetaFresh, nil)
		return doc, time.Time{}, nil
	}
	if fetchErr == nil {
		fetchErr = idpFetchDefinitive(fmt.Errorf("IdP returned an empty document"))
	}
	if !idpFetchStaleEligible(fetchErr) {
		// The IdP ANSWERED (4xx, non-200, empty or invalid document), or the
		// request was refused by policy before it left: not an outage, so the
		// last-known-good copy is NOT consulted — see (3) above. Counted and
		// rate-limit-logged as unavailable, the same verdict as no cache.
		noteIdPMetadataOutcome(profileID, idpDocRef{Kind: kind, Source: source}, idpMetaUnavailable, fetchErr)
		return nil, time.Time{}, fetchErr
	}
	return serveCachedIdPDocument(store, profileID, kind, source, fetchErr, validate, expiry)
}

// serveCachedIdPDocument is resolveIdPDocument's fallback half: the fetch failed
// for an AVAILABILITY reason, so the last-known-good document is served if one
// is cached, usable, within idpmeta.StaleMaxAge and not past its own expiry.
// Otherwise the original fetch error is returned unchanged.
func serveCachedIdPDocument(store *idpmeta.Store, profileID string, kind idpmeta.Kind, source string, fetchErr error, validate func([]byte) error, expiry func([]byte) time.Time) ([]byte, time.Time, error) {
	cached, age, cacheErr := store.Get(profileID, kind, source)
	if cacheErr != nil {
		noteIdPMetadataOutcome(profileID, idpDocRef{Kind: kind, Source: source}, idpMetaUnavailable, fetchErr)
		return nil, time.Time{}, fetchErr
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
			noteIdPMetadataOutcome(profileID, idpDocRef{Kind: kind, Source: source}, idpMetaUnavailable, fetchErr)
			logger.Printf("IdP[%s]: metadata fetch failed (%v) AND the cached document fetched %s ago is no longer usable (%v) — this profile cannot be compiled",
				sanitizeLog(profileID), sanitizeLog(fmt.Sprint(fetchErr)), age.Round(time.Second), sanitizeLog(fmt.Sprint(vErr)))
			return nil, time.Time{}, fetchErr
		}
	}
	// The document's OWN expiry caps the ceiling — see (4) above. SAML
	// metadata past its validUntil must not be relied on, and serving it from
	// the cache would be the cache extending a lifetime the IdP itself bounded.
	if expiry != nil {
		if vu := expiry(cached); !vu.IsZero() && !time.Now().Before(vu) {
			noteIdPMetadataOutcome(profileID, idpDocRef{Kind: kind, Source: source}, idpMetaUnavailable, fetchErr)
			logger.Printf("IdP[%s]: metadata fetch failed (%v) AND the cached document expired at %s (its validUntil) — this profile cannot be compiled",
				sanitizeLog(profileID), sanitizeLog(fmt.Sprint(fetchErr)), vu.UTC().Format(time.RFC3339))
			return nil, time.Time{}, fetchErr
		}
	}
	noteIdPMetadataOutcome(profileID, idpDocRef{Kind: kind, Source: source}, idpMetaStale, fetchErr)
	logger.Printf("IdP[%s]: metadata fetch failed (%v) — continuing from the cached document fetched %s ago (refused past %s)",
		sanitizeLog(profileID), sanitizeLog(fmt.Sprint(fetchErr)), age.Round(time.Second), idpmetaStaleMaxAgeString())
	// WHEN this document was fetched travels with it, so the ceiling stays
	// enforceable after the compile returns: Store.Get owns idpmeta.StaleMaxAge,
	// but it is reached only from a compile and a steady-state node never
	// recompiles (Codex review round 8).
	//
	// ROUNDED to the second: the store stamps fetch times in whole seconds and
	// reports an age against its own clock read, so now-age carries a few
	// nanoseconds of drift that differs per call. Unrounded, two compiles from
	// the SAME cached document reported different fetch times, and the
	// recovery loop's revalidation would read "a newer document" into what is
	// the identical one (idpRevalidationAdopts).
	return cached, time.Now().Add(-age).Round(time.Second), nil
}

// idpUnavailableError marks a document fetch that failed for AVAILABILITY
// reasons: the request did not complete (dial, TLS, timeout, DNS resolution,
// body read) or the IdP answered 5xx. It is the ONLY class resolveIdPDocument
// answers from the last-known-good cache (RFC 5861 stale-if-error). The mark is
// POSITIVE on purpose: an error nobody classified is not stale-eligible, so a
// new failure path added to a fetcher fails closed (no cache) until someone
// decides it is an outage.
//
// Error() is the wrapped error's text unchanged, so operator-visible messages
// and log lines are exactly what the fetchers produced before.
type idpUnavailableError struct{ err error }

func (e *idpUnavailableError) Error() string { return e.err.Error() }
func (e *idpUnavailableError) Unwrap() error { return e.err }

// idpFetchUnavailable marks err as an availability failure. An SSRF policy
// refusal (errSSRFBlocked, from the pre-flight or the dialer) is NEVER marked:
// a host that now resolves into a private range is a policy verdict about the
// destination, not an IdP outage, and is not something the cache may answer.
func idpFetchUnavailable(err error) error {
	if err == nil || errors.Is(err, errSSRFBlocked) {
		return err
	}
	return &idpUnavailableError{err: err}
}

// idpFetchStatusError classifies a non-200 answer: a 5xx is the IdP failing to
// serve (stale-eligible); every other status, notably a 4xx (404 withdrawn,
// 401/403 refused, 410 gone, 429 throttled), is an ANSWER and is not.
func idpFetchStatusError(status int, err error) error {
	if status >= 500 && status <= 599 {
		return idpFetchUnavailable(err)
	}
	return idpFetchDefinitive(err)
}

// idpDefinitiveError marks a fetch the IdP ANSWERED in a way that says the
// document this profile depends on is not the one this node holds: a non-5xx
// status (404 withdrawn, 410 gone, 401/403 refused, 429 throttled), or a 200
// whose body is empty or is not a usable document.
//
// IT IS A POSITIVE MARK FOR THE SAME REASON idpUnavailableError IS, and the
// reason matters more here. "Not stale-eligible" is also true of an error
// nobody classified — a parse bug, an SP key-pair failure, a validator
// tightened across an upgrade — so acting on the ABSENCE of the availability
// mark would let an internal compile fault retire a provider that is serving
// browser SSO perfectly. Retiring requires POSITIVE evidence that the IdP
// spoke, and anything unclassified leaves the provider alone.
//
// An SSRF policy refusal is NEVER marked, mirroring idpFetchUnavailable: a host
// that now resolves into a private range is a verdict about the DESTINATION,
// not the IdP stating that its document is gone, and marking it would let a DNS
// change take SSO dark.
type idpDefinitiveError struct{ err error }

func (e *idpDefinitiveError) Error() string { return e.err.Error() }
func (e *idpDefinitiveError) Unwrap() error { return e.err }

// idpFetchDefinitive marks err as an answer from the IdP. See
// idpDefinitiveError.
func idpFetchDefinitive(err error) error {
	if err == nil || errors.Is(err, errSSRFBlocked) {
		return err
	}
	return &idpDefinitiveError{err: err}
}

// idpFetchIsDefinitive reports whether a failed fetch was the IdP ANSWERING
// that the document is not what this node holds. See idpDefinitiveError.
func idpFetchIsDefinitive(err error) bool {
	var d *idpDefinitiveError
	return errors.As(err, &d) && !errors.Is(err, errSSRFBlocked)
}

// idpFetchStaleEligible reports whether a failed fetch may be answered from the
// last-known-good cache. See idpUnavailableError.
func idpFetchStaleEligible(err error) bool {
	var u *idpUnavailableError
	return errors.As(err, &u) && !errors.Is(err, errSSRFBlocked)
}
