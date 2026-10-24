package main

// idp_metadata_staleness_policy_test.go — CHAOS-87 owner decisions on #1485.
//
// An unreachable IdP is degraded AVAILABILITY, not revocation, and the cache
// is RFC 5861 stale-if-error, not stale-on-anything:
//
//  1. Only a transport failure or an HTTP 5xx is answered from the
//     last-known-good cache. A 4xx, any other non-200, an empty or invalid
//     document, or an SSRF policy refusal is an ANSWER and fails the compile.
//  2. A cached document is served for at most min(idpmeta.StaleMaxAge, the
//     SAML metadata's own validUntil); past validUntil it is not served.
//  3. The recovery loop revalidates providers that are LIVE but serving from
//     cache, and swaps in the fresh document — so a rotated signing key is
//     adopted when the IdP answers again rather than seven days later.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/idpmeta"
)

// chaos87StatusIdP is a metadata endpoint whose answer is set per test: a
// status code (200 serves body) and the body itself.
type chaos87StatusIdP struct {
	srv    *httptest.Server
	status atomic.Int32
	body   atomic.Value // string
}

func newChaos87StatusIdP(t *testing.T, body string) *chaos87StatusIdP {
	t.Helper()
	m := &chaos87StatusIdP{}
	m.status.Store(http.StatusOK)
	m.body.Store(body)
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if code := int(m.status.Load()); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		_, _ = w.Write([]byte(m.body.Load().(string)))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *chaos87StatusIdP) URL() string { return m.srv.URL + "/metadata" }

// TestChaos87_StaleIfErrorOnlyOnTransportAnd5xx drives every failure class end
// to end through NewSAMLProvider after a healthy compile cached a valid
// document. The CONTROL rows (5xx, transport) prove the cache still works; the
// rest prove an answer is never papered over.
func TestChaos87_StaleIfErrorOnlyOnTransportAnd5xx(t *testing.T) {
	cases := []struct {
		name      string
		fail      func(m *chaos87StatusIdP)
		wantStale bool
	}{
		{"500", func(m *chaos87StatusIdP) { m.status.Store(500) }, true},
		{"502", func(m *chaos87StatusIdP) { m.status.Store(502) }, true},
		{"503", func(m *chaos87StatusIdP) { m.status.Store(503) }, true},
		{"504", func(m *chaos87StatusIdP) { m.status.Store(504) }, true},
		{"transport-refused", func(m *chaos87StatusIdP) { m.srv.Close() }, true},
		{"400", func(m *chaos87StatusIdP) { m.status.Store(400) }, false},
		{"401", func(m *chaos87StatusIdP) { m.status.Store(401) }, false},
		{"403", func(m *chaos87StatusIdP) { m.status.Store(403) }, false},
		{"404", func(m *chaos87StatusIdP) { m.status.Store(404) }, false},
		{"410", func(m *chaos87StatusIdP) { m.status.Store(410) }, false},
		{"429", func(m *chaos87StatusIdP) { m.status.Store(429) }, false},
		{"204-non-200", func(m *chaos87StatusIdP) { m.status.Store(204) }, false},
		{"invalid-document", func(m *chaos87StatusIdP) { m.body.Store("<html>not SAML metadata</html>") }, false},
		{"unsigned-garbage", func(m *chaos87StatusIdP) { m.body.Store("\x00\x01 not xml at all") }, false},
		{"empty-200", func(m *chaos87StatusIdP) { m.body.Store("") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := chaos87Env(t)
			m := newChaos87StatusIdP(t, chaos87MetadataXML(t, "cert-A"))
			prof := chaos87Profile("p-"+tc.name, m.URL())
			if _, err := NewSAMLProvider(prof); err != nil {
				t.Fatalf("healthy compile: %v", err)
			}
			goodBytes, _, err := store.Get(prof.ID, idpmeta.KindSAMLMetadata, m.URL())
			if err != nil {
				t.Fatalf("setup: the healthy document must be cached: %v", err)
			}

			tc.fail(m)
			prov, err := NewSAMLProvider(chaos87Profile(prof.ID, m.URL()))
			st := idpMetadataState()
			if tc.wantStale {
				if err != nil {
					t.Fatalf("an availability failure must be answered from the cache: %v", err)
				}
				if prov.servedDocumentCachedAt().IsZero() || st.StaleServed != 1 {
					t.Fatalf("the fallback must be the cached document and counted (cachedAt=%v StaleServed=%d)",
						prov.servedDocumentCachedAt(), st.StaleServed)
				}
				return
			}
			if err == nil {
				t.Fatal("an IdP ANSWER (4xx / non-200 / invalid document) must not be answered from the cache")
			}
			if st.StaleServed != 0 || !st.Failing {
				t.Fatalf("an answer must be a failed acquisition, never stale-served: %+v", st)
			}
			// The refused answer must not have touched the valid copy a later
			// genuine outage falls back to.
			after, _, aErr := store.Get(prof.ID, idpmeta.KindSAMLMetadata, m.URL())
			if aErr != nil || !bytes.Equal(after, goodBytes) {
				t.Fatalf("the last-known-good document must survive a refused answer (err=%v)", aErr)
			}
		})
	}
}

// The OIDC fetcher classifies the same way: its errors decide eligibility, and
// the message an operator sees is unchanged by the classification.
func TestChaos87_OIDCDiscoveryFetchErrorsAreClassified(t *testing.T) {
	chaos87Env(t)
	m := newChaos87StatusIdP(t, `{}`)
	wellKnown := m.srv.URL + "/.well-known/openid-configuration"

	m.status.Store(503)
	_, err := fetchOIDCDiscoveryOverNetwork(wellKnown)
	if err == nil || !idpFetchStaleEligible(err) {
		t.Fatalf("a 503 must be stale-eligible, got %v", err)
	}
	if err.Error() != "oidc discovery: HTTP 503" {
		t.Fatalf("the classification must not change the message, got %q", err.Error())
	}

	m.status.Store(404)
	if _, err := fetchOIDCDiscoveryOverNetwork(wellKnown); err == nil || idpFetchStaleEligible(err) {
		t.Fatalf("a 404 must NOT be stale-eligible, got %v", err)
	}

	m.srv.Close()
	if _, err := fetchOIDCDiscoveryOverNetwork(wellKnown); err == nil || !idpFetchStaleEligible(err) {
		t.Fatalf("a refused connection must be stale-eligible, got %v", err)
	}
}

// The classifier itself: positive marking, and an SSRF policy refusal is never
// an outage even when something marked it as one.
func TestChaos87_StaleEligibilityClassifier(t *testing.T) {
	blocked := fmt.Errorf("metadata URL host refused: %w", errSSRFBlocked)
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"unclassified", errors.New("something"), false},
		{"transport", idpFetchUnavailable(errors.New("dial tcp: connection refused")), true},
		{"wrapped-transport", fmt.Errorf("saml[x] metadata: %w", idpFetchUnavailable(errors.New("i/o timeout"))), true},
		{"5xx", idpFetchStatusError(503, errors.New("HTTP 503")), true},
		{"4xx", idpFetchStatusError(404, errors.New("HTTP 404")), false},
		{"3xx", idpFetchStatusError(304, errors.New("HTTP 304")), false},
		{"ssrf-blocked", idpFetchUnavailable(blocked), false},
		{"ssrf-blocked-forced", &idpUnavailableError{err: blocked}, false},
	} {
		if got := idpFetchStaleEligible(tc.err); got != tc.want {
			t.Errorf("%s: stale-eligible = %v, want %v", tc.name, got, tc.want)
		}
	}
	if idpFetchUnavailable(nil) != nil {
		t.Error("marking a nil error must stay nil")
	}
}

// ── validUntil ──────────────────────────────────────────────────────────────

func chaos87MetadataWithValidUntil(t *testing.T, cn string, vu time.Time) string {
	t.Helper()
	return strings.Replace(chaos87MetadataXML(t, cn), "<EntityDescriptor ",
		`<EntityDescriptor validUntil="`+vu.UTC().Format(time.RFC3339)+`" `, 1)
}

func chaos87AggregateWithValidUntil(t *testing.T, cn string, vu time.Time) string {
	t.Helper()
	inner := strings.Replace(chaos87MetadataXML(t, cn), ` xmlns="urn:oasis:names:tc:SAML:2.0:metadata"`, "", 1)
	return `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="` +
		vu.UTC().Format(time.RFC3339) + `">` + inner + `</EntitiesDescriptor>`
}

// A cached SAML document past its own validUntil is NOT served, however young
// the cached copy is against the seven-day ceiling — for an EntityDescriptor
// and for an enclosing EntitiesDescriptor alike. The CONTROL (validUntil still
// in the future) is served and the provider carries the expiry so the live
// ceiling can enforce it later.
func TestChaos87_CachedSAMLMetadataPastValidUntilIsNotServed(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(6 * time.Hour).Truncate(time.Second)
	cases := []struct {
		name      string
		doc       func(t *testing.T) string
		wantServe bool
	}{
		{"entity-expired", func(t *testing.T) string { return chaos87MetadataWithValidUntil(t, "cert-A", past) }, false},
		{"aggregate-expired", func(t *testing.T) string { return chaos87AggregateWithValidUntil(t, "cert-A", past) }, false},
		{"entity-valid", func(t *testing.T) string { return chaos87MetadataWithValidUntil(t, "cert-A", future) }, true},
		{"aggregate-valid", func(t *testing.T) string { return chaos87AggregateWithValidUntil(t, "cert-A", future) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := chaos87Env(t)
			m := newChaos87StatusIdP(t, "")
			m.status.Store(http.StatusServiceUnavailable) // an outage: stale-eligible
			doc := tc.doc(t)
			if err := validateSAMLMetadataDocument([]byte(doc)); err != nil {
				t.Fatalf("fixture must be valid metadata: %v", err)
			}
			if err := store.Put("vu", idpmeta.KindSAMLMetadata, m.URL(), []byte(doc)); err != nil {
				t.Fatalf("seed: %v", err)
			}

			prov, err := NewSAMLProvider(chaos87Profile("vu", m.URL()))
			if !tc.wantServe {
				if err == nil {
					t.Fatal("a cached document past its validUntil must not be served")
				}
				if st := idpMetadataState(); st.StaleServed != 0 {
					t.Fatalf("an expired cached document must not be counted stale-served: %+v", st)
				}
				return
			}
			if err != nil {
				t.Fatalf("a cached document within its validUntil must be served: %v", err)
			}
			if !prov.servedDocumentValidUntil().Equal(future) {
				t.Fatalf("provider validUntil = %v, want %v", prov.servedDocumentValidUntil(), future)
			}
			sd, ok := idpServedEntry(m.URL(), prov)
			if !ok || !sd.validUntil.Equal(future) {
				t.Fatalf("the served-generation record must carry validUntil (ok=%v, %+v)", ok, sd)
			}
		})
	}
}

// The LIVE half: a provider serving cache is retired at min(7d, validUntil).
func TestChaos87_LiveCeilingIsTheEarlierOfStaleMaxAgeAndValidUntil(t *testing.T) {
	chaos87Env(t)
	now := time.Now()
	const src = "https://idp.example/metadata"
	idpNotePublishedGeneration("vu-live", src, chaos87CacheBuiltProvider{
		cachedAt: now.Add(-time.Hour), validUntil: now.Add(time.Hour),
	})
	t.Cleanup(func() { idpNotePublishedGeneration("vu-live", src, nil) })

	if v := idpStaleCeilingSweep(now); len(v) != 0 {
		t.Fatalf("within both bounds nothing may be retired, got %+v", v)
	}
	v := idpStaleCeilingSweep(now.Add(2 * time.Hour))
	if len(v) != 1 || v[0].profileID != "vu-live" || !v[0].validUntilPassed {
		t.Fatalf("past validUntil (but well inside %s) the provider must be selected for retirement, got %+v", idpmeta.StaleMaxAge, v)
	}

	// CONTROL: with no validUntil the seven-day ceiling alone applies.
	idpNotePublishedGeneration("vu-live", src, chaos87CacheBuiltProvider{cachedAt: now.Add(-time.Hour)})
	if v := idpStaleCeilingSweep(now.Add(2 * time.Hour)); len(v) != 0 {
		t.Fatalf("a document declaring no validUntil is bounded by %s only, got %+v", idpmeta.StaleMaxAge, v)
	}
	if v := idpStaleCeilingSweep(now.Add(idpmeta.StaleMaxAge)); len(v) != 1 || v[0].validUntilPassed {
		t.Fatalf("past %s the provider must be selected on age, got %+v", idpmeta.StaleMaxAge, v)
	}
}

// ── revalidation ────────────────────────────────────────────────────────────

func chaos87LiveSAMLEntityID(t *testing.T, id string) (string, *SAMLProvider) {
	t.Helper()
	prov, ok := idpRegistry.LiveProvider(id)
	if !ok {
		t.Fatalf("profile %q has no live provider", id)
	}
	sp, ok := prov.(*SAMLProvider)
	if !ok || sp.sp == nil || sp.sp.IDPMetadata == nil {
		t.Fatalf("profile %q live provider is %T, want a compiled *SAMLProvider", id, prov)
	}
	return sp.sp.IDPMetadata.EntityID, sp
}

// A LIVE provider serving from cache is revalidated by the recovery loop, and a
// recovered IdP's ROTATED signing certificate replaces the cached one — without
// waiting for the seven-day ceiling. Pre-fix the loop only looked at profiles
// with no live provider, so a cache-built provider kept trusting the withdrawn
// key until it expired.
func TestChaos87_RecoveryRevalidatesCacheServingProviderAndAdoptsRotatedKey(t *testing.T) {
	chaos87Env(t)
	idp := newChaos87IdP(t) // serves cert-A

	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("healthy upsert: %v", err)
	}
	// The IdP goes down and the profile is (re)published from the cache.
	idp.down.Store(true)
	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert during the outage must publish from cache: %v", err)
	}
	if !idpRegistry.hasCacheServingProfile() {
		t.Fatal("setup: the live provider must be serving from cache")
	}
	if !idpAnyProfileDark() {
		t.Fatal("a cache-serving provider must arm the recovery loop (watchdog supervision seam)")
	}
	entity, before := chaos87LiveSAMLEntityID(t, "corp")
	if entity != "https://idp.example/cert-A" {
		t.Fatalf("setup: serving %q, want cert-A", entity)
	}

	// CONTROL: still down — revalidation changes nothing and keeps serving.
	if n := revalidateCacheServingProviders(); n != 0 {
		t.Fatalf("an IdP still down must not replace the provider, replaced %d", n)
	}
	if _, still := chaos87LiveSAMLEntityID(t, "corp"); still != before {
		t.Fatal("an availability failure must leave the cache-serving provider in place")
	}

	// The IdP comes back with a ROTATED key. Run the real loop.
	idp.rotateSigningKey(t)
	idp.down.Store(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); runIdPRecoveryLoop(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if e, _ := chaos87LiveSAMLEntityID(t, "corp"); e == "https://idp.example/cert-B" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the recovery loop did not swap in the recovered IdP's rotated document")
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, after := chaos87LiveSAMLEntityID(t, "corp")
	if !after.servedDocumentCachedAt().IsZero() {
		t.Fatal("the adopted provider must be built from the FRESH document")
	}
	if idpRegistry.hasCacheServingProfile() {
		t.Fatal("after revalidation nothing may still be recorded as serving from cache")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop must exit once nothing is dark or serving from cache")
	}
}

// publishRevalidated re-checks the live identity under the lock: a provider
// replaced (retired, republished) since selection is never overwritten.
func TestChaos87_PublishRevalidatedRefusesAStaleSelection(t *testing.T) {
	chaos87Env(t)
	idp := newChaos87IdP(t)
	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	gen := idpRegistry.profiles[0]
	other := chaos87CacheBuiltProvider{cachedAt: time.Now()}
	if idpRegistry.publishRevalidated("corp", gen, gen, other, chaos87StubProvider{}) {
		t.Fatal("a selection whose live provider has since changed must not publish")
	}
	cur, _ := idpRegistry.LiveProvider("corp")
	if idpRegistry.publishRevalidated("corp", &IdPProfile{ID: "corp"}, gen, cur, chaos87StubProvider{}) {
		t.Fatal("a selection from an older generation must not publish")
	}
}

// Retiring a provider at the ceiling is NOT revocation: the profile stays
// enabled and stored (the predicate #1564's session check consults), so the
// seven-day expiry by itself never logs anybody out.
func TestChaos87_StaleExpiryRetirementLeavesTheProfileEnabled(t *testing.T) {
	chaos87Env(t)
	idp := newChaos87IdP(t)
	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	src := idpRemoteDocumentSource(chaos87Profile("corp", idp.URL()))
	served := chaos87SeedStaleServe("corp", src)
	if !idpRegistry.retireStaleProvider("corp", src, served) {
		t.Fatal("setup: retirement must apply")
	}
	p := idpRegistry.Get("corp")
	if p == nil || !p.Enabled {
		t.Fatal("a stale-expiry retirement must leave the profile stored and enabled — it is not a revocation")
	}
}

// ── Codex P1 on the owner-decision round: a DEFINITIVE answer retires a
// ── cache-serving provider; an OUTAGE does not ──

// TestChaos87_DefinitiveAnswerRetiresACacheServingProvider is the DEFECT gate.
//
// The owner decision separates an OUTAGE from an ANSWER: a transport failure or
// a 5xx may be served from the last-known-good copy, a 404/410/401/403 or an
// unusable 200 may not. That rule was applied where a document is ACQUIRED and
// not where a provider is REVALIDATED, so revalidateCacheServingProviders took
// the compile-error branch for EVERY error class and left the provider live —
// keeping withdrawn SAML signing material trusted until the seven-day ceiling
// even though the IdP was answering and saying it was gone. That is the exact
// exposure the decision's first item describes.
//
// A rule enforced at one layer and not carried to the next is this review's
// most repeated defect shape.
func TestChaos87_DefinitiveAnswerRetiresACacheServingProvider(t *testing.T) {
	chaos87Env(t)
	idp := newChaos87IdP(t)

	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("healthy upsert: %v", err)
	}
	idp.down.Store(true) // 503: an outage, so the republish serves from cache
	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert during the outage must publish from cache: %v", err)
	}
	if !idpRegistry.hasCacheServingProfile() {
		t.Fatal("setup: the live provider must be serving from cache")
	}

	// The IdP comes back and ANSWERS that the metadata is gone.
	idp.down.Store(false)
	idp.status.Store(http.StatusNotFound)
	revalidateCacheServingProviders()

	if idpRegistry.HasEnabledInteractiveProvider() {
		t.Fatal("a provider whose IdP answered 404 must be retired, not left serving " +
			"a withdrawn document until the seven-day ceiling")
	}
	// The profile is WITHDRAWN, not revoked: it stays enabled and stored so the
	// recovery loop republishes it the moment a usable document is served.
	if !chaos87ProfileIsEnabledAndStored(t, "corp") {
		t.Fatal("retirement must leave the profile ENABLED and STORED — it is a " +
			"withdrawal of a stale document, not a revocation")
	}
}

// TestChaos87_OutageDoesNotRetireACacheServingProvider is the CONTROL, and it
// is the whole availability posture of this round: the cheapest way to pass the
// gate above is to retire on any compile failure, which would take SSO down for
// every profile whose IdP is merely unreachable — the behaviour the owner
// decision exists to prevent.
func TestChaos87_OutageDoesNotRetireACacheServingProvider(t *testing.T) {
	chaos87Env(t)
	idp := newChaos87IdP(t)

	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("healthy upsert: %v", err)
	}
	idp.down.Store(true)
	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert during the outage must publish from cache: %v", err)
	}
	if !idpRegistry.hasCacheServingProfile() {
		t.Fatal("setup: the live provider must be serving from cache")
	}

	// Still down — a 5xx and a transport failure are OUTAGES.
	revalidateCacheServingProviders()
	if !idpRegistry.HasEnabledInteractiveProvider() {
		t.Fatal("an OUTAGE must leave the cache-serving provider live: an unreachable " +
			"IdP is degraded availability, not revocation")
	}
}

// TestChaos87_UnclassifiedCompileFailureDoesNotRetire is the second CONTROL and
// the reason the definitive mark is POSITIVE rather than "not stale-eligible".
//
// "Not stale-eligible" is also true of an error nobody classified — a parse
// bug, an SP key-pair failure, an SSRF policy refusal — so retiring on the
// ABSENCE of the availability mark would let an internal fault take down a
// provider that is serving browser SSO perfectly.
func TestChaos87_UnclassifiedCompileFailureDoesNotRetire(t *testing.T) {
	chaos87Env(t)
	idp := newChaos87IdP(t)

	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("healthy upsert: %v", err)
	}
	idp.down.Store(true)
	if err := idpRegistry.Upsert(chaos87Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert during the outage must publish from cache: %v", err)
	}
	cands := idpRegistry.cacheServingProfiles()
	if len(cands) != 1 {
		t.Fatalf("setup: want one cache-serving candidate, got %d", len(cands))
	}

	for _, err := range []error{
		errors.New("saml[corp] sp key: entropy source failed"),
		fmt.Errorf("oidc[corp] discovery: %w", errSSRFBlocked),
	} {
		retireOnDefinitiveAnswer(cands[0], err)
		if !idpRegistry.HasEnabledInteractiveProvider() {
			t.Fatalf("an unclassified compile failure must NOT retire a live provider: %v", err)
		}
	}
}

// TestChaos87_DefinitiveClassifierIsDisjointFromStaleEligible pins the two
// marks against each other. They decide opposite actions on the same error
// value — serve the cache, or retire the provider — so an error that satisfied
// both, or neither where one is required, is a silent policy failure.
func TestChaos87_DefinitiveClassifierIsDisjointFromStaleEligible(t *testing.T) {
	for _, tc := range []struct {
		name           string
		err            error
		wantStale      bool
		wantDefinitive bool
	}{
		{"transport failure", idpFetchUnavailable(errors.New("dial tcp: no such host")), true, false},
		{"http 500", idpFetchStatusError(500, errors.New("HTTP 500")), true, false},
		{"http 503", idpFetchStatusError(503, errors.New("HTTP 503")), true, false},
		{"http 404 withdrawn", idpFetchStatusError(404, errors.New("HTTP 404")), false, true},
		{"http 410 gone", idpFetchStatusError(410, errors.New("HTTP 410")), false, true},
		{"http 403 refused", idpFetchStatusError(403, errors.New("HTTP 403")), false, true},
		{"http 429 throttled", idpFetchStatusError(429, errors.New("HTTP 429")), false, true},
		{"invalid document", idpFetchDefinitive(errors.New("IdP returned an invalid document")), false, true},
		// An SSRF refusal is a verdict about the DESTINATION, not the IdP
		// speaking about its document: neither mark may claim it, or a DNS
		// change would either poison the cache or take SSO dark.
		{"ssrf refusal", idpFetchUnavailable(fmt.Errorf("host refused: %w", errSSRFBlocked)), false, false},
		{"ssrf refusal marked definitive", idpFetchDefinitive(fmt.Errorf("host refused: %w", errSSRFBlocked)), false, false},
		// BOTH layers refuse an SSRF refusal, and this case pins the PREDICATE
		// rather than the constructor. Constructing through idpFetchDefinitive
		// leaves the error unmarked, so errors.As fails and the predicate's own
		// guard is never reached — a mutation that deleted that guard passed
		// the case above, which is a gate proving less than it claims. The
		// struct is therefore built directly, the way a future caller might.
		{"ssrf refusal marked directly", &idpDefinitiveError{err: fmt.Errorf("host refused: %w", errSSRFBlocked)}, false, false},
		{"ssrf refusal marked directly as unavailable", &idpUnavailableError{err: fmt.Errorf("host refused: %w", errSSRFBlocked)}, false, false},
		{"unclassified", errors.New("some internal failure"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := idpFetchStaleEligible(tc.err); got != tc.wantStale {
				t.Errorf("idpFetchStaleEligible = %v, want %v", got, tc.wantStale)
			}
			if got := idpFetchIsDefinitive(tc.err); got != tc.wantDefinitive {
				t.Errorf("idpFetchIsDefinitive = %v, want %v", got, tc.wantDefinitive)
			}
			if idpFetchStaleEligible(tc.err) && idpFetchIsDefinitive(tc.err) {
				t.Error("an error may never be BOTH an outage and an answer")
			}
		})
	}
}

// chaos87ProfileIsEnabledAndStored reports whether the registry still holds the
// profile as enabled — the half of a retirement that must NOT change.
func chaos87ProfileIsEnabledAndStored(t *testing.T, id string) bool {
	t.Helper()
	for _, p := range idpRegistry.All() {
		if p != nil && p.ID == id && p.Enabled {
			return true
		}
	}
	return false
}
