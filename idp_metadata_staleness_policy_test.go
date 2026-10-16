package main

// idp_metadata_staleness_policy_test.go — CHAOS-71 owner decisions on #1485.
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

// chaos71StatusIdP is a metadata endpoint whose answer is set per test: a
// status code (200 serves body) and the body itself.
type chaos71StatusIdP struct {
	srv    *httptest.Server
	status atomic.Int32
	body   atomic.Value // string
}

func newChaos71StatusIdP(t *testing.T, body string) *chaos71StatusIdP {
	t.Helper()
	m := &chaos71StatusIdP{}
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

func (m *chaos71StatusIdP) URL() string { return m.srv.URL + "/metadata" }

// TestChaos71_StaleIfErrorOnlyOnTransportAnd5xx drives every failure class end
// to end through NewSAMLProvider after a healthy compile cached a valid
// document. The CONTROL rows (5xx, transport) prove the cache still works; the
// rest prove an answer is never papered over.
func TestChaos71_StaleIfErrorOnlyOnTransportAnd5xx(t *testing.T) {
	cases := []struct {
		name      string
		fail      func(m *chaos71StatusIdP)
		wantStale bool
	}{
		{"500", func(m *chaos71StatusIdP) { m.status.Store(500) }, true},
		{"502", func(m *chaos71StatusIdP) { m.status.Store(502) }, true},
		{"503", func(m *chaos71StatusIdP) { m.status.Store(503) }, true},
		{"504", func(m *chaos71StatusIdP) { m.status.Store(504) }, true},
		{"transport-refused", func(m *chaos71StatusIdP) { m.srv.Close() }, true},
		{"400", func(m *chaos71StatusIdP) { m.status.Store(400) }, false},
		{"401", func(m *chaos71StatusIdP) { m.status.Store(401) }, false},
		{"403", func(m *chaos71StatusIdP) { m.status.Store(403) }, false},
		{"404", func(m *chaos71StatusIdP) { m.status.Store(404) }, false},
		{"410", func(m *chaos71StatusIdP) { m.status.Store(410) }, false},
		{"429", func(m *chaos71StatusIdP) { m.status.Store(429) }, false},
		{"204-non-200", func(m *chaos71StatusIdP) { m.status.Store(204) }, false},
		{"invalid-document", func(m *chaos71StatusIdP) { m.body.Store("<html>not SAML metadata</html>") }, false},
		{"unsigned-garbage", func(m *chaos71StatusIdP) { m.body.Store("\x00\x01 not xml at all") }, false},
		{"empty-200", func(m *chaos71StatusIdP) { m.body.Store("") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := chaos71Env(t)
			m := newChaos71StatusIdP(t, chaos71MetadataXML(t, "cert-A"))
			prof := chaos71Profile("p-"+tc.name, m.URL())
			if _, err := NewSAMLProvider(prof); err != nil {
				t.Fatalf("healthy compile: %v", err)
			}
			goodBytes, _, err := store.Get(prof.ID, idpmeta.KindSAMLMetadata, m.URL())
			if err != nil {
				t.Fatalf("setup: the healthy document must be cached: %v", err)
			}

			tc.fail(m)
			prov, err := NewSAMLProvider(chaos71Profile(prof.ID, m.URL()))
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
func TestChaos71_OIDCDiscoveryFetchErrorsAreClassified(t *testing.T) {
	chaos71Env(t)
	m := newChaos71StatusIdP(t, `{}`)
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
func TestChaos71_StaleEligibilityClassifier(t *testing.T) {
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

func chaos71MetadataWithValidUntil(t *testing.T, cn string, vu time.Time) string {
	t.Helper()
	return strings.Replace(chaos71MetadataXML(t, cn), "<EntityDescriptor ",
		`<EntityDescriptor validUntil="`+vu.UTC().Format(time.RFC3339)+`" `, 1)
}

func chaos71AggregateWithValidUntil(t *testing.T, cn string, vu time.Time) string {
	t.Helper()
	inner := strings.Replace(chaos71MetadataXML(t, cn), ` xmlns="urn:oasis:names:tc:SAML:2.0:metadata"`, "", 1)
	return `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="` +
		vu.UTC().Format(time.RFC3339) + `">` + inner + `</EntitiesDescriptor>`
}

// A cached SAML document past its own validUntil is NOT served, however young
// the cached copy is against the seven-day ceiling — for an EntityDescriptor
// and for an enclosing EntitiesDescriptor alike. The CONTROL (validUntil still
// in the future) is served and the provider carries the expiry so the live
// ceiling can enforce it later.
func TestChaos71_CachedSAMLMetadataPastValidUntilIsNotServed(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(6 * time.Hour).Truncate(time.Second)
	cases := []struct {
		name      string
		doc       func(t *testing.T) string
		wantServe bool
	}{
		{"entity-expired", func(t *testing.T) string { return chaos71MetadataWithValidUntil(t, "cert-A", past) }, false},
		{"aggregate-expired", func(t *testing.T) string { return chaos71AggregateWithValidUntil(t, "cert-A", past) }, false},
		{"entity-valid", func(t *testing.T) string { return chaos71MetadataWithValidUntil(t, "cert-A", future) }, true},
		{"aggregate-valid", func(t *testing.T) string { return chaos71AggregateWithValidUntil(t, "cert-A", future) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := chaos71Env(t)
			m := newChaos71StatusIdP(t, "")
			m.status.Store(http.StatusServiceUnavailable) // an outage: stale-eligible
			doc := tc.doc(t)
			if err := validateSAMLMetadataDocument([]byte(doc)); err != nil {
				t.Fatalf("fixture must be valid metadata: %v", err)
			}
			if err := store.Put("vu", idpmeta.KindSAMLMetadata, m.URL(), []byte(doc)); err != nil {
				t.Fatalf("seed: %v", err)
			}

			prov, err := NewSAMLProvider(chaos71Profile("vu", m.URL()))
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
func TestChaos71_LiveCeilingIsTheEarlierOfStaleMaxAgeAndValidUntil(t *testing.T) {
	chaos71Env(t)
	now := time.Now()
	const src = "https://idp.example/metadata"
	idpNotePublishedGeneration("vu-live", src, chaos71CacheBuiltProvider{
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
	idpNotePublishedGeneration("vu-live", src, chaos71CacheBuiltProvider{cachedAt: now.Add(-time.Hour)})
	if v := idpStaleCeilingSweep(now.Add(2 * time.Hour)); len(v) != 0 {
		t.Fatalf("a document declaring no validUntil is bounded by %s only, got %+v", idpmeta.StaleMaxAge, v)
	}
	if v := idpStaleCeilingSweep(now.Add(idpmeta.StaleMaxAge)); len(v) != 1 || v[0].validUntilPassed {
		t.Fatalf("past %s the provider must be selected on age, got %+v", idpmeta.StaleMaxAge, v)
	}
}

// ── revalidation ────────────────────────────────────────────────────────────

func chaos71LiveSAMLEntityID(t *testing.T, id string) (string, *SAMLProvider) {
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
func TestChaos71_RecoveryRevalidatesCacheServingProviderAndAdoptsRotatedKey(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t) // serves cert-A

	if err := idpRegistry.Upsert(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("healthy upsert: %v", err)
	}
	// The IdP goes down and the profile is (re)published from the cache.
	idp.down.Store(true)
	if err := idpRegistry.Upsert(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert during the outage must publish from cache: %v", err)
	}
	if !idpRegistry.hasCacheServingProfile() {
		t.Fatal("setup: the live provider must be serving from cache")
	}
	if !idpAnyProfileDark() {
		t.Fatal("a cache-serving provider must arm the recovery loop (watchdog supervision seam)")
	}
	entity, before := chaos71LiveSAMLEntityID(t, "corp")
	if entity != "https://idp.example/cert-A" {
		t.Fatalf("setup: serving %q, want cert-A", entity)
	}

	// CONTROL: still down — revalidation changes nothing and keeps serving.
	if n := revalidateCacheServingProviders(); n != 0 {
		t.Fatalf("an IdP still down must not replace the provider, replaced %d", n)
	}
	if _, still := chaos71LiveSAMLEntityID(t, "corp"); still != before {
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
		if e, _ := chaos71LiveSAMLEntityID(t, "corp"); e == "https://idp.example/cert-B" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the recovery loop did not swap in the recovered IdP's rotated document")
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, after := chaos71LiveSAMLEntityID(t, "corp")
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
func TestChaos71_PublishRevalidatedRefusesAStaleSelection(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)
	if err := idpRegistry.Upsert(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	gen := idpRegistry.profiles[0]
	other := chaos71CacheBuiltProvider{cachedAt: time.Now()}
	if idpRegistry.publishRevalidated("corp", gen, gen, other, chaos71StubProvider{}) {
		t.Fatal("a selection whose live provider has since changed must not publish")
	}
	cur, _ := idpRegistry.LiveProvider("corp")
	if idpRegistry.publishRevalidated("corp", &IdPProfile{ID: "corp"}, gen, cur, chaos71StubProvider{}) {
		t.Fatal("a selection from an older generation must not publish")
	}
}

// Retiring a provider at the ceiling is NOT revocation: the profile stays
// enabled and stored (the predicate #1564's session check consults), so the
// seven-day expiry by itself never logs anybody out.
func TestChaos71_StaleExpiryRetirementLeavesTheProfileEnabled(t *testing.T) {
	chaos71Env(t)
	idp := newChaos71IdP(t)
	if err := idpRegistry.Upsert(chaos71Profile("corp", idp.URL())); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	src := idpRemoteDocumentSource(chaos71Profile("corp", idp.URL()))
	served := chaos71SeedStaleServe("corp", src)
	if !idpRegistry.retireStaleProvider("corp", src, served) {
		t.Fatal("setup: retirement must apply")
	}
	p := idpRegistry.Get("corp")
	if p == nil || !p.Enabled {
		t.Fatal("a stale-expiry retirement must leave the profile stored and enabled — it is not a revocation")
	}
}
