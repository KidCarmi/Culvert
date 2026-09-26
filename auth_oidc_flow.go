package main

// OIDCFlowProvider implements a full OIDC Authorization Code flow with PKCE
// (RFC 7636) for browser-based authentication via the captive portal, and
// RFC 7662 token introspection for non-browser / API clients that supply a
// Bearer token in the Proxy-Authorization header.
//
// Security properties:
//   - PKCE (S256) prevents authorisation-code interception attacks.
//   - State parameter prevents CSRF on the callback endpoint.
//   - ID tokens are validated against the IdP's JWKs (RS256/ES256 only).
//   - Nonces prevent token replay attacks.
//   - All upstream URLs are validated as HTTPS + non-private (SSRF guard).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/KidCarmi/Culvert/internal/ssrf"

	"github.com/KidCarmi/Culvert/internal/authstate"

	"github.com/KidCarmi/Culvert/internal/idpmeta"
)

// ---------------------------------------------------------------------------
// OIDC Discovery
// ---------------------------------------------------------------------------

// oidcDiscoveryDoc is the subset of fields we consume from the
// OpenID Provider Metadata document (RFC 8414 / OIDC Discovery 1.0).
type oidcDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKsURI               string `json:"jwks_uri"`
}

// oidcWellKnownURL is the ONE derivation of an issuer's discovery-document URL.
//
// It is a function rather than two inline concatenations because that string is
// not only fetched: it is the cache key the last-known-good store is written
// under AND the source a metadata failure episode is keyed by. Deriving it in
// more than one place is how those three stopped agreeing — the episode key was
// computed from the raw ISSUER while the episode itself was recorded under the
// well-known URL, so a refused edit's cleanup looked up a key that never
// existed (Codex review round 6). When one layer decides what a value MEANS,
// every other layer must ask that layer rather than re-derive the rule.
//
// THE TRAILING-SLASH NORMALISATION BELONGS HERE, and leaving it outside was
// round 6's own defect one layer down (Codex review round 7). Neither admission
// gate normalises the issuer, so an issuer ending in "/" is ordinary stored
// configuration; the fetch path trimmed it locally before calling this helper
// while idpRemoteDocumentSource passed the stored string through untouched, so
// acquisition and cleanup derived DIFFERENT keys for one profile and a refused
// edit left its speculative episode behind to degrade and alert for a
// configuration that was never published. One derivation means one string,
// normalisation included: do not re-add a trim at a call site.
func oidcWellKnownURL(issuer string) string {
	issuer = strings.TrimRight(issuer, "/")
	if issuer == "" {
		return ""
	}
	return issuer + "/.well-known/openid-configuration"
}

// fetchOIDCDiscoveryOverNetwork performs exactly the request the
// pre-CHAOS-71 code performed: same 10 s budget, same SSRF-safe dialer, same
// 64 KiB read limit, same HTTP-status rule. Split out only so
// acquireIdPDocument can own the cache/fallback decision around it.
//
// THE GUARD IS REPEATED HERE ON PURPOSE — see the matching note on
// fetchSAMLMetadataOverNetwork. The convention is that the check sits in the
// same function as the outbound request so CodeQL can verify it; a check in a
// calling function is what raised a critical go/request-forgery alert when
// this helper was first split out.
func fetchOIDCDiscoveryOverNetwork(wellKnown string) ([]byte, error) {
	// Inline url.Parse + scheme check + private-host check, in the SAME
	// function as the request, per the repo's SSRF convention.
	//
	// This replaces a validateExternalURL call, and the replacement is NOT a
	// widening: that helper is isSafeRedirectURL, i.e. exactly an absolute
	// http/https check plus isPrivateHost, and isPrivateHost's failure mode is
	// fail-CLOSED (an unresolvable host is refused). All three properties are
	// preserved below, so the set of URLs this function will fetch is
	// unchanged, and a refusal still reaches resolveIdPDocument as a failed
	// FETCH and therefore falls back to the last-known-good cache.
	//
	// What changes is the BOUND. isPrivateHost resolves under
	// context.Background(), so the guard ran to the OS resolver's full budget
	// BEFORE the request context existed — an unbounded step introduced into a
	// bounded operation by the guard itself, on boot and on every CP->DP
	// snapshot apply, and one that also delays reaching the cached document
	// this sweep exists to serve. That is the CHAOS-60/64 shape, and it is the
	// SAME defect this sweep already fixed on the SAML half
	// (fetchSAMLMetadataOverNetwork) and did not carry across — the third time
	// the SAML/OIDC asymmetry has produced a finding here. A bounded operation
	// is only as bounded as its first step. Do not un-bound this for CodeQL.
	u, err := url.Parse(wellKnown)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("oidc discovery: URL must be an absolute http:// or https:// URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryFetchBudget)
	defer cancel()
	if err := isPrivateHostContext(ctx, u.Host); err != nil {
		return nil, fmt.Errorf("oidc discovery: host refused: %w", err)
	}
	client := &http.Client{
		Timeout:   oidcDiscoveryFetchBudget,
		Transport: &http.Transport{DialContext: ssrfSafeDialContext},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// fetchOIDCDiscovery fetches and validates the provider's well-known metadata
// for a configured profile. The caller is responsible for ensuring issuer is a
// valid HTTPS URL.
func fetchOIDCDiscovery(profileID, issuer string) (*oidcDiscoveryDoc, time.Time, error) {
	// The trailing-slash normalisation lives INSIDE oidcWellKnownURL — see the
	// note there. Trimming again here is what made two layers disagree.
	wellKnown := oidcWellKnownURL(issuer)

	// CONFIGURATION errors fail fast and are never answered from cache; a
	// RESOLUTION failure is not one. validateExternalURL resolves the host, so
	// using it here made "DNS is down" indistinguishable from "this issuer is
	// misconfigured" and returned BEFORE the last-known-good document could be
	// consulted — the OIDC half of this sweep's own headline defect, left in
	// place by the fix that closed the SAML half. The DNS-backed check still
	// runs, inline in fetchOIDCDiscoveryOverNetwork, where its failure is a
	// failed FETCH and routes to the cache.
	if err := validateExternalURLStructure(wellKnown); err != nil {
		return nil, time.Time{}, fmt.Errorf("oidc discovery: %w", err)
	}

	// CHAOS-71: a discovery endpoint that is momentarily unreachable must not
	// destroy the provider. acquireIdPDocument prefers the network and falls
	// back to the last successfully fetched document within
	// idpmeta.StaleMaxAge. The bytes are decoded and RE-VALIDATED below by the
	// same code either way — every discovered endpoint is put back through
	// validateExternalURLStructure, so a cached document cannot name an
	// endpoint the network path would have accepted on structure.
	//
	// THE GATE IS THE AUTHORITATIVE VERDICT, AND ITS RESULT IS CARRIED OUT
	// RATHER THAN RECOMPUTED (Codex review round 7). Round 6 wired this
	// validator to the STRUCTURAL half of the parser so the one check that
	// resolves DNS would not run twice — but that made the gate WEAKER than the
	// verdict that decides whether the provider goes live, and
	// resolveIdPDocument caches whatever the gate accepts. A 200 document that
	// parses and whose endpoints are structurally legal but whose
	// authorization_endpoint resolves into a private range therefore REPLACED
	// the last-known-good copy and recorded a FRESH acquisition, and was only
	// then refused: the document that could be compiled was gone, so the next
	// outage had nothing to fall back to, and the surface said success.
	//
	// Carrying the parse result out of the closure fixes both halves at once.
	// The gate is the full parse, so nothing the compile refuses can enter the
	// cache; and because the caller reuses what the gate produced, the
	// authoritative parse — address lookup and counter included — still runs
	// exactly ONCE per document, which is the property round 6 was protecting.
	// Two lookups remain possible in one case only, and it is not waste: when a
	// FETCHED document is refused and a CACHED one is then vetted before being
	// served, those are two different documents and each must be judged.
	//
	// Do not narrow this validator again. A gate that admits what the compile
	// rejects is a cache-poisoning path, not an optimisation.
	fetched, fetchErr := fetchOIDCDiscoveryOverNetwork(wellKnown)
	var parsed *oidcDiscoveryDoc
	_, cachedAt, err := resolveIdPDocument(profileID, idpmeta.KindOIDCDiscovery, wellKnown, fetched, fetchErr, func(b []byte) error {
		doc, vErr := parseAndValidateOIDCDiscovery(profileID, b)
		if vErr != nil {
			return vErr
		}
		parsed = doc
		return nil
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	if parsed == nil {
		// Unreachable while resolveIdPDocument returns a nil error only for
		// bytes the validator it was handed accepted. Fail CLOSED rather than
		// hand back a nil document if that contract ever changes.
		return nil, time.Time{}, fmt.Errorf("oidc discovery: document accepted without a parse result")
	}
	return parsed, cachedAt, nil
}

// parseAndValidateOIDCDiscovery decodes and validates a discovery document.
//
// CHAOS-71 makes this the SINGLE parser for the document, reached identically
// whether the bytes came off the network or out of the last-known-good cache.
// That is the load-bearing half of the cache's safety argument: the discovery
// document names the authorization and token endpoints this appliance sends
// users and credentials to, so every one of them is re-validated here and a
// cached document cannot widen anything the network path would have refused —
// including one edited on disk by something that got write access to dataDir.
//
// The endpoints are NOT all guarded the same way, and the difference is the
// point (CHAOS-71 round 3). The token and JWKS endpoints are ones this
// appliance DIALS, so ssrfSafeDialContext refuses a private resolved address
// at connect time and is rebinding-proof — a structural check is enough for
// them. The AUTHORIZATION endpoint is not dialled by us at all: it is handed
// to the user's BROWSER as a redirect, so no dialer of ours is ever consulted
// and isSafeCaptiveRedirect checks only the shape (absolute, http/https,
// non-empty host). An earlier round of this sweep claimed that function
// re-checked the address and it does not; dropping the resolving validator
// here therefore opened a path for a discovery document — or an edited cache
// file — to redirect a browser at an internal address. It gets its own guard.
func parseOIDCDiscoveryStructural(raw []byte) (*oidcDiscoveryDoc, error) {
	var doc oidcDiscoveryDoc
	if err := json.NewDecoder(io.LimitReader(bytes.NewReader(raw), 64<<10)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("oidc discovery parse: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("oidc discovery: missing required endpoints")
	}
	// Validate all discovered endpoints before storing.
	for _, u := range []string{
		doc.AuthorizationEndpoint,
		doc.TokenEndpoint,
		doc.JWKsURI,
	} {
		if u == "" {
			continue
		}
		// STRUCTURAL, and deliberately: this parser runs on the cached
		// document too, so a DNS-backed REFUSAL-ON-FAILURE here would make the
		// fallback unusable during exactly the outage it exists for.
		if err := validateExternalURLStructure(u); err != nil {
			return nil, fmt.Errorf("oidc discovery endpoint %q: %w", u, err)
		}
	}
	return &doc, nil
}

// parseAndValidateOIDCDiscovery is parseOIDCDiscoveryStructural plus the ONE
// check that is not a property of the document bytes at all: the
// browser-redirect target's ADDRESS.
//
// THIS is the verdict every consumer must use — the compile AND the gate
// resolveIdPDocument applies before a document may replace the last-known-good
// copy. Round 6 handed the gate the structural half alone, to keep the DNS
// lookup and its counter from running twice, and that made the gate admit
// documents the compile refuses; what actually keeps the work single is that
// fetchOIDCDiscovery CARRIES OUT the result this function produced instead of
// recomputing it (Codex review round 7). Cost is bounded by not doing the work
// twice, never by asking a cheaper question.
//
// The two-function split survives as a decomposition, and it is a principled
// one: whether a document parses and whether its endpoints are structurally
// legal are properties OF THE BYTES, deterministic and free, so they are
// reusable by anything that only needs to know the shape; whether a hostname
// currently resolves into a private range is a property of the NETWORK at this
// instant, which two calls can legitimately disagree about. Nothing outside
// this function may use the structural half as a substitute for the verdict.
func parseAndValidateOIDCDiscovery(profileID string, raw []byte) (*oidcDiscoveryDoc, error) {
	doc, err := parseOIDCDiscoveryStructural(raw)
	if err != nil {
		return nil, err
	}
	// The browser-redirect target gets the address check the dialer would have
	// given it if we dialled it. Refused ONLY on a DEFINITE private verdict:
	// ssrf.PrivateHostContext has three outcomes and a resolution FAILURE is
	// not "private", it is "unknown" — treating it as a refusal would hand a
	// resolver outage the power to reject a cached document, which is this
	// sweep's own headline defect in miniature (the CHAOS-65 (6e) rule: a
	// guard that can fail for more than one reason must say which).
	if err := refuseDefinitelyPrivateRedirect(profileID, doc.AuthorizationEndpoint); err != nil {
		return nil, err
	}
	return doc, nil
}

// oidcRedirectHostCheckBudget bounds the one address lookup the authorization
// endpoint gets. This runs at COMPILE time (boot, admin write, config sync) —
// never on the proxy request path — so it is bounded for the same reason the
// fetch beside it is, not because a request is waiting on it.
const oidcRedirectHostCheckBudget = 5 * time.Second

// oidcDiscoveryFetchBudget bounds ONE discovery acquisition end to end — the
// pre-flight host check AND the HTTP request share it, from one context, so
// the guard can never outlive the operation it guards. It is the value the
// request already used; only the guard was outside it.
const oidcDiscoveryFetchBudget = 10 * time.Second

// refuseDefinitelyPrivateRedirect refuses an authorization endpoint that
// RESOLVES into a private range. A host that cannot be resolved right now is
// ALLOWED: the document was validated against a resolving check when it was
// first fetched and cached, so "unknown" during an outage is the fallback
// working as designed, while "definitely private" is the case no outage
// excuses.
func refuseDefinitelyPrivateRedirect(profileID, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("oidc discovery authorization_endpoint %q: unusable", raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), oidcRedirectHostCheckBudget)
	defer cancel()
	if err := isPrivateHostContext(ctx, u.Host); err != nil {
		if errors.Is(err, ssrf.ErrBlocked) {
			return fmt.Errorf("oidc discovery authorization_endpoint %q resolves to a private address", raw)
		}
		// COULD NOT DETERMINE (resolver outage, or this budget spent). Not a
		// refusal — treating it as one would hand a resolver outage the power
		// to reject a cached document, which is this sweep's headline defect.
		//
		// It is therefore ADMITTED UNVERIFIED, and that is a real residual
		// (register row IDP-9), not a closed case: this endpoint is handed to
		// the user's BROWSER, so no dialer of ours is ever consulted, and
		// isSafeCaptiveRedirect checks only shape. A host unresolvable now that
		// later resolves private would be a browser redirect into the internal
		// network, and nothing re-checks a LIVE provider.
		//
		// Closing it is a POSTURE decision with an availability price — failing
		// closed here takes SSO down whenever OUR resolver cannot resolve the
		// authorization host, even though the user's browser could — so it is
		// left to an owner rather than changed inside this sweep. What is NOT
		// acceptable is that it was SILENT: the admission is now counted, so an
		// operator can see that a provider is serving redirects to an endpoint
		// this appliance never verified.
		noteIdPAuthzEndpointUnverified(profileID)
	}
	return nil
}

// probeOIDCDiscovery is the ADMIN "test this issuer" path (POST
// /api/idp/oidc/discover). It deliberately does NOT go through the
// last-known-good cache, in either direction:
//
//   - it must never READ the cache, because its whole job is to report
//     whether the issuer is reachable RIGHT NOW; answering a diagnostic from
//     cache would report a dead IdP as healthy, which is the
//     `ocspCoverage`/"found nothing wrong vs never consulted" mistake;
//   - it must never WRITE the cache, because the issuer is CALLER-SUPPLIED.
//     A cache keyed on an arbitrary admin-supplied issuer would let the test
//     endpoint pre-seed documents for profiles that do not exist yet.
func probeOIDCDiscovery(issuer string) (*oidcDiscoveryDoc, error) {
	wellKnown := oidcWellKnownURL(issuer)
	if err := validateExternalURL(wellKnown); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	raw, err := fetchOIDCDiscoveryOverNetwork(wellKnown)
	if err != nil {
		return nil, err
	}
	// "" profile id: this is the admin diagnostic, which produces no live
	// provider, so an unverified authorization endpoint here is not counted
	// against a profile that does not exist.
	return parseAndValidateOIDCDiscovery("", raw)
}

// ---------------------------------------------------------------------------
// JWKs cache + ID-token verification
// ---------------------------------------------------------------------------

type jwkSet struct {
	Keys []json.RawMessage `json:"keys"`
}

type jwkKeyRaw struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksCache caches the public keys fetched from the IdP's JWKs endpoint.
//
// Two of its fields exist only to bound failure (CHAOS-49):
//
//   - lastAttempt bounds the refresh RATE, not its freshness. The `kid` that
//     drives a cache miss is read from an UNVERIFIED token header, so it is
//     attacker-controlled and reachable without any credential. Keying the
//     refetch decision on cache membership alone turned one unauthenticated
//     request into one outbound JWKS GET, per configured provider, forever —
//     an amplifier pointed at the customer's own IdP. lastAttempt advances on
//     every attempt (success or failure) so an unknown kid costs at most one
//     fetch per jwksMinRefreshInterval.
//
//   - refreshing/refreshDone coalesce concurrent misses. Without them a burst
//     of N simultaneous requests carrying the same unknown kid produced N
//     simultaneous fetches, which is precisely the shape of a reconnect storm.
type jwksCache struct {
	mu          sync.RWMutex
	keys        map[string]interface{} // kid → *rsa.PublicKey or *ecdsa.PublicKey
	fetchedAt   time.Time
	lastAttempt time.Time
	jwksURI     string
	client      *http.Client

	// single-flight state, guarded by mu
	refreshing  bool
	refreshDone chan struct{}
	refreshErr  error

	logAt      time.Time // rate-limits the refresh-failure log line
	staleLogAt time.Time // rate-limits the stale-ceiling refusal log line

	// ceilingBreached mirrors the current SEC-JWKS-1 posture: set true the
	// moment a lookup is refused for being past jwksStaleMaxAge, cleared the
	// moment a refresh next succeeds. It exists so operator-facing surfaces
	// (checkOIDCJWKSTrust, diagnostics.go) can report the fail-closed
	// transition without depending on the rate-limited log line as the only
	// signal — see logStaleRefusal's own comment on why that transition must
	// not be silent.
	ceilingBreached bool
}

const (
	jwksCacheTTL = 15 * time.Minute

	// jwksMinRefreshInterval is the floor between two refresh ATTEMPTS. It
	// bounds both the amplification described above and the retry rate against
	// a struggling IdP. It must stay well under jwksCacheTTL so a genuine key
	// rotation is still picked up promptly.
	jwksMinRefreshInterval = time.Minute

	// jwksStaleMaxAge is the HARD ceiling on how long getKey may keep
	// authenticating with a key set it can no longer refresh (SEC-JWKS-1).
	//
	// Serving a stale key past the TTL is the right degradation for a blip, a
	// rate-limiter body, or a multi-hour outage — wiping the cache instead is
	// the CHAOS-49 silent-SSO-outage bug. But "stale" and "unbounded" are not
	// the same posture. Withdrawing a signing key from the JWKS document is the
	// IdP's ONLY revocation lever over tokens it has already minted, so a
	// relying party that keeps a withdrawn key indefinitely has silently opted
	// out of revocation — and the window closes only on a successful refresh,
	// which is precisely what is broken in that scenario.
	//
	// The ceiling bounds the exposure without giving back the availability win:
	// inside it, behaviour is byte-identical to before; past it, ID-token
	// validation fails CLOSED and says so. It is deliberately generous (a day
	// absorbs any realistic outage) and deliberately a CONSTANT — an operator
	// override would be a knob whose only use is widening a trust window, and
	// immutable beats configurable for a fail-closed bound.
	//
	// Recovery is on OBSERVED evidence only: one refresh that actually returns
	// usable keys re-arms the full window (it advances fetchedAt). Elapsed time
	// never does.
	jwksStaleMaxAge = 24 * time.Hour

	// jwksFetchTimeout bounds a single key-set fetch.
	jwksFetchTimeout = 10 * time.Second
)

// errJWKSThrottled is returned when a refresh was suppressed by the negative
// window. It is a deny for this lookup, never a statement about the IdP.
var errJWKSThrottled = errors.New("jwks: refresh throttled (recent attempt)")

// errJWKSStaleCeiling is returned when a cached key set is past jwksStaleMaxAge
// and refreshes are still failing. It is a fail-CLOSED deny: the node can no
// longer show that the IdP still vouches for these keys.
var errJWKSStaleCeiling = errors.New("jwks: cached key set is past the stale-trust ceiling and cannot be refreshed")

// getKey returns the public key for kid, refreshing the cache when stale.
func (j *jwksCache) getKey(kid string) (interface{}, error) {
	j.mu.RLock()
	k, ok := j.keys[kid]
	fetchedAt := j.fetchedAt
	j.mu.RUnlock()
	stale := time.Since(fetchedAt) > jwksCacheTTL

	if ok && !stale {
		return k, nil
	}

	// Re-fetch, rate-limited and single-flighted. A failure leaves fetchedAt
	// untouched, so the snapshot above still measures the last time the IdP
	// actually vouched for this key set.
	if err := j.refreshOnce(); err != nil {
		if ok && j.staleServable(fetchedAt) {
			return k, nil // serve the stale key rather than failing (inside the ceiling)
		}
		if ok {
			// Past the ceiling AS FAR AS OUR PRE-REFRESH SNAPSHOT KNOWS — but
			// our refreshOnce may have returned errJWKSThrottled precisely
			// because a CONCURRENT lookup refreshed successfully after we
			// captured fetchedAt (that success advanced fetchedAt and cleared
			// the flag; the throttle is a rate control, never staleness
			// evidence). Re-read fetchedAt under the lock: only record a breach
			// and fail closed if the cache is STILL past the ceiling. Otherwise
			// the recovered key set is live, so serve it — and never restore a
			// breach flag from an obsolete snapshot (which would report a
			// freshly refreshed provider as failing until the next TTL refresh).
			// fetchedAt is monotonic non-decreasing, so re-reading it never
			// weakens the staleness bound.
			j.mu.Lock()
			curFetchedAt := j.fetchedAt
			if j.staleServable(curFetchedAt) {
				kk, okk := j.keys[kid]
				j.mu.Unlock()
				if okk {
					return kk, nil
				}
				return nil, fmt.Errorf("jwks: key %q not found", kid)
			}
			j.ceilingBreached = true
			j.mu.Unlock()
			j.logStaleRefusal(curFetchedAt)
			// The cause is sanitised + %q because this error reaches a log via the
			// callback handler, and the house rule is that anything crossing that
			// boundary is sanitised at the site CodeQL can see (CWE-117).
			return nil, fmt.Errorf("%w (last successful fetch %s ago, ceiling %s): %q",
				errJWKSStaleCeiling, time.Since(curFetchedAt).Truncate(time.Minute), jwksStaleMaxAge,
				sanitizeLog(err.Error()))
		}
		return nil, err
	}

	j.mu.RLock()
	k, ok = j.keys[kid]
	j.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("jwks: key %q not found", kid)
	}
	return k, nil
}

// staleServable reports whether a key set last successfully fetched at
// fetchedAt may still authenticate a token. A zero fetchedAt means no fetch has
// ever succeeded, so nothing is servable (fail closed — never trust a key set
// whose provenance we cannot date).
func (j *jwksCache) staleServable(fetchedAt time.Time) bool {
	if fetchedAt.IsZero() {
		return false
	}
	return time.Since(fetchedAt) <= jwksStaleMaxAge
}

// logStaleRefusal emits one rate-limited line when the stale-trust ceiling
// starts refusing lookups. Without it, the transition from "degraded but
// working" to "authentication is failing" is invisible: refreshOnce's own line
// says the cached keys are still being served, which stops being true here.
func (j *jwksCache) logStaleRefusal(fetchedAt time.Time) {
	j.mu.Lock()
	doLog := j.staleLogAt.IsZero() || time.Since(j.staleLogAt) >= jwksMinRefreshInterval
	if doLog {
		j.staleLogAt = time.Now()
	}
	uri := j.jwksURI
	j.mu.Unlock()
	if doLog && logger != nil {
		logger.Printf("OIDC: JWKS for %q has been unrefreshable for %s (ceiling %s) — "+
			"FAILING ID-token validation CLOSED. A signing key withdrawn at the IdP could "+
			"otherwise keep authenticating here. Restore reachability to the JWKS endpoint.",
			sanitizeLog(uri), time.Since(fetchedAt).Truncate(time.Minute), jwksStaleMaxAge)
	}
}

// staleCeilingStatus reports whether this cache is currently refusing lookups
// under the SEC-JWKS-1 stale-trust ceiling, and how long it has been since the
// last successful refresh. Side-effect-free: reads cached state only, issues
// no fetch. Used by operator-facing surfaces (checkOIDCJWKSTrust); the
// rate-limited log line stays the debug-level detail, this is the always-on
// signal.
func (j *jwksCache) staleCeilingStatus() (breached bool, since time.Duration, jwksURI string) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	if j.fetchedAt.IsZero() {
		return j.ceilingBreached, 0, j.jwksURI
	}
	return j.ceilingBreached, time.Since(j.fetchedAt), j.jwksURI
}

// jwksStaleProviders returns the display names of every live, enabled
// OIDCFlowProvider whose JWKS cache is currently past the stale-trust
// ceiling — i.e. ID-token validation for that provider is failing closed.
// Side-effect-free: issues no fetch, only reads cached state.
func jwksStaleProviders() []string {
	var names []string
	for _, live := range idpRegistry.EnabledProviders() {
		ofp, ok := live.(*OIDCFlowProvider)
		if !ok || ofp.jwks == nil {
			continue
		}
		if breached, _, _ := ofp.jwks.staleCeilingStatus(); breached {
			names = append(names, ofp.DisplayName())
		}
	}
	return names
}

// refreshOnce runs at most one refresh per jwksMinRefreshInterval and lets
// concurrent callers share a single in-flight fetch.
//
// The leader publishes its error to followers rather than letting them return
// success on an empty cache, so a failed refresh produces one diagnosable
// reason for every caller instead of N "key not found"s.
func (j *jwksCache) refreshOnce() error {
	j.mu.Lock()
	if j.refreshing {
		done := j.refreshDone
		j.mu.Unlock()
		<-done
		j.mu.RLock()
		err := j.refreshErr
		j.mu.RUnlock()
		return err
	}
	if !j.lastAttempt.IsZero() && time.Since(j.lastAttempt) < jwksMinRefreshInterval {
		j.mu.Unlock()
		return errJWKSThrottled
	}
	j.refreshing = true
	j.refreshDone = make(chan struct{})
	j.lastAttempt = time.Now()
	done := j.refreshDone
	j.mu.Unlock()

	err := j.refresh()

	j.mu.Lock()
	j.refreshing = false
	j.refreshDone = nil
	j.refreshErr = err
	doLog := err != nil && (j.logAt.IsZero() || time.Since(j.logAt) >= jwksMinRefreshInterval)
	if doLog {
		j.logAt = time.Now()
	}
	j.mu.Unlock()
	close(done)

	if doLog && logger != nil {
		// Serving the previously cached keys is the correct degradation here,
		// but it is degradation: without a line, a JWKS endpoint that has been
		// broken for hours is indistinguishable from a healthy one.
		logger.Printf("OIDC: JWKS refresh FAILED for %q — serving previously cached keys: %v",
			sanitizeLog(j.jwksURI), err)
	}
	return err
}

func (j *jwksCache) refresh() error {
	ctx, cancel := context.WithTimeout(context.Background(), jwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.jwksURI, http.NoBody)
	if err != nil {
		return fmt.Errorf("jwks request: %w", err)
	}
	resp, err := j.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()

	// A non-200 is not a key set. Decoding one anyway is how an HTTP 503 whose
	// body happens to be JSON ("{"error":...}") became an empty key map that
	// overwrote every good key in the cache.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch: HTTP %d", resp.StatusCode)
	}

	var set jwkSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&set); err != nil {
		return fmt.Errorf("jwks parse: %w", err)
	}

	keys := make(map[string]interface{}, len(set.Keys))
	for _, raw := range set.Keys {
		var kh jwkKeyRaw
		if err := json.Unmarshal(raw, &kh); err != nil {
			continue
		}
		if kh.Kty != "RSA" {
			continue // only RSA for now (ES256 extension is straightforward to add)
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(kh.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(kh.E)
		if err != nil {
			continue
		}
		var eInt big.Int
		eInt.SetBytes(eBytes)
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(eInt.Int64()),
		}
		keys[kh.Kid] = pub
	}

	// A response carrying no usable key is not evidence that the IdP has no
	// keys — it is evidence that something is wrong with the response (an edge
	// stub, a rate-limiter body, a rotation to key types this build cannot
	// parse). Installing it destroys the cache AND the stale-key fallback that
	// exists to survive exactly this, so every ID-token validation fails until
	// a good refresh lands. Keep what we have and fail the lookup closed.
	if len(keys) == 0 {
		return fmt.Errorf("jwks fetch: response carried no usable keys (keeping cached key set)")
	}

	j.mu.Lock()
	j.keys = keys
	j.fetchedAt = time.Now()
	j.ceilingBreached = false
	j.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// PKCE + state store
// ---------------------------------------------------------------------------

type pkceEntry struct {
	verifier   string
	nonce      string
	relayURL   string
	providerID string
}

// pkceStore is the bounded, fair-share store for in-flight OIDC authorization
// requests (verifier + nonce + return target), keyed by the `state` token.
//
// Entries are minted SPECULATIVELY for clients that have not authenticated —
// resolveCaptivePortalURL does it on the proxy's no-credentials path, and the
// public /auth/select page does it per render — so the store's eviction policy
// decides whether an anonymous flood can destroy other users' in-flight login
// state. It cannot: see internal/authstate.
type pkceStore = authstate.Store[*pkceEntry]

const pkceEntryTTL = 10 * time.Minute
const pkceStoreMax = 1000

var globalPKCEStore = newPKCEStore()

func newPKCEStore() *pkceStore {
	return authstate.New[*pkceEntry](pkceEntryTTL, pkceStoreMax)
}

// ---------------------------------------------------------------------------
// OIDCFlowProvider
// ---------------------------------------------------------------------------

// OIDCFlowProvider is the live, compiled provider built from an OIDCProfileConfig.
type OIDCFlowProvider struct {
	profile *IdPProfile
	cfg     *OIDCProfileConfig
	disc    *oidcDiscoveryDoc
	jwks    *jwksCache
	client  *http.Client
	// cachedAt is when the discovery document this provider was built from was
	// fetched, if it came from the last-known-good cache; zero when fetched
	// live. Read only by the publish sites (idpNotePublishedGeneration).
	cachedAt time.Time

	// ── Introspection result cache + availability gate (CHAOS-49) ────────────
	//
	// The registry path authenticates on EVERY proxied request, and the
	// dispatch loop in proxy.go asks every enabled provider in turn. Without a
	// cache that is one RFC 7662 round trip per request per provider; without a
	// gate, an IdP outage is one 10 s dial timeout per request per provider,
	// serialized, while the request goroutine is held. The legacy single-provider
	// backend (auth_oidc.go) has had both since CHAOS-47 — this is the same
	// contract on the newer surface, reusing the same primitives.
	mu    sync.Mutex
	cache map[string]*oidcCacheEntry // key = cacheKey("", token)
	ttl   time.Duration
	gate  authProbeGate
}

// oidcFlowCacheTTL matches the legacy backend's default: short, because a token
// can be revoked at the IdP at any moment and this cache is what delays the
// proxy noticing.
const oidcFlowCacheTTL = 2 * time.Minute

func (p *OIDCFlowProvider) cacheTTL() time.Duration {
	if p.ttl > 0 {
		return p.ttl
	}
	return oidcFlowCacheTTL
}

// introspectCacheGet returns a cached verdict, if one is live.
func (p *OIDCFlowProvider) introspectCacheGet(key string) (identity *Identity, ok, hit bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, found := p.cache[key]; found && time.Now().Before(e.expiry) {
		return cloneIdentity(e.identity), e.ok, true
	}
	return nil, false, false
}

// introspectCacheSet records an AUTHORITATIVE verdict. Infrastructure failures
// never reach here — see ResolveIdentity.
func (p *OIDCFlowProvider) introspectCacheSet(key string, identity *Identity, ok bool, tokenExp *int64) (*Identity, bool) {
	if ok && (identity == nil || strings.TrimSpace(identity.Sub) == "") {
		identity = nil
		ok = false
	}
	now := time.Now()
	ttl, stillValid := clampCacheTTLToTokenExpiry(p.cacheTTL(), tokenExp, now)
	if ok && !stillValid {
		identity = nil
		ok = false
	}
	p.mu.Lock()
	if p.cache == nil {
		p.cache = map[string]*oidcCacheEntry{}
	}
	// Evict an arbitrary entry when full — the key space is token-derived and
	// therefore caller-controlled, so the map must stay bounded.
	if len(p.cache) >= maxAuthCacheSize {
		for k := range p.cache {
			delete(p.cache, k)
			break
		}
	}
	p.cache[key] = &oidcCacheEntry{ok: ok, identity: cloneIdentity(identity), expiry: now.Add(ttl)}
	p.mu.Unlock()
	return cloneIdentity(identity), ok
}

// NewOIDCFlowProvider validates the profile, runs OIDC discovery, and returns
// a ready-to-use OIDCFlowProvider.
func NewOIDCFlowProvider(p *IdPProfile) (*OIDCFlowProvider, error) {
	cfg := p.OIDC
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc[%s]: client_id required", p.ID)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = ssrfSafeDialContext // SSRF guard at dial level
	if cfg.TLSSkipVerify {
		logWarnf("OIDC flow [%s]: TLS certificate verification DISABLED (tls_skip_verify) — credentials traverse an unverified channel vulnerable to MITM; intended for self-signed dev IdPs only", sanitizeLog(p.ID)) // RISK-009
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}                                                                                                                                              // #nosec G402 -- InsecureSkipVerify is an explicit admin opt-in via cfg.TLSSkipVerify (warned above)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}

	disc, cachedAt, err := fetchOIDCDiscovery(p.ID, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc[%s] discovery: %w", p.ID, err)
	}
	// Persist discovered endpoints back into the profile config so the UI
	// can display them.
	cfg.AuthorizationEndpoint = disc.AuthorizationEndpoint
	cfg.TokenEndpoint = disc.TokenEndpoint
	cfg.IntrospectionEndpoint = disc.IntrospectionEndpoint
	cfg.UserinfoEndpoint = disc.UserinfoEndpoint
	cfg.JWKsURI = disc.JWKsURI

	prov := &OIDCFlowProvider{
		profile: p,
		cfg:     cfg,
		disc:    disc,
		client:  client,
		cache:   map[string]*oidcCacheEntry{},
		ttl:     oidcFlowCacheTTL,

		cachedAt: cachedAt,
	}
	if disc.JWKsURI != "" {
		prov.jwks = &jwksCache{jwksURI: disc.JWKsURI, client: client, keys: make(map[string]interface{})}
	}
	return prov, nil
}

func (p *OIDCFlowProvider) Name() string { return "oidc:" + p.profile.ID }

func (p *OIDCFlowProvider) servedDocumentCachedAt() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.cachedAt
}

// DisplayName returns the admin-configured label shown to end users (e.g. on
// the IdP selection screen), falling back to the machine key if unset.
func (p *OIDCFlowProvider) DisplayName() string {
	if p.profile.Name != "" {
		return p.profile.Name
	}
	return p.Name()
}

// Verify supports non-browser clients that supply an access token as the
// proxy password (RFC 7662 introspection).
func (p *OIDCFlowProvider) Verify(username, token string) bool {
	id, ok := p.ResolveIdentity(username, token)
	return ok && id != nil
}

// ResolveIdentity introspects the token (for non-browser clients) or validates
// an ID token (for browser flows after callback).  For non-browser clients
// the token is treated as an opaque access token and sent to the introspection
// endpoint.
func (p *OIDCFlowProvider) ResolveIdentity(username, token string) (*Identity, bool) {
	if token == "" {
		return nil, false
	}

	// Try JWT validation first (browser flow — token is an ID token).
	// No nonce check here: non-browser clients submit access tokens, not ID tokens.
	if id, err := p.validateIDToken(token, ""); err == nil {
		if id.Sub == "" {
			return nil, false // reject empty subject
		}
		return id, true
	}

	// Fallback: RFC 7662 introspection (non-browser / access token flow).
	if p.disc.IntrospectionEndpoint == "" {
		return nil, false
	}
	return p.resolveByIntrospection(token)
}

// resolveByIntrospection is the cached, gated, observable introspection path
// (CHAOS-49). It mirrors OIDCAuth.ResolveIdentity exactly, including the rule
// that makes the whole thing safe: only an AUTHORITATIVE answer from a reachable
// endpoint is cacheable. A failure to REACH the IdP denies this request and is
// then forgotten, so a one-second IdP blip cannot keep denying valid tokens for
// the full cache TTL after the IdP is healthy again.
func (p *OIDCFlowProvider) resolveByIntrospection(token string) (*Identity, bool) {
	backend := p.Name()

	// A bearer token has one canonical identity regardless of which Basic
	// username accompanies it, so cache by token only. cacheKey HMACs the input,
	// so no bearer token is held in the map.
	k := cacheKey("", token)
	if id, ok, hit := p.introspectCacheGet(k); hit {
		return id, ok
	}

	if !p.gate.allow() {
		// The IdP is in its unreachable cooldown — deny without another round
		// trip. This is what collapses "N providers × 10 s dial timeout on
		// every request" back to a constant during an outage.
		noteAuthBackendGatedDenial()
		return nil, false
	}

	id, ok, exp, err := p.introspect(token)
	if err != nil {
		if errors.Is(err, errIntrospectClient) {
			// A 4xx is a client/token-side rejection, not an outage. It must not
			// arm the provider-wide gate — otherwise one caller with a malformed
			// token locks out every other user. And because the endpoint
			// demonstrably answered, it must CLEAR a cooldown a previous outage
			// armed, rather than silently eating each half-open probe.
			p.gate.recordReachable()
			noteAuthBackendReachable(backend)
			logger.Printf("OIDC[%s] auth DENY (introspection 4xx) — client/token error, not a backend outage; "+
				"the endpoint answered, so any cooldown is cleared", sanitizeLog(p.profile.ID))
			return nil, false
		}
		p.gate.recordUnavailable()
		noteAuthBackendUnavailable(backend, err.Error())
		logger.Printf("OIDC[%s] auth UNAVAILABLE (introspection endpoint unreachable) — failing closed, not cached",
			sanitizeLog(p.profile.ID))
		return nil, false
	}
	p.gate.recordReachable()
	noteAuthBackendReachable(backend)

	return p.introspectCacheSet(k, id, ok, exp)
}

// CaptiveLoginURL builds an OIDC authorization URL with PKCE + state + nonce,
// stores the verifier in globalPKCEStore, and returns the URL to redirect to.
func (p *OIDCFlowProvider) CaptiveLoginURL(relayURL string, r *http.Request) string {
	if p.disc.AuthorizationEndpoint == "" {
		return ""
	}

	// Generate state (CSRF token), PKCE verifier + challenge, nonce.
	state := mustRandHex(16)
	verifier := mustRandHex(32)
	nonce := mustRandHex(16)

	// PKCE S256: challenge = base64url(sha256(verifier))
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Attributed to the requesting client so a flood from one source can only
	// evict its own in-flight state, never another user's mid-login entry.
	globalPKCEStore.Set(state, authStateClientKey(r), &pkceEntry{
		verifier:   verifier,
		nonce:      nonce,
		relayURL:   relayURL,
		providerID: p.profile.ID,
	})

	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {proxyBaseURL(r) + "/auth/oidc/callback"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return p.disc.AuthorizationEndpoint + "?" + q.Encode()
}

// ---------------------------------------------------------------------------
// OIDC callback (exchangeCode)
// ---------------------------------------------------------------------------

// ExchangeCode handles the authorization code callback: exchanges the code for
// tokens, validates the ID token, fetches userinfo, and returns the Identity.
func (p *OIDCFlowProvider) ExchangeCode(r *http.Request, code, state string) (*Identity, error) {
	entry, ok := globalPKCEStore.Pop(state)
	if !ok {
		return nil, fmt.Errorf("oidc callback: invalid or expired state")
	}
	if entry.providerID != p.profile.ID {
		return nil, fmt.Errorf("oidc callback: state belongs to different provider")
	}

	// Exchange code → tokens.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {proxyBaseURL(r) + "/auth/oidc/callback"},
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code_verifier": {entry.verifier},
	}
	tokenCtx, tokenCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer tokenCancel()
	req, err := http.NewRequestWithContext(tokenCtx,
		http.MethodPost, p.disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("oidc token endpoint HTTP %d: %s", resp.StatusCode, body)
	}

	var tr struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("oidc token parse: %w", err)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("oidc: no id_token in response")
	}

	// Validate ID token and extract identity; nonce verified inside.
	id, err := p.validateIDToken(tr.IDToken, entry.nonce)
	if err != nil {
		return nil, fmt.Errorf("oidc id_token validation: %w", err)
	}

	if id.Sub == "" {
		return nil, fmt.Errorf("oidc: empty sub in id_token")
	}

	// Fetch userinfo for richer attributes (email, name, groups).
	if p.disc.UserinfoEndpoint != "" && tr.AccessToken != "" {
		if err := p.enrichFromUserinfo(id, tr.AccessToken); err != nil {
			logger.Printf("OIDC userinfo error (non-fatal): %v", err)
		}
	}

	id.Provider = p.profile.ID
	return id, nil
}

// ---------------------------------------------------------------------------
// ID token validation
// ---------------------------------------------------------------------------

// validateIDToken parses, validates, and extracts identity from a raw JWT ID token.
// expectedNonce must match the "nonce" claim when non-empty (browser PKCE flow);
// pass "" to skip nonce verification (non-browser introspection path).
func (p *OIDCFlowProvider) validateIDToken(rawToken, expectedNonce string) (*Identity, error) {
	if p.jwks == nil {
		return nil, fmt.Errorf("oidc: no jwks_uri configured for ID-token validation")
	}

	// Parse without verification first to get the key ID from the header.
	unverified, _, err := jwtv5.NewParser().ParseUnverified(rawToken, jwtv5.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("oidc: parse id_token header: %w", err)
	}
	kid := unverified.Header["kid"]
	kidStr, _ := kid.(string)

	pubKey, err := p.jwks.getKey(kidStr)
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks key %q: %w", kidStr, err)
	}

	// Full validation with signature check. The issuer claim is pinned to
	// the discovery document's issuer (OIDC Core §3.1.3.7 step 2): without
	// it, a token minted by a different issuer that shares the same JWKS —
	// e.g. another tenant of a multi-tenant IdP — would be accepted.
	opts := []jwtv5.ParserOption{
		jwtv5.WithIssuedAt(),
		jwtv5.WithAudience(p.cfg.ClientID),
		jwtv5.WithExpirationRequired(),
		jwtv5.WithLeeway(60 * time.Second), // tolerate clock skew between IdP and proxy
	}
	if p.disc.Issuer != "" {
		opts = append(opts, jwtv5.WithIssuer(p.disc.Issuer))
	}
	token, err := jwtv5.NewParser(opts...).Parse(rawToken, func(t *jwtv5.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtv5.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token invalid: %w", err)
	}

	claims, ok := token.Claims.(jwtv5.MapClaims)
	if !ok {
		return nil, fmt.Errorf("oidc: claims type error")
	}

	id := &Identity{}
	id.Sub, _ = claims["sub"].(string)
	id.Email, _ = claims["email"].(string)
	id.Name, _ = claims["name"].(string)

	// Extract groups from the configured claim.
	groupsClaim := p.cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	id.Groups = extractStringSliceClaim(claims, groupsClaim)

	// Verify nonce to prevent ID token replay attacks (OIDC Core §3.1.3.7).
	if expectedNonce != "" {
		nonceClaim, _ := claims["nonce"].(string)
		if nonceClaim != expectedNonce {
			return nil, fmt.Errorf("oidc: nonce mismatch — possible token replay")
		}
	}

	return id, nil
}

// ---------------------------------------------------------------------------
// Userinfo
// ---------------------------------------------------------------------------

func (p *OIDCFlowProvider) enrichFromUserinfo(id *Identity, accessToken string) error {
	uiCtx, uiCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer uiCancel()
	req, err := http.NewRequestWithContext(uiCtx,
		http.MethodGet, p.disc.UserinfoEndpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("userinfo HTTP %d", resp.StatusCode)
	}

	var claims map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&claims); err != nil {
		return err
	}

	if id.Email == "" {
		id.Email, _ = claims["email"].(string)
	}
	if id.Name == "" {
		id.Name, _ = claims["name"].(string)
	}

	groupsClaim := p.cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	if len(id.Groups) == 0 {
		id.Groups = extractStringSliceClaim(claims, groupsClaim)
	}
	return nil
}

// ---------------------------------------------------------------------------
// RFC 7662 introspection (non-browser path)
// ---------------------------------------------------------------------------

// introspect returns the canonical token identity and its declared Unix expiry.
//
// The returned error is reserved for INFRASTRUCTURE failure — the endpoint could
// not be reached, or did not answer coherently. `(nil, false, nil, nil)` means
// the endpoint answered and the answer was "this token is not valid". Only the
// latter is cacheable; see resolveByIntrospection.
//
// RFC 7662 is what makes the split clean: an inactive token is reported as HTTP
// 200 with `active:false`, so ANY non-200 is a problem with the endpoint or our
// client credentials — never a verdict about the caller's token.
func (p *OIDCFlowProvider) introspect(token string) (identity *Identity, active bool, tokenExp *int64, err error) {
	form := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}
	intrCtx, intrCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer intrCancel()
	req, reqErr := http.NewRequestWithContext(intrCtx,
		http.MethodPost, p.disc.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if reqErr != nil {
		return nil, false, nil, fmt.Errorf("build request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.cfg.ClientID, p.cfg.ClientSecret)

	resp, doErr := p.client.Do(req)
	if doErr != nil {
		return nil, false, nil, fmt.Errorf("introspection request: %w", doErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if isIntrospectClientError(resp.StatusCode) {
			return nil, false, nil, fmt.Errorf("%w: HTTP %d", errIntrospectClient, resp.StatusCode)
		}
		// A 401 is a provider-wide client-credential fault, not a token verdict —
		// it arms the gate and is reported as an outage. See isIntrospectClientError.
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, false, nil, fmt.Errorf("%w", errIntrospectClientAuth)
		}
		return nil, false, nil, fmt.Errorf("introspection endpoint returned HTTP %d", resp.StatusCode)
	}

	var claims map[string]interface{}
	if decErr := decodeStrictJSON(resp.Body, 64<<10, &claims, true); decErr != nil {
		return nil, false, nil, fmt.Errorf("introspection response: %w", decErr)
	}
	// From here on the endpoint has answered coherently: every remaining branch
	// is an authoritative verdict about the token, and therefore cacheable.
	id, exp, ok := p.identityFromIntrospectionClaims(claims)
	return id, ok, exp, nil
}

func (p *OIDCFlowProvider) identityFromIntrospectionClaims(claims map[string]interface{}) (*Identity, *int64, bool) {
	active, _ := claims["active"].(bool)
	if !active {
		return nil, nil, false
	}
	var tokenExp *int64
	if rawExp, present := claims["exp"]; present {
		expNumber, numeric := rawExp.(json.Number)
		if !numeric {
			return nil, nil, false
		}
		exp, valid := parseDeclaredExpiry(json.RawMessage(expNumber.String()))
		if !valid || exp == nil || *exp <= time.Now().Unix() {
			return nil, nil, false
		}
		tokenExp = exp
	}
	scope, _ := claims["scope"].(string)
	if p.cfg.RequiredScope != "" {
		if !strings.Contains(" "+scope+" ", " "+p.cfg.RequiredScope+" ") {
			return nil, nil, false
		}
	}
	if p.cfg.RequiredAudience != "" && !audienceContains(claims["aud"], p.cfg.RequiredAudience) {
		return nil, nil, false
	}

	sub, _ := claims["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		sub, _ = claims["username"].(string)
	}
	if strings.TrimSpace(sub) == "" {
		return nil, nil, false
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	groupsClaim := p.cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	id := &Identity{
		Sub:      sub,
		Email:    email,
		Name:     name,
		Groups:   extractStringSliceClaim(claims, groupsClaim),
		Provider: p.profile.ID,
	}
	return id, tokenExp, true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustRandHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func extractStringSliceClaim(claims map[string]interface{}, key string) []string {
	raw, ok := claims[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	}
	return nil
}

// proxyBaseURL returns the external-facing base URL of the proxy UI.
// Used to construct the OIDC/SAML callback redirect_uri.
//
// Priority: (1) explicit base_url config, (2) derive from request Host header,
// (3) fall back to https://localhost:9090.
//
// X-Forwarded-* headers are only trusted when trust_forwarded_headers is enabled
// (prevents host header injection when directly exposed to the internet).
func proxyBaseURL(r *http.Request) string {
	if u := cfg.ProxyBaseURL(); u != "" {
		return u
	}
	if r != nil {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		host := r.Host
		if trustForwardedHeaders {
			if fp := r.Header.Get("X-Forwarded-Proto"); fp == "http" || fp == "https" {
				scheme = fp
			}
			if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
				host = fh
			}
		}
		return scheme + "://" + host
	}
	return "https://localhost:9090"
}
