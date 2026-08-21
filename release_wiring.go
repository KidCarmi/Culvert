// Release Management startup wiring (P1.6d-0.1).
//
// Constructs and publishes the Release Management backend (catalog provider +
// DispatchService + releaseManager) so the /api/releases* routes are actually
// usable instead of reporting "not configured". It is deliberately MINIMAL and
// NON-FATAL: any failure leaves globalReleaseMgr nil and the routes report a
// clear 503 — never a panic.
//
// Scope: empty catalog holder (a later refresh slice populates it), the default
// proxy_repo, an optional empty repo_rewrite, and the single CP-LOCAL
// maintenance agent (key "local"), reached over its unix socket by default or an
// http(s) URL via CULVERT_MAINT_AGENT_URL. NO mutable config route, NO GUI.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// defaultReleaseProxyRepo matches the documented config.proxy_repo default
	// (P1.4). Overridable via CULVERT_RELEASE_PROXY_REPO until the GUI slice adds
	// a managed config surface.
	defaultReleaseProxyRepo = "ghcr.io/kidcarmi/culvert"
	// defaultMaintAgentSocket is the culvert-maint server's default unix socket.
	defaultMaintAgentSocket = "/run/culvert-maint/culvert-maint.sock"
	// localAgentKey is the stable key for the CP's own maintenance agent.
	localAgentKey = "local"

	envReleaseProxyRepo = "CULVERT_RELEASE_PROXY_REPO"
	envMaintAgentURL    = "CULVERT_MAINT_AGENT_URL"
	// envReleaseCatalogTrustKeys is a JSON array of operator trust roots that
	// EXTEND the baked roots:
	// [{"key_id":"prod-2026","alg":"ed25519","public_key":"<base64-raw-32-byte-key>"}]
	envReleaseCatalogTrustKeys = "CULVERT_RELEASE_CATALOG_TRUST_KEYS"
	// envReleaseCatalogVerify is the read-once break-glass override for the catalog
	// signature mode. The SECURE DEFAULT is enforce whenever any trust root is
	// present; this env exists only to deliberately relax that:
	//   - "enforce"    — explicit enforce (default when roots present).
	//   - "permissive" — BREAK-GLASS: load an unsigned catalog with a loud warning
	//                    (a present-but-invalid signature is still rejected).
	//   - "disabled"   — BREAK-GLASS: skip verification entirely (local dev only).
	// Unset + roots present ⇒ enforce. Unset + no roots ⇒ Release Management is
	// disabled (an unsigned catalog is NEVER auto-trusted).
	envReleaseCatalogVerify = "CULVERT_RELEASE_CATALOG_VERIFY"
	// envReleaseCatalogURL is the operator OVERRIDE for the catalog origin (M1-2
	// product revision). Unset ⇒ the baked default (defaultReleaseCatalogURL); a
	// http(s) URL ⇒ that mirror/staging origin; an off/none/disabled sentinel ⇒ NO
	// outbound fetch with the trust posture unchanged. Auto-seed runs ONLY in
	// enforce mode. The origin NEVER affects trust (see resolveCatalogURL).
	envReleaseCatalogURL = "CULVERT_RELEASE_CATALOG_URL"
	// envReleaseSigstoreIdentity is the OPTIONAL operator override for the pinned
	// keyless identity policy, JSON {"issuer","san_regex"} (P2b). Unset ⇒ the baked
	// official identity. Break-glass / fork-mirror use only; env-only (GUI-parity
	// deferral, same as the other CULVERT_RELEASE_* vars).
	envReleaseSigstoreIdentity = "CULVERT_RELEASE_SIGSTORE_IDENTITY"

	// envReleaseRefreshInterval sets the periodic catalog refresh cadence (M1-2).
	// Go duration string ("6h", "90m"); unset/invalid ⇒ the 6h default. Env-only,
	// matching the CULVERT_RELEASE_* family precedent (recorded GUI-parity
	// deferral); surfaced read-only on GET /api/releases.
	envReleaseRefreshInterval = "CULVERT_RELEASE_REFRESH_INTERVAL"
	// envReleaseSigstoreTrustedRoot is the OPTIONAL path to a custom Sigstore TUF
	// trusted_root.json (P2b). Unset ⇒ the baked embed (empty in OSS ⇒ scheme
	// dormant). PUBLIC trust material only — never private keys.
	envReleaseSigstoreTrustedRoot = "CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT"
)

// bakedReleaseTrustKeysJSON is the BAKED-IN public trust root set, in the same
// JSON shape as CULVERT_RELEASE_CATALOG_TRUST_KEYS. It is empty in the open-source
// tree and is populated at official-build time via the linker
// (`-ldflags "-X main.bakedReleaseTrustKeysJSON=[...]"`) so a shipped Control
// Plane trusts the official release-signing key out of the box and enters enforce
// mode automatically. It holds PUBLIC keys only — never private key material.
var bakedReleaseTrustKeysJSON = ""

type releaseStartupConfig struct {
	proxyRepo        string
	catalogDir       string
	statePath        string     // persisted rollback version floor (sibling of catalogDir)
	maintURL         string     // CP-local maint agent endpoint (unix socket path or http[s] URL)
	catalogURL       string     // optional http(s) origin to auto-seed the signed catalog (P1.7); "" ⇒ no fetch
	trustKeys        []TrustKey // baked roots ∪ operator-configured roots
	trustKeysErr     error
	sigstore         *sigstoreVerifier // optional keyless (Sigstore-identity) verifier; nil ⇒ scheme inactive
	sigstoreActive   bool              // true ⇒ a Sigstore trusted root is present
	sigstoreWarn     string            // loud one-line note (identity set without a root) ("" ⇒ none)
	sigstoreErr      error             // fatal Sigstore config error ⇒ Release Management disabled
	verifyMode       VerifyMode
	verifyModeWarn   string        // loud break-glass message to log once at startup ("" ⇒ none)
	refreshInterval  time.Duration // periodic catalog refresh cadence (M1-2); 0 ⇒ loop disabled
	catalogURLSource string        // catalogURLSource{Default,Override,Disabled} (M1-2 product revision)
}

// resolveReleaseStartupConfig reads the static inputs (env + dataDir). No mutable
// config route, no FileConfig change — env overrides over documented defaults.
func resolveReleaseStartupConfig() releaseStartupConfig {
	return resolveReleaseStartupConfigFrom(os.Getenv)
}

// resolveReleaseStartupConfigFrom is the env-injectable core (tests pass a fake
// getenv so they never mutate process state — avoids t.Setenv data races under
// -race when other goroutines read the environment).
func resolveReleaseStartupConfigFrom(getenv func(string) string) releaseStartupConfig {
	proxyRepo := getenv(envReleaseProxyRepo)
	if proxyRepo == "" {
		proxyRepo = defaultReleaseProxyRepo
	}
	maintURL := getenv(envMaintAgentURL)
	if maintURL == "" {
		maintURL = defaultMaintAgentSocket
	}
	catalogDir := filepath.Join(dataDir, "release_catalog")
	keys, keysErr := combinedReleaseTrustKeys(getenv(envReleaseCatalogTrustKeys))
	sig := resolveSigstoreWiring(getenv)
	// Enforce-by-default keys off ANY configured trusted scheme (ed25519 ring OR
	// the Sigstore verifier) — not just the ed25519 ring count.
	nSchemes := len(keys)
	if sig.active {
		nSchemes++
	}
	mode, warn := resolveCatalogVerifyMode(getenv(envReleaseCatalogVerify), nSchemes)
	interval := resolveRefreshInterval(getenv(envReleaseRefreshInterval))
	catalogURL, catalogURLSource := resolveCatalogURL(getenv(envReleaseCatalogURL))
	return releaseStartupConfig{
		proxyRepo:        proxyRepo,
		catalogDir:       catalogDir,
		statePath:        filepath.Join(dataDir, "release_catalog_state.json"),
		maintURL:         maintURL,
		catalogURL:       catalogURL,
		trustKeys:        keys,
		trustKeysErr:     keysErr,
		sigstore:         sig.verifier,
		sigstoreActive:   sig.active,
		sigstoreWarn:     sig.warn,
		sigstoreErr:      sig.err,
		verifyMode:       mode,
		verifyModeWarn:   warn,
		refreshInterval:  interval,
		catalogURLSource: catalogURLSource,
	}
}

// Catalog origin sources, surfaced read-only on /api/releases as
// catalog_url_source so an operator can see WHERE releases come from (and whether
// fetching is off) without SSH/log access.
const (
	catalogURLSourceDefault  = "default"  // baked canonical origin (customer configured nothing)
	catalogURLSourceOverride = "override" // operator pointed CULVERT_RELEASE_CATALOG_URL at a mirror/staging origin
	catalogURLSourceDisabled = "disabled" // operator explicitly turned outbound catalog fetch OFF
)

// resolveCatalogURL returns the effective catalog origin and its source. Pure.
//   - empty/whitespace         ⇒ the canonical built-in default (a customer never
//     needs to configure this; the override exists for air-gap/mirror/staging).
//   - an explicit off sentinel ⇒ NO outbound fetch, trust posture UNCHANGED. This
//     is the trust-SAFE opt-out: silencing the fetch must never require relaxing
//     CULVERT_RELEASE_CATALOG_VERIFY (which would weaken the trust channel to
//     solve a network/privacy concern).
//   - anything else            ⇒ used verbatim as the operator override origin.
func resolveCatalogURL(v string) (origin, source string) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return defaultReleaseCatalogURL, catalogURLSourceDefault
	case isCatalogFetchDisabled(v):
		return "", catalogURLSourceDisabled
	default:
		return v, catalogURLSourceOverride
	}
}

// isCatalogFetchDisabled recognizes the explicit "turn outbound catalog fetch
// off" sentinels (case-insensitive). These are the ONLY values that stop the
// fetch while leaving verification fully enforced on any on-disk catalog.
func isCatalogFetchDisabled(v string) bool {
	switch strings.ToLower(v) {
	case "off", "none", "disabled":
		return true
	}
	return false
}

// defaultReleaseCatalogURL is the CANONICAL built-in catalog origin (M1-2 product
// revision): a normal customer needs NO configuration — the appliance fetches the
// official signed catalog by default. CULVERT_RELEASE_CATALOG_URL remains an
// explicit operator OVERRIDE (air-gapped deployments, internal mirrors,
// staging/regional distribution), or one of the disable sentinels
// (off/none/disabled) to turn outbound fetch off entirely. The origin NEVER
// affects trust: verification is always the baked roots + pinned identity
// regardless of where bytes come from, and overriding the URL cannot change
// trusted signing identities or roots.
// NOTE (recorded constraint): the SSRF guard rejects private-IP origins by design;
// an internal mirror must be served on a publicly-resolving, non-private host, or
// a future explicit allowlist knob (deferred) is required — the guard is not
// relaxed here.
const defaultReleaseCatalogURL = "https://catalog.culvertlabs.com/release-catalog"

// defaultRefreshInterval is the periodic catalog refresh cadence when
// CULVERT_RELEASE_REFRESH_INTERVAL is unset. Six hours keeps appliances within
// half a day of a new/re-signed catalog without meaningful origin load.
const defaultRefreshInterval = 6 * time.Hour

// resolveRefreshInterval parses the refresh cadence. Pure. Unset or invalid ⇒
// the default (fail-safe: a typo must not disable the freshness loop); a value
// below 1m is clamped to 1m (defense against hammering the origin).
func resolveRefreshInterval(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return defaultRefreshInterval
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return defaultRefreshInterval
	}
	if d < time.Minute {
		return time.Minute
	}
	return d
}

// combinedReleaseTrustKeys merges the BAKED roots with the operator-configured
// roots (env). Either being malformed is fail-closed (Release Management stays
// disabled rather than booting with a half-parsed trust ring).
func combinedReleaseTrustKeys(envRaw string) ([]TrustKey, error) {
	baked, err := parseReleaseCatalogTrustKeys(bakedReleaseTrustKeysJSON)
	if err != nil {
		return nil, fmt.Errorf("baked trust keys: %w", err)
	}
	configured, err := parseReleaseCatalogTrustKeys(envRaw)
	if err != nil {
		return nil, err
	}
	return append(baked, configured...), nil
}

// resolveCatalogVerifyMode implements the central Phase 1 rule: trust roots imply
// VerifyEnforce; permissive/disabled are EXPLICIT break-glass only. It returns the
// mode plus a loud one-line warning to log when a break-glass mode is selected.
//
//   - override "disabled"   → VerifyDisabled (break-glass; warn).
//   - override "permissive" → VerifyPermissive (break-glass; warn).
//   - override "enforce" or unset, roots present → VerifyEnforce (secure default).
//   - unset, NO roots       → VerifyEnforce with an empty ring; NewTrustStore then
//     fails closed and Release Management is disabled (never auto-trusts unsigned).
func resolveCatalogVerifyMode(override string, nRoots int) (VerifyMode, string) {
	switch strings.ToLower(strings.TrimSpace(override)) {
	case "disabled":
		return VerifyDisabled, "release catalog: signature verification DISABLED via " +
			envReleaseCatalogVerify + "=disabled (BREAK-GLASS — unsigned/forged catalogs are NOT rejected; local dev only)"
	case "permissive":
		return VerifyPermissive, "release catalog: signature verification PERMISSIVE via " +
			envReleaseCatalogVerify + "=permissive (BREAK-GLASS — UNSIGNED catalogs are accepted; a present-but-invalid signature is still rejected)"
	case "enforce", "":
		if nRoots == 0 {
			// Secure default with no roots: enforce-empty fails closed downstream
			// (NewTrustStore rejects an empty enforce ring) and Release Management
			// is disabled. Surface that as a warning rather than a silent 503.
			return VerifyEnforce, "release catalog: no trust roots present; Release Management will be DISABLED " +
				"(set CULVERT_RELEASE_CATALOG_TRUST_KEYS, ship baked roots, or use CULVERT_RELEASE_CATALOG_VERIFY=permissive for break-glass)"
		}
		return VerifyEnforce, ""
	default:
		// An unrecognized value must not silently relax: fall back to the secure
		// default and warn so the typo is visible.
		return VerifyEnforce, "release catalog: unrecognized " + envReleaseCatalogVerify +
			" value " + fmt.Sprintf("%q", override) + "; defaulting to enforce"
	}
}

// loadReleaseManagement constructs and publishes the Release Management backend.
// Best-effort and NON-FATAL: on any failure globalReleaseMgr stays nil so the
// routes report 503 rather than panicking.
func loadReleaseManagement(cfg releaseStartupConfig) {
	if cfg.trustKeysErr != nil {
		logger.Printf("release management disabled: catalog trust keys: %v", cfg.trustKeysErr)
		return
	}
	if cfg.sigstoreErr != nil {
		logger.Printf("release management disabled: sigstore trust: %v", cfg.sigstoreErr)
		return
	}
	if cfg.sigstoreWarn != "" {
		logger.Printf("%s", cfg.sigstoreWarn)
	}
	if cfg.verifyModeWarn != "" {
		logger.Printf("%s", cfg.verifyModeWarn)
	}
	// Central Phase 1 invariant: production wiring enters VerifyEnforce whenever a
	// trust root (baked or configured, ed25519 OR Sigstore) is present. With NO
	// trusted scheme and no break-glass override, the mode is enforce with an EMPTY
	// trust store → NewTrustStoreWithSigstore fails closed → Release Management is
	// DISABLED. An unsigned catalog is never auto-trusted; the only way to load one
	// is the explicit CULVERT_RELEASE_CATALOG_VERIFY break-glass.
	trust, err := NewTrustStoreWithSigstore(cfg.trustKeys, cfg.verifyMode, cfg.sigstore)
	if err != nil {
		logger.Printf("release management disabled: %v (configure CULVERT_RELEASE_CATALOG_TRUST_KEYS, ship baked roots, or set CULVERT_RELEASE_CATALOG_VERIFY=permissive for break-glass)", err)
		// The empty-enforce-ring failure IS the case the Sigstore warning
		// describes: an operator who set a custom identity (…_SIGSTORE_IDENTITY)
		// with no trusted root leaves the keyless scheme dormant, so with no
		// ed25519 roots either the enforce ring is empty and construction fails
		// here. Publish a warning-only manager (no dispatch service, no catalog)
		// so GET /api/releases surfaces available:false + sigstore_warn instead
		// of a blank 503 the operator cannot diagnose without log access — the
		// exact misconfiguration this warning exists to make visible.
		if cfg.sigstoreWarn != "" {
			setReleaseManager(&releaseManager{
				verifyMode:   cfg.verifyMode,
				trustSchemes: trustSchemes(cfg),
				sigstoreWarn: cfg.sigstoreWarn,
				// A non-nil store keeps the dispatch-status read (which does not
				// gate on svc) safe; it stays empty, so that endpoint reports
				// "phase: none" for a disabled manager. Every dispatch/refresh
				// handler already gates on svc == nil and returns 503.
				store: newDispatchStore(),
			})
		}
		return
	}

	// Freshness (expires_at) + rollback (catalog_version) are enforced ONLY in
	// enforce mode — break-glass intentionally relaxes the whole trust channel.
	var holder *CatalogHolder
	if cfg.verifyMode == VerifyEnforce {
		holder = NewCatalogHolder(cfg.catalogDir, trust,
			WithFreshnessEnforcement(nil, catalogClockSkew, cfg.statePath))
	} else {
		holder = NewCatalogHolder(cfg.catalogDir, trust)
	}

	// Verified auto-seed (P1.7): ONLY in enforce mode and ONLY when a URL is set.
	// Runs BEFORE the holder load so a freshly-seeded catalog is what gets
	// published (and the holder, not auto-seed, raises the rollback floor). Any
	// failure is logged host-only and leaves the on-disk catalog untouched.
	//
	// The outcome is captured and folded into refreshStatus below (as trigger
	// "startup") so an operator sees a boot-time seed failure on /api/releases
	// IMMEDIATELY — not only after the first periodic tick one full interval later
	// (M1-2 review HIGH: an air-gapped default appliance was otherwise "tried and
	// failed" vs "hasn't tried" indistinguishable for ~6h without log access).
	var startupSeedAttempted bool
	var startupSeedErr error // already REDACTED (viewer-safe) when non-nil
	if cfg.catalogURL != "" {
		if cfg.verifyMode == VerifyEnforce {
			startupSeedAttempted = true
			if err := runStartupAutoSeed(cfg, trust); err != nil {
				// Redact the URL's credentials/path/query before logging OR storing:
				// a transport error wraps net/http's *url.Error, whose string includes
				// the full request URL (path + query, and any userinfo) — a presigned
				// URL's signature would otherwise leak into startup logs AND into
				// refreshStatus.LastErr (viewer-readable via /api/releases).
				redacted := redactSeedError(err, cfg.catalogURL)
				logger.Printf("release catalog: auto-seed from %q did not update the catalog: %s",
					sanitizeLog(seedHost(cfg.catalogURL)), sanitizeLog(redacted))
				startupSeedErr = errors.New(redacted)
			}
		} else {
			logger.Printf("release catalog: auto-seed skipped — it only runs in enforce mode (verify=%s); an unsigned catalog is never auto-downloaded", cfg.verifyMode)
		}
	}

	// BEST-EFFORT startup load so a catalog already seeded/cached in cfg.catalogDir
	// is usable immediately (and survives restarts). A failure (no catalog, or one
	// that fails verification / freshness / rollback) is the normal no-catalog
	// state: reads degrade to {available:false}. The specific expired-refusal is
	// remembered: booting AFTER the catalog lapsed leaves the holder empty, so the
	// runtime freshness watchdog has nothing to evaluate — the boot-after-lapse
	// stale alert below is the only signal for that terminal case (impl review
	// MED-1).
	startupReloadExpired := false
	if err := holder.Reload(); err != nil {
		startupReloadExpired = errors.Is(err, errCatalogExpired)
		logger.Printf("release management: no catalog loaded from %q (%v); reads report available:false until a trusted one is present",
			sanitizeLog(cfg.catalogDir), err)
	}

	svc, err := NewDispatchService(holder, DispatchConfig{ProxyRepo: cfg.proxyRepo})
	if err != nil {
		logger.Printf("release management disabled: dispatch service (proxy_repo=%q): %v",
			sanitizeLog(cfg.proxyRepo), err)
		return
	}

	resolve, note := releaseAgentResolver(cfg.maintURL)
	rm := newReleaseManager(svc, resolve)
	rm.verifyMode = cfg.verifyMode
	rm.trustSchemes = trustSchemes(cfg)
	rm.sigstoreWarn = cfg.sigstoreWarn
	rm.catalogURLSource = cfg.catalogURLSource
	if cfg.catalogURL != "" {
		// Host only (never the full override URL — it may carry presigned creds).
		rm.catalogOrigin = seedHost(cfg.catalogURL)
	}
	// Observability accessor (M1-3): the stale watchdog + expiry gauge read the
	// RAW published catalog so an expired one stays visible to detection after
	// GetCatalog starts hiding it from serving/dispatch.
	rm.observeCatalog = holder.PublishedRaw
	// Surface the boot-time seed outcome right away (M1-2 review HIGH). Folded via
	// the SAME shared status the loop/manual refresh use, tagged "startup".
	if startupSeedAttempted {
		rm.recordRefreshOutcome("startup", startupSeedErr)
	}
	// Runtime catalog refresh (admin POST /api/releases/catalog-refresh): re-run
	// the verified auto-seed (only when a URL is configured AND in enforce mode)
	// then reload from disk — the SAME sequence as startup, so a release published
	// to the catalog origin after boot appears without a restart. Captures
	// cfg+trust+holder; verification is never relaxed, and an auto-seed failure
	// leaves the on-disk catalog untouched (fail-closed).
	//
	// refreshMu serializes the FULL stage+swap+reload sequence: two concurrent
	// admin refreshes must not stage different catalog versions and swap/reload
	// out of order, which could leave the holder on N+1 while disk holds N (the
	// next restart's rollback gate would then refuse N and lose the catalog).
	//
	// Auto-seed errors are redacted before they leave this closure: a transport
	// failure wraps net/http's *url.Error whose string includes the full request
	// URL, so a presigned/credentialed CULVERT_RELEASE_CATALOG_URL would otherwise
	// leak into the API response and audit log (startup redacts the same way).
	var refreshMu sync.Mutex
	// Long-lived provider (M1-2 / RT-M2), constructed LAZILY with retry: the SSRF
	// preflight resolves DNS, and a transient boot-time resolution failure must not
	// disable refresh until restart (Codex review) — each refresh retries
	// construction until it succeeds, then the ONE provider is cached so
	// conditional-request state (ETag/Last-Modified) survives across refreshes.
	// Serialization: the boot probe below runs before any goroutine exists; every
	// later call happens under refreshMu.
	wantSeed := cfg.catalogURL != "" && cfg.verifyMode == VerifyEnforce
	var seedProv *HTTPCatalogProvider
	getSeedProv := func() (*HTTPCatalogProvider, error) {
		if seedProv != nil {
			return seedProv, nil
		}
		p, err := newCatalogSeedProvider(cfg, trust)
		if err != nil {
			return nil, err
		}
		seedProv = p
		return p, nil
	}
	if wantSeed {
		if _, err := getSeedProv(); err != nil {
			logger.Printf("release catalog: refresh provider unavailable (will retry on refresh): %s",
				sanitizeLog(redactSeedError(err, cfg.catalogURL)))
		}
	}
	rm.refresh = func(ctx context.Context) error {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		var prov *HTTPCatalogProvider
		if wantSeed {
			// A configured origin that cannot be reached is a SURFACED failure
			// (counted in refreshStatus), never a silent reload-only degrade.
			var provErr error
			if prov, provErr = getSeedProv(); provErr != nil {
				return errors.New(redactSeedError(provErr, cfg.catalogURL))
			}
			if err := runAutoSeed(ctx, prov, cfg, trust); err != nil {
				// A rejected seed must never leave its ETag armed: the next tick
				// has to re-download, not 304 into a false success (impl review HIGH).
				prov.InvalidateValidators()
				return errors.New(redactSeedError(err, cfg.catalogURL))
			}
		}
		if err := holder.Reload(); err != nil {
			if prov != nil {
				// Post-304 (or post-swap) on-disk failure: drop validators so the
				// next tick fully re-downloads and self-heals a corrupted dir.
				prov.InvalidateValidators()
			}
			// Reload errors carry local data-dir paths; refreshStatus.LastErr is
			// viewer-readable via /api/releases, so log the detail and surface a
			// fixed message (impl review LOW).
			logger.Printf("release catalog: on-disk reload failed: %v", err)
			return errors.New("release catalog: on-disk catalog reload failed (see server log)")
		}
		if prov != nil {
			prov.CommitValidators()
		}
		return nil
	}
	setReleaseManager(rm)
	// M1-3 freshness watchdog: evaluate the installed catalog's expiry ONCE at
	// boot so an already-stale appliance alerts immediately instead of one full
	// refresh interval later (restart-refire caveat documented in
	// release_alerts.go; the deferStartupAlert seam is ordering-robust —
	// currently a passthrough since webhooks load before this wiring runs).
	rm.evaluateCatalogFreshness()
	// Boot-after-lapse (impl review MED-1): the startup Reload REFUSED an
	// expired on-disk catalog, so the holder is empty and the runtime watchdog
	// above has nothing to see — fire the stale alert here (latched: the state
	// is by definition already past the crossing) so the terminal case the
	// 180-day watchdog exists for is never silent.
	if startupReloadExpired {
		rm.statusMu.Lock()
		already := rm.staleLatched
		rm.staleLatched = true
		rm.statusMu.Unlock()
		if !already {
			releaseAlertFire("release_catalog_stale", AlertPayload{
				Event:  "release_catalog_stale",
				Host:   rm.alertHost(),
				Detail: "on-disk release catalog is already EXPIRED (refused at load; reads report available:false) — re-sign pipeline may have been failing while this appliance was down",
				Source: "release",
			})
		}
	}
	// Periodic production refresh + freshness-watchdog driver (M1-2/M1-3):
	// started HERE — after the manager, its refresh seam, and the alert
	// webhooks exist (RT-M1) — on the app lifecycle context.
	startReleaseDetectionLoop(cfg, wantSeed, rm)
	logger.Printf("release management enabled: proxy_repo=%q verify=%s schemes=%s local_agent=%s",
		sanitizeLog(cfg.proxyRepo), cfg.verifyMode, rm.trustSchemes, note)
}

// startReleaseDetectionLoop starts exactly ONE runtime driver for the M1-3
// freshness watchdog:
//
//   - Catalog origin configured in enforce mode ⇒ the M1-2 periodic refresh
//     loop (RT-L2), which runs evaluateCatalogFreshness on every tick via
//     runRefresh. rm.refreshInterval is set ONLY on this path, so
//     /api/releases never advertises a fetch cadence that does not exist.
//   - Otherwise (outbound fetch disabled, or break-glass permissive/disabled
//     verify mode) ⇒ the CHAOS-23 standalone stale watchdog at the same
//     resolved cadence — detection-only, nothing fetched or reloaded. Without
//     it, a disabled-fetch appliance crossing the 30-day stale threshold
//     after boot stayed silent until the next restart or manual refresh.
//
// A non-positive interval starts nothing (bare test-constructed configs; the
// production resolver never yields one).
func startReleaseDetectionLoop(cfg releaseStartupConfig, wantSeed bool, rm *releaseManager) {
	if cfg.refreshInterval <= 0 {
		return
	}
	if wantSeed {
		rm.refreshInterval = cfg.refreshInterval
		go runCatalogRefreshLoop(resolveLifecycleCtx(), cfg.refreshInterval, currentReleaseManager)
		return
	}
	go runCatalogStaleWatchdogLoop(resolveLifecycleCtx(), cfg.refreshInterval, currentReleaseManager)
	logger.Printf("release catalog: standalone freshness watchdog started (no refresh loop: catalog_url_source=%s verify=%s); stale detection stays live at %s cadence",
		cfg.catalogURLSource, cfg.verifyMode, cfg.refreshInterval)
}

// trustSchemes returns a compact log-safe description of the active trust schemes.
func trustSchemes(cfg releaseStartupConfig) string {
	schemes := make([]string, 0, 2)
	if len(cfg.trustKeys) > 0 {
		schemes = append(schemes, catalogSigAlg)
	}
	if cfg.sigstoreActive {
		schemes = append(schemes, sigstoreSigAlg)
	}
	if len(schemes) == 0 {
		return "none"
	}
	return strings.Join(schemes, "+")
}

// newCatalogSeedProvider builds the LONG-LIVED HTTP provider for cfg.catalogURL:
// inline SSRF guard (url.Parse + scheme + isPrivateHost) BEFORE any outbound
// request — defense-in-depth on top of the provider's dial-time guard — staged
// onto the data-dir filesystem (so the final rename is atomic). One provider is
// constructed per process (M1-2 / RT-M2) so its ETag/Last-Modified state persists
// across refreshes and an unchanged origin is a genuine 304 no-op instead of a
// full re-download + catalog-dir rewrite every tick.
func newCatalogSeedProvider(cfg releaseStartupConfig, trust TrustStore) (*HTTPCatalogProvider, error) {
	u, err := url.Parse(cfg.catalogURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envReleaseCatalogURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("%s scheme %q must be http or https", envReleaseCatalogURL, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s has no host", envReleaseCatalogURL)
	}
	if err := isPrivateHost(u.Host); err != nil {
		return nil, fmt.Errorf("%s host rejected (SSRF guard): %w", envReleaseCatalogURL, err)
	}
	prov, err := NewHTTPCatalogProvider(cfg.catalogURL, trust)
	if err != nil {
		return nil, err
	}
	prov.SetStageBase(filepath.Dir(cfg.catalogDir))
	return prov, nil
}

// runAutoSeed performs one verified auto-seed via the long-lived provider under a
// bounded timeout derived from the CALLER's context (M1-2 / RT-M3: shutdown or a
// cancelled admin request aborts an in-flight fetch). Non-fatal: callers log.
func runAutoSeed(ctx context.Context, prov *HTTPCatalogProvider, cfg releaseStartupConfig, trust TrustStore) error {
	ctx, cancel := context.WithTimeout(ctx, httpCatalogDefaultTimeout)
	defer cancel()
	return autoSeedCatalog(ctx, prov, autoSeedConfig{
		catalogDir: cfg.catalogDir,
		statePath:  cfg.statePath,
		trust:      trust,
		skew:       catalogClockSkew,
	})
}

// runStartupAutoSeed keeps the startup call shape: build the guard-checked
// provider and run one seed. (Startup constructs its own provider; the long-lived
// one used by refresh is created in loadReleaseManagement.)
func runStartupAutoSeed(cfg releaseStartupConfig, trust TrustStore) error {
	prov, err := newCatalogSeedProvider(cfg, trust)
	if err != nil {
		return err
	}
	return runAutoSeed(context.Background(), prov, cfg, trust)
}

// seedHost returns just the host of a seed URL for log lines, so userinfo/query
// never reach the logs. Falls back to a placeholder on a malformed URL.
func seedHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return "configured-url"
}

// redactSeedError returns err's message with the seed URL's sensitive components
// (userinfo, PATH, and raw query — any of which may carry a presigned/tokenized
// secret on an operator override origin) stripped, since a transport error wraps
// net/http's *url.Error whose string embeds the full request URL. The host is
// preserved (already logged separately, not secret). The result is stored in
// refreshStatus.LastErr (viewer-readable via /api/releases) and passed through
// sanitizeLog at the call site.
func redactSeedError(err error, rawURL string) string {
	msg := err.Error()
	// A transport error wraps *url.Error, whose embedded request URL carries the
	// full path (+ query/userinfo). Replace that whole embedded URL token with the
	// host only — the surest way to strip a secret path segment (M1-2 review MED:
	// tokenized mirrors embed secrets in the path, which the component strips below
	// would miss if the error path differs from cfg.catalogURL's path).
	var ue *url.Error
	if errors.As(err, &ue) && ue.URL != "" {
		msg = strings.ReplaceAll(msg, ue.URL, seedHost(rawURL))
	}
	u, perr := url.Parse(rawURL)
	if perr != nil {
		return msg
	}
	if u.User != nil {
		// Strip "user:password" (and the bare username) wherever they appear.
		if s := u.User.String(); s != "" {
			msg = strings.ReplaceAll(msg, s, "REDACTED")
		}
		if name := u.User.Username(); name != "" {
			msg = strings.ReplaceAll(msg, name, "REDACTED")
		}
	}
	if u.RawQuery != "" {
		msg = strings.ReplaceAll(msg, u.RawQuery, "REDACTED")
	}
	// Defense-in-depth for non-url.Error chains that still embedded the URL: strip
	// the configured origin's path (a bare "/" is not sensitive and would over-match).
	if p := u.EscapedPath(); p != "" && p != "/" {
		msg = strings.ReplaceAll(msg, p, "/REDACTED")
	}
	return msg
}

type releaseCatalogTrustKeyJSON struct {
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
}

func parseReleaseCatalogTrustKeys(raw string) ([]TrustKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var in []releaseCatalogTrustKeyJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("%s must be JSON array: %w", envReleaseCatalogTrustKeys, err)
	}
	out := make([]TrustKey, 0, len(in))
	for _, k := range in {
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("trust key %q: public_key must be std-base64: %w", sanitizeLog(k.KeyID), err)
		}
		out = append(out, TrustKey{KeyID: k.KeyID, Alg: k.Alg, PublicKey: ed25519.PublicKey(pub)})
	}
	return out, nil
}

// releaseAgentResolver maps the single CP-local maintenance agent (key "local")
// to its endpoint. A blank/invalid endpoint yields a resolver that knows no
// agents — dispatch then returns 404, while the catalog reads still work. The
// returned note is a sanitized, log-safe description of the wired endpoint.
func releaseAgentResolver(rawURL string) (agentResolver, string) {
	ep, ok := localAgentEndpoint(rawURL)
	if !ok {
		return func(string) (AgentEndpoint, bool) { return AgentEndpoint{}, false }, "none"
	}
	return func(key string) (AgentEndpoint, bool) {
		if key == localAgentKey {
			return ep, true
		}
		return AgentEndpoint{}, false
	}, sanitizeLog(rawURL)
}

// localAgentEndpoint builds the AgentEndpoint for the CP-local maintenance agent.
// A unix-socket endpoint ("unix:///path" or a bare "/path") gets an http.Client
// whose transport dials the socket; an http(s) URL is used as-is. Anything else
// is rejected (resolver knows no agents).
func localAgentEndpoint(raw string) (AgentEndpoint, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return AgentEndpoint{}, false
	}
	if strings.HasPrefix(raw, "unix:") || strings.HasPrefix(raw, "/") {
		sock := strings.TrimPrefix(strings.TrimPrefix(raw, "unix://"), "unix:")
		if sock == "" || !strings.HasPrefix(sock, "/") {
			logger.Printf("release management: ignoring invalid maint socket %q", sanitizeLog(raw))
			return AgentEndpoint{}, false
		}
		d := &net.Dialer{Timeout: 10 * time.Second}
		client := &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return d.DialContext(ctx, "unix", sock)
				},
			},
		}
		return AgentEndpoint{Key: localAgentKey, BaseURL: "http://unix", Client: client}, true
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		logger.Printf("release management: ignoring invalid maint agent URL %q", sanitizeLog(raw))
		return AgentEndpoint{}, false
	}
	return AgentEndpoint{Key: localAgentKey, BaseURL: raw, Client: &http.Client{Timeout: 30 * time.Second}}, true
}
