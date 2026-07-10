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
	// envReleaseCatalogURL is the OPTIONAL http(s) origin to auto-seed the signed
	// catalog from at startup (P1.7). Auto-seed runs ONLY in enforce mode; the
	// installer never bakes a default. Unset ⇒ no fetch (behavior unchanged).
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
	proxyRepo       string
	catalogDir      string
	statePath       string     // persisted rollback version floor (sibling of catalogDir)
	maintURL        string     // CP-local maint agent endpoint (unix socket path or http[s] URL)
	catalogURL      string     // optional http(s) origin to auto-seed the signed catalog (P1.7); "" ⇒ no fetch
	trustKeys       []TrustKey // baked roots ∪ operator-configured roots
	trustKeysErr    error
	sigstore        *sigstoreVerifier // optional keyless (Sigstore-identity) verifier; nil ⇒ scheme inactive
	sigstoreActive  bool              // true ⇒ a Sigstore trusted root is present
	sigstoreWarn    string            // loud one-line note (identity set without a root) ("" ⇒ none)
	sigstoreErr     error             // fatal Sigstore config error ⇒ Release Management disabled
	verifyMode      VerifyMode
	verifyModeWarn  string        // loud break-glass message to log once at startup ("" ⇒ none)
	refreshInterval time.Duration // periodic catalog refresh cadence (M1-2); 0 ⇒ loop disabled
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
	return releaseStartupConfig{
		proxyRepo:       proxyRepo,
		catalogDir:      catalogDir,
		statePath:       filepath.Join(dataDir, "release_catalog_state.json"),
		maintURL:        maintURL,
		catalogURL:      strings.TrimSpace(getenv(envReleaseCatalogURL)),
		trustKeys:       keys,
		trustKeysErr:    keysErr,
		sigstore:        sig.verifier,
		sigstoreActive:  sig.active,
		sigstoreWarn:    sig.warn,
		sigstoreErr:     sig.err,
		verifyMode:      mode,
		verifyModeWarn:  warn,
		refreshInterval: interval,
	}
}

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
	if cfg.catalogURL != "" {
		if cfg.verifyMode == VerifyEnforce {
			if err := runStartupAutoSeed(cfg, trust); err != nil {
				// Redact the URL's credentials/query before logging: a transport
				// error wraps net/http's *url.Error, whose string includes the full
				// request URL (path + query, and any userinfo) — a presigned URL's
				// signature would otherwise leak into startup logs.
				logger.Printf("release catalog: auto-seed from %q did not update the catalog: %s",
					sanitizeLog(seedHost(cfg.catalogURL)), sanitizeLog(redactSeedError(err, cfg.catalogURL)))
			}
		} else {
			logger.Printf("release catalog: auto-seed skipped — it only runs in enforce mode (verify=%s); an unsigned catalog is never auto-downloaded", cfg.verifyMode)
		}
	}

	// BEST-EFFORT startup load so a catalog already seeded/cached in cfg.catalogDir
	// is usable immediately (and survives restarts). A failure (no catalog, or one
	// that fails verification / freshness / rollback) is the normal no-catalog
	// state: reads degrade to {available:false}.
	if err := holder.Reload(); err != nil {
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
	// Long-lived provider (M1-2 / RT-M2): constructed ONCE so conditional-request
	// state (ETag/Last-Modified) survives across refreshes. A guard/URL error here
	// leaves seedProv nil; refresh then degrades to a reload-only (and the startup
	// seed above already logged the same failure).
	var seedProv *HTTPCatalogProvider
	if cfg.catalogURL != "" && cfg.verifyMode == VerifyEnforce {
		var provErr error
		if seedProv, provErr = newCatalogSeedProvider(cfg, trust); provErr != nil {
			logger.Printf("release catalog: refresh provider unavailable: %s", sanitizeLog(redactSeedError(provErr, cfg.catalogURL)))
		}
	}
	rm.refresh = func(ctx context.Context) error {
		refreshMu.Lock()
		defer refreshMu.Unlock()
		if seedProv != nil {
			if err := runAutoSeed(ctx, seedProv, cfg, trust); err != nil {
				return errors.New(redactSeedError(err, cfg.catalogURL))
			}
		}
		return holder.Reload()
	}
	rm.refreshInterval = cfg.refreshInterval
	setReleaseManager(rm)
	// Periodic production refresh (M1-2): started HERE — after the manager, its
	// refresh seam, and the alert webhooks exist (RT-M1) — on the app lifecycle
	// context, and only when a catalog origin is configured in enforce mode
	// (RT-L2; in permissive mode a tick would be a pointless disk re-read).
	if seedProv != nil && cfg.refreshInterval > 0 {
		go runCatalogRefreshLoop(appLifecycleCtx, cfg.refreshInterval, currentReleaseManager)
	}
	logger.Printf("release management enabled: proxy_repo=%q verify=%s schemes=%s local_agent=%s",
		sanitizeLog(cfg.proxyRepo), cfg.verifyMode, rm.trustSchemes, note)
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
// (userinfo and raw query — e.g. a presigned-URL signature) stripped, since a
// transport error wraps net/http's *url.Error whose string embeds the full
// request URL. The host is preserved (it is already logged separately and is not
// secret). The result is still passed through sanitizeLog at the call site.
func redactSeedError(err error, rawURL string) string {
	msg := err.Error()
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
