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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
)

// bakedReleaseTrustKeysJSON is the BAKED-IN public trust root set, in the same
// JSON shape as CULVERT_RELEASE_CATALOG_TRUST_KEYS. It is empty in the open-source
// tree and is populated at official-build time via the linker
// (`-ldflags "-X main.bakedReleaseTrustKeysJSON=[...]"`) so a shipped Control
// Plane trusts the official release-signing key out of the box and enters enforce
// mode automatically. It holds PUBLIC keys only — never private key material.
var bakedReleaseTrustKeysJSON = ""

type releaseStartupConfig struct {
	proxyRepo      string
	catalogDir     string
	statePath      string     // persisted rollback version floor (sibling of catalogDir)
	maintURL       string     // CP-local maint agent endpoint (unix socket path or http[s] URL)
	catalogURL     string     // optional http(s) origin to auto-seed the signed catalog (P1.7); "" ⇒ no fetch
	trustKeys      []TrustKey // baked roots ∪ operator-configured roots
	trustKeysErr   error
	verifyMode     VerifyMode
	verifyModeWarn string // loud break-glass message to log once at startup ("" ⇒ none)
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
	mode, warn := resolveCatalogVerifyMode(getenv(envReleaseCatalogVerify), len(keys))
	return releaseStartupConfig{
		proxyRepo:      proxyRepo,
		catalogDir:     catalogDir,
		statePath:      filepath.Join(dataDir, "release_catalog_state.json"),
		maintURL:       maintURL,
		catalogURL:     strings.TrimSpace(getenv(envReleaseCatalogURL)),
		trustKeys:      keys,
		trustKeysErr:   keysErr,
		verifyMode:     mode,
		verifyModeWarn: warn,
	}
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
	if cfg.verifyModeWarn != "" {
		logger.Printf("%s", cfg.verifyModeWarn)
	}
	// Central Phase 1 invariant: production wiring enters VerifyEnforce whenever a
	// trust root (baked or configured) is present. With NO roots and no break-glass
	// override, the mode is enforce with an EMPTY ring → NewTrustStore fails closed
	// → Release Management is DISABLED. An unsigned catalog is never auto-trusted;
	// the only way to load one is the explicit CULVERT_RELEASE_CATALOG_VERIFY
	// break-glass.
	trust, err := NewTrustStore(cfg.trustKeys, cfg.verifyMode)
	if err != nil {
		logger.Printf("release management disabled: %v (configure CULVERT_RELEASE_CATALOG_TRUST_KEYS, or set CULVERT_RELEASE_CATALOG_VERIFY=permissive for break-glass)", err)
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
				logger.Printf("release catalog: auto-seed from %q did not update the catalog: %v",
					sanitizeLog(seedHost(cfg.catalogURL)), err)
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
	setReleaseManager(rm)
	logger.Printf("release management enabled: proxy_repo=%q verify=%s local_agent=%s",
		sanitizeLog(cfg.proxyRepo), cfg.verifyMode, note)
}

// runStartupAutoSeed performs one verified auto-seed from cfg.catalogURL. It
// applies an inline SSRF guard (url.Parse + scheme + isPrivateHost) BEFORE any
// outbound request — defense-in-depth on top of the provider's dial-time guard —
// stages onto the data-dir filesystem (so the final rename is atomic), and runs
// the auto-seed under a bounded timeout. Non-fatal: the caller logs the error.
func runStartupAutoSeed(cfg releaseStartupConfig, trust TrustStore) error {
	u, err := url.Parse(cfg.catalogURL)
	if err != nil {
		return fmt.Errorf("%s: %w", envReleaseCatalogURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("%s scheme %q must be http or https", envReleaseCatalogURL, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s has no host", envReleaseCatalogURL)
	}
	if err := isPrivateHost(u.Host); err != nil {
		return fmt.Errorf("%s host rejected (SSRF guard): %w", envReleaseCatalogURL, err)
	}

	prov, err := NewHTTPCatalogProvider(cfg.catalogURL, trust)
	if err != nil {
		return err
	}
	// Stage onto the SAME filesystem as the destination so the swap rename is
	// atomic (release_catalog lives directly under the data dir).
	prov.SetStageBase(filepath.Dir(cfg.catalogDir))

	ctx, cancel := context.WithTimeout(context.Background(), httpCatalogDefaultTimeout)
	defer cancel()
	return autoSeedCatalog(ctx, prov, autoSeedConfig{
		catalogDir: cfg.catalogDir,
		statePath:  cfg.statePath,
		trust:      trust,
		skew:       catalogClockSkew,
	})
}

// seedHost returns just the host of a seed URL for log lines, so userinfo/query
// never reach the logs. Falls back to a placeholder on a malformed URL.
func seedHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return "configured-url"
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
