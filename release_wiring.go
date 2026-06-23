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
	// envReleaseCatalogTrustKeys is a JSON array of operator trust roots:
	// [{"key_id":"prod-2026","alg":"ed25519","public_key":"<base64-raw-32-byte-key>"}]
	envReleaseCatalogTrustKeys = "CULVERT_RELEASE_CATALOG_TRUST_KEYS"
)

type releaseStartupConfig struct {
	proxyRepo    string
	catalogDir   string
	maintURL     string // CP-local maint agent endpoint (unix socket path or http[s] URL)
	trustKeys    []TrustKey
	trustKeysErr error
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
	trustKeys, trustKeysErr := parseReleaseCatalogTrustKeys(getenv(envReleaseCatalogTrustKeys))
	return releaseStartupConfig{
		proxyRepo:    proxyRepo,
		catalogDir:   filepath.Join(dataDir, "release_catalog"),
		maintURL:     maintURL,
		trustKeys:    trustKeys,
		trustKeysErr: trustKeysErr,
	}
}

// loadReleaseManagement constructs and publishes the Release Management backend.
// Best-effort and NON-FATAL: on any failure globalReleaseMgr stays nil so the
// routes report 503 rather than panicking.
func loadReleaseManagement(cfg releaseStartupConfig) {
	// Permissive trust: the holder is never reloaded here (it starts with NO
	// catalog), so the mode is inert — but permissive is the safe default for the
	// later refresh slice (unsigned OK; present signatures must verify).
	if cfg.trustKeysErr != nil {
		logger.Printf("release management disabled: catalog trust keys: %v", cfg.trustKeysErr)
		return
	}
	trust, err := NewTrustStore(cfg.trustKeys, VerifyPermissive)
	if err != nil {
		logger.Printf("release management disabled: trust store: %v", err)
		return
	}
	// Empty holder ⇒ GetCatalog() == nil until populated. Run a BEST-EFFORT
	// startup load so a catalog already seeded/cached in cfg.catalogDir is usable
	// immediately (and survives restarts) instead of reporting available:false
	// until a refresh runs — there is no production refresher yet. A failure (no
	// catalog present, or a signature we can't verify under permissive trust) is
	// the normal no-catalog state: reads degrade to {available:false}. Signed
	// catalogs need a configured trust ring (the deferred authenticity slice).
	holder := NewCatalogHolder(cfg.catalogDir, trust)
	if err := holder.Reload(); err != nil {
		logger.Printf("release management: no catalog loaded from %q (%v); reads report available:false until one is present",
			sanitizeLog(cfg.catalogDir), err)
	}

	svc, err := NewDispatchService(holder, DispatchConfig{ProxyRepo: cfg.proxyRepo})
	if err != nil {
		logger.Printf("release management disabled: dispatch service (proxy_repo=%q): %v",
			sanitizeLog(cfg.proxyRepo), err)
		return
	}

	resolve, note := releaseAgentResolver(cfg.maintURL)
	setReleaseManager(newReleaseManager(svc, resolve))
	logger.Printf("release management enabled: proxy_repo=%q local_agent=%s",
		sanitizeLog(cfg.proxyRepo), note)
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
