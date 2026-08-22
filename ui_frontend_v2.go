package main

// ui_frontend_v2.go — FE-1B embedded static serving for the NEW admin frontend
// (ADR-FE-001, docs/design/FRONTEND-MIGRATION-PLAN.md §2).
//
// Serves the committed Vite production artifact (frontend/dist, embedded) under
// the EXPERIMENTAL /app/ preview namespace plus the stable /assets/ hashed-
// asset namespace. Default-OFF: without CULVERT_EXPERIMENTAL_UI the routes
// return the same 404 an unregistered path gets. The legacy `/` frontend and
// its nonce-based CSP are untouched — the strict nonce-free CSP below is
// route-scoped to the new surface only.
//
// Failure semantics (FE-1B §4): an invalid embedded artifact must never take
// down the proxy data plane. Validation runs ONCE at initialization; failure
// degrades to status "invalid" (503 on the new-UI routes, one critical log
// line, a report-only /ready row) while everything else keeps serving.

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// The committed production output is the ONLY thing embedded — frontend/src,
// node_modules, and the generator workspace are never part of the binary.
// frontend/dist is the single canonical generated tree (ADR-FE-001 OQ-1).
//
//go:embed all:frontend/dist
var frontendV2DistFS embed.FS

const (
	frontendV2EnvVar = "CULVERT_EXPERIMENTAL_UI"

	// frontendV2CSP is the strict, nonce-free policy for the new app
	// (FRONTEND-SECURITY-CONTRACT.md §3.P2). Route-scoped: the legacy shell
	// keeps its per-request nonce policy from securityMiddleware.
	frontendV2CSP = "default-src 'self'; script-src 'self'; script-src-attr 'none'; " +
		"style-src 'self'; style-src-attr 'none'; img-src 'self' data:; " +
		"connect-src 'self'; object-src 'none'; base-uri 'none'; " +
		"form-action 'self'; frame-ancestors 'none'"

	frontendV2UnavailableBody = "new admin UI unavailable: embedded frontend artifact failed validation; see server log\n"
)

// frontendV2MIME is the explicit serving allowlist (FE-1B §9). With
// X-Content-Type-Options: nosniff active, MIME correctness is load-bearing —
// never rely on host MIME databases. Extend only for formats the build
// actually emits.
var frontendV2MIME = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".webp":  "image/webp",
	".woff2": "font/woff2",
}

type frontendV2Status string

const (
	frontendV2Disabled frontendV2Status = "disabled"
	frontendV2Ready    frontendV2Status = "ready"
	frontendV2Invalid  frontendV2Status = "invalid"
)

// frontendV2Asset is the bounded per-asset metadata cached by validation.
// Bodies stay in the embed FS — no duplicate in-memory copies.
type frontendV2Asset struct {
	contentType string
	size        int64
}

type frontendV2State struct {
	status frontendV2Status
	reason string // sanitized one-line cause when status == invalid (log only)
	shell  []byte // exact embedded index.html bytes — served verbatim, never rewritten
	assets map[string]frontendV2Asset
}

// frontendV2 is resolved once (ensureFrontendV2) and read-only afterward.
// Tests swap it via swapFrontendV2ForTest.
var frontendV2 atomic.Pointer[frontendV2State]

// readFrontendV2Enabled parses the opt-in env var once at resolution time.
// Fail-safe default-OFF: only an explicit true-ish value enables the preview
// surface (same convention as CULVERT_CLUSTER_GRPC_COMPRESSION).
func readFrontendV2Enabled(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// ensureFrontendV2 resolves the state exactly once (called from
// newAdminUIHandler before route registration; handlers only Load). The env
// var is never re-read per request.
func ensureFrontendV2(rawEnv string) *frontendV2State {
	if s := frontendV2.Load(); s != nil {
		return s
	}
	s := resolveFrontendV2(rawEnv)
	frontendV2.CompareAndSwap(nil, s)
	return frontendV2.Load()
}

func resolveFrontendV2(rawEnv string) *frontendV2State {
	if !readFrontendV2Enabled(rawEnv) {
		logger.Printf("FrontendV2: disabled (set %s=1 to enable the experimental /app preview)", frontendV2EnvVar)
		return &frontendV2State{status: frontendV2Disabled}
	}
	dist, err := fs.Sub(frontendV2DistFS, "frontend/dist")
	if err != nil {
		logger.Printf("CRITICAL: FrontendV2: invalid — embedded dist unavailable")
		return &frontendV2State{status: frontendV2Invalid, reason: "embedded dist unavailable"}
	}
	shell, assets, verr := validateFrontendV2(dist)
	if verr != nil {
		// One critical line at initialization; requests never log (FE-1B §4).
		logger.Printf("CRITICAL: FrontendV2: invalid embedded frontend artifact — new UI degraded to 503 (%s)", sanitizeLog(verr.Error()))
		return &frontendV2State{status: frontendV2Invalid, reason: verr.Error()}
	}
	logger.Printf("FrontendV2: ready — experimental /app preview enabled (%d assets, shell %d bytes)", len(assets), len(shell))
	return &frontendV2State{status: frontendV2Ready, shell: shell, assets: assets}
}

// swapFrontendV2ForTest installs a state and returns a restore func.
func swapFrontendV2ForTest(s *frontendV2State) (restore func()) {
	old := frontendV2.Swap(s)
	return func() { frontendV2.Store(old) }
}

// ─── Validation (FE-1B §3/§15 — runs once, fail-closed) ─────────────────────

// frontendV2Manifest is the subset of the Vite manifest the validator reads.
type frontendV2ManifestEntry struct {
	File    string   `json:"file"`
	CSS     []string `json:"css"`
	Assets  []string `json:"assets"`
	IsEntry bool     `json:"isEntry"`
}

func validateFrontendV2(dist fs.FS) (shell []byte, assets map[string]frontendV2Asset, err error) {
	shell, err = fs.ReadFile(dist, "index.html")
	if err != nil || len(shell) == 0 {
		return nil, nil, fmt.Errorf("index.html missing or empty")
	}
	rawManifest, err := fs.ReadFile(dist, "manifest.json")
	if err != nil {
		return nil, nil, fmt.Errorf("manifest.json missing")
	}
	var manifest map[string]frontendV2ManifestEntry
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return nil, nil, fmt.Errorf("manifest.json does not parse")
	}
	if len(manifest) == 0 {
		return nil, nil, fmt.Errorf("manifest.json has no entries")
	}

	referenced, err := frontendV2CollectRefs(manifest)
	if err != nil {
		return nil, nil, err
	}

	embedded, err := frontendV2ListDist(dist)
	if err != nil {
		return nil, nil, err
	}

	// Every manifest reference must exist in the embed; every embedded asset
	// must be referenced (an unreferenced asset means the manifest and the
	// tree disagree — ambiguous, fail closed).
	assets = make(map[string]frontendV2Asset, len(referenced))
	for ref := range referenced {
		info, ok := embedded[ref]
		if !ok {
			return nil, nil, fmt.Errorf("manifest references missing file %q", ref)
		}
		assets[ref] = info
	}
	for p := range embedded {
		if _, ok := referenced[p]; !ok {
			return nil, nil, fmt.Errorf("embedded asset %q not referenced by manifest", p)
		}
	}
	// Ambiguity: two logical assets must never collide case-insensitively.
	lower := make(map[string]string, len(assets))
	for p := range assets {
		lc := strings.ToLower(p)
		if prev, dup := lower[lc]; dup && prev != p {
			return nil, nil, fmt.Errorf("ambiguous assets differing only by case")
		}
		lower[lc] = p
	}
	return shell, assets, nil
}

// frontendV2CollectRefs gathers and path-validates every file the manifest
// references. At least one entry chunk (isEntry) must exist.
func frontendV2CollectRefs(manifest map[string]frontendV2ManifestEntry) (map[string]struct{}, error) {
	referenced := make(map[string]struct{})
	haveEntry := false
	for key, e := range manifest {
		if e.File == "" {
			return nil, fmt.Errorf("manifest entry %q has no file", sanitizeLog(key))
		}
		refs := append([]string{e.File}, e.CSS...)
		refs = append(refs, e.Assets...)
		for _, r := range refs {
			if err := frontendV2ValidateAssetPath(r); err != nil {
				return nil, fmt.Errorf("manifest entry %q: %w", sanitizeLog(key), err)
			}
			referenced[r] = struct{}{}
		}
		if e.IsEntry {
			haveEntry = true
		}
	}
	if !haveEntry {
		return nil, fmt.Errorf("manifest has no entry chunk")
	}
	return referenced, nil
}

// frontendV2ValidateAssetPath is the manifest-string trust boundary (FE-1B
// §3): normalize and reject before any lookup. Manifest strings are build
// output, but they are validated as if hostile — a compromised build must
// fail closed here, not reach the filesystem layer.
func frontendV2ValidateAssetPath(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("empty asset path")
	case strings.HasPrefix(p, "/") || strings.Contains(p, "\\"):
		return fmt.Errorf("absolute or backslash asset path")
	case strings.Contains(p, ".."):
		return fmt.Errorf("traversal in asset path")
	case strings.Contains(p, "%"):
		return fmt.Errorf("encoded characters in asset path")
	case strings.Contains(p, ":") || strings.Contains(p, "//"):
		return fmt.Errorf("scheme or origin in asset path")
	case path.Clean(p) != p:
		return fmt.Errorf("non-canonical asset path")
	case !strings.HasPrefix(p, "assets/"):
		return fmt.Errorf("asset outside assets/ namespace")
	case strings.HasSuffix(p, ".map"):
		return fmt.Errorf("sourcemap referenced")
	}
	if _, ok := frontendV2MIME[path.Ext(p)]; !ok {
		return fmt.Errorf("unsupported asset extension %q", path.Ext(p))
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '/' || r == '.' || r == '-' || r == '_') {
			return fmt.Errorf("disallowed character in asset path")
		}
	}
	return nil
}

// frontendV2ListDist inventories the embedded tree: only index.html,
// manifest.json, and allowlisted assets/* files may exist; sourcemaps are
// refused outright.
func frontendV2ListDist(dist fs.FS) (map[string]frontendV2Asset, error) {
	embedded := map[string]frontendV2Asset{}
	err := fs.WalkDir(dist, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && p != "assets" {
				return fmt.Errorf("unexpected directory %q in dist", sanitizeLog(p))
			}
			return nil
		}
		if p == "index.html" || p == "manifest.json" {
			return nil
		}
		if strings.HasSuffix(p, ".map") {
			return fmt.Errorf("sourcemap %q embedded", sanitizeLog(p))
		}
		if verr := frontendV2ValidateAssetPath(p); verr != nil {
			return fmt.Errorf("embedded file %q: %w", sanitizeLog(p), verr)
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		embedded[p] = frontendV2Asset{contentType: frontendV2MIME[path.Ext(p)], size: info.Size()}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(embedded) == 0 {
		return nil, fmt.Errorf("no assets in dist")
	}
	return embedded, nil
}

// ─── Serving (FE-1B §7/§9/§12/§13) ──────────────────────────────────────────

// registerFrontendV2Routes registers the experimental namespace. Registration
// is UNCONDITIONAL so the C1/D0 route walls stay deterministic; the default-
// off gate lives in the handlers (state == disabled ⇒ the same 404 an
// unregistered path yields via the legacy catch-all's FileServer).
func registerFrontendV2Routes(mux *http.ServeMux) {
	mux.HandleFunc("/app", handleFrontendV2Shell)
	mux.HandleFunc("/app/", handleFrontendV2Shell)
	mux.HandleFunc("/assets/", handleFrontendV2Asset)
}

func frontendV2Current() *frontendV2State {
	if s := frontendV2.Load(); s != nil {
		return s
	}
	// Handlers can only run after newAdminUIHandler resolved the state; this
	// branch exists for direct handler-level tests.
	return &frontendV2State{status: frontendV2Disabled}
}

func frontendV2Unavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", frontendV2CSP)
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(frontendV2UnavailableBody))
}

// handleFrontendV2Shell serves the SPA shell for /app and every GET/HEAD deep
// link under /app/. The bytes are the embedded index.html verbatim — no
// substitution, no nonce, no templating (FE-1B §12).
func handleFrontendV2Shell(w http.ResponseWriter, r *http.Request) {
	st := frontendV2Current()
	if st.status == frontendV2Disabled {
		http.NotFound(w, r) // indistinguishable from an unregistered path
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// Mutations never receive the shell (FE-1B §13).
		http.NotFound(w, r)
		return
	}
	if st.status == frontendV2Invalid {
		frontendV2Unavailable(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", frontendV2CSP)
	w.Header().Set("Content-Length", strconv.Itoa(len(st.shell)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(st.shell)
}

// handleFrontendV2Asset serves exactly the validated hashed assets under
// /assets/. Lookup is exact-match against the validated set — no cleaning,
// no fallback, no directory listing; anything else is a 404 (never the
// shell). manifest.json and sourcemaps are structurally unreachable: the
// namespace serves only paths admitted by validation.
func handleFrontendV2Asset(w http.ResponseWriter, r *http.Request) {
	st := frontendV2Current()
	if st.status == frontendV2Disabled {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	if st.status == frontendV2Invalid {
		frontendV2Unavailable(w)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/")
	asset, ok := st.assets[key]
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := frontendV2DistFS.Open(path.Join("frontend/dist", key))
	if err != nil {
		// Validated at startup; a miss here is a programming error, not I/O.
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()
	rs, ok := f.(interface {
		fs.File
		Seek(offset int64, whence int) (int64, error)
	})
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", asset.contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Content-Security-Policy", frontendV2CSP)
	// Zero modtime ⇒ ServeContent omits Last-Modified and skips conditional
	// handling; the immutable cache header is the caching contract. HEAD and
	// Range are handled by ServeContent; Content-Type is ours (allowlisted).
	http.ServeContent(w, r, "", time.Time{}, rs)
}

// ─── Observability (FE-1B §20) ──────────────────────────────────────────────

// appendFrontendV2ReadinessCheck adds the report-only frontend_v2 row to
// /ready. Absent entirely while the experimental UI is disabled (mirrors the
// cluster_ca absent-when-unconfigured convention); FIXED detail because the
// endpoint is unauthenticated (same rule as the ca/clamav rows). Never gates
// the default verdict — a broken preview UI must not eject a serving proxy
// from rotation.
func appendFrontendV2ReadinessCheck(checks map[string]*readinessCheck) {
	switch frontendV2Current().status {
	case frontendV2Disabled:
		return
	case frontendV2Ready:
		checks["frontend_v2"] = &readinessCheck{Status: "ok"}
	case frontendV2Invalid:
		checks["frontend_v2"] = &readinessCheck{
			Status: "fail",
			Detail: "embedded frontend artifact failed validation; new UI serving 503 — see server log",
		}
	}
}

// frontendV2AssetInventory returns the sorted validated asset paths (tests).
func frontendV2AssetInventory(st *frontendV2State) []string {
	out := make([]string, 0, len(st.assets))
	for p := range st.assets {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
