package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// openAPIFiles embeds the generated OpenAPI contract artifacts so the running
// appliance can serve its own admin-API documentation offline — no network,
// no Node, no external Swagger CDN. These files are produced by
// `make api-bundle` (cmd/apibundle) from api/openapi/openapi.yaml; the YAML is
// the source of truth and the JSON/HTML are generated, deterministic mirrors.
//
// Only the three served artifacts are embedded (not the whole directory) so
// the binary does not carry index.public.html and so the embed pattern never
// trips over .dockerignore exclusions (*.md etc.) in the source-free deploy
// bundle build.
//
//go:embed api/openapi/index.html api/openapi/openapi.json api/openapi/openapi.yaml
var openAPIFiles embed.FS

// openAPIURLPrefix is the runtime mount point for the OpenAPI docs + spec.
// A trailing-slash prefix registration means http.ServeMux redirects the
// bare /api/openapi form here automatically.
const openAPIURLPrefix = "/api/openapi/"

// openAPIFileServer is the file handler rooted at the embedded api/openapi
// directory, built once at package init. Serving index.html at the mount
// root and the raw openapi.json / openapi.yaml alongside it.
var openAPIFileServer = func() http.Handler {
	sub, err := fs.Sub(openAPIFiles, "api/openapi")
	if err != nil {
		// Should never happen — the embed pattern above guarantees the dir.
		// Fall back to a 500 so the failure is visible rather than a panic.
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "openapi assets unavailable", http.StatusInternalServerError)
		})
	}
	return http.StripPrefix(openAPIURLPrefix, http.FileServer(http.FS(sub)))
}()

// apiOpenAPI serves the self-contained OpenAPI documentation page (index.html)
// at /api/openapi/ and the raw spec at /api/openapi/openapi.json and
// /api/openapi/openapi.yaml. It is read-only and viewer-gated: the documented
// surface describes the full admin API, so it is not exposed unauthenticated.
func apiOpenAPI(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	// The embedded FS has zero mod-times, so http.FileServer emits no
	// validators and a browser would re-download the ~500 KB spec on every
	// load. The artifacts only change with a binary upgrade, so a bounded
	// max-age is safe.
	if strings.HasSuffix(r.URL.Path, ".json") || strings.HasSuffix(r.URL.Path, ".yaml") {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}
	openAPIFileServer.ServeHTTP(w, r)
}

// registerOpenAPIRoutes wires the runtime OpenAPI docs + spec endpoint.
// The path is a string literal (not the openAPIURLPrefix constant) because
// the C1 reverse-parity scanner matches the registration on a literal arg.
func registerOpenAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/openapi/", apiOpenAPI)
}
