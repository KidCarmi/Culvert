// Package frontendbundle validates a built admin-frontend tree before any byte
// of it is served (FE-1B §3/§15, ADR-FE-001; boundary in ADR-0050).
//
// Validate reads a Vite production output through an fs.FS (index.html,
// manifest.json and assets/) and either returns the shell bytes and the exact
// set of assets that may be served, or an error. It fails closed: manifest
// strings are build output but are treated as hostile, so a compromised or
// inconsistent build is rejected here instead of reaching the serving layer.
// The checks are:
//
//   - manifest.json parses, has no duplicate object key at any depth
//     (encoding/json is last-value-wins) and has an entry chunk;
//   - every referenced path is canonical, relative, under assets/, has an
//     allowlisted extension and carries the content-hash suffix that the
//     immutable Cache-Control header depends on;
//   - every imports / dynamicImports value is an existing manifest key;
//   - the manifest's reference set and the tree agree exactly, with no
//     sourcemap, stray file, unexpected directory or case-only collision;
//   - the shell references exactly the manifest entry's script and stylesheet
//     set, and only validated /assets/ paths.
//
// Package main (ui_frontend_v2.go) owns the embedded artifact, the
// CULVERT_EXPERIMENTAL_UI gate, the resolved-once state, the routes, the
// response headers and the /ready row. This package owns only the decision
// "is this tree safe to serve, and which files". It holds no mutable state,
// starts no goroutines, does no logging and performs no I/O beyond reading the
// fs.FS it is given. Its only non-stdlib import is internal/obs, for the
// CWE-117 sanitizer applied to manifest strings quoted in error text.
package frontendbundle
