package frontendbundle

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// hashedName enforces the content-hash filename contract at
// RUNTIME, independently of the FE-1A bundle gate: every admitted asset is
// served with `Cache-Control: … immutable`, so an un-hashed name would be
// cached forever across upgrades. Rule: `<name>-<hash≥8 of [A-Za-z0-9_-]>`
// before the allowlisted extension — the current Vite/Rolldown base64url
// hash shape, extension-agnostic (works for future svg/png/webp/woff2).
// KEPT IN LOCKSTEP with the FE-1A bundle scan's identical pattern in
// frontend/scripts/check-dist.mjs (`-[A-Za-z0-9_-]{8,}`); the cross-contract
// test TestFE1B_HashRuleMatchesBundleScan pins the two representations
// together.
var hashedName = regexp.MustCompile(`-[A-Za-z0-9_-]{8,}$`)

// validateAssetPath is the manifest-string trust boundary (FE-1B
// §3): normalize and reject before any lookup. Manifest strings are build
// output, but they are validated as if hostile — a compromised build must
// fail closed here, not reach the filesystem layer.
func validateAssetPath(p string) error {
	if err := assetPathShape(p); err != nil {
		return err
	}
	return assetNameContract(p)
}

// assetPathShape rejects structurally hostile paths: absolute,
// traversal, encoded, scheme/origin, non-canonical, out-of-namespace, or
// sourcemap references.
func assetPathShape(p string) error {
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
	return nil
}

// assetNameContract enforces the serving-name contract: an
// allowlisted extension, the content-hash suffix required for immutable
// caching (see hashedName), and a conservative character set.
func assetNameContract(p string) error {
	if _, ok := contentTypeFor(path.Ext(p)); !ok {
		return fmt.Errorf("unsupported asset extension %q", path.Ext(p))
	}
	// Immutable-cache naming contract: the served Cache-Control is
	// `max-age=31536000, immutable`, so only content-hashed names may be
	// admitted (see hashedName).
	if base := strings.TrimSuffix(path.Base(p), path.Ext(p)); !hashedName.MatchString(base) {
		return fmt.Errorf("asset %q lacks the content-hash suffix required for immutable caching", obs.Sanitize(p))
	}
	for _, r := range p {
		if !allowedPathRune(r) {
			return fmt.Errorf("disallowed character in asset path")
		}
	}
	return nil
}

// allowedPathRune is the conservative asset-path alphabet.
func allowedPathRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
		r == '/' || r == '.' || r == '-' || r == '_'
}

// contentTypeFor is the explicit serving allowlist (FE-1B §9): the Content-Type
// for each admitted file extension, and ok=false for every other extension.
// With X-Content-Type-Options: nosniff active, MIME correctness is
// load-bearing, so the caller never relies on a host MIME database. Extend
// only for formats the build actually emits.
//
// A switch rather than a map so the package holds no mutable table.
func contentTypeFor(ext string) (contentType string, ok bool) {
	switch ext {
	case ".js":
		return "text/javascript; charset=utf-8", true
	case ".css":
		return "text/css; charset=utf-8", true
	case ".svg":
		return "image/svg+xml", true
	case ".png":
		return "image/png", true
	case ".webp":
		return "image/webp", true
	case ".woff2":
		return "font/woff2", true
	default:
		return "", false
	}
}
