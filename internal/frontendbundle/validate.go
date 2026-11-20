package frontendbundle

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// Asset is the bounded per-asset metadata Validate returns for each admitted
// file. Bodies stay in the caller's file system; no copy is held here.
type Asset struct {
	ContentType string
	Size        int64
}

// ManifestEntry is the subset of the Vite ManifestChunk the
// validator reads. Imports/DynamicImports carry MANIFEST KEYS (not file
// paths) referring to other chunks; both are validated for existence.
type ManifestEntry struct {
	File           string   `json:"file"`
	CSS            []string `json:"css"`
	Assets         []string `json:"assets"`
	IsEntry        bool     `json:"isEntry"`
	IsDynamicEntry bool     `json:"isDynamicEntry"`
	Imports        []string `json:"imports"`
	DynamicImports []string `json:"dynamicImports"`
}

// Validate checks a built frontend tree (index.html, manifest.json, assets/)
// and returns the exact shell bytes plus the set of assets that may be served.
// It fails closed: any missing, ambiguous, unreferenced, mis-named or
// out-of-namespace file is an error, and the returned set is empty. The error
// text is safe to log (untrusted manifest strings are sanitized and quoted).
func Validate(dist fs.FS) (shell []byte, assets map[string]Asset, err error) {
	shell, err = fs.ReadFile(dist, "index.html")
	if err != nil || len(shell) == 0 {
		return nil, nil, fmt.Errorf("index.html missing or empty")
	}
	manifest, err := readManifest(dist)
	if err != nil {
		return nil, nil, err
	}

	referenced, err := collectRefs(manifest)
	if err != nil {
		return nil, nil, err
	}
	if err := validateImportGraph(manifest); err != nil {
		return nil, nil, err
	}

	embedded, err := listDist(dist)
	if err != nil {
		return nil, nil, err
	}
	assets, err = crossCheckAssets(referenced, embedded)
	if err != nil {
		return nil, nil, err
	}
	// Bind the static shell to the validated authoritative entry: a shell
	// that points at anything else must never be classified Ready (a 200
	// index.html whose JS 404s is a broken blank UI, not a working one).
	if err := validateShellBinding(shell, manifest, assets); err != nil {
		return nil, nil, err
	}
	return shell, assets, nil
}

// readManifest reads + decodes manifest.json with the duplicate-key
// pre-scan BEFORE the generic decode: encoding/json is last-value-wins on
// duplicate object keys, which would let an ambiguous manifest smuggle a
// second definition past validation.
func readManifest(dist fs.FS) (map[string]ManifestEntry, error) {
	rawManifest, err := fs.ReadFile(dist, "manifest.json")
	if err != nil {
		return nil, fmt.Errorf("manifest.json missing")
	}
	if err := rejectDuplicateJSONKeys(rawManifest); err != nil {
		return nil, err
	}
	var manifest map[string]ManifestEntry
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return nil, fmt.Errorf("manifest.json does not parse")
	}
	if len(manifest) == 0 {
		return nil, fmt.Errorf("manifest.json has no entries")
	}
	return manifest, nil
}

// crossCheckAssets requires the manifest reference set and the
// embedded tree to agree exactly: every manifest reference must exist in the
// embed; every embedded asset must be referenced (an unreferenced asset means
// the manifest and the tree disagree — ambiguous, fail closed); and two
// logical assets must never collide case-insensitively.
func crossCheckAssets(referenced map[string]struct{}, embedded map[string]Asset) (map[string]Asset, error) {
	assets := make(map[string]Asset, len(referenced))
	for ref := range referenced {
		info, ok := embedded[ref]
		if !ok {
			return nil, fmt.Errorf("manifest references missing file %q", ref)
		}
		assets[ref] = info
	}
	for p := range embedded {
		if _, ok := referenced[p]; !ok {
			return nil, fmt.Errorf("embedded asset %q not referenced by manifest", p)
		}
	}
	lower := make(map[string]string, len(assets))
	for p := range assets {
		lc := strings.ToLower(p)
		if prev, dup := lower[lc]; dup && prev != p {
			return nil, fmt.Errorf("ambiguous assets differing only by case")
		}
		lower[lc] = p
	}
	return assets, nil
}

// validateImportGraph checks the chunk graph: every imports /
// dynamicImports value must be an existing MANIFEST KEY. Referenced chunks
// pass the normal file/css/assets checks because validation walks every
// manifest entry flat — there is no recursive traversal anywhere, so cyclic
// or hostile graphs terminate by construction (bounded by len(manifest)).
func validateImportGraph(manifest map[string]ManifestEntry) error {
	for key, e := range manifest {
		for _, imp := range e.Imports {
			if _, ok := manifest[imp]; !ok {
				return fmt.Errorf("manifest entry %q imports missing key %q", obs.Sanitize(key), obs.Sanitize(imp))
			}
		}
		for _, imp := range e.DynamicImports {
			if _, ok := manifest[imp]; !ok {
				return fmt.Errorf("manifest entry %q dynamically imports missing key %q", obs.Sanitize(key), obs.Sanitize(imp))
			}
		}
	}
	return nil
}

// collectRefs gathers and path-validates every file the manifest
// references. At least one entry chunk (isEntry) must exist.
func collectRefs(manifest map[string]ManifestEntry) (map[string]struct{}, error) {
	referenced := make(map[string]struct{})
	haveEntry := false
	for key, e := range manifest {
		if e.File == "" {
			return nil, fmt.Errorf("manifest entry %q has no file", obs.Sanitize(key))
		}
		refs := append([]string{e.File}, e.CSS...)
		refs = append(refs, e.Assets...)
		for _, r := range refs {
			if err := validateAssetPath(r); err != nil {
				return nil, fmt.Errorf("manifest entry %q: %w", obs.Sanitize(key), err)
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

// listDist inventories the embedded tree: only index.html,
// manifest.json, and allowlisted assets/* files may exist; sourcemaps are
// refused outright.
func listDist(dist fs.FS) (map[string]Asset, error) {
	embedded := map[string]Asset{}
	err := fs.WalkDir(dist, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && p != "assets" {
				return fmt.Errorf("unexpected directory %q in dist", obs.Sanitize(p))
			}
			return nil
		}
		if p == "index.html" || p == "manifest.json" {
			return nil
		}
		if strings.HasSuffix(p, ".map") {
			return fmt.Errorf("sourcemap %q embedded", obs.Sanitize(p))
		}
		if verr := validateAssetPath(p); verr != nil {
			return fmt.Errorf("embedded file %q: %w", obs.Sanitize(p), verr)
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		contentType, _ := contentTypeFor(path.Ext(p)) // validateAssetPath admitted the extension
		embedded[p] = Asset{ContentType: contentType, Size: info.Size()}
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
