package frontendbundle

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// shellScriptRE / shellLinkRE extract resource references
// from VITE'S CONSTRAINED GENERATED SHELL — a handful of <script>/<link> tags
// with double-quoted attributes emitted by the bundler. This is deliberately
// NOT a general HTML parser; the shell is machine-generated and the FE-1A
// bundle gate already pins its structural shape (no inline bodies, no
// single-quoted attributes, no exotic markup).
var (
	shellScriptRE = regexp.MustCompile(`<script\b[^>]*\bsrc="([^"]+)"`)
	shellLinkRE   = regexp.MustCompile(`<link\b[^>]*>`)
	shellAttrRE   = regexp.MustCompile(`\b(rel|href)="([^"]*)"`)
)

// validateShellBinding requires the authoritative entry
// manifest["index.html"] (isEntry, hashed JS file) and proves the static
// shell references EXACTLY that entry's artifacts: its JS file as the only
// script, its CSS set as the stylesheet set, modulepreload targets only
// validated assets. Same-origin /assets/ addressing is implied: every bound
// reference must resolve to a validated asset path.
func validateShellBinding(shell []byte, manifest map[string]ManifestEntry, assets map[string]Asset) error {
	entry, ok := manifest["index.html"]
	if !ok {
		return fmt.Errorf(`manifest has no "index.html" entry`)
	}
	if !entry.IsEntry {
		return fmt.Errorf(`manifest "index.html" entry is not isEntry`)
	}
	if path.Ext(entry.File) != ".js" {
		return fmt.Errorf(`manifest "index.html" entry file is not a JS chunk`)
	}

	scripts, stylesheets, preloads := shellRefs(shell)

	// Exactly the entry JS, nothing else, addressed under /assets/.
	wantJS := "/" + entry.File
	if !scripts[wantJS] {
		return fmt.Errorf("shell does not reference the manifest entry JS")
	}
	if len(scripts) != 1 {
		return fmt.Errorf("shell references %d scripts, want exactly the entry chunk", len(scripts))
	}
	// Exactly the entry CSS set.
	wantCSS := map[string]bool{}
	for _, c := range entry.CSS {
		wantCSS["/"+c] = true
	}
	if len(stylesheets) != len(wantCSS) {
		return fmt.Errorf("shell stylesheet set differs from manifest entry css")
	}
	for href := range stylesheets {
		if !wantCSS[href] {
			return fmt.Errorf("shell references stylesheet outside the manifest entry css")
		}
	}
	// Every bound URL must be a validated asset (same-origin /assets/ path).
	if err := requireValidatedAssets(scripts, assets, "shell script is not a validated /assets/ artifact"); err != nil {
		return err
	}
	if err := requireValidatedAssets(stylesheets, assets, "shell stylesheet is not a validated /assets/ artifact"); err != nil {
		return err
	}
	return requireValidatedAssets(preloads, assets, "shell modulepreload is not a validated /assets/ artifact")
}

// shellRefs extracts the shell's script srcs, stylesheet hrefs, and
// modulepreload hrefs from the constrained Vite-generated markup.
func shellRefs(shell []byte) (scripts, stylesheets, preloads map[string]bool) {
	scripts = map[string]bool{}
	for _, m := range shellScriptRE.FindAllSubmatch(shell, -1) {
		scripts[string(m[1])] = true
	}
	stylesheets = map[string]bool{}
	preloads = map[string]bool{}
	for _, tag := range shellLinkRE.FindAll(shell, -1) {
		var rel, href string
		for _, am := range shellAttrRE.FindAllSubmatch(tag, -1) {
			switch string(am[1]) {
			case "rel":
				rel = string(am[2])
			case "href":
				href = string(am[2])
			}
		}
		switch rel {
		case "stylesheet":
			stylesheets[href] = true
		case "modulepreload":
			preloads[href] = true
		}
	}
	return scripts, stylesheets, preloads
}

// requireValidatedAssets requires every referenced URL to be a
// validated asset addressed under same-origin /assets/.
func requireValidatedAssets(refs map[string]bool, assets map[string]Asset, msg string) error {
	for href := range refs {
		if _, ok := assets[strings.TrimPrefix(href, "/")]; !ok || !strings.HasPrefix(href, "/assets/") {
			return fmt.Errorf("%s", msg)
		}
	}
	return nil
}
