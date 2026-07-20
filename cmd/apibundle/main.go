// Command apibundle deterministically bundles the OpenAPI YAML contract into a
// canonical openapi.json and renders a self-contained, offline HTML docs page.
//
// Usage:
//
//	go run ./cmd/apibundle -spec api/openapi/openapi.yaml -json api/openapi/openapi.json -html api/openapi/index.html
//
// Reproducible and air-gapped: no network, no Node, no external assets. The
// generated files carry a do-not-edit header enforced by the drift gate.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/KidCarmi/Culvert/internal/apicontract"
)

func main() {
	spec := flag.String("spec", "api/openapi/openapi.yaml", "path to the OpenAPI YAML contract")
	jsonOut := flag.String("json", "api/openapi/openapi.json", "canonical JSON output path")
	htmlOut := flag.String("html", "api/openapi/index.html", "admin offline HTML docs output path")
	publicHTMLOut := flag.String("public-html", "api/openapi/index.public.html", "public-only offline HTML docs output path")
	manifest := flag.String("manifest", "api/route-classification.yaml", "path to the route-classification manifest")
	inventoryOut := flag.String("inventory", "docs/api/API-INVENTORY.md", "generated API inventory output path")
	check := flag.Bool("check", false, "verify committed artifacts match regeneration (no writes); exit 1 on drift")
	flag.Parse()

	// The admin build renders every documented operation; the public build is
	// visibility-filtered to public-supported so internal operations can never
	// leak into a customer-facing document.
	jsonBytes, err := apicontract.BundleJSON(*spec)
	if err != nil {
		die("bundle json: %v", err)
	}
	adminHTML, err := apicontract.RenderDocsHTML(*spec)
	if err != nil {
		die("render admin html: %v", err)
	}
	publicHTML, err := apicontract.RenderDocsHTML(*spec, "public-supported")
	if err != nil {
		die("render public html: %v", err)
	}
	inventory, err := apicontract.RenderInventory(*manifest)
	if err != nil {
		die("render inventory: %v", err)
	}

	artifacts := []struct {
		path  string
		bytes []byte
	}{
		{*jsonOut, jsonBytes},
		{*htmlOut, adminHTML},
		{*publicHTMLOut, publicHTML},
		{*inventoryOut, inventory},
	}

	if *check {
		drift := false
		for _, a := range artifacts {
			if !sameFile(a.path, a.bytes) {
				fmt.Fprintf(os.Stderr, "DRIFT: %s is stale — run `make api-bundle`\n", a.path)
				drift = true
			}
		}
		if drift {
			os.Exit(1)
		}
		fmt.Println("api artifacts up to date")
		return
	}

	for _, a := range artifacts {
		if err := os.WriteFile(a.path, a.bytes, 0o600); err != nil {
			die("write %s: %v", a.path, err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", a.path, len(a.bytes))
	}
}

func sameFile(path string, want []byte) bool {
	got, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Equal(got, want)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
