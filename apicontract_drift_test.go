package main

// Gate 8 — generated-artifact drift. The canonical openapi.json and the offline
// index.html are generated from api/openapi/openapi.yaml. This test regenerates
// them in-process and fails if the committed copies differ, so editing the
// contract without running `make api-bundle` breaks CI.

import (
	"os"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/apicontract"
)

func TestOpenAPI_Gate8_BundleNotStale(t *testing.T) {
	jsonBytes, err := apicontract.BundleJSON(openapiSpecPath)
	if err != nil {
		t.Fatalf("bundle json: %v", err)
	}
	committed, err := os.ReadFile("api/openapi/openapi.json")
	if err != nil {
		t.Fatalf("read committed openapi.json: %v", err)
	}
	if string(committed) != string(jsonBytes) {
		t.Fatal("api/openapi/openapi.json is stale — run `make api-bundle` and commit the result")
	}

	htmlBytes, err := apicontract.RenderDocsHTML(openapiSpecPath)
	if err != nil {
		t.Fatalf("render html: %v", err)
	}
	committedHTML, err := os.ReadFile("api/openapi/index.html")
	if err != nil {
		t.Fatalf("read committed index.html: %v", err)
	}
	if string(committedHTML) != string(htmlBytes) {
		t.Fatal("api/openapi/index.html is stale — run `make api-bundle` and commit the result")
	}

	publicHTML, err := apicontract.RenderDocsHTML(openapiSpecPath, "public-supported")
	if err != nil {
		t.Fatalf("render public html: %v", err)
	}
	committedPublic, err := os.ReadFile("api/openapi/index.public.html")
	if err != nil {
		t.Fatalf("read committed index.public.html: %v", err)
	}
	if string(committedPublic) != string(publicHTML) {
		t.Fatal("api/openapi/index.public.html is stale — run `make api-bundle` and commit the result")
	}
}

// TestOpenAPI_PublicDocs_NoInternalLeak proves the public documentation build
// contains only public-supported operations — no admin/internal operation can
// leak into a customer-facing document.
func TestOpenAPI_PublicDocs_NoInternalLeak(t *testing.T) {
	spec, err := apicontract.LoadSpec(openapiSpecPath)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	publicHTML, err := apicontract.RenderDocsHTML(openapiSpecPath, "public-supported")
	if err != nil {
		t.Fatalf("render public html: %v", err)
	}
	body := string(publicHTML)
	for _, o := range spec.Ops {
		vis := apicontract.Ext(o.Op, "x-culvert-visibility")
		if vis == "public-supported" {
			continue
		}
		// A non-public operationId must NOT appear in the public build.
		if o.Op.OperationID != "" && strings.Contains(body, ">"+o.Op.OperationID+"<") {
			t.Errorf("public docs leaked non-public operation %s (%s)", o.Op.OperationID, vis)
		}
	}
}
