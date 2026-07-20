# Culvert developer Makefile.
#
# The API-governance targets below drive the OpenAPI contract program. The
# CORE enforcement gates (validation, style-lint, route coverage, conformance,
# drift, exemption expiry) are ordinary Go tests, so they ALSO run inside the
# required `go test ./...` fast PR gate — these targets are the fast local
# equivalents plus the out-of-band tools (docs build, breaking-change, client
# generation) that stay off the fast gate.

GO ?= go
SPEC := api/openapi/openapi.yaml

.PHONY: build test api-verify api-lint api-bundle api-route-coverage \
        api-contract-test api-breaking-check api-client-generate api-docs-build \
        api-classification-skeleton

build:
	CGO_ENABLED=0 $(GO) build -o culvert .

test:
	$(GO) test ./...

## ── API governance ──────────────────────────────────────────────────────────

# Full PR-safe API gate (fast, Go-native, offline). Mirrors what CI enforces.
api-verify: api-bundle-check api-lint api-route-coverage api-contract-test
	@echo "API contract verified."

# Gate 1+2: spec validates and passes organizational style lint.
api-lint:
	$(GO) test ./internal/apicontract/... -run 'TestReal|TestStyleLint' -count=1
	$(GO) test . -run 'TestOpenAPI_Gate1|TestOpenAPI_Gate2' -count=1

# Regenerate the canonical JSON + offline HTML from the YAML contract.
api-bundle:
	$(GO) run ./cmd/apibundle -spec $(SPEC) -json api/openapi/openapi.json -html api/openapi/index.html -public-html api/openapi/index.public.html -manifest api/route-classification.yaml -inventory docs/api/API-INVENTORY.md

# Gate 8: fail if the committed generated artifacts are stale.
api-bundle-check:
	$(GO) run ./cmd/apibundle -spec $(SPEC) -check

# Gate 3: live route ⇄ manifest ⇄ spec coverage + exemption expiry.
api-route-coverage:
	$(GO) test . -run 'TestOpenAPI_Gate3' -count=1

# Gates 4/5/6: request/response/authz conformance through real handlers.
api-contract-test:
	$(GO) test . -run 'TestConformance_' -count=1

# Gate 7: breaking-change detection vs the base branch (oasdiff, pinned).
api-breaking-check:
	./scripts/openapi/breaking-check.sh

# Gate 9: generate a typed Go client from the contract and compile it.
api-client-generate:
	./scripts/openapi/generate-client.sh

# Gate 10: build offline documentation (self-contained, no CDN).
api-docs-build: api-bundle
	@echo "Offline docs at api/openapi/index.html (self-contained, no external assets)."

# Regenerate the classification manifest SKELETON from the live router (review
# the diff by hand — never blindly overwrite classifications).
api-classification-skeleton:
	./scripts/openapi/classification-skeleton.sh
