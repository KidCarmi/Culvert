# Keep grpc-gateway's HTTP runtime out of every build (CVE-2026-37236)

This directory is the `github.com/sigstore/rekor-tiles/v2 v2.3.0` Go module
(tag commit `fa390b1c17f9685f7a164da2c06e82dc295cfdca`; module sum and zip
sha256 in `CULVERT-PROVENANCE.json`) with FIVE upstream files left out and
nothing changed. Licensing is unchanged (Apache-2.0, `LICENSE`).

## Why

CVE-2026-37236 / `SNYK-GOLANG-GITHUBCOMGRPCECOSYSTEMGRPCGATEWAYV2RUNTIME-19432132`
(no fixed version): grpc-gateway's `runtime.(*ServeMux).ServeHTTP` rewrites the
request method from `X-HTTP-Method-Override` on form POSTs. Nothing in this
repository serves a gateway mux, but the package was still COMPILED into all
three modules (the proxy, `cmd/culvert-maint`, `pkg/releaseproof`):
sigstore-go `pkg/verify` imports rekor-tiles' generated protobuf package for its
message types, and that package's `rekor_service.pb.gw.go` — the server-side
`RegisterRekorHandler*` HTTP registration — imports `grpc-gateway/v2/runtime`.
It was the only importer of that package in any of our build graphs. Leaving
the file out removes the vulnerable package from every graph, which is a
remediation rather than a reachability argument.

## What is left out (and nothing else)

| File | Why |
|---|---|
| `pkg/generated/protobuf/rekor_service.pb.gw.go` | the gateway HTTP handler registration; no caller here (server-side, `RegisterRekorHandler*`) |
| `pkg/client/read/read_test.go`, `pkg/note/note_test.go`, `internal/signerverifier/file_test.go`, `tests/testdata/pki/ed25519-priv-key.pem` | upstream TEST-ONLY files embedding private test keys; never built into a binary here; not vendored so no key material enters this repository (secret scanning stays exception-free for this fork) |

The protobuf messages, the gRPC client/server stubs (`rekor_service_grpc.pb.go`)
and every verifier are byte-identical to upstream. `grpc-gateway` stays a
module requirement because the generated messages use its unaffected
`protoc-gen-openapiv2/options` annotations package.

## Verification

```text
python3 appliance/artifact-audit/verify_dependency_forks.py   # upstream bytes, exactly these five absent, replaces in all three go.mod
go test -run TestNoModuleBuildsGrpcGatewayRuntime .            # no module builds grpc-gateway/v2/runtime; the importer is linked from this fork
```

The verifier also accepts `--upstream-zip rekor-tiles=<v2.3.0.zip>` for a
byte-for-byte inventory comparison with the proxy.golang.org module zip.

## Maintenance obligation

Upgrading rekor-tiles must replace the full upstream tree, re-check whether
upstream still generates the gateway file into the message package (or whether
grpc-gateway has fixed the advisory), re-apply this removal, regenerate
`CULVERT-PROVENANCE.json` and run the checks above. Every module that links
rekor-tiles must keep its `replace` (the verifier and the test both fail
otherwise). SBOM consumers must retain the upstream version plus this
provenance.
