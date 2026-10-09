# Source-mode scan correction — candidate `7c7b29ee` (no OVA rebuild)

ASTRA's 7c ESXi round found that the source-mode reachability scan did not use
the shipped build settings of docker-compose and containerd-shim-runc-v2. This
record states what the shipped binaries were built with, what the scanner did,
what changed, and what the regenerated evidence shows.

## Shipped build settings (from each binary's own build info, exact OVA bytes)

| binary | Go | CGO_ENABLED | GOOS/GOARCH/GOAMD64 | -tags |
|---|---|---|---|---|
| docker-compose | go1.26.8 | **0** | linux/amd64/v1 | e2e |
| containerd-shim-runc-v2 | go1.27.2 | **0** | linux/amd64/v1 | urfave_cli_no_docs,no_grpc |
| containerd | go1.27.2 | 1 | linux/amd64/v1 | urfave_cli_no_docs |
| ctr | go1.27.2 | 1 | linux/amd64/v1 | urfave_cli_no_docs |
| runc | go1.27.2 | 1 | linux/amd64/v1 | seccomp,urfave_cli_no_docs |
| dockerd | go1.26.9 | 1 | linux/amd64/v1 | nri_no_wasm,journald |
| docker-proxy | go1.26.9 | 1 | linux/amd64/v1 | nri_no_wasm,journald |
| docker | go1.26.9 | 1 | linux/amd64/v1 | grpcnotrace |

The binaries analysed are byte-identical to the OVA's: their sha256 equal the
`go-binaries.tsv` digests recorded from the guest filesystem.

## Scanner change (`test/e2e/appliance/lab/exact-scan.sh`, `scan-dispositions.py`)

- **Before:** `CGO_ENABLED=1` forced for every binary; GOOS/GOARCH/GOAMD64 left
  to the scanner host's defaults.
- **After:** CGO_ENABLED, GOOS, GOARCH and GOAMD64 are read from each binary's
  own build info, alongside the Go version and `-tags` already taken from it. A
  binary whose setting is missing is refused. Each source-mode row records
  `cgo=` and `target=`.
- **Renderer:** cross-checks every row against the build info that binary mode
  captured from the exact bytes, and fails on any difference. It refuses the
  previous evidence (run 37914496496), whose rows carry no build settings.
- **Table step:** an advisory found in several shipped modules (net/http's
  bundled HTTP/2 in `stdlib` and `golang.org/x/net`) now lists every module.
  Before, the row named whichever trace govulncheck reported first, so the
  module column could differ between runs. Counts are unchanged.

## Before / after (exact 7c7b29ee binaries)

| binary | before (scan 37914496496) | after (scan 37929914413) |
|---|---|---|
| docker-compose | called 10, imported 3, required 1 | called 10, imported 3, required 1 |
| containerd-shim-runc-v2 | imported 1, required 5 | imported 1, required 5 |
| containerd | called 5, imported 1, required 1 | unchanged |
| ctr | called 5, imported 1 | unchanged |
| runc | required 7 | unchanged |
| dockerd | required 1 | unchanged |
| docker-proxy, docker | 0 | 0 |

- Every advisory keeps its level in all eight binaries.
- docker-compose's 10 called advisories keep **identical call-path sets**.
- The CI regeneration (artifact 11615728677) equals an independent local run on
  the same bytes, finding for finding.

**Effect:** the correction changes no disposition. It makes the evidence match
the shipped bytes, and the renderer now enforces that.

Evidence: scan run 37929914413, artifact 11615728677. `findings.tsv` was
re-derived from that artifact's raw govulncheck JSON with the table step at this
commit. Dispositions: `candidate-7c7b29ee-scan-dispositions.md`.
