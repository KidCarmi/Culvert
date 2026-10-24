# Receipt notes — a8df88c2 (tree a47abce6): main cutoff 039295bc

- The merge of main `039295bc` (owner decision 6387402372 §2: one deliberate reconciliation at a recorded cutoff, then freeze). Command 1 records the ancestry: every reviewed commit is an ancestor (A `0fb4daf9`, C `1e50cf9c`, B `41e2e86f`, combined `783f7142`, the CI-green head `0e190a94`), and so is `039295bc`.
- **This clean run: all 9 commands exit 0**, tree clean before and after. It covers:
  - build + vet;
  - main's new tests together with the touched appliance areas at `-race -count=2 -shuffle` (empty-body/NoBody, CDR fail-closed, HTTP forward / SSL inspect, MCP distribution UX, diagnostics, readiness posture, access-CIDR, session/revocation, AV-unavailable);
  - `internal/admission` at `-race -count=2 -shuffle`;
  - benchgate in root + admission;
  - full `go test ./...`;
  - lint `--new-from-rev 039295bc`;
  - `make api-verify`;
  - gitleaks.
- **The first run is kept unedited in `../a8df88c2-run1-enospc/`.** Command 6 (`go test ./...`) failed in `internal/catdb` and `internal/feedsync` with `fallocate … no space left on device`: badger reserves 128–256 MiB per store file, and the sandbox had about 1.2 GB free. That is environmental. Neither package is touched by the main delta, and both passed in the full `52463785` receipt. I cleared the Go build cache (to about 8.7 GB free) and reran the identical command file on the same commit.
- **Main delta trace (no interaction found):**
  - `proxy_http.go` / `proxy_tunnel.go`: main skips the request-body wrapper only for the `http.NoBody` sentinel (request path). This branch's own edits in those files are comments on the response-scan path.
  - `diagnostics.go`: main adds a CDR `enabled-dark` row; the branch edits `policy_loaded`. These are separate functions.
  - `static/index.html`: main changes the MCP Command Center/Health panels; the branch changes other panels.
  - CDR fail-closed (`cdrstore.go`, `cdr_proxy.go`): it applies only when CDR is enabled. The appliance does not enable CDR, and the default `fail_mode` stays `open`, so no appliance default changes.
  - The admission zero-value hardening is self-contained.
