# Claim-Evidence Ledger — "Content security"

Article: [`content-security.md`](content-security.md). Verified against repo
revision `ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| Body scanning runs on decrypted traffic (content-scan pipeline stage) | src | `docs/architecture.md` §1 (stage 11); `scanner.go` (invoked on inspected path) |
| Host/URL controls run pre-dispatch (no decryption) | src | `proxy.go:401` `preDispatchBlocked` (blocklist `:406`, threat `:417`, file-ext `:449`) |
| ClamAV INSTREAM, external sidecar via `-clamav-addr` | src | `internal/clamav/clamav.go:168` (`zINSTREAM`); `main.go:267` (flag) |
| ClamAV is a gating readiness check when configured | src | `healthcheck.go:156-166` (`allOK = false` on non-connected) |
| Pure-Go YARA engine (no cgo/libyara); `-yara-rules-dir` | src | `internal/yara/yara.go:1-18`; `main.go:268` |
| YARA runtime API (rules CRUD/validate/reload/settings) | src | `ui_security.go:1333-1337` |
| Regex DPI on decrypted response bodies; `/api/dpi` (+ bypass) | src | `internal/scanner/scanner.go`; `ui_security.go:1326-1342` |
| File-type blocking: extension profiles + magic-byte/MIME | src | `internal/fileblock/fileprofile.go`; `internal/filemagic/filemagic.go`; routes `ui_policy.go:2145-2146` |
| Per-rule `fileFiltering` + `fileProfile` | src | `PolicyRule` (`policy.go`) |
| Threat feeds URLhaus + OpenPhish; domain allowlist | src | `internal/threatfeed/threatfeed.go:103-104,359-363`; route `ui_security.go:1332` |
| Threat feed persistence flag | src | `main.go:269` (`-threat-feed-db`) |
| Domain blocklist + mode/feed/exceptions routes | src | `ui_policy.go:2144-2167` |
| CDR is a client to an external Sluice engine (gRPC/mTLS); outcomes logged | src | `cdr.go:3-10`; `internal/reqlog/reqlog.go` (`CDR_BLOCKED`/`CDR_SANITIZED`); routes `cdr_ui.go:949-955` |
| Scan exclusions + SHA-256 result cache | src | `ui_security.go:1338` (`/api/security-scan/exclusions`); `internal/hashcache` |
| Metrics: clamav/dpi/file blocked totals | src | `metrics.go` (`culvert_{clamav,dpi,file}_blocked_total`) |
| Scanner status route | src | `ui_security.go:1330` (`/api/security-scan/status`) |

## Notes

- The "Bypass = body-scan blind spot" framing follows directly from the pipeline
  order: body scanners run at the content-scanning stage, which is reached only
  on the `Inspect` branch (`docs/architecture.md` §1).
- CDR labeling is consistent with the C-001 correction (companion engine, not
  in-binary).
