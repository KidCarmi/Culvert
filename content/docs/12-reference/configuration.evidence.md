# Claim-Evidence Ledger — "Configuration reference"

Article: [`configuration.md`](configuration.md). Verified against repo revision
`ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| Precedence: flag > config > default (`firstNonZero`) | src | `main.go:502-503` (`firstNonZero(*proxyPort, fc.Proxy.Port, 8080)`) |
| Config validated at load (enums/limits/cluster/CDR) | src | `config.go:356` (`validate`), `:369` (`validateEnums`), `:407` (`validateLimits`), `:450`, `:475` |
| `default_action` ∈ {allow, deny, empty} | src | `config.go:369-376` |
| `session_timeout_hours` must be 1–168 | src | `config.go:411-412` |
| `proxy.port` / `socks5_port` must be 1–65535 (non-zero) | src | `config.go:416-417`; `:23` (`socks5_port` 0 = disabled) |
| Top-level sections: proxy/auth/ldap/oidc/security/security_scan/upstream/rewrite/file_block/cluster/log_* | cfg | `config.example.yaml:9-182` |
| `ldap` is top-level (sibling of `auth`) | cfg | `config.example.yaml:59,64`; README config note |
| `upstream.health_interval` / `circuit_breaker` are siblings of `proxies` | cfg | `config.example.yaml:105-116`; README config note |
| Shipped-image paths/ports come from the container command line | cfg | `docker-compose.yml:129-140` |
| GUI parity for CLI/config options; `CULVERT_RELEASE_*` env-only exception | src | CLAUDE.md GUI-parity convention; `CULVERT_RELEASE_*` notes |

## Notes

- This reference deliberately does not enumerate every field (that would mirror
  source and drift). `config.example.yaml` is cited as the authoritative,
  version-matched field list; this page documents precedence, validation, and
  structure — behavior the raw field list does not convey.
