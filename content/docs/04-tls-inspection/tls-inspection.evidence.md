# Claim-Evidence Ledger — "TLS inspection administration"

Article: [`tls-inspection.md`](tls-inspection.md). Verified against repo revision
`ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| Inspection is opt-in per rule via `sslAction: Inspect` | src | `policy.go:33-34`; `PolicyRule.SSLAction` |
| Leaf certs ECDSA P-256, per-SNI, cache 10k / 1h TTL LRU, memory-only key | src | `internal/ca/ca.go:78-79` (`certCacheMaxSize = 10_000`, `certCacheTTL = 1h`), `:763` (leaf P-256) |
| CA key AES-256-GCM + PBKDF2-SHA256 @ 600k, `CULVERT_CA_PASSPHRASE` | src | `internal/ca/ca.go:138,352,358` |
| CA API: status/download/cert/key-provider/upload/cache-clear/rotate | src | `ui_security.go:1323-1354` |
| SSL-bypass management route | src | `ui_security.go:1325` (`/api/ssl-bypass`) |
| Decryption Profiles API (the "how") | src | `ui_policy.go:2171` (`/api/decryption-profiles`) |
| Decryption health + exclusions + tunables API | src | `ui_policy.go:2172-2174` |
| Default posture `fail-close`; `fail-open` is the adaptive-exclusion opt-in | src | `internal/decryptprofile/decryptprofile.go:50-79` |
| `permissive` verify + `fail-open` on unsupported TLS are "coming soon" | src | `docs/operator/decryption-profiles.md:14-15`; `internal/decryptprofile/decryptprofile.go:75-76` |
| Auto CA rotation (local + cluster); force via API | src | `ca.go:59-63` `StartCAAutoRotation`; `ui_security.go:1354` `/api/ca/rotate` |
| Root-CA change rotates client ticket key, ends resumption epoch | src | `docs/architecture.md` §2 |
| Min-TLS floor drops the tunnel; metric per profile | src | `docs/operator/decryption-profiles.md` (`culvert_decrypt_profile_mintls_reject_total{profile}`) |
| Adaptive exclusions volatile, per-profile-scoped, never CP→DP synced | src | `internal/autoexclude`; CLAUDE.md architecture note |
| Inspection does not preserve client TLS fingerprint (JA3/JA4) | src | `docs/operator/decryption-profiles.md` (honest-scope section) |
| `tlsSkipVerify` disables upstream verification per rule | src | `PolicyRule.TLSSkipVerify` (`policy.go`) |

## Notes

- Deep field-level behavior (profile fields, anti-bot scope, HTTP/2 inspection,
  auto-exclusion classifier) is intentionally delegated to the in-repo operator
  guides rather than re-derived; this article verifies the core claims and the
  admin surface.
