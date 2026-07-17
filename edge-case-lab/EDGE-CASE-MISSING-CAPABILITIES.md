# Culvert Edge-Case Lab — Security Bypass, Missing Capabilities & Recorded Limitations

## SECURITY_BYPASS (advertised interface bypasses the enforcement boundary)

### SWG-0210 — Egress policy must apply to SOCKS5 clients (news.example.test)
- **Requirement:** A blocked destination 'news.example.test' must be blocked for SOCKS5 clients exactly as for HTTP/CONNECT clients; egress policy is transport-agnostic in a mature SWG.
- **Finding:** Culvert SOCKS5 handler does not run the PBAC policy engine (only the legacy blocklist); destination policy cannot be represented for SOCKS5 clients. Documented architecture, but a valid enterprise requirement that is unrepresentable => missing capability.
- **Evidence:** `representative_evidence/SWG-0210.json` — HTTP/CONNECT enforces the block; the SOCKS5 path allows the same host (policy engine bypassed).

### SWG-0211 — Egress policy must apply to SOCKS5 clients (media.corp.local)
- **Requirement:** A blocked destination 'media.corp.local' must be blocked for SOCKS5 clients exactly as for HTTP/CONNECT clients; egress policy is transport-agnostic in a mature SWG.
- **Finding:** Culvert SOCKS5 handler does not run the PBAC policy engine (only the legacy blocklist); destination policy cannot be represented for SOCKS5 clients. Documented architecture, but a valid enterprise requirement that is unrepresentable => missing capability.
- **Evidence:** `representative_evidence/SWG-0211.json` — HTTP/CONNECT enforces the block; the SOCKS5 path allows the same host (policy engine bypassed).

## Missing capabilities (valid enterprise requirement, not representable in Culvert)

_None recorded in this run._

## Recorded coverage limitations (valid capability, infra-bounded — not executed)

| ID | Capability | Why recorded rather than executed |
|---|---|---|
| SWG-0205 | GeoIP / destination country | GeoIP is cache-only fail-closed and requires a GeoLite2 DB + public IPs; TEST-NET fixtures cannot populate the GeoIP cache, so this dimension is recor |
| SWG-0206 | IPv6 support | The SSRF guard blocks ::1/ULA and the lab cannot assign a public IPv6 to a fixture; recorded as an untested dimension. |
| SWG-0207 | DNS rebinding protection | Culvert applies a connect-time ssrfControl re-check (verified by code review); a full rebinding harness (TTL=0 flip) is out of scope for the fixture l |
| SWG-0208 | WebSocket handling | The fixture provides a WS stub; deterministic frame-level assertions were deferred and the dimension recorded for coverage completeness. |
| SWG-0209 | Partial downloads | Recorded; the fixture supports byte-sized bodies but deterministic multi-range assertions were deferred. |
| SWG-0215 | Open-redirect safety on the redirect action | Culvert refuses to redirect to an unvalidated external host (isSafeRedirectURL -> 403 instead of an open 302). This is a DEFENSIBLE safety posture (no |

Additional not-covered capabilities (require mocks a fuller lab would add): client-certificate origins, CDR (Sluice), PAC resolution, IdP unavailability, control-plane unavailability. Recorded honestly rather than faked.
