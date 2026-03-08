# ProxyShield Development Roadmap & Security Standards
This document outlines the strategic progression for ProxyShield, moving from a PoC to an Enterprise-Grade Secure Web Gateway (SWG).

> **Shift-Left Security**: Every feature ships with security tests. No feature merges without a corresponding `_test.go` covering the security-relevant code paths.

## Phase 1: Policy Engine Refactoring (Palo Alto Style) ✅
- [x] **Object-Based Rules:** Implement a rule schema supporting Source IP, Identity (Mock/OIDC), Destination (FQDN/Category), and Service.
- [x] **Action Matrix:** Support `Allow`, `Drop`, `Block_Page` (HTML 403), and `Redirect`.
- [x] **SSL Policy:** Integrate `Decrypt` (Inspect) and `Bypass` (Tunnel) logic per rule.
- [x] **Hit Counter:** Persistent tracking of rule triggers in the UI.

## Phase 2: Security Hardening ✅
- [x] **CA Secret Management:** Root CA private key encrypted at rest with AES-256-GCM + PBKDF2-SHA256 (100k iterations). Passphrase via `PROXYSHIELD_CA_PASSPHRASE` env var — never in CLI args. Flag: `-ca-path`.
- [x] **Strict SSL Validation:** Upstream connections enforce TLS 1.2 minimum (`MinVersion: tls.VersionTLS12`). Certificate validation is on by default (fail-secure — no `InsecureSkipVerify`).
- [x] **Non-Root Execution:** Dockerfile runs as unprivileged `proxy` user. Recommended runtime flags documented: `--read-only --cap-drop=ALL --security-opt no-new-privileges`.
- [x] **Header Scrubbing:** `scrubForwardedHeaders()` strips RFC 1918 / loopback / link-local IPs from `X-Forwarded-For`, removes private `X-Real-IP`, and always deletes `X-User-Identity` before forwarding (prevents topology leakage and identity injection).

## Phase 3: Identity & Advanced Inspection
- [ ] **Okta/OIDC Integration:** Replace Mock identity with real-time OIDC authentication.
- [ ] **MITM Content Scanning:** Implement basic signature-based scanning for malicious patterns in decrypted HTTPS traffic.
- [ ] **File Blocking Profile:** Ability to block specific file extensions (.exe, .dll, .zip) based on user group.

## Phase 4: Observability & Management
- [x] **Audit Logs:** Track all configuration changes (Who, What, When). Every mutating API call (policy, blocklist, security, settings, rewrite, SSL bypass, file block) is recorded with actor IP, action, object, and detail. Accessible via `GET /api/audit`. In-memory ring buffer of 500 entries.
- [ ] **Live Stats:** Real-time WebSocket feed of active connection counts and blocked attempts per second.
- [ ] **Content Scanning (DPI):** Regex/YARA engine applied to decrypted HTTPS traffic (requires SSL Inspect mode).
