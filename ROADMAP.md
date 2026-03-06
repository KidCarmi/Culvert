# ProxyShield Development Roadmap & Security Standards
This document outlines the strategic progression for ProxyShield, moving from a PoC to an Enterprise-Grade Secure Web Gateway (SWG).
## Phase 1: Policy Engine Refactoring (Palo Alto Style)
- [ ] **Object-Based Rules:** Implement a rule schema supporting Source IP, Identity (Mock/OIDC), Destination (FQDN/Category), and Service.
- [ ] **Action Matrix:** Support `Allow`, `Drop`, `Block_Page` (HTML 403), and `Redirect`.
- [ ] **SSL Policy:** Integrate `Decrypt` (Inspect) and `Bypass` (Tunnel) logic per rule.
- [ ] **Hit Counter:** Persistent tracking of rule triggers in the UI.
## Phase 2: Security Hardening (Current Priority)
- [ ] **CA Secret Management:** Move the Root CA Private Key from plain-text storage to an encrypted volume or use environment-based passphrases.
- [ ] **Strict SSL Validation:** Ensure the proxy validates upstream certificates and blocks connections on invalid/expired certs unless bypassed.
- [ ] **Non-Root Execution:** Update Dockerfile to run the proxy process as a non-privileged user.
- [ ] **Header Scrubbing:** Strip internal headers (e.g., X-Forwarded-For with internal IPs) before forwarding requests to the internet.
## Phase 3: Identity & Advanced Inspection
- [ ] **Okta/OIDC Integration:** Replace Mock identity with real-time OIDC authentication.
- [ ] **MITM Content Scanning:** Implement basic signature-based scanning for malicious patterns in decrypted HTTPS traffic.
- [ ] **File Blocking Profile:** Ability to block specific file extensions (.exe, .dll, .zip) based on user group.
## Phase 4: Observability & Management
- [ ] **Audit Logs:** Track all configuration changes (Who, What, When).
- [ ] **Live Dashboard:** Real-time view of active connections and blocked attempts.
