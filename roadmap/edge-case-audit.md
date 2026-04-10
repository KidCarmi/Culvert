# Edge Case Audit — End-User Operator Assessment

> Generated: 2026-04-08
> Assessed by independent agent from a 500-person enterprise operator perspective.
> Code-only audit (no roadmap files consulted).

Here is the comprehensive audit report.

---

## Culvert Enterprise Proxy -- Operator Feature Audit

### 1. BLOCKLIST MANAGEMENT

**Finding 1.1: Config import merges blocklist entries instead of replacing them** ✅ DONE
- Use case: Restore a known-good blocklist from a backup after a misconfiguration.
- Current behavior: `apiConfigImport` (ui.go:1789-1793) iterates `b.Blocklist` and calls `bl.Add(h)` for each entry, then `bl.Save()`. This appends entries to whatever already exists. There is no `bl.Clear()` call before importing.
- Expected behavior: Config import should offer a "replace" mode so an operator can restore an exact snapshot without accumulating stale entries from the current state.
- Severity: **High**
- Category: **Workflow Gap**

**Finding 1.2: No undo for accidental blocklist removals**
- Use case: An operator accidentally removes a critical blocklist domain and wants to undo.
- Current behavior: DELETE on `/api/blocklist` (ui.go:1155+) immediately removes the entry. The only recovery path is config version rollback (`/api/config/versions`), which rolls back ALL configuration, not just the blocklist.
- Expected behavior: Single-resource undo or at minimum a confirmation flow for bulk removals, and the ability to rollback just the blocklist independently.
- Severity: **Medium**
- Category: **UX Gap**

**Finding 1.3: No validation that wildcard blocklist entries are syntactically correct** ✅ DONE
- Use case: Operator adds `*.*.example.com` or `**bad.com` as a wildcard blocklist entry.
- Current behavior: The blocklist POST handler (ui.go:1155+) trims whitespace and length-checks entries but does not validate wildcard syntax. Malformed wildcards are silently stored but may never match.
- Expected behavior: Validate wildcard syntax on input (e.g., only `*.domain.tld` format) and warn the operator if a pattern is unusual.
- Severity: **Low**
- Category: **Edge Case**

**Finding 1.4: Feed sync result not visible after manual trigger** ✅ DONE
- Use case: Operator clicks "Sync Now" for the blocklist feed and wants to know if it succeeded.
- Current behavior: `apiBlocklistFeedSync` (ui.go:1330-1341) fires `go blFeedSyncer.Sync()` asynchronously and immediately returns `{"ok": true}`. There is no mechanism to report sync errors, count of new entries imported, or sync duration back to the UI.
- Expected behavior: Return sync results (entries imported, errors encountered) either synchronously or via an SSE notification.
- Severity: **Medium**
- Category: **UX Gap**

---

### 2. POLICY RULES (PBAC)

**Finding 2.1: Policy tester does not simulate file blocking or SSL inspection path**
- Use case: Operator wants to test whether a request to `https://example.com/file.exe` would be blocked by the file extension profile or subject to SSL inspection.
- Current behavior: `apiPolicyTest` (ui.go:2389-2468) only evaluates PBAC rules (source match, schedule, destination match). It does not check the file blocker, blocklist, threat feeds, or SSL bypass list. The result includes `hostCategory` but omits file-block status, SSL action, and blocklist membership.
- Expected behavior: The tester should simulate the full request pipeline (blocklist, threat feed, file block, policy, SSL action) and report the aggregate outcome.
- Severity: **Medium**
- Category: **Missing Feature**

**Finding 2.2: No duplicate rule name detection** ✅ DONE
- Use case: Operator creates two policy rules named "Block Social Media" at different priorities.
- Current behavior: `validatePolicyRule` (ui.go:914-938) checks name non-empty, valid action, redirect URL safety, and timezone parsing. It does not check for name uniqueness across existing rules.
- Expected behavior: Warn or reject duplicate rule names, since rule names are used as identifiers in logs, audit trail, and the hit counter.
- Severity: **Medium**
- Category: **Edge Case**

**Finding 2.3: Policy hit counters are not persisted across restarts** ✅ DONE
- Use case: Operator reviews policy usage after a proxy restart to identify unused rules for cleanup.
- Current behavior: `PolicyRule.HitCount` is an in-memory counter incremented by `ruleMet.RecordHit()`. It resets to zero on restart.
- Expected behavior: Hit counters should be periodically persisted so operators can make data-driven decisions about rule lifecycle.
- Severity: **Low**
- Category: **Workflow Gap**

**Finding 2.4: No policy rule enable/disable toggle** ✅ DONE
- Use case: Operator wants to temporarily disable a rule during an incident without deleting it.
- Current behavior: Policy rules have no `Enabled` field. The only way to disable a rule is to delete it and re-add it later.
- Expected behavior: An `enabled` boolean field on each rule, with disabled rules skipped during evaluation.
- Severity: **Medium**
- Category: **Missing Feature**

---

### 3. SSL / TLS INSPECTION

**Finding 3.1: No visibility into which requests are being SSL-inspected vs bypassed** ✅ DONE
- Use case: Operator wants to audit how many connections are being inspected versus bypassed, per domain.
- Current behavior: The `LogEntry` struct (store.go:105-118) records status, host, method, rule matched, and action taken but does not record the SSL action (inspect/bypass). The log line in `handleRequest` at proxy.go:438 prints `SSL_BYPASS_PATTERN` to the system log but this is not captured in the structured request log visible in the UI.
- Expected behavior: Include `sslAction` in the `LogEntry` struct so the Live Feed and exports reflect inspection status per request.
- Severity: **High**
- Category: **Missing Feature**

**Finding 3.2: CA rotation force-regenerates without confirmation** ✅ DONE
- Use case: Operator accidentally clicks "Rotate CA" in the UI, invalidating all deployed CA trust across 500 workstations.
- Current behavior: `apiCARotate` (ui.go:3327-3346) calls `certMgr.InitCA()` immediately on POST. There is no confirmation step, dry-run, or cooling-off period.
- Expected behavior: A dangerous operation affecting all endpoints should require explicit confirmation (e.g., two-step with a confirmation token) or at least a mandatory dry-run preview showing impact.
- Severity: **Critical**
- Category: **UX Gap**

**Finding 3.3: Dual-CA overlap expiry is not alertable** ✅ DONE
- Use case: During a CA rotation, the secondary CA overlap window is about to expire and the operator needs to know.
- Current behavior: `apiCAStatus` (ui.go:3268-3294) reports dual-CA status including secondary CA info. But the alert system (`alerts.go`) only has `cert_expiry` as an event type -- there is no specific event for dual-CA overlap window expiring.
- Expected behavior: Fire a `cert_expiry` alert when the dual-CA overlap window is within a configurable threshold of expiry.
- Severity: **Medium**
- Category: **Missing Feature**

---

### 4. SECURITY SCANNING (ClamAV / YARA / Threat Feeds)

**Finding 4.1: Brotli-compressed responses are not decompressed for scanning** ✅ DONE
- Use case: A malware payload is delivered via brotli-compressed HTTP response (increasingly common with CDNs).
- Current behavior: `decompressForScan` (security_scan.go:182-220) handles gzip and deflate but returns raw bytes for brotli (`ce == "br"` at line 198), meaning ClamAV and YARA signatures will not match the decompressed content.
- Expected behavior: Decompress brotli content before scanning. The code has a TODO comment acknowledging this gap.
- Severity: **High**
- Category: **Bug**

**Finding 4.2: Large responses bypass scanning silently** ✅ DONE
- Use case: A 10 MB malware executable is downloaded through the proxy.
- Current behavior: `SecurityScanner.maxBytes` defaults to 5 MiB (security_scan.go:74). Responses exceeding this are forwarded unscanned. There is no log entry or alert when this happens.
- Expected behavior: Log a warning when a response exceeds the scan buffer limit, and optionally block oversized responses in strict mode. The operator should be able to see how often this occurs.
- Severity: **High**
- Category: **Workflow Gap**

**Finding 4.3: No way to update ClamAV virus definitions from the UI**
- Use case: Operator wants to trigger a freshclam update or verify definition currency.
- Current behavior: The UI shows ClamAV status (connected/unreachable) via `secScanStatusMap()` (security_scan.go:401-442) but has no endpoint to trigger definition updates or display definition version/date.
- Expected behavior: Display ClamAV definition version and date, and optionally provide a trigger for freshclam.
- Severity: **Medium**
- Category: **Missing Feature**

**Finding 4.4: Scan cache has no manual purge mechanism** ✅ DONE
- Use case: A false positive is cached and the operator wants to force a re-scan of a specific hash.
- Current behavior: The hash cache exposes `Stats()` but there is no API endpoint to evict a specific hash or clear the entire cache. Only `cache_size`, `cache_hits`, and `cache_misses` are shown in the status.
- Expected behavior: Provide an API endpoint to purge a specific hash or the entire scan cache.
- Severity: **Medium**
- Category: **Missing Feature**

---

### 5. USER / AUTH MANAGEMENT

**Finding 5.1: No password reset workflow for locked-out admin** ✅ DONE
- Use case: The sole admin account is locked out (5 failed attempts, 15 min lockout) and no other admin exists.
- Current behavior: `loginLimiter` (lockout.go) locks accounts in memory for 15 minutes. The lockout is not persisted (restart clears it). There is no password reset endpoint, no "forgot password" flow, and no CLI command to reset credentials. The only recovery is restarting the proxy process.
- Expected behavior: Provide a CLI command (`culvert reset-password`) or a recovery token mechanism for admin lockout scenarios.
- Severity: **High**
- Category: **Workflow Gap**

**Finding 5.2: Deleting a user does not revoke their active sessions** ✅ DONE
- Use case: An operator account is deleted by an admin; the deleted user still has an active browser session.
- Current behavior: `apiAuthUsers` DELETE (ui.go:744-761) calls `cfg.DeleteUIUser(username)` and `cfg.SaveUIUsersFile()`. There is no call to revoke sessions for that username. The HMAC-signed session cookie will remain valid until it naturally expires (default 8 hours).
- Expected behavior: Deleting a user should immediately revoke all their active sessions.
- Severity: **High**
- Category: **Bug**

**Finding 5.3: No password complexity requirements beyond minimum length** ✅ DONE
- Use case: An admin sets a user's password to "12345678" (8 chars, meeting the minimum).
- Current behavior: `apiAuthUsers` POST (ui.go:725-726) checks `len(body.Password) < 8` only. No uppercase, lowercase, digit, or special character requirements.
- Expected behavior: Enforce configurable password complexity (at a minimum: mixed case + digit) or integrate with a well-known strength estimator.
- Severity: **Medium**
- Category: **UX Gap**

**Finding 5.4: No user self-service password change** ✅ DONE
- Use case: An operator wants to change their own password without asking an admin.
- Current behavior: Password changes require admin role (`RoleAdmin` check at ui.go:707-710 on the GET, 708 on POST). Operators and viewers cannot change their own passwords.
- Expected behavior: Allow authenticated users to change their own password via a self-service endpoint.
- Severity: **Medium**
- Category: **Missing Feature**

---

### 6. LOGS AND AUDIT

**Finding 6.1: Request log limited to 1,000 entries in memory with no persistent search** ✅ DONE
- Use case: Investigating a security incident that happened 3 hours ago on a busy proxy serving 500 users.
- Current behavior: `maxLogs = 1000` (store.go:133). At high traffic (e.g., 100 req/min), the log buffer rolls over in ~10 minutes. There is no persistent request log storage or external search integration. The `/api/export` endpoint exports only what is currently in the ring buffer.
- Expected behavior: For a 500-user deployment, provide persistent request log storage with configurable retention and searchable history (e.g., SQLite or log file with indexing). Alternatively, ensure syslog integration captures request-level detail.
- Severity: **Critical**
- Category: **Missing Feature**

**Finding 6.2: Audit log limited to 500 entries in memory** ✅ DONE
- Use case: Compliance review requires 90 days of configuration change history.
- Current behavior: `maxAuditLogs = 500` (store.go:180). The JSONL file persistence (`auditLogFile`) stores all entries to disk but the UI API (`apiAudit`, ui.go:892-902) only returns the in-memory ring buffer (`auditGet()`), not the full file contents.
- Expected behavior: The audit API should support pagination over the persistent JSONL file, not just the in-memory buffer. For compliance, the full audit history must be queryable.
- Severity: **Critical**
- Category: **Bug**

**Finding 6.3: No date range filtering on logs or audit** ✅ DONE
- Use case: Operator wants to see all blocked requests from yesterday between 2pm and 4pm.
- Current behavior: `apiLogs` (ui.go:1044-1076) supports filtering by host, status, level, method, and identity but not by timestamp range. `apiAudit` (ui.go:892-902) returns all in-memory entries with no filtering at all.
- Expected behavior: Support `from` and `to` timestamp parameters on both log and audit endpoints.
- Severity: **High**
- Category: **Missing Feature**

**Finding 6.4: CSV export missing fields** ✅ DONE
- Use case: Exporting request logs for SIEM ingestion.
- Current behavior: `apiExport` CSV (ui.go:2587-2595) exports only: timestamp, time, ip, method, host, status. The `identity`, `ruleMatched`, `actionTaken`, `bytesSent`, `bytesRecv`, and `level` fields present in `LogEntry` are omitted from the CSV.
- Expected behavior: Export all fields in the LogEntry struct.
- Severity: **Medium**
- Category: **Bug**

---

### 7. CLUSTER / HIGH AVAILABILITY

**Finding 7.1: No automatic failover for control plane failure**
- Use case: The control plane node crashes; data plane nodes need to keep operating.
- Current behavior: The cluster architecture uses CP/DP gRPC connectivity. The HA configuration is documented as available via admin GUI (`apiClusterHA`). However, the HA status endpoint is a GET-only read. The actual failover mechanism relies on a standby CP that must be pre-enrolled with `--ha-join`/`--ha-token` CLI flags. If the standby is not set up, DP nodes operate on their last-known config but there is no automatic CP election.
- Expected behavior: Document clearly in the UI that HA requires explicit standby setup, and show a prominent warning when HA is not configured in a cluster deployment.
- Severity: **High**
- Category: **UX Gap**

**Finding 7.2: No cluster-wide log aggregation in the UI**
- Use case: Investigating a request that may have hit any of the 5 data plane nodes.
- Current behavior: The `/api/cluster/audit` endpoint provides centralized audit log. But there is no equivalent for the request log -- each node's 1,000-entry ring buffer is isolated. An operator must check each node individually.
- Expected behavior: Aggregate request logs across cluster nodes or provide a central query mechanism.
- Severity: **High**
- Category: **Missing Feature**

---

### 8. ALERTING / WEBHOOKS

**Finding 8.1: No alert delivery history visible in UI** ✅ DONE
- Use case: Operator wants to verify that the alert for a threat detection was delivered to Slack.
- Current behavior: `apiAlertsWebhooks` (ui.go:1412-1488) supports CRUD and test-fire. The retry queue is persisted to `/data/alert_retry_queue.json`. But there is no API endpoint to list delivery history, failed deliveries, or retry status.
- Expected behavior: Expose alert delivery history (last N deliveries with status, timestamp, retry count) via API and UI.
- Severity: **Medium**
- Category: **Missing Feature**

**Finding 8.2: Webhook test fires asynchronously with no result feedback** ✅ DONE
- Use case: Operator tests a new Slack webhook to verify it works.
- Current behavior: `apiAlertsWebhookTest` (ui.go:1491-1518) calls `go deliverWebhook(...)` and immediately returns `{"ok": true}` regardless of whether delivery succeeds.
- Expected behavior: Either deliver synchronously with a timeout or report the delivery result back to the UI.
- Severity: **Medium**
- Category: **UX Gap**

**Finding 8.3: No alert for scan timeout events** ✅ DONE
- Use case: ClamAV is overloaded and body scans are timing out, causing fail-closed blocks.
- Current behavior: `ScanBody` (security_scan.go:258-260) logs a warning and caches the timeout result but does not fire an alert. The alert event types in `alerts.go` are: `threat_detected`, `policy_block`, `auth_lockout`, `cert_expiry`, `cluster_updated`, `cluster_update_halted`. There is no `scan_timeout` or `scan_error` event.
- Expected behavior: Fire an alert when scan timeouts exceed a threshold, indicating infrastructure issues.
- Severity: **Medium**
- Category: **Missing Feature**

---

### 9. UPDATES / SELF-UPDATE

**Finding 9.1: Update rollback has no pre-check for data compatibility**
- Use case: Rolling back from v2.1 to v2.0 after a failed update, but v2.1 migrated the config schema.
- Current behavior: `apiUpdateRollback` proxies to the updater sidecar on `:7123`. The updater handles the Docker image swap but there is no pre-flight check for config schema compatibility in the rollback path (unlike config version rollback which has `DryRun` mode).
- Expected behavior: The rollback should verify that the target version can read the current config/data files, or at minimum warn the operator.
- Severity: **Medium**
- Category: **Edge Case**

**Finding 9.2: No notification when background version check finds an update** ✅ DONE
- Use case: A critical security update is available and the operator should be proactively notified.
- Current behavior: The background version check runs every 6 hours (update.go) and stores the result. The UI dashboard shows the status when the operator visits. But there is no alert/webhook fired when a new version is detected.
- Expected behavior: Fire an alert (new event type `update_available`) when the background check finds a newer version.
- Severity: **Medium**
- Category: **Missing Feature**

---

### 10. CONFIGURATION MANAGEMENT

**Finding 10.1: Config version rollback is all-or-nothing**
- Use case: Operator wants to restore just the policy rules from version N-3 without touching the blocklist or SSL bypass settings.
- Current behavior: `captureConfigBackup` in configversion.go snapshots blocklist, policy, rewrite, SSL bypass, DPI patterns, file block, IP filter, and rate limit all together. Rollback restores the entire snapshot atomically.
- Expected behavior: Support selective rollback by subsystem (e.g., "restore only policy rules from version 5").
- Severity: **Medium**
- Category: **Workflow Gap**

**Finding 10.2: Maximum 50 config versions with oldest pruning**
- Use case: After a busy day of policy changes, the operator wants to review the state from two weeks ago.
- Current behavior: `maxConfigVersions = 50` (configversion.go). With frequent changes across multiple subsystems, 50 versions may cover only a few days. Pruning removes the oldest versions first.
- Expected behavior: Allow configurable retention count or time-based retention. Consider pinning important versions.
- Severity: **Low**
- Category: **Workflow Gap**

**Finding 10.3: Config export does not include URL categories, IdP profiles, or alert webhooks** ✅ DONE
- Use case: Migrating from a standalone instance to a new cluster setup.
- Current behavior: `configBackup` struct (used by apiConfigExport/apiConfigImport) contains: blocklist, blocklist mode, policy rules, default action, rewrite rules, SSL bypass, content scan patterns, file block extensions, IP filter mode/list, rate limit RPM. Notably missing: URL categories, IdP profiles, PAC configuration, alert webhooks, syslog config, GeoIP settings, connection limits, block page template, upstream proxy config.
- Expected behavior: The backup/restore should cover all configurable subsystems for complete disaster recovery.
- Severity: **High**
- Category: **Missing Feature**

---

### 11. NETWORK EDGE CASES

**Finding 11.1: WebSocket connections bypass body scanning and policy file filtering**
- Use case: Malware uses WebSocket tunneling to exfiltrate data.
- Current behavior: `handleRequest` (proxy.go:445-446) checks `isWebSocketUpgrade(r)` and routes to `handleWebSocket()`, a raw TCP bridge. The WebSocket path does not pass through body scanning, file blocking, or content inspection.
- Expected behavior: At minimum log WebSocket connections with their duration and bytes transferred. Optionally support message-level inspection for text frames.
- Severity: **Medium**
- Category: **Edge Case**

**Finding 11.2: DNS resolution failures are fail-closed with no operator notification** ✅ DONE
- Use case: Internal DNS is flaky, causing legitimate requests to be blocked by SSRF check.
- Current behavior: `isPrivateHost` (proxy.go:111-117) returns an error when DNS resolution fails ("DNS resolution failed"), which causes the request to be rejected. DNS errors are not cached (correctly), but there is no metric or alert for DNS failure rates.
- Expected behavior: Track DNS resolution failure rate and alert when it exceeds a threshold, as this could indicate infrastructure issues rather than actual SSRF.
- Severity: **Medium**
- Category: **Missing Feature**

**Finding 11.3: IPv6 addresses in IP filter and rate limiter**
- Use case: Enterprise network uses IPv6 internally and operators need to filter/rate-limit by IPv6 address.
- Current behavior: `privateCIDRs` (proxy.go:64-83) includes IPv6 ranges (::1/128, fc00::/7, fe80::/10). IP filtering and rate limiting accept CIDRs. However, the same client connecting via IPv4 and IPv6 would have separate rate-limit buckets and connection-limit counters, potentially doubling their effective limits.
- Expected behavior: Document this behavior. Consider optional IPv4/IPv6 grouping for dual-stack environments.
- Severity: **Low**
- Category: **Edge Case**

---

### 12. MONITORING / DASHBOARD

**Finding 12.1: Time-series data limited to 60 minutes with 1-minute granularity**
- Use case: Operator wants to see traffic patterns over the last 24 hours or the last week.
- Current behavior: `timeSeries` (store.go:38-101) maintains a 60-bucket ring buffer. Each bucket is one minute. The dashboard shows "last 60 minutes" only.
- Expected behavior: Provide multiple time windows (1h, 24h, 7d) or export historical data for external dashboarding.
- Severity: **Medium**
- Category: **Missing Feature**

**Finding 12.2: Dashboard does not auto-refresh threat feed sync status**
- Use case: Operator is waiting for a threat feed sync to complete after clicking "Sync Now."
- Current behavior: The SSE `/api/events` endpoint pushes stat updates but the threat feed sync status (last_sync timestamp, entry count) requires a manual refresh of the Security Scanning panel.
- Expected behavior: Push threat feed sync completion events via SSE so the UI updates automatically.
- Severity: **Low**
- Category: **UX Gap**

**Finding 12.3: No per-user traffic summary**
- Use case: Investigating which user is consuming the most bandwidth or hitting the most blocked sites.
- Current behavior: The `LogEntry` struct includes `Identity` and `BytesSent`/`BytesRecv`, but there is no aggregation endpoint. The dashboard shows `topHosts` but not top users.
- Expected behavior: Provide a top-users endpoint that aggregates request count and bytes by identity.
- Severity: **Medium**
- Category: **Missing Feature**

---

### 13. FILE BLOCKING

**Finding 13.1: File blocking is extension-based only, no MIME type verification** ✅ DONE
- Use case: An attacker renames `malware.exe` to `malware.txt` to bypass extension-based blocking.
- Current behavior: `fileBlocker.CheckPath` (fileblock.go) checks the file extension in the URL path. `fileBlocker.CheckContentDisposition` checks the Content-Disposition header filename. Neither inspects the actual response body MIME type or magic bytes.
- Expected behavior: For defense-in-depth, optionally verify the response Content-Type header against the extension, or use magic byte detection for high-risk MIME types.
- Severity: **High**
- Category: **Missing Feature**

**Finding 13.2: File blocking check happens before upstream request for URL path, but Content-Disposition check timing is unclear** ✅ DONE
- Use case: A file download URL like `/download?id=123` has no extension in the path but serves `Content-Disposition: attachment; filename="payload.exe"`.
- Current behavior: The URL path check happens in `handleRequest` (proxy.go:345-354) before the upstream request. The Content-Disposition check must happen after the response is received. Both paths exist but the response-phase check depends on body scanning being enabled (`bodyNeedsBuffering`).
- Expected behavior: Clearly document that Content-Disposition checking requires body scanning to be active, and warn in the UI if file blocking is enabled but body scanning is disabled.
- Severity: **Medium**
- Category: **Edge Case**

---

### 14. REWRITE RULES

**Finding 14.1: All matching rewrite rules execute, not first-match**
- Use case: Two rewrite rules match the same host with conflicting header mutations (one sets `X-Custom: A`, another sets `X-Custom: B`).
- Current behavior: Rewrite rules (rewrite.go) apply in order, and all matching rules execute. The last matching rule's "set" operation wins for the same header name.
- Expected behavior: This is documented behavior but the UI does not warn about conflicting rules. A conflict detection mechanism or at minimum a visual indicator would prevent operator confusion.
- Severity: **Low**
- Category: **UX Gap**

**Finding 14.2: No rewrite rule test/preview**
- Use case: Operator wants to verify a new rewrite rule before deploying it to production traffic.
- Current behavior: There is no equivalent of `apiPolicyTest` for rewrite rules. The operator must add the rule and test with live traffic.
- Expected behavior: A dry-run endpoint that accepts a sample request and shows what headers would be added/removed/modified.
- Severity: **Low**
- Category: **Missing Feature**

---

### 15. GeoIP

**Finding 15.1: No GeoIP database update mechanism in the UI**
- Use case: The MaxMind GeoLite2 database is 6 months old and needs updating.
- Current behavior: `apiGeoIPConfig` (ui.go:3405-3413) is a read-only GET that returns `enabled` and `dbPath`. There is no endpoint to upload a new database or trigger a download.
- Expected behavior: Provide an upload endpoint for new .mmdb files, or a download trigger if a MaxMind license key is configured.
- Severity: **Medium**
- Category: **Missing Feature**

**Finding 15.2: GeoIP failure is silent in policy evaluation**
- Use case: A policy rule blocks traffic to country "RU" but the GeoIP database is missing.
- Current behavior: GeoIP is fail-open (geoip.go): when the database is missing, `geo.Lookup()` returns empty string, so country-based policy conditions silently never match. There is no warning in the policy tester or dashboard.
- Expected behavior: When a policy rule references a country condition but GeoIP is disabled, show a warning in the policy editor and the policy tester results.
- Severity: **Medium**
- Category: **UX Gap**

---

### 16. RATE LIMITING

**Finding 16.1: No rate limit whitelist / exemption capability** ✅ DONE
- Use case: An internal monitoring system polls through the proxy at high frequency and should not be rate-limited.
- Current behavior: Rate limiting (`rl.AllowAuto(clientIP)` at proxy.go:201) applies uniformly to all client IPs. There is no exemption list. IP filter allowlist is a separate mechanism (allows/blocks at the IP level, not rate-limit exemption).
- Expected behavior: Allow specific IPs or CIDRs to be exempted from rate limiting.
- Severity: **High**
- Category: **Missing Feature**

**Finding 16.2: Rate limit is global per-IP, not per-rule or per-policy**
- Use case: Different user groups should have different rate limits (e.g., developers get 200 req/min, general staff get 60 req/min).
- Current behavior: The rate limiter is a single global per-IP limit configured via `security.rate_limit` in config or the Security API. Policy rules do not have per-rule rate-limit fields.
- Expected behavior: Support per-policy or per-group rate limits for differentiated service levels.
- Severity: **Medium**
- Category: **Missing Feature**

---

### 17. SYSLOG / SIEM INTEGRATION

**Finding 17.1: Syslog configuration changes take effect immediately with no test option** ✅ DONE
- Use case: Operator enters a syslog address and wants to verify connectivity before committing.
- Current behavior: `apiSyslogConfig` POST (ui.go:1970-2008) calls `InitSyslog(body.Addr, body.Format)` which immediately attempts connection. If it fails, an error is returned. But there is no "test" button that verifies connectivity without replacing the current config.
- Expected behavior: Add a test endpoint that validates connectivity without changing the active syslog configuration.
- Severity: **Low**
- Category: **UX Gap**

**Finding 17.2: Request-level log entries are not forwarded to syslog** ✅ DONE
- Use case: SIEM team wants all proxy request logs (not just audit events) forwarded via syslog for correlation.
- Current behavior: The syslog integration (syslog.go) forwards audit events at severity=5 as JSON. System log lines are forwarded via the logger. But individual `LogEntry` records (the structured request log with IP, identity, host, status) are not explicitly forwarded as syslog messages.
- Expected behavior: Optionally forward request log entries (especially blocked/threat events) as individual syslog messages in a structured format.
- Severity: **Medium**
- Category: **Missing Feature**

---

### 18. PAC FILE

**Finding 18.1: PAC file auto-detect relies on request Host header** ✅ DONE
- Use case: Proxy is behind a load balancer and the Host header does not reflect the correct proxy address.
- Current behavior: PAC file generation auto-detects the proxy host from the request. When behind a load balancer or NAT, the detected address may be incorrect (e.g., internal hostname instead of external).
- Expected behavior: Allow explicit configuration of the proxy address used in PAC file generation, not just auto-detection. The `base_url` config option exists but it is not clear if it feeds into PAC generation.
- Severity: **Medium**
- Category: **Edge Case**

**Finding 18.2: PAC file changes are not versioned** ✅ DONE
- Use case: An operator modifies PAC exclusions and later wants to see what changed.
- Current behavior: PAC configuration is persisted to a JSON file. But PAC config is NOT included in `captureConfigBackup` (configversion.go), so PAC changes are not captured by the config versioning system and cannot be rolled back.
- Expected behavior: Include PAC configuration in config versioning snapshots.
- Severity: **Medium**
- Category: **Bug**

---

### 19. URL CATEGORIES

**Finding 19.1: Category host limit of 10,000 may be insufficient for enterprise use**
- Use case: Operator imports a commercial URL categorization feed with millions of entries.
- Current behavior: `apiURLCat` POST (ui.go:1548-1549) rejects categories with more than 10,000 hosts: `"category cannot contain more than 10000 hosts"`.
- Expected behavior: For enterprise deployments, this limit should be configurable. 10,000 hosts across a small number of categories is reasonable but a single "Adult" category feed could easily exceed this.
- Severity: **Medium**
- Category: **Edge Case**

**Finding 19.2: No URL category feed auto-sync**
- Use case: Operator wants URL categories to auto-update from a community feed (similar to blocklist feed sync).
- Current behavior: URL categories are manually managed via the UI CRUD API. There is no feed sync mechanism for categories (unlike the blocklist which has `blFeedSyncer`).
- Expected behavior: Support auto-sync from external URL category feeds.
- Severity: **Medium**
- Category: **Missing Feature**

---

### 20. GENERAL UX

**Finding 20.1: No confirmation dialog for destructive bulk operations**
- Use case: Operator accidentally triggers "Clear All" on the blocklist or deletes multiple policy rules.
- Current behavior: The UI's `confirmAction()` function provides a generic confirmation modal. However, the confirmation does not show the scope of impact (e.g., "This will remove 1,247 blocklist entries").
- Expected behavior: Destructive operations should display the count/scope of affected items in the confirmation dialog.
- Severity: **Medium**
- Category: **UX Gap**

**Finding 20.2: Session timeout is global, not per-role**
- Use case: Admin sessions should have a shorter timeout (1 hour) than viewer sessions (8 hours).
- Current behavior: `SessionTimeoutHours` (config.go:107) is a single value applied to all sessions regardless of role. Configurable between 1-168 hours.
- Expected behavior: Allow per-role session timeouts (shorter for admin, longer for viewer).
- Severity: **Low**
- Category: **Missing Feature**

**Finding 20.3: UI rate limiter applies uniformly to all API mutations**
- Use case: An automated script legitimately making rapid policy changes is throttled.
- Current behavior: `securityMiddleware` (ui.go:380-389) applies `apiLimiter.Allow(ip)` to all mutating API requests uniformly. The rate limit applies per-IP across all endpoints -- a burst of blocklist additions counts against policy changes.
- Expected behavior: Either document the API rate limit clearly or provide per-endpoint rate limits, with an exemption mechanism for automation.
- Severity: **Low**
- Category: **Edge Case**

**Finding 20.4: No dark/light theme preference persistence across sessions** ✅ DONE
- Use case: Operator prefers dark theme but it resets on every login.
- Current behavior: The theme toggle exists in the UI (index.html) but uses `localStorage` which persists per-browser. This is actually fine for single-browser use but there is no server-side preference stored with the user profile.
- Expected behavior: For environments where operators use multiple workstations, store theme preference server-side in the user profile.
- Severity: **Low**
- Category: **UX Gap**

---

### SUMMARY OF FINDINGS BY SEVERITY

| Severity | Total | Done | Remaining |
|----------|-------|------|-----------|
| Critical | 3     | 2    | 1         |
| High     | 11    | 10   | 1         |
| Medium   | 24    | 11   | 13        |
| Low      | 10    | 3    | 7         |
| **Total**| **48**| **26** | **22**  |

### COMPLETED FINDINGS (26/48)

- 1.1 Config import replace mode ✅
- 1.3 Wildcard blocklist validation ✅
- 2.2 Duplicate rule name detection ✅
- 2.4 Policy rule enable/disable toggle ✅
- 3.1 SSL inspection status in request log ✅
- 3.2 CA rotation confirmation step ✅
- 3.3 Dual-CA overlap expiry alert ✅
- 4.1 Brotli decompression for scanning ✅
- 4.2 Large response scan skip alert ✅
- 4.4 Scan cache manual purge ✅
- 5.1 Password reset workflow ✅
- 5.2 User deletion revokes sessions ✅
- 5.4 User self-service password change ✅
- 6.2 Audit log persistent file API ✅
- 6.3 Date range filtering on logs/audit ✅
- 6.4 CSV export all fields ✅
- 8.1 Alert delivery history ✅
- 8.2 Webhook test sync delivery ✅
- 8.3 Scan timeout alert ✅
- 9.2 Update available alert ✅
- 10.3 Config export expanded ✅
- 13.2 Content-Disposition check timing ✅
- 16.1 Rate limit whitelist/exemption ✅
- 18.1 PAC file explicit proxy address ✅
- 18.2 PAC config versioning ✅
- 20.4 Theme preference persistence ✅

### CRITICAL FINDINGS REMAINING

1. **Request log limited to 1,000 entries (6.1)** -- At enterprise scale, this makes incident response impossible. The log rolls over in minutes during peak traffic.

### HIGH FINDINGS REMAINING

1. File blocking is extension-only, no MIME verification (13.1)

### NOTE: Previously listed as HIGH, now resolved
- ~~Config import merges instead of replaces (1.1)~~ ✅
- ~~No SSL inspection status in request log (3.1)~~ ✅
- ~~Brotli decompression gap in security scanning (4.1)~~ ✅
- ~~Large responses bypass scanning silently (4.2)~~ ✅
- ~~No password reset workflow for locked-out admin (5.1)~~ ✅
- ~~Deleting a user does not revoke active sessions (5.2)~~ ✅
- ~~No date range filtering on logs or audit (6.3)~~ ✅
- ~~No rate limit whitelist/exemption (16.1)~~ ✅
- ~~Config export missing major subsystems (10.3)~~ ✅
