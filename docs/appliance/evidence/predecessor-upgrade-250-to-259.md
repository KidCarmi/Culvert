# Predecessor upgrade qualification — v1.0.250 → v1.0.259 → v1.0.250

**Verdict: PASS** — 55 assertions passed, 0 failed, across three boots of ONE state root.

Executed on 2026-10-02 against the REAL published linux/amd64 release binaries (GitHub Releases), not synthetic builds.
Driver: `test/appliance/predecessor-upgrade.sh` (this commit). Every process was started with its PID recorded and stopped by that exact PID.

## Environment

- worktree: `/home/user/Culvert/.claude/worktrees/agent-ad18042642914dee6` (branch `worktree-agent-ad18042642914dee6`, base commit `3fcc07e (Merge pull request #1525 from KidCarmi/codex/repair-frontend-audit)`)
- host: Linux 6.18.44-fc-v51 (container, root), python3 3.11.15, curl, bash; no Docker
- state root: `/tmp/claude-0/-home-user-Culvert/cf36caf0-214a-5d31-ba4b-95168e4ca302/scratchpad/predecessor/run-250-259/state` (fresh, empty before leg A; `CULVERT_DATA_DIR` points at it, `CULVERT_CA_PASSPHRASE=test-passphrase` so the CA bundle is encrypted as on a real install)
- ports: proxy `20300`, admin UI `20301` (https, self-signed, `-k`), allowed origin `127.0.0.1:20302` (`python3 -m http.server`), credentialed parent proxy `127.0.0.1:20303`, unmatched origin `127.0.0.1:20304`
- proxy env caveat: admin-API calls use `--noproxy '*'`; proxied requests clear `*_proxy`/`no_proxy` from the environment (with `--noproxy '*'` curl bypasses the `-x` proxy under test as well — observed during development, hence the split)

### Binaries (sha256)

| role | file | sha256 | reports |
|---|---|---|---|
| FROM | `culvert-linux-amd64-v1.0.250` | `49484d95e92904e01bdd74b3a812533ae9c8adfe8e4bcd77407a44a500fc7760` | `v1.0.250` (/healthz and /ready) |
| TO | `culvert-linux-amd64-v1.0.259` | `3ba95443374ea7bbf1b8d1fe826089267414a3de93e6b51f1081a99c9bb0b5a0` | `v1.0.259` (/healthz and /ready) |
| FROM maint agent (not executed — host-root component with no state-root involvement; recorded for the release pair) | `culvert-maint-linux-amd64-v1.0.250` | `6cbd4e3a6afa8c764d389cc06d62eb6e8ccf9ec9df1e985d312228d10cc0c20b` | — |
| TO maint agent (not executed) | `culvert-maint-linux-amd64-v1.0.259` | `ed499b2abd6c0e58b82cac24a8afcec9242adec27e6f5bd3c58add9d97ec8cc5` | — |

## Command

```bash
PORT_BASE=20300 ./test/appliance/predecessor-upgrade.sh \
  /tmp/claude-0/artifacts/culvert-linux-amd64-v1.0.250 \
  /tmp/claude-0/artifacts/culvert-linux-amd64-v1.0.259 \
  /tmp/claude-0/-home-user-Culvert/cf36caf0-214a-5d31-ba4b-95168e4ca302/scratchpad/predecessor/run-250-259/state \
  /tmp/claude-0/-home-user-Culvert/cf36caf0-214a-5d31-ba4b-95168e4ca302/scratchpad/predecessor/run-250-259/evidence
# exit status 0 (verdict PASS)
```

Each boot used the compose-equivalent flag set:

```
CULVERT_DATA_DIR=<root> CULVERT_CA_PASSPHRASE=test-passphrase <binary> -port 20300 -ui-port 20301 \
  -ca-path <root>/ca.bundle -policy <root>/policy.json -ui-users-file <root>/ui_users.json \
  -audit-log <root>/audit.jsonl -request-log <root>/requests.jsonl -logfile <root>/proxy.log \
  -revocations-file <root>/revocations.json -idp-profiles-file <root>/idp_profiles.json -fileprofiles-file <root>/fileprofiles.json
```

## Processes

- allowed origin pid 10618 (127.0.0.1:20302), unmatched origin pid 10619 (127.0.0.1:20304), parent proxy pid 10620 (127.0.0.1:20303)
- `A-from`: pid 10653 — exited after SIGTERM (see `*.sigterm_exit` rows)
- `B-to`: pid 11027 — exited after SIGTERM (see `*.sigterm_exit` rows)
- `C-from-again`: pid 11392 — exited after SIGTERM (see `*.sigterm_exit` rows)
- after the run: `ps -eo pid,args | grep -E 'culvert-linux|http.server|parent_proxy'` → no leftover processes

## Seeded state (leg A, FROM)

Exact admin-API calls and answers, in order (secrets redacted by the script; bodies trimmed to 300 chars):

```
GET /api/setup/status -> 200 {"needsSetup":true,"ui_tls_fallback":false}
POST /api/setup/complete {user,pass} -> 200 {"ok":true}
POST /api/auth/login -> 200 {"ok":true,"role":"admin","user":"admin"}
POST /api/default-action {"action":"deny"} -> 200 {"defaultAction":"deny"}
POST /api/policy -> 200 {"priority":10,"name":"allow-local-origin","sourceIP":"","sourceIdentity":"","sourceGroup":"","authSource":"","destFQDN":"localhost","destCategory":"","destCategoryGroup":"","destCountry":null,"sslAction":"","fileFiltering":false,"fileProfile":"","logFullUri":false,"tlsSkipVerify":false,"action":"Al…
POST /api/upstream/entries -> 201 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","entries":1,"eligible":1,"fallbackTotal":…
POST /api/upstream/entries/01M3Y0XEXPJ7BJ29MHFED1M4RR/credential {action:replace,password:<redacted>,revision:1} -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","entries":1,"eligible":1,"fallbackTotal":…
GET /api/upstream -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","entries":1,"eligible":1,"fallbackTotal":…
POST /api/alerts/webhooks {…,secret:<redacted>} -> 200 {"id":"1790935219368406746","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}
GET /api/alerts/webhooks -> 200 {"webhooks":[{"id":"1790935219368406746","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}]}
GET /api/config/versions -> 200 [{"version":2,"created_at":"2026-10-02T10:00:19Z","actor":"admin","action":"policy.add"},{"version":1,"created_at":"2026-10-02T10:00:18Z","actor":"admin","action":"policy.default_action"}]
```

Request bodies used: `{"user":"admin","pass":"<strong>"}` (setup + login), `{"action":"deny"}`, `{"name":"allow-local-origin","priority":10,"destFQDN":"localhost","action":"Allow","enabled":true}` (note the capitalised `Allow` — the engine rejects lowercase `allow` with 400 `action must be Allow, Drop, Block_Page, or Redirect`), `{"scheme":"http","host":"127.0.0.1","port":20303,"username":"parentuser","revision":1}`, `{"action":"replace","password":"<parent password>","revision":1}`, `{"name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true,"secret":"<secret>"}`.

`audit.jsonl` after leg A (file tail, verbatim; the rule's `after` blob is the full rule JSON):

```
{"ts":1790935218823,"time":"2026-10-02 10:00:18","actor":"127.0.0.1","action":"setup.complete","object":"admin","detail":"first-time admin password configured"}
{"ts":1790935218940,"time":"2026-10-02 10:00:18","actor":"admin@127.0.0.1","action":"auth.login","object":"admin","detail":"admin UI login role=admin"}
{"ts":1790935218988,"time":"2026-10-02 10:00:18","actor":"admin@127.0.0.1","action":"policy.default_action","object":"deny","detail":""}
{"ts":1790935219057,"time":"2026-10-02 10:00:19","actor":"admin@127.0.0.1","action":"policy.add","object":"allow-local-origin","objectId":"01M3Y0XEVFVC44D18CB0Q5CZ4D","detail":"priority=10 action=Allow","after":"{\"priority\":10,\"name\":\"allow-local-origin\",\"sourceIP\":\"\",\"sourceIdentity\":\"\",\"sourceGroup\":\"\",\"authSource\":\"\",\"destFQDN\":\"localhost\",\"destCategory\":\"\",\"destC…
{"ts":1790935219128,"time":"2026-10-02 10:00:19","actor":"admin@127.0.0.1","action":"upstream.entry.create","object":"01M3Y0XEXPJ7BJ29MHFED1M4RR","detail":"authority=http://parentuser@127.0.0.1:20303"}
{"ts":1790935219228,"time":"2026-10-02 10:00:19","actor":"admin@127.0.0.1","action":"upstream.credential.replace","object":"01M3Y0XEXPJ7BJ29MHFED1M4RR","detail":"authority=http://parentuser@127.0.0.1:20303"}
{"ts":1790935219369,"time":"2026-10-02 10:00:19","actor":"admin@127.0.0.1","action":"alert.webhook.create","object":"1790935219368406746","detail":"https://siem.example.invalid/culvert-hook"}
```

## Assertions

Legend: A = FROM on a fresh root, B = TO on the same root (upgrade), C = FROM again on the same root (reverse leg / downgrade tolerance). `enforce.*` rows are the SAME three proxied requests on every leg.

| leg | status | check | detail |
|---|---|---|---|
| A | PASS | `A-from.ready` | /ready answered 200 (pid 10653) |
| A | INFO | `A.version` | /healthz version=v1.0.250 /ready version=v1.0.250 |
| A | PASS | `A.setup_status_needs_setup` | got true |
| A | PASS | `A.setup_complete_200` | got 200 |
| A | PASS | `A.login_200` | got 200 |
| A | PASS | `A.default_action_set_deny` | got deny |
| A | PASS | `A.allow_rule_created` | id=01M3Y0XEVFVC44D18CB0Q5CZ4D destFQDN=localhost action=Allow |
| A | PASS | `A.upstream_entry_created` | id=01M3Y0XEXPJ7BJ29MHFED1M4RR authority=http://parentuser@127.0.0.1:20303 revision=1 |
| A | PASS | `A.upstream_credential_sealed` | got configured |
| A | INFO | `A.upstream_health` | health= {'status': 'unprobed', 'reason': 'none'} eligible= True mode= chained key= {'state': 'present', 'keyId': '12cb6f5553151325'} |
| A | PASS | `A.webhook_created` | id=1790935219368406746 |
| A | PASS | `A.webhook_not_signing_degraded` | got False |
| A | PASS | `A.config_version_autocreated` | 2 version(s): ['policy.add', 'policy.default_action'] |
| A | INFO | `A.admin_settings_schema` | admin_settings_schema=2 keys=43 |
| A | INFO | `A.ca_bundle_sha` | c27d3c28b2ff7c581ce5ff68e3be6e70a1d2c73c668d5f5a57ac9be16a7c0773 |
| A | PASS | `enforce.allowed_origin_with_credentials_200` | got 200 |
| A | PASS | `enforce.chained_via_credentialed_parent` | X-Parent-Proxy: seen — the sealed upstream credential was unsealed and accepted by the parent |
| A | PASS | `enforce.unmatched_origin_default_deny_403` | got 403 |
| A | PASS | `enforce.no_credentials_407` | got 407 |
| A | INFO | `A.ready_fail_rows` | [none] |
| A | INFO | `A.diagnostics` | verdict=ok non-ok rows: [none] |
| A | PASS | `A-from.sigterm_exit` | pid 10653 exited after SIGTERM |
| A | PASS | `A.no_quarantine_files` | clean after FROM shutdown |
| B | PASS | `B-to.ready` | /ready answered 200 (pid 11027) |
| B | PASS | `B.no_quarantine_files` | no *.corrupt.* / quarantine artefacts in the state root |
| B | PASS | `B.admin_settings_parses` | admin_settings.json parses (admin_settings_schema=2) |
| B | PASS | `B.admin_settings_schema_unchanged` | got 2 |
| B | PASS | `B.login_same_password` | got 200 |
| B | PASS | `B.upstream_entry_present` | got 1 |
| B | PASS | `B.upstream_credential_configured` | got configured |
| B | INFO | `B.upstream_key_mode_migration` | key.state/mode/migration.state = present chained ok |
| B | PASS | `B.webhook_still_listed` | got 1790935219368406746 |
| B | PASS | `B.webhook_not_signing_degraded` | got False |
| B | PASS | `B.default_action_deny` | got deny |
| B | PASS | `B.allow_rule_present` | got 01M3Y0XEVFVC44D18CB0Q5CZ4D:allow-local-origin:Allow |
| B | PASS | `enforce.allowed_origin_with_credentials_200` | got 200 |
| B | PASS | `enforce.chained_via_credentialed_parent` | X-Parent-Proxy: seen — the sealed upstream credential was unsealed and accepted by the parent |
| B | PASS | `enforce.unmatched_origin_default_deny_403` | got 403 |
| B | PASS | `enforce.no_credentials_407` | got 407 |
| B | INFO | `B.version` | /healthz version=v1.0.259 /ready version=v1.0.259 |
| B | PASS | `B.ready_no_new_fail_rows` | fail rows now: [none] ⊆ leg A: [none] |
| B | PASS | `B.ca_bundle_sha_unchanged` | got c27d3c28b2ff7c581ce5ff68e3be6e70a1d2c73c668d5f5a57ac9be16a7c0773 |
| B | PASS | `B.diagnostics_verdict_not_worse` | verdict ok (leg A: ok) |
| B | INFO | `B.diagnostics_non_ok_rows` | now: [none] ; leg A: [none] |
| B | INFO | `B.config_versions` | 2 version(s): [(1, 'policy.default_action'), (2, 'policy.add')] |
| B | PASS | `B-to.sigterm_exit` | pid 11027 exited after SIGTERM |
| C | PASS | `C-from-again.ready` | /ready answered 200 (pid 11392) |
| C | PASS | `C.no_quarantine_files` | no *.corrupt.* / quarantine artefacts in the state root |
| C | PASS | `C.admin_settings_parses` | admin_settings.json parses (admin_settings_schema=2) |
| C | PASS | `C.admin_settings_schema_unchanged` | got 2 |
| C | PASS | `C.login_same_password` | got 200 |
| C | PASS | `C.upstream_entry_present` | got 1 |
| C | PASS | `C.upstream_credential_configured` | got configured |
| C | INFO | `C.upstream_key_mode_migration` | key.state/mode/migration.state = present chained ok |
| C | PASS | `C.webhook_still_listed` | got 1790935219368406746 |
| C | PASS | `C.webhook_not_signing_degraded` | got False |
| C | PASS | `C.default_action_deny` | got deny |
| C | PASS | `C.allow_rule_present` | got 01M3Y0XEVFVC44D18CB0Q5CZ4D:allow-local-origin:Allow |
| C | PASS | `enforce.allowed_origin_with_credentials_200` | got 200 |
| C | PASS | `enforce.chained_via_credentialed_parent` | X-Parent-Proxy: seen — the sealed upstream credential was unsealed and accepted by the parent |
| C | PASS | `enforce.unmatched_origin_default_deny_403` | got 403 |
| C | PASS | `enforce.no_credentials_407` | got 407 |
| C | INFO | `C.version` | /healthz version=v1.0.250 /ready version=v1.0.250 |
| C | PASS | `C.ready_no_new_fail_rows` | fail rows now: [none] ⊆ leg A: [none] |
| C | PASS | `C.ca_bundle_sha_unchanged` | got c27d3c28b2ff7c581ce5ff68e3be6e70a1d2c73c668d5f5a57ac9be16a7c0773 |
| C | PASS | `C.diagnostics_verdict_not_worse` | verdict ok (leg A: ok) |
| C | INFO | `C.diagnostics_non_ok_rows` | now: [none] ; leg A: [none] |
| C | INFO | `C.config_versions` | 2 version(s): [(1, 'policy.default_action'), (2, 'policy.add')] |
| C | PASS | `C-from-again.sigterm_exit` | pid 11392 exited after SIGTERM |

## Enforcement — verbatim curl output per leg

`X-Parent-Proxy: seen` is added by the credentialed parent proxy only when Culvert presented the correct `Proxy-Authorization` for the sealed upstream credential, so a 200 on the allowed origin proves the credential unsealed on that binary. The 403 body is the Culvert block page (HTML, trimmed here).

### Leg A — FROM v1.0.250

```
$ curl -s -x http://127.0.0.1:20300 -U admin:<ADMIN_PASS> http://localhost:20302/
HTTP/1.1 200 OK
Content-Length: 26
Content-Type: text/plain
Date: Fri, 02 Oct 2026 10:00:19 GMT
Server: BaseHTTP/0.6 Python/3.11.15
X-Parent-Proxy: seen
X-Request-Id: fa45c6ac631b53ee
hello-from-allowed-origin
[http_code=200]
```
```
$ curl -s -x http://127.0.0.1:20300 -U admin:<ADMIN_PASS> http://127.0.0.1:20304/
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Request-Id: 3fdc1e12c39b56d1
Date: Fri, 02 Oct 2026 10:00:19 GMT
Transfer-Encoding: chunked
[http_code=403]
```
```
$ curl -s -x http://127.0.0.1:20300 http://localhost:20302/
HTTP/1.1 407 Proxy Authentication Required
Content-Type: text/plain; charset=utf-8
Proxy-Authenticate: Basic realm="Culvert"
X-Content-Type-Options: nosniff
X-Request-Id: 4b8784f3c1fa912f
Date: Fri, 02 Oct 2026 10:00:19 GMT
Content-Length: 30
Proxy Authentication Required
[http_code=407]
```

### Leg B — TO v1.0.259

```
$ curl -s -x http://127.0.0.1:20300 -U admin:<ADMIN_PASS> http://localhost:20302/
HTTP/1.1 200 OK
Content-Length: 26
Content-Type: text/plain
Date: Fri, 02 Oct 2026 10:00:21 GMT
Server: BaseHTTP/0.6 Python/3.11.15
X-Parent-Proxy: seen
X-Request-Id: 5dae205557b5bce6
hello-from-allowed-origin
[http_code=200]
```
```
$ curl -s -x http://127.0.0.1:20300 -U admin:<ADMIN_PASS> http://127.0.0.1:20304/
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Request-Id: 83132b2b5d9966c3
Date: Fri, 02 Oct 2026 10:00:21 GMT
Transfer-Encoding: chunked
[http_code=403]
```
```
$ curl -s -x http://127.0.0.1:20300 http://localhost:20302/
HTTP/1.1 407 Proxy Authentication Required
Content-Type: text/plain; charset=utf-8
Proxy-Authenticate: Basic realm="Culvert"
X-Content-Type-Options: nosniff
X-Request-Id: dd63d8c8b06414ce
Date: Fri, 02 Oct 2026 10:00:21 GMT
Content-Length: 30
Proxy Authentication Required
[http_code=407]
```

### Leg C — FROM again v1.0.250

```
$ curl -s -x http://127.0.0.1:20300 -U admin:<ADMIN_PASS> http://localhost:20302/
HTTP/1.1 200 OK
Content-Length: 26
Content-Type: text/plain
Date: Fri, 02 Oct 2026 10:00:23 GMT
Server: BaseHTTP/0.6 Python/3.11.15
X-Parent-Proxy: seen
X-Request-Id: 4d49799bcc399fdc
hello-from-allowed-origin
[http_code=200]
```
```
$ curl -s -x http://127.0.0.1:20300 -U admin:<ADMIN_PASS> http://127.0.0.1:20304/
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Request-Id: 3468761a97e1846f
Date: Fri, 02 Oct 2026 10:00:23 GMT
Transfer-Encoding: chunked
[http_code=403]
```
```
$ curl -s -x http://127.0.0.1:20300 http://localhost:20302/
HTTP/1.1 407 Proxy Authentication Required
Content-Type: text/plain; charset=utf-8
Proxy-Authenticate: Basic realm="Culvert"
X-Content-Type-Options: nosniff
X-Request-Id: 91e856aeb5049422
Date: Fri, 02 Oct 2026 10:00:23 GMT
Content-Length: 30
Proxy Authentication Required
[http_code=407]
```

## Health, readiness and diagnostics per leg

- leg A `/healthz`: `{"leader":true,"role":"standalone","status":"ok","version":"v1.0.250","write_authority":true}`
- leg A `/ready`: `{"status":"ready","uptime":"0m 2s","version":"v1.0.250","checks":{"admin_ui":{"status":"ok"},"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"ok"},"saas_feed":{"status":"ok","detail":"disabled (embedded baseline)"},"session_secret":{"status":"ok"}}}`
- leg A `/api/diagnostics`: verdict `ok`, 40 rows, non-ok rows: none
- leg B `/healthz`: `{"leader":true,"role":"standalone","status":"ok","version":"v1.0.259","write_authority":true}`
- leg B `/ready`: `{"status":"ready","uptime":"0m 1s","version":"v1.0.259","checks":{"admin_ui":{"status":"ok"},"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"ok"},"saas_feed":{"status":"ok","detail":"disabled (embedded baseline)"},"session_secret":{"status":"ok"}}}`
- leg B `/api/diagnostics`: verdict `ok`, 41 rows, non-ok rows: none
- leg C `/healthz`: `{"leader":true,"role":"standalone","status":"ok","version":"v1.0.250","write_authority":true}`
- leg C `/ready`: `{"status":"ready","uptime":"0m 1s","version":"v1.0.250","checks":{"admin_ui":{"status":"ok"},"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"ok"},"saas_feed":{"status":"ok","detail":"disabled (embedded baseline)"},"session_secret":{"status":"ok"}}}`
- leg C `/api/diagnostics`: verdict `ok`, 40 rows, non-ok rows: none
- diagnostics row set: rows only reported by v1.0.259: ['admin_username_length']; rows only reported by v1.0.250: none

Admin-API read-backs on legs B and C (from the transcript):

```
[B] POST /api/auth/login -> 200 {"ok":true,"role":"admin","user":"admin"}
[B] GET /api/upstream -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","…
[B] GET /api/alerts/webhooks -> 200 {"webhooks":[{"id":"1790935219368406746","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}]}
[B] GET /api/default-action -> 200 {"defaultAction":"deny"}
[B] GET /api/policy -> 200 {"count":1,"draft":false,"persisted":true,"rules":[{"priority":10,"name":"allow-local-origin","sourceIP":"","sourceIdentity":"","sourceGroup":"","authSource":"","destFQDN":"localhost","destCategory":"","destCategoryGroup":"","destCountry":null,"sslAction":"","…
[B] GET /api/config/versions -> 200 [{"version":2,"created_at":"2026-10-02T10:00:19Z","actor":"admin","action":"policy.add"},{"version":1,"created_at":"2026-10-02T10:00:18Z","actor":"admin","action":"policy.default_action"}]
[C] POST /api/auth/login -> 200 {"ok":true,"role":"admin","user":"admin"}
[C] GET /api/upstream -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","…
[C] GET /api/alerts/webhooks -> 200 {"webhooks":[{"id":"1790935219368406746","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}]}
[C] GET /api/default-action -> 200 {"defaultAction":"deny"}
[C] GET /api/policy -> 200 {"count":1,"draft":false,"persisted":true,"rules":[{"priority":10,"name":"allow-local-origin","sourceIP":"","sourceIdentity":"","sourceGroup":"","authSource":"","destFQDN":"localhost","destCategory":"","destCategoryGroup":"","destCountry":null,"sslAction":"","…
[C] GET /api/config/versions -> 200 [{"version":2,"created_at":"2026-10-02T10:00:19Z","actor":"admin","action":"policy.add"},{"version":1,"created_at":"2026-10-02T10:00:18Z","actor":"admin","action":"policy.default_action"}]
```

Audit entries recorded by the TO and the FROM-again boots (`GET /api/audit?limit=8`, action/object only):

- leg B: `auth.login:admin`, `alert.webhook.create:1790935219368406746`, `upstream.credential.replace:01M3Y0XEXPJ7BJ29MHFED1M4RR`, `upstream.entry.create:01M3Y0XEXPJ7BJ29MHFED1M4RR`, `policy.add:allow-local-origin`, `policy.default_action:deny`, `auth.login:admin`, `setup.complete:admin`
- leg C: `auth.login:admin`, `auth.login:admin`, `alert.webhook.create:1790935219368406746`, `upstream.credential.replace:01M3Y0XEXPJ7BJ29MHFED1M4RR`, `upstream.entry.create:01M3Y0XEXPJ7BJ29MHFED1M4RR`, `policy.add:allow-local-origin`, `policy.default_action:deny`, `auth.login:admin`

## State root — sha256 after each leg

`upgrade` = after-FROM vs after-TO, `downgrade` = after-TO vs after-FROM-again. Append-only logs and the hit counter are expected to change; every durable configuration/trust file must be unchanged.

| file | after A (FROM) | after B (TO) | after C (FROM again) | upgrade | downgrade |
|---|---|---|---|---|---|
| `.alert_webhook_key` | `646990428c1af27b99e25b056266b5841031de25531bf3f9ca647383191f17f2` | `646990428c1af27b99e25b056266b5841031de25531bf3f9ca647383191f17f2` | `646990428c1af27b99e25b056266b5841031de25531bf3f9ca647383191f17f2` | same | same |
| `.upstream_cred_key` | `12cb6f5553151325676b4414d469250626ef452b8589a05e87c2e9af9fe8b3b3` | `12cb6f5553151325676b4414d469250626ef452b8589a05e87c2e9af9fe8b3b3` | `12cb6f5553151325676b4414d469250626ef452b8589a05e87c2e9af9fe8b3b3` | same | same |
| `admin_settings.json` | `4700a6320247c9bf9c550fd793a79fa1ccd8e710ab3ef5dcba1a651cbdf78fc2` | `4700a6320247c9bf9c550fd793a79fa1ccd8e710ab3ef5dcba1a651cbdf78fc2` | `4700a6320247c9bf9c550fd793a79fa1ccd8e710ab3ef5dcba1a651cbdf78fc2` | same | same |
| `alert_webhooks.json` | `096d8c9b2c1add705d3ccaed09dc5df0c583c6dfb96749e62481765643b49ed3` | `096d8c9b2c1add705d3ccaed09dc5df0c583c6dfb96749e62481765643b49ed3` | `096d8c9b2c1add705d3ccaed09dc5df0c583c6dfb96749e62481765643b49ed3` | same | same |
| `audit.jsonl` | `8499ae770741c050554d64e68e001c9d20aa23bcbe032423122181abec0645d4` | `adb86854f1a35b8bf5b7cc3185ddea71c9d22e826c6807f473bbd63a73ed5e13` | `d1ccf23c2728cebfbab64b9b85d825d30e8dffa72d19d94871c9562566b77dbb` | changed | changed |
| `ca.bundle` | `c27d3c28b2ff7c581ce5ff68e3be6e70a1d2c73c668d5f5a57ac9be16a7c0773` | `c27d3c28b2ff7c581ce5ff68e3be6e70a1d2c73c668d5f5a57ac9be16a7c0773` | `c27d3c28b2ff7c581ce5ff68e3be6e70a1d2c73c668d5f5a57ac9be16a7c0773` | same | same |
| `config_versions/v1.json` | `2c6a4e3483dd22a1b2a1972288f29402a8606cc1e36922d8f71cc4c6f64cd8a7` | `2c6a4e3483dd22a1b2a1972288f29402a8606cc1e36922d8f71cc4c6f64cd8a7` | `2c6a4e3483dd22a1b2a1972288f29402a8606cc1e36922d8f71cc4c6f64cd8a7` | same | same |
| `config_versions/v2.json` | `de43773133e940ed59afcc63d799aad1a6bf7712b0cefac29e71620f0d5d34ed` | `de43773133e940ed59afcc63d799aad1a6bf7712b0cefac29e71620f0d5d34ed` | `de43773133e940ed59afcc63d799aad1a6bf7712b0cefac29e71620f0d5d34ed` | same | same |
| `decryption_profiles.json` | `e79d1a9917a933c12169ccff53ac9c13d49cc1585b6aa55fb1ce8aad4136c390` | `e79d1a9917a933c12169ccff53ac9c13d49cc1585b6aa55fb1ce8aad4136c390` | `e79d1a9917a933c12169ccff53ac9c13d49cc1585b6aa55fb1ce8aad4136c390` | same | same |
| `fileprofiles.json` | `b70d748820fb818a74b577d5b998ecb717a313b37e9246c89aa60e4fe14b900b` | `b70d748820fb818a74b577d5b998ecb717a313b37e9246c89aa60e4fe14b900b` | `b70d748820fb818a74b577d5b998ecb717a313b37e9246c89aa60e4fe14b900b` | same | same |
| `hit_counters.json` | `8cf5900de323b948a8060d7b2883d586017ba797c6fa58cde4fd23bdc7deba24` | `7f84ba08ebd898f0cea43ca5267ba6a21f4f2796b2a6616c6109ae9a7042c01a` | `23becdfbe8ddd608c39b6f3905467be3e191d38ea39f8d3b0b446fbe214f1ad4` | changed | changed |
| `policy.json` | `00079920591b351f7d7187a44d23e1fed39889f2553bb5b0b8d59d02ba47aba0` | `00079920591b351f7d7187a44d23e1fed39889f2553bb5b0b8d59d02ba47aba0` | `00079920591b351f7d7187a44d23e1fed39889f2553bb5b0b8d59d02ba47aba0` | same | same |
| `policy.json.meta` | `88a4f22a506f89e77125808306af32c196a1626cc35cc5e44eab9c5acabf5b52` | `88a4f22a506f89e77125808306af32c196a1626cc35cc5e44eab9c5acabf5b52` | `88a4f22a506f89e77125808306af32c196a1626cc35cc5e44eab9c5acabf5b52` | same | same |
| `proxy.log` | `43d81095f7905071be41f508991ff41aebbb82687eb593eb5e0ce90e74aae12f` | `7a691a45a716b9b7f02cbd4f9a0f18a9ed7fcc8ee0a1d1ff3624906f1beaaa60` | `57eefa24c3a5f5dce51eab003200eafdb45c21f4154b5193edce573319823126` | changed | changed |
| `requests.jsonl` | `67b49b2cdd2484723e90508b09a7e2ba2daa545ee1b0ccd9ef9b240bb2067939` | `946c00cd8cca56ba5f0010f2c4fc79b14781f301a0f3da93a06a2336255b7d3d` | `1b05c470565de9a9c33147e413ea647b3629888942ab7eab793dabc22c6ca245` | changed | changed |
| `ui_users.json` | `595b0820921789ae2ca82bc8442876b907174fa00b44cae296522833d05e6c74` | `595b0820921789ae2ca82bc8442876b907174fa00b44cae296522833d05e6c74` | `595b0820921789ae2ca82bc8442876b907174fa00b44cae296522833d05e6c74` | same | same |

No `*.corrupt.*`, `*quarantin*` or `*.poison*` artefact appeared at any point (asserted after every boot). No file was added or removed by the TO boot or by the FROM-again boot (the file set is identical in all three snapshots).

## Compatibility notes

- `GET /api/diagnostics` on v1.0.250 lacks one row that v1.0.259 reports (`admin_username_length`, CHAOS-63). Additive `ok` row.
- `GET /api/policy` already carries `persisted:true` on v1.0.250 (identical to v1.0.259).
- Every seeding call accepted the v1.0.259 OpenAPI body shape unchanged; `admin_settings_schema: 2` on both binaries. No version branch was needed.

## Findings

- No assertion failed on the upgrade leg (B) or on the reverse leg (C). v1.0.259 booted the v1.0.250-written root without rewriting a single durable file (`admin_settings.json`, `ui_users.json`, `policy.json`, `alert_webhooks.json`, `ca.bundle`, both node-local key files and both config-version snapshots are byte-identical across all three boots), and v1.0.250 booted the root again after v1.0.259 had run on it with the same result.
- The sealed upstream credential (AES-GCM under `.upstream_cred_key`, bound to the entry id + authority hash) and the encrypted webhook secret (`.alert_webhook_key`) were usable on every leg: `credentialState: configured`, `signing_degraded` absent, and the live chained request carried the credential to the parent.
- The three enforcement decisions (Allow rule → 200 via the parent; default-deny → 403 block page; no credentials → 407) are identical on all three boots.
- Observed, not a defect: `hit_counters.json`, `proxy.log`, `requests.jsonl` and `audit.jsonl` change on every boot (append-only logs and the rule hit counter); the request log records the three probes per leg.

