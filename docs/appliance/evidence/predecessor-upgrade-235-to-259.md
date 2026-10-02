# Predecessor upgrade qualification — v1.0.235 → v1.0.259 → v1.0.235

**Verdict: PASS** — 55 assertions passed, 0 failed, across three boots of ONE state root.

Executed on 2026-10-02 against the REAL published linux/amd64 release binaries (GitHub Releases), not synthetic builds.
Driver: `test/appliance/predecessor-upgrade.sh` (this commit). Every process was started with its PID recorded and stopped by that exact PID.

## Environment

- worktree: `/home/user/Culvert/.claude/worktrees/agent-ad18042642914dee6` (branch `worktree-agent-ad18042642914dee6`, base commit `3fcc07e (Merge pull request #1525 from KidCarmi/codex/repair-frontend-audit)`)
- host: Linux 6.18.44-fc-v51 (container, root), python3 3.11.15, curl, bash; no Docker
- state root: `/tmp/claude-0/-home-user-Culvert/cf36caf0-214a-5d31-ba4b-95168e4ca302/scratchpad/predecessor/run-235-259/state` (fresh, empty before leg A; `CULVERT_DATA_DIR` points at it, `CULVERT_CA_PASSPHRASE=test-passphrase` so the CA bundle is encrypted as on a real install)
- ports: proxy `20400`, admin UI `20401` (https, self-signed, `-k`), allowed origin `127.0.0.1:20402` (`python3 -m http.server`), credentialed parent proxy `127.0.0.1:20403`, unmatched origin `127.0.0.1:20404`
- proxy env caveat: admin-API calls use `--noproxy '*'`; proxied requests clear `*_proxy`/`no_proxy` from the environment (with `--noproxy '*'` curl bypasses the `-x` proxy under test as well — observed during development, hence the split)

### Binaries (sha256)

| role | file | sha256 | reports |
|---|---|---|---|
| FROM | `culvert-linux-amd64-v1.0.235` | `5a2c6cf8c3d9d5a829e030dc8044a59d5276907c87cc06f150d5470f4d7aa91e` | `v1.0.235` (/healthz and /ready) |
| TO | `culvert-linux-amd64-v1.0.259` | `3ba95443374ea7bbf1b8d1fe826089267414a3de93e6b51f1081a99c9bb0b5a0` | `v1.0.259` (/healthz and /ready) |
| FROM maint agent (not executed — host-root component with no state-root involvement; recorded for the release pair) | `culvert-maint-linux-amd64-v1.0.235` | `751e38ed6219e5de0a03d9c7353035be01f9c01aef6142ad096ad8fd4e373c9a` | — |
| TO maint agent (not executed) | `culvert-maint-linux-amd64-v1.0.259` | `ed499b2abd6c0e58b82cac24a8afcec9242adec27e6f5bd3c58add9d97ec8cc5` | — |

## Command

```bash
PORT_BASE=20400 ./test/appliance/predecessor-upgrade.sh \
  /tmp/claude-0/artifacts/culvert-linux-amd64-v1.0.235 \
  /tmp/claude-0/artifacts/culvert-linux-amd64-v1.0.259 \
  /tmp/claude-0/-home-user-Culvert/cf36caf0-214a-5d31-ba4b-95168e4ca302/scratchpad/predecessor/run-235-259/state \
  /tmp/claude-0/-home-user-Culvert/cf36caf0-214a-5d31-ba4b-95168e4ca302/scratchpad/predecessor/run-235-259/evidence
# exit status 0 (verdict PASS)
```

Each boot used the compose-equivalent flag set:

```
CULVERT_DATA_DIR=<root> CULVERT_CA_PASSPHRASE=test-passphrase <binary> -port 20400 -ui-port 20401 \
  -ca-path <root>/ca.bundle -policy <root>/policy.json -ui-users-file <root>/ui_users.json \
  -audit-log <root>/audit.jsonl -request-log <root>/requests.jsonl -logfile <root>/proxy.log \
  -revocations-file <root>/revocations.json -idp-profiles-file <root>/idp_profiles.json -fileprofiles-file <root>/fileprofiles.json
```

## Processes

- allowed origin pid 11744 (127.0.0.1:20402), unmatched origin pid 11745 (127.0.0.1:20404), parent proxy pid 11746 (127.0.0.1:20403)
- `A-from`: pid 11777 — exited after SIGTERM (see `*.sigterm_exit` rows)
- `B-to`: pid 12143 — exited after SIGTERM (see `*.sigterm_exit` rows)
- `C-from-again`: pid 12444 — exited after SIGTERM (see `*.sigterm_exit` rows)
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
POST /api/upstream/entries/01M3Y0XNW1DVA3JJRR05FYG9H9/credential {action:replace,password:<redacted>,revision:1} -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","entries":1,"eligible":1,"fallbackTotal":…
GET /api/upstream -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","entries":1,"eligible":1,"fallbackTotal":…
POST /api/alerts/webhooks {…,secret:<redacted>} -> 200 {"id":"1790935226544706885","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}
GET /api/alerts/webhooks -> 200 {"webhooks":[{"id":"1790935226544706885","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}]}
GET /api/config/versions -> 200 [{"version":2,"created_at":"2026-10-02T10:00:26Z","actor":"admin","action":"policy.add"},{"version":1,"created_at":"2026-10-02T10:00:26Z","actor":"admin","action":"policy.default_action"}]
```

Request bodies used: `{"user":"admin","pass":"<strong>"}` (setup + login), `{"action":"deny"}`, `{"name":"allow-local-origin","priority":10,"destFQDN":"localhost","action":"Allow","enabled":true}` (note the capitalised `Allow` — the engine rejects lowercase `allow` with 400 `action must be Allow, Drop, Block_Page, or Redirect`), `{"scheme":"http","host":"127.0.0.1","port":20403,"username":"parentuser","revision":1}`, `{"action":"replace","password":"<parent password>","revision":1}`, `{"name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true,"secret":"<secret>"}`.

`audit.jsonl` after leg A (file tail, verbatim; the rule's `after` blob is the full rule JSON):

```
{"ts":1790935225851,"time":"2026-10-02 10:00:25","actor":"127.0.0.1","action":"setup.complete","object":"admin","detail":"first-time admin password configured"}
{"ts":1790935225988,"time":"2026-10-02 10:00:25","actor":"admin@127.0.0.1","action":"auth.login","object":"admin","detail":"admin UI login role=admin"}
{"ts":1790935226034,"time":"2026-10-02 10:00:26","actor":"admin@127.0.0.1","action":"policy.default_action","object":"deny","detail":""}
{"ts":1790935226128,"time":"2026-10-02 10:00:26","actor":"admin@127.0.0.1","action":"policy.add","object":"allow-local-origin","objectId":"01M3Y0XNR9R5D5T7WTTR1A6DCX","detail":"priority=10 action=Allow","after":"{\"priority\":10,\"name\":\"allow-local-origin\",\"sourceIP\":\"\",\"sourceIdentity\":\"\",\"sourceGroup\":\"\",\"authSource\":\"\",\"destFQDN\":\"localhost\",\"destCategory\":\"\",\"destC…
{"ts":1790935226248,"time":"2026-10-02 10:00:26","actor":"admin@127.0.0.1","action":"upstream.entry.create","object":"01M3Y0XNW1DVA3JJRR05FYG9H9","detail":"authority=http://parentuser@127.0.0.1:20403"}
{"ts":1790935226379,"time":"2026-10-02 10:00:26","actor":"admin@127.0.0.1","action":"upstream.credential.replace","object":"01M3Y0XNW1DVA3JJRR05FYG9H9","detail":"authority=http://parentuser@127.0.0.1:20403"}
{"ts":1790935226545,"time":"2026-10-02 10:00:26","actor":"admin@127.0.0.1","action":"alert.webhook.create","object":"1790935226544706885","detail":"https://siem.example.invalid/culvert-hook"}
```

## Assertions

Legend: A = FROM on a fresh root, B = TO on the same root (upgrade), C = FROM again on the same root (reverse leg / downgrade tolerance). `enforce.*` rows are the SAME three proxied requests on every leg.

| leg | status | check | detail |
|---|---|---|---|
| A | PASS | `A-from.ready` | /ready answered 200 (pid 11777) |
| A | INFO | `A.version` | /healthz version=v1.0.235 /ready version=v1.0.235 |
| A | PASS | `A.setup_status_needs_setup` | got true |
| A | PASS | `A.setup_complete_200` | got 200 |
| A | PASS | `A.login_200` | got 200 |
| A | PASS | `A.default_action_set_deny` | got deny |
| A | PASS | `A.allow_rule_created` | id=01M3Y0XNR9R5D5T7WTTR1A6DCX destFQDN=localhost action=Allow |
| A | PASS | `A.upstream_entry_created` | id=01M3Y0XNW1DVA3JJRR05FYG9H9 authority=http://parentuser@127.0.0.1:20403 revision=1 |
| A | PASS | `A.upstream_credential_sealed` | got configured |
| A | INFO | `A.upstream_health` | health= {'status': 'unprobed', 'reason': 'none'} eligible= True mode= chained key= {'state': 'present', 'keyId': 'a9030a5b16c939ad'} |
| A | PASS | `A.webhook_created` | id=1790935226544706885 |
| A | PASS | `A.webhook_not_signing_degraded` | got False |
| A | PASS | `A.config_version_autocreated` | 2 version(s): ['policy.add', 'policy.default_action'] |
| A | INFO | `A.admin_settings_schema` | admin_settings_schema=2 keys=43 |
| A | INFO | `A.ca_bundle_sha` | 504f605c62feb5856ca18a673e42d3d9d422acd88f0375c494fd694bf751d03b |
| A | PASS | `enforce.allowed_origin_with_credentials_200` | got 200 |
| A | PASS | `enforce.chained_via_credentialed_parent` | X-Parent-Proxy: seen — the sealed upstream credential was unsealed and accepted by the parent |
| A | PASS | `enforce.unmatched_origin_default_deny_403` | got 403 |
| A | PASS | `enforce.no_credentials_407` | got 407 |
| A | INFO | `A.ready_fail_rows` | [none] |
| A | INFO | `A.diagnostics` | verdict=ok non-ok rows: [none] |
| A | PASS | `A-from.sigterm_exit` | pid 11777 exited after SIGTERM |
| A | PASS | `A.no_quarantine_files` | clean after FROM shutdown |
| B | PASS | `B-to.ready` | /ready answered 200 (pid 12143) |
| B | PASS | `B.no_quarantine_files` | no *.corrupt.* / quarantine artefacts in the state root |
| B | PASS | `B.admin_settings_parses` | admin_settings.json parses (admin_settings_schema=2) |
| B | PASS | `B.admin_settings_schema_unchanged` | got 2 |
| B | PASS | `B.login_same_password` | got 200 |
| B | PASS | `B.upstream_entry_present` | got 1 |
| B | PASS | `B.upstream_credential_configured` | got configured |
| B | INFO | `B.upstream_key_mode_migration` | key.state/mode/migration.state = present chained ok |
| B | PASS | `B.webhook_still_listed` | got 1790935226544706885 |
| B | PASS | `B.webhook_not_signing_degraded` | got False |
| B | PASS | `B.default_action_deny` | got deny |
| B | PASS | `B.allow_rule_present` | got 01M3Y0XNR9R5D5T7WTTR1A6DCX:allow-local-origin:Allow |
| B | PASS | `enforce.allowed_origin_with_credentials_200` | got 200 |
| B | PASS | `enforce.chained_via_credentialed_parent` | X-Parent-Proxy: seen — the sealed upstream credential was unsealed and accepted by the parent |
| B | PASS | `enforce.unmatched_origin_default_deny_403` | got 403 |
| B | PASS | `enforce.no_credentials_407` | got 407 |
| B | INFO | `B.version` | /healthz version=v1.0.259 /ready version=v1.0.259 |
| B | PASS | `B.ready_no_new_fail_rows` | fail rows now: [none] ⊆ leg A: [none] |
| B | PASS | `B.ca_bundle_sha_unchanged` | got 504f605c62feb5856ca18a673e42d3d9d422acd88f0375c494fd694bf751d03b |
| B | PASS | `B.diagnostics_verdict_not_worse` | verdict ok (leg A: ok) |
| B | INFO | `B.diagnostics_non_ok_rows` | now: [none] ; leg A: [none] |
| B | INFO | `B.config_versions` | 2 version(s): [(1, 'policy.default_action'), (2, 'policy.add')] |
| B | PASS | `B-to.sigterm_exit` | pid 12143 exited after SIGTERM |
| C | PASS | `C-from-again.ready` | /ready answered 200 (pid 12444) |
| C | PASS | `C.no_quarantine_files` | no *.corrupt.* / quarantine artefacts in the state root |
| C | PASS | `C.admin_settings_parses` | admin_settings.json parses (admin_settings_schema=2) |
| C | PASS | `C.admin_settings_schema_unchanged` | got 2 |
| C | PASS | `C.login_same_password` | got 200 |
| C | PASS | `C.upstream_entry_present` | got 1 |
| C | PASS | `C.upstream_credential_configured` | got configured |
| C | INFO | `C.upstream_key_mode_migration` | key.state/mode/migration.state = present chained ok |
| C | PASS | `C.webhook_still_listed` | got 1790935226544706885 |
| C | PASS | `C.webhook_not_signing_degraded` | got False |
| C | PASS | `C.default_action_deny` | got deny |
| C | PASS | `C.allow_rule_present` | got 01M3Y0XNR9R5D5T7WTTR1A6DCX:allow-local-origin:Allow |
| C | PASS | `enforce.allowed_origin_with_credentials_200` | got 200 |
| C | PASS | `enforce.chained_via_credentialed_parent` | X-Parent-Proxy: seen — the sealed upstream credential was unsealed and accepted by the parent |
| C | PASS | `enforce.unmatched_origin_default_deny_403` | got 403 |
| C | PASS | `enforce.no_credentials_407` | got 407 |
| C | INFO | `C.version` | /healthz version=v1.0.235 /ready version=v1.0.235 |
| C | PASS | `C.ready_no_new_fail_rows` | fail rows now: [none] ⊆ leg A: [none] |
| C | PASS | `C.ca_bundle_sha_unchanged` | got 504f605c62feb5856ca18a673e42d3d9d422acd88f0375c494fd694bf751d03b |
| C | PASS | `C.diagnostics_verdict_not_worse` | verdict ok (leg A: ok) |
| C | INFO | `C.diagnostics_non_ok_rows` | now: [none] ; leg A: [none] |
| C | INFO | `C.config_versions` | 2 version(s): [(1, 'policy.default_action'), (2, 'policy.add')] |
| C | PASS | `C-from-again.sigterm_exit` | pid 12444 exited after SIGTERM |

## Enforcement — verbatim curl output per leg

`X-Parent-Proxy: seen` is added by the credentialed parent proxy only when Culvert presented the correct `Proxy-Authorization` for the sealed upstream credential, so a 200 on the allowed origin proves the credential unsealed on that binary. The 403 body is the Culvert block page (HTML, trimmed here).

### Leg A — FROM v1.0.235

```
$ curl -s -x http://127.0.0.1:20400 -U admin:<ADMIN_PASS> http://localhost:20402/
HTTP/1.1 200 OK
Content-Length: 26
Content-Type: text/plain
Date: Fri, 02 Oct 2026 10:00:26 GMT
Server: BaseHTTP/0.6 Python/3.11.15
X-Parent-Proxy: seen
X-Request-Id: af5a486ac46d65cf
hello-from-allowed-origin
[http_code=200]
```
```
$ curl -s -x http://127.0.0.1:20400 -U admin:<ADMIN_PASS> http://127.0.0.1:20404/
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Request-Id: 5efe821a8330d5bb
Date: Fri, 02 Oct 2026 10:00:27 GMT
Transfer-Encoding: chunked
[http_code=403]
```
```
$ curl -s -x http://127.0.0.1:20400 http://localhost:20402/
HTTP/1.1 407 Proxy Authentication Required
Content-Type: text/plain; charset=utf-8
Proxy-Authenticate: Basic realm="Culvert"
X-Content-Type-Options: nosniff
X-Request-Id: 7e9f825b1f69e92d
Date: Fri, 02 Oct 2026 10:00:27 GMT
Content-Length: 30
Proxy Authentication Required
[http_code=407]
```

### Leg B — TO v1.0.259

```
$ curl -s -x http://127.0.0.1:20400 -U admin:<ADMIN_PASS> http://localhost:20402/
HTTP/1.1 200 OK
Content-Length: 26
Content-Type: text/plain
Date: Fri, 02 Oct 2026 10:00:29 GMT
Server: BaseHTTP/0.6 Python/3.11.15
X-Parent-Proxy: seen
X-Request-Id: e57d404d5aa46097
hello-from-allowed-origin
[http_code=200]
```
```
$ curl -s -x http://127.0.0.1:20400 -U admin:<ADMIN_PASS> http://127.0.0.1:20404/
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Request-Id: c12fa54ede32baf0
Date: Fri, 02 Oct 2026 10:00:29 GMT
Transfer-Encoding: chunked
[http_code=403]
```
```
$ curl -s -x http://127.0.0.1:20400 http://localhost:20402/
HTTP/1.1 407 Proxy Authentication Required
Content-Type: text/plain; charset=utf-8
Proxy-Authenticate: Basic realm="Culvert"
X-Content-Type-Options: nosniff
X-Request-Id: d0c4cc027cf139bc
Date: Fri, 02 Oct 2026 10:00:29 GMT
Content-Length: 30
Proxy Authentication Required
[http_code=407]
```

### Leg C — FROM again v1.0.235

```
$ curl -s -x http://127.0.0.1:20400 -U admin:<ADMIN_PASS> http://localhost:20402/
HTTP/1.1 200 OK
Content-Length: 26
Content-Type: text/plain
Date: Fri, 02 Oct 2026 10:00:31 GMT
Server: BaseHTTP/0.6 Python/3.11.15
X-Parent-Proxy: seen
X-Request-Id: dd9aebfa82594eae
hello-from-allowed-origin
[http_code=200]
```
```
$ curl -s -x http://127.0.0.1:20400 -U admin:<ADMIN_PASS> http://127.0.0.1:20404/
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Request-Id: f26df1d0ba2ab402
Date: Fri, 02 Oct 2026 10:00:31 GMT
Transfer-Encoding: chunked
[http_code=403]
```
```
$ curl -s -x http://127.0.0.1:20400 http://localhost:20402/
HTTP/1.1 407 Proxy Authentication Required
Content-Type: text/plain; charset=utf-8
Proxy-Authenticate: Basic realm="Culvert"
X-Content-Type-Options: nosniff
X-Request-Id: 57294a8752bf0f72
Date: Fri, 02 Oct 2026 10:00:31 GMT
Content-Length: 30
Proxy Authentication Required
[http_code=407]
```

## Health, readiness and diagnostics per leg

- leg A `/healthz`: `{"leader":true,"role":"standalone","status":"ok","version":"v1.0.235","write_authority":true}`
- leg A `/ready`: `{"status":"ready","uptime":"0m 2s","version":"v1.0.235","checks":{"admin_ui":{"status":"ok"},"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"ok"},"saas_feed":{"status":"ok","detail":"disabled (embedded baseline)"},"session_secret":{"status":"ok"}}}`
- leg A `/api/diagnostics`: verdict `ok`, 39 rows, non-ok rows: none
- leg B `/healthz`: `{"leader":true,"role":"standalone","status":"ok","version":"v1.0.259","write_authority":true}`
- leg B `/ready`: `{"status":"ready","uptime":"0m 1s","version":"v1.0.259","checks":{"admin_ui":{"status":"ok"},"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"ok"},"saas_feed":{"status":"ok","detail":"disabled (embedded baseline)"},"session_secret":{"status":"ok"}}}`
- leg B `/api/diagnostics`: verdict `ok`, 41 rows, non-ok rows: none
- leg C `/healthz`: `{"leader":true,"role":"standalone","status":"ok","version":"v1.0.235","write_authority":true}`
- leg C `/ready`: `{"status":"ready","uptime":"0m 1s","version":"v1.0.235","checks":{"admin_ui":{"status":"ok"},"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"ok"},"saas_feed":{"status":"ok","detail":"disabled (embedded baseline)"},"session_secret":{"status":"ok"}}}`
- leg C `/api/diagnostics`: verdict `ok`, 39 rows, non-ok rows: none
- diagnostics row set: rows only reported by v1.0.259: ['admin_username_length', 'rewrite_identity']; rows only reported by v1.0.235: none

Admin-API read-backs on legs B and C (from the transcript):

```
[B] POST /api/auth/login -> 200 {"ok":true,"role":"admin","user":"admin"}
[B] GET /api/upstream -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","…
[B] GET /api/alerts/webhooks -> 200 {"webhooks":[{"id":"1790935226544706885","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}]}
[B] GET /api/default-action -> 200 {"defaultAction":"deny"}
[B] GET /api/policy -> 200 {"count":1,"draft":false,"persisted":true,"rules":[{"priority":10,"name":"allow-local-origin","sourceIP":"","sourceIdentity":"","sourceGroup":"","authSource":"","destFQDN":"localhost","destCategory":"","destCategoryGroup":"","destCountry":null,"sslAction":"","…
[B] GET /api/config/versions -> 200 [{"version":2,"created_at":"2026-10-02T10:00:26Z","actor":"admin","action":"policy.add"},{"version":1,"created_at":"2026-10-02T10:00:26Z","actor":"admin","action":"policy.default_action"}]
[C] POST /api/auth/login -> 200 {"ok":true,"role":"admin","user":"admin"}
[C] GET /api/upstream -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","…
[C] GET /api/alerts/webhooks -> 200 {"webhooks":[{"id":"1790935226544706885","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}]}
[C] GET /api/default-action -> 200 {"defaultAction":"deny"}
[C] GET /api/policy -> 200 {"count":1,"draft":false,"rules":[{"priority":10,"name":"allow-local-origin","sourceIP":"","sourceIdentity":"","sourceGroup":"","authSource":"","destFQDN":"localhost","destCategory":"","destCategoryGroup":"","destCountry":null,"sslAction":"","fileFiltering":fa…
[C] GET /api/config/versions -> 200 [{"version":2,"created_at":"2026-10-02T10:00:26Z","actor":"admin","action":"policy.add"},{"version":1,"created_at":"2026-10-02T10:00:26Z","actor":"admin","action":"policy.default_action"}]
```

Audit entries recorded by the TO and the FROM-again boots (`GET /api/audit?limit=8`, action/object only):

- leg B: `auth.login:admin`, `alert.webhook.create:1790935226544706885`, `upstream.credential.replace:01M3Y0XNW1DVA3JJRR05FYG9H9`, `upstream.entry.create:01M3Y0XNW1DVA3JJRR05FYG9H9`, `policy.add:allow-local-origin`, `policy.default_action:deny`, `auth.login:admin`, `setup.complete:admin`
- leg C: `auth.login:admin`, `auth.login:admin`, `alert.webhook.create:1790935226544706885`, `upstream.credential.replace:01M3Y0XNW1DVA3JJRR05FYG9H9`, `upstream.entry.create:01M3Y0XNW1DVA3JJRR05FYG9H9`, `policy.add:allow-local-origin`, `policy.default_action:deny`, `auth.login:admin`

## State root — sha256 after each leg

`upgrade` = after-FROM vs after-TO, `downgrade` = after-TO vs after-FROM-again. Append-only logs and the hit counter are expected to change; every durable configuration/trust file must be unchanged.

| file | after A (FROM) | after B (TO) | after C (FROM again) | upgrade | downgrade |
|---|---|---|---|---|---|
| `.alert_webhook_key` | `481a15441148ab9905b3370677a15a5e0aae2374629913ad279c02b87b0f0870` | `481a15441148ab9905b3370677a15a5e0aae2374629913ad279c02b87b0f0870` | `481a15441148ab9905b3370677a15a5e0aae2374629913ad279c02b87b0f0870` | same | same |
| `.upstream_cred_key` | `a9030a5b16c939ad6f7d6ad364c1f8dcf0e92c8b84f292fc749dda37d2635403` | `a9030a5b16c939ad6f7d6ad364c1f8dcf0e92c8b84f292fc749dda37d2635403` | `a9030a5b16c939ad6f7d6ad364c1f8dcf0e92c8b84f292fc749dda37d2635403` | same | same |
| `admin_settings.json` | `e3a3ae88752da8a8903ee67e41276c5df52d5df1064ce196ab22fcfdd99aa1ca` | `e3a3ae88752da8a8903ee67e41276c5df52d5df1064ce196ab22fcfdd99aa1ca` | `e3a3ae88752da8a8903ee67e41276c5df52d5df1064ce196ab22fcfdd99aa1ca` | same | same |
| `alert_webhooks.json` | `26326f6df737e100d74699c4478733b3bb1f0c5d9c026ed7b908679f7d901958` | `26326f6df737e100d74699c4478733b3bb1f0c5d9c026ed7b908679f7d901958` | `26326f6df737e100d74699c4478733b3bb1f0c5d9c026ed7b908679f7d901958` | same | same |
| `audit.jsonl` | `8cb3c95fc6d5dae4f1a897c675e8db8711060b7b2b2f4602111c7aadbbb21701` | `bbe3f7f833c58da865292fa1f3f071c8786e0bb48891eada1eb0a3c43cac6cf0` | `17697324fc7e57ac9412661e416aca939772ef328e5eadcd1a18448a18ae6392` | changed | changed |
| `ca.bundle` | `504f605c62feb5856ca18a673e42d3d9d422acd88f0375c494fd694bf751d03b` | `504f605c62feb5856ca18a673e42d3d9d422acd88f0375c494fd694bf751d03b` | `504f605c62feb5856ca18a673e42d3d9d422acd88f0375c494fd694bf751d03b` | same | same |
| `config_versions/v1.json` | `7d0fb1f3ec0f1bef7f01b1ef1586162811c78cd38a4c3d5b1ea79c6237988c77` | `7d0fb1f3ec0f1bef7f01b1ef1586162811c78cd38a4c3d5b1ea79c6237988c77` | `7d0fb1f3ec0f1bef7f01b1ef1586162811c78cd38a4c3d5b1ea79c6237988c77` | same | same |
| `config_versions/v2.json` | `769492b501247778d90ecddf8e5d3da18176d28f4e203081258d0721379fbbd4` | `769492b501247778d90ecddf8e5d3da18176d28f4e203081258d0721379fbbd4` | `769492b501247778d90ecddf8e5d3da18176d28f4e203081258d0721379fbbd4` | same | same |
| `decryption_profiles.json` | `a9122293e25371e34d65f171a3d4e38b2496d54ce8035ba6ec6ee8a571c02d1f` | `a9122293e25371e34d65f171a3d4e38b2496d54ce8035ba6ec6ee8a571c02d1f` | `a9122293e25371e34d65f171a3d4e38b2496d54ce8035ba6ec6ee8a571c02d1f` | same | same |
| `fileprofiles.json` | `b70d748820fb818a74b577d5b998ecb717a313b37e9246c89aa60e4fe14b900b` | `b70d748820fb818a74b577d5b998ecb717a313b37e9246c89aa60e4fe14b900b` | `b70d748820fb818a74b577d5b998ecb717a313b37e9246c89aa60e4fe14b900b` | same | same |
| `hit_counters.json` | `35141a9d2df625bf1130cb68cf1a22d4257b10a8e29d6fcabc85afab26df506d` | `3114e7e6417533f848ace32382e9be8cd4f01555d902abc38110b94aed1bab37` | `2458dbe3a8e42c1fbde125c3fab844435f5cb058ab2a24431a53d9ee42c6e25a` | changed | changed |
| `policy.json` | `584cd4061ff8a51f24109ce0603568a583fe71f9d013cad8b5ed657d23fecf51` | `584cd4061ff8a51f24109ce0603568a583fe71f9d013cad8b5ed657d23fecf51` | `584cd4061ff8a51f24109ce0603568a583fe71f9d013cad8b5ed657d23fecf51` | same | same |
| `policy.json.meta` | `c7ca0b255d66b8309427ab9343b14a2b55ec77a16aa2c9ce04b27fdebc8ec2d9` | `c7ca0b255d66b8309427ab9343b14a2b55ec77a16aa2c9ce04b27fdebc8ec2d9` | `c7ca0b255d66b8309427ab9343b14a2b55ec77a16aa2c9ce04b27fdebc8ec2d9` | same | same |
| `proxy.log` | `e1244092c6459d27b4b9e6ba1273ad7c1561e5e7e8dd12fb597d7edd00364b96` | `8ab3eddd012b8af15a8351f588ae68ddb362890c317081c008ac5f98395ecf5d` | `20a7aa6b4e090bca60cc4ce4e256ec955efde5c28c2cc8c55b51fd273d87b044` | changed | changed |
| `requests.jsonl` | `0884d72c458d1ef9de54b3ac86ac9049ba276f7c5e04230edf21cc0efe010db1` | `4ba868a8ae094c2796985a595ef87c29e413aef30e6c79ef0ed0cd65e0903bcb` | `b5e96fa244b3f5dd326a4c86619358c7fadb5f37ccdc2e1bc9ffa5298ab5c833` | changed | changed |
| `ui_users.json` | `c986dbfe81f18a9f38cb13e1c02455fb02c9f3c572050e2fa2fa2d0e4326a5a6` | `c986dbfe81f18a9f38cb13e1c02455fb02c9f3c572050e2fa2fa2d0e4326a5a6` | `c986dbfe81f18a9f38cb13e1c02455fb02c9f3c572050e2fa2fa2d0e4326a5a6` | same | same |

No `*.corrupt.*`, `*quarantin*` or `*.poison*` artefact appeared at any point (asserted after every boot). No file was added or removed by the TO boot or by the FROM-again boot (the file set is identical in all three snapshots).

## Compatibility notes

- `GET /api/policy` on v1.0.235 answers `{count,draft,rules,updatedAt,version}`; v1.0.259 adds `persisted:true`. Additive — the script reads only `rules[].{id,name,action}`.
- `GET /api/diagnostics` on v1.0.235 lacks two rows that v1.0.259 reports (`admin_username_length`, `rewrite_identity`). Both are additive `ok` rows; the verdict comparison is on the top-level `verdict` and the non-ok row set, which is empty on every leg.
- Every seeding call (`/api/setup/complete`, `/api/auth/login`, `/api/default-action`, `/api/policy`, `/api/upstream/entries`, `/api/upstream/entries/{id}/credential`, `/api/alerts/webhooks`) accepted the v1.0.259 OpenAPI body shape unchanged on v1.0.235, and `admin_settings.json` is written with `admin_settings_schema: 2` by both binaries. No version branch was needed in the script.

## Findings

- No assertion failed on the upgrade leg (B) or on the reverse leg (C). v1.0.259 booted the v1.0.235-written root without rewriting a single durable file (`admin_settings.json`, `ui_users.json`, `policy.json`, `alert_webhooks.json`, `ca.bundle`, both node-local key files and both config-version snapshots are byte-identical across all three boots), and v1.0.235 booted the root again after v1.0.259 had run on it with the same result.
- The sealed upstream credential (AES-GCM under `.upstream_cred_key`, bound to the entry id + authority hash) and the encrypted webhook secret (`.alert_webhook_key`) were usable on every leg: `credentialState: configured`, `signing_degraded` absent, and the live chained request carried the credential to the parent.
- The three enforcement decisions (Allow rule → 200 via the parent; default-deny → 403 block page; no credentials → 407) are identical on all three boots.
- Observed, not a defect: `hit_counters.json`, `proxy.log`, `requests.jsonl` and `audit.jsonl` change on every boot (append-only logs and the rule hit counter); the request log records the three probes per leg.

