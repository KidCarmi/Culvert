# Predecessor upgrade qualification — v1.0.258 → v1.0.259 → v1.0.258

**Verdict: PASS** — 55 assertions passed, 0 failed, across three boots of ONE state root.

Executed on 2026-10-02 against the REAL published linux/amd64 release binaries (GitHub Releases), not synthetic builds.
Driver: `test/appliance/predecessor-upgrade.sh` (this commit). Every process was started with its PID recorded and stopped by that exact PID.

## Environment

- worktree: `/home/user/Culvert/.claude/worktrees/agent-ad18042642914dee6` (branch `worktree-agent-ad18042642914dee6`, base commit `3fcc07e (Merge pull request #1525 from KidCarmi/codex/repair-frontend-audit)`)
- host: Linux 6.18.44-fc-v51 (container, root), python3 3.11.15, curl, bash; no Docker
- state root: `/tmp/claude-0/-home-user-Culvert/cf36caf0-214a-5d31-ba4b-95168e4ca302/scratchpad/predecessor/run-258-259/state` (fresh, empty before leg A; `CULVERT_DATA_DIR` points at it, `CULVERT_CA_PASSPHRASE=test-passphrase` so the CA bundle is encrypted as on a real install)
- ports: proxy `20200`, admin UI `20201` (https, self-signed, `-k`), allowed origin `127.0.0.1:20202` (`python3 -m http.server`), credentialed parent proxy `127.0.0.1:20203`, unmatched origin `127.0.0.1:20204`
- proxy env caveat: admin-API calls use `--noproxy '*'`; proxied requests clear `*_proxy`/`no_proxy` from the environment (with `--noproxy '*'` curl bypasses the `-x` proxy under test as well — observed during development, hence the split)

### Binaries (sha256)

| role | file | sha256 | reports |
|---|---|---|---|
| FROM | `culvert-linux-amd64-v1.0.258` | `667eeae8583cbba2544571597dc2ccc9e5575ed18c3b8e0a5162a84c569a6ea5` | `v1.0.258` (/healthz and /ready) |
| TO | `culvert-linux-amd64-v1.0.259` | `3ba95443374ea7bbf1b8d1fe826089267414a3de93e6b51f1081a99c9bb0b5a0` | `v1.0.259` (/healthz and /ready) |
| FROM maint agent (not executed — host-root component with no state-root involvement; recorded for the release pair) | `culvert-maint-linux-amd64-v1.0.258` | `1a7fea60fe41d7516bc10be23f6247dcff0771f8d0375b4bad2782675f3120e7` | — |
| TO maint agent (not executed) | `culvert-maint-linux-amd64-v1.0.259` | `ed499b2abd6c0e58b82cac24a8afcec9242adec27e6f5bd3c58add9d97ec8cc5` | — |

## Command

```bash
PORT_BASE=20200 ./test/appliance/predecessor-upgrade.sh \
  /tmp/claude-0/artifacts/culvert-linux-amd64-v1.0.258 \
  /tmp/claude-0/artifacts/culvert-linux-amd64-v1.0.259 \
  /tmp/claude-0/-home-user-Culvert/cf36caf0-214a-5d31-ba4b-95168e4ca302/scratchpad/predecessor/run-258-259/state \
  /tmp/claude-0/-home-user-Culvert/cf36caf0-214a-5d31-ba4b-95168e4ca302/scratchpad/predecessor/run-258-259/evidence
# exit status 0 (verdict PASS)
```

Each boot used the compose-equivalent flag set:

```
CULVERT_DATA_DIR=<root> CULVERT_CA_PASSPHRASE=test-passphrase <binary> -port 20200 -ui-port 20201 \
  -ca-path <root>/ca.bundle -policy <root>/policy.json -ui-users-file <root>/ui_users.json \
  -audit-log <root>/audit.jsonl -request-log <root>/requests.jsonl -logfile <root>/proxy.log \
  -revocations-file <root>/revocations.json -idp-profiles-file <root>/idp_profiles.json -fileprofiles-file <root>/fileprofiles.json
```

## Processes

- allowed origin pid 9507 (127.0.0.1:20202), unmatched origin pid 9508 (127.0.0.1:20204), parent proxy pid 9509 (127.0.0.1:20203)
- `A-from`: pid 9562 — exited after SIGTERM (see `*.sigterm_exit` rows)
- `B-to`: pid 9929 — exited after SIGTERM (see `*.sigterm_exit` rows)
- `C-from-again`: pid 10283 — exited after SIGTERM (see `*.sigterm_exit` rows)
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
POST /api/upstream/entries/01M3Y0X8AX4H6ETMF5KSNTN9DK/credential {action:replace,password:<redacted>,revision:1} -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","entries":1,"eligible":1,"fallbackTotal":…
GET /api/upstream -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","entries":1,"eligible":1,"fallbackTotal":…
POST /api/alerts/webhooks {…,secret:<redacted>} -> 200 {"id":"1790935212602960453","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}
GET /api/alerts/webhooks -> 200 {"webhooks":[{"id":"1790935212602960453","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}]}
GET /api/config/versions -> 200 [{"version":2,"created_at":"2026-10-02T10:00:12Z","actor":"admin","action":"policy.add"},{"version":1,"created_at":"2026-10-02T10:00:12Z","actor":"admin","action":"policy.default_action"}]
```

Request bodies used: `{"user":"admin","pass":"<strong>"}` (setup + login), `{"action":"deny"}`, `{"name":"allow-local-origin","priority":10,"destFQDN":"localhost","action":"Allow","enabled":true}` (note the capitalised `Allow` — the engine rejects lowercase `allow` with 400 `action must be Allow, Drop, Block_Page, or Redirect`), `{"scheme":"http","host":"127.0.0.1","port":20203,"username":"parentuser","revision":1}`, `{"action":"replace","password":"<parent password>","revision":1}`, `{"name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true,"secret":"<secret>"}`.

`audit.jsonl` after leg A (file tail, verbatim; the rule's `after` blob is the full rule JSON):

```
{"ts":1790935212085,"time":"2026-10-02 10:00:12","actor":"127.0.0.1","action":"setup.complete","object":"admin","detail":"first-time admin password configured"}
{"ts":1790935212200,"time":"2026-10-02 10:00:12","actor":"admin@127.0.0.1","action":"auth.login","object":"admin","detail":"admin UI login role=admin"}
{"ts":1790935212245,"time":"2026-10-02 10:00:12","actor":"admin@127.0.0.1","action":"policy.default_action","object":"deny","detail":""}
{"ts":1790935212316,"time":"2026-10-02 10:00:12","actor":"admin@127.0.0.1","action":"policy.add","object":"allow-local-origin","objectId":"01M3Y0X88TRA5EFNA5QE3Z928Q","detail":"priority=10 action=Allow","after":"{\"priority\":10,\"name\":\"allow-local-origin\",\"sourceIP\":\"\",\"sourceIdentity\":\"\",\"sourceGroup\":\"\",\"authSource\":\"\",\"destFQDN\":\"localhost\",\"destCategory\":\"\",\"destC…
{"ts":1790935212382,"time":"2026-10-02 10:00:12","actor":"admin@127.0.0.1","action":"upstream.entry.create","object":"01M3Y0X8AX4H6ETMF5KSNTN9DK","detail":"authority=http://parentuser@127.0.0.1:20203"}
{"ts":1790935212475,"time":"2026-10-02 10:00:12","actor":"admin@127.0.0.1","action":"upstream.credential.replace","object":"01M3Y0X8AX4H6ETMF5KSNTN9DK","detail":"authority=http://parentuser@127.0.0.1:20203"}
{"ts":1790935212604,"time":"2026-10-02 10:00:12","actor":"admin@127.0.0.1","action":"alert.webhook.create","object":"1790935212602960453","detail":"https://siem.example.invalid/culvert-hook"}
```

## Assertions

Legend: A = FROM on a fresh root, B = TO on the same root (upgrade), C = FROM again on the same root (reverse leg / downgrade tolerance). `enforce.*` rows are the SAME three proxied requests on every leg.

| leg | status | check | detail |
|---|---|---|---|
| A | PASS | `A-from.ready` | /ready answered 200 (pid 9562) |
| A | INFO | `A.version` | /healthz version=v1.0.258 /ready version=v1.0.258 |
| A | PASS | `A.setup_status_needs_setup` | got true |
| A | PASS | `A.setup_complete_200` | got 200 |
| A | PASS | `A.login_200` | got 200 |
| A | PASS | `A.default_action_set_deny` | got deny |
| A | PASS | `A.allow_rule_created` | id=01M3Y0X88TRA5EFNA5QE3Z928Q destFQDN=localhost action=Allow |
| A | PASS | `A.upstream_entry_created` | id=01M3Y0X8AX4H6ETMF5KSNTN9DK authority=http://parentuser@127.0.0.1:20203 revision=1 |
| A | PASS | `A.upstream_credential_sealed` | got configured |
| A | INFO | `A.upstream_health` | health= {'status': 'unprobed', 'reason': 'none'} eligible= True mode= chained key= {'state': 'present', 'keyId': 'af3758cf06c0f947'} |
| A | PASS | `A.webhook_created` | id=1790935212602960453 |
| A | PASS | `A.webhook_not_signing_degraded` | got False |
| A | PASS | `A.config_version_autocreated` | 2 version(s): ['policy.add', 'policy.default_action'] |
| A | INFO | `A.admin_settings_schema` | admin_settings_schema=2 keys=43 |
| A | INFO | `A.ca_bundle_sha` | 95d99449b7330b9c05eb8bff4ac7f15d5f0af4397b581b10155f3554a91d87ea |
| A | PASS | `enforce.allowed_origin_with_credentials_200` | got 200 |
| A | PASS | `enforce.chained_via_credentialed_parent` | X-Parent-Proxy: seen — the sealed upstream credential was unsealed and accepted by the parent |
| A | PASS | `enforce.unmatched_origin_default_deny_403` | got 403 |
| A | PASS | `enforce.no_credentials_407` | got 407 |
| A | INFO | `A.ready_fail_rows` | [none] |
| A | INFO | `A.diagnostics` | verdict=ok non-ok rows: [none] |
| A | PASS | `A-from.sigterm_exit` | pid 9562 exited after SIGTERM |
| A | PASS | `A.no_quarantine_files` | clean after FROM shutdown |
| B | PASS | `B-to.ready` | /ready answered 200 (pid 9929) |
| B | PASS | `B.no_quarantine_files` | no *.corrupt.* / quarantine artefacts in the state root |
| B | PASS | `B.admin_settings_parses` | admin_settings.json parses (admin_settings_schema=2) |
| B | PASS | `B.admin_settings_schema_unchanged` | got 2 |
| B | PASS | `B.login_same_password` | got 200 |
| B | PASS | `B.upstream_entry_present` | got 1 |
| B | PASS | `B.upstream_credential_configured` | got configured |
| B | INFO | `B.upstream_key_mode_migration` | key.state/mode/migration.state = present chained ok |
| B | PASS | `B.webhook_still_listed` | got 1790935212602960453 |
| B | PASS | `B.webhook_not_signing_degraded` | got False |
| B | PASS | `B.default_action_deny` | got deny |
| B | PASS | `B.allow_rule_present` | got 01M3Y0X88TRA5EFNA5QE3Z928Q:allow-local-origin:Allow |
| B | PASS | `enforce.allowed_origin_with_credentials_200` | got 200 |
| B | PASS | `enforce.chained_via_credentialed_parent` | X-Parent-Proxy: seen — the sealed upstream credential was unsealed and accepted by the parent |
| B | PASS | `enforce.unmatched_origin_default_deny_403` | got 403 |
| B | PASS | `enforce.no_credentials_407` | got 407 |
| B | INFO | `B.version` | /healthz version=v1.0.259 /ready version=v1.0.259 |
| B | PASS | `B.ready_no_new_fail_rows` | fail rows now: [none] ⊆ leg A: [none] |
| B | PASS | `B.ca_bundle_sha_unchanged` | got 95d99449b7330b9c05eb8bff4ac7f15d5f0af4397b581b10155f3554a91d87ea |
| B | PASS | `B.diagnostics_verdict_not_worse` | verdict ok (leg A: ok) |
| B | INFO | `B.diagnostics_non_ok_rows` | now: [none] ; leg A: [none] |
| B | INFO | `B.config_versions` | 2 version(s): [(1, 'policy.default_action'), (2, 'policy.add')] |
| B | PASS | `B-to.sigterm_exit` | pid 9929 exited after SIGTERM |
| C | PASS | `C-from-again.ready` | /ready answered 200 (pid 10283) |
| C | PASS | `C.no_quarantine_files` | no *.corrupt.* / quarantine artefacts in the state root |
| C | PASS | `C.admin_settings_parses` | admin_settings.json parses (admin_settings_schema=2) |
| C | PASS | `C.admin_settings_schema_unchanged` | got 2 |
| C | PASS | `C.login_same_password` | got 200 |
| C | PASS | `C.upstream_entry_present` | got 1 |
| C | PASS | `C.upstream_credential_configured` | got configured |
| C | INFO | `C.upstream_key_mode_migration` | key.state/mode/migration.state = present chained ok |
| C | PASS | `C.webhook_still_listed` | got 1790935212602960453 |
| C | PASS | `C.webhook_not_signing_degraded` | got False |
| C | PASS | `C.default_action_deny` | got deny |
| C | PASS | `C.allow_rule_present` | got 01M3Y0X88TRA5EFNA5QE3Z928Q:allow-local-origin:Allow |
| C | PASS | `enforce.allowed_origin_with_credentials_200` | got 200 |
| C | PASS | `enforce.chained_via_credentialed_parent` | X-Parent-Proxy: seen — the sealed upstream credential was unsealed and accepted by the parent |
| C | PASS | `enforce.unmatched_origin_default_deny_403` | got 403 |
| C | PASS | `enforce.no_credentials_407` | got 407 |
| C | INFO | `C.version` | /healthz version=v1.0.258 /ready version=v1.0.258 |
| C | PASS | `C.ready_no_new_fail_rows` | fail rows now: [none] ⊆ leg A: [none] |
| C | PASS | `C.ca_bundle_sha_unchanged` | got 95d99449b7330b9c05eb8bff4ac7f15d5f0af4397b581b10155f3554a91d87ea |
| C | PASS | `C.diagnostics_verdict_not_worse` | verdict ok (leg A: ok) |
| C | INFO | `C.diagnostics_non_ok_rows` | now: [none] ; leg A: [none] |
| C | INFO | `C.config_versions` | 2 version(s): [(1, 'policy.default_action'), (2, 'policy.add')] |
| C | PASS | `C-from-again.sigterm_exit` | pid 10283 exited after SIGTERM |

## Enforcement — verbatim curl output per leg

`X-Parent-Proxy: seen` is added by the credentialed parent proxy only when Culvert presented the correct `Proxy-Authorization` for the sealed upstream credential, so a 200 on the allowed origin proves the credential unsealed on that binary. The 403 body is the Culvert block page (HTML, trimmed here).

### Leg A — FROM v1.0.258

```
$ curl -s -x http://127.0.0.1:20200 -U admin:<ADMIN_PASS> http://localhost:20202/
HTTP/1.1 200 OK
Content-Length: 26
Content-Type: text/plain
Date: Fri, 02 Oct 2026 10:00:12 GMT
Server: BaseHTTP/0.6 Python/3.11.15
X-Parent-Proxy: seen
X-Request-Id: 8d5b766ec0e8e731
hello-from-allowed-origin
[http_code=200]
```
```
$ curl -s -x http://127.0.0.1:20200 -U admin:<ADMIN_PASS> http://127.0.0.1:20204/
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Request-Id: 63ab77cb8eeaeb9d
Date: Fri, 02 Oct 2026 10:00:13 GMT
Transfer-Encoding: chunked
[http_code=403]
```
```
$ curl -s -x http://127.0.0.1:20200 http://localhost:20202/
HTTP/1.1 407 Proxy Authentication Required
Content-Type: text/plain; charset=utf-8
Proxy-Authenticate: Basic realm="Culvert"
X-Content-Type-Options: nosniff
X-Request-Id: 5ed658fa06e041f8
Date: Fri, 02 Oct 2026 10:00:13 GMT
Content-Length: 30
Proxy Authentication Required
[http_code=407]
```

### Leg B — TO v1.0.259

```
$ curl -s -x http://127.0.0.1:20200 -U admin:<ADMIN_PASS> http://localhost:20202/
HTTP/1.1 200 OK
Content-Length: 26
Content-Type: text/plain
Date: Fri, 02 Oct 2026 10:00:14 GMT
Server: BaseHTTP/0.6 Python/3.11.15
X-Parent-Proxy: seen
X-Request-Id: 452c1c46f0d6083e
hello-from-allowed-origin
[http_code=200]
```
```
$ curl -s -x http://127.0.0.1:20200 -U admin:<ADMIN_PASS> http://127.0.0.1:20204/
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Request-Id: 258e7a8b49e33524
Date: Fri, 02 Oct 2026 10:00:14 GMT
Transfer-Encoding: chunked
[http_code=403]
```
```
$ curl -s -x http://127.0.0.1:20200 http://localhost:20202/
HTTP/1.1 407 Proxy Authentication Required
Content-Type: text/plain; charset=utf-8
Proxy-Authenticate: Basic realm="Culvert"
X-Content-Type-Options: nosniff
X-Request-Id: 1d456b399271c476
Date: Fri, 02 Oct 2026 10:00:14 GMT
Content-Length: 30
Proxy Authentication Required
[http_code=407]
```

### Leg C — FROM again v1.0.258

```
$ curl -s -x http://127.0.0.1:20200 -U admin:<ADMIN_PASS> http://localhost:20202/
HTTP/1.1 200 OK
Content-Length: 26
Content-Type: text/plain
Date: Fri, 02 Oct 2026 10:00:16 GMT
Server: BaseHTTP/0.6 Python/3.11.15
X-Parent-Proxy: seen
X-Request-Id: 9fd7a90bf99d2a06
hello-from-allowed-origin
[http_code=200]
```
```
$ curl -s -x http://127.0.0.1:20200 -U admin:<ADMIN_PASS> http://127.0.0.1:20204/
HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Request-Id: cca34849237844d1
Date: Fri, 02 Oct 2026 10:00:16 GMT
Transfer-Encoding: chunked
[http_code=403]
```
```
$ curl -s -x http://127.0.0.1:20200 http://localhost:20202/
HTTP/1.1 407 Proxy Authentication Required
Content-Type: text/plain; charset=utf-8
Proxy-Authenticate: Basic realm="Culvert"
X-Content-Type-Options: nosniff
X-Request-Id: 1333ac42ac9fbf47
Date: Fri, 02 Oct 2026 10:00:16 GMT
Content-Length: 30
Proxy Authentication Required
[http_code=407]
```

## Health, readiness and diagnostics per leg

- leg A `/healthz`: `{"leader":true,"role":"standalone","status":"ok","version":"v1.0.258","write_authority":true}`
- leg A `/ready`: `{"status":"ready","uptime":"0m 2s","version":"v1.0.258","checks":{"admin_ui":{"status":"ok"},"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"ok"},"saas_feed":{"status":"ok","detail":"disabled (embedded baseline)"},"session_secret":{"status":"ok"}}}`
- leg A `/api/diagnostics`: verdict `ok`, 41 rows, non-ok rows: none
- leg B `/healthz`: `{"leader":true,"role":"standalone","status":"ok","version":"v1.0.259","write_authority":true}`
- leg B `/ready`: `{"status":"ready","uptime":"0m 1s","version":"v1.0.259","checks":{"admin_ui":{"status":"ok"},"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"ok"},"saas_feed":{"status":"ok","detail":"disabled (embedded baseline)"},"session_secret":{"status":"ok"}}}`
- leg B `/api/diagnostics`: verdict `ok`, 41 rows, non-ok rows: none
- leg C `/healthz`: `{"leader":true,"role":"standalone","status":"ok","version":"v1.0.258","write_authority":true}`
- leg C `/ready`: `{"status":"ready","uptime":"0m 1s","version":"v1.0.258","checks":{"admin_ui":{"status":"ok"},"ca":{"status":"ok"},"config_snapshot_validator":{"status":"ok"},"policy_loaded":{"status":"ok"},"saas_feed":{"status":"ok","detail":"disabled (embedded baseline)"},"session_secret":{"status":"ok"}}}`
- leg C `/api/diagnostics`: verdict `ok`, 41 rows, non-ok rows: none
- diagnostics row set: rows only reported by v1.0.259: none; rows only reported by v1.0.258: none

Admin-API read-backs on legs B and C (from the transcript):

```
[B] POST /api/auth/login -> 200 {"ok":true,"role":"admin","user":"admin"}
[B] GET /api/upstream -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","…
[B] GET /api/alerts/webhooks -> 200 {"webhooks":[{"id":"1790935212602960453","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}]}
[B] GET /api/default-action -> 200 {"defaultAction":"deny"}
[B] GET /api/policy -> 200 {"count":1,"draft":false,"persisted":true,"rules":[{"priority":10,"name":"allow-local-origin","sourceIP":"","sourceIdentity":"","sourceGroup":"","authSource":"","destFQDN":"localhost","destCategory":"","destCategoryGroup":"","destCountry":null,"sslAction":"","…
[B] GET /api/config/versions -> 200 [{"version":2,"created_at":"2026-10-02T10:00:12Z","actor":"admin","action":"policy.add"},{"version":1,"created_at":"2026-10-02T10:00:12Z","actor":"admin","action":"policy.default_action"}]
[C] POST /api/auth/login -> 200 {"ok":true,"role":"admin","user":"admin"}
[C] GET /api/upstream -> 200 {"coverage":{"connect":"direct","plainHttp":"chained","socks5":"direct","summary":"plain_http_only","websocket":"direct"},"credentialsIneligible":0,"credentialsRequiringReplacement":0,"direct_fallback":{"active":false,"total":0},"effective":{"mode":"chained","…
[C] GET /api/alerts/webhooks -> 200 {"webhooks":[{"id":"1790935212602960453","name":"pilot-siem","url":"https://siem.example.invalid/culvert-hook","events":["cert_expiry","storage_write_failed"],"enabled":true}]}
[C] GET /api/default-action -> 200 {"defaultAction":"deny"}
[C] GET /api/policy -> 200 {"count":1,"draft":false,"persisted":true,"rules":[{"priority":10,"name":"allow-local-origin","sourceIP":"","sourceIdentity":"","sourceGroup":"","authSource":"","destFQDN":"localhost","destCategory":"","destCategoryGroup":"","destCountry":null,"sslAction":"","…
[C] GET /api/config/versions -> 200 [{"version":2,"created_at":"2026-10-02T10:00:12Z","actor":"admin","action":"policy.add"},{"version":1,"created_at":"2026-10-02T10:00:12Z","actor":"admin","action":"policy.default_action"}]
```

Audit entries recorded by the TO and the FROM-again boots (`GET /api/audit?limit=8`, action/object only):

- leg B: `auth.login:admin`, `alert.webhook.create:1790935212602960453`, `upstream.credential.replace:01M3Y0X8AX4H6ETMF5KSNTN9DK`, `upstream.entry.create:01M3Y0X8AX4H6ETMF5KSNTN9DK`, `policy.add:allow-local-origin`, `policy.default_action:deny`, `auth.login:admin`, `setup.complete:admin`
- leg C: `auth.login:admin`, `auth.login:admin`, `alert.webhook.create:1790935212602960453`, `upstream.credential.replace:01M3Y0X8AX4H6ETMF5KSNTN9DK`, `upstream.entry.create:01M3Y0X8AX4H6ETMF5KSNTN9DK`, `policy.add:allow-local-origin`, `policy.default_action:deny`, `auth.login:admin`

## State root — sha256 after each leg

`upgrade` = after-FROM vs after-TO, `downgrade` = after-TO vs after-FROM-again. Append-only logs and the hit counter are expected to change; every durable configuration/trust file must be unchanged.

| file | after A (FROM) | after B (TO) | after C (FROM again) | upgrade | downgrade |
|---|---|---|---|---|---|
| `.alert_webhook_key` | `f05164262632c0829c4868a391573a3739886929f12839015591811b7cdb6bb1` | `f05164262632c0829c4868a391573a3739886929f12839015591811b7cdb6bb1` | `f05164262632c0829c4868a391573a3739886929f12839015591811b7cdb6bb1` | same | same |
| `.upstream_cred_key` | `af3758cf06c0f947620d779924f495143bdcb489d0b0f5e03f1a723165200c80` | `af3758cf06c0f947620d779924f495143bdcb489d0b0f5e03f1a723165200c80` | `af3758cf06c0f947620d779924f495143bdcb489d0b0f5e03f1a723165200c80` | same | same |
| `admin_settings.json` | `c179b355d1c45111033b24930ff0194bd5a60288357886b9654ef1421ceaa7af` | `c179b355d1c45111033b24930ff0194bd5a60288357886b9654ef1421ceaa7af` | `c179b355d1c45111033b24930ff0194bd5a60288357886b9654ef1421ceaa7af` | same | same |
| `alert_webhooks.json` | `4415511ac1f793f6c11934b395fab1af6503cae34f8215caa0dc627b36de3c99` | `4415511ac1f793f6c11934b395fab1af6503cae34f8215caa0dc627b36de3c99` | `4415511ac1f793f6c11934b395fab1af6503cae34f8215caa0dc627b36de3c99` | same | same |
| `audit.jsonl` | `2d8cd19cee8a7ecd18bee547cc761126050bc7df28b45fed0635040e1275da63` | `31b11a99537c9a4c4ea03217d2a6091b9d4b6cdb72f3313b14cfb41962da64b4` | `4fbbb7f041ded6c08d00a344aa3cacf069db1fdd86b4ddf216a3319b33eb5b4e` | changed | changed |
| `ca.bundle` | `95d99449b7330b9c05eb8bff4ac7f15d5f0af4397b581b10155f3554a91d87ea` | `95d99449b7330b9c05eb8bff4ac7f15d5f0af4397b581b10155f3554a91d87ea` | `95d99449b7330b9c05eb8bff4ac7f15d5f0af4397b581b10155f3554a91d87ea` | same | same |
| `config_versions/v1.json` | `275055a7b58936e0e574b98c8f97442265c3dd3bf0b4591e97247e93572ce2f6` | `275055a7b58936e0e574b98c8f97442265c3dd3bf0b4591e97247e93572ce2f6` | `275055a7b58936e0e574b98c8f97442265c3dd3bf0b4591e97247e93572ce2f6` | same | same |
| `config_versions/v2.json` | `0f6d0b0bac7541f2fc33a8e97a7c45003a4848642f59159a883989f3f6425902` | `0f6d0b0bac7541f2fc33a8e97a7c45003a4848642f59159a883989f3f6425902` | `0f6d0b0bac7541f2fc33a8e97a7c45003a4848642f59159a883989f3f6425902` | same | same |
| `decryption_profiles.json` | `02dc325172a812f6a59a87cc74898a6e7193093d693665b43e56935b9fff8178` | `02dc325172a812f6a59a87cc74898a6e7193093d693665b43e56935b9fff8178` | `02dc325172a812f6a59a87cc74898a6e7193093d693665b43e56935b9fff8178` | same | same |
| `fileprofiles.json` | `b70d748820fb818a74b577d5b998ecb717a313b37e9246c89aa60e4fe14b900b` | `b70d748820fb818a74b577d5b998ecb717a313b37e9246c89aa60e4fe14b900b` | `b70d748820fb818a74b577d5b998ecb717a313b37e9246c89aa60e4fe14b900b` | same | same |
| `hit_counters.json` | `efffd05daeeb737fde55f508526384cd78c35d2759d2b9ef2d9fa5b42e77f55e` | `c811f0742679e41b02ad4fb7636385210abda6080ad53e920029b20cc1808853` | `fb8c24acaa7e666938d00e2c3daca7f06167e1e87c285c95f5f2be611e288335` | changed | changed |
| `policy.json` | `10b5e712830b3ceacff9ac10d19066725486da008b52625ae759879ed2439382` | `10b5e712830b3ceacff9ac10d19066725486da008b52625ae759879ed2439382` | `10b5e712830b3ceacff9ac10d19066725486da008b52625ae759879ed2439382` | same | same |
| `policy.json.meta` | `67aeafb320f06a8c368d26f29c15051dd2264b44b318e4816b122356d57bd444` | `67aeafb320f06a8c368d26f29c15051dd2264b44b318e4816b122356d57bd444` | `67aeafb320f06a8c368d26f29c15051dd2264b44b318e4816b122356d57bd444` | same | same |
| `proxy.log` | `0737430fe6b994a39e655587a8f438627d69a720f61eb6c5560c1af47519b4a5` | `207b622630d391b957486a7654d0f369941f5c0a94113d564bd2e8eeb9db404e` | `7303f77251b5a51bca5dbcda94b45ddc58c8be6dc7a0322b0f283ddd35920d08` | changed | changed |
| `requests.jsonl` | `15204bd78f9907b52429ff31e9465926c5f6de7fcc7ae41c19c91179114c3bc2` | `25cc82765d046d5f3eb6d7df0b4059101e070216b35f1af1db6296a8c2e890e3` | `23a7c472db83e0fd211e76e235876666de5d43bf1a6e10a03f69af608ed6fcb6` | changed | changed |
| `ui_users.json` | `285a5ad2a0c6d56f31f798c4ff302126a19d36f265250a6f18b3182d01defe0a` | `285a5ad2a0c6d56f31f798c4ff302126a19d36f265250a6f18b3182d01defe0a` | `285a5ad2a0c6d56f31f798c4ff302126a19d36f265250a6f18b3182d01defe0a` | same | same |

No `*.corrupt.*`, `*quarantin*` or `*.poison*` artefact appeared at any point (asserted after every boot). No file was added or removed by the TO boot or by the FROM-again boot (the file set is identical in all three snapshots).

## Compatibility notes

- No API-shape difference observed between v1.0.258 and v1.0.259 on any surface the script reads (`/api/policy`, `/api/upstream`, `/api/alerts/webhooks`, `/api/default-action`, `/api/diagnostics` row set, `/ready` row set).
- `admin_settings_schema: 2` on both binaries; the file is byte-identical after the upgrade and after the downgrade.

## Findings

- No assertion failed on the upgrade leg (B) or on the reverse leg (C). v1.0.259 booted the v1.0.258-written root without rewriting a single durable file (`admin_settings.json`, `ui_users.json`, `policy.json`, `alert_webhooks.json`, `ca.bundle`, both node-local key files and both config-version snapshots are byte-identical across all three boots), and v1.0.258 booted the root again after v1.0.259 had run on it with the same result.
- The sealed upstream credential (AES-GCM under `.upstream_cred_key`, bound to the entry id + authority hash) and the encrypted webhook secret (`.alert_webhook_key`) were usable on every leg: `credentialState: configured`, `signing_degraded` absent, and the live chained request carried the credential to the parent.
- The three enforcement decisions (Allow rule → 200 via the parent; default-deny → 403 block page; no credentials → 407) are identical on all three boots.
- Observed, not a defect: `hit_counters.json`, `proxy.log`, `requests.jsonl` and `audit.jsonl` change on every boot (append-only logs and the rule hit counter); the request log records the three probes per leg.

