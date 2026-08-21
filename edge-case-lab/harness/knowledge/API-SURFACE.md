# Culvert Admin API Surface (Operator ground truth)

## Auth
- GET /api/setup/status -> {needsSetup}
- POST /api/setup/complete {user,pass} | {unauth:true}  (first-run only; 403 if configured)
- POST /api/auth/login {user,pass,totp} -> sets ps_ui_session cookie; {totp_required:true} if TOTP
- In OPEN/unconfigured mode: all /api/ granted RoleAdmin. Basic Auth also accepted every call.

## CSRF: origin-based. Omit Origin header => allowed (curl/API clients). No token needed.
- Mutating body cap 1 MiB. Mutating /api/ rate-limited per client IP (429). Throttle config bursts.

## Policy core
- GET /api/policy ; POST/PUT/DELETE /api/policy (PolicyRule JSON; name required; ?ifVersion=N optimistic; ?id= for PUT/DELETE)
- POST /api/policy/reorder ; /api/policy/move ; POST /api/policy/test (DRY-RUN match) 
- POST /api/default-action {"action":"allow"|"deny"}
- PUT /api/settings/default-auth-outcome {"defaultAuthOutcome":"Default"|"Exempt"}
- GET/POST/PUT/DELETE /api/authpolicy (Stage-1 auth rules; ruleType=auth)
- POST /api/urlcat {name,hosts[]} ; POST/DELETE /api/urlcat/host {category,host} ; GET /api/urlcat/lookup
- POST /api/category-groups {name,categories[]}
- POST /api/decryption-profiles (Profile JSON)
- GET/DELETE /api/decryption-exclusions
- POST/DELETE /api/ssl-bypass
- GET/POST/DELETE /api/blocklist {host}|{hosts[]} ; /api/blocklist/mode ; /api/blocklist/feed ; /api/blocklist/exceptions
- GET/POST/PUT/DELETE /api/fileblock ; /api/fileblock/profiles
- GET /api/objects/references (where-used)
- GET /api/config/export ; POST /api/config/import ; /api/config/versions ; /api/config/diff

## Read-back / trace
- GET /api/policy (rules+version), GET /api/config/export (effective config)
- GET /api/logs (request log), GET /api/audit (audit ring), GET /api/stats, GET /api/dashboard/*
- GET /metrics (prometheus culvert_*)

## PolicyRule JSON (json tags):
priority,name,sourceIP,sourceIdentity,sourceGroup,authSource,destFQDN,destCategory,destCategoryGroup,
destCountry[],schedule{days[],timeStart,timeEnd,timezone},sslAction(Inspect|Bypass),fileFiltering,
fileProfile,logFullUri,logTraffic,tlsSkipVerify,stripAlpn,decryptionProfile,action(Allow|Drop|Block_Page|Redirect),
redirectURL,enabled,id,ruleType(access|auth),comment
- POST /api/policy rejects ruleType=auth (use /api/authpolicy).
- createdAt/modifiedAt/modifiedBy server-stamped.

## DecryptionProfile JSON:
id,name,inspectHttp2,certVerification(strict|skip),onUnsupported(fail-close|fail-open),
onInspectError(fail-close|fail-open),minTlsVersion,maxTlsVersion,stallTimeoutSecs

## Roles: admin>operator>viewer. policy CRUD=operator; authpolicy/idp/settings=admin; reads=viewer.
