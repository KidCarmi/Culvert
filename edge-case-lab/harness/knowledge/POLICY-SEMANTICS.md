# Policy Engine Semantics (Oracle ground truth) — captured from source analysis
(See git commit for exact line refs; summary below drives oracle.py)

## PolicyRule (policy.go) — first-match by Priority ASC (lower first)
Match conditions (all configured conds ANDed): sourceIP (IP or CIDR), sourceIdentity (EqualFold),
sourceGroup (case-insensitive membership), authSource, destFQDN (glob), destCategory (single),
destCategoryGroup, destCountry ([]ISO2, GeoIP cache-only FAIL-CLOSED), schedule (days+HH:MM, tz).
NO http-method condition on Stage-2 access rules.

Actions: Allow, Drop (silent TCP RST, no HTTP response), Block_Page (branded HTML block page),
Redirect (302 to RedirectURL; invalid redirect => 403).
SSLAction: Inspect | Bypass.

## Matching order in Evaluate:
skip if !enabled; skip if ruleType != access (auth rules inert in stage2);
skip if !matchSourceAddr; skip if !matchSchedule; skip if !matchDestNorm.
First match wins -> returns PolicyMatch. No match -> nil.

## No-match default (applyPolicyDecision):
defaultPolicyAction()=="allow" -> passthrough (OK/default-allow).
else -> POLICY_DEFAULT_DENY block page (zero trust). This is a PROCESS-GLOBAL, separate from defaultAuthOutcome.

## FQDN glob (hostutil.MatchFQDNNorm):
"*" => all. "*.example.com" => suffix ".example.com" OR host=="example.com".
Bare "example.com" (PAN-style) => host==pattern OR suffix ".example.com" (implicitly includes subdomains).
IDNA-normalized both sides.

## SSL decision (resolveSSLAction) precedence:
base = Bypass; if matched rule SSLAction==Inspect => Inspect.
explicit operator sslBypass.Matches(host) overrides Inspect->Bypass (SSL_BYPASS_PATTERN).
then adaptive auto-exclusion (only if rule names a fail-open DecryptionProfile & host in scoped cache).
=> precedence: explicit ssl-bypass > learned auto-exclusion (same scope) > policy inspect.

## Schedule (matchSchedule): nil=always. Day = Weekday()[:3] case-insensitive in Days.
Time HH:MM string compare; normal start<=cur<end; overnight start>end.

## Auth enforcement (resolveRequestAuth, BEFORE policy engine):
defaultAuthOutcome (Default vs Exempt) governs no-rule no-credential case:
 Default => fail-closed: 407 Proxy-Authenticate Basic (or 302 captive portal for browsers).
 Exempt => open (unauth), fall through to Stage-2 (DEFAULT-DENY STILL APPLIES: open != allow).
Proxy-Authorization Basic failure => 407. SSORequired browser => 302 portal else 403.

## Pre-policy gates (preDispatchBlocked) run BEFORE policy engine (block regardless of allow rule):
legacy blocklist (403), threat-intel feed (block page), plugin (403), file-ext profile (block page).

## Inner decrypted requests (SSL inspect) re-checked: global file-ext blocklist, per-rule FileProfileBlocked,
Content-Disposition, MIME, magic-byte/polyglot, CDR, DPI, ClamAV/YARA. Each fail-closed.

## SOCKS5 does NOT run PBAC policy engine — only IDNA gate, legacy blocklist, plugin, SSRF, dial. CONNECT only.

## Decision trace / request log Entry fields: TS,Time,IP,Identity,Method,Host,URI(if LogFullURI),
Status(OK/BLOCKED/POLICY_DROP/POLICY_BLOCK/POLICY_REDIRECT/POLICY_DEFAULT_DENY/FILE_BLOCKED/THREAT_BLOCKED/
AUTH_FAIL/CRED_REQUIRED/...), RuleMatched(name), RuleID(ULID), ActionTaken, BytesSent/Recv, SSLAction, DurationMs.

## Fail-closed asymmetries for oracle:
GeoIP cache-miss=no-match; category-group unknown=no-match; invalid host IDNA=400; category community tier
requires exact case-insensitive category-name equality.
