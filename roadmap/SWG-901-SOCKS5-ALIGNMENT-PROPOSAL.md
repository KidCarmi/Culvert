# SWG-901 — SOCKS5 / Stage-2 policy alignment proposal

> **Status: proposal, awaiting owner decision.** No product behaviour is changed by this document.
> Evidence-backed investigation for the verification program (see roadmap/VERIFICATION-PROGRAM.md); a known, documented architecture gap (SWG-901), not a newly introduced vulnerability.

Revision inspected: `8178c19` (clean worktree). Read-only investigation; no code changed.
Contract: `contracts/registry.yaml:577-586` (SWG-901, `open`, `owner_approved: false`).
Marking: **[V]** verified by reading source at the cited line; **[U]** uncertain / not run end to end.

## 0. Summary

- SOCKS5 is **off by default** and can only be enabled at **startup** (flag/YAML); there is no runtime admin API/UI switch. **[V]**
- When enabled it binds **all interfaces** and applies conn-limit, IP filter, rate limit, a
  credential check, IDNA/length bounds, blocklist, plugin and SSRF guard. It applies **no
  Stage-2 policy (rules, categories, groups, geo, schedules, default-deny), no threat-feed check,
  no Stage-1 auth rules, no inspection/CDR/AV/DLP**, and logs **no identity or rule ID**. **[V]**
- Two findings go beyond the SWG-901 text: (a) the **threat-intel feed is skipped** too; (b) SOCKS5
  credential verification **does not consult the IdP registry** and yields **no identity/groups**,
  so identity/group rules could not match even if the evaluator were called. **[V]**
- Operator-facing docs do **not** disclose the gap. Two docs make it worse: the deployment guide's
  copy-paste examples **enable** `-socks5-port 1080`, and the enterprise prerequisites table lists
  SOCKS5 auth as "Policy". **[V]**
- Recommendation: treat SOCKS5 as **inside** the managed boundary; route it through the ADR-0026
  core with a three-state mode `legacy → shadow → enforce`, defaulting to `legacy` for existing
  deployments; fix docs and add a startup/health warning immediately (no behavior change).

## 1. Reachability

| Item | Evidence |
|---|---|
| Flag `-socks5-port`, default `0` = disabled | `main.go:335` **[V]** |
| YAML `proxy.socks5_port` (0 = disabled), range-checked | `config.go:27`, `config.go:661-662`; resolved `main.go:681` (flag wins if non-zero) **[V]** |
| Listener only started when port > 0 | `main.go:1158-1168` (`initSOCKS5`) **[V]** |
| Bind address is `":%d"` = all interfaces; no bind-address option exists | `socks5_bind.go:328` **[V]** |
| Env var | none found (`grep -i socks` over env/`Getenv` paths) **[V]** |
| Runtime enable via admin API/UI | none: no `SOCKS5Port` reference in `ui*.go`/`admin_settings.go`; only SOCKS5 UI strings are a webhook event (`static/index.html:20108`) and upstream-coverage text (`ui_upstream.go`, `frontend/src/features/network/upstream/upstreamShared.tsx:19`) **[V]** |
| `config.example.yaml` | `socks5_port: 0` (`config.example.yaml:22`) **[V]** |
| Dockerfile | `EXPOSE 8080 9090`; CMD has no `-socks5-port` (`Dockerfile:192`, `:218-225`) **[V]** |
| `docker-compose.yml` | no SOCKS5 **[V]** |
| `docker-compose.ha.yml` | publishes `1080:1080` (`:74`, `:220`) but the `ARGS` lists (`:129-140`, `:254-266`) do **not** pass `-socks5-port`, so nothing listens **[V]** (only the shown ARGS lines were read; later conditional appends set cp/ha flags only) |
| `docs/deployment-guide.md` examples | **enable** SOCKS5: compose `-socks5-port 1080` (`:31`, `:40`) and binary (`:69`) **[V]** |
| Helm / install scripts / systemd | no Helm chart in repo; `grep -i socks packaging/` empty **[V]** |
| Startup posture | listener is held closed (`NOT_READY`) until admin settings are restored (`socks5.go:456-460`, `persistent_admin_state_startup.go:60-69`), which runs after `initPolicy` and `initRewriteAndDefaultAction` (`main.go:270-298`) **[V]** — so policy and default action are installed before the first served SOCKS5 connection. |

Conclusion: reachable only when an operator opts in at startup, but the documented quickstart opts
in, and once on it is exposed on every interface.

## 2. SOCKS5 authentication

- Methods: NO-AUTH (0x00) when `!cfg.AuthEnabled()`; otherwise only RFC 1929 USER/PASS (0x02),
  else 0xFF (`socks5.go:356-373`). No GSSAPI, no IdP/SSO. **[V]**
- Predicate: `AuthEnabled()` = admin pair set ∨ roster non-empty ∨ legacy provider (`store.go:1522-1526`).
  This is **not** the HTTP Stage-1 predicate (`credCapable || ssoCapable || rosterWithoutVerifier ||
  Exempt default`, `proxy.go:404`), and SOCKS5 ignores Stage-1 auth rules and the default auth
  outcome entirely (auth rules with `protocol: socks5` are rejected: `authpolicy.go:1041-1042`). **[V]**
- Verifier: `cfg.VerifyAuthFrom` → legacy single provider, else the **local admin pair only**
  (`store.go:1356-1382`). HTTP tries `idpRegistry.EnabledCredentialProviders()` first
  (`proxy.go:477-486`). So in a registry-only LDAP/OIDC deployment, SOCKS5 users can only use the
  admin credential. **[V for the code path; U whether any deployment relies on this]**
- Identity at decision time: **none**. The bool result discards identity; `uname` is zeroed
  (`socks5.go:395-398`); every `recordRequest` passes identity `""` (`socks5.go:581`, tunnel close
  `:704`). Groups and authSource are never derived. An identity-returning call already exists:
  `cfg.resolveAuthIdentityFrom` (`store.go:1476`), used by HTTP (`proxy.go:498`). **[V]**

## 3. Control parity

| Control | HTTP | CONNECT | SOCKS5 | Evidence |
|---|---|---|---|---|
| Raw/canonical host length bounds | yes | yes | canonical only (RFC caps raw at 255) | `proxy.go:1587-1629`; `socks5.go:502-533` |
| Per-IP connection limit | yes | yes | yes | `proxy.go:1631`; `socks5.go:467` |
| IP filter (admission) | yes | yes | yes | `proxy.go:1645`; `socks5.go:428` |
| Rate limit `rl.AllowAuto` | yes | yes | yes | `proxy.go:1654`; `socks5.go:432` |
| Pre-posture gate | n/a | n/a | yes | `socks5.go:456` |
| Stage-1 auth (rules, Exempt, SSO, IdP registry) | yes | yes | **no**: legacy/admin USER/PASS only | `proxy.go:1664`; `socks5.go:345-408` |
| IDNA strict gate | yes | yes | yes | `proxy.go:1702-1709`; `socks5.go:514` |
| Blocklist (incl. allow-mode) | yes | yes | yes | `proxy.go:688`; `socks5.go:536`; `internal/blocklist/blocklist.go:456-470` |
| Threat feed (domain) | yes | yes | **no** | `proxy.go:698-705`; no `globalSecScanner` in `socks5*.go` |
| Threat feed (full URL) | yes | n/a | n/a | `proxy.go:707-720` |
| Plugin chain | yes | yes | yes | `proxy.go:725`; `socks5.go:545` |
| File-extension block | yes | inner only (inspect) | n/a (opaque) | `proxy.go:734-743` |
| Stage-2 policy: FQDN/category/group/geo/source/identity/schedule | yes | yes | **no** | `proxy.go:1738`; no `policyStore` in `socks5*.go` |
| Default action (deny when rules exist) | yes | yes | **no** (always allows) | `proxy.go:885-896`; `rewrite_default_action_startup.go:32-36` |
| Unknown-action fail-closed | yes | yes | n/a | `proxy.go:801-814` |
| TLS inspection / CDR / AV / DLP | yes (plain) | if `Inspect` | **no** | `proxy.go:1780-1799`; `cdr_proxy.go:236` |
| SSRF pre-flight + connect-time | **no** (SWG-900) | yes | yes | `proxy_tunnel.go:669-676`; `socks5.go:607,626` |
| Upstream chaining | yes | direct | direct | `upstreamShared.tsx:19` |
| Drain fence / drainable tunnel | n/a | yes | yes | `socks5.go:569`, `:660` |
| Request log: identity / rule ID / authSource | yes | yes | **no** (all empty) | `proxy.go:763+`; `socks5.go:402,581,704` |
| Rule hit counters / decision trace | yes | yes | **no** | `policy.go:1813-1814` |
| Metrics | stat counters | stat counters | stat counters + listener health only | `socks5.go:516,580`; `metrics.go:1336-1377` |
| Learning observation | yes | yes | no (and **walled**: `socks5.go` must not reference learning) | `policylearn_wall_test.go:170-180` |

Minor divergence: SOCKS5 passes IPv6 destinations **bracketed** (`socks5.go:324`) where HTTP passes
them unbracketed after `SplitHostPort` (`proxy.go:1681-1684`). Whether `hostutil.NormalizeHost`
strips brackets for the blocklist/plugin matchers was not checked. **[U]**

## 4. Compensating controls and disclosure

Compensating controls an operator has today: keep the port at 0; IP filter (source allowlist);
blocklist in `allow` mode (an FQDN allowlist that does reach SOCKS5); plugins; SSRF guard; per-IP
connection and rate limits; host firewalling (there is no bind-address option).

Disclosure:
- README advertises SOCKS5 as a first-class interface (`README.md:9`, `:40`, `:93`); "Limitations &
  Known Gaps" lists only "CONNECT only — UDP ASSOCIATE is rejected" (`README.md:378`). **No disclosure.**
- `docs/enterprise/ENTERPRISE-PREREQUISITES.md:113`: SOCKS5 row says Auth = "Policy". **Incorrect.**
- `docs/deployment-guide.md:31,40,69`: examples enable SOCKS5 with no caveat.
- No startup warning (only `"SOCKS5: socks5://localhost:%d"`, `socks5_bind.go:417`); no UI/health warning.
- Internal/roadmap acknowledgement exists: `roadmap/AUTHENTICATION-POLICY-SPEC.md:195-208` (hard
  invariant: no SOCKS5 auth exemption before Stage-2; Phase 4 behind a toggle defaulting to legacy
  allow-through, `:384-388`); `roadmap/AUTH-POLICY-PHASE1-PLAN.md:276-282`; security reviews
  2026-10-17 R5 and 2026-10-18 note it is undocumented in the README; `edge-case-lab/EDGE-CASE-FINDING-RECLASSIFICATION.md`
  Finding 1 classifies it SECURITY_BYPASS (High, latent/opt-in) and recommends a warning first.
- `roadmap/PACKAGE-ISOLATION.md:285` still carries it as "not rechecked"; this report rechecks it.

## 5. Customer impact

What a policy author expects vs what a SOCKS5 client gets (SOCKS5 enabled):

| Policy | HTTP/CONNECT | SOCKS5 today |
|---|---|---|
| `Drop`/`Block_Page` on category "Gambling" | refused | **allowed** |
| Default deny + Allow rules for group "eng" | non-matching traffic denied | **all allowed** |
| Source-subnet (tenant) restriction rule | enforced | **not enforced** (only global IP filter) |
| Geo / schedule rule | enforced | **not enforced** |
| Threat-feed domain | `THREAT_BLOCKED` | **allowed** |
| `Inspect` SSL action | MITM + CDR/AV | **raw tunnel** |
| SIEM attribution | identity, rule ID, authSource | IP + host only |

Destination information SOCKS5 lacks: with ATYP 0x01/0x04 (client resolved DNS, e.g. `socks5://`
vs `socks5h://`, or browsers without remote DNS) the proxy sees only an IP (`socks5.go:303-308,
319-324`). FQDN rules on names and category rules then cannot match (categories are keyed by host
text: `policy_hostcat.go:291-316`); source/identity/schedule rules still work; geo uses
`geo.LookupCached(host)` (`policy.go:2547`) — **[U]** whether an IP literal hits the cache directly.
This is **not SOCKS5-specific**: a CONNECT to an IP literal reaches the same evaluator with the same
limitation. The difference is frequency, not semantics. No SOCKS4 support exists (`socks5.go:297`).

## 6. Alignment proposal

### 6.1 One evaluator (ADR-0026)
Do not add a second walk. SOCKS5 calls the same `PolicyStore` / `evalAccessRules` core
(`policy.go:1694`, wrapped by `Evaluate` at `:1781`) with:

| Input | SOCKS5 source |
|---|---|
| `clientIP` | raw peer (`socks5.go:445`); no forwarding headers exist, as today |
| `identity`, `groups`, `authSource` | from a **shared** credential resolver extracted from `proxy.go:464-510` (registry providers, then `resolveAuthIdentityFrom`), so HTTP Basic and SOCKS5 USER/PASS resolve identically; `"unauth"` when NO-AUTH was negotiated |
| `host` | port-less destination, IPv6 brackets stripped (matches HTTP's `SplitHostPort` form); `Evaluate` derives `normHost` itself, honoring the `normHost == normalizeHost(host)` contract (`policy_hostcat.go:131-136`) |

Order in `handleSOCKS5`: blocklist → **threat `CheckDomain`** → plugin → **policy** → SSRF/dial, mirroring
HTTP (`proxy.go:1725` then `:1738`, SSRF inside the tunnel). Put the decision in a helper (e.g.
`socks5_policy.go`) so `handleSOCKS5` stays under cyclop 15 (CHAOS-102 already extracted one helper
for this reason, `socks5.go:423-426`).

Action mapping (no HTTP response is possible):

```
match == nil:  default allow → proceed (log "default-allow");  default deny → reply 0x02, POLICY_DEFAULT_DENY
unknown action → reply 0x02, POLICY_BLOCK          (SEC-POLICYACTION-1 fail-closed parity)
Drop           → close without reply (SetLinger(0) = RST), POLICY_DROP
Block_Page     → reply 0x02, POLICY_BLOCK
Redirect       → reply 0x02, POLICY_REDIRECT       (cannot redirect a raw tunnel)
Allow          → proceed; record rule name/ID; SSLAction Inspect → see decision D5
```

Logging: reuse existing statuses with method `"SOCKS5"` and populate identity/rule ID/authSource via
`recordRequestAuth*`, `%q` + `sanitizeLog` on host values. Learning stays out of `socks5.go` (wall).

### 6.2 IP-only destinations
Evaluate the IP literal as-is (same as CONNECT-to-IP). Do not reverse-resolve (attacker-controlled
PTR). Count ATYP mix in a metric so operators can see how much traffic is IP-only before enforcing.
Optional later: a strict toggle that refuses ATYP IPv4/IPv6 with 0x08 when rules use FQDN/category.

### 6.3 Default action semantics
Use the one process-wide default (`defaultPolicyActionState`, `proxy.go:33-56`) — no SOCKS5-specific
default. Consequence (errata): zero rules → allow; any rules + empty `default_action` → deny
(`rewrite_default_action_startup.go:32-36`). POL-900 (runtime vs boot derivation) applies equally.

### 6.4 Rollout
`socks5_policy_mode: legacy | shadow | enforce`.

1. **Now, no behavior change:** README limitation entry; fix `ENTERPRISE-PREREQUISITES.md:113`;
   caveat on `deployment-guide.md` examples; startup `logger.Printf` warning and a report-only
   `/ready`/diagnostics row "socks5 policy: legacy (not enforced)" when the listener is configured.
2. **Shadow:** evaluate, never block. Use a **non-accounting** wrapper around the pure core (same
   snapshot + `scanIndexFor`, no hit counters) so shadow does not inflate rule hit stats — ADR-0026
   §4 names shadow as a core consumer. Emit a rate-limited `SOCKS5 POLICY_WOULD_BLOCK` line and
   `culvert_socks5_policy_decisions_total{mode,verdict,reason}` with bounded labels
   (`verdict=allow|would_block|block`, `reason=rule|default`), plus `culvert_socks5_requests_total{atyp}`.
   Do not add a new request-log status in shadow unless D4 says so (SIEM/UI taxonomy).
3. **Enforce:** opt-in; flip after the operator reviews shadow data.
4. **Later:** consider `enforce` as the default for **new** installs only; existing configs keep
   their mode on upgrade (spec §1.7 requires opt-in for existing users).

Backward compatibility / migration: absent key = `legacy` (byte-identical behavior). Downgrade drops
the key harmlessly if parsed leniently **[U: confirm YAML/admin-settings unknown-field handling]**.
If the mode is runtime (D2), include it in `ConfigSnapshot`, config backup and versioning; a DP that
does not understand the field stays `legacy` — acceptable only because legacy is today's behavior,
and should raise a mixed-version warning. Migration note for operators: identity/group Allow rules
will start matching SOCKS5 users only after the shared resolver lands; with default deny, SOCKS5
clients on NO-AUTH get `authSource=unauth` and will be denied unless a rule allows them.

### 6.5 Contract impact
- Resolve SWG-901's question ("inside the managed policy boundary") with the owner; then rewrite it as
  an `enforced` entry ("In `enforce` mode, SOCKS5 traffic is decided by the same Stage-2 evaluator and
  default action as HTTP/CONNECT"), `code: socks5.go, socks5_policy.go, policy.go`, with tests.
  Narrowing the invariant to a mode is a wording change: record it with an `amended` entry and reason.
- Update roadmap spec §1.7/Phase 4 and `roadmap/PACKAGE-ISOLATION.md:285`.
- Auth rules `protocol: socks5` (`authpolicy.go:1041`) stay rejected until Stage-2 is enforced
  (spec hard invariant).

### 6.6 Tests needed
- Per mode, table-driven over a real SOCKS5 handshake: FQDN `Drop`, category `Block_Page`, `Redirect`,
  default deny with rules, zero rules → allow, unknown action → refuse; `legacy` unchanged.
- Differential oracle: for a corpus of (client, identity, groups, host), SOCKS5 verdict == CONNECT
  verdict (same evaluator), plus a negative control that fails if SOCKS5 bypasses it.
- Shadow: never refuses; would-block metric/log increments; rule hit counters unchanged.
- Identity: registry LDAP/OIDC user matches identity/group rules via SOCKS5; NO-AUTH → `unauth`.
- ATYP IPv4 vs domain for the same destination; IPv6 bracket normalization.
- Threat-feed domain refused on SOCKS5.
- Log hygiene: hostile host bytes stay escaped (extend `socks5_log_injection_test.go`).
- Existing walls stay green: `policylearn_wall_test.go`, admission owner walls (`AllowAuto`), posture gate.
- Global-state hygiene: `snapshotPolicyStoreForTest(t)` and default-action restore per conventions.

## 7. Open decisions for the owner

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Is SOCKS5 inside the managed boundary? (SWG-901 question) | (a) inside; (b) explicitly unmanaged, documented; (c) remove SOCKS5 | **(a)**. It is advertised as first-class; (b) at minimum must ship immediately as disclosure |
| D2 | Where does the mode live? | (a) startup flag/YAML like the port; (b) admin setting (API+UI, audited, `saveConfigVersion`, snapshot) | **(b)**: it is policy posture, so GUI parity applies; (a) is acceptable as a recorded startup-only deferral for phase 1 |
| D3 | Default mode | legacy for all; enforce for new installs; enforce for all | **legacy for existing configs, enforce for new installs** after one release in shadow |
| D4 | Shadow evidence channel | log + metric only; also a request-log status (`POLICY_SHADOW`) | **log + metric** first; a new status touches SIEM/UI taxonomy |
| D5 | Allow rule with `SSLAction: Inspect` on SOCKS5 | (a) tunnel uninspected + log; (b) refuse (fail closed, TLS-900 spirit); (c) implement SOCKS5 inspection | **(a)** in shadow/first enforce with an explicit counter; revisit (b) per rule |
| D6 | Drop semantics | RST without reply; reply 0x02 | **RST** (covert, matches HTTP Drop) |
| D7 | Threat-feed parity | fold into this change; separate contract | **Fold in** (cheap, same pre-dispatch order); record it in SWG-901 since the contract text omits it |
| D8 | SOCKS5 credential source | keep legacy/admin-only; share HTTP's resolver | **Share** — prerequisite for identity rules; also stops SOCKS5 users needing the admin credential |
| D9 | IP-only destinations | evaluate as-is; strict mode refusing IP ATYP; ignore | **Evaluate as-is** + ATYP metric; strict mode later if demand |
| D10 | Bind exposure | keep `":port"`; add bind-address option | Add an option later; out of SWG-901 scope |
