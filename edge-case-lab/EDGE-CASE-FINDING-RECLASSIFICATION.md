# Culvert Edge-Case Lab — Finding Reclassification (Adversarial Review)

Re-evaluated against actual Culvert source, docker-compose, README/docs, and API behavior.
Classifications were **not** preserved merely because they appeared in the campaign reports.
Taxonomy adds **SECURITY_BYPASS** (a security-relevant enforcement-boundary gap) to the original set.

**Net effect on the campaign's "0 confirmed product bugs":** upheld in the strict PRODUCT_BUG sense,
but the headline is **misleading** — one finding (SOCKS5) is upgraded to **SECURITY_BYPASS**
(more serious than the "missing capability" label the campaign gave it), and two findings were
**overstated** and are downgraded (one was the harness's own misconfiguration).

---

## Finding 1 — SOCKS5 traffic bypasses the policy engine
**Campaign class:** MISSING_CAPABILITY → **Reclassified: SECURITY_BYPASS** · Severity **High (latent/opt-in)** · Confidence **High**

- **Contract.** README advertises SOCKS5 as a first-class proxy interface: masthead
  "HTTP · HTTPS · SOCKS5 · WebSocket" (`README.md:9`) and the feature table "HTTP/HTTPS forward
  proxy … SOCKS5 (RFC 1928/1929, CONNECT)" (`README.md:40`). No document states SOCKS5 is outside
  the managed security boundary. The architecture is stated in `CLAUDE.md`: "SOCKS5 does NOT run
  the PBAC policy engine — only … blocklist, plugin, SSRF, dial."
- **Code evidence.** `socks5.go` request handler enforces **only**: IDNA host gate, legacy
  `bl.IsBlocked` blocklist, `pluginDecision`, and the SSRF guard, then dials. It never calls
  `policyStore.Evaluate`. Listener binds `":%d"` = **all interfaces** (`socks5.go:51`). RFC-1929
  auth via `cfg.VerifyAuth` applies only if credentials are configured; in open mode it negotiates
  no-auth. Default `-socks5-port 0` = **disabled by default** (`main.go:234`, `README.md:93`).
- **What is bypassed when enabled:** authorization rules, URL/domain objects, URL categories &
  groups, **source-IP/subnet (tenant isolation)**, GeoIP, schedules, **TLS inspection**, file-type
  control, redirect/drop actions, and **rule-attributed logging/decision trace** (only `SOCKS5 OK`
  is logged, no rule ID). Retained: RFC-1929 auth (if set), manual blocklist, plugin, SSRF.
- **Expected admin interpretation.** An admin who enables an advertised proxy interface reasonably
  expects the same access policy to apply. Nothing warns otherwise.
- **Security impact.** When enabled and network-reachable, SOCKS5 is a policy-bypass path: a client
  can reach category/FQDN/tenant-blocked destinations and evade TLS inspection & audit. This is a
  **security control bypass**, not a mere absent feature — the per the review instruction,
  MISSING_CAPABILITY is wrong because there is **no defensible product contract** placing SOCKS5
  outside the managed boundary; the docs advertise it *inside* the proxy feature set.
- **Operational impact.** Silent audit gap (no rule-attributed logs for SOCKS5 flows).
- **Mitigating factors.** Disabled by default; still subject to blocklist/SSRF/optional auth.
- **Minimal repro:** enable `-socks5-port 1080`; add a policy block for `H`; HTTP/CONNECT to `H`
  → blocked; `curl --socks5-hostname 127.0.0.1:1080 http://H/` → **allowed** (SWG-0210/0211).
- **Recommended immediate mitigation (priority order):** (1) keep disabled-by-default;
  (2) on enable, emit an explicit **"SOCKS5 runs in unmanaged mode — policy engine not applied"**
  startup warning + surface it in the UI/health; (3) offer an allowlist-only SOCKS5 mode;
  (4) full policy-engine parity (route SOCKS5 through `policyStore.Evaluate`). Until (4), treat as
  a known SECURITY_BYPASS gated by an opt-in flag.

## Finding 2 — Admin-API policy lost after restart
**Campaign class:** CONFIGURATION_CONTRACT_GAP → **Reclassified: TEST_INFRA_FAILURE** (residual low-severity DOCUMENTATION/UX note) · Confidence **High**

- **Contract.** Startup logs "Policy: in-memory only (set -policy <file> for persistence)". The
  **shipped** `docker-compose.yml` sets `-policy /data/policy.json` (`docker-compose.yml:133`).
- **Code evidence.** Every mutating policy handler calls `policyStore.Save()`
  (`ui_policy.go:1177,1232,1274,1330,1353`); `Save()` atomically writes to `ps.path`
  (`policy.go:334-358`), and `ps.path` is set by `Load(polPath)` when `-policy` is present. So
  **with the shipped flag, API-created policy IS persisted and survives restart.**
- **Why the campaign saw a loss.** The lab ran the bare binary **without `-policy`**, so
  `ps.path == ""` and `Save()` is a no-op. The "finding" is a **harness-configuration artifact**,
  not a product defect. This corrects an overstatement in the original campaign.
- **Residual (low severity, DOCUMENTATION/UX):** a bare `./culvert` (README "Minimal" run) does not
  persist and the API returns success with no ephemeral-mode indication. Worth a one-line API/UI
  hint, but **not** a contract gap in the supported (compose) deployment.
- **Repro:** run `./culvert` (no `-policy`) → POST /api/policy → restart → rules gone. Run with
  `-policy /data/policy.json` → same steps → **rules persist**.

## Finding 3 — `priority: 0` silently reassigned to the end
**Campaign class:** CONFIGURATION_CONTRACT_GAP → **Reclassified: DOCUMENTATION_GAP / CONFIGURATION_CONTRACT_GAP (documented behavior)** · Severity **Low–Medium** · Confidence **High**

- **Contract.** `docs/enterprise/POLICY-ROLLOUT-GUIDE.md:20` — "add auto-assigns/deconflicts
  priority." The `Priority<=0` auto-assign branch is a reviewed, intentional behavior
  (`docs/security-reviews/2026-07-09-…`).
- **Code evidence.** `policy.go:444` — `if nr.Priority <= 0 { … nr.Priority = maxPri + 1 }`. So
  priority 0 (Go zero-value) is treated as "unset" and appended at the **lowest** precedence.
- **Expected admin interpretation.** An admin using the common "0 = highest" convention who does
  **not** read the rollout guide gets the intended precedence **silently inverted** (a top
  category-exception rule lands at the bottom and never fires → potential **fail-open**).
- **Why NOT a product bug.** The behavior is intentional **and documented**; priorities ≥1 behave
  correctly (verified — the precedence family passes). The gap is that the API accepts `0` without
  surfacing the "append" coercion.
- **Security/Operational impact.** Latent fail-open if a block rule is authored at priority 0.
- **Repro:** POST rule A `{priority:1, fqdn:*, allow}`, rule B `{priority:0, category:X, block}` →
  read back: B is priority 2 (below A) → X is allowed (SWG-0166–0169).
- **Recommendation:** reject `priority:0` with `400` (or a warning) at the API, or document the
  "0 = append" convention in the API schema/UI. Reclassify severity up to Medium only if a UI path
  makes 0 easy to hit.

## Finding 4 — `certVerification=permissive` accepted but behaves strict
**Campaign class:** CONFIGURATION_CONTRACT_GAP → **Held: CONFIGURATION_CONTRACT_GAP (documented-deferred)** · Severity **Low (fail-closed)** · Confidence **High**

- **Contract.** `internal/decryptprofile/decryptprofile.go:71` documents `"permissive" (verify,
  allow+log — DEFERRED enforcement)`. `decryptprofile_resolve.go:170` maps `"strict","permissive"`
  to the **same** verify path.
- **Code evidence.** The profile validator accepts `permissive`
  (`decryptprofile.go:49`); the resolver treats it as strict; an untrusted upstream is blocked.
- **Interpretation & impact.** An admin selecting `permissive` (expecting allow-on-fail) gets a
  hard block instead. Direction is **fail-closed** (MORE secure than advertised) → **no security
  bypass**; the impact is availability/surprise (connections blocked unexpectedly).
- **Why the class holds.** A named, accepted option does not deliver its stated semantics; the
  deferral is documented only in source, not the API/UI. This is a genuine contract/documentation
  gap, low severity.
- **Repro:** create profile `{certVerification:permissive}`, inspect an untrusted-cert origin →
  connection blocked, not allowed-with-log (SWG-0069).
- **Recommendation:** either implement allow+log, or reject/deprecate `permissive` at the API with
  a clear message, or document it as an alias of `strict` pending implementation.

## Finding 5 — External redirect targets rejected
**Campaign class:** CONFIGURATION_CONTRACT_GAP → **Reclassified: EXPECTED_LIMITATION (correct security behavior) + minor UX note** · Severity **Info/Low** · Confidence **High**

- **Contract/Code.** The redirect action validates the target via `isSafeRedirectURL`
  (`proxy.go`/`proxy_portal.go`); an unvalidated external URL yields `403`, not an open 302.
- **Interpretation.** This is **correct, secure** anti-open-redirect behavior. The only "gap" is
  that the restriction (external redirect targets disallowed) is not surfaced at config time — the
  admin discovers it at runtime.
- **Security impact.** Positive (prevents the proxy from being an open redirect). No bypass.
- **Why reclassified.** Calling correct security behavior a "contract gap" over-weights it. It is an
  **EXPECTED_LIMITATION** with a minor UX improvement (surface the constraint when the redirect
  rule is saved).
- **Repro:** create redirect rule → `redirectURL:http://external/…` → request → 403 (SWG-0215).

---

## Reclassification summary

| Finding | Campaign class | Reclassified | Severity | Δ |
|---|---|---|---|---|
| 1 SOCKS5 policy bypass | MISSING_CAPABILITY | **SECURITY_BYPASS** | High (opt-in) | ⬆ upgraded |
| 2 Policy lost on restart | CONFIG_CONTRACT_GAP | **TEST_INFRA_FAILURE** (+minor doc/UX) | Low | ⬇ downgraded (harness fault) |
| 3 priority 0 reassigned | CONFIG_CONTRACT_GAP | **DOCUMENTATION_GAP / CONFIG_CONTRACT_GAP** | Low–Med | ↔ softened (documented) |
| 4 permissive = strict | CONFIG_CONTRACT_GAP | **CONFIG_CONTRACT_GAP** (fail-closed) | Low | ↔ held |
| 5 external redirect reject | CONFIG_CONTRACT_GAP | **EXPECTED_LIMITATION** | Info/Low | ⬇ downgraded (correct behavior) |

**Confirmed strict PRODUCT_BUGs after review: 0.** **Confirmed SECURITY_BYPASS: 1 (SOCKS5, opt-in).**
The single most important correction is that the campaign under-classified SOCKS5 as a "missing
capability" when the evidence supports a security-relevant enforcement-boundary bypass on an
advertised interface.
