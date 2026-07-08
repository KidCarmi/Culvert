# QA Gate — hard-blocking pipeline gate

> **STATUS (2026-07-03): PR-time enforcement is superseded by the Fast/Deep
> PR Gates** (`pr-fast-gate.yml` / `pr-deep-gate.yml` — see
> `roadmap/CI-REDESIGN.md`, retirement step 5). On PRs this workflow's jobs
> skip and `qa-gate-approved` reports pass-through success; the gate runs
> fully on main pushes. Branch protection should require the Fast/Deep gate
> aggregates, NOT `qa-gate-approved`. Sections below describe the original
> (main-push) behavior; job counts and required-check instructions predate
> the lane redesign.

This document describes the QA-as-hard-gate enforcement introduced on branch
`claude/enforce-qa-pipeline-gate-WHnKi`. It pairs with the workflow at
`.github/workflows/qa-gate.yml` and the tests at `qa_gate_test.go`.

The goal is twofold:

1. Treat QA as a **blocking** release criterion rather than an advisory check.
2. Structure the gate so that when it goes red, the **layer at fault is
   obvious from the job name alone** — application, infra, OS, or contract.

## 1. Findings & fixes

The gate work was NOT pure test mirroring. Each fix below came from actively
challenging the committed implementation while writing the tests.

| # | Severity | File | Defect (before) | Fix (now) | Test |
|---|----------|------|-----------------|-----------|------|
| 1 | Critical | `ui.go` `apiAuthLogin` | TOTP failure did **not** increment the lockout counter. With a valid password, an attacker could brute-force the 6-digit OTP (10⁶ codes) with only a 300 ms delay as a barrier — trivially parallelisable across connections. | On bad OTP, call `loginLimiter.RecordFailure(user)`, emit an `auth.totp.fail` audit event, and return `429` once locked. | `TestAPIAuthLogin_TOTPFailureRecordsLockout` |
| 2 | High | `totp.go` `verifyTOTP` | Same OTP accepted for up to ~90 s (30 s step × ±1 skew). An observer of a single code could replay it for the remainder of the window. | New `verifyTOTPReturnCounter` returns the matched time-step; call-site persists it via `Config.SetTOTPLastCounter` so subsequent codes whose counter ≤ last are rejected. Counter is persisted across restarts in `ui_users.json` under `totp_last_counter`. | `TestVerifyTOTPReturnCounter_ReplayRejected`, `TestConfig_TOTPLastCounter_PersistsThroughFile` |
| 3 | High | `totp.go` `verifyTOTP` | Empty secret silently validated — the base32 decode produced an empty HMAC key, and the resulting deterministic digest could still match a predictable code. | Explicit empty-secret fail-closed; explicit non-digit rejection; `math.Pow10` float conversion replaced with a computed integer modulus. | `TestVerifyTOTP_RejectsEmptyAndBlankSecret`, `TestVerifyTOTP_RejectsNonDigitCode` |
| 4 | High | `security.go` `ssrfSafeDialContext`, `proxy.go` tunnel handlers, `socks5.go` | Classic DNS-rebinding TOCTOU: the code resolved DNS in `isPrivateHost`, found a public IP, then Dial re-resolved and could get a private IP (e.g. `169.254.169.254`). The 30 s cache narrowed the window but did not close it — the OS resolver and an attacker-controlled DNS TTL bypass the cache. | Introduced `ssrfControl` as `net.Dialer.Control`. The kernel-about-to-connect address is validated post-resolution, so DNS rebinding between pre-check and dial is structurally impossible. Wired into `ssrfSafeDialer`, `handleTunnelBypass`, `handleTunnelInspect`, `handleWebSocket`, and the SOCKS5 handler. | `TestSSRFControl_BlocksPrivate`, `TestSSRFControl_AllowsPublic`, `TestSSRFControl_MalformedAddrFailsClosed`, `TestSSRFSafeDialer_RejectsLoopbackDial` |
| 5 | Medium | `proxy.go` `sanitizeLog` | Only `\n`, `\r`, `\t` were stripped. `ESC (0x1B)` passed through, enabling terminal-escape injection into log viewers (CWE-150), along with NUL, BS, VT, FF and DEL. | Strip all C0 controls (`0x00-0x1F`) and DEL (`0x7F`). Fast path preserved via `containsControl` check. | `TestSanitizeLog_StripsCtrlAndANSIEscape`, `TestSanitizeLog_FastPathNoAlloc` |
| 6 | Medium | `proxy.go` `privateCIDRs` | Missing ranges: `0.0.0.0/8` (this-host on many stacks), `100.64.0.0/10` (carrier NAT), `198.18.0.0/15` (benchmark), `224.0.0.0/4` (multicast), `240.0.0.0/4` (reserved/broadcast), and the IPv6 equivalents. | Expanded CIDR list with explanatory comments. Explicitly documented WHY `::ffff:0:0/96` is **not** in the list (would match every IPv4 address in Go's default 16-byte representation). | `TestIsPrivateIP_ExpandedCoverage`, `TestIsPrivateIP_KnownPublicStaysPublic` |

Rejected as "looks bad but isn't": `isSafeRedirectURL` userinfo concern —
`url.Parse` routes userinfo correctly to `u.User`, so `u.Host` is the real
host. Not an open redirect.

## 2. Pipeline gate — layer isolation

The new `.github/workflows/qa-gate.yml` splits QA into six jobs so the failing
layer is visible at a glance in the PR checks list:

| Job | What it proves | What a red X means |
|-----|----------------|--------------------|
| `qa-logic` | `go vet` + `go test -race` for every package, deterministic seed. | **Application code is wrong.** Independent of infra/OS. |
| `qa-determinism` | Re-runs with `-shuffle=on -count=2`. | A test is **non-deterministic** (order-dependent, wall-clock dependent, RNG leak). Fix the test — never mark it flaky. |
| `qa-coverage` | Enforces a per-file coverage floor on the security-sensitive surface (`totp.go`, `security.go`, `session.go`, `lockout.go`, `policy.go`). | A hot file has **unwatched branches**. Regression risk. |
| `qa-infra-compose` | Builds the Docker image, boots `proxy` alone (clamav/updater disabled) via a generated `compose.qa.yml`, waits for the healthcheck. | **Docker / orchestration problem.** Not application logic. |
| `qa-os` | Static `CGO_ENABLED=0` build, `ldd` check, smoke run on the bare runner with no Docker. | **OS / runtime environment problem.** Not application logic. |
| `qa-contract` | Re-runs the persisted-users-file test to lock the on-disk JSON schema. | **Operator-facing schema broke.** Upgrades will fail for existing deployments. |
| `qa-gate-approved` | Depends on all six. | ✅ only when every layer is green. Mark as a required status check in Branch Protection. |

## 3. Docker Compose decoupling

The production `docker-compose.yml` ties the proxy's startup to `clamav` and
`updater`. That is correct for production but **masks failure isolation** in
CI: a ClamAV signature update hiccup would look indistinguishable from a
proxy bug.

`qa-infra-compose` generates a minimal `compose.qa.yml` at runtime that
brings up **only** the proxy service with its own healthcheck. This ensures:

- Proxy correctness is validated without waiting for ClamAV's ~250 MB signature
  download (flakiness source eliminated).
- A failure in this job is unambiguously an image/orchestration issue,
  because the application-logic layer (`qa-logic`) has already passed.
- `docker compose config --quiet` validates `docker-compose.yml` itself so
  syntax or anchor-expansion mistakes in the production file are still caught.

**Recommendation for the production compose file (not changed in this PR):**
when ClamAV *is* required, use `depends_on: { clamav: { condition:
service_healthy } }` instead of the bare list form; the current form starts
the proxy before ClamAV is ready and relies on per-request retry for
recovery, which hides ClamAV outages from health signals.

## 4. Deterministic validation

The following mechanisms make the gate reproducible:

- **`TEST_SEED=20260421` environment variable** — exported in `qa-logic` and
  `qa-determinism`. Tests that need randomness should read this seed rather
  than calling `time.Now()` or `rand.Int()` directly.
- **`verifyTOTPAt(secret, code, nowUnix, lastCounter)`** — the TOTP verifier
  now takes `nowUnix` as a parameter. Tests exercise time-skew behaviour at
  fixed moments (`deriveCodeAt`) with no `time.Now()` monkey-patching.
- **`-shuffle=on -count=2` in `qa-determinism`** — catches tests that leak
  state between runs (e.g. mutation of the shared `upstreamTransport`).
- **Per-test cleanup via `t.Cleanup`** — e.g.
  `TestAPIAuthLogin_TOTPFailureRecordsLockout` deletes the test user and
  resets the lockout bucket so repeated runs are byte-identical.

## 5. How to use the gate

1. **In Branch Protection**: mark `qa-gate-approved` (and
   `release-approved` from the existing security workflow) as REQUIRED
   status checks on `main`. Without this, the gate is advisory — exactly
   the anti-pattern this work fixes.
2. **Locally, before pushing**:
   ```bash
   go test -race -count=1 -timeout=15m ./...            # qa-logic
   go test -race -count=2 -shuffle=on -timeout=20m ./... # qa-determinism
   ```
3. **When a job goes red**: look at the job name first. Don't retry.
   - `qa-logic` red ⇒ read the diff and fix the code.
   - `qa-determinism` red ⇒ find the flaky test and pin its inputs.
   - `qa-infra-compose` red ⇒ check the Dockerfile / compose graph.
   - `qa-os` red ⇒ check `go.mod` / build tags / runner image.
   - `qa-contract` red ⇒ the on-disk schema changed; add a migration or
     revert the field rename.
