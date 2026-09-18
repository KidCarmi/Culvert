# CDR (Content Disarm & Reconstruction) — the Sluice integration

Culvert can strip active content (macros, embedded OLE objects, JavaScript,
external references) from files downloaded over SSL-inspected HTTPS, by
handing the decrypted body to **Sluice** — a separate, independently
versioned CDR engine (`github.com/KidCarmi/Sluice`) reached over mTLS gRPC.
Manage it under **CDR** in the admin UI's Policies section (the default
`static/index.html` UI), or **Security → CDR Integration** when the
experimental React frontend is armed (`CULVERT_EXPERIMENTAL_UI`, off by
default), or directly via `/api/cdr/*`.

This is the operator-facing runbook for the feature as it actually ships
today. Do not confuse it with
[`roadmap/SLUICE-CDR-HANDOFF.md`](../../roadmap/SLUICE-CDR-HANDOFF.md), which
is the pre-implementation design brief written before Sluice was integrated
and does not describe current behavior.

> **CDR only ever sees traffic that SSL inspection has already decrypted.**
> Plain HTTP and un-inspected (bypassed) HTTPS never reach CDR — there is no
> separate "does CDR apply here" toggle beyond that. If the root CA becomes
> unusable, inspection silently falls back to bypass and CDR (along with
> DLP/AV/YARA/DPI) stops running fleet-wide; see
> [`root-ca-expiry.md`](root-ca-expiry.md).

## 1. Configuration

CDR is off by default. Every field below is `config.yaml`'s `cdr:` block or
the matching `-cdr-*` CLI flag (CLI wins on conflict, same precedence as the
rest of `config.go`); none of it is CP→DP synced or config-version rolled
back — see [§7](#7-what-this-does-not-give-you).

| YAML key | CLI flag | Default | Notes |
|---|---|---|---|
| `cdr.enabled` | `-cdr-enabled` | `false` | Also forced on by the `<dataDir>/cdr_enabled` marker file the GUI toggle and the admin API write — see below. |
| `cdr.endpoint` | `-cdr-endpoint` | `""` | `host:port`. Only consulted by the pre-enrollment bootstrap dial (§2) — once at least one instance is enrolled, the pool dials from the enrolled registry instead. |
| `cdr.fail_mode` | `-cdr-fail-mode` | `""` (→ open) | `open` or `closed` — see [§4](#4-fail-open-vs-fail-closed). |
| `cdr.default_profile` | `-cdr-default-profile` | `"default"` | Sanitization profile sent when no policy rule matches; must be a profile Sluice's own Health response advertises. |
| `cdr.default_mode` | `-cdr-default-mode` | `"ENFORCE"` | `ENFORCE` \| `REPORT_ONLY` \| `BYPASS_WITH_REPORT` — see [§3](#3-policy-what-gets-sanitized). |
| `cdr.timeout_sec` | `-cdr-timeout-sec` | `35` | Must be ≥ 30 (Sluice's own per-file cap is 30s). |
| `cdr.max_file_size_mb` | `-cdr-max-file-size-mb` | `50` | Rejected client-side before any bytes are sent. |
| `cdr.chunk_size_kb` | *(YAML-only)* | `64` | Must be 16–3072 when set. |
| `cdr.server_fingerprint` | `-cdr-server-fingerprint` | `""` | TOFU-pinned SHA-256 of Sluice's server cert; hex, optional `sha256:` prefix. Set automatically by enrollment (§2) — a manual value here is for pre-provisioned/bootstrap dials only. |
| `cdr.certs_dir` | `-cdr-certs-dir` | `""` | Directory holding a pre-provisioned `ca.pem`/`client.pem`/`client.key` triad, used **only** by the bootstrap dial when no instance has been enrolled yet. |

There is no `-cdr-*` equivalent for enable/disable at runtime beyond the flag
above: the CDR panel's **Overview** tab on/off switch and
`PUT /api/cdr/config` both write the `<dataDir>/cdr_enabled` marker file,
which forces `enabled` at every subsequent boot regardless of what
`config.yaml`/the CLI say — this is the only field the GUI can change without
a restart. Everything else in the table above is read-only in the GUI and
needs a config change + restart.

## 2. Enrollment (pairing with a Sluice instance)

CDR does not discover Sluice instances automatically. Each one is paired
explicitly:

1. On the Sluice side, obtain a single-use enrollment token and the server's
   TLS certificate fingerprint (Sluice prints both on its own first boot).
2. In the CDR panel's **Instances** tab (Enroll), or
   `POST /api/cdr/instances/enroll` (admin-only), submit `name`, `endpoint`,
   `serverFingerprint`, and `token`. `name` must match
   `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`.
3. Culvert TOFU-verifies the Sluice server cert against the pasted
   fingerprint, receives a client certificate + key, persists them under
   `<dataDir>/integrations/sluice/<name>/`, and re-initializes the CDR pool
   immediately — no restart needed. A failure partway through this flow
   tears down any partial state so the enrollment can be retried cleanly.

Because the token exchange happens in one round trip, a lost or timed-out
response can leave Culvert unable to tell whether Sluice actually issued a
credential. If enrollment appears to fail but you are unsure whether it
landed, use the recovery-receipt surface (`GET`/`DELETE
/api/cdr/instances/enroll/receipts`, or `POST
/api/cdr/instances/enroll/recover`, both reachable from the CDR panel's
**Instances** tab) rather than retrying blindly — it re-queries Sluice for
the authoritative outcome instead of guessing.

**Revoke vs. Delete are different operations, and only one of them is
reversible-in-practice:**

- **Revoke** (`POST /api/cdr/instances/revoke`) retires every credential
  ever issued to that instance **on the Sluice side** — irreversible, and
  Sluice refuses to let an instance revoke itself, so you need at least two
  enrolled instances to revoke one.
- **Delete** (`DELETE /api/cdr/instances?name=...`) only removes the
  instance from this appliance's local registry and shreds its local copy
  of the credential. Sluice keeps trusting that certificate until it
  expires or is separately revoked — deleting is not a security action by
  itself.

The CDR client's private key can be encrypted at rest
(`CULVERT_CDR_CLIENT_KEY_ENCRYPT`); this shares the CA-3 key-at-rest
machinery documented in full in
[`key-at-rest.md`](key-at-rest.md#3-the-three-protected-keys) — do not
duplicate that runbook here.

## 3. Policy: what gets sanitized

CDR policy rules mirror the shape of access-policy rules (source IP/identity/
group/AuthSource, destination FQDN/category/category-group/country,
optional schedule — empty means "any") so admins reuse the same mental
model. Manage them under the CDR panel's **Policies** tab, or
`GET/POST/DELETE /api/cdr/policies` (deletion is by rule name). Rules are
evaluated first-match-by-priority; a request that matches no rule falls back
to `cdr.default_profile` / `cdr.default_mode`.

Each rule picks a **profile** (which Sluice sanitization profile to request)
and a **mode**:

| Mode | Behavior |
|---|---|
| `ENFORCE` | Strip active content, deliver the sanitized bytes. |
| `REPORT_ONLY` | Detect and report threats, deliver the original bytes unchanged. |
| `BYPASS_WITH_REPORT` | VIP carve-out: report threats, deliver the original bytes — same wire effect as `REPORT_ONLY`, kept as a distinct name for audit/reporting clarity. |

An unrecognized mode string is treated as `ENFORCE` (the safer default —
never silently fall back to something that lets active content through).

Identical files are not re-sanitized on every request: results are cached by
SHA-256(body) plus the current policy generation, so an admin edit to a
policy rule invalidates the cache automatically.

Use the CDR panel's **Test** tab (`POST /api/cdr/test`, admin-only) to run a
single file through Sluice in `REPORT_ONLY` mode as a one-off check. It is a
diagnostic tool under your own identity, audited like any other admin
action — it says nothing about how production traffic is currently being
handled.

## 4. Fail-open vs. fail-closed

`cdr.fail_mode` governs only what happens when a Sluice call **errors or the
engine is unreachable** — it is never consulted for an actual
threat-detected verdict, which always blocks the file regardless of
fail_mode.

- **`open`** (default, any value other than the literal string `closed`):
  the original file is delivered, a `cdr_unavailable` alert fires, and
  `culvert_cdr_fail_open_total` increments.
- **`closed`**: the response is blocked (block page), the same alert fires,
  and `culvert_cdr_fail_closed_total` increments.
- **A file too large for Sluice's own cap** is not a fail-mode event at
  all — it passes through unconditionally (`SKIPPED_OVERSIZE`) on the
  reasoning that the client deserves to see a file Sluice was never going to
  scan.
- **CDR disabled, or every enrolled instance's circuit breaker is
  open** (5 consecutive failures trips a breaker; it half-opens after 30s)
  also passes through unconditionally as `SKIPPED` — this is *not* routed
  through `fail_mode` either, since there is nothing to have failed.
- **A panic inside the CDR stage always blocks**, regardless of
  `fail_mode` — this is the one case that is unconditionally fail-closed,
  on the reasoning that no configuration should be able to ship possibly-
  unsafe bytes.

## 5. Observability

**`GET /api/diagnostics`** (and the admin Diagnostics panel) carries a `cdr`
operator-contract row: `disabled` (OK) when off, `enabled-healthy` (OK) when
at least one pool member is reachable and both `fail_mode` and
`default_profile` are set, `enabled-degraded` (WARN) when connected but
missing one of those two settings, and `enabled-broken` (FAIL) when enabled
with zero connected instances. **CDR does not appear on the unauthenticated
proxy-port `/health` or `/ready` endpoints** — those are reserved for data-
plane-serving signals, so an operator who only watches `/health` will not
see a broken CDR pool; watch `/api/diagnostics` or `/metrics` instead.

**`GET /api/cdr/health`** serves a background-polled cache (refreshed every
15s, one 5s probe per pool member) of each Sluice instance's own reported
health, falling back to a synchronous probe only if no cache exists yet. The
cache is deliberately dropped — not served stale — after 3 consecutive
all-members-failed polls, so a `503` here means "no data," not "old data."

**Metrics** (`/metrics`, all present only once CDR has processed at least
one relevant event):

| Metric | Meaning |
|---|---|
| `culvert_cdr_files_processed_total{status}` | `clean` \| `sanitized` \| `blocked` \| `unsupported` |
| `culvert_cdr_oversize_skipped_total` | Skipped for exceeding the size cap |
| `culvert_cdr_errors_total` | Sluice call errors (excludes oversize) |
| `culvert_cdr_fail_open_total` / `culvert_cdr_fail_closed_total` | Errors resolved by `fail_mode` |
| `culvert_cdr_panics_total` | Always-fail-closed panic recoveries |
| `culvert_cdr_cache_hits_total` / `_misses_total` / `culvert_cdr_cache_size` | The SHA-256 decision cache from §3 |
| `culvert_cdr_bytes_in_total` / `_bytes_out_total` | Original vs. sanitized bytes |
| `culvert_cdr_instance_healthy` | 1 if any pool member's last probe succeeded |
| `culvert_cdr_queue_depth` | Minimum Sluice-reported queue depth across healthy members |
| `culvert_cdr_threats_detected_total{type}` | Capped at 64 distinct threat types |

**A caveat worth knowing before you rely on alerting**: `cdr_unavailable`
fires on every non-oversize call error, one `go fireAlert(...)` per request,
without the `alerts.HasSubscriber` pre-check most other request-path
producers in this codebase use, and its `Detail` carries the raw Go error
string rather than a bounded reason class. In practice this means a sustained
Sluice outage can generate one distinct-`Detail` alert per failing request
rather than a single deduplicated one — watch `culvert_cdr_errors_total`
and the `cdr` diagnostics row as the primary signal, and treat a burst of
`cdr_unavailable` webhook deliveries as expected noise during an outage
rather than N separate incidents.

## 6. Admin API summary

| Path | Methods | Role |
|---|---|---|
| `/api/cdr/config` | GET / PUT | viewer / admin |
| `/api/cdr/instances` | GET / DELETE | viewer / admin |
| `/api/cdr/instances/enroll` | POST | admin |
| `/api/cdr/instances/enroll/recover` | POST | admin |
| `/api/cdr/instances/enroll/receipts` | GET / DELETE | viewer / admin |
| `/api/cdr/instances/revoke` | POST | admin |
| `/api/cdr/policies` | GET / POST / DELETE | viewer / admin |
| `/api/cdr/health` | GET | viewer |
| `/api/cdr/test` | POST | admin |

Every mutation is admin-only (never operator) and audited — there is no
operator-role write path for CDR, unlike most other admin-API domains.

## 7. What this does not give you

- **No config-version rollback, export/import, or CP→DP cluster sync.**
  `cdr.enabled`, enrolled instances, and CDR policies are node-local state
  (`<dataDir>/cdr_instances.json`, `cdr_policies.json`,
  `cdr_enroll_receipts.json`); the audit log is the only durable record of
  a change. Each enrolled Sluice instance must be paired separately on
  every appliance/DP node that needs it.
- **No unauthenticated health signal.** As noted in §5, CDR posture is not
  on `/health`/`/ready` — only on the authenticated `/api/diagnostics` and
  `/metrics`.
- **Requires SSL inspection.** CDR cannot see plaintext HTTP or bypassed
  HTTPS traffic; it runs only inside the same decrypted-body pipeline as
  ClamAV/YARA, immediately before those scanners so they see sanitized
  bytes when CDR stripped something.
