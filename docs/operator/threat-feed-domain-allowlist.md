# Threat-Feed Domain Allowlist — operator guide

The domain allowlist exempts specific hosts from **domain-level** threat-feed
blocking. Use it to clear a false positive (a legitimate platform whose domain
appears in a public feed because one user uploaded one bad file) without
disabling threat intelligence for everyone.

Managed from the admin UI (Security → Threat Feed) or the API
(`GET`/`PUT /api/security-scan/feeds/domain-allowlist`, admin role).

## What the allowlist does and does not do

| Control | Effect on an allowlisted host |
|---|---|
| Domain-level feed hit (`CheckDomain`, and the domain fallback of `CheckURL`) | **Suppressed** — the host is not blocked on the domain alone |
| Exact malicious-URL feed hit (`CheckURL` exact match) | **Still enforced** — a known-bad URL on the host is blocked |
| Legacy blocklist, policy engine, ClamAV/YARA, DPI | **Unaffected** — the allowlist is threat-feed-only |

The security boundary is deliberate: **the allowlist is not a URL glassbreak.**
Allowlisting `github.com` stops the feed from blocking all of GitHub because one
raw URL was flagged, but the specific flagged URL stays blocked.

## Important: non-inspected CONNECT tunnels

For an HTTPS `CONNECT` tunnel **without** SSL inspection, the proxy only sees the
hostname — there is no URL to match. So for opaque CONNECT traffic, allowlisting
a host **fully exempts it from threat-feed blocking**, including any exact-URL
intel, because that intel is never evaluated on the encrypted stream. URL-level
enforcement resumes only when SSL inspection is enabled and the inner request is
re-dispatched.

**Operator takeaway:** on non-inspected paths, allowlisting a host = trusting all
traffic to it. Prefer enabling SSL inspection for hosts you must allowlist, or
keep allowlist entries tightly scoped.

## Matching semantics

- **Exact host only.** Allowlisting `example.com` does **not** exempt
  `www.example.com`. Add each host you mean to exempt.
- **Forgiving input.** Entries are normalized: case, a trailing dot, a `:port`,
  a full URL, or a URL with a path all reduce to the bare host
  (`WWW.GOOGLE.COM.`, `www.google.com:443`, `https://www.google.com/x` →
  `www.google.com`). Unicode and punycode spellings converge (IDNA), so a
  homograph cannot dodge or over-trigger an entry.
- **Rejected input.** Values with a path but no resolvable host (e.g. a CIDR
  like `10.0.0.1/24`, or a bare `http://`) are dropped, not stored as dead keys.
  The audit count reflects what was actually stored.

## Observability

- **Metric** `culvert_threat_feed_allowlist_masked_total` (Prometheus) and the
  `threat_feed_allowlist_masked` field on the security-scan status API count
  every domain-level threat hit the allowlist suppressed since process start.
  A **rising** value means the allowlist is actively overriding live intel —
  investigate whether an exemption is too broad or an allowlisted platform is
  now hosting malware at the domain level.
- Every allowlist change writes an audit event (`threatfeed.allowlist.update`).
  If persistence fails, the change still applies in memory and is audited as
  `threatfeed.allowlist.update_unpersisted` (see below).

## Persistence, restart, upgrade, rollback

- **Immediate effect.** Adding or removing an entry takes effect on the next
  lookup — no waiting for a feed re-sync. Removing an entry re-enables blocking
  immediately (the underlying intel is retained in memory).
- **Persist failure.** If the on-disk save fails, the API returns HTTP 500 but
  the allowlist is already live in memory (fail-safe), and the change is audited
  as `...update_unpersisted`. A retry is safe (the PUT is a full replace). On
  restart the last successfully persisted allowlist is what loads.
- **Cluster.** Changes made on the Control Plane are pushed to Data Plane nodes
  in the next config snapshot (published immediately on a PUT). Clearing the
  entire allowlist propagates as an explicit wipe.
- **Upgrade / rollback safety.** The persisted feed database and the CP→DP wire
  format exclude currently-allowlisted hosts from the domain list, so an older
  binary (rollback, or a not-yet-upgraded DP during a rolling upgrade) never
  sees a masked host and cannot wrongly block it. Masked intel is held in
  memory only and rebuilt by the next feed sync after a restart.
