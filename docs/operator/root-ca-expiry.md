# Runbook — Root CA expiry and SSL-inspection outage

**Applies to:** the SSL-inspection Root CA (the MITM CA Culvert uses to forge leaf
certificates), not the cluster enrollment CA.
**Symptom class:** inspected HTTPS stops working fleet-wide, all at once.
**Posture:** fail closed — Culvert refuses to inspect rather than presenting a certificate
clients cannot accept.

---

## 1. What happens when the Root CA goes out of its validity window

Culvert forges a leaf certificate for every inspected HTTPS destination, signed by the
inspection Root CA that your clients have been provisioned to trust. If that Root CA is
outside its own validity window — expired, or (after a clock rollback) not yet valid — no
leaf it signs can be accepted by any client, because certificate path validation checks
every certificate in the chain.

Culvert therefore **refuses to inspect** in that state:

- Inspect-matched `CONNECT` requests are answered **502 Bad Gateway** *before* the tunnel is
  established, so clients get a proxy error rather than an unexplainable TLS failure.
- The refusal is **not** a bypass. Traffic that policy said to inspect is not quietly
  forwarded uninspected — that would leave DLP, antivirus, YARA, CDR, file-blocking and DPI
  silently off across the whole fleet.
- Traffic that policy does **not** inspect is unaffected: plain HTTP, SSL-bypass rules,
  SOCKS5 and WebSocket relays all keep working normally.

> **Expect a fleet-wide, simultaneous onset.** Every node provisioned from the same CA bundle
> holds the same `NotAfter`. There is no canary and no gradual degradation.

## 2. How to confirm it

Any one of these is conclusive:

| Surface | What you'll see |
|---|---|
| `GET /healthz` | `"ssl_inspection": "expired"` |
| `GET /readyz` | `checks.ca.status = "fail"` (report-only — it does **not** flip the node to `not_ready` unless you probe `/readyz?strict=1`) |
| `GET /metrics` | `culvert_ca_usable 0`, `culvert_ca_expires_in_seconds` negative, `culvert_ca_inspect_blocked_total` climbing |
| `GET /api/diagnostics` | operator-contract row `root_ca` = **fail**, with the remediation |
| Admin UI → CA Management | red banner: *SSL inspection is DOWN* |
| Alerts | `cert_expiry` with detail `SSL inspection is DOWN — the Root CA cannot sign a usable leaf: …` |
| Logs | `CA: SSL inspection is DOWN — the Root CA cannot sign a usable leaf: …` (rate-limited to once per 5 minutes; the counters carry the true volume) |

## 3. Recovery

1. **Check the clock first.** If the log says `not valid until <timestamp> (system clock may
   have rolled back)`, this is an NTP/RTC problem, not a certificate problem. Fix time sync;
   inspection resumes on its own with no certificate work at all.
2. **Otherwise, rotate the Root CA** — Admin UI → *CA Management* → *Force Rotation*, or
   `POST /api/ca/rotate` (admin role, confirmation-token flow). Culvert also checks for a
   needed rotation at every startup and every 24 hours, and rotates automatically inside the
   30-day pre-expiry window.
3. **Confirm the rotation persisted.** If you see an amber banner *"Root CA rotated but not
   saved"* — or the `root_ca` row on `/api/diagnostics` warns, or `POST /api/ca/rotate`
   answered with `"persisted": false` — the replacement CA exists **in memory only** and will
   be lost on the next restart, which will then rotate again to a *different* CA. Fix the data
   volume (space, mount flags, permissions on the `-ca-path` bundle) and force another rotation
   before doing anything else. Those three surfaces clear as soon as a rotation actually
   writes; `culvert_ca_rotation_persist_failures_total` is a cumulative counter and does not.
4. **Redistribute the new Root CA to clients.** This step cannot be automated from inside the
   gateway: a new root is untrusted by definition. Download it from *CA Management → Download
   CA*, or `GET /api/ca/download`, and push it through your existing trust-store channel
   (MDM, group policy, configuration management).
5. **Verify.** `culvert_ca_usable` returns to `1` and `/healthz` returns to
   `"ssl_inspection": "ready"`. Culvert clears the degraded state only after it has actually
   verified the CA is usable again — elapsed time alone never clears it.

## 4. Preventing it

Alert on the *runway*, not the cliff. The useful rule is:

```promql
# Page well before inspection breaks. Rotation begins automatically at 30 days;
# clients still need the new root pushed to them, so 45 days gives you room.
culvert_ca_expires_in_seconds < 45 * 24 * 3600
```

and a hard backstop on the outage itself:

```promql
culvert_ca_usable == 0

# Cumulative counter — use a rate/increase window, not `> 0`, or the rule latches
# forever after a single historical failure. The live "is the active CA durable?"
# state is the `root_ca` row on /api/diagnostics and the CA panel banner, both of
# which clear once a rotation actually persists.
increase(culvert_ca_rotation_persist_failures_total[1h]) > 0
```

The `culvert_ca_expires_in_seconds` series is omitted entirely on a node with no Root CA
loaded, so these rules do not fire on nodes that never do SSL inspection.

## 5. Dual-CA overlap (what normal rotation looks like)

An automatic rotation inside the 30-day window is **not** an outage. Culvert keeps the old CA
as a *secondary* for the remainder of its original lifetime and includes it in the chain, so
clients trusting either the old or the new root keep validating while you roll the new root
out. The CA Management panel shows the overlap window and its end date. Use that window to
redistribute; once it closes, only the new root works.

## 6. Related

- Design and evidence: `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-09.md` (CHAOS-28)
- Standing register rows: CA-1, CA-1b, CA-2, CA-4, CA-16 in
  `roadmap/CHAOS-ENGINEERING-REVIEW.md` §16
