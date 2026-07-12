# Decryption Profiles

A **Decryption Profile** is a named, reusable "how to decrypt" object that a policy
rule references. Culvert's policy rule is the "what to match / whether to inspect"
half (match criteria + `SSLAction: Inspect | Bypass`); the profile is the "how"
half — the PAN-OS Decryption Profile model. Manage them under **Decryption
Profiles** in the admin UI, or via `POST/PUT/DELETE /api/decryption-profiles`.

## What it controls

| Field | Meaning | Default (when "inherit") |
|---|---|---|
| **Inspect as HTTP/2** | Inspect the tunnel natively as HTTP/2 instead of downgrading to HTTP/1.1. Removes the HTTP/1.1-downgrade anti-bot signal. | strip → HTTP/1.1 (today's behavior) |
| **Certificate Verification** | Upstream (origin) cert posture: `strict` (verify, block untrusted/expired), `permissive` (verify, allow + log — *coming soon*), `skip` (no verification ⚠). | the rule's inline **Skip TLS Verify** |
| **On Unsupported TLS** | Posture when the origin's TLS can't be inspected: `fail-close` (drop). `fail-open` (bypass out of inspection) is *coming soon*. | fail-close (today's behavior) |
| **Min / Max TLS Version** | Floor / cap on the upstream inspect handshake (`1.2` / `1.3`). | floor 1.2, no cap |
| **Per-stream Stall Timeout** | Inactivity bound per inspected H2 stream, seconds (clamped `[5, 3600]`; `0` = default). | the engine default |

Every field defaults to **inherit** — a profile that sets nothing changes nothing,
and a rule with no profile behaves exactly as before this feature. Binding a profile
is always a deliberate per-rule choice.

`Max Concurrent Streams` is intentionally **not** a per-profile field — it is a
system-wide resource bound on the one shared HTTP/2 inspection server (see
`http2-inspection.md`), so it is global, not per-profile.

## Honest scope — read before enabling for anti-bot destinations

Inspect-as-HTTP/2 removes the **HTTP/1.1-downgrade** signal, which is a real anti-bot
trigger. It does **NOT** change the **TLS fingerprint**: Culvert re-originates TLS
with Go's stack, so a destination that fingerprints the ClientHello (JA3/JA4) or keys
on **egress-IP reputation** — notably **Google** (Search, reCAPTCHA) — may still
challenge even with native H2 on. For those, the answer remains a **Bypass** rule or
a **warmed/dedicated egress IP**.

Where the profile pays off: **business-critical HTTP/2 SaaS you must keep under
inspection** whose bot-manager is tuned for its own app traffic (not adversarial JA3
pinning) — removing the H1 anomaly often clears the soft challenges while you keep
DLP/inspection. That is the intended win.

## Binding a profile to a rule

In the policy-rule editor, set **SSL Action = Inspect**, then pick a **Decryption
Profile**. The picker is hidden for `Bypass` rules (a profile on a non-Inspect rule
is a silent no-op — the editor warns if you do it anyway). Enabling native H2 for a
rule is done here (this is the GUI on-switch; the legacy per-rule `stripAlpn` JSON
field remains as a fallback and is superseded when a profile is bound).

**Dangling references are fail-safe:** if a bound profile is deleted or hasn't synced
to a data-plane node yet, the rule falls back to its inline settings / today's
strip-to-HTTP/1.1 default. A dangling reference can only degrade H2→H1 inspection —
it can **never** turn inspection off. Deleting a profile that a rule references is
blocked (409) until the reference is removed (**Where used** shows the referrers).

## Defaults, sync, and durability

- **On-ramp seed:** on first run Culvert seeds a documented, **non-auto-bound**
  `recommended-h2` profile (Inspect-as-HTTP/2 on, everything else inherit) as a safe
  starting point. It is bound to nothing until you attach it to a rule; delete it and
  it stays deleted.
- Profiles persist in `<dataDir>/decryption_profiles.json` (0600), sync CP→DP in the
  `ConfigSnapshot`, and are covered by config-version rollback and config
  export/import (import merges by name and never wipes).

## Observability

- `culvert_inspect_upstream_alpn_total{protocol="h2"|"http/1.1"}` — the protocol
  inspected tunnels negotiated on the **upstream (origin) leg**. The `h2`/`http1.1`
  ratio is how you confirm enabling Inspect-as-HTTP/2 actually changed the negotiated
  protocol for your traffic (the success delta).
- The native-H2 drain/stream metrics (`culvert_h2_inspect_*`) are documented in
  `http2-inspection.md`.

## Deferred (coming soon)

- `CertVerification: permissive` (verify-but-allow + log) and `OnUnsupported:
  fail-open` (bypass out of inspection) — both are "relax safety" behaviors that
  touch the relay path and ship in a later, separately-reviewed slice; the fields are
  visible now (fail-open greyed) so the object's shape is stable.
- A "test this profile against a destination" preview tool and a dry-run/shadow mode
  are planned operability follow-ups.
