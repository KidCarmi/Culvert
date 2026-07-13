# Adaptive decryption exclusions (fail-open + auto-learn)

Culvert can automatically learn which hosts are **incompatible with SSL
inspection** and bypass decryption for them, so a pinned mobile app or an origin
that requires a client certificate keeps working instead of breaking. This is the
adaptive counterpart to the manual **SSL Bypass** list (operator-authored
patterns): the manual list is what you *know* breaks; auto-exclusion learns what
you *don't*.

It models the PAN-OS "local SSL decryption exclusion cache" for a multi-tenant
forward proxy, with extra guardrails because auto-disabling inspection for a host
is a security decision.

## What it does

When a rule's Decryption Profile opts into **fail-open** and an inspected tunnel
cannot be established because the host is incompatible with decryption, Culvert:

1. **Learns** the host into a volatile, bounded, TTL-bounded cache — but only
   after a **confirm-count of distinct client IPs** hit the same failure (so a
   single endpoint cannot force an exclusion).
2. **Rescues the current session** where it can (the strip inspection path, before
   the client is committed) by transparently falling back to a bypass tunnel.
3. **Bypasses subsequent sessions** to that host — for sessions whose rule is also
   fail-open — until the entry expires.

Every learn event is **alerted** (to syslog/SIEM), **audited**, exposed as a
**metric**, and listed in the **Decryption Exclusions** panel with its blast
radius, where you can evict it.

**Live rescues are observable too.** The confirm-count-exempt live rescue (step 2)
does not wait for promotion, so it is surfaced independently: each rescue emits a
`decryption.autoexclude.rescue` **audit** entry (actor = triggering client IP), a
`decryption_autoexclude_rescue` **alert**, and increments the
`culvert_decrypt_autoexclude_rescue_total` **metric**. This makes a client that
repeatedly forces per-session bypasses (e.g. by routing through a cert-demanding
origin under a fail-open rule) visible even before it ever reaches the
confirm-count — watch the rescue counter's rate as an early poisoning/evasion
signal.

## What it will and will NOT learn

An origin controls its own TLS alerts, so the classifier trusts only **narrow,
specific** signals — a generic origin-emitted failure is not proof of decryption
incompatibility and never triggers a bypass.

| Inspect failure | Learned? | Live-rescues the triggering session? |
|---|---|---|
| Origin requires a client certificate (`certificate_required` alert) | ✅ | ✅ (strip path only — the one reason allowed to rescue) |
| TLS parameter mismatch our OWN stack detected (no version/cipher overlap) | ✅ | ❌ learn-only; the next session self-heals |
| Client rejects our forged cert with a specific cert alert (pinning) | ✅ (guarded) | ❌ learn-only; spoofable → confirm-count + shorter TTL |
| Generic origin alert (`handshake_failure`, `no_application_protocol`) | ❌ | ❌ origin-controlled + ambiguous → stays a `502` |
| Origin cert untrusted / expired / hostname mismatch | ❌ | ❌ a **block** decision — auto-bypassing a bad cert is an exfil channel |
| Connection reset / timeout / wrapped / unknown error | ❌ | ❌ fail-closed default |

The classifier **defaults to not learning** — only a positive match on a narrow
signal populates the cache, so a misclassification can only ever keep inspecting
(fail closed), never wrongly bypass.

> **Residual downgrade risk (live rescue).** Even `certificate_required` is an
> origin-emitted alert, so an attacker-controlled origin *under a fail-open rule*
> could demand a client cert to force a one-session bypass. This is bounded by the
> per-profile opt-in (you chose fail-open for that traffic class) and the profile
> scope (below), and it is why DLP-critical / inspection-mandatory hosts belong on
> **fail-close** rules — those never rescue, learn, or consult the cache.

> **Private-PKI origins:** if a business-critical SaaS uses a private/enterprise
> CA Culvert doesn't trust, the *correct* fix is to add that CA to Culvert's trust
> store and **keep inspecting** — not fail-open. Because an untrusted issuer is
> never auto-excluded, that origin stays a hard `502` until you add the CA, which
> surfaces the misconfiguration instead of silently going dark.

## Enabling it

1. Open **Decryption Profiles**, create or edit a profile, and set **On Inspect
   Failure → Fail-open (auto-exclude + learn)**. A red warning explains the
   security implication.
2. Reference that profile from the policy rule(s) whose traffic you want to
   fail-open. Only traffic matched by a **fail-open** rule is ever learned OR
   auto-bypassed.

It is **off by default** — with no fail-open profile the cache is inert and
inspection behavior is byte-for-byte unchanged.

### Scope: exclusions are per decryption profile, not global

Every learned exclusion is keyed by **(profile, host)** — the decryption profile
that matched the failing session owns it. A host learned under profile *A* is
bypassed **only** for sessions that also match profile *A*; a different fail-open
profile *B* targeting the same host is unaffected and keeps inspecting until it
learns the host itself. This is real policy isolation: one team's / tenant's /
population's fail-open profile cannot open a hole in another's. The panel shows
each exclusion's owning profile and its **blast radius** (how many policy rules
that profile is bound to).

### The never-exclude control

The cache is consulted **only for sessions whose matched rule is fail-open**. A
rule that is **fail-close never consults the cache**, so:

- Hosts covered only by fail-close rules are **never auto-excluded** — keep your
  IdP/SSO, banking, software-update, and DLP-critical origins on fail-close rules
  and they are un-poisonable by design.
- A fail-open rule for one user population cannot silently disable inspection for
  a different, inspect-mandatory rule targeting the same host.

### Distinct-client evidence (confirm-count)

Promotion requires the same failure from **N distinct clients** (default 2). The
"client" is the **authenticated identity** when the session is authenticated,
otherwise the client address (IPv6 collapsed to /64 for single-host address
churn; IPv4 kept raw). **NAT/DHCP limitation:** unauthenticated devices sharing
one egress IP count as one client, so a host that breaks only for such a fleet
needs failures from two distinct egress IPs (or two authenticated users) before
it is excluded. Authenticating clients gives the best device-independence signal.

### Downgrade / rollback

`OnInspectError` is an additive persisted decryption-profile field (a
config-schema change, though it adds no new top-level surface). It round-trips
through config export and version rollback. **Downgrade is safe:** an older binary
that does not know the field ignores the unknown JSON key on load and the profile
still parses, resolving to **fail-close** (today's behavior) — enabling fail-open
on a new build and rolling back never breaks profile loading.

### Staged rollout (recommended)

This feature disables inspection for learned hosts, so roll it out gradually:

1. Enable fail-open on **one narrow profile** bound to a **specific** rule (e.g.
   a known pinned-app or BYOD segment) — never a catch-all `*` rule.
2. Watch the **Decryption Exclusions** panel and
   `culvert_decrypt_autoexclude_active` for a week. Confirm the learned hosts are
   the ones you expect and the blast radius is small.
3. Alert on the active gauge and on the `decryption_autoexclude` learn events in
   your SIEM. Treat an unexpected host going dark as an incident.
4. Expand to more profiles only after the above is stable. Keep every
   inspection-mandatory host on a fail-close rule throughout.

## Operating it

**Decryption Exclusions** panel (viewer can read; operator can evict/clear):

- Each row: host, reason, **hit count** (how much traffic rode the bypass —
  triage signal), distinct-client count, learned time, and expiry.
- The panel's first line is the **provable-OFF / footprint** evidence: it states
  either "Fail-open is not configured — SSL inspection cannot be auto-disabled on
  this node" (0 fail-open profiles) or how many fail-open profiles exist and **how
  many policy rules reference them**. This is the affirmative fact an auditor asks
  for — an empty cache alone does not prove inspection *cannot* be disabled; 0
  fail-open rules does. A high rule count is your over-adoption signal (a fail-open
  profile bound to a broad/catch-all rule).
- The stats line shows the posture: active/pending counts, confirm-count (distinct
  clients — authenticated identity when present, else client IP), TTLs, and cap.
- **Evict** one host (inspection resumes immediately; it may re-learn if still
  incompatible) or **Clear all**. Both actions are audited.

The cache is **volatile**: it is in-memory only, per-node (never synced between
Control Plane and Data Plane nodes), and **not** part of config export, import, or
version rollback. It is cleared on restart and re-learns cheaply.

### Metrics

- `culvert_decrypt_autoexclude_total{reason,scope}` — learn events by reason and
  owning decryption profile (scope).
- `culvert_decrypt_autoexclude_hit_total` — sessions bypassed due to a learned
  exclusion.
- `culvert_decrypt_autoexclude_active` — current active exclusions (gauge). Alert
  on this to catch inspection-coverage erosion.
- `culvert_decrypt_autoexclude_pending` — in-progress (unconfirmed) observations.

### Audit / alert actions

- `decryption.autoexclude.learn` — a host was excluded (actor = the triggering
  client IP, so a poisoning source is traceable). Also raised as a
  `decryption_autoexclude` alert to any configured syslog/SIEM channel.
- `decryption.autoexclude.evict` / `decryption.autoexclude.clear` — operator
  removed one / all.

## First-session behavior (expectation-setting)

For a **never-before-seen** incompatible host, the *first* connection can still
fail — you cannot rescue a client that refuses your certificate without prior
knowledge of the host. Behavior by path:

- **Strip inspection path, origin-requires-client-cert ONLY**: the current
  session **is rescued live** — no visible failure. This is the single
  live-rescued case, and it is **confirm-count-exempt** (it bypasses the
  *triggering* session on the first `certificate_required` signal; the
  confirm-count protects the *persistent* cache future sessions read). Because it
  applies only to hosts an operator deliberately put on a fail-open rule, size
  fail-open scope accordingly — keep DLP-critical hosts on fail-close.
- **Everything else** — unsupported-params (strip path), the native-HTTP/2 path,
  and client-pinning — is **learn-only**: the first session fails with a `502`,
  and the *next* session to that host self-heals via the cache once the
  confirm-count is met. (Unsupported-params does NOT live-rescue: it is
  origin-influenced and lower-confidence than client-cert-required.)

For **known** pinned apps — the most persistent incompatibility, and one the
`client_pinned` short (1h) TTL deliberately does not durably cache — add them to
the manual **SSL Bypass** list for guaranteed first-session success (precedence:
manual bypass > auto-exclusion > policy inspect). A curated predefined pinned-app
list is a planned enhancement.

## Deferred (planned)

- Native-HTTP/2-path live rescue (currently learn-only there).
- A curated predefined exclusion list of well-known pinned apps.
- A `learn-review` posture (record + alert, bypass only after operator approval).
- Operator-tunable confirm-count / TTL (currently fixed PAN-OS-aligned defaults;
  the posture is surfaced read-only).
