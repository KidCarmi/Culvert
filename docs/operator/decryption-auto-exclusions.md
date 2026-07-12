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

## What it will and will NOT learn

| Inspect failure | Learned? | Why |
|---|---|---|
| Unsupported TLS version/cipher | ✅ | genuine can't-decrypt; server-observed |
| Origin requires a client certificate | ✅ | genuine can't-decrypt; server-observed, non-spoofable |
| Client rejects our forged cert (pinning) | ✅ (guarded) | real pinning signal, but spoofable → needs the confirm-count and gets a shorter TTL |
| Origin cert untrusted / expired / hostname mismatch | ❌ | this is a **block** decision, not a compatibility problem — auto-bypassing a bad cert would be an exfil channel. Stays a `502`. |
| Connection reset / timeout / unknown error | ❌ | fail-closed default; the proxy never learns on an ambiguous signal |

The classifier **defaults to not learning** — only a positive match on a genuine
can't-decrypt signal populates the cache, so a misclassification can only ever
keep inspecting (fail closed), never wrongly bypass.

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

### The never-exclude control

The cache is consulted **only for sessions whose matched rule is fail-open**. A
rule that is **fail-close never consults the cache**, so:

- Hosts covered only by fail-close rules are **never auto-excluded** — keep your
  IdP/SSO, banking, software-update, and DLP-critical origins on fail-close rules
  and they are un-poisonable by design.
- A fail-open rule for one user population cannot silently disable inspection for
  a different, inspect-mandatory rule targeting the same host.

## Operating it

**Decryption Exclusions** panel (viewer can read; operator can evict/clear):

- Each row: host, reason, **hit count** (how much traffic rode the bypass —
  triage signal), distinct-client count, learned time, and expiry.
- The stats line shows the posture: active/pending counts, confirm-count, TTLs,
  and cap — so you can prove the configuration to an auditor. A deployment with no
  fail-open profile shows an empty, inert cache.
- **Evict** one host (inspection resumes immediately; it may re-learn if still
  incompatible) or **Clear all**. Both actions are audited.

The cache is **volatile**: it is in-memory only, per-node (never synced between
Control Plane and Data Plane nodes), and **not** part of config export, import, or
version rollback. It is cleared on restart and re-learns cheaply.

### Metrics

- `culvert_decrypt_autoexclude_total{reason}` — learn events by reason.
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

- **Strip inspection path, server-observed failure** (unsupported params /
  origin-requires-client-cert): the current session **is rescued live** — no
  visible failure.
- **Native-HTTP/2 inspection path, or client-pinning**: **learn-only** — the
  first session fails, and the *next* session to that host self-heals via the
  cache once the confirm-count is met.

For **known** pinned apps where you want guaranteed first-session success, add
them to the manual **SSL Bypass** list (precedence: manual bypass > auto-exclusion
> policy inspect). A curated predefined pinned-app list is a planned enhancement.

## Deferred (planned)

- Native-HTTP/2-path live rescue (currently learn-only there).
- A curated predefined exclusion list of well-known pinned apps.
- A `learn-review` posture (record + alert, bypass only after operator approval).
- Operator-tunable confirm-count / TTL (currently fixed PAN-OS-aligned defaults;
  the posture is surfaced read-only).
