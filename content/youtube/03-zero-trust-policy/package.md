# YouTube package — "Zero-Trust egress policy in the admin UI"

A hands-on demo: author allow rules, test them, then flip the default to deny —
without locking yourself out. Every claim maps to the verified
[Policy engine guide](../../docs/03-policy/policy-engine.md). No synthetic
screenshots; the on-camera UI must be a real instance.

---

## Video objective

Show an administrator how to move a Culvert instance from fresh-install
passthrough to enforced default-deny, safely, using allow rules and the Policy
Tester.

## Target viewer

Security engineers and administrators implementing egress control.

## Expected viewer outcome

The viewer can author a priority-ordered allow rule, dry-run it with the Policy
Tester, and enforce Zero Trust by setting `default_action: deny` — understanding
why order and the fresh-install passthrough matter.

## Title options

1. Zero-Trust egress in Culvert: from passthrough to default-deny
2. Author, test, enforce — Culvert egress policy in 6 minutes
3. Don't lock yourself out: rolling out default-deny in Culvert

## Thumbnail brief

- Split: a red "DENY (default)" block and a green "allow *.github.com" rule.
- Chip: "first match wins". No fabricated dashboards.

## Full narration script

> **[0:00 — The goal]**
> Out of the box, a fresh Culvert install runs in passthrough — it allows
> everything so you can't lock yourself out on day one. Our job today is to turn
> that into Zero Trust: deny by default, allow only what we sanction. And we'll
> do it in the right order so we never cut off our own access.

> **[0:30 — The rule model]**
> Culvert's policy engine evaluates rules in priority order, and the first match
> wins. Each rule can match on source IP, identity, IdP group, auth source,
> destination host, URL category, country, and a time schedule — and then it
> takes an action: Allow, Drop, Block Page, or Redirect. Every allow rule also
> decides whether to Inspect or Bypass TLS.

> **[1:15 — Author allow rules first]**
> Rule number one: we author our allow rules *before* we enforce deny. In the
> Policy panel, I'll add a rule — priority 10, destination `*.github.com`,
> action Allow, TLS action Inspect. Notice priorities are ascending: lower
> numbers evaluate first.

> **[2:15 — Test before enforcing]**
> Now the safety step. The Policy Tester dry-runs a request against the live
> ruleset — same evaluation path as real traffic — and tells us which rule
> matches and what happens. I'll test `api.github.com` for a user: it matches
> our allow rule. I'll also test a destination we haven't allowed, to confirm
> what will happen once deny is on.

> **[3:30 — Flip the default to deny]**
> With allow rules in place and tested, we enforce Zero Trust. I set
> `default_action: deny`. From now on, anything that matches no rule is blocked.
> The moment any rule exists, the default is already deny — setting it
> explicitly makes the posture unambiguous.

> **[4:20 — Verify with Diagnostics and hit counters]**
> Two checks. First, Diagnostics under Infrastructure — resolve any red rows.
> Second, the per-rule hit counters: after some traffic, they show which rules
> are actually matching, so you can spot dead or over-broad rules. Culvert also
> flags conflicts — same priority, different action — as warnings.

> **[5:15 — Close]**
> That's Zero-Trust egress in Culvert: author allow rules, test them with the
> Policy Tester, enforce default-deny, and verify. Do it in that order and you
> never lock yourself out. Full written guide in the description.

## Demonstration plan

Record against a **real** instance. Every rule, test, and result must be genuine.

1. Show the fresh-install passthrough note (startup log or Policy panel).
2. Author an allow rule in the Policy panel.
3. Run the Policy Tester on an allowed and a not-allowed destination.
4. Set `default_action: deny`.
5. Show Diagnostics and the per-rule hit counters.

## Exact commands / UI actions

- Admin UI → **Policy** → add rule (priority 10, `*.github.com`, Allow, Inspect).
- Policy Tester (UI or API):

```bash
curl -sk -X POST https://<host>:9090/api/policy/test \
  -H 'Content-Type: application/json' --cookie "$ADMIN_COOKIE" \
  -d '{"host":"api.github.com","identity":"alice","sourceIP":"10.0.0.5"}'
```

- Set default-deny (config):

```yaml
default_action: deny
```

- Admin UI → **Infrastructure → Diagnostics**.

## Lab prerequisites

- A running Culvert instance with the setup wizard completed.
- An admin session cookie for the API calls.

## Expected results

- The Policy Tester returns the matched rule and action for an allowed host, and
  a no-match (deny once enforced) for an unlisted host.
- After enforcing deny, unlisted destinations are blocked.

## Failure and recovery path

| Failure | Fix (show on camera) |
|---|---|
| Enforced deny before authoring allow rules → own access blocked | Add the allow rule; first-match ordering restores access |
| Two equal-priority rules with different actions | Culvert flags a conflict warning; reorder or re-prioritize |

## Chapter timestamps (proposal)

| Time | Chapter |
|---|---|
| 0:00 | The goal (passthrough → Zero Trust) |
| 0:30 | The rule model |
| 1:15 | Author allow rules first |
| 2:15 | Test with the Policy Tester |
| 3:30 | Enforce default-deny |
| 4:20 | Verify (Diagnostics, hit counters, conflicts) |
| 5:15 | Recap |

## Video description

```
Move a Culvert Secure Web Gateway from fresh-install passthrough to enforced
Zero-Trust egress. We author priority-ordered allow rules, dry-run them with the
Policy Tester (the same evaluation path as live traffic), then set
default_action: deny — in the order that keeps you from locking yourself out.

Chapters:
0:00 The goal
0:30 The rule model
1:15 Author allow rules first
2:15 Test with the Policy Tester
3:30 Enforce default-deny
4:20 Verify
5:15 Recap

Policy guide: <link: Policy engine & Zero-Trust authoring>
Source: https://github.com/KidCarmi/Culvert
```

## Pinned comment

```
The safe rollout order (from the video):
1) Author allow rules for everything users need.
2) Dry-run them with the Policy Tester (POST /api/policy/test).
3) Set default_action: deny.
4) Verify with Diagnostics + per-rule hit counters.
Reminder: first match wins, priorities ascending, and a fresh install starts in
passthrough by design.
Full guide → <link: Policy engine & Zero-Trust authoring>
```

## Related documentation (placeholders)

- `<link: Policy engine & Zero-Trust authoring>` → `content/docs/03-policy/policy-engine.md`
- `<link: TLS inspection administration>` → `content/docs/04-tls-inspection/tls-inspection.md`
- `<link: Quick start>` → `content/docs/02-getting-started/quick-start.md`

## Short-form version (≤60s)

> Turn Culvert into Zero-Trust egress in four steps — in the right order.
> One: author your allow rules — priority, destination, Allow, Inspect or
> Bypass. Two: dry-run them with the Policy Tester, same path as real traffic.
> Three: set `default_action: deny`. Four: verify with Diagnostics and per-rule
> hit counters. First match wins, and a fresh install starts in passthrough — so
> allow first, enforce second, and you never lock yourself out.

## Claim-evidence ledger

| Claim in the video | Evidence |
|---|---|
| First-match by priority, 8 conditions, actions + TLS action | `policy.go:1083,94-109,23-34` |
| Fresh install passthrough; `default_action: deny` enforces | `proxy.go:19`; `config.go:84-87`; README Limitations |
| Policy Tester dry-runs the live ruleset (same eval path) | `POST /api/policy/test`; `ui_policy.go:1880` |
| Per-rule hit counters | `culvert_policy_rule_hits_total` (`metrics.go:332`) |
| Conflict detection (same priority, different action) | `policy.go:877` `DetectConflicts` |

All map to the [Policy engine ledger](../../docs/03-policy/policy-engine.evidence.md).
The on-camera UI must be recorded from a real instance (no synthetic screens).
