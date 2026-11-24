# Security decision — a ruleset the build cannot enforce is refused whole; the per-rule drop (SEC-POLICYDROP-1) is superseded

**Date:** 2026-11-24
**Decided by:** repository owner (explicit authorization to revise the earlier decision for this case)
**Supersedes:** the per-rule drop in `PolicyStore.Load` / `PolicyStore.ReplaceAll` and the
`ConfiguredRuleCount` compensation recorded as SEC-POLICYDROP-1 in
[2026-10-17](2026-10-17-session-audience-and-policy-fail-open-window.md). That record is history and
is left as written; this one is current.
**Contract:** `POL-005` in `contracts/registry.yaml` (amended in the same change).

## The governing invariant

No policy replacement, normalization, migration or compatibility conversion may silently remove an
enforcement rule and thereby expand access.

## What was decided before, and why it was not enough

`policyRulePersistable` refuses four shapes: an access rule carrying a `subjectMatch` (the evaluator
does not consult it), an access rule carrying an `auth` spec, an auth rule that fails validation,
and a null entry (which only the policy-file door could see; the other doors decode it to an empty
rule, below). `Load` and `ReplaceAll` dropped such a rule and installed the rest.

The drop was reasoned from one direction: a scoped **Allow** that lost its scope would match
everyone, so it must not be installed. That holds. SEC-POLICYDROP-1 then closed the case where every
rule was dropped and the empty result looked like "no policy configured".

The other direction was not covered. A rule that **restricts** is also dropped, and then the
restriction is gone. Measured over a real proxy socket, default allow:

```
ReplaceAll{Block backend, subjectMatch cidr 127.0.0.0/8}
  running rules = (none)   status=200   backend_hits=1
```

The same class had already been handled for two other fields: an unknown action is kept and blocks
(POL-004), and an unknown `ruleType` refuses the whole ruleset (POL-005).

## The decision

A ruleset that holds any rule the build cannot enforce as written is refused **whole**, by the
POL-005 gate, at every POL-005 door. Nothing is dropped and nothing is partially applied. The
running policy and the persisted policy stay as they were.

| Door | Behaviour |
|---|---|
| `PolicyStore.Load` | error; previous rules and path stand. At startup this is fatal, as for a malformed file |
| `PolicyStore.ReplaceAll` | atomic refusal (backstop) |
| Control-plane snapshot | refused on publish and, on a data plane, before any mutation |
| Config import, both modes and dry run | `400` before any section applies |
| Config-version rollback | `400` in the handler for a version the gate refuses. A version it accepts is restored with **every** stored rule, as stored |
| Pending policy draft on disk | not reloaded |
| Policy-file reload | previous rules and previous default action both stand |

### Two things the review of this change added

**Rollback restores what was stored.** The restore used to run every stored rule through the
write-time validator and skip the ones that failed. That validator resolves a Redirect rule's host
in DNS, reads the host's timezone database, and refuses shapes the store holds and enforces: a
lower-case action from the policy file, a rule with no name, an empty action. So a rollback removed
live rules, and which ones depended on DNS at that moment. A first version of this change turned the
skip into a refusal with the same validator; an independent review showed that made versions
captured from a running system unrestorable. Rollback now applies the gate and nothing else, and
restores every rule.

**An empty entry is refused at every door.** A `null` or `{}` in a rule list decodes, wherever the
list is read into rule values (import, snapshot, rollback, draft), to a rule with no name, no type
and no action: no conditions, so it matches every request, and an empty action resolves to Allow.
The gate refuses an entry with no name, no type and no action. A named rule with an empty action is
untouched; POL-901 stays open.

Unchanged on purpose: POL-004 (an unknown action is kept and a match blocks), POL-901 (an empty
action resolves to Allow; still an open question), and default-allow semantics for a valid policy,
including a genuinely empty one.

## Why refuse rather than keep-and-block

Keeping a scoped Block without its scope would block everyone the scope excluded. That is
fail-closed, but it enforces a rule nobody wrote, and it cannot be applied to Allow rules, so the
store would need a per-action policy for unenforceable rules. Refusing treats every such ruleset the
same way and matches POL-005, which the owner asked to reuse rather than add a parallel mechanism.

## What the operator sees

- Diagnostics row `policy_ruleset_refused_unenforceable_rule` (or `…_unknown_ruletype`), naming the
  door, the first offending rule, how many times the same ruleset was refused and since when. It
  clears when a ruleset is next accepted. The old `policy_rules_dropped_on_load` row is removed:
  nothing is dropped any more.
- One log line for the first refusal, another at once if the door or reason changes, and otherwise
  at most one per 15 minutes. A data plane that cannot follow its control plane refuses the same
  snapshot on every poll; its rejection path now logs through this record instead of writing a line
  per poll. A refused policy-file reload still logs each time it is requested.
- `culvert policy-check <file>...` lists **every** rule a policy file, config backup, stored config
  version or policy draft holds that this version would refuse, without starting anything. Startup's fatal error names only
  the first and now points at this command.

## Cost

Strictness. A node handed a ruleset from a newer release keeps its last accepted policy until it is
upgraded or the ruleset is corrected. A policy file holding such a rule stops startup. A stored
config version holding a rule the gate refuses cannot be restored. The gate is a pure function of
the rule (no clock, DNS, registry or timezone lookups), and every write path validates at least as
strictly, so the product cannot write a ruleset it then refuses.

## Evidence

`policy_unenforceable_rule_test.go`: three real-socket tests that start from a running Block under
default allow, offer the replacement through one door, and require an unchanged rulebase, `403` and
zero backend hits; every refusal reason alone and beside valid rules at both store doors; rollback
(refused whole, or every stored rule restored, including the shapes above) and import; log
deduplication; the preflight. Nineteen existing tests that asserted "drop one rule, install the
rest" were migrated to assert whole-ruleset refusal, keeping their other coverage;
`diagnostics_policy_dropped_test.go` was removed with the row it tested.
