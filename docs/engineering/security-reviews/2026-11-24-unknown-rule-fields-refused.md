# Security decision — a rule whose JSON keys the build cannot honour (unknown, or given twice) is refused, at every door

**Date:** 2026-11-24
**Decided by:** repository owner ("Unknown JSON fields — approved for contract unification. Establish a
consistent policy across all entry points. Prefer explicit rejection for supported configuration
schemas rather than silently discarding user intent. Preserve backward compatibility through an
explicit compatibility strategy where necessary.")
**Contract:** `POL-005` in `contracts/registry.yaml` (amended in the same change).
**Builds on:** [ruleset refusal supersedes the per-rule drop](2026-11-24-ruleset-refusal-supersedes-per-rule-drop.md).

## The finding, as measured

A rule object can carry a key this build has no field for: a typo (`"destFQDN "`, `"sourceIPs"`,
`"srcIP"`) or a condition added by a newer release. `encoding/json` ignores it. An ignored match
condition widens the rule.

Ruleset offered, over a running `Block H` under default allow, client `198.51.100.7`:

```
[{"name":"allow-finance","action":"Allow","destFQDN":H,"srcIP":"203.0.113.0/24"},
 {"name":"lkg-block","action":"Block_Page","destFQDN":H}]
```

| Door | Decode | Before | After |
|---|---|---|---|
| `POST`/`PUT /api/policy`, `/api/authpolicy` | strict (`decodeJSON`) | unknown key: `400 invalid JSON`. Duplicate key: accepted, last value | `400` naming the rule and the keys; nothing changed |
| Draft edit | the same handlers | as above | as above |
| Config import: merge, replace, dry run | strict (`decodeJSON`) | `400 invalid JSON: json: unknown field "srcIP"` | `400` naming the rule and the key, from the gate |
| Policy file: startup, reload | `json.Unmarshal` | loaded; client **allowed** by `allow-finance` | refused whole; startup fatal; reload keeps rules and default action |
| Stored config version (rollback) | `json.Unmarshal` | `200 rolled_back`; client **allowed** | `400`, nothing applied |
| Pending draft on disk | `json.Unmarshal` | reloaded as an active draft with the widened rule | not reloaded |
| Control-plane snapshot: full, delta remainder | `json.Unmarshal` | applied; client **allowed** | refused before any mutation; last accepted policy kept |
| HA bundle, data-plane last-good snapshot | `json.Unmarshal`, then `validateConfigSnapshot` | accepted | refused by the same gate; last-good at boot is a Diagnostics row |
| `culvert policy-check` | `json.Unmarshal` | `OK` (and `OK — 0 rule(s)` for a snapshot-shaped file) | lists every such rule and key, snapshots included |
| Policy learning | builds the rule from a typed DTO | no rule JSON | unchanged |
| Snapshot publish (control plane) | encodes typed rules | cannot emit an unknown key | unchanged |

So the earlier statement that the key was ignored "at every door except import" was wrong in the
safe direction: every operator door already refused it. The exposure was the persisted and wire
doors.

Two properties of the decoder, reported because they are easy to assume wrongly:

- **Key names are matched case-insensitively.** `"sourceIp"`, `"sourceip"` and `"destFqdn"` bind to
  their fields. They are not unknown and are not refused; this repository's own tests and stored
  files use `"destFqdn"`. The check applies the decoder's rule (exact, else case-insensitive), and a
  test compares it with `encoding/json`'s strict mode case by case.
- **Duplicate keys: the last wins.** `{"sourceIP":"203.0.113.0/24","sourceip":""}` decodes to an
  empty source: the same Allow, for every source, at every door including the operator ones. This
  is the same defect (a condition present in the document and not enforced) and is refused by the
  same gate.

## The decision

A rule decoded from JSON is refused, as a rule the build cannot enforce as written, when it carries

- a key the build has no field for,
- the same key twice (after the decoder's case folding), or
- an `annotations` value outside its bounds (below).

It is refused by the POL-005 gate, at the doors that gate already guards, with the same Diagnostics
code (`policy_ruleset_refused_unenforceable_rule`). Nothing is dropped, nothing is partially applied,
and the refusal names the rule and every such key (the first eight, then a count).

Scope:

- The rule object and everything inside it: `schedule`, `subjectMatch` and its predicates, `auth`.
- **Not** the documents around rules. A `ConfigSnapshot` from a newer control plane may carry
  sections, and keys on non-rule objects, that this build does not know. That is ordinary forward
  compatibility and is unchanged (tested through `fetchAndApply`). A config backup's envelope was
  already strict at import and stays so.
- **Not** the contents of `annotations`.

A **rule list given twice** in one document (`"policyRules":[…],"policyRules":[…]`, and likewise
`policy_rules` and `rules`) is the same defect one level up: the first list is discarded, which can
remove every rule (`[…]` then `[]`). Every envelope declares its list as `ruleList`, which
notices the second decode and adds an entry the gate refuses.

Mechanism: `PolicyRule` decodes itself (`UnmarshalJSON`, `policy_unknown_field.go`): the rule is
decoded onto a zero value (so nothing survives from an earlier decode of the same slice element or
variable, and no bytes are shared with it), its keys are read a second time against the struct's
fields, and what cannot be honoured is recorded on the rule instead of failing the surrounding
document. No production caller decodes a partial rule onto a populated one.
`ruleEnforceable` refuses a rule so marked. There is no per-door code; `PolicyStore.ReplaceAll` and
`Load` are the backstop. The single-rule API handlers call one helper, `decodeRuleJSON`. Each rule's
JSON is read twice; these are load-time paths.

## Compatibility strategy: one container, and a rule about new keys

The first version of this change relied on "new rule keys are `omitempty`, so an older node refuses
only when a rule uses a condition it lacks". Independent review showed that does not hold for this
project: it routinely adds keys that are **not** conditions and that land on existing rules right
after an upgrade (`id` backfilled on load, `decryptionProfileId` / `destCategoryGroupId` /
`fileProfileId` stamped from names, `createdAt` / `modifiedAt` / `modifiedBy`). One more such key in
a later release, with the control plane upgraded first (the documented order), and every data plane
on this build would refuse every snapshot, whole, blocklist and IP-filter changes included.

So the strategy is structural and needs no negotiation. It is the same for a policy file, a stored
version and the wire:

> **A new rule key is, by definition, an enforcement condition.** Every build that does not know it
> refuses, whole, any ruleset in which a rule carries it.
>
> **Anything that is not a condition** — identifiers, timestamps, provenance, display data, notes —
> **must not be a new rule key. It goes inside `annotations`.**

`annotations` is one reserved key on a rule: a JSON object whose contents this build and every later
one carry without interpreting. It never affects a match, an action or validation.

- Carried through the store, the policy file, export, stored versions and snapshots, so what a
  newer node writes there survives a pass through an older one (tested).
- Held and bounded in **canonical form**: compact JSON, escaped as `encoding/json` escapes when it
  writes (`<`, `>`, `&`, U+2028, U+2029 as `\uXXXX`). At most 4096 bytes and 8 levels of that form.
  The first version measured the bytes as written, and Culvert's own encoders enlarge those: a
  4004-byte container loaded clean, the store re-saved the policy file indented (7665 bytes) and the
  next start was fatal; `{"n":"<<<…"}` of 1008 bytes was accepted by the API and was 6008 bytes in
  the snapshot every data plane then refused. The canonical form is a fixed point of every encoder
  in use (Marshal, MarshalIndent, a stream encoder with or without HTML escaping), so a rule
  accepted once is accepted after any number of save, export and publish round trips, and a rule
  refused is refused however it is written. Tested for adversarial contents through every
  encoder × document pair, and through the "no rule ids → first start saves → second start" sequence.
  The limits are part of the format and must not be raised, or an older node would refuse what a
  newer one accepts. `null` is the same as absent.
- It is one pointer on the rule, not the bytes. `PolicyRule` is copied into `PolicyMatch` on every
  matched request and sat exactly on its malloc size class (568 bytes in the 576 class); the inline
  form made it 608 and cost 64 B on every match. The pointer's 8 bytes come from `lastHitUnix`, an
  unexported transport field, now `uint32` seconds placed in existing padding (saturates in 2106;
  the authoritative timestamp in the counters cell stays `int64`). The pointee is immutable once
  decoded and is shared by rule copies.
- The legal place for a hand-editor's note. The refusal text and `culvert policy-check` say so.
- Not preserved by a rule edit that omits it: `PUT /api/policy` replaces a rule whole, and neither
  admin UI sends `annotations`, so editing a rule in a UI removes them. Server-stamped data that must
  survive edits will need the update path to carry the container over; nothing writes it yet.

Enforced by `TestRuleKeys_AreAPinnedSetAndNewOnesAreConditions`: it derives, by reflection from
`PolicyRule`, every struct type the decoder reads, pins today's 53 keys, and fails on any other with
the rule above. It asks the real encoder what an empty rule is written as, so `omitempty` on a
non-pointer struct (which never omits) cannot pass as "omitted when unused"; the set of keys written
into every rule (27) may not grow; embedded and untagged fields, and nested types that decode
themselves, fail. The existing informational keys stay where they are: every build that refuses
unknown keys already knows them.

Other parts of the strategy:

1. **Nothing Culvert wrote is refused.** The clone used is shallow at the repository's first commit
   (2026-03-05); in `main`'s history since then (174 commits to `policy.go` and `authpolicy.go`) no
   key was removed or renamed on `PolicyRule`, `PolicySchedule`, `SubjectMatch` or
   `SubjectPredicate`. One key was removed from the nested auth spec: `auth.idpRef` (added
   2026-06-08, removed within days). It was `omitempty`, validation refused any non-empty value, and
   it named an identity provider to target, so no stored rule carries it and it would not be safe to
   ignore. The server writes rules only by encoding these structs, and never writes a key twice.
   There is no allowlist of legacy keys.
2. **Case-insensitive names keep working** (above).
3. **Preflight.** `culvert policy-check <file>...` lists every such rule and key in a policy file,
   config backup, stored config version, pending draft, and now a control-plane snapshot (the data
   plane's `dp_last_config_snapshot.json`) or HA bundle. A snapshot-shaped file used to read as a
   backup with no rules and print `OK`.

| Control plane | Data plane | Result |
|---|---|---|
| this release | this release | unchanged; a published snapshot is encoded from typed rules |
| this release | older | unchanged for existing keys. A rule that has `annotations` sends a key the older node ignores, harmlessly |
| older | this release | unchanged; fewer keys, all known |
| newer, new data only inside `annotations` | this release | applied; annotations kept |
| newer, a rule uses a new **condition** | this release | snapshot refused whole; last accepted configuration kept; Diagnostics row; upgrade the node |
| newer, a rule uses a new condition | older than this release | key ignored, rule widened (the defect; not fixable retroactively) |

## What remains, by design

When a future release adds a real **condition** and an operator uses it while older data planes are
still deployed, those nodes refuse the whole snapshot and stay on their last accepted configuration.
That includes the snapshot's blocklist and IP-filter changes, because a snapshot is validated and
applied as one unit. It is the posture an unknown `ruleType` already has. The alternative is to
enforce the rule without the condition.

**Follow-up, not implemented:** the control plane cannot see *why* a node lags. The heartbeat carries
the applied config and policy versions only (`controlplane_client.go`, heartbeat request), so a node
refusing snapshots looks merely behind. Carrying the node's ruleset-refusal code (and door) in the
heartbeat would let the control plane show "refusing: rule uses a condition this node lacks" per
node, and warn before an operator saves such a rule while older nodes are enrolled.

## Upgrade impact

- A **hand-edited policy file** in which a rule carries an extra, misspelt or repeated key
  (`"_comment"`, `"description"`, `"srcIP"`) stops startup, with an error naming the first such rule
  and all its keys. Until now the key was ignored. Run `culvert policy-check <policy file>` with the
  new binary before upgrading; move notes under `annotations`.
- The same file on reload is refused; the running rules and default action stay.
- A stored config version or pending draft holding such a rule cannot be restored or reloaded. The
  product cannot have written one.
- A data plane whose last-known-good snapshot is refused at startup now shows it in Diagnostics
  (door "last-known-good snapshot on disk") instead of only logging it.
- API clients: a rule body with an unknown key was a `400` and is a `400`; the text now names the
  rule and the keys. A rule body with a **duplicate** key was accepted (last value) and is now a
  `400`. Both admin UIs send only known keys, once each (tested with the exact bodies they build,
  and with a GET→PUT of what the server returns).
- **Binary rollback** from a future release to this one: refused only if a rule was given a
  condition the future release added. That rule would otherwise load without the condition.

## Left for the owner

- **Carrying `annotations` across a UI edit** (above).
- **The auth view's `warnings`.** `GET /api/authpolicy` adds a `warnings` array to each rule. Echoing
  it back on `PUT` was and is a `400`. Neither UI does. Documented in the OpenAPI text.
- **`culvert policy-check` on `{"version":N}` alone** still prints `OK — 0 rule(s) in a config
  backup`: a registered test pins "a backup need not carry a policy section". A document with none
  of the known keys exits 2.

## Evidence

`policy_unknown_field_test.go`. Each consequence test starts from `Block H` under default allow,
offers a ruleset in which an Allow above it is narrowed only by a key the build cannot honour,
through one door, and requires that the client is still blocked (`policyStore.Evaluate`), the rules
and version are unchanged, and the refusal names the rule and the key. Each door has a control in
which the correctly spelt ruleset is accepted through the same door and the Allow is scoped as
written: single rule, import (preview), policy file, rollback, pending draft, `applyConfigSnapshot`,
`fetchAndApply`. `applyDeltaReply` is covered for the refusal only. Negative controls are recorded
in the change's verification notes: each mechanism (fault recording, duplicates, the canonical
bound, zero-value decode, the duplicated list, the preflight locations, the last-good row, the
startup wording, the key pin, the struct size) fails its own test when disabled alone.
