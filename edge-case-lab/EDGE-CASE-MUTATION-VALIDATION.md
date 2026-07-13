# Culvert Edge-Case Lab — Mutation Validation

**Purpose.** Prove the lab actually detects real enforcement regressions (not just green-on-correct).
Eight controlled mutations were applied to Culvert **in an isolated git worktree** (`/tmp/mut-tree`,
built there, never pushed), each scenario subset run against the mutated binary via
`CULVERT_LAB_BIN`, and the worktree restored (`git checkout`) after every mutation. The main tree
was never modified. **No product mutation was committed or pushed.**

Harness: `subset_run.py` (runs a capability subset against `CULVERT_LAB_BIN`, fresh `/data`+restart
per scenario). Orchestrators: `/tmp/mutrun.sh` (all 8) + a detail pass for the partial ones.

## Results

| # | Mutation (injected fault) | Site | Subset (cap) | Flipped | Detected? |
|---|---|---|---|---|---|
| M1 | First-match → last-match (reverse priority sort) | `policy.go` sortLocked `<`→`>` | rule_ordering (8) | 4/8 | **YES** (overlapping-precedence scenarios) |
| M2 | TLS-inspected file blocking skipped | `proxy_tunnel.go` `inspectFileBlocked` → `return false` | file_type_mime (2) | 2/2 | **YES** |
| M3 | Tenant/source identity ignored | `policy.go` `matchSourceAddr` → `return true` | source_ip_subnet (8) | 8/8 | **YES** |
| M4 | Policy persistence disabled | `policy.go` `Save()` → no-op | config_persistence (2) | 1/2 | **NO — ESCAPED** |
| M5 | Threat-intel/blocklist bypassed | `proxy.go` `if false && bl.IsBlocked` | threat_intel (4) | 4/4 | **YES** |
| M6 | Schedule evaluation inverted | `policy.go` `matchSchedule` wrapper `!impl` | schedule_time (6) | 6/6 | **YES** |
| M7 | Default deny → allow | `proxy.go` `if true || defaultPolicyAction()=="allow"` | default_deny (8) | 4/8 | **YES** (exact-allowlist scenarios) |
| M8 | Manual SSL bypass list ignored | `proxy.go` `if false && … sslBypass.Matches` | manual_ssl_bypass (6) | 1/6 | **YES** (list-override scenario) |

**Mutation detection rate: 7 / 8 (87.5%).** One escape (M4). Restoration verified clean after
each mutation (`git status` empty; worktree `git status --short` empty at end).

## Detail & honesty notes (why partial ≠ escape, and where it IS an escape)

**M1 (4/8) — detected, partial is expected.** The 4 detectors (SWG-0007/0008/0057/0058) are the
2-rule scenarios with **overlapping** matches, where reversing the sort flips the first-match
winner (e.g. `permit app` above `block *.corp.local` → app blocked). The non-detectors are:
- SWG-0059 three-tier — each host matches **exactly one** rule, so order is irrelevant (the
  scenario doesn't actually exercise precedence between overlapping rules).
- SWG-0166–0168 carve-outs — confounded by the priority-0 issue (already CONFIG_CONTRACT_GAP),
  so not reliable precedence detectors.
→ **Finding:** precedence coverage rests on only ~4 clean scenarios; add explicit overlapping
  3-rule precedence cases with a deterministic winner.

**M4 (persistence) — TRUE ESCAPE.** SWG-0124 is classified CONFIGURATION_CONTRACT_GAP **with or
without** the mutation, because the lab runs the bare binary **without `-policy`**, so `Save()` is
already a no-op and there is nothing for the mutation to break. The lab **does not validate policy
persistence enforcement at all.** Required new coverage: run a persistence scenario **with**
`-policy /data/policy.json` and assert rules survive restart (and a mutation that breaks `Save()`
must flip it). This is the most important escaped fault.

**M7 (4/8) — detected; exposes a scenario-quality defect.** Detectors (SWG-0009/0036/0038/0040)
use an **exact** allow-list, so the negative vector (`media.corp.local`) genuinely hits default-deny
and flips to allow under the mutation. Non-detectors (SWG-0037/0039/0041) use a **wildcard**
allow-list `*.corp.local`, which **accidentally covers** the intended "deny-other" host
`media.corp.local` — so that vector is permitted by the rule, never reaching default-deny.
→ **Finding:** the wildcard-allow-list scenarios have a weak negative vector; their "denied"
  probe must target a host **outside** the permit's wildcard (e.g. `example.test`).

**M8 (1/6) — detected; narrow blast radius by design.** Only SWG-0011 exercises the explicit
**ssl-bypass list**; the other five use rule-level `sslAction: bypass`, a **different code path**
(`resolveSSLAction` base branch) that M8 does not touch. Detection is correct for the mutated
mechanism, but reveals the lab has **only one** scenario for the manual ssl-bypass *list* override.
→ **Finding:** add ≥2 more ssl-bypass-list scenarios (wildcard patterns, precedence vs inspect).

**M2, M3, M5, M6 — clean full detection (2/2, 8/8, 4/4, 6/6)**, latency 1 (the first matching
scenario in each subset flips). These capabilities are well-covered.

## Detection latency
The lab is a batch runner, not a streaming detector; "latency" = scenarios executed before the
first flip. For M2/M3/M5/M6 the first scenario in the subset already flips (latency = 1). For
M1/M7 the first flip occurs within the first two scenarios. There is no long-tail detection delay;
the risk is **coverage** (escapes), not latency.

## Required new scenarios / assertions (from this exercise)
1. **Persistence-with-`-policy`** scenario (closes the M4 escape) — highest priority.
2. Overlapping **3-rule precedence** scenarios with a unique deterministic winner (strengthen M1).
3. Fix wildcard-allow-list **negative vectors** to target a host outside the permit (strengthen M7).
4. Additional **ssl-bypass-list** scenarios (strengthen M8).
5. A **default-deny mutation** case included in the PR smoke suite (M7 is a security-critical fault
   that must always be caught fast).

## Verdict of mutation validation
The lab **reliably detects** first-match, TLS file-blocking, source/tenant matching, threat-intel,
schedule, default-deny, and ssl-bypass-list regressions. It **does not** currently detect a policy
**persistence** regression (harness runs without `-policy`), and several capabilities rest on a
thin set of behaviorally-distinct scenarios. These are addressable with the five additions above;
until #1 lands, "persistence" must not be claimed as a validated capability.
