# Culvert Edge-Case Lab — Mutation Validation

**Purpose.** Prove the lab detects real enforcement regressions. Eight controlled mutations are
applied to Culvert **in a throwaway git worktree** (built there, never pushed), each mapped to
specific deterministic scenarios that must FLIP to non-PASS to count as detected. The worktree is
restored (`git checkout`) after every mutation and removed at the end. **No product mutation is
committed or pushed.**

Harness: `subset_run.py` (runs specified scenario ids against `CULVERT_LAB_BIN`, fresh `/data` +
proven-ownership restart per scenario). Gate orchestrator: `/tmp/mutgate.sh`. Machine-readable
result: `reports/mutation-gate.jsonl`.

## Acceptance gate — 8 / 8 DETECTED

| # | Mutation (injected fault) | Site | Detecting scenarios | Non-PASS |
|---|---|---|---|---|
| M1 | First-match → last-match (reverse priority sort) | `policy.go` sortLocked `<`→`>` | SWG-0007, SWG-0057 | 2 |
| M2 | TLS-inspected file blocking skipped | `proxy_tunnel.go inspectFileBlocked`→`return false` | SWG-0074, SWG-0075 | 2 |
| M3 | Tenant/source identity ignored | `policy.go matchSourceAddr`→`return true` | SWG-0006, SWG-0121 | 2 |
| M4 | **Policy persistence disabled** | `policy.go Save()`→no-op | **SWG-0124** | 1 |
| M5 | Threat-intel/blocklist bypassed | `proxy.go if false && bl.IsBlocked` | SWG-0013, SWG-0088 | 2 |
| M6 | Schedule evaluation inverted | `policy.go matchSchedule` wrapper `!impl` | SWG-0019, SWG-0020 | 2 |
| M7 | Default deny → allow | `proxy.go if true \|\| defaultPolicyAction()` | SWG-0009, SWG-0037 | 2 |
| M8 | Manual SSL-bypass list ignored | `proxy.go if false && … sslBypass.Matches` | SWG-0011 | 1 |

**Every mutation is detected by ≥1 mapped scenario. Detection rate: 8 / 8.** Clean-tree restoration
verified after each mutation; the throwaway worktree was removed; no `//MUT` markers remain in the
main tree.

## What changed since the 7/8 baseline (adversarial-review phase)

The prior mutation validation caught **7/8**; **M4 (persistence) escaped** and M7/M8 rested on thin
or misleading scenarios. The hardening phase closed these:

- **M4 now detected.** The harness runs Culvert with the shipped `-policy /data/policy.json` durable
  store (R1), and SWG-0124 restarts the proxy without wiping `/data` and asserts **post-restart
  enforcement** via the decision trace (`POLICY_ALLOW` for the surviving rule, `POLICY_DEFAULT_DENY`
  for the unmatched host). Disabling `Save()` now flips SWG-0124 → detected.
- **M7 strengthened.** The wildcard-allow-list scenarios (SWG-0037/0039/0041) had a negative vector
  (`media.corp.local`) accidentally *inside* the `*.corp.local` permit, so `default→allow` did not
  change them. Fixed to target `example.test` (outside the permit); SWG-0037 now detects M7. The
  carve-out scenario SWG-0127 had its exception below the broad permit (shadowed); the exception was
  moved above it. (R4 weak-negative fixes.)
- **M8 kept honest.** M8 breaks only the ssl-bypass **list** override; SWG-0011 (the list scenario)
  detects it. Rule-level `sslAction: bypass` is a separate path (SWG-0010/0061…) intentionally not
  in M8's blast radius; the mapping reflects this.

## Latency & scope
The lab is a batch runner; "latency" = scenarios executed before the first flip. Every mapped
mutation flips within the first one or two scenarios of its subset (latency ≤ 2). The residual risk
is coverage (addressed by the direct per-mutation mapping above), not latency.

## Standing gate
The 8/8 floor is asserted in **release certification** (and run nightly). A drop below 8/8 blocks the
release and opens an issue — the lab now guards its own regression surface.
