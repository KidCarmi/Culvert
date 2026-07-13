# Culvert Edge-Case Lab — Suite Tiers

Runner: `edge-case-lab/harness/suite_tiers.py {smoke|nightly|full}` (+ `run_campaign.py` for
full/release). Raw scenario count is **never** the gate metric — the canonical behavior count is.

## Tier overview

| Tier | Command | Scope | Blocking | Measured runtime | Resource |
|---|---|---|---|---|---|
| **PR smoke** | `suite_tiers.py smoke` | 14 curated deterministic scenarios + 22 harness self-tests | **Yes** | **~25 s** scenarios + ~15 s self-tests (**~40 s total**) | 1 vCPU, single serial Culvert; <300 MB |
| **Nightly canonical** | `suite_tiers.py nightly` | one representative per **canonical behavior** (49) | Advisory (opens issues) | ~2–3 min | 1 vCPU serial; <300 MB |
| **Full campaign** | `run_campaign.py --per 30` | all **215** generated scenarios + retriage + reports | Advisory | ~20–30 min (per-scenario fresh restart) | 1 vCPU serial; disk for evidence (~13 MB/run) |
| **Release certification** | `run_campaign.py` + `canonical.py` + mutation gate | canonical + a freshly generated campaign + **8/8 mutation floor** + SSRF guard test | **Yes** (release blocker) | ~30–40 min | 1 vCPU; worktree for mutations (~1 GB transient) |

Serial execution is a design constraint (Culvert hardcodes `dataDir=/data`; the harness runs one
proxy at a time with proven port ownership). Parallelism would require containerized isolation.

## PR smoke — the 14 curated scenarios (highest-risk contracts)

| ID | Contract |
|---|---|
| SWG-0007 | First-match precedence (specific permit above broad block) |
| SWG-0009 | Default deny (Zero Trust) |
| SWG-0006 | Source / tenant isolation (corp subnet only) |
| SWG-0121 | Multi-tenant isolation (no cross-tenant leakage) |
| SWG-0010 | TLS inspection (inspect + bypass, MITM proof) |
| SWG-0011 | Manual SSL-bypass **list** override |
| SWG-0074 | File blocking under TLS inspection (.exe) |
| SWG-0013 | Threat-intelligence / blocklist pre-emption |
| SWG-0019 | Schedule evaluation (active window) |
| SWG-0124 | **Durable policy restart** (persistence + post-restart enforcement trace) |
| SWG-0023 | Authentication boundary (407 challenge) |
| SWG-0122 | Decision-trace attribution (blocked request carries a rule-attributed trace) |
| SWG-0004 | URL category |
| SWG-0017 | Wildcard boundary (no over-match) |

Plus the harness self-tests (`test_harness.py`), which cover the two contracts that are **not**
normal PASS scenarios:
- **Upstream failure vs policy block** (`upstream.not_policy_block`): a policy-allowed request to a
  dead upstream must attribute to upstream/fixture failure, never a policy block.
- **Attribution invariants** (`attr.*`): a BLOCK disposition requires an authoritative Culvert
  marker; a bare 403 with no marker is `unattributed_blockish`, never a confirmed policy block.
- **Process ownership / zombie regression** (`ownership.*`, `zombie.*`): refuses to start over an
  unmanaged port owner; reaps a stray proxy and comes up clean (reproduces the T4 defect).

A smoke run FAILS the gate only on an unexpected `PRODUCT_BUG`/`TEST_INFRA_FAILURE` on a
should-pass scenario, or any self-test failure. Legitimate findings (e.g. SOCKS5 `SECURITY_BYPASS`)
are **not** in the smoke set.

## Nightly canonical
Runs `EDGE-CASE-SCENARIO-MAPPING.json`'s `canonical_representative` scenarios (one per behavior).
Asserts the mutation-detection floor (≥7/8, target 8/8) via the release job. Opens an issue on any
new non-PASS vs the committed baseline; does not block PRs.

## Full campaign
The complete 215-scenario generated sweep — a discovery/coverage instrument, not a gate. Produces
the machine-readable results + coverage reports and (in CI) uploads the evidence bundle as an
artifact.

## Release certification
Full campaign + canonical + the 8-mutation gate (`/tmp/mutgate.sh` equivalent) + the SSRF-guard Go
test, run against the release image digest. Blocks the release on: any unresolved
`SECURITY_BYPASS`/`PRODUCT_BUG` regression vs the last release baseline, or a mutation-detection
drop below 8/8. Preserves an immutable summary (attached to the GitHub Release).
