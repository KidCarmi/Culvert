> **STATUS: PROPOSED — NOT ADOPTED.** This is an exploratory RFC for a possible cloud/AI/infra-ops direction. It is NOT an accepted architectural decision and is not ratified by merging the appliance support code. Adopting this direction requires a separate, explicitly-recorded architecture + security board decision.
>

# ADR-0036: AI receives normalized findings and approved excerpts by default, not raw bundles

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (to ratify)
- **Relates to:** ADR-0016 (raw vs normalized), ADR-0012 (cloud-first). Basis: `docs/support/TAC-CLOUD-ARCHITECTURE.md §6`.

## Context
AI-assisted diagnosis is a Tier-3 (cloud) capability. Feeding a raw support bundle to a model maximizes sensitive-data exposure and opens a prompt-injection channel (bundle-derived text is attacker-influenceable — a hostile hostname, log line, or config value). The framework must bound what the model sees and what its output can do.

## Decision
By default, the AI receives **normalized `Finding` records + evidence excerpts explicitly approved for reuse** (already appliance-redacted and re-checked during normalization) — **not** unrestricted raw bundle contents. Raw access is available only via audited, dual-control break-glass on the raw plane and never through the AI path. Bundle-derived text reaching the AI is treated as **untrusted data** (delimited/escaped, under a fixed system policy the model cannot be argued out of). AI outputs are **drafts for TAC approval**, never auto-sent to the customer, and — by the outbound-only invariant (ADR-0014) — have **no path to act on the appliance**. No training on customer data occurs without a separate, explicit contractual entitlement.

Enforced by cloud-side contract tests: AI job inputs are drawn from the findings plane, not the raw plane; a raw-bundle reference in an AI input is a hard error.

## Consequences
**Positive:** minimizes sensitive-data exposure to the model; contains prompt injection (untrusted-data handling + human approval + no action path); keeps AI value (diagnosis drafting) without raw exposure.
**Negative:** the AI cannot "see everything" by default — occasionally a case needs break-glass raw review (audited, rare).
**Neutral:** normalization must produce findings rich enough for useful AI drafting.

## Alternatives considered
- **Give AI the raw bundle for maximum context.** Rejected: maximal exposure + prompt-injection surface; findings + approved excerpts give most of the value at a fraction of the risk.
- **No AI at all.** Rejected: AI-assisted drafting is a core TAC accelerator; the risk is manageable with the normalized-input + approval-gate design.
