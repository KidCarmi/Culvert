# ADR Proposal: MCP subsystem trust boundaries — SUPERSEDED

> **This proposal has been promoted.** The authoritative decision record is now the numbered repository
> ADR **[`docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md)**.
> This file is retained only as a non-authoritative pointer so existing links do not break. **Do not edit
> the decision content here** — make all trust-boundary and PR-1-entry-decision changes in ADR-0024.

- **Status:** Superseded by ADR-0024 (2026-07-24).
- **What moved:** the Option-B six-section proposal that previously lived here — including the eight
  trust-boundary constraints and the separation doctrine — was promoted verbatim (with the five closed
  PR-1 entry decisions D-2, D-5, D-8, D-9, D-13 added) into ADR-0024.
- **Current ADR status:** ADR-0024 is `Proposed`, awaiting formal ratification by the Architecture Review
  Board and Security Architecture. It becomes the accepted PR-1 entry-gate ADR only once that ratification
  is recorded in the ADR's "Ratification" section.

## Why this pointer exists

Per [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) D-0 (Option B), PR-0 was confined to `docs/design/mcp/`, so
the trust-boundary ADR was first authored here as a proposal. Promotion to a numbered ADR under
`docs/adr/` was the human-controlled PR-1 entry step. That promotion has now occurred (ADR-0024). To avoid
two competing authoritative records (a repository invariant — see ADR-0001 supersession practice), the
decision content is kept in exactly one place: **ADR-0024**.

## Where to look now

- **Trust-boundary decisions + D-2/D-5/D-8/D-9/D-13 closures:** [`ADR-0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md).
- **Decision lifecycle / closure records:** [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md).
- **PR-1 entry gate:** [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md) and ADR-0024 "PR-1 entry gate".
