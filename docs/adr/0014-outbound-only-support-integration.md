# ADR-0014: Outbound-only support integration (TAC Cloud can never dial into Culvert)

- **Status:** Proposed (design recorded 2026-07-13; no code moved)
- **Date:** 2026-07-13
- **Deciders:** Principal Supportability Architect (proposed); project maintainer (to ratify)
- **Relates to:** ADR-0012 (cloud-first), ADR-0015 (cloud independence), ADR-0011 (export/consent). Basis: `docs/support/SECURE-UPLOAD-ARCHITECTURE.md`, `TAC-CLOUD-ARCHITECTURE.md`.

## Context
Culvert is an internet-adjacent, egress-critical security appliance in the customer's environment. Any inbound path from a vendor cloud is a direct attack surface into the customer network and a compliance non-starter. The maintenance-agent precedent already forbids inbound TCP (UDS + peercred only).

## Decision
**All support connections originate outbound from Culvert over authenticated HTTPS.** The TAC Cloud MUST NEVER be able to: initiate a connection into Culvert, run commands on Culvert, retrieve evidence without customer action or explicit local policy, modify configuration, affect traffic enforcement, access private keys or credentials, request arbitrary files, or bypass redaction. There is no inbound listener, port, or route for TAC. A cloud "please send a bundle for case X" request is expressed as a **policy the appliance polls for on its own outbound schedule**, and even then collection/redaction/consent gate locally before anything is produced or sent — the cloud can request, never compel.

Enforced by `TestNoInboundTACSurface` (no route/listener admits a TAC-initiated request) and the D0 route-count wall (no new inbound surface added).

## Consequences
**Positive:** a fully compromised TAC Cloud still cannot reach, command, reconfigure, or exfiltrate from an appliance — the containment is structural, not policy. Firewall posture stays "outbound HTTPS only."
**Negative:** TAC cannot pull fresh evidence on demand; it must wait for the appliance's next outbound poll + local consent (acceptable and safer).
**Neutral:** the upload protocol and any future remote-support session are both appliance-initiated.

## Alternatives considered
- **A cloud-initiated control channel (reverse tunnel) for convenience.** Rejected outright: it is precisely the inbound path this appliance must not have; it would let a cloud compromise reach the customer network.
- **A long-poll where the cloud holds the connection.** Still appliance-initiated (acceptable) but adds complexity; the simple outbound poll + upload is preferred for MVP.
