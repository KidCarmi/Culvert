# Culvert Language & Terminology Governance Review — 2026-11-06

> **Status:** Point-in-time review. **Window:** `0022e1c..b05d649` (CHAOS-111 cluster rate-limit gossip bounds,
> blocklist-feed diagnostic, CA certificate-cache work, vendored SAML fork GO-2026-6909, scanner in-flight cost).

## Executive Summary

No production-worthy terminology improvements were identified. Terminology Health Score: 93/100 (unchanged).

## What was checked

- **CHAOS-111 gossip bounds:** API fields `hot_ips_per_node_bound`, `hot_ips_broadcast_bound`,
  `hot_ips_omitted_{export,ingest,broadcast,total}`, metrics `culvert_cluster_ratelimit_hot_ips_omitted[_total]{leg}`,
  GUI cards "Hot IPs Omitted (now/total)" and the banner "Hot-IP set exceeds the gossip bounds" all use one
  vocabulary (*hot IP*, *omitted*, *bound*, and the three legs *export / ingest / broadcast*) across API, OpenAPI,
  metrics HELP, GUI, logs and comments. "Omitted" is used consistently and always paired with the statement that
  the IP keeps its local rate limit, so it does not collide with the `rejected`/`blocked`/`refused` verbs (T-70).
  The "now" gauge versus "total" counter split matches the existing `remote_counts_*` pair.
- **Control Plane / Data Plane:** GUI and HELP text spell out "Control Plane" per the glossary; "CP" is not introduced.
- **Blocklist-feed diagnostic, CA certificate cache, SAML fork, scanner in-flight:** no new operator-facing names.

## Candidates considered and rejected

- Internal Go names (`maxGossipHotIPsPerNode`, `maxExportedHotIPs`, `maxBroadcastHotIPs`) differ in verb for the same
  bound at different legs. They are unexported, document each other in comments, and surface to operators only through
  the unified `hot_ips_*` fields; renaming would be cosmetic.
- `hot_ips_per_node_bound` is reported for both export and ingest; it is one number (`maxGossipHotIPsPerNode ==
  maxExportedHotIPs`) and one concept, so a single field is correct.
- "Hot IP" has no glossary row. It is a narrow, self-explaining term confined to the cluster rate-limit panel and
  its HELP text; adding a row would not change any operator-visible name, so it is deferred until a second surface uses it.

## Priority

Critical none · High none · Medium none · Low none.

No identifiers, wire fields, metrics or GUI labels were changed.
