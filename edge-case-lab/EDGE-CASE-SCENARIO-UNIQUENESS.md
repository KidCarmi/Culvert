# Culvert Edge-Case Lab — Scenario Uniqueness & Behavioral Coverage

- **Raw accepted scenarios:** 215
- **Distinct behavioral fingerprints (effective unique coverage):** 51
- **Behavioral-collapse ratio:** 215/51 = **4.2× parametric multiplier** (24% of scenarios are behaviorally distinct)
- **Total test vectors:** 405  (positive/allow: 194, negative/block: 211)
- **Protocol diversity (vectors):** http=314, https=89, socks5=2
- **Source-class diversity:** ['corp', 'other'] (infra limit: only 2 locally-bindable client source IPs)
- **Action diversity (rules):** allow=103, block_page=112, drop=7, redirect=7

## Interpretation

The raw count of 215 is a PARAMETRIC EXPANSION over ~51 distinct enforcement behaviors. Blocking `news.example.test` vs `media.corp.local` by exact FQDN is the SAME code path with a different string; such families inflate the count but not the behavioral coverage. The honest coverage metric is the **distinct-behavior count**. This is adequate for a broad regression sweep but should NOT be reported as '215 independent tests'.

## Largest superficial-variation clusters (same behavior, many scenarios)

| Count | Behavior (normalized) | Example IDs |
|---|---|---|
| 17 | default=allow, rules=[fqdn->allow/inspect], precedence=False | SWG-0060, SWG-0062, SWG-0064 … |
| 15 | default=allow, rules=[fqdn->block_page], precedence=False | SWG-0001, SWG-0002, SWG-0003 … |
| 13 | default=deny, rules=[fqdn+src_ip->allow], precedence=False | SWG-0049, SWG-0051, SWG-0053 … |
| 13 | default=allow, rules=[fqdn+src_ip->block_page], precedence=False | SWG-0050, SWG-0052, SWG-0054 … |
| 11 | default=allow, rules=[fqdn->block_page], precedence=False | SWG-0031, SWG-0032, SWG-0170 … |
| 11 | default=allow, rules=[fqdn->block_page], precedence=False | SWG-0017, SWG-0024, SWG-0025 … |
| 9 | default=deny, rules=[fqdn->allow/inspect], precedence=False | SWG-0196, SWG-0197, SWG-0198 … |
| 9 | default=deny, rules=[fqdn->allow], precedence=False | SWG-0036, SWG-0038, SWG-0040 … |
| 7 | default=allow, rules=[fqdn->redirect], precedence=False | SWG-0014, SWG-0076, SWG-0077 … |
| 7 | default=allow, rules=[fqdn->drop], precedence=False | SWG-0015, SWG-0078, SWG-0079 … |
| 7 | default=allow, rules=[fqdn->block_page], precedence=False | SWG-0094, SWG-0095, SWG-0096 … |
| 7 | default=allow, rules=[fqdn->block_page], precedence=False | SWG-0018, SWG-0091, SWG-0092 … |
| 6 | default=deny, rules=[fqdn->allow; fqdn->block_page], precedence=True | SWG-0007, SWG-0057, SWG-0123 … |
| 6 | default=allow, rules=[fqdn->allow/inspect], precedence=False | SWG-0068, SWG-0069, SWG-0111 … |
| 6 | default=allow, rules=[fqdn->allow/bypass], precedence=False | SWG-0061, SWG-0063, SWG-0065 … |

## Coverage gaps revealed by normalization

- **Tenant diversity: LOW.** Only 2 source classes (corp `192.0.2.0/24` / other `127.0.0.0/8`); true multi-tenant matrices (N tenants, overlapping destinations) are under-covered.
- **Negative/boundary vectors present but thin** in some families (e.g. schedule has one active + one inactive; few over-match negative probes per wildcard).
- **Identity/group behavior: NONE** (no IdP; source-IP is the only 'identity' axis).
- **Failure-mode diversity: MODERATE** — cert-fail-closed, drop, conn-fail covered; auth-timeout, IdP-down, CP-down, partial-download NOT behaviorally exercised.
- **Protocol diversity: GOOD for http/https, THIN for socks5 (2), none for raw WebSocket frame assertions.**
