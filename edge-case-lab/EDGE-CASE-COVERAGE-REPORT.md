# Culvert Edge-Case Lab — Coverage Report

Accepted scenarios: **215** · Executed: **215** · Unique fingerprints: **215** · Duplicate rejection rate: **0.9%**.

## Coverage by capability tag

| Capability | Scenarios | PASS | Other classes |
|---|---|---|---|
| http | 158 | 151 | CONFIGURATION_CONTRACT_GAP:6, TEST_INFRA_FAILURE:1 |
| rule_first_match | 111 | 104 | CONFIGURATION_CONTRACT_GAP:4, TEST_INFRA_FAILURE:1, MISSING_CAPABILITY:2 |
| https_connect | 90 | 89 | CONFIGURATION_CONTRACT_GAP:1 |
| url_domain_objects | 62 | 62 | — |
| default_deny | 46 | 45 | TEST_INFRA_FAILURE:1 |
| tls_inspection | 43 | 42 | CONFIGURATION_CONTRACT_GAP:1 |
| source_ip_subnet | 38 | 38 | — |
| url_categories | 27 | 22 | CONFIGURATION_CONTRACT_GAP:4, TEST_INFRA_FAILURE:1 |
| rule_ordering | 10 | 6 | CONFIGURATION_CONTRACT_GAP:4 |
| schedule_time | 10 | 10 | — |
| manual_ssl_bypass | 8 | 8 | — |
| redirect | 7 | 6 | CONFIGURATION_CONTRACT_GAP:1 |
| drop | 7 | 7 | — |
| upload_download | 6 | 6 | — |
| decryption_profile | 6 | 5 | CONFIGURATION_CONTRACT_GAP:1 |
| limitation_record | 5 | 0 | EXPECTED_LIMITATION:5 |
| category_groups | 4 | 4 | — |
| threat_intel | 4 | 4 | — |
| blocklist | 4 | 4 | — |
| streaming_chunked | 4 | 4 | — |
| large_files | 4 | 4 | — |
| cert_validation | 3 | 2 | CONFIGURATION_CONTRACT_GAP:1 |
| rule_lifecycle | 3 | 3 | — |
| redirect_chains | 3 | 3 | — |
| file_type_mime | 2 | 2 | — |
| config_persistence | 2 | 1 | CONFIGURATION_CONTRACT_GAP:1 |
| security | 2 | 0 | EXPECTED_LIMITATION:1, CONFIGURATION_CONTRACT_GAP:1 |
| socks5 | 2 | 0 | MISSING_CAPABILITY:2 |
| authorization_policy | 2 | 0 | MISSING_CAPABILITY:2 |
| auth_policy | 1 | 1 | — |
| multi_tenant | 1 | 1 | — |
| observability | 1 | 1 | — |
| decision_trace | 1 | 1 | — |
| logging | 1 | 1 | — |
| concurrency | 1 | 1 | — |
| data_plane_restart | 1 | 0 | CONFIGURATION_CONTRACT_GAP:1 |
| geoip_country | 1 | 0 | EXPECTED_LIMITATION:1 |
| ipv6 | 1 | 0 | EXPECTED_LIMITATION:1 |
| dns_rebinding | 1 | 0 | EXPECTED_LIMITATION:1 |
| websocket | 1 | 0 | EXPECTED_LIMITATION:1 |
| partial_content | 1 | 0 | EXPECTED_LIMITATION:1 |
| header_scrub | 1 | 1 | — |
| identity | 1 | 1 | — |
| object_lifecycle | 1 | 1 | — |
| policy_conflict | 1 | 1 | — |

## Novelty / duplicate

- Candidate scenarios generated: 217
- Rejected as semantic duplicates: 2 (0.9%)
- Accepted (unique fingerprints): 215
- Every accepted scenario carries a distinct 16-hex semantic fingerprint over identity+source+destination+schedule+auth+TLS+content-control+failure+action.
