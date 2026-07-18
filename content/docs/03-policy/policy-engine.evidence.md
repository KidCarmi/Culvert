# Claim-Evidence Ledger — "Policy engine & Zero-Trust authoring"

Article: [`policy-engine.md`](policy-engine.md). Verified against repo revision
`ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| Rules evaluated in priority order, first match wins | src | `policy.go:1083` `Evaluate` (priority-sorted), first hit `:1140`, comment `:90` |
| Conditions within a rule are ANDed; empty = any | src | `PolicyRule` field comments `policy.go:93-109` ("empty = any") |
| Default-deny; fresh install passthrough | src | `proxy.go:19` `defaultPolicyActionAllow // 0 = deny (default)`; `setDefaultPolicyAction` |
| Action enum: `Allow`, `Drop`, `Block_Page`, `Redirect` | src | `policy.go:23-26` |
| SSL action: `Inspect`, `Bypass` | src | `policy.go:33-34` |
| Rule fields (sourceIP/identity/group, authSource, destFQDN, destCategory[Group], destCountry, schedule, sslAction, decryptionProfile, fileProfile, redirectURL, enabled) | src | `PolicyRule` struct `policy.go:91-135` |
| `destCountry` is a list of ISO 3166-1 alpha-2 codes | src | `policy.go` (`DestCountry []string` "ISO 3166-1 alpha-2") |
| GeoIP condition fail-closed on cache miss | src | `policy.go:1384-1389` ("rule does NOT match") |
| Schedule = days + `HH:MM` start/end + IANA timezone (empty = UTC) | src | `policy.go:214-219` (`PolicySchedule`) |
| Policy routes: `/api/policy` (GET/POST/DELETE), `/reorder`, `/move`, `/test`, `/draft(+commit/revert)` | src | `ui_policy.go:2148-2155` |
| RBAC: GET → viewer, POST/DELETE → operator | src | `ui_policy.go:39` (viewer), `:45,:51` (operator) |
| Draft/require-commit: enable = admin, commit/revert = operator | src | `ui_policy.go:2153-2155` (route comments) |
| Policy Tester dry-runs the live ruleset via the real eval path | src/test | `apiPolicyTest`, trace `ui_policy.go:1880`; `authpolicy_slice8_test.go:295` |
| Conflict detection (same priority, different action, overlap) | src | `policy.go:877` `DetectConflicts` |
| Per-rule hit counters exported to Prometheus, capped at 200 | src | `PolicyRule.HitCount`; `metrics.go:332` (`culvert_policy_rule_hits_total`, "capped at 200 rules") |
| `tlsSkipVerify` disables upstream cert verification per rule | src | `PolicyRule.TLSSkipVerify` (`policy.go`, comment "use with caution") |

## Notes

- The overview's "8 condition types" maps to fields 1–8 above; `destCategory`
  and `destCategoryGroup` are two forms of the single URL-category condition
  type (the engine resolves group membership to categories).
- The `decryptionProfile` field binds a Decryption Profile that governs *how* an
  `Inspect` rule decrypts (HTTP/2, cert verification, TLS floor/cap); covered in
  the TLS inspection article.
