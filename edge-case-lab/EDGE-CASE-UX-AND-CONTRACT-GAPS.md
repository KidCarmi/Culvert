# Culvert Edge-Case Lab — Configuration-Contract, UX & Observability Gaps

## Configuration-contract gaps

### SWG-0069 — Decryption profile certVerification=permissive
- **Requirement:** Use a named decryption profile with certVerification='permissive' to inspect 'app.corp.local' when the upstream presents an untrusted certificate.
- **Finding:** certVerification='permissive' is accepted but behaves like 'strict' (blocks untrusted upstream); its documented allow+log semantics are deferred/unimplemented (decryptprofile.go:71, decryptprofile_resolve.go:170). The named option does not deliver its stated contract.
- **Apply errors:** none — config accepted; divergence at enforcement
- **Evidence:** `scenarios/SWG-0069.json`, `evidence/SWG-0069/`

### SWG-0166 — Allow-all-with-social-media-carveout (category exception above broad permit)
- **Requirement:** Permit all egress but block the 'social-media' category via a higher-priority rule; verifies priority-0 category block wins over a priority-1 allow-all.
- **Finding:** The admin set the category-exception rule to priority 0 intending TOP precedence (a common '0 = highest' convention), but Culvert treats priority 0 as the Go zero-value 'unset' and silently auto-assigns it to the END (persisted as priority 2, BELOW the priority-1 allow-all). The config is accepted with NO warning, so the intended precedence is silently INVERTED and the exception never fires. Priority 0 is unusable as a top-priority value; the coercion is not surfaced. (The same layering works correctly with priorities >=1 — see the precedence family, which passes.)
- **Apply errors:** none — config accepted; divergence at enforcement
- **Evidence:** `scenarios/SWG-0166.json`, `evidence/SWG-0166/`

### SWG-0167 — Allow-all-with-news-carveout (category exception above broad permit)
- **Requirement:** Permit all egress but block the 'news' category via a higher-priority rule; verifies priority-0 category block wins over a priority-1 allow-all.
- **Finding:** The admin set the category-exception rule to priority 0 intending TOP precedence (a common '0 = highest' convention), but Culvert treats priority 0 as the Go zero-value 'unset' and silently auto-assigns it to the END (persisted as priority 2, BELOW the priority-1 allow-all). The config is accepted with NO warning, so the intended precedence is silently INVERTED and the exception never fires. Priority 0 is unusable as a top-priority value; the coercion is not surfaced. (The same layering works correctly with priorities >=1 — see the precedence family, which passes.)
- **Apply errors:** none — config accepted; divergence at enforcement
- **Evidence:** `scenarios/SWG-0167.json`, `evidence/SWG-0167/`

### SWG-0168 — Allow-all-with-streaming-carveout (category exception above broad permit)
- **Requirement:** Permit all egress but block the 'streaming' category via a higher-priority rule; verifies priority-0 category block wins over a priority-1 allow-all.
- **Finding:** The admin set the category-exception rule to priority 0 intending TOP precedence (a common '0 = highest' convention), but Culvert treats priority 0 as the Go zero-value 'unset' and silently auto-assigns it to the END (persisted as priority 2, BELOW the priority-1 allow-all). The config is accepted with NO warning, so the intended precedence is silently INVERTED and the exception never fires. Priority 0 is unusable as a top-priority value; the coercion is not surfaced. (The same layering works correctly with priorities >=1 — see the precedence family, which passes.)
- **Apply errors:** none — config accepted; divergence at enforcement
- **Evidence:** `scenarios/SWG-0168.json`, `evidence/SWG-0168/`

### SWG-0169 — Allow-all-with-webmail-carveout (category exception above broad permit)
- **Requirement:** Permit all egress but block the 'webmail' category via a higher-priority rule; verifies priority-0 category block wins over a priority-1 allow-all.
- **Finding:** The admin set the category-exception rule to priority 0 intending TOP precedence (a common '0 = highest' convention), but Culvert treats priority 0 as the Go zero-value 'unset' and silently auto-assigns it to the END (persisted as priority 2, BELOW the priority-1 allow-all). The config is accepted with NO warning, so the intended precedence is silently INVERTED and the exception never fires. Priority 0 is unusable as a top-priority value; the coercion is not surfaced. (The same layering works correctly with priorities >=1 — see the precedence family, which passes.)
- **Apply errors:** none — config accepted; divergence at enforcement
- **Evidence:** `scenarios/SWG-0169.json`, `evidence/SWG-0169/`

## UX / observability / documentation gaps

_No automated UX/observability/documentation gaps flagged. Note: decision-trace richness was strong (rule name + ULID + matched conditions on every enforcement), but the structured request-log API (`/api/logs`) is empty unless the log store is enabled — an operability observation worth surfacing in the UI defaults._
