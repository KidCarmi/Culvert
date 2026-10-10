# Candidate input equivalence: `72c827b7f59f` → `bad788e54ffe`

9 files differ; **5 are build inputs**.

No changed build input means a rebuild would consume the same source inputs. It is NOT a byte-identity claim (VCS stamp, commit-named OVA, build-time GeoLite/apt fetches). The qualified OVA is evidence for its own hash only.

| file | build input | reason |
|---|---|---|
| `docs/appliance/readiness-report.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/appliance/sbom-cve-evidence.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `docs/appliance/scanning-outage-posture.md` | no | .dockerignore *.md; not embedded, not copied by any stage |
| `internal/hashcache/hashcache.go` | **YES** | Go source compiled into culvert/culvert-maint (non-test) |
| `internal/secscan/clam_quarantine.go` | **YES** | Go source compiled into culvert/culvert-maint (non-test) |
| `internal/secscan/clam_quarantine_cache_test.go` | no | .dockerignore *_test.go; never compiled into a shipped binary |
| `internal/secscan/secscan.go` | **YES** | Go source compiled into culvert/culvert-maint (non-test) |
| `metrics.go` | **YES** | Go source compiled into culvert/culvert-maint (non-test) |
| `security_scan.go` | **YES** | Go source compiled into culvert/culvert-maint (non-test) |
