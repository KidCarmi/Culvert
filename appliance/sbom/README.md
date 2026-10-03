# SBOM + CVE evidence

Produced by real tools against the pinned images — never hand-written. How to
regenerate, what each file is, coverage limits and the triage table live in
`docs/appliance/sbom-cve-evidence.md`. `evidence/tool-versions.txt` records the
tool versions and vulnerability-DB timestamp of the run; `evidence/summary.txt`
is the machine-generated count summary.

Regenerate (Docker socket needed; trivy's DB is fetched from the registry):

```bash
syft docker:ghcr.io/kidcarmi/culvert@sha256:<index-digest> -o cyclonedx-json > evidence/culvert-<ver>.cdx.json
trivy image --scanners vuln,secret --format json --output evidence/culvert-<ver>.trivy.json ghcr.io/kidcarmi/culvert@sha256:<index-digest>
trivy image --scanners vuln --format table --output evidence/culvert-<ver>.trivy.txt  ghcr.io/kidcarmi/culvert@sha256:<index-digest>
```

Guest-OS package inventory: `appliance/build/build-ova.sh` writes
`dpkg-list.txt` + `host-components.txt` next to the OVA; scan the disk with
`trivy vm --scanners vuln <disk.qcow2|vmdk>` or the package list with
`trivy fs` on a mounted copy (see the evidence doc for what was actually run).
