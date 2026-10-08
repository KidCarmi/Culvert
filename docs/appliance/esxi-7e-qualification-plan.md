# Independent ESXi qualification of 7e53720d

Candidate source: `7e53720d06f525f4e5fdbfec42f52840d5b734e2`.
Retained OVA SHA256: `578ea6b83b450b91bccc10ac80058db42d157e2161a45aa23fc8a23a2def7c65`.
Application image: `sha256:2a355d7a8930b12581c0f42c273bc3357cbefa36d9382ab7071d2c187dda0554`.
The intake report records the downloadable artifact and independent archive checks.
This plan is not a qualification result or merge/release approval.

## Controller and access

Reconcile the shared lifecycle at `442cb87420c2d9dc523a536afe5878e6d2bb5a9d`;
the provenance manifest enumerates the retained ESXi transport/hooks. Commit
all helpers before creating the detached controller. Freeze canonical runtime
bytes, scopes, runner, fonts and helper executables before any import. Do not
edit a running checkout. A failed stage remains on record; a continuation
requires specific evidence and a new frozen controller where code changes.

Use only the approved ESXi endpoint, one owned VM, 2 vCPU, 4 GiB RAM and 40 GiB
disk, with the existing resource reserves. The old cd8 VM was retired after
full-run DPAPI encryption, roundtrip/per-file verification and API identity
checks; both its VM and disk directory are absent. Retain the original OVA.
Use credential-free import, local PAM/password sudo, and read-only operator
SSH. No administrator SSH or fixture trust is added to the deliverable.

## Run order and oracles

1. Capacity/ownership preflight; import the exact retained OVA with the passive
   cold-boot observer armed before power-on. Capture branding, progress and
   initial-access display privately. Review frames before publishing any image.
2. Default bootstrap and operator enrollment; disposable signed registry;
   access-aware lifecycle, real restore, signed update/rollback and OS reboot.
   The lifecycle hooks already run failed static-network rollback before and
   after its reboot; do not dispatch those one-shot stages twice.
3. Independent image/state/CA/enforcement check. Install the bounded diagnostic
   sampler and export a validated encrypted backup plus encrypted history.
   Preserve archive passwords and CA/log/session recovery material separately
   in private escrow. Seed and record twelve uniquely identified log entries.
4. Three maintenance reboots, each against the unchanged **120-second** budget
   from accepted request to sustained healthy samples. Require actual allowed
   and denied proxy requests, ClamAV readiness, unchanged state and the first
   backup-list response. Correlate authenticated guest clocks/service/I/O data
   with controller observations and host storage metrics. First-install timing
   and deliberate slow-service fixture boots are separate. Preserve original
   timeouts and all previous candidate recovery failures.
5. ClamAV outage/recovery and isolated supported SAML browser qualification;
   verify HTTP and actual HTTPS CONNECT, identity/groups and denial. Restore
   touched configuration and remove fixture trust. Local OIDC remains blocked
   by production private-address restrictions; do not bypass them.
6. Visual service-delay/failure fixture outside normal recovery measurements;
   inspect diagnostics/menu/VT behavior, remove fixture and diagnostic sampler.
7. Identity baseline, authenticated reset, automatic power-off and fresh boot;
   require new console/OS/SSH identities, old-password and superseded-key
   refusals. Preserve the complete source run in verified encrypted custody.
8. Delete only the exact exported source and its disks, verify absence, import
   the same OVA as the sole fresh VM, bootstrap, restore using separately
   retained recovery material. Verify empty history before import, effective
   log-key rotation, live-lock and wrong-passphrase refusals, offline history
   import and exact twelve-record equality plus real enforcement.

## Closeout

Tie every verdict to OVA and frozen controller hashes in the existing #1528
status comment. Keep F-DISK-1's bounded nested-Docker evidence, ClamAV baked
versus adopted identities/scans, app/OS scanner dispositions, recovery-secret
custody, OIDC and any missing boot-console coverage explicit. Neither prior
candidate passes nor QEMU results transfer into an unrun ESXi check.
