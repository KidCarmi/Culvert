# 2e3 replacement ESXi controller

This controller admits the exact replacement candidate as a new run. Offline
checks below prepare the harness; they do not qualify the appliance or turn the
superseded d698 measurements into replacement-candidate evidence.

## Exact inputs

- Product: `2e3bcc2a1095f3e26e4f0b73a6a5515bdd069ee2`
- OVA SHA256: `55e98116ba2c020789b3f5de4eabab7e29af611c83b9c972b82a6319a19f145e`
- App image: `sha256:536403fc9ba8a4bc15d229a12a7586ce6ccc35ba99148b71869a81596e0ea940`
- Baked ClamAV image: `sha256:f3fcbf45d0a50da7e1880e498a030e38b1cd31d792a2737a881ebe8391b13ec3`
- ClamAV ref: `culvert/clamav:1.4.6-pcre2-10.49`
- Network helper Git-blob SHA256: `4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6`
- Identity-reset helper Git-blob SHA256: `602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391`

The sidecar identity comes from the replacement build-info in evidence artifact
11477120696; it differs from the d698 derivative despite the same tag. Source,
OVA and app image must match as a complete tuple. b579 and d698 profiles remain
unchanged. P1 guest payloads embed the selected, reviewed network/reset hashes.
No earlier candidate's post-OS continuation or initrd experiment is authorized
for this source.

The network helper was inspected directly from this product revision: it waits
for a default route before claiming DHCP rollback restored connectivity. Its
failure injection and existing immediate exact-network assertion remain active.
The controller does not add a delay to hide an unsuccessful product rollback.

## Shared harness provenance

Shared upstream is `e96895c4b5ba4e4254f92d89038a57023daf365b`.
The three copied shared library files are byte-identical to upstream 5cae; the
intervening changes affect workflow candidate selection and the separate F-DISK
harness. Existing documented ESXi hooks and the Windows AF_UNIX guard are the
only local shared-library deltas. `shared-harness-provenance.json` records their
hashes. The final freeze records actual runtime bytes.

Both real release-proof-fixture sources were read from exact 2e3 Git blobs and
match their existing pinned hashes. Registry preparation selects this source
explicitly; manual fixture generation must pass `--source-revision` with the
full 2e3 revision. No fake verifier or substituted signing path is introduced.

## Execution order after the separate freeze

Use a new scope/run directory and retain the OVA before boot. Keep the one-VM
limit and verify any preceding VM's escrow/deletion independently.

1. `esxi-lab.py --scope SCOPE up`; bootstrap via `access-aware-bootstrap.py`, then
   enroll/pin `culvert-operator` using `operator-enroll.py`. Use approved fonts.
2. Prepare signed evidence with `prepare-lab-registry.py --scope SCOPE --bind IP`.
   Install the lab-only boot sampler using the existing frozen sampler controller
   after the main lifecycle and before the three measured reboots; retain its
   source/owner/install receipts. The first lifecycle reboot has separate existing
   console/timing observations, without the sampler.
3. Run `candidate-run.ps1` with the new scope, bind address, Python and approved
   font list. Do not pass `-ResumePostOS` or `-ContinueUndispatched`. This performs
   the complete setup/auth/custody/actual-restore/signed-update/OS lifecycle.
4. Run the three independent maintenance cycles using the existing production
   dispatch, probe and evidence-controller commands and unique cycle IDs. They
   retain the 120s budget, three consecutive samples, direct PONG/current-container
   binding and one fresh-session first-ready backup listing bounded to 5s.
5. Run `qualify-clamav-outage.py --scope SCOPE --bind IP --attempt initial`.
   Do not supply `--prior-failure-sha256`. The controller refuses any existing
   `clamav-outage*` evidence in this fresh run; failures require review, not retry.
6. Use `fresh-recovery.py export` into private external encrypted escrow, then
   the existing P1 identity-before/reset/power-on/bootstrap/after sequence and
   `prepare-identity-reset.py` readiness guard. Delete only through verified
   `delete-exported-source.py`, import the exact retained OVA into a fresh owned
   VM, and run `fresh-recovery.py restore` with the deletion ledger/receipt.
7. Collect reviewed evidence, including independent current-boot persistence
   checks and exact artifact identities, before the explicit owned-VM cleanup.

The fresh ClamAV test retains the corrected descriptor-relative, no-follow,
inode-checked maintenance locks and the dedicated daemon-owned directory guard.
It embeds the selected exact app/sidecar identities into the guest payload and
requires matching returned identities. It still tests unique clean/EICAR bodies,
closed behavior/readiness during outage and guarded sidecar/policy restoration.
The d698 continuation separately continues to require its original failure hash;
a fresh 2e3 run cannot use that history to bypass its first attempt.

All privileged operations remain authenticated local-console operations.
Operator SSH retains its read-only forced command and exact host-key pin.
Credentials, console captures, fixture trust and escrow stay private. Product
F-DISK/scanner/ClamAV disposition comes from actual replacement-run evidence.

## Offline validation

The complete ESXi unittest suite passed 303 tests with two environment skips,
including cross-profile recovery guards, fresh initial ClamAV admission/refusal
and actual generated guest-payload identity selection. Both approved fonts were
provided. Shared/adapter Bash syntax, launcher PowerShell parsing, exact product
blob hashes and real signed-fixture source verification passed. No VM calls were
made during reconciliation.

## Registry preparation firstboot precondition continuation

The initial 0da controller imported and authenticated the replacement before
firstboot had finished. Its registry script returned the exact `first boot
incomplete` exception before acquiring locks or creating registry paths, trust or
containers. This failed attempt remains unchanged. An authenticated read-only
observation subsequently recorded complete.done, the same product and absence of
registry paths and fixture containers.

A separate controller can run only this proven precondition continuation:

```powershell
python test/e2e/appliance/esxi/prepare-lab-registry.py --scope NEW_SCOPE --bind CONTROLLER_IP --resume-firstboot-incomplete --original-controller-root D:/AI/Culvert-esxi-2e3-controller
```

The new scope points to the original owned run directory but its own new freeze
manifest. `--original-controller-root` is required only for this continuation.
The helper verifies the original 0da freeze, exact helper/payload/failure hashes,
blocked marker and owned UUID, and unique authenticated results for both the
failure and `.tools/private-operations/firstboot-registry-observation.out` in that
original checkout. There is no general failed-operation retry flag.

The separate `registry-preparation-firstboot-continuation-*` records preserve the
original marker and transport. A read-only authenticated wait checks product,
boot and absence of registry state, waits at most 900s for completion, then checks
again before the unchanged registry payload can run. A missing/duplicate result,
changed boot/source, changed original evidence or failed wait blocks mutation.
The new continuation marker is exclusive even after wait failure; no automatic
retry follows. Normal fresh registry preparation also waits before dispatch.

The registry trust/dispatch receipts record the preparation controller and helper
hash, its provisioning observation and original-failure binding. After successful
preparation, lifecycle and the three measured boots may continue on unchanged 0da
and its original scope. This change does not require reimport or alter the
retained OVA, real fixture generator, access boundary or measurement controller.
