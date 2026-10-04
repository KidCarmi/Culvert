# b579 LAB P1 regressions

These are one-shot controller stages for source
`b579ca28c9d936e9141292ce5ec564a26feeae86` and retained OVA SHA256
`1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775`.
They neither change the OVA nor grant administrative SSH. Do not run against
the superseded 4f candidate. One owned VM remains the resource limit.

Invoke `p1-regressions.py --scope SCOPE --bind CONTROLLER_IP STAGE` through
the existing Windows Python environment. The parent must freeze/hash all
controller inputs before using them, retain all private attempt records, and
run stages sequentially. The helpers perform no guest operations on import.
No automatic retry is permitted after any stage starts. A stopped or ambiguous
stage is BLOCKED and requires evidence review; do not remove its attempt file.

## Network rollback around the lifecycle maintenance reboot

After ordinary bootstrap, operator enrollment and application qualification,
run `network-before` before the existing lifecycle maintenance reboot. This
requires one physical management interface with one IPv4 address and an
on-link default gateway. It uses that same address/prefix/gateway for a
temporary static configuration; it does not invent another address.

The installed, hash-pinned `culvert-net` invokes a private PATH-local shim.
The shim runs real `netplan generate` and real `netplan apply`, then injects
exit 71 once, after apply succeeded. It subsequently delegates both rollback
generate/apply calls to real Netplan. This is fault injection after actual
network activation, not proof of every possible native Netplan failure.
The product helper must report failure while restoring the original file
bytes/mode or absence, the address and gateway. The controller checks the
unchanged owned IP, strict-pinned read-only operator SSH and external `/health`.
The shim never enters any service's global PATH and is removed after success;
failure preserves scratch evidence without automatically modifying networking.

After the lifecycle's real maintenance reboot, run `network-after`. It requires
a different boot ID, unchanged OS identity, exact original Netplan state,
the same usable management network, operator SSH and external application
health. The parent must require both stages to pass.

## Reset identity last, after external backup and escrow verification

First run `identity-before`, preserving the old active console password,
operator public key, host pin and OS/SSH identity in the private run directory.
Export the backup and CA/log passphrase escrow before reset. The parent's
verified exporter supplies a private JSON readiness record containing the
same `uuid`, exact `ova_sha256`, `backup_export_verified: true` and
`escrow_export_verified: true`. These are an explicit parent evidence contract;
this helper does not itself prove that backup restoration into a fresh VM works.

Run `identity-reset --escrow-evidence RECORD`. Authenticated local sudo invokes
the exact installed reset helper and answers its confirmation through stdin.
The initial transport acknowledgment proves only dispatch. PASS requires the
owned VM to become powered off independently; no hypervisor force-off is used.

Run `identity-power-on`, which powers on only that same owned, observed-off VM.
Run `identity-bootstrap`: the original active password file is preserved,
the existing exact-pixel observer reads the new one-time handoff twice, and
the genuine F2/PAM forced-password-change sequence authenticates a new password.
Neither old host pin nor old operator key is replaced or re-enrolled.

After first boot completes, run `identity-after`. The local authenticated
console collects a changed machine ID, boot ID and Ed25519 host key, an empty
fresh operator authorization file and completed key re-import. It makes one
`pam_authenticate` call against the real `login` PAM service with the old
password; exactly one password conversation and `PAM_AUTH_ERR` are required.
This is a real PAM refusal, not a hash comparison, but it does not inject a
failed password into the interactive F2 login session. New password acceptance
was separately proved by the genuine interactive PAM bootstrap.

The controller pins the new SSH public key observed over authenticated console
in a separate private known-hosts file. It then requires explicit public-key
authentication refusal for the old operator key. A timeout, changed host-key
warning, routing error or unavailable SSH server is BLOCKED, never a refusal
PASS. External application health must remain available.

After collecting these results, the parent can delete the source VM/volumes and
import the retained original OVA for separate fresh-appliance disaster recovery.
These helpers do not delete VMs, import a second VM, alter ESXi configuration,
prove fresh-appliance restore, resolve F-DISK-1 or change ClamAV disposition.

## Local validation and evidence

`python -m unittest discover -s test/e2e/appliance/esxi -p test_p1_regressions.py`
uses synthetic records only; it does not connect to ESXi, authenticate or call
PAM. Local tests validate refusal of stale identity, missing real-apply proof,
network drift, old-password acceptance and overwritten attempt evidence.
All raw records, scripts containing old credentials, transport results and
screenshots remain under the existing private `secrets` ACL. Publish only
reviewed stage verdicts and source hashes. Native runtime qualification is
pending until these exact staged helpers run on the owned candidate.
