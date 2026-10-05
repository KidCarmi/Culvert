# Disposable ESXi early-initramfs readahead comparison

This is a predeclared experiment on the single owned b579 LAB guest, not an OVA
change or artifact qualification. The earlier recovery failures remain failures.
Opus owns any eventual product/provisioning fix. No live guest action is implied
by committing the controller or this protocol.

Keep the same 2 vCPU, 4 GiB RAM, 40 GiB disk, datastore, policy, access boundary,
6.8.0-146-generic kernel, maintenance reboot command and frozen recovery observer.
The production budget remains 120 seconds through completion of three consecutive
joint healthy samples started five seconds apart. Keep all existing ClamAV,
traffic, operator, backup, persistence and maintenance-lock requirements.

The sequence is **A128 → B1024 → B1024 → B1024 → A128 → original initrd**.
Each arrow includes the existing authenticated product maintenance reboot and
postboot verification. Repeated B boots reuse identical staged initrd bytes.
The final original-image boot proves restoration; it cannot erase any preceding
budget failure. Restore is available after either A or B regardless of whether
service recovery met its budget.

## Preparation and controls

Use `production-early-readahead.py` only from a frozen controller checkout through
its existing PAM/sudo console transport. Operations are `prepare`, `export`,
`applyA`, `applyB`, `verify --profile A|B|original`, and `restore`. Every invocation
also takes `--scope`, `--bind`, `--campaign`, `--ra-campaign`, `--ra-generator`, and
the private `--facts` file. The readahead campaign/generator identify the already
owned real-root udev rule; they must match its actual private receipt.

Preparation validates the original146 initrd: 37,347,640 bytes, SHA256
`d22af6fa8e3b0c609ae3227b7e036b1262b3054b4f395ced2a4d3beedf32bf54`.
It copies those bytes to root-private guest storage and builds A/B by editing
only the original main cpio archive in private campaign storage. It does not install a persistent hook in `/etc`, regenerate
GRUB, change kernel arguments or touch the142 kernel/initrd. Presence of the142
fallback is recorded; its usability is **not** asserted.

Before applying either fixture, export the original through a one-use TLS
endpoint pinned by public key and restricted to the owned guest IP. The endpoint
requires the exact byte count, bounds transfers below128 MiB, fsyncs the file,
recomputes its SHA256 from disk and fsyncs/verifies its private receipt before
acknowledging. Activation also revalidates the local escrow and the guest's
authenticated export acknowledgement.

Original→A expanded manifests may differ only by the exact owned local-premount
script and its exact two-line invocation in `scripts/local-premount/ORDER`.
All original ORDER lines and all other file contents, modes, owners and symlink
targets must remain unchanged. A→B manifests must be identical except for the
fixture's128/1024 target value. The original initrd contains no owned live-root udev rule, and neither fixture
adds it, so that rule cannot preempt the hook's128-default guard; it remains
owned on the real root and follows the selected profile after switch-root.
Original and staged initrds must contain the tools used by the hook. Unapproved
manifest differences or unavailable tools block activation; do not widen the
allowlist merely to obtain a passing build.

The hook verifies VMware identity, the approved root UUID resolving to `sda1`,
ext4, the40 GiB disk, selected kernel, scheduler and128 KiB starting value. It
writes only the disk's readahead attribute, verifies readback and emits a boot-bound
`CULVERT_LAB_EARLY_RA` kernel message. Postboot verification requires exactly one
successful marker **before the first root-filesystem mount**, plus the expected
current value and unchanged boot-file identities. A refusal preserves ordinary
boot and invalidates this measurement. It cannot affect reads which load the
kernel or initrd before the hook runs.

Publishing copies verified bytes to a new file on `/boot`, fsyncs it, atomically
replaces only the selected146 initrd and fsyncs `/boot`. Rollback uses the preserved
original bytes and must restore their exact hash. Private write-ahead receipts
and incomplete-operation locks prohibit automatic replay after partial failure.
All altered-guest results are experimental evidence only.

## Pre-staging tool-check failure and isolated replacement campaign

The first prepare attempt stopped while checking tools in the expanded original
initrd, before staging or activation. Its private fixed state directory, lock,
intent and original copy remain untouched. The corrected check uses no in-chroot
redirection or device mounts: an unpacked initrd need not contain `/dev/null`.
Every required discovery step must succeed. Failed commands retain bounded private
argv, stdout, stderr, exit status and timeout evidence.

A reviewed replacement uses a **new campaign UUID** beneath the root-private
`/var/lib/culvert-lab-early-read-ahead-campaigns/` directory. It repeats original
identity, headroom and expansion checks from the unchanged active initrd. Existing
campaign directories remain exclusive and cannot be retried automatically. This
is a separate attempt, not an unlock or a rewrite of the original failed result.
The A/B allowlist, export prerequisite, boot-file guards and recovery budget are
unchanged. Freeze the revised controller before invoking the new campaign.

## Deterministic staging after the manifest refusal

The second prepare attempt correctly rejected `mkinitramfs` output: it imported
an owned rule under `usr/lib/udev/rules.d` and regenerated random seed, mdadm
configuration and font caches differently between A and B. That failed campaign
is retained. The allowlist is not expanded.

The next reviewed campaign preserves the original 13,732,352-byte prefix exactly
(SHA256 `a0882502b00f90f80306735a373a1f96fbba53889ce2c6f0ac8a36a7a720b709`).
Its remaining 23,615,288 bytes are the observed zstd main archive; kernel146 has
`CONFIG_RD_ZSTD=y`. Decompression is time bounded and file-size limited to512 MiB.
A strict streaming newc parser rejects malformed or duplicate paths, a nonregular
or linked ORDER, existing fixture, symlink parents, additional archives and
unexpected trailing data. Surgery preserves each other record byte-for-byte,
including timestamps, hardlink records and data. It changes only ORDER's size and
payload and inserts the exact hook before the original trailer.

Both profiles use recorded `zstd -q -3 --single-thread -c` arguments. A complete A
rewrite and compression is repeated and must yield identical bytes. The original
prefix is prepended unchanged. The installed `unmkinitramfs` then extracts each
complete staged image, followed by the existing exact manifest and tool checks.
No package hook runs and no host configuration is imported. This avoids relying
on an appended archive that an extractor might silently ignore.

Recompression changes the compressed main archive layout, so the initial A boot
is a necessary control. This remains an altered-guest comparison, never evidence
that the deliverable OVA itself acquired the fixture or passed qualification.
