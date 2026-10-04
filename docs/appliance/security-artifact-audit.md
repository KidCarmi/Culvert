# Pristine appliance artifact inspection

This audit reads the delivered OVA bytes, the allocated files of its VMDK
filesystems, and every recognized embedded container layer separately. It does
not boot the appliance, run a container, execute extracted programs, or infer
an artifact result from the build recipe. A deleted file in a later container
layer does not erase a finding in an earlier layer.

The inspected candidate is
`culvert-appliance-1.0.260-candidate.g36b5407e5bd3-ubuntu-24.04.ova`, SHA-256
`7bd09aaac19ab0525654d2863d4382bf0415e0ac75e2b55aee8a424a9df6bca1`.
This is historical candidate `36b5407e`, not proof about a subsequently rebuilt
image or the current source branch. The hash was checked before disk extraction.

## Reproduction and custody

The inspection tool is `appliance/artifact-audit/audit.py`. Install the pinned
`requirements.txt` into a dedicated Python environment. The observed environment
was Windows and Python 3.12, without a running Docker daemon or WSL. Dissect
provides read-only stream-optimized VMDK, GPT, ext4 and FAT readers; the tool does
not mount the disk in the operating system.

Create a new private workspace before running the tool. On Windows its ACL must
have inheritance disabled and grant access only to the operator and SYSTEM;
on Unix use mode 0700. The tool checks the directory and rejects symlink/reparse
ancestors. Run against a separately retained, hash-verified OVA:

```text
python appliance/artifact-audit/audit.py --ova <pristine.ova> --sha256 <expected-sha256> --private-workspace <new-private-directory> --report <private-report.json>
```

The workspace receives one fixed-name VMDK copy and temporary archive streams.
Archive member names are never extracted into host paths; links are not followed.
Existing extracted disks and report destinations are refused. Keep the workspace
private until a separately authorized, path-checked cleanup. Never upload the
disk, raw file contents, or private credentials to an issue or CI log.

Reports contain sanitized paths, indicator categories, counts, file hashes,
coverage gaps and tool provenance. They never contain matched values, file
snippets, environment contents or third-party exception payloads. Indicators
require triage: a compiled cryptographic implementation can contain a PEM header
string without containing a private key, and binary bytes can match a provider
credential pattern accidentally. Finding an indicator is not proof that a
credential is usable; finding none is not proof that arbitrary secrets are absent.

## Bounds and interpretation

The scanner has a 30-minute wall-clock observation budget, 64 GiB cumulative read
budget, 4 GiB per-file limit, five nested archive levels, 500,000 regular-file
entries and a 10,000-finding cap. It limits JSON inspection to 2 MiB and reports
missing referenced container layers instead of treating them as clean. Tests
exercise whiteouted files, both OCI layers, traversal names, output redaction,
short reads, expired budgets and locked versus usable shadow fields.

Coverage does not include deleted disk files, unallocated sectors, filesystem
slack, arbitrary encoding/encryption, or recursive initramfs/cpio decoding.
Unsupported partitions and unreadable directories/files are explicit gaps. A
successful invocation means the bounded inspection completed, not that an image
is secure or release-qualified. A release must separately satisfy vulnerability,
dependency/provenance, runtime access-control and lifecycle qualification gates.

## Evidence from this inspection

The completed scan read **71,975 regular-file entries / 2,531,599,989 bytes**
across an ext4 root partition, EFI FAT partition, ext4 boot partition and the
embedded archives. Repeated bytes inside nested archives are included in this
count. **All 18 referenced container filesystem layers** were decoded separately;
27 content-addressed container blobs matched their SHA-256 names. Two in-toto
attestation descriptors were read as metadata, not incorrectly counted as
filesystem layers. The two explicit structural gaps are the BIOS boot partition
and compressed initramfs/cpio contents.

The scanner recorded **90 indicators, not 90 leaked secrets**: 29 PEM markers,
53 credential-assignment patterns, seven provider-style patterns and one retained
build transcript. The allocated-file pass found no usable/empty shadow password
fields, no named SSH host keys, an empty machine-id, and no source-control
metadata or credential-store path indicators. These findings support only the
stated patterns and coverage, not a blanket absence claim.

### Confirmed production-binary test-key residue

The actual container `/app/culvert` binary contains a complete, parseable RSA
private key. Its public-key SHA-256 is
`7ea3450aa488c616e3b6c28a191ab4e7c61a4dafce2d172d4527c9a172a5736f`.
Read-only `go version -m` inspection of that extracted binary identifies
`github.com/crewjam/saml v0.5.1`, matching the module checksum in the repository.
The same public-key fingerprint is derived from the upstream module's
`xmlenc/fuzz.go:13`. That file has no build constraint; a package-level `testKey`
initializer parses the embedded RSA key, and the `Fuzz` function uses it.

This is confirmed fuzz/test material embedded in the production executable,
not evidence of an exposed operator SAML signing key or an authentication bypass.
It should be removed through a reviewed dependency remediation and a rebuilt
artifact scan. Merely filtering PEM markers from a report would conceal the
finding. Binary SHA-256:
`db8c3520a0d334a4006b4cbe2317616adbeb56efab0a8ecba3e14dc3a7b892ab`.

At review time, upstream's latest release remained v0.5.1 and its main branch
still included this fixture. [Upstream PR #646](https://github.com/crewjam/saml/pull/646)
moves it into test code but remains unmerged. No module upgrade or cache edit was
made here. A maintained, provenance-recorded patch needs SAML acceptance and
signature/audience/replay rejection tests plus a new binary/image scan; a version
bump alone cannot claim to resolve this finding.

### Separate raw-disk PEM sweep

`raw_keys.py` read the entire **42,949,672,960-byte virtual disk**, including
sectors not reached by named-file traversal. It found 28 complete parseable
unencrypted PEM occurrences representing 11 distinct public keys. All 11 match
keys in named Twisted test files/bytecode or the packaged libgnutls library.
The corresponding source fixtures and library match their installed dpkg file
checksums; generated Python bytecode has no dpkg checksum entry. This comparison
is attribution to the installed package content, not independent package-signature
verification. No additional unmatched complete PEM key was detected by this
sweep. Fixture/library presence is not proof of runtime use as an identity.

The raw sweep is deliberately narrow: it cannot rule out fragmented keys,
encrypted keys, DER-only material, arbitrary secrets, deleted-file recovery, or
keys inside compressed content. In particular, it **does not replace the layer
inspection that found the Culvert binary's SAML fixture key**. Invoke it only on
the private, extracted VMDK with its separately calculated SHA-256:

```text
python appliance/artifact-audit/raw_keys.py --vmdk <private/audit-disk.vmdk> --vmdk-sha256 <disk-sha256> --report <private/raw-key-report.json>
```

The retained `/var/lib/culvert-appliance/prepare-guest.log` is 8,309 bytes. Its
inspection found no private-key marker or private IPv4 pattern; it is still
build-transcript residue and should have an explicit retention decision.

Sanitized evidence is retained under
[`appliance/artifact-audit/evidence`](../../appliance/artifact-audit/evidence):

- `candidate-36b5407e-report.json`: actual disk/layer counts, indicators, gaps,
  dependencies and exact scanner SHA-256.
- `candidate-36b5407e-raw-key-report.json`: raw sweep bounds, offsets and public-key
  fingerprints; no private key bytes.
- `candidate-36b5407e-named-key-triage.json`: named vendor-file attribution and
  pristine identity checks.
- `candidate-36b5407e-container-key-attribution.json`: actual binary/module and
  source-fixture fingerprint agreement.

Twelve focused synthetic tests passed on Windows Python 3.12. CI can run them
without an OVA, hypervisor, network target or disk parser by installing
`cryptography==50.0.2` and running
`python -m unittest discover -s appliance/artifact-audit -v`.

Any source/dependency hardening or newly built image requires another artifact
audit. These historical results must not be relabeled as evidence for the new
candidate.
