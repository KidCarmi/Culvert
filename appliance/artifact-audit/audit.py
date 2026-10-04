#!/usr/bin/env python3
"""Read-only allocated-file/layer audit. Never extracts archive member paths.

Findings are indicators requiring triage, not proof that a matched value works.
All output is metadata; content and exception messages are never reported.
"""
import argparse
from collections import Counter
import hashlib
import importlib.metadata
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import tempfile
import time

MAX_FILE = 4 * 1024**3
MAX_TOTAL = 64 * 1024**3
MAX_ENTRIES = 500000
MAX_DEPTH = 5
MAX_FINDINGS = 10000
CHUNK = 1024 * 1024
PEM = re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')
CREDENTIAL = re.compile(rb'(?i)(?:password|passwd|passphrase|api[_-]?key|secret|(?:access|setup)[_-]?token)["\x27]?\s*[:=]\s*["\x27]?([A-Za-z0-9+/=_!@#%-]{12,})(?=["\x27\s,}]|$)')
PROVIDER = re.compile(rb'(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})')
SHA = re.compile(r'^[0-9a-f]{64}$')


class Refused(Exception):
    pass


def safe_path(value):
    """Printable bounded path; opaque long/control-bearing components are hashed."""
    parts = str(value).replace('\\', '/').split('/')
    return '/'.join(p if len(p) <= 80 and all(32 <= ord(c) < 127 for c in p)
                    else '[name-sha256:' + hashlib.sha256(p.encode()).hexdigest() + ']'
                    for p in parts)[:2048]


def valid_member(name):
    path = PurePosixPath(name)
    return not path.is_absolute() and '..' not in path.parts and '\\' not in name and not re.match(r'^[A-Za-z]:', name) and '\x00' not in name


def private_workspace(path):
    path = path.absolute()
    if not path.is_dir() or path.resolve() != path:
        raise Refused('workspace')
    for current in (path, *path.parents):
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise Refused('workspace')
    if os.name != 'nt' and path.stat().st_mode & 0o077:
        raise Refused('workspace permissions')
    if os.name == 'nt':
        # Fixed read-only ACL check. No artifact-controlled PowerShell input.
        import subprocess
        env = {k: v for k, v in os.environ.items() if k.upper() != 'PSMODULEPATH'}
        env['CULVERT_AUDIT_PRIVATE'] = str(path)
        script = "$ErrorActionPreference='Stop'; $a=Get-Acl -LiteralPath $env:CULVERT_AUDIT_PRIVATE; if(-not $a.AreAccessRulesProtected){exit 1}; $s=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18'); foreach($r in $a.Access){if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $s){exit 1}}"
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                env=env, capture_output=True, timeout=15)
        if result.returncode:
            raise Refused('workspace permissions')
    return path


class Audit:
    def __init__(self, workspace, seconds=1800):
        self.workspace = workspace
        self.deadline = time.monotonic() + seconds
        self.counts = Counter()
        self.findings = []
        self.gaps = []
        self.archives = []
        self.expected_layers = set()
        self.scanned_layers = set()
        self.current_path = ''

    def bound(self):
        if time.monotonic() > self.deadline or self.counts['bytes'] > MAX_TOTAL or self.counts['entries'] > MAX_ENTRIES:
            raise Refused('audit budget')

    def finding(self, path, category, digest=None):
        if len(self.findings) >= MAX_FINDINGS:
            raise Refused('finding budget')
        row = {'path': safe_path(path), 'category': category}
        if digest:
            row['sha256'] = digest
        self.findings.append(row)

    def gap(self, path, category):
        if len(self.gaps) >= MAX_FINDINGS:
            raise Refused('gap budget')
        self.gaps.append({'path': safe_path(path), 'category': category})

    def path_indicators(self, path, size):
        lower = path.lower()
        components = lower.replace('::', '/').split('/')
        if '.git' in components or '.svn' in components:
            self.finding(path, 'source_control_metadata')
        if any(c in components for c in ('.aws', '.kube', '.docker')) or lower.endswith(('/authorized_keys', '/.netrc', '/.npmrc', '/.pypirc')):
            if size:
                self.finding(path, 'credential_store_or_authorized_key')
        if size and (lower.endswith(('.bash_history', '.zsh_history')) or '/var/log/' in lower or lower.endswith(('builder.log', 'prepare-guest.log'))):
            self.finding(path, 'nonempty_log_or_history')
        if '/usr/local/go/' in lower or any(c in components for c in ('go-build', '.cache')) or lower.endswith(('/go.mod', '/go.sum')):
            self.finding(path, 'build_or_source_residue_indicator')
        if size and (lower.endswith('/.env') or lower.endswith('/credential.json') or lower.endswith('/ca.bundle')):
            self.finding(path, 'sensitive_state_file')
        if 'initrd.img' in lower or lower.endswith('.cpio'):
            self.gap(path, 'initramfs_cpio_payload_not_recursively_decoded')

    def scan_file(self, source, size, path, depth=0, image_root=None):
        self.current_path = path
        self.counts['entries'] += 1
        self.bound()
        self.path_indicators(path, size)
        if size > MAX_FILE or size < 0:
            self.gap(path, 'file_size_limit')
            return
        digest = hashlib.sha256()
        tail = b''
        categories = set()
        total = 0
        prefix = b''
        small = bytearray()
        archive_candidate = path.endswith(('.tar', '.tar.gz', '.tgz')) or (image_root is not None and ('/blobs/' in path or '::blobs/' in path))
        spool = tempfile.TemporaryFile(dir=self.workspace) if archive_candidate else None
        try:
            while True:
                data = source.read(min(CHUNK, size - total + 1))
                if not data:
                    break
                total += len(data)
                if total > size:
                    raise Refused('file length')
                self.counts['bytes'] += len(data)
                self.bound()
                digest.update(data)
                if len(prefix) < 512:
                    prefix = (prefix + data)[:512]
                if len(small) < 2 * CHUNK:
                    small.extend(data[:2 * CHUNK - len(small)])
                window = tail + data
                if PEM.search(window):
                    categories.add('private_key_pem_marker')
                if PROVIDER.search(window):
                    categories.add('provider_credential_pattern')
                if CREDENTIAL.search(window):
                    categories.add('literal_credential_assignment_indicator')
                tail = window[-4096:]
                if spool:
                    spool.write(data)
            if total != size:
                raise Refused('short file')
            self.counts['regular_files_scanned'] += 1
            if image_root and '::blobs/sha256/' in path and SHA.fullmatch(path.rsplit('/', 1)[-1]):
                if digest.hexdigest() != path.rsplit('/', 1)[-1]:
                    raise Refused('container blob digest mismatch')
                self.counts['container_blob_digests_verified'] += 1
            for category in sorted(categories):
                self.finding(path, category, digest.hexdigest())
            if path.endswith('/etc/shadow'):
                for line in bytes(small).splitlines():
                    fields = line.split(b':')
                    if len(fields) == 9 and fields[1] and fields[1][:1] not in (b'!', b'*'):
                        self.finding(path, 'usable_password_hash_in_pristine_shadow', digest.hexdigest())
                        break
            if image_root and total <= 2 * CHUNK:
                self.container_metadata(bytes(small), image_root)
            if spool:
                spool.seek(0)
                if prefix[:2] == b'\x1f\x8b' or prefix[257:262] == b'ustar' or (size >= 1024 and prefix == b'\x00' * 512):
                    if depth >= MAX_DEPTH:
                        self.gap(path, 'archive_depth_limit')
                    else:
                        root = image_root or path
                        self.scan_tar(spool, path, depth + 1, root)
                        self.scanned_layers.add(path)
                elif path.endswith(('.tar', '.tar.gz', '.tgz')):
                    self.gap(path, 'unsupported_archive_encoding')
        finally:
            if spool:
                spool.close()

    def container_metadata(self, data, root):
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError):
            return
        if isinstance(value, dict) and isinstance(value.get('layers'), list):
            for layer in value['layers']:
                if not isinstance(layer, dict):
                    continue
                if layer.get('mediaType') == 'application/vnd.in-toto+json':
                    self.counts['container_attestation_descriptors'] += 1
                    continue
                digest = layer.get('digest', '')
                if isinstance(digest, str) and digest.startswith('sha256:') and SHA.fullmatch(digest[7:]):
                    self.expected_layers.add(root + '::blobs/sha256/' + digest[7:])
        if isinstance(value, list):
            for manifest in value:
                if isinstance(manifest, dict) and isinstance(manifest.get('Layers'), list):
                    for name in manifest['Layers']:
                        if isinstance(name, str) and valid_member(name):
                            self.expected_layers.add(root + '::' + name)

    def scan_tar(self, source, path, depth, image_root):
        count = 0
        with tarfile.open(fileobj=source, mode='r|*') as archive:
            for member in archive:
                self.bound()
                count += 1
                if count > MAX_ENTRIES:
                    raise Refused('archive entries')
                if not valid_member(member.name):
                    raise Refused('unsafe archive path')
                name = path + '::' + member.name.removeprefix('./')
                if member.isfile():
                    with archive.extractfile(member) as content:
                        self.scan_file(content, member.size, name, depth, image_root)
                else:
                    self.counts['archive_nonregular_entries'] += 1
                    if member.issym() or member.islnk():
                        self.counts['archive_links_not_followed'] += 1
                if PurePosixPath(member.name).name.startswith('.wh.'):
                    self.counts['whiteout_entries_retained'] += 1
        self.archives.append({'path': safe_path(path), 'members': count})

    def filesystem(self, fs, label):
        stack = [fs.get('/')]
        seen = set()
        while stack:
            directory = stack.pop()
            self.current_path = label + ':' + directory.path
            self.bound()
            try:
                entries = list(directory.scandir())
            except Exception:
                self.gap(self.current_path, 'filesystem_directory_unreadable')
                continue
            for entry in entries:
                path = label + ':' + entry.path
                try:
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        identity = (info.st_dev, info.st_ino)
                        if identity not in seen:
                            seen.add(identity)
                            stack.append(entry.get())
                    elif stat.S_ISREG(info.st_mode):
                        with entry.get().open() as content:
                            self.scan_file(content, info.st_size, path)
                    else:
                        self.counts['filesystem_nonregular_entries'] += 1
                except Refused:
                    raise
                except Exception:
                    self.gap(path, 'filesystem_entry_unreadable')


def extract_disk(ova, workspace, expected):
    with ova.open('rb') as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != expected:
            raise Refused('artifact hash mismatch')
    destination = workspace / 'audit-disk.vmdk'
    if destination.exists():
        raise Refused('existing extraction')
    with tarfile.open(ova, 'r:') as archive:
        members = []
        for member in archive:
            if len(members) >= 16 or not member.isfile() or not valid_member(member.name) or member.size > 16 * 1024**3:
                raise Refused('OVA members')
            members.append(member)
        disks = [m for m in members if m.name.endswith('.vmdk')]
        if len(disks) != 1:
            raise Refused('OVA disk count')
        with archive.extractfile(disks[0]) as source, destination.open('xb') as out:
            while data := source.read(CHUNK):
                out.write(data)
    return destination


def validate_vmdk(source):
    header = source.read(512)
    if len(header) != 512 or header[:4] != b'KDMV':
        raise Refused('unsupported VMDK')
    offset, size = struct.unpack_from('<QQ', header, 28)
    if not 0 < size <= 128 or not 0 < offset <= 128:
        raise Refused('VMDK descriptor bounds')
    source.seek(offset * 512)
    descriptor = source.read(size * 512)
    parents = re.findall(rb'(?m)^parentCID=([^\s]+)', descriptor)
    kinds = re.findall(rb'(?m)^createType="([^"\r\n]+)"', descriptor)
    if parents != [b'ffffffff'] or kinds != [b'streamOptimized']:
        raise Refused('external VMDK dependencies')
    source.seek(0)


def audit_disk(path, audit):
    from dissect.hypervisor.disk.vmdk import VMDK
    from dissect.volume.disk import Disk
    from dissect.target.filesystems.extfs import ExtFilesystem
    from dissect.target.filesystems.fat import FatFilesystem
    partitions = []
    with path.open('rb') as source:
        validate_vmdk(source)
        for partition in Disk(VMDK(source)).partitions:
            row = {'number': partition.number, 'size': partition.size, 'type': str(partition.type)}
            for kind in (ExtFilesystem, FatFilesystem):
                try:
                    fs = kind(partition.open())
                except Exception:
                    continue
                row['filesystem'] = kind.__name__
                audit.filesystem(fs, 'partition-' + str(partition.number))
                break
            else:
                row['filesystem'] = 'not_decoded'
                audit.gap('partition-' + str(partition.number), 'non_filesystem_or_unsupported_partition')
            partitions.append(row)
    return partitions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ova', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--private-workspace', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    report = {'schema_version': 1, 'status': 'incomplete', 'findings_are_indicators': True,
              'limitations': ['allocated named files only; no deleted files/free space/slack recovery',
                              'pattern matching cannot prove absence of arbitrary encoded or encrypted secrets',
                              'symlinks/device nodes not followed; artifact content never executed',
                              'initramfs/cpio and arbitrary nested non-container compression not decoded']}
    audit = None
    try:
        if not SHA.fullmatch(args.sha256):
            raise Refused('invalid hash')
        workspace = private_workspace(args.private_workspace)
        audit = Audit(workspace)
        disk = extract_disk(args.ova, workspace, args.sha256)
        report['artifact_sha256'] = args.sha256
        report['partitions'] = audit_disk(disk, audit)
        for missing in sorted(audit.expected_layers - audit.scanned_layers):
            audit.gap(missing, 'referenced_container_layer_not_decoded')
        report['status'] = 'inspection_completed_with_limits'
    except Exception as error:
        report['failure'] = 'audit_refused_or_incomplete_no_exception_payload'
        report['failure_type'] = type(error).__name__
        if audit:
            report['failure_path'] = safe_path(audit.current_path)
    if audit:
        report.update(counts=dict(audit.counts), findings=audit.findings, gaps=audit.gaps,
                      archives=audit.archives, expected_container_layers=len(audit.expected_layers),
                      decoded_referenced_layers=len(audit.expected_layers & audit.scanned_layers))
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['dependencies'] = {d.metadata['Name']: d.version for d in importlib.metadata.distributions()
                              if d.metadata['Name'].lower().startswith(('dissect', 'flow.', 'defusedxml', 'structlog', 'msgpack', 'cryptography', 'cffi', 'pycparser', 'tzdata'))}
    data = json.dumps(report, indent=2).encode()
    if len(data) > 8 * CHUNK:
        raise SystemExit('Audit report exceeds output bound.')
    with args.report.open('xb') as out:
        out.write(data)
    print(json.dumps({'status': report['status'], 'findings': len(report.get('findings', [])), 'gaps': len(report.get('gaps', []))}))
    return 0 if report['status'] == 'inspection_completed_with_limits' else 1


if __name__ == '__main__':
    raise SystemExit(main())
