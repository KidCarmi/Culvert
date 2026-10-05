"""Offline tests only. No hypervisor, console, reboot or guest calls."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
import sys
import uuid
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('early_readahead', HERE / 'production-early-readahead.py')
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)
COMMON = dict(need=p.need, hashlib=hashlib, os=os, re=re, stat=stat, file_hash=p.file_hash, uuid=uuid)
exec(compile(p.COMMON, '<early-common>', 'exec'), COMMON)
OWNER = '12345678-1234-4567-89ab-123456789abc'
CAMPAIGN = '23456789-2345-4678-9abc-23456789abcd'
ROOT = '3456789a-3456-4789-abcd-3456789abcde'
BOOT = '456789ab-4567-489a-bcde-456789abcdef'


def facts():
    def row(output):
        return dict(output=output, result='ok', exit_code=0, truncated=False, timed_out=False)
    return {'early': {
        'initrd': dict(kernel=p.KERNEL, bytes=p.ORIGINAL_BYTES, mode='0o644', uid=0, sha256=p.ORIGINAL_SHA),
        'initrd_listing_status': row(''), 'initrd_rule_entries': [],
        'grub_menu': row('linux /vmlinuz-' + p.KERNEL + ' root=UUID=' + ROOT),
        'mounts': row(json.dumps({'filesystems': [{'target': '/', 'source': '/dev/sda1', 'fstype': 'ext4'}]})),
        'local_script': row('local_mount_root()\n{\n ROOT="${DEV}"\n\tlocal_premount\n\tcheckfs root\n\tmount root\n}\nlocal_mount_fs()')
    }}


def fixture_manifests():
    a, b = p.boot_hook(OWNER, CAMPAIGN, ROOT, 128), p.boot_hook(OWNER, CAMPAIGN, ROOT, 1024)
    original = {'main/init': {'kind': 'file', 'mode': 0o755, 'uid': 0, 'gid': 0, 'size': 4, 'sha256': 'a' * 64}}
    prior_order = b'/scripts/local-premount/resume "$@"\n[ -e /conf/param.conf ] && . /conf/param.conf\n'
    new_order = prior_order + b'/scripts/local-premount/culvert-lab-early-read-ahead "$@"\n[ -e /conf/param.conf ] && . /conf/param.conf\n'
    order_name = 'main/scripts/local-premount/ORDER'
    def order_row(content):
        return {'kind': 'file', 'mode': 0o644, 'uid': 0, 'gid': 0, 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
    original[order_name] = order_row(prior_order)
    path = 'main/scripts/local-premount/' + p.HOOK_NAME
    def added(hook):
        result = copy.deepcopy(original)
        result[order_name] = order_row(new_order)
        result[path] = {'kind': 'file', 'mode': 0o755, 'uid': 0, 'gid': 0, 'size': len(hook), 'sha256': hashlib.sha256(hook).hexdigest()}
        return result
    return original, added(a), added(b), a, b, {'original': prior_order, 'A': new_order, 'B': new_order}


class EarlyTests(unittest.TestCase):
    def test_campaign_state_is_canonical_and_does_not_reuse_legacy_directory(self):
        parent = Path('/var/lib/culvert-lab-early-read-ahead-campaigns')
        self.assertEqual(COMMON['campaign_state'](parent, CAMPAIGN), parent / CAMPAIGN)
        self.assertNotEqual(COMMON['campaign_state'](parent, OWNER), parent / CAMPAIGN)
        for bad in ('../legacy', CAMPAIGN.upper(), CAMPAIGN + '/other', '', None):
            with self.subTest(bad=bad), self.assertRaises((ValueError, TypeError)):
                COMMON['campaign_state'](parent, bad)
        self.assertNotIn("pathlib.Path('/var/lib/culvert-lab-early-read-ahead')", p.GUEST)
        self.assertIn("need(not os.path.lexists(state), 'prepare already attempted')", p.GUEST)

    def test_boot_tool_probe_has_no_device_redirection_and_fails_missing_functions(self):
        guest = {}; exec(p.GUEST, guest)
        calls = []
        guest['bounded'] = lambda args, **kwargs: calls.append(args)
        guest['boot_tools'](Path('/expanded'), {'main/scripts/functions': {'kind': 'file'}})
        command = calls[0][-1]
        self.assertNotIn('>', command)
        self.assertNotIn('/dev/', command)
        self.assertIn('command -v get_fstype || exit 1', command)
        self.assertIn('. /scripts/functions || exit 1', command)
        shell = shutil.which('bash') or ('C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else None)
        if not shell: self.skipTest('shell unavailable')
        # Execute the exact discovery program with only the sourced fixture path
        # redirected to an ordinary temporary file. No guest, chroot or mounts.
        with tempfile.TemporaryDirectory() as directory:
            functions = Path(directory) / 'functions'
            fixture_path = functions.as_posix()
            if os.name == 'nt': fixture_path = '/' + fixture_path[0].lower() + fixture_path[2:]
            probe = command.replace('/scripts/functions', "'" + fixture_path + "'")
            for definitions, expected in [('get_fstype() { :; }; blkid() { :; }', 0),
                                           ('blkid() { :; }', 1)]:
                functions.write_bytes(definitions.encode())
                result = subprocess.run([shell, '-c', probe], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr.decode(errors='replace'))

    @unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'geteuid') and os.geteuid() == 0,
                         'real empty-dev chroot requires Linux root; Windows runs discovery/shell tests')
    def test_real_chroot_discovery_without_dev_null(self):
        guest = {}; exec(p.GUEST, guest); guest['tempfile'] = tempfile
        with tempfile.TemporaryDirectory() as directory:
            expanded = Path(directory); root = expanded / 'main'
            (root / 'bin').mkdir(parents=True); (root / 'scripts').mkdir()
            # Copy the host shell plus its dynamic dependencies, never any device.
            shell = Path('/bin/sh').resolve()
            shutil.copyfile(shell, root / 'bin/sh'); (root / 'bin/sh').chmod(0o755)
            linked = subprocess.run(['ldd', str(shell)], capture_output=True, text=True, timeout=10)
            if linked.returncode != 0: self.skipTest('dynamic library inventory unavailable')
            for library in set(re.findall(r'(/[^\s()]+)', linked.stdout)):
                source = Path(library)
                if source.is_file():
                    target = root / library.lstrip('/'); target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
            (root / 'scripts/functions').write_text('get_fstype() { :; }\nblkid() { :; }\n')
            for name in ('cat', 'tr', 'readlink'):
                (root / 'bin' / name).write_text('#!/bin/sh\nexit 0\n'); (root / 'bin' / name).chmod(0o755)
            self.assertFalse((root / 'dev').exists())
            guest['boot_tools'](expanded, {'main/scripts/functions': {'kind': 'file'}})
            self.assertFalse((root / 'dev').exists())
            (root / 'scripts/functions').write_text('blkid() { :; }\n')
            with self.assertRaisesRegex(ValueError, 'bounded command failed'):
                guest['boot_tools'](expanded, {'main/scripts/functions': {'kind': 'file'}})

    def test_bounded_command_keeps_nonzero_timeout_and_oversize_diagnostics_private(self):
        guest = {}; exec(p.GUEST, guest); guest['tempfile'] = tempfile
        with tempfile.TemporaryDirectory() as directory:
            guest['COMMAND_DIAGNOSTICS'] = Path(directory)
            # The production O_EXCL/fsync writer is Linux-specific; substitute
            # only persistence so the real bounded child process runs on Windows.
            def private_new(path, content):
                with path.open('xb') as output: output.write(content)
            guest['new'] = private_new
            for command, timeout, expected in [
                ('import sys; print("probe"); print("missing /dev/null", file=sys.stderr); sys.exit(7)', 5, 7),
                ('import sys,time; print("before timeout", flush=True); time.sleep(5)', 0.2, None),
                ('print("x" * 2048)', 5, 0)]:
                prior = set(Path(directory).glob('*.json'))
                with self.assertRaisesRegex(ValueError, 'bounded command failed'):
                    guest['bounded']([sys.executable, '-c', command], timeout=timeout, limit=1024)
                paths = set(Path(directory).glob('*.json')) - prior
                self.assertEqual(len(paths), 1)
                row = json.loads(paths.pop().read_bytes())
                self.assertEqual(row['argv'], [sys.executable, '-c', command])
                self.assertEqual(row['returncode'], expected)
                self.assertGreater(row['elapsed_ns'], 0)
                if expected == 7: self.assertIn('missing /dev/null', row['stderr'])
                if expected is None:
                    self.assertIn('TimeoutExpired', row['error']); self.assertIn('before timeout', row['stdout'])
                if expected == 0: self.assertTrue(row['truncated']); self.assertLessEqual(len(row['stdout']), 1024)
            self.assertEqual(guest['bounded']([sys.executable, '-c', 'print("ok")']).strip(), 'ok')

    def test_facts_require_exact_original_and_actual_premount_ordering(self):
        self.assertEqual(p.private_facts(facts()), ROOT)
        for part, key, value in [('initrd', 'sha256', '0' * 64), ('initrd', 'bytes', 128),
                                 ('initrd_listing_status', 'truncated', True), ('grub_menu', 'timed_out', True)]:
            data = facts(); data['early'][part][key] = value
            with self.subTest(part=part, key=key), self.assertRaises(ValueError): p.private_facts(data)
        data = facts(); data['early']['initrd_rule_entries'] = ['etc/udev/rules.d/65-culvert-lab-read-ahead.rules']
        with self.assertRaises(ValueError): p.private_facts(data)
        data = facts(); data['early']['local_script']['output'] = data['early']['local_script']['output'].replace('\tlocal_premount', '\tcheckfs ').replace('\tcheckfs root', '\tlocal_premount')
        with self.assertRaises(ValueError): p.private_facts(data)
        data = facts(); data['early']['grub_menu']['output'] += '\nroot=UUID=' + OWNER
        with self.assertRaises(ValueError): p.private_facts(data)

    def test_expanded_original_A_B_allow_only_the_exact_fixture(self):
        values = fixture_manifests()
        self.assertEqual(COMMON['compare_manifests'](*values), 'main/scripts/local-premount/' + p.HOOK_NAME)
        for mutation in ('package_content', 'mode', 'extra_file', 'symlink', 'rule', 'wrong_fixture', 'missing_original'):
            original, a, b, hook_a, hook_b, orders = copy.deepcopy(values)
            if mutation == 'package_content': b['main/init']['sha256'] = 'b' * 64
            elif mutation == 'mode': a['main/init']['mode'] = 0o777
            elif mutation == 'extra_file': a['main/unrelated'] = dict(a['main/init'])
            elif mutation == 'symlink': b['main/init'] = {'kind': 'symlink', 'target': '/outside'}
            elif mutation == 'rule':
                for tree in (original, a, b): tree['main/etc/udev/rules.d/65-culvert-lab-read-ahead.rules'] = dict(tree['main/init'])
            elif mutation == 'wrong_fixture': hook_b += b'\n# changed\n'
            else: del b['main/init']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                COMMON['compare_manifests'](original, a, b, hook_a, hook_b, orders)

    def test_ORDER_allows_only_one_exact_invocation_preserving_all_original_lines(self):
        for mutation in ('extra_command', 'removed_existing', 'duplicate_fixture', 'AB_difference'):
            original, a, b, hook_a, hook_b, orders = fixture_manifests()
            if mutation == 'extra_command': orders['A'] += b'/bin/unrelated\n'
            elif mutation == 'removed_existing': orders['A'] = orders['A'].replace(orders['original'], b'')
            elif mutation == 'duplicate_fixture': orders['A'] += orders['A'].replace(orders['original'], b'')
            else: orders['B'] += b'\n'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                COMMON['compare_manifests'](original, a, b, hook_a, hook_b, orders)

    def test_hook_LF_and_real_shell_syntax_and_prereqs_are_side_effect_free(self):
        for value in (128, 1024):
            hook = p.boot_hook(OWNER, CAMPAIGN, ROOT, value)
            self.assertNotIn(b'\r', hook)
            self.assertIn(b'[ "$old" = 128 ] || refuse default_readahead', hook)
            self.assertIn(b'case "${1:-}" in prereqs)', hook)
            self.assertNotIn(b'panic ', hook)
            self.assertNotIn(b'update-grub', hook)
            shell = shutil.which('bash')
            if shell:
                checked = subprocess.run([shell, '-n'], input=hook, capture_output=True, timeout=10)
                self.assertEqual(checked.returncode, 0, checked.stderr.decode(errors='replace'))
                # Real execution ONLY of the early prereqs branch, before /scripts/functions or sysfs.
                prereqs = subprocess.run([shell, '-s', '--', 'prereqs'], input=hook, capture_output=True, timeout=10)
                self.assertEqual((prereqs.returncode, prereqs.stdout), (0, b'\n'))

    def test_A_B_hooks_differ_only_in_target_value(self):
        a, b = p.boot_hook(OWNER, CAMPAIGN, ROOT, 128), p.boot_hook(OWNER, CAMPAIGN, ROOT, 1024)
        # The default-value guard stays128 in BOTH profiles.
        normalized = b.replace(b' 1024', b' 128')
        self.assertEqual(a, normalized)
        for bad in (0, 256, True, '128'):
            with self.assertRaises(ValueError): p.boot_hook(OWNER, CAMPAIGN, ROOT, bad)

    def test_marker_requires_same_boot_profile_and_precedes_first_mount(self):
        good = ('[    1.2] CULVERT_LAB_EARLY_RA campaign=' + CAMPAIGN + ' boot=' + BOOT
                + ' profile=1024 result=applied old=128 effective=1024 uptime=1.2 reason=verified\n'
                '[    1.3] EXT4-fs (sda1): mounted filesystem abc ro\n')
        result = COMMON['verify_boot_marker'](good, CAMPAIGN, 1024, BOOT)
        self.assertEqual(result['marker_monotonic_seconds'], 1.2)
        for text in (good.replace('[    1.2]', '[    1.4]'), good.replace('result=applied', 'result=refused'),
                     good.replace('old=128', 'old=1024'), good.replace(BOOT, OWNER), good + good,
                     good.splitlines()[0], good.replace('effective=1024', 'effective=128')):
            with self.assertRaises(ValueError): COMMON['verify_boot_marker'](text, CAMPAIGN, 1024, BOOT)

    def test_original_restore_available_from_either_profile_without_measurement_PASS(self):
        target = COMMON['target_profile']
        self.assertEqual(target('applyA', 'original', True), 'A')
        self.assertEqual(target('applyB', 'A', True), 'B')
        self.assertEqual(target('applyA', 'B', True), 'A')
        self.assertEqual(target('restore', 'A', True), 'original')
        self.assertEqual(target('restore', 'B', True), 'original')
        for action, active, exported in [('applyB', 'original', True), ('applyA', 'A', True),
                                        ('restore', 'original', True), ('applyA', 'original', False)]:
            with self.assertRaises(ValueError): target(action, active, exported)

    def test_export_bounded_owned_ip_one_use_and_exact_hash_with_durable_readback(self):
        raw = b'disposable initrd fixture\n'
        sha = hashlib.sha256(raw).hexdigest()
        identity = {'campaign': CAMPAIGN, 'owner_uuid': OWNER}
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(p, 'ORIGINAL_BYTES', len(raw)), mock.patch.object(p, 'ORIGINAL_SHA', sha):
            export = p.Export('192.0.2.10', '/one-use', Path(temp), identity)
            for peer, route, headers in [('192.0.2.11', '/one-use', {'Content-Length': str(len(raw))}),
                                         ('192.0.2.10', '/wrong', {'Content-Length': str(len(raw))}),
                                         ('192.0.2.10', '/one-use', {'Content-Length': str(len(raw)+1)}),
                                         ('192.0.2.10', '/one-use', {'Content-Length': str(len(raw)), 'Transfer-Encoding': 'chunked'})]:
                with self.assertRaises(ValueError): export.receive(peer, route, headers, io.BytesIO(raw))
                self.assertFalse(export.used)
            ack = json.loads(export.receive('192.0.2.10', '/one-use', {'Content-Length': str(len(raw))}, io.BytesIO(raw)))
            self.assertEqual(ack, dict(result='stored', bytes=len(raw), sha256=sha, **identity))
            self.assertEqual((Path(temp) / 'original.initrd').read_bytes(), raw)
            self.assertTrue(export.complete)
            with self.assertRaises(ValueError): export.receive('192.0.2.10', '/one-use', {'Content-Length': str(len(raw))}, io.BytesIO(raw))

    def test_short_or_wrong_hash_export_never_acknowledged_and_cannot_retry(self):
        for raw in (b'ab', b'xyz'):
            with tempfile.TemporaryDirectory() as temp, mock.patch.object(p, 'ORIGINAL_BYTES', 3), mock.patch.object(p, 'ORIGINAL_SHA', hashlib.sha256(b'abc').hexdigest()):
                export = p.Export('192.0.2.10', '/route', Path(temp), {})
                with self.assertRaises(ValueError): export.receive('192.0.2.10', '/route', {'Content-Length': '3'}, io.BytesIO(raw))
                self.assertTrue(export.used); self.assertFalse(export.complete)
                self.assertFalse((Path(temp) / 'export-receipt.json').exists())

    def test_guest_payload_python_compiles_and_LF_shell_is_valid(self):
        body = p.payload({'action': 'verify'})
        self.assertNotIn(b'\r', body)
        embedded = body.split(b"<<'CULVERT_LAB_EARLY_READ_AHEAD'\n", 1)[1].rsplit(b'\nCULVERT_LAB_EARLY_READ_AHEAD\n', 1)[0]
        compile(embedded, '<generated-early-guest>', 'exec')
        shell = shutil.which('bash')
        if shell:
            result = subprocess.run([shell, '-n'], input=body, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
