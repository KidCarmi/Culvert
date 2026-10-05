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
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('early_readahead', HERE / 'production-early-readahead.py')
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)
COMMON = dict(need=p.need, hashlib=hashlib, os=os, re=re, stat=stat, file_hash=p.file_hash)
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
