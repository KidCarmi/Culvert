"""Offline synthetic proof execution; no console, hypervisor or guest calls."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('early_journal_proof_test', HERE / 'production-early-journal-proof.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
early = p.load('early_journal_test_original', 'production-early-readahead.py')
CAMPAIGN = '13222c13-21fb-4ad3-ad38-48d0acf84778'
BOOT = 'f73683af-9965-4dca-869d-3e37bd8c90ad'
# Sanitized exact journalctl short-monotonic shape from the authenticated A boot.
JOURNAL = ('[    2.902043] fixture-host unknown: CULVERT_LAB_EARLY_RA campaign=' + CAMPAIGN
           + ' boot=' + BOOT + ' profile=128 result=applied old=128 effective=128 uptime=2.87 reason=verified\n'
           '[    2.999911] fixture-host kernel: EXT4-fs (sda1): mounted filesystem fixture-root ro with ordered data mode. Quota mode: none.\n')


class ProofTests(unittest.TestCase):
    def run_proof(self, journal=JOURNAL, profile='A', mutation=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            boot_path = root / 'proc/sys/kernel/random/boot_id'
            boot_path.parent.mkdir(parents=True); boot_path.write_text(BOOT)
            active = root / ('boot/initrd.img-' + early.KERNEL)
            active.parent.mkdir(); active.write_bytes(b'controlled initrd bytes')
            state = root / ('var/lib/culvert-lab-early-read-ahead-campaigns/' + CAMPAIGN)
            state.mkdir(parents=True); (state / 'receipt.json').write_text('{"fixture":true}')
            digest = hashlib.sha256(active.read_bytes()).hexdigest()
            record = {'active': profile, 'exported': True, 'before_boot': '00000000-0000-0000-0000-000000000001',
                      'stages': {'A': {'bytes': active.stat().st_size, 'sha256': digest}}, 'preserved': {}}
            config = {'profile': profile, 'campaign': CAMPAIGN, 'kernel': early.KERNEL,
                      'original_sha': digest, 'original_bytes': active.stat().st_size,
                      'ra_guest_b64': base64.b64encode(b'def trusted_dir(*args): pass\n').decode(),
                      'owner_uuid': '12345678-1234-4567-89ab-123456789abc', 'source_sha': early.SOURCE,
                      'image_id': early.IMAGE, 'generator_sha256': p.EARLY_HASH, 'verifier_sha256': 'f' * 64,
                      'prior_failed_verification': {'operation': 'retained'}}
            namespace = {}
            exec(early.GUEST + '\n' + early.COMMON + '\n' + p.PROOF_GUEST, namespace)
            namespace['os'] = SimpleNamespace(geteuid=lambda: 0)
            namespace['pathlib'] = SimpleNamespace(Path=lambda path: root / path.lstrip('/'))
            observed = {'effective': 128, 'boot_id': BOOT}
            calls = []
            namespace['immutable_guard'] = lambda *args: (observed, None, None)
            namespace['receipt_guard'] = lambda *args: copy.deepcopy(record)
            def bounded(command, timeout, limit):
                calls.append(command)
                self.assertEqual(command, p.JOURNAL_COMMAND)
                self.assertEqual(timeout, 30)
                self.assertEqual(limit, 4 * 1024**2)
                if mutation == 'transport':
                    raise ValueError('bounded command failed')
                if mutation == 'boot':
                    boot_path.write_text('00000000-0000-0000-0000-000000000002')
                if mutation == 'receipt':
                    (state / 'receipt.json').write_text('{"changed":true}')
                return journal
            namespace['bounded'] = bounded
            if mutation == 'sameboot':
                record['before_boot'] = BOOT
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                namespace['journal_proof'](config)
            self.assertEqual(len(calls), 1)
            return json.loads(output.getvalue())

    def test_captured_journal_shape_supported_and_proof_bound(self):
        result = self.run_proof()
        self.assertEqual(result['marker']['marker_monotonic_seconds'], 2.902043)
        self.assertEqual(result['marker']['first_root_mount_monotonic_seconds'], 2.999911)
        self.assertEqual(result['boot_id'], BOOT)
        self.assertEqual(result['campaign_generator_sha256'], p.EARLY_HASH)
        self.assertEqual(result['prior_failed_verification'], {'operation': 'retained'})
        self.assertFalse(result['journal_truncated'])

    def test_refuses_empty_duplicate_wrong_boot_profile_and_command_failure(self):
        for text in ('', '-- No entries --', JOURNAL + JOURNAL,
                     JOURNAL.replace(BOOT, '00000000-0000-0000-0000-000000000003'),
                     JOURNAL.replace('profile=128', 'profile=1024'),
                     JOURNAL.replace('[    2.902043]', '[    3.902043]')):
            with self.subTest(text=text[:40]), self.assertRaises(ValueError):
                self.run_proof(text)
        for mutation in ('transport', 'boot', 'receipt', 'sameboot'):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.run_proof(mutation=mutation)

    def test_original_requires_exact_bytes_and_no_hook(self):
        plain = JOURNAL.splitlines()[1] + '\n'
        result = self.run_proof(plain, 'original')
        self.assertTrue(result['marker']['original_initrd_hash_verified'])
        with self.assertRaises(ValueError):
            self.run_proof(JOURNAL, 'original')

    def test_manifest_requires_original_raw_hash_and_frozen_additive_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root / 'early.py'; helper = root / 'proof.py'
            original.write_bytes(b'changed campaign helper'); helper.write_bytes(b'verifier')
            manifest = {'files': {p.EARLY_NAME: p.EARLY_HASH, p.SELF_NAME: p.sha(helper)}}
            with self.assertRaises(ValueError):
                p.freeze_guard(manifest, original, helper)
            # Independently check actual immutable source hash using canonical LF
            # in fixtures, accommodating Git's Windows checkout newline policy.
            original.write_bytes((HERE / 'production-early-readahead.py').read_bytes().replace(b'\r\n', b'\n'))
            p.freeze_guard(manifest, original, helper)
            del manifest['files'][p.SELF_NAME]
            with self.assertRaises(ValueError):
                p.freeze_guard(manifest, original, helper)

    def test_failed_builtin_record_bound_and_never_reclassified(self):
        operation = '9bd3dcdf-5cbd-43fd-946c-f0ae311701e1'
        owner = '12345678-1234-4567-89ab-123456789abc'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ('operation-' + operation); path.mkdir()
            intent = dict(action='verify', profile='A', campaign=CAMPAIGN, owner_uuid=owner,
                          operation=operation, generator_sha256=p.EARLY_HASH)
            (path / 'intent.json').write_text(json.dumps(intent))
            (path / 'payload.sh').write_bytes(b'private retained old payload')
            (path / 'guest-result.json').write_bytes(b'dmesg: mutually exclusive arguments')
            result = p.prior_failure(path, CAMPAIGN, owner)
            self.assertEqual(result['disposition'], 'retained_failed_builtin_verification')
            (path / 'complete.json').write_text('{}')
            with self.assertRaises(ValueError):
                p.prior_failure(path, CAMPAIGN, owner)

    def test_generated_payload_compiles_without_calling_old_main(self):
        body = p.payload(early, {'profile': 'A'})
        self.assertNotIn(b'\r', body)
        python = body.split(b"<<'CULVERT_EARLY_JOURNAL_PROOF'\n", 1)[1].rsplit(b'CULVERT_EARLY_JOURNAL_PROOF\n', 1)[0]
        compile(python, '<offline-journal-proof>', 'exec')
        self.assertIn(b"journal_proof({'profile': 'A'})", python)
        self.assertNotIn(b"\nmain({'profile': 'A'})", python)


if __name__ == '__main__':
    unittest.main()
