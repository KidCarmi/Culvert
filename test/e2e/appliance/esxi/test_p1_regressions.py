"""Synthetic P1 evidence tests. Never access a VM, local credentials, or PAM."""
import base64
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('p1_regressions', Path(__file__).with_name('p1-regressions.py'))
p1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p1)


def identity(new=False):
    return {'source': p1.SOURCE, 'boot_id': ('22222222' if new else '11111111') + '-1111-4111-8111-111111111111',
            'machine_id': ('b' if new else 'a') * 32,
            'ssh_public': 'ssh-ed25519 ' + base64.b64encode((b'b' if new else b'a') * 51).decode() + ' fixture'}


class RegressionEvidenceTests(unittest.TestCase):
    def test_all_identity_boundaries_are_required(self):
        before = {'phase': 'identity-before-reset', 'identity': identity()}
        after = {'phase': 'identity-after-reset', 'identity': identity(True), 'operator_keys_empty': True,
                 'old_password': {'service': 'login', 'pam_status': 7, 'password_prompts': 1}}
        self.assertTrue(p1.validate_identity(before, after))
        for field in ('boot_id', 'machine_id', 'ssh_public'):
            bad = copy.deepcopy(after)
            bad['identity'][field] = before['identity'][field]
            self.assertFalse(p1.validate_identity(before, bad), field)
        for field, value in [('operator_keys_empty', False),
                             ('old_password', {'service': 'login', 'pam_status': 0, 'password_prompts': 1}),
                             ('old_password', {'service': 'login', 'pam_status': 7, 'password_prompts': 0}),
                             ('old_password', {'service': 'login', 'pam_status': 7, 'password_prompts': 2})]:
            bad = copy.deepcopy(after)
            bad[field] = value
            self.assertFalse(p1.validate_identity(before, bad))
        bad = copy.deepcopy(after)
        bad['identity']['boot_id'] = 'not-a-boot-id'
        self.assertFalse(p1.validate_identity(before, bad))

    def test_network_requires_real_apply_failure_exact_restore_and_reboot(self):
        snapshot = {'identity': identity(), 'network': {'address': '192.0.2.2/24', 'gateway': '192.0.2.1', 'interface': 'ens160'},
                    'netplan': {'exists': False}}
        before = {'phase': 'network-before-reboot', 'source': p1.SOURCE, 'helper_exit': 1, 'health': True,
                  'before': copy.deepcopy(snapshot), 'after': copy.deepcopy(snapshot),
                  'injection_sequence': ['generate', 'apply', 'real-apply-succeeded-inject-71', 'generate', 'apply', 'real-rollback-apply-succeeded']}
        after = {'phase': 'network-after-reboot', 'source': p1.SOURCE, 'health': True,
                 'before': copy.deepcopy(snapshot), 'after': copy.deepcopy(snapshot)}
        after['after']['identity']['boot_id'] = identity(True)['boot_id']
        self.assertTrue(p1.validate_network(before, after))
        for section, field, value in [('after', 'netplan', {'exists': True}),
                                      ('after', 'network', {'address': '192.0.2.3/24'})]:
            bad = copy.deepcopy(after)
            bad[section][field] = value
            self.assertFalse(p1.validate_network(before, bad))
        bad = copy.deepcopy(after)
        bad['after']['identity']['boot_id'] = snapshot['identity']['boot_id']
        self.assertFalse(p1.validate_network(before, bad))
        for field, value in [('helper_exit', 0), ('health', False), ('injection_sequence', ['generate', 'apply'])]:
            bad = copy.deepcopy(before)
            bad[field] = value
            self.assertFalse(p1.validate_network(bad, after))

    def test_exclusive_records_cannot_overwrite_previous_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'attempt.json'
            p1.save_new(path, {'status': 'blocked'})
            with self.assertRaises(FileExistsError):
                p1.save_new(path, {'status': 'pass'})
            self.assertEqual(p1.read_record(path), {'status': 'blocked'})


if __name__ == '__main__':
    unittest.main()
