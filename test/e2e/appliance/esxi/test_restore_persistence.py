"""Synthetic restore evidence only; no guest, scope, credentials or networking."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('restore_persistence', Path(__file__).with_name('restore-persistence.py'))
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class RestorePersistenceTests(unittest.TestCase):
    def test_restored_policy_requires_exact_mutation_absence_and_enabled_baseline(self):
        mutation = 'esxi-post-backup-block-1791100000-12345'
        baseline = {'name': 'lab-allow-example', 'enabled': True}
        self.assertTrue(validator.validate({'rules': [baseline]}, mutation))
        self.assertFalse(validator.validate({'rules': [baseline, {'name': mutation}]}, mutation))
        # An unrelated marker cannot hide the exact block restored by accident.
        self.assertTrue(validator.validate({'rules': [baseline, {'name': mutation + '-other'}]}, mutation))
        for enabled in (False, None, 1, 'true'):
            self.assertFalse(validator.validate({'rules': [{'name': baseline['name'], 'enabled': enabled}]}, mutation))
        for policy in ({'rules': []}, {'rules': [baseline, None]}, {}, [], None):
            self.assertFalse(validator.validate(policy, mutation))
        for marker in ('', 'esxi-post-backup-block-', 'lab-post-backup', mutation + '\nother'):
            self.assertFalse(validator.validate({'rules': [baseline]}, marker))

    def test_cli_refuses_missing_malformed_and_oversized_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            policy, marker = Path(directory) / 'policy.json', Path(directory) / 'marker.txt'
            args = [str(policy), str(marker)]
            self.assertEqual(validator.main(args), 1)
            marker.write_text('esxi-post-backup-block-1791100000-12345\n', encoding='utf-8')
            policy.write_text(json.dumps({'rules': [{'name': 'lab-allow-example', 'enabled': True}]}), encoding='utf-8')
            self.assertEqual(validator.main(args), 0)
            policy.write_text('{', encoding='utf-8')
            self.assertEqual(validator.main(args), 1)
            policy.write_bytes(b' ' * (1024 * 1024 + 1))
            self.assertEqual(validator.main(args), 1)


if __name__ == '__main__':
    unittest.main()
