"""Synthetic credential-label parsing only; no VM, keyboard or authentication."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('bootstrap_checks', Path(__file__).with_name('bootstrap-checks.py'))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)

# Fixed synthetic fixture, never a credential from an appliance.
FIXTURE = 'AbCdEfGhJkMnPq23'


class ExtractInitialTests(unittest.TestCase):
    def test_legacy_and_new_handoff_preserve_exact_case(self):
        for heading, label in [('INITIAL CONSOLE ACCESS', 'One-time password'),
                               ('INITIAL CONSOLE ACCESS', 'Initial password'),
                               ('LOCAL CONSOLE ACCESS', 'Initial password')]:
            for separator in ('\n', ' '):
                for user in ('', 'User: culvert' + separator):
                    with self.subTest(heading=heading, separator=separator, user=user):
                        text = heading + separator + user + label + ': ' + FIXTURE + '\nL/F2 Sign in'
                        self.assertEqual(bootstrap.extract_initial(text), FIXTURE)
                        self.assertEqual(bootstrap.extract_initial(text.swapcase()), FIXTURE.swapcase())

    def test_rejects_invalid_or_ambiguous_handoff(self):
        valid = 'LOCAL CONSOLE ACCESS\nUser: culvert\nInitial password: ' + FIXTURE
        cases = {
            'duplicate-block': valid + '\n' + valid,
            'duplicate-label': valid + '\nInitial password: ' + FIXTURE,
            'duplicate-malformed-label': valid + '\nOne-time password: invalid',
            'short': valid[:-1],
            'long-valid-alphabet': valid + 'A',
            'long-forbidden-alphabet': valid + '0',
            'forbidden-character': valid[:-1] + '0',
            'trailing-cursor': valid + '_',
            'token-label': 'LOCAL CONSOLE ACCESS\nSetup token: ' + FIXTURE,
            'unrelated-initial': 'INITIAL deployment complete\nInitial password: ' + FIXTURE,
            'unrelated-heading': 'INITIAL CONSOLE ACCESS\nOther status\nInitial password: ' + FIXTURE,
            'mismatched-new': 'LOCAL CONSOLE ACCESS\nOne-time password: ' + FIXTURE,
            'wrong-user': 'LOCAL CONSOLE ACCESS\nUser: root\nInitial password: ' + FIXTURE,
            'heading-in-word': 'NOTLOCAL CONSOLE ACCESS\nInitial password: ' + FIXTURE,
            'missing-heading': 'Initial password: ' + FIXTURE,
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                self.assertIsNone(bootstrap.extract_initial(text))


if __name__ == '__main__':
    unittest.main()
