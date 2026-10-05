import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('dispatch', Path(__file__).with_name('production-maintenance-dispatch.py'))
dispatch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dispatch)


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.expected = dict(cycle_id='baseline-1', operation_id='a'*32,
                             source_sha='b'*40, image_id='sha256:'+'c'*64, nonce='d'*64)
        self.data = dict(self.expected, schema=1, old_boot_id='12345678-1234-1234-1234-123456789abc',
                         guest_monotonic_ns=12345678, guest_realtime_ns=1791155034000000000)

    def test_wrong_cycle_or_replayed_operation_refused(self):
        for field in self.expected:
            data = dict(self.data)
            data[field] = 'wrong'
            with self.subTest(field=field), self.assertRaises(ValueError):
                dispatch.validate_acceptance(data, self.expected)

    def test_invalid_clock_or_boot_refused(self):
        for field, value in [('guest_monotonic_ns', True), ('guest_realtime_ns', -1),
                             ('guest_realtime_ns', 10**20), ('old_boot_id', 'unknown')]:
            data = dict(self.data)
            data[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                dispatch.validate_acceptance(data, self.expected)

    def test_extra_untrusted_fields_refused(self):
        with self.assertRaises(ValueError):
            dispatch.validate_acceptance(dict(self.data, controller_monotonic_ns=1), self.expected)

    def test_valid_guest_identity(self):
        self.assertEqual(dispatch.validate_acceptance(self.data, self.expected), self.data)

    def test_payload_ack_precedes_unmodified_command(self):
        payload = dispatch.guest_script(dict(self.expected, pin='sha256//example', url='https://example.invalid/nonce')).decode()
        python = payload.split("CULVERT_PRODUCTION_DISPATCH'\n", 1)[1].rsplit('\nCULVERT_PRODUCTION_DISPATCH', 1)[0]
        compile(python, 'guest-dispatch', 'exec')
        self.assertLess(python.index("r.stdout==b'accepted\\n'"), python.index('os.execv'))
        self.assertIn("['culvert-os-update','reboot']", python)
        self.assertNotIn('--force', python)


if __name__ == '__main__':
    unittest.main()
