import io
import json
import unittest

import raw_keys


class RawKeyTests(unittest.TestCase):
    def test_complete_generated_test_key_found_across_chunk_boundary_without_leak(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        key = ed25519.Ed25519PrivateKey.generate()
        encoded = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        start = 4 * 1024**2 - 25
        data = b'\0' * start + encoded + b'\0' * 100
        report = raw_keys.sweep(io.BytesIO(data), len(data))
        self.assertEqual(len(report['parseable_private_keys']), 1)
        self.assertEqual(report['parseable_private_keys'][0]['offset'], start)
        self.assertNotIn('BEGIN PRIVATE', json.dumps(report))
        self.assertNotIn(encoded.decode(), json.dumps(report))

    def test_compiled_marker_is_not_private_key_material(self):
        data = b'compiled -----BEGIN PRIVATE KEY----- constant'
        self.assertEqual(raw_keys.parseable_keys(data), [])

    def test_short_input_and_expired_budget_fail(self):
        with self.assertRaises(ValueError):
            raw_keys.sweep(io.BytesIO(b'a'), 2)
        with self.assertRaises(ValueError):
            raw_keys.sweep(io.BytesIO(b'a'), 1, seconds=-1)


if __name__ == '__main__':
    unittest.main()
