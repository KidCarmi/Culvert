import base64
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('evidence', Path(__file__).with_name('production-evidence-controller.py'))
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class SamplerBindingTests(unittest.TestCase):
    def payload(self, raw):
        return {'result': 'active_snapshot', 'encoding': 'gzip+base64',
                'data': base64.b64encode(gzip.compress(raw)).decode(),
                'uncompressed_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

    def test_hash_and_length_bind_actual_sampler(self):
        raw = b'{"kind":"header"}\n'
        p = self.payload(raw)
        self.assertEqual(evidence.unpack_sampler(p), [{'kind': 'header'}])
        for key, value in [('sha256', '0'*64), ('uncompressed_bytes', len(raw)+1), ('result', 'byte_limit')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                evidence.unpack_sampler(dict(p, **{key: value}))

    def test_compressed_oversize_refused_without_unbounded_decompression(self):
        raw = b'x'*(8*1024*1024+1)
        with self.assertRaises(ValueError):
            evidence.unpack_sampler(self.payload(raw))


if __name__ == '__main__':
    unittest.main()
