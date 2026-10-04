import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

spec=importlib.util.spec_from_file_location('enroll',Path(__file__).with_name('operator-enroll.py'))
enroll=importlib.util.module_from_spec(spec);spec.loader.exec_module(enroll)


class EnrollmentContinuationTests(unittest.TestCase):
    def test_continuation_requires_verified_no_mutation_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as directory:
            lab=SimpleNamespace(sec=Path(directory),state={'uuid':'synthetic'},record=Mock())
            marker=enroll.prepare_attempt(lab)
            old=marker.read_bytes()
            transport=lab.sec/('transport-'+'a'*48);transport.mkdir()
            result=transport/'result';result.write_bytes(b'0\nNO_ENROLLMENT_MUTATION_AND_FIRSTBOOT_COMPLETE\n')
            self.assertEqual(enroll.prepare_attempt(lab,result),marker)
            self.assertEqual((lab.sec/'operator-enrollment-initial-attempt.json').read_bytes(),old)
            self.assertEqual(lab.record.call_args.args[1],'fail')
            with self.assertRaises(FileExistsError):enroll.prepare_attempt(lab,result)

    def test_unknown_dispatch_or_existing_host_pin_refuses_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            lab=SimpleNamespace(sec=Path(directory),state={'uuid':'synthetic'},record=Mock())
            enroll.prepare_attempt(lab)
            transport=lab.sec/('transport-'+'b'*48);transport.mkdir()
            result=transport/'result';result.write_bytes(b'0\npartial\n')
            with self.assertRaises(ValueError):enroll.prepare_attempt(lab,result)
            result.write_bytes(b'0\nNO_ENROLLMENT_MUTATION_AND_FIRSTBOOT_COMPLETE\n')
            (lab.sec/'known_hosts').write_text('synthetic')
            with self.assertRaises(ValueError):enroll.prepare_attempt(lab,result)
            self.assertFalse((lab.sec/'operator-enrollment-resume-attempt.json').exists())


if __name__=='__main__':unittest.main()
