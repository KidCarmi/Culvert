#!/usr/bin/env python3
"""Behavioral checks for metadata/report handling and real ELF evidence."""
import contextlib
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("exceptions", ROOT / ".github/scripts/security-exceptions.py")
EXCEPTIONS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXCEPTIONS)
STATIC = ROOT / ".github/scripts/assert-static-binary.sh"


class MetadataEvidenceTests(unittest.TestCase):
    def check(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ignore"
            path.write_text(text)
            return EXCEPTIONS.check_trivy(path, datetime.date(2026, 10, 3))

    def exception(self, expiry="2026-11-03"):
        return (
            "# exception-owner: @KidCarmi\n"
            "# exception-claim: accepted-risk\n"
            "# exception-scope: application image linux/amd64\n"
            "# exception-evidence: docs/engineering/TECHNICAL-RISK-REGISTER.md#security-suppression-evidence\n"
            f"CVE-2026-14456 exp:{expiry}\n"
        )

    def test_empty_file_and_documented_exception(self):
        self.assertEqual(self.check("# no exceptions\n"), 0)
        self.assertEqual(self.check(self.exception()), 1)

    def test_expired_or_expiring_today_refuses(self):
        for date in ("2026-09-15", "2026-10-03"):
            with self.subTest(date=date), self.assertRaisesRegex(ValueError, "expired"):
                self.check(self.exception(date))

    def test_missing_metadata_or_missing_expiry_refuses(self):
        for text in ("CVE-2026-14456 exp:2026-11-03", "CVE-2026-14456"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.check(text)

    def test_duplicate_invalid_date_or_external_evidence_refuses(self):
        for text in (
            self.exception() * 2,
            self.exception("2026-99-99"),
            self.exception().replace("docs/engineering/TECHNICAL-RISK-REGISTER.md", "https://example.test"),
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.check(text)


class ReportEvidenceTests(unittest.TestCase):
    def test_no_fail_scan_errors_and_empty_scan_are_not_evidence(self):
        for data in (
            {"Golang errors": {"pkg": ["build failed"]}, "Stats": {"files": 1, "found": 0}, "Issues": []},
            {"Golang errors": {}, "Stats": {"files": 0, "found": 0}, "Issues": []},
            {"Golang errors": {}, "Stats": {"files": 1, "found": 0}},
            {"Golang errors": {}, "Stats": {"files": 1, "found": 1}, "Issues": []},
        ):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "report.json"
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    EXCEPTIONS.report_gosec(path, ROOT)

    def test_complete_reports_keep_findings_visible(self):
        issue = {"rule_id": "G704", "file": str(ROOT / "auth_oidc.go"), "line": "304", "details": "SSRF finding"}
        for issues in ([], [issue]):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "report.json"
                path.write_text(json.dumps({"Golang errors": {}, "Stats": {"files": 1, "found": len(issues)}, "Issues": issues}))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    EXCEPTIONS.report_gosec(path, ROOT)
                self.assertIn(f"({len(issues)} findings)", output.getvalue())
                if issues:
                    self.assertIn("auth_oidc.go:304", output.getvalue())
                    self.assertIn("G704", output.getvalue())


class ArtifactEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.source = cls.directory / "main.go"
        cls.source.write_text("package main\nfunc main() {}\n")
        cls.env = dict(os.environ, GO111MODULE="off", GOWORK="off", GOTOOLCHAIN="local", CGO_ENABLED="0", GOFLAGS="-p=2")
        cls.binaries = []
        for arch in ("amd64", "arm64"):
            binary = cls.directory / arch
            subprocess.run(["go", "build", "-o", str(binary), str(cls.source)],
                           cwd=cls.directory, env=dict(cls.env, GOOS="linux", GOARCH=arch), check=True)
            cls.binaries.append(binary)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check(self, binary, script=STATIC):
        return subprocess.run(["bash", str(script), str(binary)], cwd=ROOT,
                              env=self.env, capture_output=True, text=True)

    def test_real_static_binaries_both_platforms(self):
        for binary in self.binaries:
            with self.subTest(platform=binary.name):
                result = self.check(binary)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_or_non_binary_refuses(self):
        for binary in (self.directory / "absent", self.source):
            self.assertNotEqual(self.check(binary).returncode, 0)

    def test_cgo_binary_refuses(self):
        source = self.directory / "cgo.go"
        source.write_text('package main\nimport "C"\nfunc main() {}\n')
        binary = self.directory / "cgo"
        subprocess.run(["go", "build", "-o", str(binary), str(source)], cwd=self.directory,
                       env=dict(self.env, CGO_ENABLED="1", GOOS="linux", GOARCH="amd64"), check=True)
        result = self.check(binary)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing CGO_ENABLED=0", result.stdout)

    def test_dynamic_headers_refuse_even_with_static_build_metadata(self):
        # Mutate ONLY a PT_NOTE header in a genuine static ELF. Go build info
        # remains CGO_ENABLED=0. Never execute these mutated artifacts.
        for header_type in (2, 3):  # PT_DYNAMIC, PT_INTERP
            data = bytearray(self.binaries[0].read_bytes())
            offset = struct.unpack_from("<Q", data, 32)[0]
            size, count = struct.unpack_from("<HH", data, 54)
            for index in range(count):
                position = offset + size * index
                if struct.unpack_from("<I", data, position)[0] == 4:
                    struct.pack_into("<I", data, position, header_type)
                    break
            else:
                self.fail("fixture ELF has no note header to mutate")
            binary = self.directory / f"mutant-{header_type}"
            binary.write_bytes(data)
            result = self.check(binary)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("interpreter or dynamic segment", result.stdout)


if __name__ == "__main__":
    unittest.main()
