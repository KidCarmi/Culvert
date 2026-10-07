"""Offline prerequisite-continuation tests; no VM, keyboard or credentials."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('access_bootstrap_resume', Path(__file__).with_name('access-aware-bootstrap.py'))
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)
UUID = '11111111-1111-4111-8111-111111111111'
PRECHECK = access.precheck_private_tool


class PreparationResumeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.run = Path(temporary.name)
        self.sec = self.run / 'secrets'
        self.sec.mkdir()
        self.lab = SimpleNamespace(run=self.run, sec=self.sec, state={'uuid': UUID},
                                   c={'credential_mode': 'none'}, vm=Mock(), record=Mock())
        (self.sec / 'import.json').write_text(json.dumps({'PropertyMapping': []}))
        self.marker = self.sec / 'access-bootstrap-attempt.json'
        self.original = {'status': 'blocked', 'stage': 'private-tool-preparation', 'uuid': UUID}
        self.marker.write_text(json.dumps(self.original))

    def test_exact_preparation_boundary_binds_old_marker_and_helper_identity(self):
        raw = self.marker.read_bytes()
        result = access.tool_preparation_continuation(self.lab, self.marker)
        self.assertEqual(result['prior_marker_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['bootstrap_helper_sha256'], hashlib.sha256(Path(access.__file__).read_bytes()).hexdigest())
        self.assertEqual(len(result['keyboard_source_sha256']), 64)
        self.assertEqual(self.marker.read_bytes(), raw)

    def test_wrong_vm_stage_status_and_extra_fields_are_refused(self):
        for change in ({'uuid': 'other'}, {'stage': 'initial-capture'}, {'stage': 'password'},
                       {'status': 'started'}, {'status': 'passed'}, {'extra': 'unknown'}):
            with self.subTest(change=change):
                self.marker.write_text(json.dumps(dict(self.original, **change)))
                with self.assertRaises(access.bootstrap.Blocked):
                    access.tool_preparation_continuation(self.lab, self.marker)

    def test_any_credential_capture_or_private_build_artifact_refuses_resume(self):
        names = ['bootstrap-console-password', 'bootstrap-001.txt', 'bootstrap-pixels-001.png',
                 'capture-private', 'screenshot.png', 'console-observation.txt', 'transport-private',
                 'private-keystrokes.exe', 'private-keyboard-build.json', 'go-cache', 'go-build123',
                 'access-bootstrap-observation-extension.json', 'access-bootstrap-tool-preparation-extension.json']
        for name in names:
            with self.subTest(name=name):
                artifact = self.sec / name
                artifact.write_bytes(b'')
                try:
                    with self.assertRaises(access.bootstrap.Blocked):
                        access.tool_preparation_continuation(self.lab, self.marker)
                finally:
                    artifact.unlink()

    def invoke_main(self, flow):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(access, 'precheck_private_tool'))
        stack.enter_context(patch.object(access.bootstrap.module, 'Lab', return_value=self.lab))
        stack.enter_context(patch.object(access.bootstrap.module, 'locked', return_value=contextlib.nullcontext()))
        stack.enter_context(patch.object(access.bootstrap.module, 'validate_scope'))
        stack.enter_context(patch.object(access.bootstrap, 'private_directory'))
        keyboard = stack.enter_context(patch.object(access.bootstrap, 'PrivateKeyboard'))
        factory = stack.enter_context(patch.object(access.bootstrap, 'Bootstrap', return_value=flow))
        stack.enter_context(patch('sys.argv', ['access-aware-bootstrap.py', '--scope', 'synthetic.json', '--resume-tool-preparation']))
        output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return keyboard, factory, output

    def test_continuation_preserves_original_and_cannot_be_reentered(self):
        original = self.marker.read_bytes()
        flow = Mock()
        keyboard, factory, output = self.invoke_main(flow)
        access.main()
        continuation = self.sec / 'access-bootstrap-tool-preparation-extension.json'
        record = json.loads(continuation.read_text())
        self.assertEqual(record['status'], 'passed')
        self.assertEqual(record['uuid'], UUID)
        self.assertEqual(record['prior_marker_sha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual(self.marker.read_bytes(), original)
        flow.authenticate.assert_called_once_with()
        self.assertTrue(factory.call_args.kwargs['capture_prefix'].startswith('bootstrap-tool-extension'))
        self.assertIn('keyboard source SHA256', output.getvalue())
        with self.assertRaises(access.bootstrap.Blocked):
            access.main()
        keyboard.assert_called_once()
        flow.authenticate.assert_called_once()

    def test_failed_continuation_keeps_its_marker_and_never_retries_authentication(self):
        flow = Mock(stage='initial-capture')
        flow.authenticate.side_effect = access.bootstrap.Blocked('synthetic observation stopped')
        keyboard, _, _ = self.invoke_main(flow)
        with self.assertRaises(SystemExit):
            access.main()
        record = json.loads((self.sec / 'access-bootstrap-tool-preparation-extension.json').read_text())
        self.assertEqual((record['status'], record['stage']), ('blocked', 'initial-capture'))
        self.assertEqual(json.loads(self.marker.read_text()), self.original)
        with self.assertRaises(access.bootstrap.Blocked):
            access.main()
        keyboard.assert_called_once()

    def write_blocked_observation(self):
        record = {'status': 'blocked', 'stage': 'initial-capture', 'uuid': UUID,
                  'prior_marker_sha256': hashlib.sha256(self.marker.read_bytes()).hexdigest(),
                  'bootstrap_helper_sha256': access.TOOL_OBSERVATION_HELPER_SHA256,
                  'keyboard_source_sha256': hashlib.sha256((access.HERE / 'private-keystrokes.go').read_bytes()).hexdigest()}
        path = self.sec / 'access-bootstrap-tool-preparation-extension.json'
        path.write_text(json.dumps(record))
        return path, record

    def test_bound_tool_observation_resumes_without_changing_either_prior_marker(self):
        extension, record = self.write_blocked_observation()
        originals = self.marker.read_bytes(), extension.read_bytes()
        result = access.observation_continuation(self.lab, self.marker)
        self.assertEqual(result['prior_marker_sha256'], hashlib.sha256(originals[1]).hexdigest())
        self.assertEqual(result['original_marker_sha256'], hashlib.sha256(originals[0]).hexdigest())
        self.assertEqual((self.marker.read_bytes(), extension.read_bytes()), originals)

    def test_observation_rejects_unfinished_auth_or_changed_bindings(self):
        extension, record = self.write_blocked_observation()
        for change in ({'status': 'started'}, {'status': 'passed'}, {'stage': 'password'},
                       {'uuid': 'wrong'}, {'prior_marker_sha256': '0'*64},
                       {'bootstrap_helper_sha256': '0'*64}, {'keyboard_source_sha256': '0'*64},
                       {'unknown': True}):
            with self.subTest(change=change):
                extension.write_text(json.dumps(dict(record, **change)))
                with self.assertRaises(access.bootstrap.Blocked):
                    access.observation_continuation(self.lab, self.marker)
        extension.write_text(json.dumps(record))
        for name in ('bootstrap-console-password', 'access-bootstrap-observation-extension.json'):
            path = self.sec / name
            path.write_bytes(b'')
            try:
                with self.assertRaises(access.bootstrap.Blocked):
                    access.observation_continuation(self.lab, self.marker)
            finally:
                path.unlink()

    def test_observation_original_legacy_boundary_remains_exact(self):
        self.lab.c['console_cell_width'] = 9
        self.marker.write_text(json.dumps(dict(self.original, stage='initial-capture')))
        result = access.observation_continuation(self.lab, self.marker)
        self.assertEqual(result['console_cell_width'], 9)
        self.assertEqual(result['pixel_decoder_sha256'], hashlib.sha256((access.HERE / 'pixel-console.py').read_bytes()).hexdigest())
        self.write_blocked_observation()
        with self.assertRaises(access.bootstrap.Blocked):
            access.observation_continuation(self.lab, self.marker)

    def test_observation_continuation_is_exclusive_and_preserves_failed_history(self):
        extension, _ = self.write_blocked_observation()
        originals = self.marker.read_bytes(), extension.read_bytes()
        flow = Mock(stage='initial-capture')
        flow.authenticate.side_effect = access.bootstrap.Blocked('synthetic capture expiry')
        keyboard, _, _ = self.invoke_main(flow)
        with patch('sys.argv', ['access-aware-bootstrap.py', '--scope', 'synthetic.json', '--resume-initial-observation']):
            with self.assertRaises(SystemExit):
                access.main()
            with self.assertRaises(access.bootstrap.Blocked):
                access.main()
        self.assertEqual((self.marker.read_bytes(), extension.read_bytes()), originals)
        result = json.loads((self.sec / 'access-bootstrap-observation-extension.json').read_text())
        self.assertEqual((result['status'], result['stage']), ('blocked', 'initial-capture'))
        self.assertEqual(result['prior_marker_sha256'], hashlib.sha256(originals[1]).hexdigest())
        keyboard.assert_called_once()
        flow.authenticate.assert_called_once()

    def test_missing_dependency_stops_before_lab_or_attempt_creation(self):
        self.marker.unlink()
        with patch('sys.argv', ['access-aware-bootstrap.py', '--scope', 'synthetic.json']), \
                patch.object(access.bootstrap.module, 'Lab') as factory, \
                patch.object(access, 'precheck_private_tool', side_effect=lambda: PRECHECK(self.run)):
            # Call the real cheap check with only an isolated synthetic root.
            with self.assertRaises(access.bootstrap.Blocked):
                access.main()
        factory.assert_not_called()
        self.assertFalse(self.marker.exists())

    def test_precheck_requires_dependency_and_compiler(self):
        with self.assertRaisesRegex(access.bootstrap.Blocked, 'govmomi'):
            PRECHECK(self.run)
        dependency = self.run / '.tools/govmomi-v0.56.0-src/go.mod'
        dependency.parent.mkdir(parents=True)
        dependency.write_text('module synthetic')
        with patch.object(access.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(access.bootstrap.Blocked, 'compiler'):
                PRECHECK(self.run)
        with patch.object(access.shutil, 'which', return_value='synthetic-go'):
            PRECHECK(self.run)

    def test_resume_modes_are_mutually_exclusive(self):
        with patch('sys.argv', ['access-aware-bootstrap.py', '--scope', 'synthetic.json',
                               '--resume-tool-preparation', '--resume-initial-observation']), \
                patch.object(access, 'precheck_private_tool') as precheck, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                access.main()
        precheck.assert_not_called()


if __name__ == '__main__':
    unittest.main()
