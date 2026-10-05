"""Synthetic collector tests only; no guest, Docker or hypervisor calls."""
import base64
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('recovery_collect', Path(__file__).with_name('production-recovery-collect.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
BOOT = '11111111-2222-3333-4444-555555555555'


class CollectorTests(unittest.TestCase):
    def test_correlation_identity_then_optional_image_then_clock(self):
        calls = []
        def read(path, limit):
            calls.append('read')
            if str(path).endswith('boot_id'):
                return BOOT.encode()
            return json.dumps({'source': {'git_commit': 'a' * 40, 'git_dirty': False},
                               'secret': 'synthetic-should-not-export'}).encode()
        def run(*args):
            calls.append('image')
            return {'result': 'ok', 'output': 'sha256:' + 'b' * 64}
        def clock():
            calls.append('clock')
            return {'monotonic_before_ns': 1, 'realtime_ns': 2, 'monotonic_after_ns': 3}
        with mock.patch.object(C, 'read_bounded', side_effect=read), mock.patch.object(C, 'clock_sample', side_effect=clock):
            result = C.correlation(True, run)
        self.assertEqual(calls, ['read', 'read', 'image', 'clock'])
        self.assertNotIn('synthetic', json.dumps(result))
        self.assertEqual(result['boot_id'], BOOT)

    def test_clock_sample_brackets_realtime(self):
        with mock.patch.object(C.time, 'monotonic_ns', side_effect=[12, 17]), mock.patch.object(C.time, 'time_ns', return_value=100):
            self.assertEqual(C.clock_sample(), {'monotonic_before_ns': 12, 'realtime_ns': 100,
                                               'monotonic_after_ns': 17, 'bracket_ns': 5})

    def test_sampler_compression_roundtrip_and_identity(self):
        rows = [{'kind': 'header', 'schema': 1, 'boot_id': BOOT},
                {'kind': 'sample', 'boot_id': BOOT}, {'kind': 'end', 'reason': 'deadline'}]
        raw = b''.join(json.dumps(x).encode() + b'\n' for x in rows)
        result = C.sampler_payload(raw, BOOT)
        self.assertTrue(result['recording_complete'])
        self.assertEqual(gzip.decompress(base64.b64decode(result['data'])), raw)
        self.assertEqual(result['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['uncompressed_bytes'], len(raw))
        with self.assertRaises(ValueError):
            C.sampler_payload(raw, 'different-boot')

    def test_partial_or_oversized_sampler_never_passes(self):
        raw = json.dumps({'kind': 'header', 'schema': 1, 'boot_id': BOOT}).encode() + b'\n'
        self.assertEqual(C.sampler_payload(raw, BOOT)['result'], 'active_snapshot')
        with self.assertRaises(ValueError):
            C.sampler_payload(raw + b'{"kind":', BOOT)
        with self.assertRaises(ValueError):
            C.sampler_payload(raw + b'{"kind":"unexpected"}\n', BOOT)
        with self.assertRaises(ValueError):
            C.sampler_payload(b'[]\n', BOOT)
        limited = C.sampler_payload(raw + b'{"kind":"end","reason":"byte_limit"}\n', BOOT)
        self.assertEqual(limited['result'], 'byte_limit')
        with mock.patch.object(C, 'SAMPLER_LIMIT', 5), self.assertRaises(ValueError):
            C.sampler_payload(raw, BOOT)

    def test_bounded_read_rejects_oversize_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'12345')
            self.assertEqual(C.read_bounded(path, 5), b'12345')
            with self.assertRaises(ValueError):
                C.read_bounded(path, 4)
            if hasattr(C.os, 'O_NOFOLLOW'):
                link = Path(directory) / 'link'
                link.symlink_to(path)
                with self.assertRaises(OSError):
                    C.read_bounded(link, 5)

    def test_child_timeout_output_limit_and_nonzero_are_retained(self):
        start = time.monotonic()
        timed = C.command([sys.executable, '-c', 'import time;time.sleep(10)'], .15, 64)
        self.assertEqual(timed['result'], 'timeout')
        self.assertTrue(timed['timed_out'])
        self.assertLess(time.monotonic() - start, 4)
        overflow = C.command([sys.executable, '-c', 'print("x"*10000)'], 3, 64)
        self.assertEqual(overflow['result'], 'output_limit')
        self.assertEqual(len(overflow['output']), 64)
        failed = C.command([sys.executable, '-c', 'import sys;print("failure-canary");sys.exit(7)'], 3, 100)
        self.assertEqual(failed['result'], 'command_failed')
        self.assertEqual(failed['exit_code'], 7)
        self.assertIn('failure-canary', failed['output'])

    def test_spawn_failure_has_no_raw_exception(self):
        with mock.patch.object(C.subprocess, 'Popen', side_effect=OSError('secret-canary')):
            result = C.command(['not-present'], 1, 64)
        self.assertEqual(result['result'], 'spawn_failed')
        self.assertNotIn('secret-canary', json.dumps(result))

    def test_plan_has_explicit_docker_fields_and_no_config_or_env_dump(self):
        plan = C.command_plan(100)
        self.assertTrue(plan)
        for name, argv, timeout, limit in plan:
            self.assertGreater(timeout, 0)
            self.assertLessEqual(limit, C.MIB)
            self.assertNotIn('config', argv)
            self.assertNotIn('env', argv)
            self.assertNotIn('.env', ' '.join(argv))
            if argv[:2] == ['docker', 'inspect']:
                self.assertIn('--format', argv)
                self.assertNotIn('.Config', ' '.join(argv))
            if argv[:2] in (['docker', 'logs'], ['docker', 'events']):
                self.assertEqual(argv[argv.index('--since') + 1], '100')
            self.assertNotIn('curl', argv)
            self.assertNotIn('up', argv)
        self.assertFalse(any('.env' in path for path in C.HASH_FILES))

    def test_docker_event_template_matches_actor_schema_and_keeps_bounds(self):
        with mock.patch.object(C.time, 'time', return_value=200.9):
            events = [entry for entry in C.command_plan(100) if entry[0] == 'docker_events']
        self.assertEqual(len(events), 1)
        _, argv, timeout, limit = events[0]
        self.assertEqual(argv[:-1], ['docker', 'events', '--since', '100', '--until', '200',
                                   '--filter', 'type=container', '--format'])
        self.assertEqual((timeout, limit), (10, 180000))
        self.assertEqual(argv[-1], '{"timeNano":{{.TimeNano}},"action":{{json .Action}},'
                                  '"id":{{json .Actor.ID}}}')

        # Exercise the real Go template engine against the modern events.Message
        # field shape: ID belongs to Actor, and there is no top-level ID field.
        # Attributes are deliberately present but must never enter the projection.
        go = shutil.which('go')
        self.assertIsNotNone(go, 'Go is required for the Docker event schema regression')
        source = r'''package main
import ("encoding/json"; "io"; "os"; "text/template")
type Actor struct { ID string; Attributes map[string]string }
type Message struct { TimeNano int64; Action string; Actor Actor }
func main() {
    raw, err := io.ReadAll(os.Stdin); if err != nil { os.Exit(2) }
    t, err := template.New("event").Funcs(template.FuncMap{
        "json": func(v any) (string, error) { b, e := json.Marshal(v); return string(b), e },
    }).Parse(string(raw)); if err != nil { os.Exit(3) }
    event := Message{123456789, "health_status: healthy", Actor{
        "synthetic-\"id\\canary", map[string]string{"private": "must-not-export"},
    }}
    if err = t.Execute(os.Stdout, event); err != nil { os.Exit(4) }
}
'''
        env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'event.go'
            path.write_text(source, encoding='utf-8')
            binary = Path(directory) / ('event.exe' if os.name == 'nt' else 'event')
            built = subprocess.run([go, 'build', '-o', str(binary), str(path)], cwd=directory,
                                   env=env, capture_output=True, timeout=60, check=False)
            self.assertEqual(built.returncode, 0, built.stderr.decode(errors='replace'))
            projected = subprocess.run([str(binary)], input=argv[-1], text=True,
                                       capture_output=True, timeout=5, check=False)
            self.assertEqual(projected.returncode, 0)
            self.assertEqual(json.loads(projected.stdout), {
                'timeNano': 123456789, 'action': 'health_status: healthy',
                'id': 'synthetic-"id\\canary'})
            self.assertNotIn('must-not-export', projected.stdout)
            legacy = subprocess.run([str(binary)], input=argv[-1].replace('.Actor.ID', '.ID'),
                                    text=True, capture_output=True, timeout=5, check=False)
            self.assertEqual(legacy.returncode, 4, 'Legacy top-level ID must fail this schema')

    def test_total_cap_omits_payload_and_keeps_failure_metadata(self):
        report = {'full': {'commands': [{'output': '\u0000' * 1000, 'result': 'timeout',
                                         'timed_out': True, 'exit_code': -9}]}}
        raw = C.encode_report(report, 512)
        self.assertLessEqual(len(raw), 512)
        parsed = json.loads(raw)
        self.assertTrue(parsed['output_truncated'])
        row = parsed['full']['commands'][0]
        self.assertTrue(row['timed_out'])
        self.assertEqual(row['result_before_omission'], 'timeout')
        self.assertTrue(row['payload_omitted'])
        self.assertNotIn('output', row)
        with self.assertRaises(ValueError):
            C.encode_report({'metadata': 'x' * 1024}, 512)

    def test_global_deadline_records_unattempted_commands(self):
        runner = mock.Mock()
        def read(path, limit):
            return b'btime 100\n' if path.as_posix().endswith('/proc/stat') else b'canary'
        with mock.patch.object(C, 'read_bounded', side_effect=read), mock.patch.object(C, 'HASH_FILES', ()), \
                mock.patch.object(C.time, 'monotonic', side_effect=[0, 2, 2]), \
                mock.patch.object(C, 'command_plan', return_value=[('one', ['one'], 2, 10), ('two', ['two'], 2, 10)]):
            result = C.full_report({'boot_id': BOOT}, runner, duration=1)
        runner.assert_not_called()
        self.assertEqual([x['result'] for x in result['commands']], ['collection_deadline'] * 2)

    def test_short_stdout_write_is_failure(self):
        stream = mock.Mock()
        stream.buffer.write.return_value = 0
        with mock.patch.object(C.sys, 'platform', 'linux'), mock.patch.object(C.os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(C, 'correlation', return_value={'boot_id': BOOT}), \
                mock.patch.object(C.sys, 'stdout', stream), self.assertRaises(OSError):
            C.main([])


if __name__ == '__main__':
    unittest.main()
