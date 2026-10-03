"""Run with: python -m unittest discover -s appliance/console -p 'test_*.py'."""
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

import console_status as status
import culvert_console as console


class StateTests(unittest.TestCase):
    def summary(self, markers=(), unit=None, health='', setup=None, ready=None):
        return status.summarize(markers, unit or {}, health, setup or {}, ready or {})

    def test_ordering_cycle_is_not_running_not_fake_progress(self):
        got = self.summary(unit={'ActiveState': 'inactive', 'Result': 'success'})
        self.assertEqual(got['reason'], 'FIRSTBOOT_NOT_RUNNING')

    def test_auto_restart_keeps_failure_visible(self):
        got = self.summary(unit={'ActiveState': 'activating', 'Result': 'exit-code'})
        self.assertEqual(got['phase'], 'failed')

    def test_running(self):
        self.assertEqual(self.summary(unit={'ActiveState': 'activating', 'Result': 'success'})['phase'], 'running')

    def test_stale_done_does_not_hide_a_failed_unit(self):
        self.assertEqual(self.summary(['complete'], {'ActiveState': 'failed'})['phase'], 'failed')

    def test_complete_marker_never_means_application_ready(self):
        self.assertEqual(self.summary(['complete'])['reason'], 'APPLICATION_UNAVAILABLE')

    def test_setup_unavailable_is_not_enrolled(self):
        got = self.summary(['complete'], health='200')
        self.assertEqual(got['reason'], 'SETUP_UNKNOWN')
        self.assertFalse(got['administrator_enrolled'])

    def test_setup_needs_real_boolean(self):
        for value in ('false', 0, None):
            self.assertFalse(self.summary(setup={'needsSetup': value})['administrator_enrolled'])

    def test_setup_required(self):
        self.assertEqual(self.summary(['complete'], health='200', setup={'needsSetup': True})['reason'], 'SETUP_REQUIRED')

    def test_strict_readiness_rows_and_http_required(self):
        ready = {'_http': '200', 'checks': {key: {'status': 'ok'} for key in
                 ('policy_loaded', 'policy_posture', 'ca', 'setup_complete')}}
        valid = self.summary(['complete'], health='200', setup={'needsSetup': False}, ready=ready)
        self.assertEqual(valid['phase'], 'ready')
        self.assertFalse(valid['traffic_verified'])
        for key in ready['checks']:
            broken = json.loads(json.dumps(ready))
            del broken['checks'][key]
            self.assertNotEqual(self.summary(['complete'], health='200',
                setup={'needsSetup': False}, ready=broken)['phase'], 'ready')
        ready['_http'] = '503'
        self.assertNotEqual(self.summary(['complete'], health='200',
            setup={'needsSetup': False}, ready=ready)['phase'], 'ready')

    def test_malformed_checks_are_unknown(self):
        for checks in (None, [], {'ca': 'ok'}):
            self.assertNotEqual(self.summary(['complete'], health='200',
                setup={'needsSetup': False}, ready={'checks': checks})['phase'], 'ready')

    def test_unknown_unit(self):
        self.assertEqual(self.summary()['phase'], 'unknown')


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.build = self.root / 'build.json'
        self.build.write_text(json.dumps({'appliance': {'version': 'test'},
                              'candidate': {'candidate': True}, 'secret': 'NEVER_DISPLAY'}))
        (self.root / 'ovf.done').touch()
        (self.root / 'console.done').touch()
        (self.root / '.env').write_text('CULVERT_SETUP_TOKEN=NEVER_DISPLAY')
        self.calls = []
        (self.root / 'net/eth0/device').mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def run_probe(self, args):
        self.calls.append(args)
        if args[0].endswith('systemctl'):
            return 'ActiveState=failed\nResult=exit-code\nExecMainStatus=1\nSECRET=NEVER_DISPLAY'
        if args[0].endswith('/ip'):
            return json.dumps([{'ifname': 'eth0', 'addr_info': [{'family': 'inet', 'local': '192.0.2.10'},
                       {'family': 'inet', 'local': '127.0.0.1'},
                       {'family': 'inet', 'local': '169.254.1.2'}]}])
        return ''

    def test_collect_works_when_application_and_docker_unavailable(self):
        got = status.collect(self.root, self.build, self.run_probe, self.root / 'net')
        self.assertEqual(got['reason'], 'FIRSTBOOT_FAILED')
        self.assertEqual(got['management_urls'], ['https://192.0.2.10:9090'])
        self.assertEqual(got['steps'][0]['state'], 'recorded')
        self.assertEqual(got['steps'][2]['state'], 'not_recorded')
        self.assertTrue(got['candidate'])
        self.assertNotIn('NEVER_DISPLAY', json.dumps(got))
        self.assertFalse(any('docker' in ' '.join(call) for call in self.calls))

    def test_docker_bridge_is_not_a_management_address(self):
        def probe(args):
            if args[0].endswith('/ip'):
                return json.dumps([{'ifname': 'docker0', 'addr_info': [
                    {'family': 'inet', 'local': '172.17.0.1'}]}])
            return self.run_probe(args)
        got = status.collect(self.root, self.build, probe, self.root / 'net')
        self.assertEqual(got['management_urls'], [])

    def test_missing_files_commands_and_network(self):
        got = status.collect(self.root / 'absent', self.root / 'absent.json', lambda _: '')
        self.assertEqual(got['phase'], 'unknown')
        self.assertEqual(got['management_urls'], [])
        self.assertIn('No IPv4 address', '\n'.join(status.lines(got)))

    def test_bad_json_shapes_do_not_crash(self):
        for raw in ('{', 'null', '[]', '[null]', '[{"addr_info":null}]'):
            got = status.collect(self.root, self.build, lambda _: raw)
            self.assertEqual(got['phase'], 'unknown')

    def test_terminal_escape_and_bidi_are_not_interpreted(self):
        self.build.write_text(json.dumps({'appliance': {'version': '\u001b[2J\nBAD\u202e'}}))
        got = status.collect(self.root, self.build, self.run_probe)
        self.assertNotIn('\u001b', got['version'])
        self.assertNotIn('\n', got['version'])
        self.assertNotIn('\u202e', got['version'])

    def test_command_failures_do_not_echo_arbitrary_error_data(self):
        with patch.object(status.subprocess, 'run', side_effect=OSError('NEVER_DISPLAY')):
            self.assertEqual(status.command(['/absent']), '')
        with patch.object(status.subprocess, 'run', side_effect=subprocess.TimeoutExpired('x', 4)):
            self.assertEqual(status.command(['/hung']), '')


class ActionTests(unittest.TestCase):
    def test_no_action_without_authenticated_identity(self):
        with patch.object(console, 'admin_identity', return_value=False), patch.object(console, 'execute') as execute:
            for choice in '12456':
                with self.assertRaises(PermissionError):
                    console.action(choice)
            execute.assert_not_called()

    def test_retry_refused_for_running_or_unknown(self):
        with patch.object(console, 'admin_identity', return_value=True), patch('builtins.input', return_value=''), patch.object(console, 'execute') as execute:
            for active in ('active', 'activating', 'unknown'):
                with patch.object(console, 'collect', return_value={'firstboot': {'ActiveState': active}, 'steps': []}):
                    console.action('4')
            execute.assert_not_called()

    def test_retry_does_not_restart_completed_provisioning(self):
        snapshot = {'firstboot': {'ActiveState': 'inactive'},
                    'steps': [{'id': 'complete', 'state': 'recorded'}]}
        with patch.object(console, 'admin_identity', return_value=True), patch.object(console, 'collect', return_value=snapshot), patch('builtins.input', return_value='RETRY'), patch.object(console, 'execute') as execute:
            console.action('4')
            execute.assert_not_called()

    def test_retry_rechecks_state_after_confirmation(self):
        snapshots = [{'firstboot': {'ActiveState': active}, 'steps': []} for active in ('failed', 'active')]
        with patch.object(console, 'admin_identity', return_value=True), patch.object(console, 'collect', side_effect=snapshots), patch('builtins.input', return_value='RETRY'), patch.object(console, 'execute') as execute:
            console.action('4')
            execute.assert_not_called()

    def test_retry_starts_without_interrupting_running_job(self):
        with patch.object(console, 'admin_identity', return_value=True), patch.object(console, 'collect', return_value={'firstboot': {'ActiveState': 'failed'}, 'steps': []}), patch('builtins.input', return_value='RETRY'), patch.object(console, 'execute', return_value=0) as execute:
            console.action('4')
            self.assertEqual(execute.call_count, 2)
            self.assertEqual(execute.call_args.args[0][-3:], ['start', '--no-block', 'culvert-firstboot.service'])

    def test_power_requires_exact_confirmation(self):
        with patch.object(console, 'admin_identity', return_value=True), patch('builtins.input', return_value='reboot; rm'), patch.object(console, 'execute') as execute:
            console.action('5')
            execute.assert_not_called()


class ScreenTests(unittest.TestCase):
    def render(self, key, admin=False, size=(25, 80)):
        window = types.SimpleNamespace(timeout=lambda _: None, erase=lambda: None,
            clear=lambda: None,
            getmaxyx=lambda: size, refresh=lambda: None, getch=lambda: key)
        drawn = []
        window.addstr = lambda row, col, text: drawn.append((row, col, text))
        curses = types.SimpleNamespace(curs_set=lambda _: None, error=RuntimeError,
            KEY_RESIZE=410, KEY_F2=266, KEY_F4=268)
        with tempfile.TemporaryDirectory() as temp:
            snapshot = status.collect(Path(temp), Path(temp) / 'absent', lambda _: '')
        with patch.dict('sys.modules', {'curses': curses}), patch.object(console, 'collect', return_value=snapshot):
            choice = console.screen(window, admin)
        return choice, drawn

    def test_public_number_key_opens_login_not_an_action(self):
        choice, drawn = self.render(ord('2'))
        self.assertEqual(choice, 'login')
        self.assertTrue(any('Sign in' in line for _, _, line in drawn))

    def test_admin_actions_remain_visible_on_vga(self):
        choice, drawn = self.render(ord('q'), admin=True)
        self.assertEqual(choice, 'logout')
        self.assertTrue(any('Restart/shutdown' in line for _, _, line in drawn))
        self.assertTrue(any('Log out' in line for _, _, line in drawn))
        self.assertTrue(all(row < 24 and len(line) < 80 for row, _, line in drawn))

    def test_small_console_clips_without_crashing(self):
        choice, drawn = self.render(ord('2'), size=(8, 20))
        self.assertEqual(choice, 'login')
        self.assertTrue(all(row < 7 and len(line) < 20 for row, _, line in drawn))


if __name__ == '__main__':
    unittest.main()
