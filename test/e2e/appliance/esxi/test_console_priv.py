"""Synthetic transport regressions; no VM, credential, or network operations."""
import base64
import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch


spec = importlib.util.spec_from_file_location('console_priv', Path(__file__).with_name('console-priv.py'))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)


class CapturedHandler(Exception):
    pass


def request(handler_type, method, *, address='192.0.2.2', path='/synthetic', length='2', body=b'0\n'):
    """Invoke the real nested handler without constructing a socket."""
    handler = object.__new__(handler_type)
    handler.client_address = (address, 12345)
    handler.path = path
    handler.headers = {'Content-Length': length}
    handler.rfile = io.BytesIO(body)
    handler.wfile = io.BytesIO()
    statuses = []
    handler.send_error = statuses.append
    handler.send_response = statuses.append
    handler.send_header = lambda *args: None
    handler.end_headers = lambda: None
    getattr(handler, 'do_' + method)()
    return statuses, handler.wfile.getvalue()


class ConsoleTransportTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.sec = Path(directory.name)
        # Synthetic fixture only: never load a real scope or password.
        (self.sec / 'bootstrap-console-password').write_text('synthetic-password', encoding='ascii')
        self.lab = SimpleNamespace(sec=self.sec, guest_ip=lambda timeout: '192.0.2.2')
        self.args = SimpleNamespace(bind='192.0.2.1', as_user=True, nowait=False, timeout=0)
        for target, value in [('b.private_directory', lambda lab: None),
                              ('make_tls', lambda directory: (None, 'sha256//synthetic')),
                              ('Console', lambda lab: SimpleNamespace(shell=lambda password: None)),
                              ('secrets.token_hex', lambda size: 'synthetic')]:
            # The dynamically loaded module is not registered in sys.modules;
            # resolve nested owners directly rather than importing it by name.
            if '.' in target:
                owner, attribute = target.split('.')
                context = patch.object(getattr(transport, owner), attribute, value)
            else:
                context = patch.object(transport, target, value)
            context.start()
            self.addCleanup(context.stop)

    def capture_handler(self):
        holder = {}

        class Server:
            def __init__(self, address, handler):
                holder['handler'] = handler
                raise CapturedHandler()

        with patch.object(transport, 'HTTPServer', Server):
            with self.assertRaises(CapturedHandler):
                transport.execute(self.lab, self.args, b'true\n')
        return holder['handler']

    def test_result_acceptance_and_transport_refusals(self):
        cases = [
            ('success', {}, True, 200),
            ('truncated', {'length': '100'}, True, 400),
            ('invalid_length', {'length': 'invalid'}, True, 400),
            ('wrong_source', {'address': '192.0.2.3'}, True, 403),
            ('wrong_nonce', {'path': '/old/result'}, True, 403),
            ('before_get', {}, False, 403),
            ('oversized', {'length': str(8 * 1024 * 1024 + 1)}, True, 403),
        ]
        for name, overrides, fetched, expected in cases:
            with self.subTest(name=name):
                # Each execute call owns its own nonce directory and handler state.
                with patch.object(transport.secrets, 'token_hex', return_value=name):
                    handler = self.capture_handler()
                if fetched:
                    statuses, script = request(handler, 'GET', path='/' + name)
                    self.assertEqual(statuses, [200])
                    self.assertEqual(script, b'true\n')
                kwargs = {'path': '/' + name + '/result', **overrides}
                self.assertEqual(request(handler, 'POST', **kwargs)[0], [expected])
                # A rejected request must leave the result slot available; a
                # successful request must consume it exactly once.
                if not fetched:
                    request(handler, 'GET', path='/' + name)
                retry = request(handler, 'POST', path='/' + name + '/result')[0]
                self.assertEqual(retry, [403] if name == 'success' else [200])

    def test_only_fresh_trailing_nonce_prompt_can_receive_password(self):
        prompt = 'LAB AUTH SYNTHETIC:'
        screens = [
            'LAB AUTH:\nculvert@appliance:~$',
            'LAB AUTH OLDNONCE:\nculvert@appliance:~$',
            prompt + '\nculvert@appliance:~$',
            'prior output\n' + prompt + ' [317.500001] br-123456789abc: port 1(veth123abcd) entered forwarding state',
        ]
        captured = {}

        class Server:
            server_port = 12345

            def __init__(self, address, handler):
                captured['handler'] = handler

            def serve_forever(self):
                pass

            def shutdown(self):
                pass

            def server_close(self):
                pass

        def enter(value):
            if 'command' not in captured:
                captured['command'] = value
                request(captured['handler'], 'GET')
            else:
                self.assertEqual(screens, [], 'password sent before fresh trailing prompt')
                self.assertEqual(value, 'synthetic-password')
                captured['password_entered'] = True
                request(captured['handler'], 'POST', path='/synthetic/result')

        console = SimpleNamespace(shell=lambda password: None, enter=enter,
                                  screen=lambda deadline: screens.pop(0))
        self.args.as_user = False
        with patch.object(transport, 'HTTPServer', Server), \
                patch.object(transport, 'Console', return_value=console), \
                patch.object(transport.threading, 'Thread'), \
                patch.object(transport.time, 'sleep'), \
                patch.object(transport.sys, 'stdout', SimpleNamespace(buffer=io.BytesIO())):
            self.assertEqual(transport.execute(self.lab, self.args, b'true\n'), 0)
        self.assertTrue(captured['password_entered'])
        self.assertNotIn(prompt, captured['command'])
        self.assertIn(base64.b64encode((prompt + ' ').encode()).decode(), captured['command'])

    def test_password_is_refused_before_fetch_or_after_result(self):
        for completed in (False, True):
            with self.subTest(completed=completed), tempfile.TemporaryDirectory() as directory:
                self.lab.sec = Path(directory)
                (self.lab.sec / 'bootstrap-console-password').write_text('synthetic-password')
                captured = {}

                class Server:
                    server_port = 12345

                    def __init__(self, address, handler):
                        captured['handler'] = handler

                    def serve_forever(self):
                        pass

                    def shutdown(self):
                        pass

                    def server_close(self):
                        pass

                def enter(value):
                    captured.setdefault('inputs', []).append(value)
                    if completed:
                        request(captured['handler'], 'GET')
                        request(captured['handler'], 'POST', path='/synthetic/result')

                console = SimpleNamespace(shell=lambda password: None, enter=enter,
                                          screen=lambda deadline: 'LAB AUTH SYNTHETIC:')
                self.args.as_user = False
                with patch.object(transport, 'HTTPServer', Server), \
                        patch.object(transport, 'Console', return_value=console), \
                        patch.object(transport.threading, 'Thread'), \
                        patch.object(transport.time, 'sleep'), \
                        patch.object(transport.time, 'monotonic', side_effect=[0, 1, 46]):
                    with self.assertRaisesRegex(transport.b.Blocked, 'credential not entered'):
                        transport.execute(self.lab, self.args, b'true\n')
                self.assertEqual(len(captured['inputs']), 1)
                self.assertNotIn('synthetic-password', captured['inputs'][0])


class SudoPromptTests(unittest.TestCase):
    prompt = 'LAB AUTH 0123456789ABCDEF:'
    kernel = '[317.500001] br-123456789abc: port 1(veth123abcd) entered forwarding state'

    def test_exact_prompt_and_only_known_kernel_diagnostics_are_accepted(self):
        lines = [self.kernel,
                 '[318.1] docker0: port 2(veth123abcd) entered blocking state',
                 '[318.2] br-123456789abc: port 1(veth123abcd) entered disabled state',
                 '[318.3] veth123abcd: entered allmulticast mode',
                 '[318.4] veth123abcd: left promiscuous mode',
                 '[318.5] device veth123abcd entered promiscuous mode',
                 '[318.6] eth0: renamed from veth123abcd',
                 '[318.7] veth123abcd: renamed from eth0']
        for separator in (' ', '\n', '\r\n'):
            with self.subTest(separator=separator):
                self.assertTrue(transport.sudo_prompt_ready(
                    'old banner\n' + self.prompt + separator + '\n'.join(lines) + '\n  ', self.prompt))
        self.assertTrue(transport.sudo_prompt_ready(self.prompt + ' ', self.prompt))

    def test_ambiguous_or_changed_input_owner_never_receives_credentials(self):
        suffixes = ['\ufffd', self.kernel + '\ufffd', 'bash-5.2$', 'LAB SHELL READY',
                    'Password:', 'Sorry, try again.', self.prompt, 'arbitrary output',
                    '[318.1] arbitrary kernel-looking output',
                    '[318.1] veth123abcd: entered Password: mode',
                    self.kernel + '; echo unexpected', self.kernel + '\nwrapped continuation',
                    self.kernel + '\nLAB AUTH OLDNONCE:',
                    self.kernel + '\n\t', self.kernel + '\r', self.kernel + '\x1b[0m']
        for suffix in suffixes:
            with self.subTest(suffix=suffix):
                self.assertFalse(transport.sudo_prompt_ready(self.prompt + '\n' + suffix, self.prompt))
        for text in ['LAB AUTH OLDNONCE:\n' + self.kernel, 'echo ' + self.prompt,
                     self.prompt[:-1] + '\n' + self.kernel, self.prompt + '\n' + self.prompt,
                     self.prompt + '\nbash-5.2$\n' + self.kernel]:
            with self.subTest(text=text):
                self.assertFalse(transport.sudo_prompt_ready(text, self.prompt))

    def test_observed_unregistering_teardown_is_narrowly_accepted(self):
        observed = ' [  364.833530] veth7eccb72 (unregistering): left allmulticast mode'
        self.assertTrue(transport.sudo_prompt_ready(self.prompt + '\n' + observed, self.prompt))
        self.assertTrue(transport.sudo_prompt_ready(
            self.prompt + '\n' + observed.replace('allmulticast', 'promiscuous'), self.prompt))
        for changed in [observed.replace('left', 'entered'),
                        observed.replace('unregistering', 'unknown'),
                        observed.replace('veth7eccb72', 'eth0'),
                        observed.replace('allmulticast', 'unknown'), observed + ' extra']:
            with self.subTest(changed=changed):
                self.assertFalse(transport.sudo_prompt_ready(self.prompt + '\n' + changed, self.prompt))


class ShellPromptTests(unittest.TestCase):
    def console(self, text):
        console = object.__new__(transport.Console)
        console.lab = SimpleNamespace(state={'name': 'culvert-esxi-synthetic'})
        console.keyboard = Mock()
        console.screen = Mock(return_value=text)
        console.wait = Mock()
        console.wait_shell = Mock()
        return console

    def test_only_owned_trailing_shell_prompt_is_accepted(self):
        console = self.console('')
        good = 'culvert@culvert-esxi-synthetic:~$ '
        self.assertTrue(console.shell_prompt('old banner\n' + good))
        for text in ['LAB SHELL READY', good + '\nPassword:',
                     good.replace('synthetic', 'other'), good.replace('culvert@', 'root@'),
                     good + 'echo command', good.replace('synthetic', 'synth\ufffdetic')]:
            with self.subTest(text=text):
                self.assertFalse(console.shell_prompt(text))

    def test_stale_banner_above_pam_never_receives_input(self):
        console = self.console('Authenticated as culvert\nLAB SHELL READY\nPassword:')
        with self.assertRaises(transport.b.Blocked):
            console.shell('synthetic-password')
        console.keyboard.send.assert_not_called()
        console.wait_shell.assert_not_called()

    def test_default_recovery_prompt_waits_for_cursor_off(self):
        console = self.console('')
        self.assertTrue(console.shell_prompt('LAB AUTH OLDNONCE:\nLAB SHELL READY\nbash-5.2$ '))
        for text in ['bash-5.2$ \ufffd', 'bash-5.2$\nLAB AUTH NEWNONCE:',
                     'bash-5.2$\nPassword:', 'echo bash-5.2$', 'bash-5.2#']:
            with self.subTest(text=text):
                self.assertFalse(console.shell_prompt(text))
        console.screen = Mock(side_effect=['LAB SHELL READY\nbash-5.2$ \ufffd',
                                          'LAB SHELL READY\nbash-5.2$ '])
        console.deadline = transport.time.monotonic() + 60
        console.budget = Mock(return_value=1)
        with patch.object(transport.time, 'sleep'):
            transport.Console.wait_shell(console)
        self.assertEqual(console.screen.call_count, 2)
        console.keyboard.send.assert_not_called()

    def test_menu_navigation_requires_actual_shell_prompt(self):
        console = self.console('Authenticated as culvert\nMenu')
        console.shell('synthetic-password')
        self.assertEqual(console.keyboard.send.call_args_list, [call('KEY_0'), call('KEY_3')])
        console.wait_shell.assert_called_once_with()

    def test_kernel_output_allows_one_redraw_then_requires_exact_prompt(self):
        console = self.console('')
        disrupted = 'LAB AUTH OLDNONCE:\nLAB SHELL READY\nbash-5.2$ [317.5] br-test: port entered forwarding state'
        console.screen = Mock(side_effect=[disrupted, disrupted + '\n[318.0] more output',
                                          'bash-5.2$ \ufffd', 'bash-5.2$ '])
        console.deadline = transport.time.monotonic() + 60
        console.budget = Mock(return_value=1)
        with patch.object(transport.time, 'sleep'):
            transport.Console.wait_shell(console)
        console.keyboard.send.assert_called_once_with('KEY_CTRL_L')
        self.assertEqual(console.screen.call_count, 4)

    def test_no_redraw_without_shell_marker_or_after_authentication_prompt(self):
        console = self.console('')
        kernel = '\n[317.5] br-test: state changed'
        for text in [kernel, 'bash-5.2$' + kernel,
                     'LAB SHELL READY\nPassword:' + kernel,
                     'LAB SHELL READY\nNew password: \ufffd' + kernel,
                     'LAB SHELL READY\nLAB AUTH NEWNONCE:' + kernel]:
            with self.subTest(text=text):
                self.assertFalse(console.can_redraw_shell(text))

    def test_redraw_never_waives_the_shell_observation_deadline(self):
        console = self.console('LAB SHELL READY\nbash-5.2$\n[317.5] br-test: state changed')
        console.deadline = 1000
        console.budget = Mock(return_value=1)
        with patch.object(transport.time, 'monotonic', side_effect=[0, 1, 61]), \
                patch.object(transport.time, 'sleep'):
            with self.assertRaisesRegex(transport.b.Blocked, 'shell prompt unavailable'):
                transport.Console.wait_shell(console)
        console.keyboard.send.assert_called_once_with('KEY_CTRL_L')


if __name__ == '__main__':
    unittest.main()
