"""Exercise the reconciled history boundary without a guest or credentials."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
LAB = HERE.parent / 'lab'
BASH = shutil.which('bash')
if os.name == 'nt' and Path('C:/Program Files/Git/bin/bash.exe').is_file():
    BASH = 'C:/Program Files/Git/bin/bash.exe'


class SharedHistoryBoundaryTests(unittest.TestCase):
    def run_library(self, script):
        if not BASH:
            self.skipTest('Bash is required for the shared-library behavioral test')
        with tempfile.TemporaryDirectory() as directory:
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(('LAB_', 'ESXI_'))}
            env.update(LAB_DIR=Path(directory).as_posix(), LAB_EXTERNAL='1',
                       LAB_LIBRARY_ONLY='1')
            result = subprocess.run(
                [BASH, '-c', 'source "$1"\n' + script, 'test',
                 (LAB / 'appliance-lab.sh').as_posix()],
                env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout, sorted(p.name for p in (Path(directory) / 'secrets').iterdir())

    def test_external_history_refuses_before_authentication_export_or_volume_mutation(self):
        output, secrets = self.run_library('''
check() { printf '%s|%s|%s|%s\\n' "$@"; }
# Any transport or host receiver reached after the boundary is an error.
gpriv() { exit 91; }
hist_login() { exit 92; }
api() { exit 93; }
curl() { exit 94; }
upload_rx_start() { exit 95; }
cmd_history
''')
        self.assertEqual(output, 'H|history-recovery|fail|BLOCKED: needs a QEMU guest\n')
        self.assertEqual(secrets, [])

    def test_history_and_rotated_log_phrases_join_existing_redaction(self):
        output, _ = self.run_library('''
printf 'synthetic-history-secret' > "$SEC/history-phrase"
printf 'synthetic-rotated-log-secret' > "$SEC/log-pass-new"
redact_str 'archive=synthetic-history-secret log=synthetic-rotated-log-secret'
''')
        self.assertEqual(output, 'archive=[REDACTED] log=[REDACTED]')

    def test_external_pressure_refuses_before_credentials_origin_or_disk_observation(self):
        output, secrets = self.run_library('''
check() { printf '%s|%s|%s|%s\\n' "$@"; }
gpriv() { exit 91; }
ensure_admin_pass() { exit 92; }
rec_origin_start() { exit 93; }
p_host_free_gb() { exit 94; }
p_host_alloc_mb() { exit 95; }
cmd_pressure
''')
        self.assertEqual(output, 'P|disk-pressure|fail|BLOCKED: bounded QEMU disk-pressure fixture cannot run on ESXi\n')
        self.assertEqual(secrets, [])

    def test_unsupported_console_transport_refuses_before_socket_creation(self):
        spec = importlib.util.spec_from_file_location('shared_console_boundary', LAB / 'console-session.py')
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'dont_write_bytecode', True):
            spec.loader.exec_module(module)
        socket = mock.Mock()
        with mock.patch.object(module, 'socket', SimpleNamespace(socket=socket)):
            with self.assertRaisesRegex(OSError, 'Unix console transport is unavailable'):
                module.Console('never-opened', None)
        socket.assert_not_called()


if __name__ == '__main__':
    unittest.main()
