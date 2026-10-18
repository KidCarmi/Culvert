"""Exercise candidate dispatch offline; guest transports are forbidden stubs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = '246cb73d4b62d7a4baf2fcb8558ad8622657529a'
OLD = '6248daf72a5312e75062e2c2823438911604af7f'
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'


class CandidateDispatchTests(unittest.TestCase):
    def test_runner_enables_engine_evidence_for_new_candidate(self):
        line = next(x for x in (HERE/'candidate-run.ps1').read_text().splitlines()
                    if x.startswith('$env:ESXI_ENGINE_SURFACE ='))
        for source, want in ((SOURCE, '1'), (OLD, '1'), ('0'*40, '0')):
            script = "$configuration=@{source_sha='"+source+"'}\n"+line+'\nWrite-Output $env:ESXI_ENGINE_SURFACE'
            result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command', script],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), want)

    def test_lifecycle_hooks_dispatch_both_phases_and_fail_closed(self):
        for source, helper in ((SOURCE, 'lifecycle-shutdown-246.py'), (OLD, 'lifecycle-shutdown.py')):
            for verdict in ('0', '90'):
                with self.subTest(source=source, verdict=verdict), tempfile.TemporaryDirectory() as directory:
                    env = dict(os.environ, ESXI_ENGINE_SOURCE=source, ESXI_BIND='offline',
                               ADAPTER_HERE=HERE.as_posix(), EV=directory, SEC=directory,
                               LAB_HOST='offline', ESXI_SCOPE='offline', VERDICT=verdict)
                    script = r'''
set -euo pipefail
api() { :; }
gpriv() { cat; }
python3() {
  case "$1" in
    */lifecycle-shutdown*.py)
      printf '%s %s\n' "${1##*/}" "$2" >> "$EV/dispatch.txt"
      [[ $2 != verify ]] || return "$VERDICT"
      printf '{}\n';;
    */timing-diagnostic.py)
      [[ $2 != observe ]] || printf '{}\n' > "$EV/timing-maintenance.jsonl";;
    -) cat >/dev/null;;
    *) return 91;;
  esac
}
check() { printf '%s\n' "$*" >> "$EV/checks.txt"; }
source "$ADAPTER_HERE/candidate-hooks.sh"
esxi_p1_stage() { printf '%s\n' "$1" >> "$EV/network.txt"; }
STOP=0
lab_before_reboot
rc=0
lab_after_reboot_observation || rc=$?
[[ $rc == "$VERDICT" ]]
if [[ $VERDICT == 90 ]]; then [[ $STOP == 1 ]]; else [[ $STOP == 0 ]]; fi
'''
                    result = subprocess.run([BASH, '-c', script], env=env, capture_output=True,
                                            text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr+result.stdout)
                    root = Path(directory)
                    self.assertEqual((root/'dispatch.txt').read_text().splitlines(),
                                     [helper+' '+phase for phase in ('before', 'after', 'verify')])
                    expected = ['network-before'] + (['network-after'] if verdict == '0' else [])
                    self.assertEqual((root/'network.txt').read_text().splitlines(), expected)

    def test_restore_allowlist_checks_apply_before_and_after_to_new_candidate(self):
        source = (HERE/'restore-checks.sh').read_text()
        conditions = [x.split(' && ', 1)[0].strip()[3:] for x in source.splitlines()
                      if '&& ! esxi_restore_assert_allowlist ' in x]
        self.assertEqual(len(conditions), 2)
        for candidate, want in ((SOURCE, 0), (OLD, 0), ('0'*40, 1)):
            for condition in conditions:
                result = subprocess.run([BASH, '-c', condition], capture_output=True,
                                        env=dict(os.environ, ESXI_ENGINE_SOURCE=candidate), timeout=10)
                self.assertEqual(result.returncode, want, result.stderr)


if __name__ == '__main__':
    unittest.main()
