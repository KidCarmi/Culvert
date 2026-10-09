"""Offline engine evidence regressions; no module or guest operations."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('engine_surface_proof', HERE / 'engine-surface-proof.py')
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


def fixture():
    lines = []
    for name in sorted(proof.MODULES):
        by = 'ib_core' if name == 'ksmbd' else name
        lines += [f'module {name} before=0 final=install /bin/false rc=1 refused-by={by} after=0',
                  f'effective install {name} /bin/false', f'effective softdep {name}',
                  f'effective blacklist {name}']
    lines += ['denylist-file ' + proof.DENYLIST_SHA256,
              'module-file nvmet_tcp 0', 'module-file ib_srpt 0',
              'sctp-socket=refused:Protocol not supported loaded-after=0',
              'running=6.8.0-146-generic', 'installed=6.8.0-146-generic',
              'snapd-status=not-installed', 'snap-dir=absent',
              'docker-ce=29.8.2', 'containerd.io=2.3.6', 'docker-compose-plugin=5.6.0',
              'sock /run/containerd/containerd.sock root:root 660',
              'sock /run/docker.sock root:docker 660', 'docker-group=',
              'dockerd-argv /usr/bin/dockerd -H fd://', 'disabled-plugins ["cri"]',
              'listen example', 'published culvert 0.0.0.0:8080->8080/tcp', 'plugin example', '=== containerd tracing', 'tracing endpoint = ""']
    return '\n'.join(lines) + '\n'


class EngineSurfaceProofTests(unittest.TestCase):
    def test_authenticated_collector_payload_and_local_parser_dispatch(self):
        bash = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')
        if not bash:
            self.skipTest('Bash required for transport dispatch regression')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'fixture.txt').write_text(fixture(), encoding='utf-8')
            env = {k: v for k, v in os.environ.items() if not k.startswith(('LAB_', 'ESXI_'))}
            env.update(LAB_DIR=root.as_posix(), LAB_EXTERNAL='1', LAB_LIBRARY_ONLY='1',
                       ESXI_ENGINE_SURFACE='1', TEST_PYTHON=sys.executable,
                       ADAPTER_HERE=HERE.as_posix())
            script = '''
source "$1"
source "$ADAPTER_HERE/engine-surface-check.sh"
python3() { "$TEST_PYTHON" "$@"; }
# No SSH or guest exists. Capture exactly what authenticated gpriv receives.
gpriv() {
  [[ "$*" == '--timeout 300' ]] || return 90
  cat > "$LAB_DIR/captured-payload.sh"
  cat "$LAB_DIR/fixture.txt"
}
ssh() { return 91; }
esxi_engine_surface
[[ $(failures) == 0 ]]
# Existing evidence must never be overwritten by a retry.
cp "$EV/E-engine-surface.txt" "$LAB_DIR/original.txt"
if esxi_engine_surface; then exit 92; fi
cmp "$EV/E-engine-surface.txt" "$LAB_DIR/original.txt"
[[ $(failures) == 1 ]]
'''
            result = subprocess.run([bash, '-c', script, 'test',
                                     (HERE.parent / 'lab/appliance-lab.sh').as_posix()],
                                    env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            payload = (root / 'captured-payload.sh').read_text()
            self.assertIn('modprobe "$m"', payload)
            self.assertIn("socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132)", payload)
            self.assertIn('modprobe -c', payload)
            self.assertNotIn('sudo -n', payload)

    def test_denied_dependency_is_valid_only_with_target_final_rule(self):
        self.assertEqual(proof.verify(fixture()), 24)
        changed = fixture().replace('module ksmbd before=0 final=install /bin/false',
                                    'module ksmbd before=0 final=insmod /lib/ksmbd.ko')
        with self.assertRaisesRegex(ValueError, 'target denial not proven: ksmbd'):
            proof.verify(changed)

    def test_missing_duplicate_loaded_success_and_unrelated_refusal_are_rejected(self):
        original = 'module sctp before=0 final=install /bin/false rc=1 refused-by=sctp after=0'
        for replacement in ('', original + '\n' + original,
                            original.replace('before=0', 'before=1'),
                            original.replace('after=0', 'after=1'),
                            original.replace('rc=1', 'rc=0'),
                            original.replace('refused-by=sctp', 'refused-by=missing')):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                proof.verify(fixture().replace(original, replacement))

    def test_old_softdep_hole_conflicting_rules_and_wrong_digest_are_rejected(self):
        for original, replacement in (
                ('effective softdep ksmbd', 'effective softdep ksmbd pre: crc32'),
                ('effective install ksmbd /bin/false', 'effective install ksmbd /bin/true'),
                ('effective install ksmbd /bin/false', 'effective install ksmbd /bin/false\neffective install ksmbd /bin/true'),
                (proof.DENYLIST_SHA256, '0' * 64),
                ('module-file nvmet_tcp 0', ''),
                ('sctp-socket=refused:Protocol not supported loaded-after=0', 'sctp-socket=opened loaded-after=1'),
                ('tracing endpoint = ""', ''), ('dockerd-argv /usr/bin/dockerd -H fd://', '')):
            with self.subTest(original=original), self.assertRaises(ValueError):
                proof.verify(fixture().replace(original, replacement))

    def test_empty_or_transport_truncated_evidence_never_passes(self):
        for text in ('', fixture().split('denylist-file')[0], fixture().split('plugin example')[0]):
            with self.subTest(length=len(text)), self.assertRaises(ValueError):
                proof.verify(text)

    def test_builtin_softdeps_following_empty_override_and_skipped_tracing_are_valid(self):
        text = fixture().replace('effective softdep ksmbd',
                                 'effective softdep ksmbd\neffective softdep ksmbd pre: crc32')
        text = text.replace('tracing endpoint = ""',
                            'plugin io.containerd.tracing.processor.v1 otlp skip\n'
                            'plugin io.containerd.internal.v1 tracing skip')
        self.assertEqual(proof.verify(text), 24)

    def test_helpers_are_loaded_before_lifecycle_and_used_after_restore_check(self):
        script = (HERE / 'access-aware-qualify.sh').read_text()
        self.assertLess(script.index('source "$ADAPTER_HERE/engine-surface-check.sh"'),
                        script.index('\ncmd_qualify\n'))
        self.assertIn('\nesxi_restore_persistence\nesxi_engine_surface\n', script)
        runner = (HERE / 'candidate-run.ps1').read_text()
        self.assertIn("$env:ESXI_ENGINE_SURFACE = if ($configuration.source_sha -eq '7c7b29ee3be40af6a0809c73ad04d4337303263d')", runner)


if __name__ == '__main__':
    unittest.main()
