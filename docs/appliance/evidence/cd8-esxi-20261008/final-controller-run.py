"""One-shot orchestration for a separately frozen cd8 final continuation."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / 'test/e2e/appliance/esxi'
OPS = ROOT / '.tools/private-operations'
ESCROW = Path('D:/AI/Culvert-esxi-cd8-font-continuation/.tools/private-escrow-cd8')
ENV = dict(os.environ)
ENV.pop('LAB_ADOPT_IMAGE_TAR', None)
ENV['PATH'] = 'C:/Program Files/Go/bin;' + ENV['PATH']
ENV['CULVERT_ESXI_CONSOLE_FONT'] = 'D:/AI/Culvert-esxi-qualification/.tools/consolefonts/Uni2-Fixed16.psf.gz;D:/AI/Culvert-esxi-qualification/.tools/consolefonts/Ethiopian-Goha16.psf.gz'


def main():
    spec = importlib.util.spec_from_file_location('final_freeze', HERE / 'controller-freeze.py')
    freeze = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(freeze)
    freeze.verify(ROOT / '.tools/controller-freeze.json', ROOT)
    stage = sys.argv[1]
    scope = ROOT / '.tools/scope-cd8-source-final.json'
    if stage == 'identity-bootstrap-continuation':
        args = ['p1-regressions.py', '--scope', str(scope), '--bind', '192.168.1.189',
                '--resume-identity-observation', 'identity-bootstrap']
        timeout = 1800
    elif stage == 'identity-after':
        args = ['p1-regressions.py', '--scope', str(scope), '--bind', '192.168.1.189', 'identity-after']
        timeout = 2400
    elif stage == 'delete-source':
        args = ['delete-exported-source.py', '--scope', str(scope), '--escrow', str(ESCROW)]
        timeout = 900
    elif stage.startswith('fresh-'):
        scope = ROOT / '.tools/scope-cd8-fresh-final.json'
        if stage == 'fresh-import':
            receipt = json.loads((ESCROW / 'source-deletion-receipt.json').read_bytes())
            assert receipt['source_disks_deleted'] is True
            args = ['esxi-lab.py', '--scope', str(scope), 'up']
            timeout = 2400
        elif stage == 'fresh-bootstrap':
            args = ['access-aware-bootstrap.py', '--scope', str(scope), '--initial-timeout', '900']
            timeout = 1800
        elif stage == 'fresh-restore':
            args = ['fresh-recovery.py', 'restore', '--scope', str(scope), '--escrow', str(ESCROW),
                    '--bind', '192.168.1.189', '--source-ledger', str(ESCROW / 'source-deleted-owned.json'),
                    '--deletion-receipt', str(ESCROW / 'source-deletion-receipt.json')]
            timeout = 2400
        else:
            raise ValueError('Unknown fresh stage')
    else:
        raise ValueError('Unknown final stage')
    with (OPS / (stage + '.started')).open('x') as output:
        output.write(datetime.datetime.now(datetime.timezone.utc).isoformat())
    print('START ' + stage, flush=True)
    with (OPS / (stage + '.out')).open('xb') as output, (OPS / (stage + '.err')).open('xb') as errors:
        proc = subprocess.run([sys.executable, str(HERE / args[0]), *args[1:]],
                              cwd=ROOT, env=ENV, stdout=output, stderr=errors, timeout=timeout)
    with (OPS / (stage + '.receipt.json')).open('x') as output:
        json.dump({'exit_code': proc.returncode, 'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'stdout_sha256': hashlib.sha256((OPS / (stage + '.out')).read_bytes()).hexdigest(),
                   'stderr_sha256': hashlib.sha256((OPS / (stage + '.err')).read_bytes()).hexdigest()}, output)
    print(('PASS ' if proc.returncode == 0 else 'BLOCKED ') + stage, flush=True)
    return proc.returncode


if __name__ == '__main__':
    sys.exit(main())
