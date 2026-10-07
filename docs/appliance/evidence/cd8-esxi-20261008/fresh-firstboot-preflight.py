"""Bounded authenticated read-only firstboot wait using frozen guest helper."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path('D:/AI/Culvert-esxi-cd8-final-controller')
HERE = ROOT / 'test/e2e/appliance/esxi'
OPS = ROOT / '.tools/private-operations'
SCOPE = ROOT / '.tools/scope-cd8-fresh-final.json'

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

load('preflight_freeze', HERE/'controller-freeze.py').verify(ROOT/'.tools/controller-freeze.json', ROOT)
wrapper = load('preflight_wrapper', ROOT/'.tools/run-final.py')
config = json.loads(SCOPE.read_bytes())
helper = load('preflight_wait', HERE/'prepare-lab-registry.py')
helper.SOURCE = config['source_sha']; helper.BASELINE = config['image_id']
label = 'fresh-firstboot-preflight'
with (OPS/(label+'.started')).open('x') as output:
    json.dump({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'orchestrator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'guest_helper_sha256':hashlib.sha256((HERE/'prepare-lab-registry.py').read_bytes()).hexdigest()}, output)
print('START authenticated firstboot wait (read-only)', flush=True)
with (OPS/(label+'.out')).open('xb') as output, (OPS/(label+'.err')).open('xb') as errors:
    result = subprocess.run([sys.executable,str(HERE/'console-priv.py'),'--scope',str(SCOPE),
                             '--bind','192.168.1.189','--timeout','960'], input=helper.wait_script(),
                            stdout=output,stderr=errors,cwd=ROOT,env=wrapper.ENV,timeout=1080)
with (OPS/(label+'.receipt.json')).open('x') as output:
    json.dump({'exit_code':result.returncode,
               'stdout_sha256':hashlib.sha256((OPS/(label+'.out')).read_bytes()).hexdigest(),
               'stderr_sha256':hashlib.sha256((OPS/(label+'.err')).read_bytes()).hexdigest()},output)
assert result.returncode == 0
value = json.loads((OPS/(label+'.out')).read_bytes())
assert value['source'] == config['source_sha'] and value['image'] == config['image_id']
assert value['firstboot_complete'] is True and value['registry_absent'] is True
print('PASS firstboot complete and no lab registry installed', flush=True)
