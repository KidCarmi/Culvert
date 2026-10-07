"""Append-only read-only supplement; preserve original failed verdict and samples."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys

ROOT = Path('D:/AI/Culvert-esxi-cd8-font-continuation')
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def main():
    m = load('cd8_orchestrator', ROOT / '.tools/run-cd8.py')
    m.verify()
    import os
    os.environ.update(m.ENV)
    e = load('cd8_evidence', m.HERE / 'production-evidence-controller.py')
    old = m.SEC / 'production-recovery/rcd8-1'
    new = m.SEC / 'production-recovery/rcd8-1-snapshot-supplement'
    original = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in old.iterdir() if p.is_file()}
    new.mkdir(exist_ok=False)
    for name in ('correlation.json', 'correlation-receipt.json', 'correlation.stderr'):
        with (new/name).open('xb') as f: f.write((old/name).read_bytes())
    args = SimpleNamespace(scope=m.SCOPE, bind=m.BIND, cycle='rcd8-1', mode='full')
    lab = e.console.b.module.Lab(m.SCOPE)
    lab.vm(timeout=30)
    e.capture(lab, args, new)
    before = json.loads((old/'full.json').read_bytes())
    after = json.loads((new/'full.json').read_bytes())
    assert before['identity']['boot_id'] == after['identity']['boot_id'], 'boot changed'
    first = e.unpack_sampler(before['full']['sampler'])
    later = e.unpack_sampler(after['full']['sampler'])
    assert later[:len(first)] == first, 'original sampler prefix changed'
    assert len(later) > len(first), 'no later samples'
    assert all(hashlib.sha256((old/n).read_bytes()).hexdigest() == h for n,h in original.items())
    with (new/'supplement-provenance.json').open('x') as f:
        json.dump({'schema':1,'reason':'original snapshot ended before uncertainty interval',
                   'original_files_sha256':original,'same_boot':True,'original_sampler_prefix_unchanged':True,
                   'original_rows':len(first),'supplement_rows':len(later),
                   'orchestrator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},f,indent=2)
    e.proof(lab,args,new)
    m.helper('rcd8-1-supplement-verdict','production-recovery-probes.py','verify',
             '--scope',m.SCOPE,'--baseline',m.SEC/'production-baseline.json',
             '--rows',m.SEC/'production-recovery-rcd8-1.jsonl',
             '--proof',new/'authenticated-boot-proof.json','--label','rcd8-1-supplement')
    print('PASS append-only historical-sample supplement; original verdict preserved')

if __name__ == '__main__': main()
