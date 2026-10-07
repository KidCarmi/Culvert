"""Frozen helper orchestration with a predeclared post-measurement snapshot margin."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('D:/AI/Culvert-esxi-cd8-font-continuation')
WRAPPER_SHA = None

def main():
    spec=importlib.util.spec_from_file_location('frozen_orchestration',ROOT/'.tools/run-cd8.py')
    m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    m.verify()
    label=sys.argv[1]
    if label not in ('rcd8-2','rcd8-3'): raise ValueError('cycle not approved here')
    with (m.OPS/(label+'.started')).open('x') as f:
        json.dump({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'orchestrator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'frozen_wrapper_sha256':hashlib.sha256((ROOT/'.tools/run-cd8.py').read_bytes()).hexdigest(),
                   'post_measurement_snapshot_margin_seconds':40,
                   'measurement_budget_seconds':120,'probe_or_verifier_changes':False},f)
    accepted=m.SEC/'production-recovery'/label/'acceptance.json'
    observed=m.SEC/('production-recovery-'+label+'.jsonl')
    directory=accepted.parent
    argv=[m.PY,str(m.HERE/'production-recovery-probes.py'),'observe','--scope',str(m.SCOPE),
          '--baseline',str(m.SEC/'production-baseline.json'),'--acceptance',str(accepted),'--label',label]
    with (m.OPS/(label+'-observer.out')).open('xb') as out,(m.OPS/(label+'-observer.err')).open('xb') as err:
        observer=subprocess.Popen(argv,stdout=out,stderr=err,cwd=m.ROOT,env=m.ENV)
        try:
            for _ in range(30):
                if observed.exists() and observed.stat().st_size: break
                if observer.poll() is not None: raise RuntimeError('Observer stopped before dispatch')
                time.sleep(1)
            else: raise RuntimeError('Observer not ready; no reboot')
            m.helper(label+'-dispatch','production-maintenance-dispatch.py','--scope',m.SCOPE,'--bind',m.BIND,'--cycle',label,timeout=360)
            if observer.wait(timeout=1500): raise RuntimeError('Observer failed; retain measurement')
        finally:
            if observer.poll() is None: observer.terminate(); observer.wait(timeout=30)
    # The observer already stopped: this only lets its recorded guest proof tail
    # cover the verifier's <=30s clock uncertainty +2.5s pad +2s sample period.
    print('Measurement retained; waiting 40s for complete historical sampler tail',flush=True)
    time.sleep(40)
    m.helper(label+'-full','production-evidence-controller.py','capture','--scope',m.SCOPE,'--bind',m.BIND,'--cycle',label,'--mode','full')
    m.helper(label+'-clock','production-evidence-controller.py','capture','--scope',m.SCOPE,'--bind',m.BIND,'--cycle',label,'--mode','correlation')
    m.helper(label+'-proof','production-evidence-controller.py','proof','--scope',m.SCOPE,'--cycle',label)
    verdict=m.run(label+'-verdict',[m.PY,str(m.HERE/'production-recovery-probes.py'),'verify','--scope',str(m.SCOPE),
        '--baseline',str(m.SEC/'production-baseline.json'),'--rows',str(observed),
        '--proof',str(directory/'authenticated-boot-proof.json'),'--label',label],allowed=(0,90))
    summary=json.loads((m.RUN/'evidence'/('production-recovery-'+label+'-summary.json')).read_bytes())
    print(json.dumps({k:summary.get(k) for k in ('result','cycle_id','seconds_to_three_healthy_samples','first_backup_seconds','reason')}),flush=True)
    a=json.loads(accepted.read_bytes())
    start=datetime.datetime.fromtimestamp(a['controller_realtime_ns']/1e9-20,datetime.timezone.utc)
    end=start+datetime.timedelta(seconds=(summary.get('seconds_to_three_healthy_samples') or 120)+40)
    remaining=end.timestamp()+25-time.time()
    if remaining>0: time.sleep(min(remaining,60))
    window=['--start',start.isoformat(),'--end',end.isoformat()]
    m.run(label+'-storage',[m.PY,str(m.HERE/'capture-host-storage.py'),'--scope',str(m.SCOPE),'--label',label,*window],allowed=(0,1,90))
    m.run(label+'-vm',[m.PY,str(m.HERE/'capture-vm-performance.py'),'--scope',str(m.SCOPE),'--label',label,'--require-realtime',*window],allowed=(0,1,90))
    if verdict: raise RuntimeError('Original verdict nonzero; stop with retained evidence')
    print('COMPLETE '+label,flush=True)

if __name__=='__main__': main()
