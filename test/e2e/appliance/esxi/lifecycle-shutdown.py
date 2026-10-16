"""Read-only original PAM/console session proof; never dispatches a reboot."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

SOURCE = '6248daf72a5312e75062e2c2823438911604af7f'
IMAGE = 'sha256:20a547edd3e9db83cd1fa65f734bdeec5fc8f6d077f6f73344a38798a5d9692d'
BOOT = r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'


def need(value, reason):
    if not value: raise ValueError(reason)


def validate_before(value):
    need(value.get('source') == SOURCE and value.get('image') == IMAGE, 'candidate mismatch')
    need(re.fullmatch(BOOT, value.get('boot', '')), 'boot identity missing')
    need(re.fullmatch(r'session-[0-9]+\.scope', value.get('scope', '')), 'local session scope missing')
    need(type(value.get('monotonic_us')) is int and value['monotonic_us'] > 0, 'guest timestamp missing')
    ancestors = value.get('ancestors', [])
    need(1 <= len(ancestors) <= 64, 'ancestry missing')
    consoles = [p for p in ancestors if p['comm'] == 'culvert-console' and p['uid'] == value['culvert_uid']]
    need(consoles and any(p['scope'] == value['scope'] and p['tty_nr'] == 1025 for p in consoles),
         'authenticated tty1 console ancestor missing')
    need(any(p['comm'] == 'sudo' for p in ancestors) and any(p['comm'] == 'bash' for p in ancestors),
         'original nested sudo/bash ancestry missing')
    return value


def journal_events(raw, before):
    """Export categories/timestamps only; never raw messages, argv or PAM secrets."""
    events=[]; parsed=0; wrong=0
    for line in raw.splitlines():
        row=json.loads(line); parsed+=1
        if row.get('_BOOT_ID') != before['boot'].replace('-', ''):
            wrong+=1; continue
        stamp=int(row['__MONOTONIC_TIMESTAMP'])
        if stamp < before['monotonic_us']: continue
        message=row.get('MESSAGE','')
        if not isinstance(message,str): continue
        unit=row.get('UNIT') or row.get('_SYSTEMD_UNIT')
        # PID1 messages name the scope when UNIT is absent. Exact token prevents
        # session-2 matching session-20; never attribute an unrelated session.
        session=before['scope'][8:-6]
        target=(unit == before['scope'] or bool(re.search(r'(?<![\w-])'+re.escape(before['scope'])+r'(?![\w.-])',message))
                or bool(re.search(r'\bSession '+re.escape(session)+r'\b',message)))
        if row.get('_PID') != '1' or not target: continue
        kinds=[]
        if re.search(r'^Stopping\b',message): kinds.append('stop_requested')
        if re.search(r'^Stopped\b|(?:^|:\s)Deactivated successfully\.',message): kinds.append('stopped')
        if re.search(r'timed out|stop-sigterm|stop-sigkill',message,re.I): kinds.append('timeout')
        if re.search(r'SIGKILL|signal KILL|signal 9',message,re.I): kinds.append('sigkill')
        for kind in kinds: events.append({'kind':kind,'monotonic_us':stamp,'scope':before['scope']})
    return {'parsed':parsed,'wrong_boot':wrong,'events':events,'entry_limit_reached':parsed>=3000}


def verdict(before, after, rows):
    validate_before(before)
    need(after.get('source') == SOURCE and after.get('image') == IMAGE, 'post candidate mismatch')
    need(re.fullmatch(BOOT,after.get('boot','')) and after['boot'] != before['boot'], 'new boot unproven')
    need(after.get('old_boot') == before['boot'] and after.get('scope') == before['scope'], 'session binding mismatch')
    journal=after['journal']
    need(journal['parsed'] > 0 and journal['wrong_boot'] == 0 and not journal['entry_limit_reached'], 'journal incomplete')
    events=journal['events'];need(all(e['scope']==before['scope'] for e in events),'wrong session event')
    need(not any(e['kind'] in ('timeout','sigkill') for e in events), 'local session timed out or was SIGKILLed')
    start=[e['monotonic_us'] for e in events if e['kind']=='stop_requested']
    end=[e['monotonic_us'] for e in events if e['kind']=='stopped']
    need(len(start)==1 and end, 'session shutdown boundaries absent or ambiguous')
    stop=min(x for x in end if x>=start[0]); elapsed=(stop-start[0])/1e6
    need(0 <= elapsed <= 10,'local session teardown exceeded10s')
    marks=[r['monotonic_ns'] for r in rows if r['event']=='dispatch_intent']
    returned=[r['monotonic_ns'] for r in rows if r['event']=='all_services_returned_after_failure']
    need(len(marks)==1 and len(returned)==1,'recovery observation incomplete')
    recovery=(returned[0]-marks[0])/1e9
    need(0 <= recovery <= 120,'original lifecycle observed recovery exceeded120s')
    return {'result':'pass','session_teardown_seconds':elapsed,'session_budget_seconds':10,
            'observed_recovery_seconds':recovery,'recovery_budget_seconds':120,
            'readiness_scope':'health and ready operator status; dedicated traffic sampler has separate full readiness gate',
            'old_boot':before['boot'],'new_boot':after['boot'],'scope':before['scope']}


def journal_command(before):
    validate_before(before)
    return ['journalctl','--boot='+before['boot'].replace('-',''),'--unit='+before['scope'],
            '--no-pager','--output=json','--lines=3000',
            '--output-fields=_BOOT_ID,_PID,UNIT,_SYSTEMD_UNIT,__MONOTONIC_TIMESTAMP,MESSAGE']


def guest_collect(phase, before=None):
    """Invoked ONLY inside the authenticated guest payload, never on import."""
    import pwd
    need(os.geteuid()==0,'authenticated root required')
    build=json.loads(Path('/var/lib/culvert-appliance/build-info.json').read_bytes())
    need(build['source']['git_commit']==SOURCE and build['source']['git_dirty'] is False,'wrong source')
    image=subprocess.run(['docker','inspect','-f','{{.Image}}','culvert'],capture_output=True,check=True,timeout=15).stdout.decode().strip()
    need(image==IMAGE,'wrong image')
    current={'source':SOURCE,'image':image,'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    if phase=='before':
        ancestors=[];pid=os.getpid(); seen=set()
        while pid>0 and pid not in seen and len(ancestors)<64:
            seen.add(pid);root=Path('/proc')/str(pid);raw=(root/'stat').read_text(); fields=raw[raw.rindex(')')+2:].split()
            comm=raw[raw.index('(')+1:raw.rindex(')')];groups=(root/'cgroup').read_text()
            scopes=re.findall(r'/(session-[0-9]+\.scope)(?:/|$)',groups,re.M)
            ancestors.append({'pid':pid,'ppid':int(fields[1]),'pgid':int(fields[2]),'sid':int(fields[3]),
                              'tty_nr':int(fields[4]),'foreground_pgid':int(fields[5]),'uid':root.stat().st_uid,
                              'comm':comm if comm in ('culvert-console','bash','sudo','login','python3','systemd') else 'other',
                              'scope':scopes[0] if len(set(scopes))==1 else None})
            pid=int(fields[1])
        uid=pwd.getpwnam('culvert').pw_uid
        consoles=[p for p in ancestors if p['comm']=='culvert-console' and p['uid']==uid]
        need(consoles,'authenticated console not found')
        current.update(ancestors=ancestors,culvert_uid=uid,scope=consoles[0]['scope'],monotonic_us=time.monotonic_ns()//1000)
        validate_before(current)
    else:
        validate_before(before)
        need(current['boot']!=before['boot'],'guest did not reboot')
        result=subprocess.run(journal_command(before),capture_output=True,timeout=20,check=True)
        need(len(result.stdout)<=8*1024*1024,'journal size exceeded')
        current.update(old_boot=before['boot'],scope=before['scope'],journal=journal_events(result.stdout,before))
    print(json.dumps(current,separators=(',',':')))


def payload(phase,before=None):
    if phase=='after': validate_before(before)
    raw=Path(__file__).read_text(); raw=raw[:raw.index("\nif __name__ == '__main__':")]
    return ('set +x\nset -euo pipefail\npython3 - <<\'CULVERT_SHUTDOWN_PROOF\'\n'+raw+
            '\nguest_collect('+repr(phase)+','+repr(before)+')\nCULVERT_SHUTDOWN_PROOF\n')


def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=('before','after','verify'))
    p.add_argument('--before',type=Path);p.add_argument('--after',type=Path);p.add_argument('--timing',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();before=json.loads(a.before.read_bytes()) if a.before else None
    # This output is piped into a Linux shell; Windows text stdout adds CRLF.
    if a.mode!='verify':sys.stdout.buffer.write(payload(a.mode,before).encode('utf-8'));return
    report={'result':'fail'}
    try:report=verdict(before,json.loads(a.after.read_bytes()),[json.loads(x) for x in a.timing.read_text().splitlines()])
    except (ValueError,KeyError,TypeError) as error:report['reason']=str(error)
    with a.output.open('x',encoding='utf-8') as out:json.dump(report,out,sort_keys=True)
    need(report['result']=='pass','shutdown proof failed; preserved receipt')


if __name__ == '__main__':
    try:main()
    except Exception:
        print('BLOCKED: original lifecycle shutdown proof incomplete; preserve evidence.',file=sys.stderr);sys.exit(90)
