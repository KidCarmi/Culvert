"""One Esc on a finite, explicitly reviewed splash-frame set; no fuzzy matching."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import importlib.util

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


capture=load('capture-coordination')


def need(value,reason):
    if not value:raise ValueError(reason)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path):
    # Windows junctions/reparse points must not redirect private evidence.
    for part in (path,*path.parents):
        need(not part.is_symlink() and not (part.stat().st_file_attributes & 0x400 if hasattr(part.stat(),'st_file_attributes') else False),'linked evidence refused')
    need(path.is_file(),'evidence missing')


def save(path,value):
    with path.open('x',encoding='utf-8') as out:
        json.dump(value,out,sort_keys=True);out.flush();os.fsync(out.fileno())


def validate_review(lab,proof,visual,now_ns=None):
    now_ns=time.time_ns() if now_ns is None else now_ns
    for key in ('source_sha','ova_sha256','image_id'):
        need(proof.get(key)==lab.c[key],'candidate differs')
    need(proof.get('uuid')==lab.state['uuid'] and proof.get('key')=='esc','owned Esc only')
    need(proof.get('scope_sha256')==sha(lab.scope_path) and proof.get('manifest_sha256')==sha(Path(lab.c['controller_manifest'])),'scope/freeze differs')
    need(proof.get('reviewed_state')=='culvert-splash-no-auth','explicit splash review required')
    need(type(proof.get('reviewed_realtime_ns')) is int and 0<=now_ns-proof['reviewed_realtime_ns']<=120*10**9,'review expired')
    campaign=proof.get('campaign','');need(re.fullmatch(r'[a-z][a-z0-9-]{0,47}',campaign),'campaign invalid')
    directory=lab.sec/('visual-'+campaign);regular(directory/'frames.jsonl')
    lines=(directory/'frames.jsonl').read_text().splitlines()
    header=json.loads(lines[0]);need(header['event']=='owned' and header['identity']['uuid']==lab.state['uuid'],'capture owner differs')
    need(header['scope_sha256']==proof['scope_sha256'] and header['source']==lab.c['source_sha'] and header['ova_sha256']==lab.c['ova_sha256'] and header['image_id']==lab.c['image_id'],'capture binding differs')
    captured={row['filename']:row for row in (json.loads(line) for line in lines[1:]) if row['event']=='frame'}
    frames=proof.get('frames',[]);need(1<=len(frames)<=32,'reviewed frame count invalid')
    accepted={}
    for frame in frames:
        name=frame['filename'];need(re.fullmatch(r'frame-[0-9]{4}(?:\.attempt-[23])?\.png',name),'invalid capture name')
        path=directory/name;regular(path);metadata=visual.image_metadata(path,visual.MAX_IMAGE)
        need(all(frame[k]==metadata[k]==captured[name][k] for k in ('sha256','bytes','width','height')),'reviewed frame changed')
        need(captured[name]['uuid']==lab.state['uuid'] and 0<=now_ns-captured[name]['finished_realtime_ns']<=120*10**9,'capture stale')
        accepted[metadata['sha256']]=metadata
    for old in proof.get('prior_attempts',[]):
        name=old['directory'];need(re.fullmatch(r'visual-(?:key|reviewed-key)-[a-z][a-z0-9-]{0,47}',name),'prior directory invalid')
        prior=lab.sec/name
        need(prior.is_dir() and not (prior/'intent.json').exists() and not (prior/'complete.json').exists(),'prior input might have been sent')
        actual={}
        for file in prior.iterdir():regular(file);actual[file.name]=sha(file)
        need(actual==old['files'] and actual,'prior failed evidence changed')
    claim=lab.sec/('visual-esc-'+campaign+'.intent.json')
    need(not claim.exists() and not claim.is_symlink(),'prior Esc intent forbids another input')
    return accepted,claim


def observe_then_send(lab,keyboard,visual,accepted,directory,claim,proof,clock=time.monotonic,pause=time.sleep):
    deadline=clock()+10;rows=[]
    for count in range(10):
        need(clock()<deadline,'no reviewed frame before deadline')
        need(lab.vm(timeout=min(3,max(.1,deadline-clock())))['runtime']['powerState']=='poweredOn','VM not poweredOn')
        path=lab.capture_snapshot(directory/('before-%02d.png'%count),deadline)
        metadata=visual.image_metadata(path,visual.MAX_IMAGE)
        rows.append({'filename':path.name,'monotonic_ns':time.monotonic_ns(),**metadata})
        save(directory/('observation-%02d.json'%count),rows[-1])
        if metadata['sha256'] not in accepted:
            pause(min(.25,max(0,deadline-clock())));continue
        need(metadata==accepted[metadata['sha256']],'frame metadata differs')
        # The passive observer shares this lock. It can continue taking frames
        # before/after, but never while final admission and input are in flight.
        with capture.lock(lab.run,deadline,clock,pause):
            need(lab.vm(timeout=min(3,max(.1,deadline-clock())))['runtime']['powerState']=='poweredOn','VM not poweredOn')
            validate_review(lab,proof,visual)  # Recheck freeze/scope/freshness and every prior refusal.
            need(clock()<deadline,'observation expired before input')
            # The campaign-wide claim is fsynced BEFORE input and cannot be reused
            # with another label. A failed send/after capture never authorizes retry.
            intent={'key':'esc','uuid':lab.state['uuid'],'campaign':proof['campaign'],'review_sha256':proof['_sha256'],'frames':rows}
            save(claim,intent);save(directory/'intent.json',intent)
            keyboard.send('KEY_ESC')
        pause(.5)
        after=lab.capture_snapshot(directory/'after.png',clock()+10)
        save(directory/'complete.json',{'key':'esc','frames':rows,'after':visual.image_metadata(after,visual.MAX_IMAGE),'result':'sent_once_visual_result_requires_review'})
        return
    raise ValueError('bounded captures did not match reviewed splash frames; no input')


def main():
    p=argparse.ArgumentParser();p.add_argument('--scope',type=Path,required=True);p.add_argument('--label',required=True)
    p.add_argument('--review',type=Path,required=True);p.add_argument('--review-sha256',required=True);a=p.parse_args()
    need(re.fullmatch(r'[a-z][a-z0-9-]{0,47}',a.label),'label invalid');regular(a.review)
    need(a.review.stat().st_size<=128*1024 and sha(a.review)==a.review_sha256,'explicit reviewed proof hash required')
    proof=json.loads(a.review.read_bytes());proof['_sha256']=a.review_sha256
    visual=load('visual-capture');console=load('console-priv');lab=console.b.module.Lab(a.scope)
    console.b.module.validate_scope(lab.c);visual.candidate_profile(lab.c);console.b.private_directory(lab)
    with console.b.module.locked(lab.run):
        visual.preflight(lab);visual.identity(lab.state);visual.no_identity_reset(lab)
        accepted,claim=validate_review(lab,proof,visual)
        directory=lab.sec/('visual-reviewed-key-'+a.label);directory.mkdir(mode=0o700)
        save(directory/'review.json',proof)
        observe_then_send(lab,console.Keyboard(lab),visual,accepted,directory,claim,proof)
    print('Esc sent once. Private after-frame requires review; no retry permitted.')


if __name__=='__main__':
    try:main()
    except Exception:
        print('BLOCKED: preserve reviewed-key evidence; never retry an intent.',file=sys.stderr);sys.exit(90)
