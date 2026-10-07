"""Validate completed private receipts and publish only a recovery summary."""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path('D:/AI/Culvert-esxi-cd8-final-controller')
OPS = ROOT / '.tools/private-operations'
RUN = ROOT / '.tools/esxi-cd8-fresh'
ESCROW = Path('D:/AI/Culvert-esxi-cd8-font-continuation/.tools/private-escrow-cd8')
PUB = Path('D:/AI/Culvert-esxi-cd8-report/docs/appliance/evidence/cd8-esxi-20261008')
def read(path): return json.loads(path.read_bytes())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

freeze=load('result_freeze',ROOT/'test/e2e/appliance/esxi/controller-freeze.py')
freeze.verify(ROOT/'.tools/controller-freeze.json',ROOT)
stages={}
for name in ('delete-source','fresh-import','fresh-bootstrap','fresh-firstboot-preflight','fresh-restore'):
    path=OPS/(name+'.receipt.json');value=read(path)
    assert value['exit_code']==0
    assert value['stdout_sha256']==sha(OPS/(name+'.out'))
    assert value['stderr_sha256']==sha(OPS/(name+'.err'))
    stages[name]={'exit_code':0,'receipt_sha256':sha(path)}
scope=read(ROOT/'.tools/scope-cd8-fresh-final.json')
owned=read(RUN/'owned.json')
deleted=read(ESCROW/'source-deletion-receipt.json')
assert deleted['source_disks_deleted'] is True and deleted['source_uuid']!=owned['uuid']
bootstrap=read(RUN/'secrets/access-bootstrap-attempt.json')
assert bootstrap['status']=='passed' and bootstrap['uuid']==owned['uuid']
assert not (RUN/'secrets/operator-enroll-attempt.json').exists()
phases=list(ESCROW.glob('transfer-restore-*'));assert len(phases)==1
transfer=phases[0]
restored=read(transfer/'restored-observation.json');baseline=read(ESCROW/'source-observation.json')
for key in ('ca_sha256','rules','categories','agent_version'):
    assert restored[key]==baseline[key]
assert restored['admin_login']=='pass' and restored['ca_decryption']=='pass' and restored['agent']=='pass'
assert restored['traffic']=={'example.com':200,'example.org':403}
assert restored['historical_encrypted_log_recovery']['result']=='blocked'
metadata=read(ESCROW/'archive-metadata.json')
assert metadata['archive_sha256']==sha(ESCROW/'recovery.tar.gz.enc')
adapter=load('result_adapter',ROOT/'test/e2e/appliance/esxi/esxi-lab.py')
with adapter.locked(RUN):
    lab=adapter.Lab(ROOT/'.tools/scope-cd8-fresh-final.json')
    guest=lab.guest_ip(timeout=30)
summary={'schema':1,'result':'pass','source_sha':scope['source_sha'],'ova_sha256':scope['ova_sha256'],
         'image_id':scope['image_id'],'controller_revision':read(ROOT/'.tools/controller-freeze.json')['revision'],
         'controller_manifest_sha256':sha(ROOT/'.tools/controller-freeze.json'),
         'source_uuid':deleted['source_uuid'],'fresh_uuid':owned['uuid'],'fresh_vm':owned['name'],
         'source_vm_and_disk_folder_absent_before_import':True,'single_vm_limit':1,'same_exact_ova':True,
         'archive_sha256':metadata['archive_sha256'],'archive_bytes':metadata['archive_bytes'],
         'original_admin_ca_policy_categories_agent_and_traffic_match':True,
         'traffic':restored['traffic'],'restored_rules_count':len(restored['rules']),
         'category_test_hosts':len(restored['categories']),'agent_version':restored['agent_version'],
         'default_fresh_bootstrap':True,'web_setup_or_operator_enrollment_before_restore':False,
         'historical_logs':restored['historical_encrypted_log_recovery'],
         'access':{'ui_url':'https://'+guest+':9090','browser_user':'labadmin',
                   'console_user':'culvert','console_entry':'L / Sign in',
                   'credentials':'Separate local private custody; no secret values published',
                   'operator_ssh':'No operator key enrolled on this default-import restored VM'},
         'stage_receipts':stages,'evidence_sha256':{
             'source-deletion-receipt.json':sha(ESCROW/'source-deletion-receipt.json'),
             'export-receipt.json':sha(ESCROW/'export-receipt.json'),
             'archive-metadata.json':sha(ESCROW/'archive-metadata.json'),
             'restored-observation.json':sha(transfer/'restored-observation.json'),
             'guest-result.json':sha(transfer/'guest-result.json'),
             'fresh-bootstrap-attempt.json':sha(RUN/'secrets/access-bootstrap-attempt.json')},
         'publication_helper_sha256':sha(Path(__file__))}
with (PUB/'fresh-recovery.json').open('x',encoding='utf-8',newline='\n') as output:
    json.dump(summary,output,indent=2);output.write('\n')
print(json.dumps({'result':'pass','fresh_vm':owned['name'],'ui_url':summary['access']['ui_url'],
                  'source_absent':True,'historical_logs':'blocked'}))
