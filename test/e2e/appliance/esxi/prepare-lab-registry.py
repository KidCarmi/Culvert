#!/usr/bin/env python3
"""One-shot disposable loopback registry and real signed fixture preparation.

Uses the existing authenticated local-console transport. No private TLS or
signing keys are exported. This helper never builds or changes the retained OVA.
"""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


HERE = Path(__file__).resolve().parent
SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
OVA = '1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775'
BASELINE = 'sha256:24b37bc217691058e56a838821b86dfbd45b927b1c0ea8ea867a28c54d4bcc47'
REPO = 'ghcr.io/kidcarmi/culvert'
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


# This source runs only in the owned guest after local PAM/sudo authentication.
# The strings prefixed below are fixed identities, not caller-supplied shell text.
GUEST = r'''
import base64, fcntl, hashlib, json, os, pathlib, subprocess, time
root = pathlib.Path('/var/lib/culvert-lab-registry')
repo = 'localhost:443/kidcarmi/culvert'
name = 'culvert-lab-registry'
temporary = 'culvert-lab-target-never-started'

def need(ok, message):
    if not ok: raise ValueError(message)

def run(argv, timeout=120):
    result = subprocess.run(argv, capture_output=True, timeout=timeout)
    need(result.returncode == 0, 'required registry preparation command failed')
    need(len(result.stdout) <= 1024*1024 and len(result.stderr) <= 4*1024*1024, 'registry command output exceeded bound')
    return result.stdout.decode().strip()

def inspect(reference):
    data = json.loads(run(['docker', 'inspect', reference]))
    need(len(data) == 1, 'ambiguous Docker inspection')
    return data[0]

need(os.geteuid() == 0, 'authenticated local root required')
build = json.loads(pathlib.Path('/var/lib/culvert-appliance/build-info.json').read_text())
need(build['source']['git_commit'] == SOURCE and build['source']['git_dirty'] is False, 'candidate source mismatch')
need(build['application']['index_digest'] == BASELINE, 'OVA baseline index mismatch')
need(inspect('culvert')['Image'] == BASELINE, 'running image differs from retained OVA')
need(pathlib.Path('/var/lib/culvert-appliance/state/complete.done').is_file(), 'first boot incomplete')
locks=[]
for path in ['/run/culvert-os-update.lock', '/var/lib/culvert-maint/host-maintenance.lock']:
    handle=open(path, 'a'); fcntl.flock(handle, fcntl.LOCK_EX|fcntl.LOCK_NB); locks.append(handle)
for path in ['/var/lib/culvert-maint/host-shutdown.pending', '/var/lib/culvert-appliance/state/stack-resume-on-boot']:
    need(not os.path.lexists(path), 'pending host maintenance refused')
journal=pathlib.Path('/var/lib/culvert-maint/reconcile')
if journal.exists():
    need(journal.is_dir() and not journal.is_symlink(), 'unexpected maintenance journal')
    need(not list(journal.glob('*.json')) and not list(journal.glob('*.corrupt.*')), 'interrupted maintenance refused')
need(not root.exists() and not root.is_symlink(), 'prior registry attempt exists; no overwrite')
containers=run(['docker','ps','-a','--format','{{.Names}}']).splitlines()
need(name not in containers and temporary not in containers, 'prior registry fixture container exists')
ca_dir=pathlib.Path('/etc/docker/certs.d/localhost:443')
need(not ca_dir.exists() and not ca_dir.is_symlink(), 'preexisting localhost registry trust refused')
os.umask(0o077)
root.mkdir(mode=0o700)
(root/'certs').mkdir(mode=0o700); (root/'data').mkdir(mode=0o700)
run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','2',
     '-subj','/CN=Disposable Culvert LAB registry',
     '-addext','subjectAltName=DNS:ghcr.io,DNS:localhost,IP:127.0.0.1',
     '-addext','basicConstraints=critical,CA:TRUE',
     '-keyout',str(root/'certs/registry.key'),'-out',str(root/'certs/registry.crt')])
os.chmod(root/'certs/registry.key',0o400)
ca_dir.mkdir(parents=True,mode=0o755)
(ca_dir/'ca.crt').write_bytes((root/'certs/registry.crt').read_bytes())
os.chmod(ca_dir/'ca.crt',0o644)
run(['docker','pull','registry:2'],300)
registry=inspect('registry:2')
need(registry.get('RepoDigests'), 'registry image content identity unavailable')
run(['docker','run','-d','--name',name,'--restart','unless-stopped','--memory','256m','--cpus','0.5',
     '-p','127.0.0.1:443:443','-v',str(root/'certs')+':/certs:ro','-v',str(root/'data')+':/var/lib/registry',
     '-e','REGISTRY_HTTP_ADDR=0.0.0.0:443','-e','REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry.crt',
     '-e','REGISTRY_HTTP_TLS_KEY=/certs/registry.key',registry['Id']])
observed=inspect(name)
need(observed['HostConfig']['PortBindings']=={'443/tcp':[{'HostIp':'127.0.0.1','HostPort':'443'}]},'registry is not loopback-only')
for attempt in range(30):
    check=subprocess.run(['curl','-fsS','--noproxy','*','--max-time','3','--cacert',str(root/'certs/registry.crt'),
                          'https://localhost:443/v2/'],capture_output=True,timeout=5)
    if check.returncode==0: break
    time.sleep(1)
else: raise ValueError('loopback registry unavailable')

def push_and_verify(tag):
    run(['docker','push',repo+':'+tag],360)
    headers=root/(tag+'.headers'); body=root/(tag+'.manifest')
    run(['curl','-fsS','--noproxy','*','--max-time','30','--cacert',str(root/'certs/registry.crt'),
         '-H','Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json',
         '-D',str(headers),'-o',str(body),'https://localhost:443/v2/kidcarmi/culvert/manifests/'+tag])
    raw=body.read_bytes(); need(0<len(raw)<=1024*1024,'registry manifest size refused')
    digest='sha256:'+hashlib.sha256(raw).hexdigest()
    values=[line.split(':',1)[1].strip() for line in headers.read_text().splitlines() if line.lower().startswith('docker-content-digest:')]
    need(values==[digest], 'registry digest header/body mismatch')
    need(json.loads(raw).get('schemaVersion')==2,'registry returned unsupported manifest')
    return digest,raw

run(['docker','tag',BASELINE,repo+':baseline'])
baseline,base_bytes=push_and_verify('baseline')
need(baseline==BASELINE,'pushed baseline manifest differs from exact retained OVA index')
run(['docker','create','--name',temporary,BASELINE])
created=inspect(temporary)
need(created['State']['Status']=='created' and created['State']['Running'] is False
     and created['State']['StartedAt']=='0001-01-01T00:00:00Z','target container was started')
run(['docker','commit','--change','LABEL org.culvert.lab-target=1',temporary,repo+':target'])
need(inspect(temporary)['State']==created['State'],'target container state changed')
run(['docker','rm','-v',temporary])
target,target_bytes=push_and_verify('target')
need(target!=baseline,'target digest must be distinct')
need(inspect(repo+':target')['Config']['Labels'].get('org.culvert.lab-target')=='1','target label missing')
need(inspect('culvert')['Image']==BASELINE,'preparation changed running application')
receipt={'schema':1,'source':SOURCE,'ova_sha256':OVA,'baseline_digest':baseline,'target_digest':target,
 'baseline_manifest_base64':base64.b64encode(base_bytes).decode(),
 'target_manifest_base64':base64.b64encode(target_bytes).decode(),
 'public_ca_pem':(root/'certs/registry.crt').read_text(),
 'registry_image_id':registry['Id'],'registry_repo_digests':registry['RepoDigests'],
 'registry_port_bindings':observed['HostConfig']['PortBindings'],'target_never_started':True,
 'temporary_container_removed':temporary not in run(['docker','ps','-a','--format','{{.Names}}']).splitlines(),
 'runtime_test_trust':['/etc/docker/certs.d/localhost:443/ca.crt'],
 'private_tls_key_exported':False,'application_unchanged':True}
(root/'receipt.json').write_text(json.dumps(receipt))
print(json.dumps(receipt))
'''


def guest_script():
    prefix = 'SOURCE=' + repr(SOURCE) + '\nOVA=' + repr(OVA) + '\nBASELINE=' + repr(BASELINE) + '\n'
    return ("timeout --signal=TERM --kill-after=10s 1500s python3 - <<'CULVERT_LAB_REGISTRY'\n"
            + prefix + GUEST + '\nCULVERT_LAB_REGISTRY\n').encode()


ORIGINAL_CONTROLLER = '0da471bf0e24ced91118478303254d4f3d6d8168'
ORIGINAL_HELPER = '8acac9c1f9c2cd03f922c694492d695cd01669a895b554928d65ff1ff4de4d68'
ORIGINAL_PAYLOAD = 'bd0ff42f304949964f9473fee96c535fe7005a0385a93235d7a7b695379f6971'
ORIGINAL_TRANSPORT = 'f3d22a5baf84b921c7c4371b848a6e8ece34ad25e45cecf5080e6f6d7b873594'
REPLACEMENT_SOURCE = '2e3bcc2a1095f3e26e4f0b73a6a5515bdd069ee2'


def file_bytes(path, limit=1024 * 1024):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= limit, 'bounded evidence required')
    return path.read_bytes()


def result_binding(sec, raw):
    matches = [p for p in sec.glob('transport-*/result')
               if re.fullmatch('transport-[0-9a-f]{48}', p.parent.name)
               and not p.parent.is_symlink() and not p.is_symlink() and p.is_file()
               and p.stat().st_size == len(raw) and p.read_bytes() == raw]
    require(len(matches) == 1, 'unique authenticated console result required')
    return {'path': str(matches[0].relative_to(sec)), 'sha256': hashlib.sha256(raw).hexdigest()}


def continuation_binding(lab, original_root):
    require(SOURCE == REPLACEMENT_SOURCE, 'continuation is only for the reviewed replacement candidate')
    manifest_path = original_root / '.tools/controller-freeze.json'
    freeze = module('registry_original_freeze', HERE / 'controller-freeze.py')
    manifest = freeze.verify(manifest_path, original_root)
    helper = 'test/e2e/appliance/esxi/prepare-lab-registry.py'
    require(manifest['revision'] == ORIGINAL_CONTROLLER and manifest['files'].get(helper) == ORIGINAL_HELPER,
            'original controller/helper identity differs')
    # freeze.verify already rehashed every original file, including this helper.
    require(hashlib.sha256(guest_script()).hexdigest() == ORIGINAL_PAYLOAD, 'original payload identity differs')
    scope = json.loads(file_bytes(original_root / '.tools/scope-2e3.json'))
    require(Path(scope['run_dir']).resolve() == lab.run.resolve()
            and all(scope[k] == lab.c[k] for k in ('source_sha', 'ova_sha256', 'image_id', 'endpoint')),
            'original run or candidate identity differs')
    raw = file_bytes(lab.sec / 'registry-preparation-transport.txt')
    require(hashlib.sha256(raw).hexdigest() == ORIGINAL_TRANSPORT, 'original failure differs')
    attempt_raw = file_bytes(lab.sec / 'registry-preparation-attempt.json')
    require(json.loads(attempt_raw) == {'status': 'blocked', 'uuid': lab.state['uuid']}, 'original VM attempt differs')
    require(not (lab.sec / 'registry-preparation-receipt.json').exists()
            and not (lab.sec / 'signed-update').exists(), 'registry already progressed')
    # The frozen helper appends one newline before empty stderr.
    failed_result = result_binding(lab.sec, b'1\n' + raw[:-1])
    proof_path = original_root / '.tools/private-operations/firstboot-registry-observation.out'
    proof_raw = file_bytes(proof_path, 65536)
    proof = json.loads(proof_raw)
    require(proof.get('schema') == 1 and proof.get('uid') == 0
            and proof.get('source_sha') == SOURCE and proof.get('firstboot_complete') is True
            and proof.get('registry_root_exists') is False and proof.get('registry_ca_exists') is False
            and proof.get('registry_containers') == [], 'firstboot/no-mutation observation differs')
    require(str(uuid.UUID(proof['boot_id'])) == proof['boot_id'], 'observation boot ID invalid')
    observation_result = result_binding(lab.sec, b'0\n' + proof_raw)
    return {'original_controller': ORIGINAL_CONTROLLER, 'original_helper_sha256': ORIGINAL_HELPER,
            'original_payload_sha256': ORIGINAL_PAYLOAD, 'original_transport_sha256': ORIGINAL_TRANSPORT,
            'original_attempt_sha256': hashlib.sha256(attempt_raw).hexdigest(),
            'original_manifest_sha256': hashlib.sha256(file_bytes(manifest_path)).hexdigest(),
            'failed_result': failed_result, 'observation_result': observation_result,
            'observation_sha256': hashlib.sha256(proof_raw).hexdigest(), 'boot_id': proof['boot_id'],
            'uuid': lab.state['uuid']}


# Read-only guest precondition: no lock creation, directories, trust or Docker mutations.
WAIT_GUEST = r'''
import json, os, pathlib, subprocess, time

def need(ok, message):
    if not ok: raise ValueError(message)

def wait_complete(ready, clock=time.monotonic, pause=time.sleep):
    deadline = clock() + 900
    while True:
        need(clock() <= deadline, 'firstboot completion wait expired; no registry mutation')
        if ready(): return
        remaining = deadline - clock()
        need(remaining > 0, 'firstboot completion wait expired; no registry mutation')
        pause(min(5, remaining))

def audit(containers=True):
    need(not os.path.lexists('/var/lib/culvert-lab-registry')
         and not os.path.lexists('/etc/docker/certs.d/localhost:443'), 'registry paths already exist')
    if not containers: return
    result = subprocess.run(['docker', 'ps', '-a', '--format', '{{.Names}}'], capture_output=True, timeout=15)
    need(result.returncode == 0 and len(result.stdout) <= 65536, 'bounded registry inventory unavailable')
    need(not {'culvert-lab-registry', 'culvert-lab-target-never-started'}.intersection(result.stdout.decode().splitlines()),
         'registry containers already exist')

def main(config):
    need(os.geteuid() == 0, 'authenticated local root required')
    build = json.loads(pathlib.Path('/var/lib/culvert-appliance/build-info.json').read_bytes())
    need(build['source']['git_commit'] == config['source'] and build['source']['git_dirty'] is False
         and build['application']['index_digest'] == config['image'], 'candidate identity differs')
    boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(config['boot_id'] is None or config['boot_id'] == boot, 'continuation boot changed')
    audit(containers=False)
    wait_complete(lambda: pathlib.Path('/var/lib/culvert-appliance/state/complete.done').is_file())
    need(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'boot changed during wait')
    audit()
    print(json.dumps({'source': config['source'], 'image': config['image'], 'boot_id': boot,
                      'firstboot_complete': True, 'registry_absent': True}))
'''


def wait_script(binding=None):
    config = {'source': SOURCE, 'image': BASELINE, 'boot_id': binding['boot_id'] if binding else None}
    return ("timeout --signal=TERM --kill-after=10s 940s python3 - <<'CULVERT_REGISTRY_WAIT'\n"
            + WAIT_GUEST + '\nmain(' + repr(config) + ')\nCULVERT_REGISTRY_WAIT\n').encode()


def console_run(args, script, timeout):
    return subprocess.run([sys.executable, str(HERE / 'console-priv.py'), '--scope', str(args.scope),
                           '--bind', args.bind, '--timeout', str(timeout)], input=script,
                          capture_output=True, timeout=timeout + 120)


def wait_provisioning(args, lab, prefix, binding):
    result = console_run(args, wait_script(binding), 960)
    save_new(lab.sec / (prefix + '-wait-transport.txt'), result.stdout + b'\n' + result.stderr)
    require(result.returncode == 0 and result.stderr == b'' and len(result.stdout) <= 65536,
            'provisioning wait failed; no registry mutation dispatched')
    value = json.loads(result.stdout)
    require(value.get('source') == SOURCE and value.get('image') == BASELINE
            and value.get('firstboot_complete') is True and value.get('registry_absent') is True
            and (binding is None or value.get('boot_id') == binding['boot_id']), 'provisioning observation differs')
    return {'sha256': hashlib.sha256(result.stdout).hexdigest(), 'observation': value}


def validate_receipt(receipt):
    require(isinstance(receipt, dict) and receipt.get('schema') == 1, 'registry receipt schema refused')
    require(receipt.get('source') == SOURCE and receipt.get('ova_sha256') == OVA, 'registry candidate mismatch')
    require(receipt.get('baseline_digest') == BASELINE, 'registry baseline mismatch')
    target = receipt.get('target_digest', '')
    require(DIGEST.fullmatch(target) and target != BASELINE, 'distinct target digest required')
    for name, expected in [('baseline', BASELINE), ('target', target)]:
        raw = base64.b64decode(receipt[name + '_manifest_base64'], validate=True)
        require(0 < len(raw) <= 1024 * 1024 and 'sha256:' + hashlib.sha256(raw).hexdigest() == expected,
                'returned registry manifest bytes differ from digest')
        require(json.loads(raw).get('schemaVersion') == 2, 'unsupported registry manifest')
    require(receipt.get('registry_port_bindings') == {'443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '443'}]},
            'registry must be loopback only')
    for field in ('target_never_started', 'temporary_container_removed', 'application_unchanged'):
        require(receipt.get(field) is True, 'required registry safety evidence missing')
    require(receipt.get('private_tls_key_exported') is False
            and receipt.get('runtime_test_trust') == ['/etc/docker/certs.d/localhost:443/ca.crt'],
            'unexpected runtime trust changes')
    require(DIGEST.fullmatch(receipt.get('registry_image_id', '')) and receipt.get('registry_repo_digests'),
            'registry runtime identity unavailable')
    pem = receipt.get('public_ca_pem', '')
    require(isinstance(pem, str) and 0 < len(pem) <= 16384 and 'PRIVATE KEY' not in pem,
            'only a public registry certificate may leave the guest')
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_pem_x509_certificate(pem.encode('ascii'))
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    require({'ghcr.io', 'localhost'} <= set(names.get_values_for_type(x509.DNSName))
            and ipaddress.ip_address('127.0.0.1') in names.get_values_for_type(x509.IPAddress),
            'registry certificate names incomplete')
    require(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'registry CA constraint missing')
    return target, pem.encode('ascii'), cert.fingerprint(hashes.SHA256()).hex()


def save_new(path, data):
    with path.open('xb') as out:
        out.write(data)


def main():
    global SOURCE, OVA, BASELINE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--resume-firstboot-incomplete', action='store_true')
    parser.add_argument('--original-controller-root', type=Path)
    args = parser.parse_args()
    boot = module('registry_bootstrap', HERE / 'bootstrap-checks.py')
    lab = boot.module.Lab(args.scope)
    prefix = 'registry-preparation-firstboot-continuation' if args.resume_firstboot_incomplete else 'registry-preparation'
    created, attempt = False, lab.sec / (prefix + '-attempt.json')
    binding = None
    try:
        boot.module.validate_scope(lab.c)
        boot.private_directory(lab)
        profile = module('registry_candidate_identities', HERE / 'candidate-identities.py').scope_profile(lab.c)
        SOURCE, OVA, BASELINE = (profile[k] for k in ('source_sha', 'ova_sha256', 'image_id'))
        require(lab.c['source_sha'] == SOURCE and lab.c['ova_sha256'] == OVA and lab.c['image_id'] == BASELINE,
                'exact approved OVA and image required')
        freeze = module('registry_current_freeze', HERE / 'controller-freeze.py')
        current_manifest = freeze.verify(Path(lab.c['controller_manifest']))
        current_helper = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        require(current_manifest['files'].get('test/e2e/appliance/esxi/prepare-lab-registry.py') == current_helper,
                'registry helper is not frozen')
        lab.vm(timeout=15)
        output = lab.sec / 'signed-update'
        require(not output.exists() and not output.is_symlink(), 'fixture output exists; preserve prior attempt')
        require(args.resume_firstboot_incomplete == (args.original_controller_root is not None),
                'explicit original controller required only for reviewed continuation')
        if args.resume_firstboot_incomplete:
            binding = continuation_binding(lab, args.original_controller_root)
        record = {'status': 'started', 'uuid': lab.state['uuid'], 'continuation': binding,
                  'controller_revision': current_manifest['revision'], 'helper_sha256': current_helper}
        save_new(attempt, json.dumps(record).encode())
        created = True
        waited = wait_provisioning(args, lab, prefix, binding)
        if binding:
            require(continuation_binding(lab, args.original_controller_root) == binding, 'original evidence changed during wait')
        save_new(lab.sec / (prefix + '-dispatch.json'), json.dumps({'uuid': lab.state['uuid'],
                 'source': SOURCE, 'payload_sha256': hashlib.sha256(guest_script()).hexdigest(),
                 'wait': waited, 'continuation': binding, 'controller_revision': current_manifest['revision'],
                 'helper_sha256': current_helper}).encode())
        result = console_run(args, guest_script(), 1530)
        save_new(lab.sec / (prefix + '-transport.txt'), result.stdout + b'\n' + result.stderr)
        require(result.returncode == 0 and len(result.stdout) <= 4 * 1024 * 1024,
                'registry transport incomplete or failed; no retry')
        receipt = json.loads(result.stdout)
        target, certificate, ca_fingerprint = validate_receipt(receipt)
        save_new(lab.sec / 'registry-preparation-receipt.json', json.dumps(receipt, indent=2).encode())
        output.mkdir(mode=0o700)
        save_new(output / 'ca.crt', certificate)
        save_new(output / 'target-digest', (target + '\n').encode())
        fixture = module('registry_signed_fixture', HERE / 'prepare-signed-fixture.py')
        fixture.generate(output, REPO + '@' + BASELINE, REPO + '@' + target, '127.0.0.1', source_revision=SOURCE)
        trust = {'schema': 1, 'uuid': lab.state['uuid'], 'source': SOURCE, 'ova_sha256': OVA,
                 'public_ca_sha256': ca_fingerprint, 'baseline_ref': REPO + '@' + BASELINE,
                 'target_ref': REPO + '@' + target, 'registry_address': '127.0.0.1',
                 'prepared_runtime_trust': receipt['runtime_test_trust'],
                 'shared_step_6c_pending_trust': ['/etc/docker/certs.d/ghcr.io/ca.crt', '/etc/hosts ghcr.io mapping',
                                                '/etc/culvert-maint/lab-fixture-keyring.json', 'agent release_trust_keys'],
                 'private_keys_exported': False, 'deliverable_ova_modified': False,
                 'registry_preparation_controller': current_manifest['revision'],
                 'registry_preparation_helper_sha256': current_helper, 'continuation': binding}
        save_new(lab.ev / 'registry-test-trust.json', (json.dumps(trust, indent=2) + '\n').encode())
        boot.module.atomic_json(attempt, dict(record, status='pass'))
        print('PASS: disposable loopback registry and real signed fixture prepared; test-only trust recorded.')
        return 0
    except Exception:
        if created:
            boot.module.atomic_json(attempt, dict(record, status='blocked'))
        print('BLOCKED: registry preparation incomplete; preserve private evidence; no retry.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
