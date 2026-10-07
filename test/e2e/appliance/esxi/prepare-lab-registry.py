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
    args = parser.parse_args()
    boot = module('registry_bootstrap', HERE / 'bootstrap-checks.py')
    lab = boot.module.Lab(args.scope)
    created, attempt = False, lab.sec / 'registry-preparation-attempt.json'
    try:
        boot.module.validate_scope(lab.c)
        boot.private_directory(lab)
        profile = module('registry_candidate_identities', HERE / 'candidate-identities.py').scope_profile(lab.c)
        SOURCE, OVA, BASELINE = (profile[k] for k in ('source_sha', 'ova_sha256', 'image_id'))
        require(lab.c['source_sha'] == SOURCE and lab.c['ova_sha256'] == OVA and lab.c['image_id'] == BASELINE,
                'exact approved OVA and image required')
        lab.vm(timeout=15)
        output = lab.sec / 'signed-update'
        require(not output.exists() and not output.is_symlink(), 'fixture output exists; preserve prior attempt')
        save_new(attempt, json.dumps({'status': 'started', 'uuid': lab.state['uuid']}).encode())
        created = True
        result = subprocess.run([sys.executable, str(HERE / 'console-priv.py'), '--scope', str(args.scope),
                                 '--bind', args.bind, '--timeout', '1530'], input=guest_script(),
                                capture_output=True, timeout=1650)
        save_new(lab.sec / 'registry-preparation-transport.txt', result.stdout + b'\n' + result.stderr)
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
                 'private_keys_exported': False, 'deliverable_ova_modified': False}
        save_new(lab.ev / 'registry-test-trust.json', (json.dumps(trust, indent=2) + '\n').encode())
        boot.module.atomic_json(attempt, {'status': 'pass', 'uuid': lab.state['uuid']})
        print('PASS: disposable loopback registry and real signed fixture prepared; test-only trust recorded.')
        return 0
    except Exception:
        if created:
            boot.module.atomic_json(attempt, {'status': 'blocked', 'uuid': lab.state['uuid']})
        print('BLOCKED: registry preparation incomplete; preserve private evidence; no retry.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
