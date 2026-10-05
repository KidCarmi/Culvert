#!/usr/bin/env python3
"""Enroll only read-only operator access through authenticated local recovery."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

HERE=Path(__file__).resolve().parent


def prepare_attempt(lab, observation=None):
    marker=lab.sec/'operator-enrollment-attempt.json'
    if observation is None:
        with marker.open('x') as out:json.dump({'status':'started','uuid':lab.state['uuid']},out)
        return marker
    # A stopped attempt may continue only after a separate authenticated local
    # observation proved no key was enrolled and first boot completed. Preserve
    # the failed attempt and accept this continuation once, never a blind retry.
    previous=json.loads(marker.read_text())
    if previous != {'status':'started','uuid':lab.state['uuid']} or (lab.sec/'known_hosts').exists():
        raise ValueError('enrollment is not an undispatched initial attempt')
    path=Path(observation).resolve(strict=True)
    if (path.name!='result' or path.parent.parent!=lab.sec.resolve()
            or not re.fullmatch(r'transport-[a-f0-9]{48}',path.parent.name)
            or Path(observation).is_symlink() or path.parent.is_symlink()):
        raise ValueError('private authenticated observation required')
    raw=path.read_bytes()
    expected=b'0\nNO_ENROLLMENT_MUTATION_AND_FIRSTBOOT_COMPLETE\n'
    # Windows stdin can retain one terminal CR after the shell's final newline.
    # Accept only these two complete byte sequences, preserving the raw proof.
    if raw not in (expected,expected+b'\r'):
        raise ValueError('undispatched observation not established')
    resumed=lab.sec/'operator-enrollment-resume-attempt.json'
    with resumed.open('x') as out:
        json.dump({'status':'started','uuid':lab.state['uuid'],
                   'observation_sha256':hashlib.sha256(raw).hexdigest()},out)
    with (lab.sec/'operator-enrollment-initial-attempt.json').open('xb') as out:
        out.write(marker.read_bytes())
    lab.record('operator-enrollment-initial','fail',
               'Controller refused a kernel-displaced sudo prompt; foreground cancelled and separate local observation proved no enrollment mutation; failure preserved')
    return marker


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope',type=Path,required=True)
    parser.add_argument('--bind',required=True)
    parser.add_argument('--resume-undispatched-observation',type=Path)
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location('enroll_boot',HERE/'bootstrap-checks.py')
    boot=importlib.util.module_from_spec(spec);spec.loader.exec_module(boot)
    lab=boot.module.Lab(args.scope);boot.private_directory(lab)
    marker=prepare_attempt(lab,args.resume_undispatched_observation)
    public=(lab.sec/'id_ed25519.pub').read_text().split()
    if len(public)<2 or public[0]!='ssh-ed25519' or len(base64.b64decode(public[1],validate=True))!=51:
        raise ValueError('invalid operator key')
    key=' '.join(public[:2])
    script=("set -euo pipefail\numask 077\n"
            "test ! -L /home/culvert\n"
            "test ! -L /home/culvert/.ssh\n"
            "test ! -L /home/culvert/.ssh/authorized_keys\n"
            "test ! -L /etc/ssh/culvert-authorized-keys\n"
            "test ! -L /etc/ssh/culvert-authorized-keys/culvert-operator\n"
            "test ! -s /home/culvert/.ssh/authorized_keys\n"
            "test ! -s /etc/ssh/culvert-authorized-keys/culvert-operator\n"
            "install -d -m 700 -o culvert -g culvert /home/culvert/.ssh\n"
            f"printf '%s\\n' '{key}' > /home/culvert/.ssh/authorized_keys\n"
            "chown culvert:culvert /home/culvert/.ssh/authorized_keys\n"
            "chmod 600 /home/culvert/.ssh/authorized_keys\n"
            "/opt/culvert-appliance/bin/culvert-access --import-keys >/dev/null\n"
            "cat /etc/ssh/ssh_host_ed25519_key.pub\n").encode()
    result=subprocess.run([sys.executable,str(HERE/'console-priv.py'),'--scope',str(args.scope),
                           '--bind',args.bind,'--timeout','180'],input=script,capture_output=True,timeout=300)
    if result.returncode:raise ValueError('operator enrollment transport failed')
    host=result.stdout.decode('ascii').strip().split()
    if len(host)<2 or host[0]!='ssh-ed25519' or len(base64.b64decode(host[1],validate=True))!=51:
        raise ValueError('invalid authenticated host identity')
    pin=lab.sec/'known_hosts'
    with pin.open('x',encoding='ascii') as out:out.write(lab.state['name']+' '+' '.join(host[:2])+'\n')
    result=subprocess.run(['ssh','-F','none','-i',str(lab.sec/'id_ed25519'),'-o','IdentitiesOnly=yes',
        '-o','IdentityAgent=none','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
        '-o','UserKnownHostsFile='+str(pin),'-o','HostKeyAlias='+lab.state['name'],
        '-o','ConnectTimeout=15','culvert-operator@'+lab.guest_ip(),'status-json'],capture_output=True,timeout=60)
    if result.returncode or json.loads(result.stdout).get('schema_version')!=1:
        raise ValueError('read-only operator validation failed')
    boot.module.atomic_json(marker,{'status':'pass','uuid':lab.state['uuid']})
    lab.record('operator-enrollment','pass','local authenticated import and host-key pin; read-only SSH verified')


if __name__=='__main__':
    try:main()
    except Exception:
        print('Operator enrollment blocked; preserve private evidence; no retry.',file=sys.stderr)
        sys.exit(90)
