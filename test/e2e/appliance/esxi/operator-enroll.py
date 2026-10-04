#!/usr/bin/env python3
"""Enroll only read-only operator access through authenticated local recovery."""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

HERE=Path(__file__).resolve().parent


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope',type=Path,required=True)
    parser.add_argument('--bind',required=True)
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location('enroll_boot',HERE/'bootstrap-checks.py')
    boot=importlib.util.module_from_spec(spec);spec.loader.exec_module(boot)
    lab=boot.module.Lab(args.scope);boot.private_directory(lab)
    marker=lab.sec/'operator-enrollment-attempt.json'
    with marker.open('x') as out:json.dump({'status':'started','uuid':lab.state['uuid']},out)
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
