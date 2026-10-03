#!/usr/bin/env python3
"""Exercise real govc CLI/API JSON and deletion fencing on loopback vcsim only."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
import time
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('adapter', Path(__file__).with_name('esxi-lab.py'))
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--govc', required=True)
    parser.add_argument('--vcsim', required=True)
    args = parser.parse_args()
    os.environ['GOVC_USERNAME'] = 'simulator'
    os.environ['GOVC_PASSWORD'] = 'simulator'
    for key in ('GOVC_TLS_CA_CERTS', 'GOVC_TLS_KNOWN_HOSTS', 'GOVC_CERTIFICATE', 'GOVC_PRIVATE_KEY'):
        os.environ.pop(key, None)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    # The only non-TLS endpoint here is a simulator launched by this process.
    flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    with tempfile.TemporaryDirectory() as tmp, subprocess.Popen(
        [args.vcsim, '-l', f'127.0.0.1:{port}', '-tls=false'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags
    ) as proc:
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=1):
                        break
                except OSError:
                    if proc.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('simulator failed to start')
                    time.sleep(.1)
            path = Path(tmp) / 'scope.json'
            path.write_text(json.dumps(dict(endpoint=f'http://127.0.0.1:{port}/sdk',
                                            run_dir=str(Path(tmp) / 'run'), govc=str(Path(args.govc).resolve()),
                                            host='/DC0/host/DC0_H0/DC0_H0', pool='/DC0/host/DC0_H0/Resources',
                                            folder='/DC0/vm', datastore='/DC0/datastore/LocalDS_0',
                                            network='/DC0/network/VM Network', ova=str(Path(tmp) / 'synthetic.ova'))))
            obj = adapter.Lab(path)
            assert 'simulator' in obj.gov('about')['about']['fullName']
            name = 'culvert-esxi-simulator-control'
            owner = 'LOCAL-ESXI:simulator-test-only'
            obj.gov('vm.create', '-on=false', '-annotation=' + owner, '-m=64', '-disk=1GB',
                    '-host=/DC0/host/DC0_H0/DC0_H0', '-pool=/DC0/host/DC0_H0/Resources',
                    '-folder=/DC0/vm', '-ds=/DC0/datastore/LocalDS_0', '-net=/DC0/network/VM Network',
                    name, json_output=False)
            vm = obj.gov('vm.info', '/DC0/vm/' + name)['virtualMachines'][0]
            obj.state = dict(name=name, owner=owner, endpoint=obj.c['endpoint'], path='/DC0/vm/' + name,
                             uuid=vm['config']['uuid'], ref=vm['self'], host_ref=vm['runtime']['host'],
                             ds_ref=vm['datastore'][0], network_ref=vm['network'][0])
            obj.save()
            obj.gov('vm.power', '-on', obj.state['path'], json_output=False)
            assert obj.vm()['runtime']['powerState'] == 'poweredOn'
            obj.state['uuid'] = 'same-name-replacement-control'
            try:
                obj.down()
                raise AssertionError('wrong UUID was deleted')
            except adapter.Refused:
                pass
            assert obj.gov('vm.info', obj.state['path'])['virtualMachines'][0]['runtime']['powerState'] == 'poweredOn'
            obj.state['uuid'] = vm['config']['uuid']
            obj.down()
            assert obj.state['deleted']
            obj.down()  # idempotent after confirmed deletion
            # Import path: a synthetic OVF + dummy bytes, NEVER an appliance.
            # Only preflight is substituted because production refuses vcsim.
            template = (adapter.ROOT / 'appliance/build/culvert-appliance.ovf.tmpl').read_text()
            substitutions = dict(DISK_GB='1', FULL_VERSION='SIMULATOR ONLY', HW_VERSION='vmx-13',
                                 MEMORY_MB='64', PRODUCT='SIMULATOR ONLY', VCPUS='1', VENDOR='test',
                                 VERSION='0', VM_NAME='simulated-import', VMDK_NAME='disk.vmdk',
                                 VMDK_POPULATED='512', VMDK_SIZE='512')
            for key, value in substitutions.items():
                template = template.replace('@@' + key + '@@', value)
            files = [('sim.ovf', template.encode()), ('disk.vmdk', b'\0' * 512)]
            mf = ''.join(f'SHA256({n})= {hashlib.sha256(b).hexdigest()}\n' for n, b in files).encode()
            with tarfile.open(obj.c['ova'], 'w') as tf:
                for n, b in files + [('sim.mf', mf)]:
                    info = tarfile.TarInfo(n)
                    info.size = len(b)
                    tf.addfile(info, io.BytesIO(b))
            obj.state = {}
            obj.state_file.unlink()
            data = dict(artifact=dict(networks=['VM Network']), host_ref=vm['runtime']['host'],
                        ds_ref=vm['datastore'][0], network_ref=vm['network'][0])
            native_run = subprocess.run
            import_error = []
            def simulated_run(*args, **kwargs):
                result = native_run(*args, **kwargs)
                if result.returncode and 'import.ova' in args[0]:
                    import_error.append(result.stderr)
                return result
            with patch.object(obj, 'preflight', return_value=data), patch.object(subprocess, 'run', side_effect=simulated_run):
                try:
                    obj.up()
                    raise AssertionError('vcsim unexpectedly implemented NFC upload digests; update this test')
                except adapter.Refused:
                    assert import_error and 'checksum type SHA256 mismatch with uploaded checksum type' in import_error[0]
            imported = obj.vm()
            assert imported['runtime']['powerState'] == 'poweredOff'
            assert obj.state['phase'] == 'import-pending'
            obj.down()
            print(json.dumps(dict(result='PASS', evidence_class='SIMULATOR_ONLY',
                                  checks=['govc-json-schema', 'powered-on-read', 'wrong-uuid-refuses-before-poweroff',
                                          'owned-poweroff-delete', 'idempotent-down', 'partial-import-remains-off',
                                          'partial-import-ledger-cleanup'],
                                  upload_digest='BLOCKED: vcsim does not return an NFC upload digest; production -m retained',
                                  guestinfo_injection='NOT RUN',
                                  appliance_import='NOT RUN', guest_boot='NOT RUN')))
        finally:
            proc.terminate()
            proc.wait(timeout=15)


if __name__ == '__main__':
    main()
