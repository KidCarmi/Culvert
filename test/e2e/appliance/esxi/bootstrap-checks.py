#!/usr/bin/env python3
"""One-shot default-import PAM bootstrap qualification; private local evidence only.

No VM creation, reboot, overlays, credential guesses, or authentication retries.
Use only after an owned credential_mode=none import. OCR ambiguity is BLOCKED,
never an excuse to try another password. The parent operator reviews this tool
before executing it against a disposable VM.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('esxi_lab', HERE / 'esxi-lab.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ALPHABET = 'A-HJ-NP-Za-km-z2-9'


class Blocked(Exception):
    """Messages are fixed stage descriptions, never raw external data."""


def ensure(condition, message):
    if not condition:
        raise Blocked(message)


def private_directory(lab):
    ensure(os.name == 'nt', 'this OCR qualification requires Windows')
    ensure(lab.sec.resolve() == lab.run.resolve() / 'secrets', 'private directory location refused')
    script = r"""$ErrorActionPreference='Stop';
$p=$env:CULVERT_PRIVATE_DIR; $a=Get-Acl -LiteralPath $p;
$allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18');
if (-not $a.AreAccessRulesProtected) {exit 1};
foreach($r in $a.Access) {if ($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed) {exit 1}};
$i=Get-Item -LiteralPath $p -Force; if (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {exit 1}
"""
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            env=dict(os.environ, CULVERT_PRIVATE_DIR=str(lab.sec)),
                            capture_output=True, timeout=15)
    ensure(result.returncode == 0, 'private directory ACL verification failed')


class PrivateKeyboard:
    """Reusable by console-checks.py: keyboard.send(value, text=False)."""
    def __init__(self, lab):
        self.lab = lab
        private_directory(lab)
        self.source = HERE / 'private-keystrokes.go'
        self.binary = lab.sec / 'private-keystrokes.exe'
        govmomi = module.ROOT / '.tools/govmomi-v0.56.0-src'
        ensure((govmomi / 'go.mod').is_file(), 'existing local govmomi source unavailable')
        env = dict(os.environ, GOWORK='off', GOENV='off', GOFLAGS='', GOPROXY='off', GOSUMDB='off',
                   CGO_ENABLED='0', GOCACHE=str(lab.sec / 'go-cache'), GOTMPDIR=str(lab.sec))
        result = subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-o', str(self.binary), str(self.source)],
                                cwd=govmomi, env=env, capture_output=True, timeout=180)
        ensure(result.returncode == 0, 'offline private keyboard helper build failed')
        hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                  for name, path in [('source_sha256', self.source), ('binary_sha256', self.binary)]}
        module.atomic_json(lab.sec / 'private-keyboard-build.json', hashes)
        lab.record('private-keyboard-helper', 'info', 'stdin helper compiled locally; source/binary SHA256 ' +
                   hashes['source_sha256'] + '/' + hashes['binary_sha256'])

    def send(self, value, text=False):
        # Re-read exact owned VM identity and resource placement before EVERY key.
        vm = self.lab.vm(timeout=15)
        ensure(vm.get('runtime', {}).get('powerState') == 'poweredOn', 'owned VM is not powered on')
        payload = dict(reference=self.lab.state['ref']['value'], uuid=self.lab.state['uuid'],
                       owner=self.lab.state['owner'], text=value if text else '', code='' if text else value)
        env = dict(self.lab._credential_env)
        env.update(GOVC_URL=self.lab.c['endpoint'], GOVC_PERSIST_SESSION='false',
                   GOVC_INSECURE='true' if self.lab.c.get('tls_insecure') else 'false')
        result = subprocess.run([str(self.binary)], input=json.dumps(payload), env=env,
                                capture_output=True, text=True, timeout=30)
        ensure(result.returncode == 0, 'private keyboard operation failed; no input retry')


def extract_initial(text):
    if 'initial console access' not in text.lower():
        return None
    matches = re.findall(r'one[ -]time\s+password\s*:\s*([' + ALPHABET + r']{16})(?![' + ALPHABET + '])', text, re.I)
    # Do not case-fold/repair the credential; validate exact original characters.
    if len(matches) == 1 and re.fullmatch('[' + ALPHABET + ']{16}', matches[0]):
        return matches[0]
    return None


def classify(text):
    normalized = ' '.join(text.lower().split())
    if any(x in normalized for x in ('login incorrect', 'authentication failure', 'password unchanged', 'bad password')):
        return 'rejected'
    if 'authenticated recovery' in normalized:
        return 'recovery'
    if 'authenticated as culvert' in normalized:
        return 'admin'
    if 'type exit to return to the menu' in normalized:
        return 'shell'
    if re.search(r'(?:retype|repeat) (?:new )?(?:unix )?password\s*:\s*$', normalized):
        return 'repeat'
    if re.search(r'(?:\(current\)|current|old) (?:unix )?password\s*:\s*$', normalized):
        return 'current'
    if re.search(r'new (?:unix )?password\s*:\s*$', normalized):
        return 'new'
    if re.search(r'(?:^|\s)password\s*:\s*$', normalized) and 'one-time password' not in normalized:
        return 'password'
    return 'unknown'


class Bootstrap:
    def __init__(self, lab, keyboard):
        self.lab, self.keyboard = lab, keyboard
        self.deadline = time.monotonic() + 600
        self.sequence = 0
        self.stage = 'initial-capture'

    def budget(self, maximum, deadline=None):
        remaining = min(self.deadline, deadline or self.deadline) - time.monotonic()
        ensure(remaining >= 1, 'bounded bootstrap observation expired')
        return min(maximum, remaining)

    def screen(self, deadline):
        self.sequence += 1
        ensure(self.sequence <= 80, 'private capture count exhausted')
        stem = 'bootstrap-' + str(self.sequence).zfill(3)
        png, ocr = self.lab.sec / (stem + '.png'), self.lab.sec / (stem + '.txt')
        self.lab.vm(timeout=self.budget(15, deadline))
        self.lab.gov('vm.console', '-capture=' + str(png), self.lab.state['path'],
                     json_output=False, timeout=self.budget(20, deadline))
        ensure(png.is_file() and 0 < png.stat().st_size <= 10 * 1024**2, 'private screenshot unavailable or oversized')
        timeout = max(1, int(self.budget(15, deadline)))
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(HERE / 'console-ocr.ps1'),
                                 '-ImagePath', str(png), '-OutputPath', str(ocr), '-TimeoutSeconds', str(timeout)],
                                capture_output=True, timeout=self.budget(timeout + 3, deadline))
        if result.returncode or not ocr.is_file():
            return ''
        ensure(ocr.stat().st_size <= 65536, 'private OCR exceeded bounds')
        return ocr.read_text(encoding='utf-8-sig')

    def wait(self, states, timeout=60):
        deadline = min(self.deadline, time.monotonic() + timeout)
        while time.monotonic() < deadline:
            state = classify(self.screen(deadline))
            ensure(state != 'rejected', 'PAM rejected the one-shot credential workflow')
            if state in states:
                return state
            time.sleep(min(2, self.budget(2, deadline)))
        raise Blocked('console prompt unreadable or unavailable; no credential retry')

    def initial(self):
        deadline = min(self.deadline, time.monotonic() + 180)
        previous = None
        while time.monotonic() < deadline:
            current = extract_initial(self.screen(deadline))
            if current and current == previous:
                return current
            previous = current
            # More than one normal display refresh separates matching captures.
            time.sleep(min(6, self.budget(6, deadline)))
        raise Blocked('initial credential not readable identically in two captures')

    def enter(self, value):
        self.budget(1)
        self.keyboard.send(value, text=True)
        self.keyboard.send('KEY_ENTER')

    def authenticate(self):
        initial = self.initial()
        self.lab.record('bootstrap-persistent-display', 'pass', 'identical initial credential recognized in two private captures separated by a refresh; reboot not tested')
        password = 'Qv7' + secrets.token_hex(18) + 'Z9'
        with (self.lab.sec / 'bootstrap-console-password').open('x', encoding='ascii') as out:
            out.write(password)
        self.stage = 'pam-login'
        self.keyboard.send('KEY_F2')
        self.wait({'password'})
        self.enter(initial)
        self.stage = 'pam-forced-change'
        state = self.wait({'current', 'new'})
        if state == 'current':
            self.enter(initial)
            self.wait({'new'})
        self.enter(password)
        self.wait({'repeat'})
        self.enter(password)
        self.wait({'admin'})
        self.lab.record('bootstrap-pam-forced-change', 'pass', 'real F2/PAM login and required password change reached authenticated menu; no authentication retries')
        return password

    def install_key_and_pin(self):
        self.stage = 'authenticated-shell'
        self.keyboard.send('KEY_0')
        self.wait({'recovery'})
        self.keyboard.send('KEY_3')
        self.wait({'shell'})
        public = (self.lab.sec / 'id_ed25519.pub').read_text(encoding='ascii').split()
        ensure(len(public) >= 2 and public[0] == 'ssh-ed25519' and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', public[1]),
               'generated public key unavailable')
        public = ' '.join(public[:2])
        self.enter("set +o history; HISTFILE=/dev/null; umask 077; mkdir -p ~/.ssh; chmod 700 ~/.ssh; printf '%s\\n' " +
                   shlex.quote(public) + " >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys")
        # keyscan is untrusted until its fingerprint is compared on the already
        # authenticated VMware console. Never use StrictHostKeyChecking=accept-new.
        self.stage = 'console-hostkey-pin'
        ip = self.lab.guest_ip(timeout=30)
        scan = subprocess.run(['ssh-keyscan', '-T', '5', '-t', 'ed25519', ip], capture_output=True, text=True, timeout=15)
        ensure(scan.returncode == 0 and len(scan.stdout) <= 8192, 'SSH host-key observation unavailable')
        candidates = {tuple(line.split()[1:]) for line in scan.stdout.splitlines() if line and not line.startswith('#')}
        ensure(len(candidates) == 1, 'SSH host-key observation ambiguous')
        kind, encoded = next(iter(candidates))
        ensure(kind == 'ssh-ed25519' and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', encoded), 'unsupported SSH host key')
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(encoded, validate=True)).digest()).decode().rstrip('=')
        nonce = secrets.token_hex(8).upper()
        expected = 'PIN VERIFIED ' + nonce
        # The literal success marker must never occur in the echoed command.
        # Encoding it prevents OCR dropping printf-format punctuation from
        # turning a command echo into apparent successful verification.
        marker = base64.b64encode((expected + '\n').encode('ascii')).decode('ascii')
        self.enter("test \"$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256 | awk '{print $2}')\" = " +
                   shlex.quote(fingerprint) + " && printf %s " + shlex.quote(marker) + " | base64 -d")
        deadline = min(self.deadline, time.monotonic() + 45)
        while time.monotonic() < deadline:
            text = ' '.join(self.screen(deadline).split())
            if expected in text:
                with (self.lab.sec / 'known_hosts').open('x', encoding='ascii') as out:
                    out.write(self.lab.state['name'] + ' ' + kind + ' ' + encoded + '\n')
                self.lab.record('bootstrap-ssh-hostkey-pin', 'pass', 'network-observed SSH host key matched authenticated console fingerprint challenge before SSH access')
                return ip
            time.sleep(min(2, self.budget(2, deadline)))
        raise Blocked('console host-key challenge unreadable or unmatched; SSH refused')

    def verify(self, ip, password):
        self.stage = 'ssh-cleanup-verification'
        ssh = self.lab.ssh_command(ip, strict=True)
        root_check = ("test \"$(id -u)\" = 0 || exit 1; "
                      "getent shadow culvert | awk -F: '$1 == \"culvert\" && $3 ~ /^[0-9]+$/ && $3 > 0 {seen++} END {exit seen != 1}' || exit 2; "
                      "if test -e /var/lib/culvert-console/bootstrap/credential.json; then printf BOOTSTRAP_PENDING; "
                      "else printf BOOTSTRAP_CLEAN; fi")
        command = "sudo -k -S -p '' -- /bin/sh -c " + shlex.quote(root_check)
        deadline = min(self.deadline, time.monotonic() + 60)
        while time.monotonic() < deadline:
            self.lab.vm(timeout=self.budget(15, deadline))
            result = subprocess.run(ssh + [command], input=password + '\n', capture_output=True,
                                    text=True, timeout=self.budget(20, deadline))
            # Authentication is never retried: only the post-auth cleanup predicate
            # may still be pending while the worker reaches its next observation.
            ensure(result.returncode == 0 and result.stdout in ('BOOTSTRAP_CLEAN', 'BOOTSTRAP_PENDING'),
                   'pinned SSH or sudo verification failed; no authentication retry')
            if result.returncode == 0 and result.stdout == 'BOOTSTRAP_CLEAN':
                self.lab.record('bootstrap-private-record-cleanup', 'pass', 'pinned SSH and password-authenticated sudo confirmed forced-change cleared and private handoff absent')
                return
            time.sleep(min(2, self.budget(2, deadline)))
        raise Blocked('private bootstrap cleanup not verified within worker budget')


def run(lab):
    module.validate_scope(lab.c)
    ensure(lab.c.get('credential_mode') == 'none' and lab.state.get('phase') == 'powered-on', 'fresh credential_mode=none import required')
    private_directory(lab)
    properties = json.loads((lab.sec / 'import.json').read_text(encoding='utf-8'))['PropertyMapping']
    ensure(not any(p.get('Value') and any(word in p.get('Key', '').lower() for word in ('password', 'public-key', 'ssh')) for p in properties),
           'import properties include credentials; default bootstrap qualification refused')
    lab.vm(timeout=15)
    # Create before compilation/capture/input; failed or partial runs cannot replay.
    with (lab.sec / 'bootstrap-attempt.json').open('x', encoding='utf-8') as out:
        json.dump({'status': 'started', 'vm_uuid': lab.state['uuid']}, out)
    flow = None
    try:
        flow = Bootstrap(lab, PrivateKeyboard(lab))
        password = flow.authenticate()
        ip = flow.install_key_and_pin()
        flow.verify(ip, password)
        module.atomic_json(lab.sec / 'bootstrap-attempt.json', {'status': 'passed', 'vm_uuid': lab.state['uuid']})
    except Exception:
        stage = flow.stage if flow else 'private-tool-preparation'
        module.atomic_json(lab.sec / 'bootstrap-attempt.json', {'status': 'blocked', 'stage': stage, 'vm_uuid': lab.state['uuid']})
        raise Blocked('default bootstrap stopped at ' + stage + '; private capture/prompt/transport evidence did not complete') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    args = parser.parse_args()
    lab = module.Lab(args.scope)
    with module.locked(lab.run):
        try:
            run(lab)
        except Exception:
            lab.record('default-bootstrap-suite', 'blocked', 'one-shot bootstrap incomplete; inspect only private local evidence; no input replay')
            raise SystemExit(1) from None
    lab.record('default-bootstrap-suite', 'pass', 'default import reached actual PAM password change, authenticated key installation and pinned SSH cleanup verification; reboot survival not tested')


if __name__ == '__main__':
    main()
