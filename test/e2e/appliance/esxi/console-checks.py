#!/usr/bin/env python3
"""Exercise the installed console through ESXi keystrokes and real tty1/PAM.

Requires an owned key-provisioned VM. Sets a disposable console password on
that VM; never installs an overlay or exports credentials/terminal contents.
This does not qualify the no-imported-credential bootstrap path.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import time

spec = importlib.util.spec_from_file_location('esxi_lab', Path(__file__).with_name('esxi-lab.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
keyboard_spec = importlib.util.spec_from_file_location('bootstrap_checks', Path(__file__).with_name('bootstrap-checks.py'))
keyboard_module = importlib.util.module_from_spec(keyboard_spec)
keyboard_spec.loader.exec_module(keyboard_module)


def run(lab):
    lab.vm()
    ssh = lab.ssh_command(lab.guest_ip(timeout=60), strict=True)
    keyboard = keyboard_module.PrivateKeyboard(lab)

    def remote(command, data=None):
        # Windows text-mode stdin expands LF to CRLF, changing a chpasswd value.
        result = subprocess.run(ssh + [command], input=data.encode() if data is not None else None,
                                capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('guest console observation/action failed')
        return result.stdout.decode('utf-8', errors='replace')

    def key(value, text=False):
        keyboard.send(value, text=text)

    def wait_for(predicate, description, timeout=30):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(.5)
        raise RuntimeError(description)

    def screen_has(text):
        return text in remote('sudo -n cat /dev/vcs1')

    def record(name, detail):
        lab.record(name, 'pass', detail)

    assert 'active' in remote('systemctl is-active culvert-console-host.service')
    assert '--login' in remote('ps -t tty1 -o args=')
    wait_for(lambda: screen_has('Network information'), 'public console unavailable')
    record('tty1-public-console', 'installed getty menu and root recovery worker active without overlay')
    for button, heading in [('KEY_1', 'NETWORK / OBSERVED STATE'),
                            ('KEY_2', 'SETUP ACCESS / BROWSER HANDOFF'),
                            ('KEY_3', 'DIAGNOSE READINESS'),
                            ('KEY_4', 'INSTALLATION REPORT / CURRENT OBSERVATION')]:
        key('KEY_B')
        key(button)
        wait_for(lambda: screen_has(heading), 'public view unavailable')
    key('KEY_B')
    record('tty1-public-views', 'all four views rendered in the real tty1 buffer')

    password = secrets.token_hex(16)
    remote('sudo -n chpasswd', 'culvert:' + password + '\n')
    # Only this disposable VM's account is changed, using the imported key's
    # existing sudo authorization. No global/host authentication is altered.
    key('KEY_F2')
    wait_for(lambda: screen_has('Password:'), 'PAM password prompt unavailable')
    key('invalid-console-qualification', text=True)
    key('KEY_ENTER')
    wait_for(lambda: screen_has('Login incorrect'), 'PAM rejection unavailable')
    assert '--admin' not in remote('ps -t tty1 -o args=')
    record('tty1-pam-rejection', 'incorrect password did not enter authenticated menu')

    remote('sudo -n systemctl restart getty@tty1.service')
    wait_for(lambda: screen_has('Network information'), 'public console did not recover')
    key('KEY_F2')
    wait_for(lambda: screen_has('Password:'), 'PAM prompt unavailable after restart')
    key(password, text=True)
    key('KEY_ENTER')
    wait_for(lambda: '--admin' in remote('ps -t tty1 -o args='), 'PAM login did not enter menu')
    wait_for(lambda: screen_has('Authenticated as culvert'), 'authenticated screen unavailable')
    record('tty1-pam-login', 'real VMware keyboard input and Linux PAM reached authenticated menu')

    key('KEY_0')
    wait_for(lambda: screen_has('AUTHENTICATED RECOVERY'), 'recovery view unavailable')
    key('KEY_3')
    time.sleep(2)
    key('stty -echo; printf CONSOLE_QUAL_CANARY; exit', text=True)
    key('KEY_ENTER')
    wait_for(lambda: screen_has('Press Enter to return'), 'shell did not return')
    mode = remote('sudo -n stty -F /dev/tty1 -a').split()
    assert 'echo' in mode and '-echo' not in mode
    key('KEY_ENTER')
    wait_for(lambda: screen_has('Authenticated as culvert'), 'menu did not resume')
    record('tty1-shell-restoration', 'real recovery shell returned with terminal echo restored')

    raw = remote('sudo -n journalctl -t culvert-console -o json --no-pager')
    assert password not in raw and 'CONSOLE_QUAL_CANARY' not in raw
    events = []
    for line in raw.splitlines():
        entry = json.loads(line)
        event = json.loads(entry['MESSAGE'])
        assert str(event['uid']) == str(entry['_UID'])
        if event['action'] == 'recovery_shell':
            events.append(event)
    assert len(events) == 2 and events[0]['id'] == events[1]['id']
    assert events[0]['phase'] == 'attempt' and events[1]['outcome'] == 'returned'
    record('tty1-action-audit', 'correlated shell attempt/result with trusted UID; secret and output canary absent')
    key('KEY_Q')
    wait_for(lambda: '--admin' not in remote('ps -t tty1 -o args='), 'logout failed')
    wait_for(lambda: screen_has('Network information'), 'public console missing after logout')
    record('tty1-logout', 'logout returned to public console')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    args = parser.parse_args()
    lab = module.Lab(args.scope)
    with module.locked(lab.run):
        try:
            run(lab)
        except Exception as exc:
            lab.record('tty1-console-suite', 'fail', str(exc) or type(exc).__name__)
            raise SystemExit(1) from None
    lab.record('tty1-console-suite', 'pass', 'installed console exercised; default credential bootstrap is a separate scenario')


if __name__ == '__main__':
    main()
