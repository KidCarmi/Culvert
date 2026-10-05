#!/usr/bin/env python3
"""ESXi LAB_PRIV_CMD: tty1 PAM session + password sudo, never admin SSH.

Scripts/results travel over a temporary controller HTTPS listener. The command
typed on the authenticated console pins its public key AND script SHA256.
Only the owned guest IP and one-use random URLs are accepted. No guest service,
sudoers rule, trusted CA, or privileged SSH command is installed.
"""
import argparse
import base64
import datetime
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
from pathlib import Path
import re
import secrets
import shlex
import ssl
import sys
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bootstrap_checks', HERE / 'bootstrap-checks.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class Keyboard(b.PrivateKeyboard):
    def __init__(self, lab):
        self.lab = lab
        b.private_directory(lab)
        self.binary = lab.sec / 'private-keystrokes.exe'
        self.source = HERE / 'private-keystrokes.go'
        record = json.loads((lab.sec / 'private-keyboard-build.json').read_text())
        for name, path in [('source_sha256', self.source), ('binary_sha256', self.binary)]:
            b.ensure(hashlib.sha256(path.read_bytes()).hexdigest() == record[name], 'keyboard identity changed')


class Console(b.Bootstrap):
    def __init__(self, lab):
        super().__init__(lab, Keyboard(lab))
        # Capture filenames stay unique across independent helper invocations.
        self.sequence = int(time.time() * 1000)

    def screen(self, deadline):
        seq = self.sequence
        self.sequence = 0
        # The existing bounded OCR helper must use a fresh filename.
        original = self.lab.sec
        capture = original / ('capture-' + secrets.token_hex(8))
        capture.mkdir()
        self.lab.sec = capture
        try:
            return super().screen(deadline)
        finally:
            self.lab.sec = original
            self.sequence = seq + 1

    def shell_prompt(self, text):
        lines = text.rstrip().splitlines()
        if not lines:
            return False
        # The recovery shell deliberately starts with a minimal environment;
        # Ubuntu's bash default PS1 is therefore version-based. VM ownership is
        # checked by the capture API. Never strip a cursor/unknown glyph: wait
        # for a clean blink-off capture instead.
        if lines[-1].strip() == 'bash-5.2$':
            return True
        pattern = r'culvert@' + re.escape(self.lab.state['name']) + r':[A-Za-z0-9_./~+-]+\$'
        return re.fullmatch(pattern, lines[-1].strip()) is not None

    def wait_shell(self):
        deadline = min(self.deadline, time.monotonic() + 60)
        redrawn = False
        while time.monotonic() < deadline:
            text = self.screen(deadline)
            if self.shell_prompt(text):
                return
            b.ensure(b.classify(text) != 'rejected', 'console authentication rejected')
            if not redrawn and self.can_redraw_shell(text):
                # Readline redraw only: never Enter, credentials, or a command.
                # Retain the prior capture and leave kernel/serial output enabled.
                self.keyboard.send('KEY_CTRL_L')
                redrawn = True
            time.sleep(min(2, self.budget(2, deadline)))
        raise b.Blocked('owned local shell prompt unavailable; input refused')

    @staticmethod
    def authentication_prompt(line):
        return (b.classify(line) in {'password', 'current', 'new', 'repeat', 'rejected'}
                or re.search(r'(?:password|LAB AUTH [A-Z0-9]+)\s*:\s*(?:\ufffd)?$', line,
                             flags=re.IGNORECASE) is not None)

    def can_redraw_shell(self, text):
        lines = [line.strip() for line in text.splitlines()]
        markers = [i for i, line in enumerate(lines) if line in {
            'LAB SHELL READY', 'Recovery shell. Type exit to return to the menu.'}]
        if not markers:
            return False
        after = lines[markers[-1] + 1:]
        # A prompt may have been displaced by kernel output too. Refuse any
        # authentication prompt since the last completed-shell marker.
        if any(self.authentication_prompt(line) for line in after):
            return False
        return any(re.match(r'^(?:bash-5\.2\$\s*)?\[\s*\d+(?:\.\d+)?\]\s', line)
                   for line in after)

    def shell(self, password):
        text = self.screen(time.monotonic() + 25)
        if self.shell_prompt(text):
            return
        # Old menu/shell banners may remain above a current PAM prompt.
        last = text.rstrip().splitlines()[-1] if text.rstrip() else ''
        b.ensure(not self.authentication_prompt(last),
                 'unexpected authentication prompt; input refused')
        state = b.classify(text)
        if state == 'admin':
            self.keyboard.send('KEY_0')
            self.wait({'recovery'})
            self.keyboard.send('KEY_3')
            self.wait_shell()
        elif state == 'recovery':
            self.keyboard.send('KEY_3')
            self.wait_shell()
        elif state == 'shell' or 'LAB SHELL READY' in text:
            self.wait_shell()
        elif 'Sign in' in text or 'SIGN IN' in text or 'Network information' in text:
            self.keyboard.send('KEY_F2')
            self.wait({'password'})
            self.enter(password)
            self.wait({'admin'})
            self.keyboard.send('KEY_0')
            self.wait({'recovery'})
            self.keyboard.send('KEY_3')
            self.wait_shell()
        else:
            raise b.Blocked('console state unknown; input refused')


def make_tls(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable ESXi lab controller')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    keypath, certpath = directory / 'controller.key', directory / 'controller.crt'
    keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pin = 'sha256//' + base64.b64encode(hashlib.sha256(spki).digest()).decode()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certpath, keypath)
    return ctx, pin


def sudo_prompt_ready(text, prompt):
    """Recognize our nonce prompt despite narrowly known kernel diagnostics.

    Kernel output may displace a waiting sudo prompt without changing who owns
    terminal input. Never normalize arbitrary suffixes or repair unknown glyphs:
    an unrecognized line must leave credentials unsent.
    """
    if text.count(prompt) != 1:
        return False
    lines = text.replace('\r\n', '\n').split('\n')
    for index, line in enumerate(lines):
        line = line.lstrip(' ')
        if line.startswith(prompt):
            suffix = [line[len(prompt):]] + lines[index + 1:]
            break
    else:
        return False
    veth = r'veth[0-9a-f]{1,11}'
    bridge = r'(?:br-[0-9a-f]{12}|docker0)'
    ethernet = r'eth[0-9]{1,3}'
    diagnostic = (
        bridge + r': port [0-9]+\(' + veth + r'\) entered (?:blocking|disabled|forwarding) state'
        + r'|' + veth + r': (?:entered|left) (?:allmulticast|promiscuous) mode'
        + r'|' + veth + r' \(unregistering\): left (?:allmulticast|promiscuous) mode'
        + r'|device ' + veth + r' (?:entered|left) (?:allmulticast|promiscuous) mode'
        + r'|' + ethernet + r': renamed from ' + veth
        + r'|' + veth + r': renamed from ' + ethernet)
    kernel = r'\[ *[0-9]{1,10}(?:\.[0-9]{1,6})?\] (?:' + diagnostic + r')'
    for line in suffix:
        if any(ord(char) < 32 or ord(char) > 126 for char in line):
            return False
        line = line.strip(' ')
        if line and re.fullmatch(kernel, line) is None:
            return False
    return True


def execute(lab, args, script):
    b.private_directory(lab)
    b.ensure(len(script) <= 1024 * 1024, 'script exceeds controller bound')
    guest = lab.guest_ip(timeout=30)
    password = (lab.sec / 'bootstrap-console-password').read_text(encoding='ascii')
    console = Console(lab)
    console.shell(password)
    nonce = secrets.token_hex(24)
    directory = lab.sec / ('transport-' + nonce)
    directory.mkdir()
    ctx, pin = make_tls(directory)
    state = {'fetched': False, 'result': None}
    event = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *unused):
            pass

        def do_GET(self):
            if self.client_address[0] != guest or self.path != '/' + nonce or state['fetched']:
                self.send_error(403)
                return
            state['fetched'] = True
            self.send_response(200)
            self.send_header('Content-Length', str(len(script)))
            self.end_headers()
            self.wfile.write(script)

        def do_POST(self):
            try:
                length = int(self.headers.get('Content-Length', '-1'))
            except ValueError:
                self.send_error(400)
                return
            if (self.client_address[0] != guest or self.path != '/' + nonce + '/result'
                    or not state['fetched'] or state['result'] is not None or not 0 <= length <= 8 * 1024 * 1024):
                self.send_error(403)
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.send_error(400)
                return
            state['result'] = body
            self.send_response(200)
            self.end_headers()
            event.set()

    class BoundedServer(HTTPServer):
        def get_request(self):
            connection, address = self.socket.accept()
            connection.settimeout(5)
            try:
                return ctx.wrap_socket(connection, server_side=True), address
            except Exception:
                connection.close()
                raise

    server = BoundedServer((args.bind, 0), Handler)
    server.timeout = 2
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = 'https://' + args.bind + ':' + str(server.server_port) + '/' + nonce
    curl = 'curl -fsSk --connect-timeout 5 --max-time 30 --pinnedpubkey ' + shlex.quote(pin)
    checksum = hashlib.sha256(script).hexdigest()
    remote = '/tmp/.culvert-lab-' + nonce
    # The result marker is assembled, not literally echoed in the command.
    finish = '; rm -f "$f" "$f.out" "$f.result"; printf TEFCIFNIRUxMIFJFQURZCg== | base64 -d'
    prompt = 'LAB AUTH ' + secrets.token_hex(8).upper() + ':'
    prompt64 = base64.b64encode((prompt + ' ').encode()).decode()
    run = 'bash "$f"' if args.as_user else 'sudo -k -p "$(printf ' + prompt64 + ' | base64 -d)" -- bash "$f"'
    if args.nowait:
        # Acknowledge only once authenticated execution begins, prior to reboot.
        body = ('printf "0\\n" > ' + shlex.quote(remote + '.started') + '; ' + curl +
                ' --data-binary @' + shlex.quote(remote + '.started') + ' ' + shlex.quote(url + '/result') +
                '; rm -f ' + shlex.quote(remote + '.started') + '\n').encode() + script
        script = body
        checksum = hashlib.sha256(script).hexdigest()
    command = ('set +o history; HISTFILE=/dev/null; umask 077; f=' + shlex.quote(remote) + '; ' + curl + ' ' +
               shlex.quote(url) + ' -o "$f" && test "$(sha256sum "$f" | head -c 64)" = ' + checksum +
               ' && { ' + run + ' >"$f.out" 2>&1; r=$?; { printf "%s\\n" "$r"; cat "$f.out"; } >"$f.result"; ' +
               curl + ' --data-binary @"$f.result" ' + shlex.quote(url + '/result') + '; }' + finish)
    try:
        console.enter(command)
        if not args.as_user:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                observed = console.screen(deadline)
                if state['fetched'] and state['result'] is None and sudo_prompt_ready(observed, prompt):
                    console.enter(password)
                    break
                time.sleep(1)
            else:
                raise b.Blocked('sudo prompt unverified; credential not entered')
        b.ensure(event.wait(args.timeout), 'console command result timed out; no retry')
        raw = state['result']
        (directory / 'result').write_bytes(raw)
        code, sep, output = raw.partition(b'\n')
        b.ensure(sep and code.isdigit() and 0 <= int(code) <= 255, 'invalid command result')
        sys.stdout.buffer.write(output)
        return int(code)
    finally:
        server.shutdown()
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--as-user', action='store_true')
    parser.add_argument('--nowait', action='store_true')
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    lab = b.module.Lab(args.scope)
    try:
        with b.module.locked(lab.run):
            return execute(lab, args, sys.stdin.buffer.read(1024 * 1024 + 1))
    except Exception:
        print('Authenticated console transport blocked; inspect private evidence; no retry.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
