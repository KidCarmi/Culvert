"""Private authenticated-console payload; never run directly on the controller.

The controller appends a literal CONFIG and calls main(CONFIG). No credentials
are accepted in argv, printed, or passed through shell evaluation.
"""
import fcntl
import hashlib
import http.client
import http.cookiejar
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import ssl
import time
import urllib.error
import urllib.request

STACK = Path('/srv/culvert')
SECRET_NAMES = ('CULVERT_CA_PASSPHRASE', 'CULVERT_LOG_PASSPHRASE', 'CULVERT_SESSION_SECRET')


def require(ok):
    if not ok:
        raise RuntimeError('fresh recovery prerequisite or evidence refused')


def regular(path):
    require(path.is_file() and not path.is_symlink())


def wait_provisioned(ready, boot_id, clock=time.monotonic, pause=time.sleep):
    """Wait read-only before locks, Docker commands or recovery transfers."""
    first_boot = boot_id()
    started = clock()
    deadline = started + 900
    while True:
        require(boot_id() == first_boot and clock() <= deadline)
        if ready():
            require(boot_id() == first_boot)
            return {'firstboot_complete': True, 'boot_id': first_boot,
                    'wait_seconds': round(clock() - started, 3), 'budget_seconds': 900}
        remaining = deadline - clock()
        require(remaining > 0)
        pause(min(5, remaining))


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


class Guest:
    def __init__(self, cfg):
        require(os.geteuid() == 0)
        os.umask(0o077)
        self.cfg = cfg
        self.work = Path(tempfile.mkdtemp(prefix='culvert-fresh-recovery-', dir='/var/tmp'))
        self.counter = 0
        self.locks = []
        self.phase = 'preflight'
        self.compose = ['docker', 'compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.maint-agent.yml']

    def run(self, argv, *, env=None, allowed=(0,), timeout=600):
        self.counter += 1
        log = self.work / ('command-%03d.log' % self.counter)
        with log.open('xb') as output:
            p = subprocess.run(argv, cwd=STACK, stdin=subprocess.DEVNULL, stdout=output,
                               stderr=subprocess.STDOUT, env=env, timeout=timeout, check=False)
        require(p.returncode in allowed)
        require(log.stat().st_size <= 4 * 1024 * 1024)
        return p.returncode, log.read_bytes()

    def dc(self, *argv, **kwargs):
        return self.run(self.compose + list(argv), **kwargs)

    def transfer(self, resource, file, upload):
        args = ['curl', '-fsSk', '--connect-timeout', '5', '--max-time', '300',
                '--pinnedpubkey', self.cfg['pin']]
        args += ['--data-binary', '@' + str(file)] if upload else ['--output', str(file)]
        self.run(args + [self.cfg['urls'][resource]], timeout=310)

    def history_client(self):
        # Credentials stay in memory on the authenticated local console path.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *unused):
                return None
        self.history_http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        started = time.monotonic()
        deadline = started + 300
        first_unavailable = None
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            try:
                self.history_api('/api/auth/login', {'user': 'labadmin', 'pass': self.cfg['history']['admin_password']},
                                 timeout=min(30, remaining))
                return
            except urllib.error.HTTPError as exc:
                # Authentication failures and throttling are terminal. Never
                # repeatedly submit the password after 401/403/429 or hide a
                # different API error behind a readiness timeout.
                if exc.code not in (502, 503, 504):
                    raise
                failure = {'kind': 'http-unavailable', 'http_status': exc.code}
                exc.close()
            except (urllib.error.URLError, TimeoutError, ConnectionError,
                    http.client.RemoteDisconnected, http.client.IncompleteRead):
                failure = {'kind': 'transport-unavailable'}
            if first_unavailable is None:
                first_unavailable = dict(failure, schema=1, phase=self.phase,
                    first_failure_elapsed_seconds=round(time.monotonic() - started, 6), retry_budget_seconds=300)
                if not hasattr(self, 'history_login_unavailable'):
                    self.history_login_unavailable = []
                self.history_login_unavailable.append(first_unavailable)
                # Immutable, bounded, secret-free evidence: never serialize an
                # exception, request, URL, header, response body or credential.
                path = self.work / ('history-login-unavailable-%03d.json' % len(self.history_login_unavailable))
                with path.open('x', encoding='utf-8') as stream:
                    json.dump(first_unavailable, stream)
                    stream.flush(); os.fsync(stream.fileno())
            require(time.monotonic() < deadline)
            time.sleep(min(5, max(0, deadline - time.monotonic())))

    def history_api(self, path, payload=None, method=None, archive=None, timeout=None):
        origin = 'https://127.0.0.1:9090'
        request = urllib.request.Request(origin + path,
            data=None if payload is None else json.dumps(payload).encode(), method=method,
            headers={'Origin': origin, 'Content-Type': 'application/json'})
        with self.history_http.open(request, timeout=timeout if timeout is not None else (300 if archive else 30)) as response:
            require(response.status == 200 and response.url == origin + path)
            if archive is not None:
                total = 0
                with archive.open('xb') as stream:
                    while True:
                        chunk = response.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        require(total <= self.cfg['archive_limit'])
                        stream.write(chunk)
                    stream.flush(); os.fsync(stream.fileno())
                require(total > 8)
                return
            data = response.read(4 * 1024 * 1024 + 1)
            require(len(data) <= 4 * 1024 * 1024)
            return json.loads(data)

    def history_markers(self):
        tag = self.cfg['history']['tag']
        require(re.fullmatch(r'freshhist[a-f0-9]{16}', tag))
        data = self.history_api('/api/logs?source=store&filter=' + tag + '&limit=500')
        return {'history': data.get('history'), 'total': data.get('total'),
                'rows': sorted([[e.get(k) for k in ('ts', 'host', 'status', 'method')]
                                for e in data.get('logs') or []])}

    def history_cli(self, archive, phrase, confirm=False, allowed=(0,)):
        env = dict(os.environ, CULVERT_HISTORY_PASSPHRASE=phrase)
        args = ['--profile', 'cli', 'run', '--rm', '-T', '--no-deps',
                '-e', 'CULVERT_HISTORY_PASSPHRASE', 'cli', '--history-import', '/backup/' + archive.name]
        if confirm:
            args.append('--confirm')
        return self.dc(*args, env=env, allowed=allowed)

    def export_history(self):
        self.phase = 'history-export'
        h = self.cfg['history']
        require(self.environment.get('CULVERT_LOG_PASSPHRASE'))
        require(h['rotated_log_password'] != self.environment['CULVERT_LOG_PASSPHRASE'])
        self.history_client()
        retention = self.history_api('/api/logs/retention', {'enabled': True, 'retentionDays': 30}, method='PUT')
        require(retention.get('enabled') is True and retention.get('encrypted') is True)
        for number in range(1, 13):
            host = h['tag'] + '-' + str(number) + '.invalid'
            connection = http.client.HTTPConnection('127.0.0.1', 8080, timeout=30)
            try:
                connection.request('GET', 'http://' + host + '/', headers={'Host': host})
                require(connection.getresponse().status == 403)
            finally:
                connection.close()
        deadline = time.monotonic() + 60
        while True:
            markers = self.history_markers()
            if markers['history'] is True and markers['total'] == 12 and len(markers['rows']) == 12:
                break
            require(time.monotonic() < deadline)
            time.sleep(2)
        archive = self.backup / ('history-' + self.cfg['nonce'] + '.cvst')
        self.history_api('/api/logs/history/export', {'archivePhrase': h['password']}, archive=archive)
        with archive.open('rb') as stream:
            require(stream.read(8) == b'CVRTST01')
        os.chown(archive, self.uid, self.gid); os.chmod(archive, 0o600)
        _, out = self.history_cli(archive, h['password'])
        require(b'history archive OK:' in out and b'0 skipped at export' in out and b'dry-run: nothing written' in out)
        self.history_result = {'result': 'exported-and-validated', 'records': 12,
                               'archive_sha256': sha(archive), 'source_encrypted': True}
        self.transfer('history', archive, True)
        return {'archive_sha256': sha(archive), 'archive_bytes': archive.stat().st_size,
                'tag': h['tag'], 'markers': markers, 'dry_run_verified': True, 'source_encrypted': True}

    def restore_history(self, archive):
        self.phase = 'history-live-refusal'
        h = self.cfg['history']
        self.history_client()
        before = self.history_markers()
        require(before == {'history': True, 'total': 0, 'rows': []})
        retention = self.history_api('/api/logs/retention')
        require(retention.get('enabled') is True and retention.get('encrypted') is True)
        runtime = json.loads(self.run(['docker', 'inspect', 'culvert'])[1])[0]
        environment = dict(v.split('=', 1) for v in runtime['Config']['Env'] if '=' in v)
        require(environment.get('CULVERT_LOG_PASSPHRASE') == h['rotated_log_password'])
        rc, out = self.history_cli(archive, h['password'], True, tuple(range(256)))
        require(rc != 0 and b'locked by another Culvert process' in out and b'imported=' not in out)
        require(self.history_markers() == before)
        self.dc('stop')
        require(self.run(['docker', 'inspect', '-f', '{{.State.Running}}', 'culvert'])[1].strip() == b'false')
        self.phase = 'history-wrong-passphrase'
        rc, out = self.history_cli(archive, 'deliberately-wrong-' + self.cfg['nonce'], True, tuple(range(256)))
        require(rc != 0 and b'invalid passphrase or tampered' in out and b'imported=' not in out)
        self.phase = 'history-dry-run'
        _, out = self.history_cli(archive, h['password'])
        require(b'history archive OK:' in out and b'0 skipped at export' in out and b'dry-run: nothing written' in out)
        self.phase = 'history-import'
        _, out = self.history_cli(archive, h['password'], True)
        match = re.search(rb'(?m)^imported=(\d+) duplicate=(\d+) rekeyed=(\d+) expired=(\d+) invalid=(\d+)$', out)
        require(match and int(match[1]) >= 12 and all(int(match[i]) == 0 for i in range(2, 6)))
        require(b'history archive verified:' in out and b'(0 skipped at export)' in out)
        require(sha(archive) == h['archive_sha256'])
        self.dc('up', '-d')
        self.history_client()
        require(self.history_markers() == h['markers'])
        self.history_result = {'result': 'pass', 'records': 12, 'identical': True,
            'source_history_absent_before_import': True, 'live_lock_refusal': True,
            'wrong_passphrase_refusal': True, 'dry_run_verified': True, 'rotated_log_key': True,
            'archive_sha256': h['archive_sha256']}

    def preflight(self):
        self.phase = 'provisioning-wait'
        build = json.loads(Path('/var/lib/culvert-appliance/build-info.json').read_text())
        require(build['source']['git_commit'] == self.cfg['source_sha'] and build['source']['git_dirty'] is False)
        require(build['application']['index_digest'] == self.cfg['image_id'])
        marker = Path('/var/lib/culvert-appliance/state/complete.done')
        def ready():
            require(not marker.is_symlink())
            return marker.is_file()
        self.provisioning = wait_provisioned(ready,
            lambda: Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        self.phase = 'preflight'
        for name in ('docker-compose.yml', 'docker-compose.maint-agent.yml', '.env'):
            regular(STACK / name)
        regular(Path('/var/lib/culvert-appliance/state/complete.done'))
        for name in ('/run/culvert-os-update.lock', '/var/lib/culvert-maint/host-maintenance.lock'):
            require(not Path(name).is_symlink())
            f = open(name, 'a+b')
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.locks.append(f)
        for name in ('/var/lib/culvert-maint/host-shutdown.pending',
                     '/var/lib/culvert-appliance/state/stack-resume-on-boot'):
            require(not os.path.lexists(name))
        journal = Path('/var/lib/culvert-maint/reconcile')
        require(not journal.is_symlink())
        if journal.exists():
            require(journal.is_dir() and not list(journal.glob('*.json')) and not list(journal.glob('*.corrupt.*')))
        _, raw = self.run(['docker', 'inspect', 'culvert'])
        container = json.loads(raw)[0]
        require(container['State']['Running'] and container['Image'] == self.cfg['image_id'])
        self.uid = int(self.run(['docker', 'exec', 'culvert', 'id', '-u'])[1])
        self.gid = int(self.run(['docker', 'exec', 'culvert', 'id', '-g'])[1])
        self.environment = dict(x.split('=', 1) for x in container['Config']['Env'] if '=' in x)
        _, raw = self.dc('--profile', 'cli', 'config', '--format', 'json')
        compose = json.loads(raw)
        # Supported read-only CLI inventory creates its otherwise-unused backup
        # volume on a fresh appliance; it does not initialize a UI administrator.
        self.dc('--profile', 'cli', 'run', '--rm', '-T', '--no-deps', 'cli', '--list-restore-leftovers')
        def volume(target):
            mounts = [v for v in compose['services']['cli']['volumes'] if v['target'] == target]
            require(len(mounts) == 1 and mounts[0]['type'] == 'volume')
            name = compose['volumes'][mounts[0]['source']]['name']
            require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name))
            record = json.loads(self.run(['docker', 'volume', 'inspect', name])[1])[0]
            path = Path(record['Mountpoint'])
            require(path.is_dir() and not path.is_symlink())
            return name, path
        self.data_name, self.data = volume('/data')
        self.backup_name, self.backup = volume('/backup')
        require(any(m['Destination'] == '/data' and m.get('Name') == self.data_name for m in container['Mounts']))
        require(not os.path.lexists(self.data / '.restore-journal.json'))
        build = json.loads(Path('/var/lib/culvert-appliance/build-info.json').read_text())
        require(build['source']['git_commit'] == self.cfg['source_sha'] and build['source']['git_dirty'] is False)

    def export(self):
        history = self.export_history() if self.cfg.get('history') else None
        self.phase = 'encrypted-backup'
        archive = self.backup / self.cfg['archive_name']
        require(not os.path.lexists(archive))
        env = dict(os.environ, CULVERT_BACKUP_PASSPHRASE=self.cfg['backup_password'])
        _, out = self.dc('--profile', 'cli', 'run', '--rm', '-T', '--no-deps',
                         '-e', 'CULVERT_BACKUP_PASSPHRASE', 'cli', '--encrypt',
                         '--backup', '/backup/' + archive.name, env=env)
        require(b'Backup written' in out)
        regular(archive)
        require(0 < archive.stat().st_size <= self.cfg['archive_limit'])
        with archive.open('rb') as f:
            require(f.read(8) == b'CVRTBK01')
        _, validation = self.dc('--profile', 'cli', 'run', '--rm', '-T', '--no-deps',
                                '-e', 'CULVERT_BACKUP_PASSPHRASE', 'cli', '--restore',
                                '/backup/' + archive.name, '--mode', 'full', env=env)
        require(b'Validation: PASS' in validation and b'This was a dry-run. No files were written.' in validation)
        secrets = {k: self.environment.get(k, '') for k in SECRET_NAMES}
        require(secrets['CULVERT_CA_PASSPHRASE'])
        require(all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9_+/.=@:-]{0,4096}', v) for v in secrets.values()))
        secret_file = self.work / 'recovery-secrets.json'
        secret_file.write_text(json.dumps(secrets))
        metadata = {'schema': 1, 'archive_sha256': sha(archive), 'archive_bytes': archive.stat().st_size,
                    'image_id': self.cfg['image_id'], 'source_sha': self.cfg['source_sha'],
                    'source_data_volume': self.data_name, 'source_backup_volume': self.backup_name}
        if history is not None:
            metadata['history'] = history
        meta_file = self.work / 'metadata.json'
        meta_file.write_text(json.dumps(metadata))
        self.phase = 'export'
        self.transfer('archive', archive, True)
        self.transfer('secrets', secret_file, True)
        self.transfer('metadata', meta_file, True)

    def restore(self):
        # Freshness is established before reading the archive or changing env.
        require(not os.path.lexists(self.data / 'ui_users.json'))
        require(not list(self.data.glob('.restore-*')))
        self.phase = 'download'
        archive = self.backup / self.cfg['archive_name']
        require(not os.path.lexists(archive))
        secret_file = self.work / 'recovery-secrets.json'
        self.transfer('archive', archive, False)
        self.transfer('secrets', secret_file, False)
        regular(archive)
        require(archive.stat().st_size == self.cfg['archive_bytes'] and sha(archive) == self.cfg['archive_sha256'])
        os.chown(archive, self.uid, self.gid)
        os.chmod(archive, 0o600)
        secrets = json.loads(secret_file.read_text())
        require(set(secrets) == set(SECRET_NAMES))
        # Generated appliance passphrases are literal env values. Refuse values
        # requiring dotenv quoting instead of silently changing their bytes.
        require(all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9_+/.=@:-]{0,4096}', v) for v in secrets.values()))
        require(secrets['CULVERT_CA_PASSPHRASE'])
        history_archive = None
        if self.cfg.get('history'):
            h = self.cfg['history']
            require(secrets['CULVERT_LOG_PASSPHRASE'] and
                    h['rotated_log_password'] != secrets['CULVERT_LOG_PASSPHRASE'])
            require(re.fullmatch(r'[a-f0-9]{64}', h['rotated_log_password']))
            history_archive = self.backup / ('history-' + self.cfg['nonce'] + '.cvst')
            self.transfer('history', history_archive, False)
            regular(history_archive)
            require(history_archive.stat().st_size == h['archive_bytes'] <= self.cfg['archive_limit'] and
                    sha(history_archive) == h['archive_sha256'])
            os.chown(history_archive, self.uid, self.gid); os.chmod(history_archive, 0o600)
            secrets['CULVERT_LOG_PASSPHRASE'] = h['rotated_log_password']
        self.phase = 'stop'
        self.dc('stop')
        require(self.run(['docker', 'inspect', '-f', '{{.State.Running}}', 'culvert'])[1].strip() == b'false')
        # No exception handler restarts the stack, including before a commit.
        self.phase = 'reenter-secrets'
        current = (STACK / '.env').read_text()
        lines = [line for line in current.splitlines() if line.split('=', 1)[0] not in SECRET_NAMES]
        lines += [k + '=' + secrets[k] for k in SECRET_NAMES]
        stage = STACK / ('.env.fresh-recovery-' + self.cfg['nonce'])
        with stage.open('x') as f:
            f.write('\n'.join(lines) + '\n'); f.flush(); os.fsync(f.fileno())
        os.replace(stage, STACK / '.env')
        fd = os.open(STACK, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        env = dict(os.environ, CULVERT_BACKUP_PASSPHRASE=self.cfg['backup_password'])
        cli = ('--profile', 'cli', 'run', '--rm', '-T', '--no-deps', '-e', 'CULVERT_BACKUP_PASSPHRASE',
               'cli', '--restore', '/backup/' + archive.name, '--mode', 'full')
        self.phase = 'dry-run'
        _, out = self.dc(*cli, env=env)
        require(b'Validation: PASS' in out and b'This was a dry-run. No files were written.' in out)
        self.phase = 'root-ca-guard'
        rc, out = self.dc(*cli, '--confirm', '--accept-dp-reenrollment', env=env, allowed=tuple(range(256)))
        require(rc != 0 and b'--accept-root-ca-change' in out and b'Restore committed.' not in out)
        require(not os.path.lexists(self.data / '.restore-journal.json'))
        self.phase = 'commit'
        _, out = self.dc(*cli, '--confirm', '--accept-dp-reenrollment', '--accept-root-ca-change', env=env)
        require(b'Restore committed.' in out and not os.path.lexists(self.data / '.restore-journal.json'))
        require(sha(archive) == self.cfg['archive_sha256'])
        self.phase = 'start'
        self.dc('up', '-d')
        require(self.run(['docker', 'inspect', '-f', '{{.Image}}', 'culvert'])[1].strip().decode() == self.cfg['image_id'])
        if history_archive is not None:
            self.restore_history(history_archive)


def main(cfg):
    guest = Guest(cfg)
    try:
        guest.preflight()
        getattr(guest, cfg['mode'])()
        result = {'schema': 1, 'phase': cfg['mode'], 'result': 'pass', 'provisioning': guest.provisioning}
        if cfg.get('history'):
            result['history'] = guest.history_result
            result['history_login_unavailable'] = getattr(guest, 'history_login_unavailable', [])
        print(json.dumps(result))
    except Exception:
        print(json.dumps({'schema': 1, 'phase': guest.phase, 'result': 'fail',
                          'detail': 'Inspect private guest work directory; no automatic recovery or retry.'}))
        raise SystemExit(1) from None
