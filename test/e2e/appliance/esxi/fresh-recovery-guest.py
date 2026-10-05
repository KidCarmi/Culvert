"""Private authenticated-console payload; never run directly on the controller.

The controller appends a literal CONFIG and calls main(CONFIG). No credentials
are accepted in argv, printed, or passed through shell evaluation.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

STACK = Path('/srv/culvert')
SECRET_NAMES = ('CULVERT_CA_PASSPHRASE', 'CULVERT_LOG_PASSPHRASE', 'CULVERT_SESSION_SECRET')


def require(ok):
    if not ok:
        raise RuntimeError('fresh recovery prerequisite or evidence refused')


def regular(path):
    require(path.is_file() and not path.is_symlink())


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

    def preflight(self):
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


def main(cfg):
    guest = Guest(cfg)
    try:
        guest.preflight()
        getattr(guest, cfg['mode'])()
        print(json.dumps({'schema': 1, 'phase': cfg['mode'], 'result': 'pass'}))
    except Exception:
        print(json.dumps({'schema': 1, 'phase': guest.phase, 'result': 'fail',
                          'detail': 'Inspect private guest work directory; no automatic recovery or retry.'}))
        raise SystemExit(1) from None
