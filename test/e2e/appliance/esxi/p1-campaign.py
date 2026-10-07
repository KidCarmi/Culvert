"""Fixed campaign namespaces and preserved initial-failure binding."""
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

NAMES = {'initial': 'p1-regressions', 'confirmation': 'p1-regressions-confirmation'}
SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
IDENTITY_SOURCE = 'cd8e44505bd329e5de675592ad4c23f92a534d55'
IDENTITY_OVA = '46cb60078eb2adbc2f8704046268f68e56798bc2b37cd824ba70f8a919bd2ab1'
IDENTITY_FRAME = '441da7236f6ffdd8fb4cdfa2d9ce7b8d8df8cf2f7a8e82c530714d92266ce613'


def identity_observation_binding(private, campaign, owned_uuid, require_unstarted=True):
    """Only the preserved first-frame, pre-PAM geometry failure can continue."""
    from PIL import Image
    if campaign != 'initial' or SOURCE != IDENTITY_SOURCE:
        raise ValueError('only exact cd8 initial identity observation can continue')
    folder = directory(private, campaign)
    files = {}
    def bind(path, maximum=1024 * 1024):
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
            raise ValueError('bounded original identity evidence required')
        raw = path.read_bytes()
        files[str(path.relative_to(private)).replace('\\', '/')] = hashlib.sha256(raw).hexdigest()
        return raw
    for stage, status in (('identity-bootstrap', 'blocked'), ('identity-reset', 'pass'), ('identity-power-on', 'pass')):
        record = json.loads(bind(folder / (stage + '.attempt.json')))
        if record.get('status') != status or record.get('uuid') != owned_uuid or record.get('campaign') != campaign:
            raise ValueError('original identity stage mismatch')
    baseline = json.loads(bind(folder / 'identity-before.json'))
    escrow = json.loads(bind(folder / 'export-readiness.json'))
    if (baseline.get('phase') != 'identity-before-reset' or baseline['identity']['source'] != IDENTITY_SOURCE
            or escrow.get('uuid') != owned_uuid or escrow.get('ova_sha256') != IDENTITY_OVA
            or escrow.get('backup_export_verified') is not True or escrow.get('escrow_export_verified') is not True):
        raise ValueError('identity source/OVA/escrow binding differs')
    old = bind(folder / 'old-console-password', 256)
    if bind(folder / 'old-console-password-original', 256) != old:
        raise ValueError('preserved old credential differs')
    if require_unstarted and os.path.lexists(private / 'bootstrap-console-password'):
        raise ValueError('authentication has already started; no credential retry')
    errors = []
    for path in folder.glob('controller-exception-*.json'):
        value = read_record(path)
        if value.get('action') == 'identity-bootstrap' and not value.get('identity_observation_continuation', False):
            errors.append((path, value))
    if len(errors) != 1:
        raise ValueError('one original identity exception required')
    path, error = errors[0]
    if (error.get('type') != 'ValueError' or error.get('error') != 'console image contains partial glyph cells'
            or error.get('campaign') != campaign or error.get('undispatched_continuation') is not False):
        raise ValueError('only exact pre-auth geometry exception supported')
    bind(path)
    frame = private / 'p1-identity-fresh-001.png'
    if list(private.glob('p1-identity-fresh-*')) != [frame]:
        raise ValueError('only original first screenshot may exist')
    if hashlib.sha256(bind(frame, 10 * 1024 * 1024)).hexdigest() != IDENTITY_FRAME:
        raise ValueError('reviewed original firmware screenshot differs')
    with Image.open(frame) as image:
        width, height = image.size
        if image.format != 'PNG' or (width, height) != (640, 480):
            raise ValueError('original frame is not a bounded partial-cell geometry')
        image.verify()
    return {'kind': 'identity-preauth-geometry', 'source': IDENTITY_SOURCE, 'ova_sha256': IDENTITY_OVA,
            'uuid': owned_uuid, 'original_geometry': [width, height], 'files': files}


def read_record(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError('bounded private evidence required')
    return json.loads(path.read_bytes())


def proof_binding(private, path):
    path = Path(path)
    if path.parent.resolve() != private.resolve() or path.is_symlink():
        raise ValueError('proof must be a direct private-run file')
    report = read_record(path)
    if report.get('exit') != 0 or report.get('stderr') != '' or not isinstance(report.get('stdout'), str):
        raise ValueError('successful authenticated observation required')
    observation = json.loads(report['stdout'])
    if (set(observation) != {'confirmation_state_exists', 'source', 'boot_id'}
            or observation['confirmation_state_exists'] is not False or observation['source'] != SOURCE
            or str(uuid.UUID(observation['boot_id'])) != observation['boot_id']):
        raise ValueError('undispatched exact-source observation required')
    expected = b'0\n' + report['stdout'].encode('utf-8')
    matches = []
    for result in private.glob('transport-*/result'):
        if (re.fullmatch(r'transport-[a-f0-9]{48}', result.parent.name)
                and not result.parent.is_symlink() and not result.is_symlink()
                and result.is_file() and result.stat().st_size == len(expected)
                and result.read_bytes() == expected):
            matches.append(result)
    if not matches:
        raise ValueError('proof lacks matching authenticated console result')
    return {'proof_name': path.name, 'proof_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'authenticated_result': str(sorted(matches)[0].relative_to(private)).replace('\\', '/'),
            'authenticated_result_sha256': hashlib.sha256(expected).hexdigest(),
            'boot_id': observation['boot_id']}


def continuation_binding(private, campaign, owned_uuid, proof):
    if campaign != 'confirmation':
        raise ValueError('only confirmation network-before can continue undispatched')
    folder = directory(private, campaign)
    original = folder / 'network-before.attempt.json'
    record = read_record(original)
    if (record.get('status') != 'blocked' or record.get('uuid') != owned_uuid
            or record.get('campaign') != campaign or (folder / 'network-before.json').exists()):
        raise ValueError('blocked pre-probe confirmation attempt required')
    return dict(proof_binding(private, proof), original_attempt_sha256=hashlib.sha256(original.read_bytes()).hexdigest())


def effective_stage(private, campaign, stage, owned_uuid):
    folder = directory(private, campaign)
    original = folder / (stage + '.attempt.json')
    record = read_record(original)
    if record.get('uuid') != owned_uuid or record.get('campaign', 'initial') != campaign:
        raise ValueError('stage identity mismatch')
    if record.get('status') == 'pass':
        return record
    if stage == 'identity-bootstrap' and campaign == 'initial' and record.get('status') == 'blocked':
        continuation = read_record(folder / 'identity-bootstrap.continuation-attempt.json')
        binding = identity_observation_binding(private, campaign, owned_uuid, require_unstarted=False)
        if (continuation.get('status') != 'pass' or continuation.get('uuid') != owned_uuid
                or continuation.get('campaign') != campaign or continuation.get('continuation') != binding):
            raise ValueError('identity observation continuation changed or incomplete')
        password = private / 'bootstrap-console-password'
        if (password.is_symlink() or not password.is_file() or not 0 < password.stat().st_size <= 256
                or hashlib.sha256(password.read_bytes()).hexdigest() != continuation.get('new_credential_sha256')):
            raise ValueError('completed fresh credential binding differs')
        return continuation
    if stage != 'network-before' or campaign != 'confirmation' or record.get('status') != 'blocked':
        raise ValueError('required stage did not pass')
    continuation = read_record(folder / 'network-before.continuation-attempt.json')
    binding = continuation.get('continuation', {})
    if (continuation.get('status') != 'pass' or continuation.get('uuid') != owned_uuid
            or continuation.get('campaign') != campaign
            or binding.get('original_attempt_sha256') != hashlib.sha256(original.read_bytes()).hexdigest()):
        raise ValueError('verified continuation did not pass')
    verified = proof_binding(private, private / binding['proof_name'])
    if any(binding.get(key) != value for key, value in verified.items()):
        raise ValueError('continuation observation changed')
    return continuation


def directory(private, campaign):
    if campaign not in NAMES:
        raise ValueError('unknown P1 campaign')
    return private / NAMES[campaign]


def initial_failure(private, owned_uuid, campaign):
    if campaign == 'initial':
        return None
    directory(private, campaign)  # Reject arbitrary namespaces.
    initial = directory(private, 'initial')
    marker = initial / 'network-before.attempt.json'
    if (initial.is_symlink() or not marker.is_file() or marker.is_symlink()
            or marker.stat().st_size > 65536 or (initial / 'stage.lock').exists()):
        raise ValueError('stopped original P1 attempt evidence required')
    raw = marker.read_bytes()
    record = json.loads(raw)
    if record.get('status') != 'blocked' or record.get('uuid') != owned_uuid:
        raise ValueError('original blocked attempt does not match owned VM')
    return {'campaign': 'initial', 'check': 'p1-network-before', 'result': 'blocked',
            'attempt_sha256': hashlib.sha256(raw).hexdigest(),
            'disposition': 'original availability failure retained; confirmation is a separate campaign'}
