"""Fixed campaign namespaces and preserved initial-failure binding."""
import hashlib
import json
from pathlib import Path
import re
import uuid

NAMES = {'initial': 'p1-regressions', 'confirmation': 'p1-regressions-confirmation'}
SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'


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
