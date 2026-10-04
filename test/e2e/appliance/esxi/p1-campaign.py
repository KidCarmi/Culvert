"""Fixed campaign namespaces and preserved initial-failure binding."""
import hashlib
import json

NAMES = {'initial': 'p1-regressions', 'confirmation': 'p1-regressions-confirmation'}


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
