"""Explicit LAB artifact identities; a source SHA alone never selects an OVA."""
import copy

B579 = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
D698 = 'd698a69c5192588d5ed3a85a9f7cd9009fb59b31'
FIXTURE_HASHES = {
    'main.go': '33034e5994cc9ae7a2b9e9f98a418ffd48165b2de39cfa26fbc620c25d80330e',
    'request.py': 'fbf7e9df27c190b47155ccbff93b3581cd0342f33cf8c8dbce943a57be49c771',
}
PROFILES = {
    B579: {
        'source_sha': B579,
        'ova_sha256': '1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775',
        'image_id': 'sha256:24b37bc217691058e56a838821b86dfbd45b927b1c0ea8ea867a28c54d4bcc47',
        'network_helper_sha256': '1007fc7f5f140c6e946f1f34617b02820d8c78d8d9786d50045865e05d862ff3',
        'reset_helper_sha256': 'fd53277fd2fc55afc79b70c8d00570b80e3ca938fc39edfa938fd81f8464d71a',
    },
    D698: {
        'source_sha': D698,
        'ova_sha256': '9e8e067db5f8ee3c6aa55ac3127b008a7fe612dcca89d1cf004ab3ac8b63d1aa',
        'image_id': 'sha256:2c03833c9641a1e24dc5a66b3faa4f0695ac44cdeac931018b9b744be301660e',
        'network_helper_sha256': '1007fc7f5f140c6e946f1f34617b02820d8c78d8d9786d50045865e05d862ff3',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.4.6-pcre2-10.49',
        'clamav_sidecar_image_id': 'sha256:86d71850ea1a01fdbb9c06b82c929d4485718c1d80f19a0824c2c454c2bce97e',
    },
}


def source_profile(source):
    if source not in PROFILES:
        raise ValueError('candidate source is not explicitly approved')
    return copy.deepcopy(PROFILES[source])


def scope_profile(scope):
    profile = source_profile(scope.get('source_sha'))
    if any(scope.get(key) != profile[key] for key in ('source_sha', 'ova_sha256', 'image_id')):
        raise ValueError('candidate source/OVA/image identity combination differs')
    return profile
