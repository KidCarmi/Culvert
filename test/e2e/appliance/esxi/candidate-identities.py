"""Explicit LAB artifact identities; a source SHA alone never selects an OVA."""
import copy

B579 = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
D698 = 'd698a69c5192588d5ed3a85a9f7cd9009fb59b31'
E2E3 = '2e3bcc2a1095f3e26e4f0b73a6a5515bdd069ee2'
CD8 = 'cd8e44505bd329e5de675592ad4c23f92a534d55'
E7E = '7e53720d06f525f4e5fdbfec42f52840d5b734e2'
E7C = '7c7b29ee3be40af6a0809c73ad04d4337303263d'
FIXTURE_HASHES = {
    'main.go': '33034e5994cc9ae7a2b9e9f98a418ffd48165b2de39cfa26fbc620c25d80330e',
    'request.py': 'fbf7e9df27c190b47155ccbff93b3581cd0342f33cf8c8dbce943a57be49c771',
}
PROFILES = {
    E7C: {
        'source_sha': E7C,
        'ova_sha256': '4b8ae484fd8b9bda8dfc12512e9e0b489edcc96c7590824f22276a19dc6b7a05',
        'image_id': 'sha256:398ffaf2090ec32cb9ff0506dd2e92bfd2414d689719373fc00cf96a5c58f906',
        'network_helper_sha256': '4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.4.6-culvert.3',
        'clamav_sidecar_image_id': 'sha256:45dbf00306ef19a9c8f9a90a078d73e8131cc6dc03e08d829acdd16816afc94e',
    },
    E7E: {
        'source_sha': E7E,
        'ova_sha256': '578ea6b83b450b91bccc10ac80058db42d157e2161a45aa23fc8a23a2def7c65',
        'image_id': 'sha256:2a355d7a8930b12581c0f42c273bc3357cbefa36d9382ab7071d2c187dda0554',
        'network_helper_sha256': '4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.4.6-culvert.3',
        'clamav_sidecar_image_id': 'sha256:1cf6b7e347c2b14b14cbcdf5d9e5de1cb8de8e3b97c44508874178315b563787',
    },
    CD8: {
        'source_sha': CD8,
        'ova_sha256': '46cb60078eb2adbc2f8704046268f68e56798bc2b37cd824ba70f8a919bd2ab1',
        'image_id': 'sha256:659258eee3fc609a8e95e0bc22c89cb57849887b0dcf2b92708ddbff0fb69b42',
        'network_helper_sha256': '4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.4.6-culvert.2',
        'clamav_sidecar_image_id': 'sha256:7d4e1087e7b94ac37971d35bc831321ebb3e891d6b7d4af8524b7a45e7f1efc3',
    },
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
    E2E3: {
        'source_sha': E2E3,
        'ova_sha256': '55e98116ba2c020789b3f5de4eabab7e29af611c83b9c972b82a6319a19f145e',
        'image_id': 'sha256:536403fc9ba8a4bc15d229a12a7586ce6ccc35ba99148b71869a81596e0ea940',
        'network_helper_sha256': '4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.4.6-pcre2-10.49',
        'clamav_sidecar_image_id': 'sha256:f3fcbf45d0a50da7e1880e498a030e38b1cd31d792a2737a881ebe8391b13ec3',
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
