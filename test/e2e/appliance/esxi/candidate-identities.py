"""Explicit LAB artifact identities; a source SHA alone never selects an OVA."""
import copy

B579 = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
D698 = 'd698a69c5192588d5ed3a85a9f7cd9009fb59b31'
E2E3 = '2e3bcc2a1095f3e26e4f0b73a6a5515bdd069ee2'
CD8 = 'cd8e44505bd329e5de675592ad4c23f92a534d55'
E7E = '7e53720d06f525f4e5fdbfec42f52840d5b734e2'
E7C = '7c7b29ee3be40af6a0809c73ad04d4337303263d'
E91 = '91e05872dfe5f96c94ec725b8b2dc2b1002116ab'
E72 = '72c827b7f59f4e43ff2a813241be9029f58f23a9'
EBAD788 = 'bad788e54ffef2a2f8490ba27ebfe027a2a6eb11'
E9E344 = '9e34452677d77f574f5c3c08ba23ea897d8e17cb'
EA80BE = 'a80be4b61ff7f2f069cf81ede1eebe6945d65306'
E6248 = '6248daf72a5312e75062e2c2823438911604af7f'
FIXTURE_HASHES = {
    'main.go': '33034e5994cc9ae7a2b9e9f98a418ffd48165b2de39cfa26fbc620c25d80330e',
    'request.py': 'fbf7e9df27c190b47155ccbff93b3581cd0342f33cf8c8dbce943a57be49c771',
}
PROFILES = {
    E6248: {
        'source_sha': E6248,
        'ova_sha256': '59d4d371b46b69ec2a992009c76ba0a72d96c30dabb1a51847f9ea8edccbfd61',
        'image_id': 'sha256:20a547edd3e9db83cd1fa65f734bdeec5fc8f6d077f6f73344a38798a5d9692d',
        'network_helper_sha256': '4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.5.4-culvert.1',
        'clamav_sidecar_image_id': 'sha256:8af92aa4da736583ede38a5565a11cc57b30fb91bdcb2b31374dd81848382413',
    },
    EA80BE: {
        'source_sha': EA80BE,
        'ova_sha256': '394788af5b839c8ff895f8e36b67ad0ca89d3c4f6ed9c71d4112416d6626ebe0',
        'image_id': 'sha256:ae009528da2c7c17f76be8177cb81d88b4641bbcd25d76b065071de9201f6d92',
        'network_helper_sha256': '4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.5.4-culvert.1',
        'clamav_sidecar_image_id': 'sha256:b11e29c503a4acb1c0196db9ad771d2cf49de8991b7c3be1a592292501ab6c0e',
    },
    E9E344: {
        'source_sha': E9E344,
        'ova_sha256': '47cb50f08d09efac5b6a970cc71517598a8edbb75805cb4b55cc2271e81a5313',
        'image_id': 'sha256:8c306a51083f13c680de4b679884b90f51923b7b50c47192bcb2adb68161e9b3',
        'network_helper_sha256': '4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.5.4-culvert.1',
        'clamav_sidecar_image_id': 'sha256:dc96d2f249d20a8a899fd1f965af18cd4cd54fe9f66d7a278199fd29195a4280',
    },
    EBAD788: {
        'source_sha': EBAD788,
        'ova_sha256': '87c8ae617f9a802f6a046627043c5609d0cb3fe260ce9b845409918c8bbe855c',
        'image_id': 'sha256:ac1909ec95d7588a86737cfa6d8927b0e7c04a5fe12891706eec86591dbb2ad7',
        'network_helper_sha256': '4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.4.6-culvert.3',
        'clamav_sidecar_image_id': 'sha256:d62dd495591dcb1f6558b09f6737f4cfe57cf2e5d33825d30d07544e4f9bf251',
    },
    E72: {
        'source_sha': E72,
        'ova_sha256': '76769f86fe1193768cd67d4829ef66749f970acb67d6306ad6d0b1082cb9dbb5',
        'image_id': 'sha256:d6fc9b07ad3921b31aaff0c227e8f7c9a36b03faae5c0b45f41da76dc7f7cc16',
        'network_helper_sha256': '4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.4.6-culvert.3',
        'clamav_sidecar_image_id': 'sha256:50bb8aa0a202add9758dfef7b6a9cfc356aa18af2df2d210f5feb020972f7826',
    },
    E91: {
        'source_sha': E91,
        'ova_sha256': '060a3dc6c79164265a241af5d91b4d6b2464a52340b3a42c461f72ee2889c07e',
        'image_id': 'sha256:d2a3377400f07ac0a6ceac54df729773b2983d6a4a5f871219ff891cb1e65fb4',
        'network_helper_sha256': '4cd5200c3cafba6d61dbc02f2cb6e0bc4318641aaf9d429d970442916dd7cee6',
        'reset_helper_sha256': '602f3e5aad0818e0078de4dd87cfdac485f871a99779ef4dde0a0c6c55679391',
        'clamav_sidecar_ref': 'culvert/clamav:1.4.6-culvert.3',
        'clamav_sidecar_image_id': 'sha256:0025aba0b328b5ecb03d155d9207af22f87fec3849493156eab01f84266ba68a',
    },
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
