"""Exact artifact/source and shared-library reconciliation tests; no VM calls."""
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
import unittest
from unittest import mock
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


class CandidateReconciliationTests(unittest.TestCase):
    def test_91_profile_helpers_and_kernel_controls_match_exact_source(self):
        ids=load('candidate-identities')
        profile=ids.source_profile(ids.E91)
        engine=load('engine-surface-proof').PROFILES[ids.E91]
        files={'appliance/provision/culvert-net':profile['network_helper_sha256'],
               'appliance/provision/culvert-appliance-reset-identity':profile['reset_helper_sha256'],
               'appliance/provision/modprobe-culvert-unused.conf':engine['denylist_sha256'],
               'appliance/provision/72-culvert-drm.rules':engine['drm_rule_sha256'],
               'appliance/provision/net-autoload-reviewed.txt':engine['net_reviewed_sha256']}
        for path,digest in files.items():
            raw=subprocess.check_output(['git','show',ids.E91+':'+path],cwd=HERE.parents[3])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)
            if path.endswith('unused.conf'):
                names=[line.split()[1] for line in raw.decode().splitlines() if line.startswith('install ')]
                self.assertEqual(names,engine['modules']);self.assertEqual(len(names),67)

    def test_current_helpers_admit_91_while_historical_continuation_remains_bound(self):
        ids=load('candidate-identities');scope=ids.source_profile(ids.E91)
        self.assertEqual(load('visual-capture').candidate_profile(scope),scope)
        self.assertEqual(load('qualify-clamav-outage').attempt_context(Path('unused'),scope,'initial',None,'owner'),
                         (Path('unused/clamav-outage'),{}))
        fixture=load('visual-service-fixture')
        script=fixture.generate('install','11111111-1111-4111-8111-111111111111','nine-one',ids.E91)
        self.assertIn(ids.E91,script)
        self.assertNotEqual(load('import-observer-continuation').SOURCE,ids.E91)
    def test_only_complete_reviewed_artifact_combinations_are_admitted(self):
        identities = load('candidate-identities')
        for source in (identities.B579, identities.D698, identities.E2E3, identities.CD8, identities.E7E, identities.E7C, identities.E91):
            scope = identities.source_profile(source)
            self.assertEqual(identities.scope_profile(scope), scope)
            for field in ('source_sha', 'ova_sha256', 'image_id'):
                changed = dict(scope); changed[field] = '0' * 64
                with self.subTest(source=source, field=field), self.assertRaises(ValueError):
                    identities.scope_profile(changed)
        scope = identities.source_profile(identities.D698)
        scope['ova_sha256'] = identities.source_profile(identities.B579)['ova_sha256']
        with self.assertRaises(ValueError):
            identities.scope_profile(scope)

    def test_real_fixture_bytes_unchanged_and_provenance_names_selected_source(self):
        identities, fixture = load('candidate-identities'), load('prepare-signed-fixture')
        for source in (identities.B579, identities.D698, identities.E2E3, identities.CD8, identities.E7E, identities.E7C, identities.E91):
            provenance = fixture.verify_sources(source)
            self.assertEqual(provenance['source_revision'], source)
            self.assertEqual({k: v['sha256'] for k, v in provenance['files'].items()}, identities.FIXTURE_HASHES)
        with self.assertRaises(ValueError):
            fixture.verify_sources('0' * 40)

    def test_shared_library_contains_only_documented_delta_from_pinned_upstream(self):
        record = json.loads((HERE / 'shared-harness-provenance.json').read_bytes())
        self.assertEqual(record['upstream_revision'], '4eabd8d4f3eee7d4d305163bd48786a340019cff')
        root = HERE.parents[3]
        for name, hashes in record['files'].items():
            raw = (root / name).read_bytes().replace(b'\r\n', b'\n')
            self.assertEqual(hashlib.sha256(raw).hexdigest(), hashes['controller_lf_sha256'])
            if name.endswith('appliance-lab.sh'):
                for hook, indentation, extra_line in (
                    ('lab_before_signed_update', '  ', True), ('lab_before_reboot', '    ', False),
                    ('lab_after_reboot_observation', '  ', True)):
                    addition = (indentation + 'if declare -F ' + hook + ' >/dev/null; then ' + hook + '; fi\n'
                                + ('\n' if extra_line else '')).encode()
                    self.assertEqual(raw.count(addition), 1)
                    raw = raw.replace(addition, b'')
                raw = raw.replace(b'  if [[ "$LAB_EXTERNAL" == 1 ]]; then check P disk-pressure fail "BLOCKED: bounded QEMU disk-pressure fixture cannot run on ESXi"; return 0; fi\n', b'')
            elif name.endswith('console-session.py'):
                raw = raw.replace(b'        if not hasattr(socket, "AF_UNIX"):\n'
                                  b'            raise OSError("Unix console transport is unavailable on this controller")\n', b'')
            self.assertEqual(hashlib.sha256(raw).hexdigest(), hashes['upstream_sha256'])

    def test_fresh_recovery_selects_each_exact_scope_without_mutating_source_default(self):
        identities, fresh = load('candidate-identities'), load('fresh-recovery')
        original = fresh.SOURCE
        args = SimpleNamespace(bind='192.0.2.1', scope=Path('never-read'), escrow=Path('never-written'))
        for source in (identities.CD8, identities.E2E3, identities.D698, identities.B579, identities.CD8):
            scope = identities.source_profile(source); scope['max_vms'] = 1
            lab = SimpleNamespace(c=scope, run=Path('never-read'))
            with mock.patch.object(fresh.console.b.module, 'Lab', return_value=lab), \
                 mock.patch.object(fresh.console.b.module, 'validate_scope'), \
                 mock.patch.object(fresh, 'private_escrow', side_effect=RuntimeError('offline-stop')):
                with self.assertRaisesRegex(RuntimeError, 'offline-stop'):
                    fresh.run(args)
                self.assertEqual(fresh.SOURCE, original)
                scope['ova_sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    fresh.run(args)

    def test_historical_mutation_campaigns_still_refuse_new_candidate(self):
        identities, resume = load('candidate-identities'), load('post-os-resume')
        with self.assertRaisesRegex(ValueError, 'first explicit confirmation'):
            resume.validate(identities.source_profile(identities.D698), Path('never-read'), continuation=True)
        with self.assertRaisesRegex(ValueError, 'wrong candidate'):
            resume.validate(identities.source_profile(identities.E2E3), Path('never-read'))
        with self.assertRaisesRegex(ValueError, 'wrong candidate'):
            resume.validate(identities.source_profile(identities.CD8), Path('never-read'))


if __name__ == '__main__':
    unittest.main()
