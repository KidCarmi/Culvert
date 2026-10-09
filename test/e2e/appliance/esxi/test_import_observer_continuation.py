"""Exact imported/off boundary tests; synthetic files and no hypervisor calls."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('continuation_test', HERE / 'import-observer-continuation.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); oldroot = root / 'old'; local = oldroot / '.tools'; local.mkdir(parents=True)
        run = local / 'run'; sec = run / 'secrets'; sec.mkdir(parents=True); ev = run / 'evidence'; ev.mkdir()
        ops = local / 'private-operations'; ops.mkdir()
        ids = c.module('test_profiles', HERE / 'candidate-identities.py')
        old = dict(ids.source_profile(ids.E7C), controller_manifest=str(local / 'freeze.json'),
                   run_dir=str(run), max_vms=1, credential_mode='none', visual_capture_label='cold7c', endpoint='https://192.0.2.1')
        freeze = {'revision': c.ORIGINAL}
        owned = {'uuid': '564d554e-498d-3787-0173-62dba5125204', 'ref': {'type':'VirtualMachine','value':'vm-70'},
                 'owner':'LOCAL-ESXI:test', 'name':'culvert-esxi-test', 'path':'/lab/test', 'endpoint':old['endpoint'],
                 'host_ref':'host', 'ds_ref':'ds', 'network_ref':'net', 'phase':'imported', 'visual_capture_nonce':'a'*32}
        (local / 'scope-7c-source.json').write_text(json.dumps(old))
        (local / 'freeze.json').write_text(json.dumps(freeze))
        (run / 'owned.json').write_text(json.dumps(owned))
        (ev / 'preflight.json').write_text(json.dumps({'harness_sha':c.ORIGINAL,'harness_dirty':False,
            'controller_freeze':freeze,'expected_source':c.SOURCE,'expected_image':old['image_id'],
            'artifact':{'ova_sha256':old['ova_sha256']}}))
        (ops / 'import.out').write_text('PASS: import: imported\nBLOCKED: up: '+c.STOP+'\n')
        (ops / 'import.err').write_bytes(b'')
        (ops / 'cold-capture.out').write_bytes(b'')
        (ops / 'cold-capture.err').write_text('BLOCKED: private visual capture stopped; preserve evidence and reconcile ownership.\n')
        (ops / 'import.receipt.json').write_text(json.dumps({'exit_code':3,
            'stdout_sha256':c.sha((ops/'import.out').read_bytes()),'stderr_sha256':c.sha(b'')}))
        locations = c.paths(oldroot, old)
        new = dict(old, controller_manifest=str(root / 'new-freeze.json'), visual_import_continuation={
            'original_root':str(oldroot),'sha256':{k:c.sha(p.read_bytes()) for k,p in locations.items()}})
        scope = root / 'new-scope.json'; scope.write_text(json.dumps(new))
        self.lab = SimpleNamespace(c=new,sec=sec,ev=ev,run=run,state=dict(owned),state_file=run/'owned.json',
                                  scope_path=scope,vm=mock.Mock(return_value={'runtime':{'powerState':'poweredOff'}}),
                                  gov=mock.Mock(),record=mock.Mock())
        self.lab.save = lambda: self.lab.state_file.write_text(json.dumps(self.lab.state))
        real_module = c.module
        self.freeze = mock.Mock()
        patcher = mock.patch.object(c,'module',side_effect=lambda name,path:
                                    SimpleNamespace(verify=self.freeze) if name == 'import_freeze' else real_module(name,path))
        patcher.start(); self.addCleanup(patcher.stop)
        self.locations = locations

    def test_prepare_preserves_originals_and_rotates_nonce_before_single_power(self):
        old = {k:p.read_bytes() for k,p in self.locations.items()}
        c.prepare(self.lab)
        self.assertNotEqual(self.lab.state['visual_capture_nonce'], 'a'*32)
        for k,p in self.locations.items():
            if k != 'owned': self.assertEqual(p.read_bytes(),old[k])
        directory = self.lab.sec/'import-observer-continuation'
        self.assertEqual((directory/'original-owned.json').read_bytes(),old['owned'])
        adapter = SimpleNamespace(wait_visual_capture=mock.Mock())
        c.power_on(self.lab,adapter)
        self.assertEqual(adapter.wait_visual_capture.call_count,2)
        self.lab.gov.assert_called_once_with('vm.power','-on','/lab/test',json_output=False)
        self.assertEqual(self.lab.state['phase'],'powered-on')
        c.validate_binding(self.lab) # Later visual observations remain bound.
        with self.assertRaises(ValueError): c.power_on(self.lab,adapter)
        self.assertEqual(self.lab.gov.call_count,1)

    def test_failed_power_dispatch_keeps_intent_and_refuses_retry(self):
        c.prepare(self.lab); self.lab.gov.side_effect=RuntimeError('ambiguous timeout')
        adapter=SimpleNamespace(wait_visual_capture=mock.Mock())
        with self.assertRaises(RuntimeError): c.power_on(self.lab,adapter)
        with self.assertRaisesRegex(ValueError,'already attempted'): c.power_on(self.lab,adapter)
        self.assertEqual(self.lab.gov.call_count,1)

    def test_wrong_vm_power_phase_or_access_started_refuses_before_nonce_change(self):
        for change in ('power','phase','uuid','auth'):
            with self.subTest(change=change):
                original=dict(self.lab.state)
                if change=='power': self.lab.vm.return_value={'runtime':{'powerState':'poweredOn'}}
                if change=='phase': self.lab.state['phase']='powered-on'
                if change=='uuid': self.lab.state['uuid']='00000000-0000-0000-0000-000000000000'
                if change=='auth': (self.lab.sec/'bootstrap-console-password').write_text('synthetic')
                with self.assertRaises(ValueError): c.prepare(self.lab)
                self.assertFalse((self.lab.sec/'import-observer-continuation').exists())
                self.lab.state=original; self.lab.vm.return_value={'runtime':{'powerState':'poweredOff'}}
                (self.lab.sec/'bootstrap-console-password').unlink(missing_ok=True)
        self.lab.gov.assert_not_called()

    def test_changed_original_evidence_or_scope_is_not_rebound(self):
        for name,path in self.locations.items():
            with self.subTest(name=name):
                data=path.read_bytes();path.write_bytes(data+b' ')
                with self.assertRaises(ValueError): c.validate_binding(self.lab)
                path.write_bytes(data)
        self.lab.c['max_vms']=2
        with self.assertRaisesRegex(ValueError,'only controller'): c.validate_binding(self.lab)

    def test_original_freeze_is_reverified_and_arm_failure_cannot_power_on(self):
        self.freeze.side_effect=ValueError('original checkout changed')
        with self.assertRaises(ValueError): c.prepare(self.lab)
        self.freeze.side_effect=None
        c.prepare(self.lab)
        adapter=SimpleNamespace(wait_visual_capture=mock.Mock(side_effect=ValueError('not armed')))
        with self.assertRaises(ValueError): c.power_on(self.lab,adapter)
        self.lab.gov.assert_not_called()
        self.assertFalse((self.lab.sec/'import-observer-continuation/power-intent.json').exists())

    def test_prepared_old_nonce_or_binding_cannot_be_replaced(self):
        c.prepare(self.lab)
        path=self.lab.sec/'import-observer-continuation/prepared.json'
        original=path.read_bytes()
        for name,value in [('old_nonce','0'*32),('original_sha256',{})]:
            prepared=json.loads(original);prepared[name]=value;path.write_text(json.dumps(prepared))
            with self.assertRaises(ValueError): c.power_on(self.lab,SimpleNamespace(wait_visual_capture=mock.Mock()))
            self.lab.gov.assert_not_called()
        path.write_bytes(original)

    def test_observer_refuses_mixed_source_image_and_allows_reviewed_candidates(self):
        visual=c.module('test_visual_profiles',HERE/'visual-capture.py')
        profiles=c.module('test_profiles_pair',HERE/'candidate-identities.py')
        for source in (profiles.E7E,profiles.E7C,profiles.E91):
            scope=profiles.source_profile(source)
            self.assertEqual(visual.candidate_profile(scope)['source_sha'],source)
            scope['image_id']='sha256:'+'0'*64
            with self.assertRaises(ValueError): visual.candidate_profile(scope)
        with self.assertRaises(ValueError): visual.candidate_profile(profiles.source_profile(profiles.CD8))

    def test_7c_visual_fixture_and_outage_select_exact_candidate(self):
        profiles=c.module('test_profiles_selection',HERE/'candidate-identities.py')
        visual=c.module('test_visual_generator',HERE/'visual-service-fixture.py')
        default=visual.generate('install',self.lab.state['uuid'],'seven-e')
        self.assertIn("'source': '"+profiles.E7E+"'",default)
        body=visual.generate('install',self.lab.state['uuid'],'seven-c',source=profiles.E7C)
        self.assertIn("'source': '"+profiles.E7C+"'",body)
        self.assertIn("build['source']['git_commit'] == config['source']",body)
        with self.assertRaises(ValueError): visual.generate('install',self.lab.state['uuid'],'seven-c',source='0'*40)
        outage=c.module('test_outage_selection',HERE/'qualify-clamav-outage.py')
        profile=profiles.source_profile(profiles.E7C)
        self.assertEqual(outage.attempt_context(self.lab.sec,profile,'initial',None,'owned'),
                         (self.lab.sec/'clamav-outage',{}))
        with self.assertRaises(outage.CheckFailure): outage.attempt_context(self.lab.sec,profile,'followup',None,'owned')

    def test_history_admits_reviewed_candidates_without_dispatch(self):
        profiles=c.module('test_history_profiles',HERE/'candidate-identities.py')
        fresh=c.module('test_history_controller',HERE/'fresh-recovery.py')
        args=SimpleNamespace(bind='192.0.2.1',scope=Path('not-read'),escrow=Path('not-written'),history=True)
        for source in (profiles.E7E,profiles.E7C,profiles.E91,profiles.CD8):
            lab=SimpleNamespace(c=dict(profiles.source_profile(source),max_vms=1),run=Path('not-read'))
            with mock.patch.object(fresh.console.b.module,'Lab',return_value=lab), \
                 mock.patch.object(fresh.console.b.module,'validate_scope'), \
                 mock.patch.object(fresh,'private_escrow',side_effect=RuntimeError('offline boundary')) as escrow:
                if source==profiles.CD8:
                    with self.assertRaises(ValueError): fresh.run(args)
                    escrow.assert_not_called()
                else:
                    with self.assertRaisesRegex(RuntimeError,'offline boundary'): fresh.run(args)
                    escrow.assert_called_once()


if __name__=='__main__': unittest.main()
