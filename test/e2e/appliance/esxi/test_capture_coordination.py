"""Read-only transport fault and cancellation regressions; no VM calls."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

c=load('capture-coordination')
x=load('cancel-abandoned-transport')

class CaptureTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.sec=self.root/'secrets';self.sec.mkdir()
        self.now=0
        self.lab=SimpleNamespace(run=self.root,sec=self.sec,private_diagnostics=self.sec,state={'path':'owned'},vm=Mock())
        self.path=self.sec/'frame.png'
        def produce(*args,**kw):Path(args[1].split('=',1)[1]).write_bytes(b'pixels')
        self.produce=produce;self.lab.gov=Mock(side_effect=produce)
    def pause(self,seconds):self.now+=seconds
    def snapshot(self):return c.snapshot(self.lab,self.path,20,clock=lambda:self.now,pause=self.pause)
    def test_transient_read_retains_receipt_and_revalidates_without_keyboard(self):
        calls=0
        def produce(*args,**kw):
            nonlocal calls;calls+=1
            if calls==1:raise c.ReadFailure('synthetic read transport')
            self.produce(*args,**kw)
        self.lab.gov.side_effect=produce
        self.assertEqual(self.snapshot().name,'frame.attempt-2.png')
        self.assertEqual(self.lab.vm.call_count,3)
        self.assertEqual(len(list((self.sec/'capture-errors').glob('*.json'))),1)
        self.assertFalse((self.root/'console-capture.lock').exists())
    def test_zero_bytes_retained_and_bounded_three_attempts(self):
        self.lab.gov.side_effect=lambda *a,**k:Path(a[1].split('=',1)[1]).write_bytes(b'')
        with self.assertRaises(c.ReadFailure):self.snapshot()
        self.assertEqual(self.lab.gov.call_count,3)
        self.assertEqual(len(list(self.sec.glob('*.png'))),3)
        self.assertEqual(len(list((self.sec/'capture-errors').glob('*.json'))),3)
    def test_ownership_failure_is_terminal_before_capture(self):
        self.lab.vm.side_effect=ValueError('wrong UUID')
        with self.assertRaises(ValueError):self.snapshot()
        self.lab.gov.assert_not_called();self.assertEqual(self.lab.vm.call_count,1)
    def test_missing_file_and_arbitrary_failure_are_terminal(self):
        for effect in (lambda *a,**k:None, OSError('not classified')):
            self.lab.gov=Mock(side_effect=effect)
            with self.assertRaises((OSError,ValueError)):self.snapshot()
            self.assertEqual(self.lab.gov.call_count,1)
    def test_capture_lock_wait_is_bounded_without_stealing(self):
        lock=self.root/'console-capture.lock';lock.write_text('other-process')
        with self.assertRaises(TimeoutError):self.snapshot()
        self.assertEqual(lock.read_text(),'other-process');self.lab.gov.assert_not_called()
    def test_existing_image_never_overwritten(self):
        self.path.write_bytes(b'original')
        with self.assertRaises(ValueError):self.snapshot()
        self.assertEqual(self.path.read_bytes(),b'original');self.lab.gov.assert_not_called()
    def test_private_error_path_does_not_follow_capture_directory(self):
        module=load('esxi-lab');lab=object.__new__(module.Lab)
        lab.sec=self.sec/'capture';lab.sec.mkdir();lab.private_diagnostics=self.sec;lab.state={'uuid':'owned'}
        (self.sec/'id_ed25519').write_text('synthetic')
        lab.gov_error('vm.console',{'returncode':1,'stderr':'synthetic capture fault'})
        lab.gov_error('vm.console',{'timeout':True})
        self.assertEqual(len(list(self.sec.glob('govc-error-*.json'))),2)
        self.assertEqual(list(lab.sec.iterdir()),[])

class CancelTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.sec=self.root/'secrets';self.sec.mkdir()
        self.binding=self.root/'binding'
        old=self.root/'original-scope';old.write_text(json.dumps({'run_dir':str(self.root/'original-run')}))
        self.binding.write_text(json.dumps({'files':{'scope':{'path':str(old)}}}))
        self.prompt='LAB AUTH ABCDEF0123456789:'
        self.lab=SimpleNamespace(run=self.root,sec=self.sec,state={'uuid':x.UUID,'ref':{'value':'vm-1'},'owner':'LOCAL-ESXI:synthetic'},
            c={'endpoint':'https://192.0.2.1'},_credential_env={},vm=Mock(return_value={'runtime':{'powerState':'poweredOn'}}))
        self.observer=Mock();self.observer.screen.side_effect=[self.prompt,self.prompt,'bash-5.2$']
        self.observer.shell_prompt.side_effect=lambda t:t=='bash-5.2$'
        self.dispatch=Mock(return_value=SimpleNamespace(returncode=0))
        for target,value in [('validate',lambda *a:(Path('cancel.exe'),self.prompt)),('Console',lambda *a:self.observer),('private_directory',lambda *a:None)]:
            owner=x if target=='validate' else x.console if target=='Console' else x.console.b
            context=patch.object(owner,target,value);context.start();self.addCleanup(context.stop)
    def run_cancel(self):x.cancel(self.lab,self.binding,self.dispatch)
    def test_exact_prompt_one_control_c_and_shell_proof(self):
        self.run_cancel();self.dispatch.assert_called_once()
        payload=json.loads(self.dispatch.call_args.kwargs['input'])
        self.assertEqual(set(payload),{'reference','uuid','owner'})
        self.observer.enter.assert_not_called();self.observer.shell.assert_not_called();self.observer.wait_shell.assert_not_called()
        self.assertTrue((self.sec/'abandoned-transport-cancel/complete.json').is_file())
        with self.assertRaises(FileExistsError):self.run_cancel()
        self.dispatch.assert_called_once()
    def test_changed_prompt_and_ownership_prevent_input(self):
        self.observer.screen.side_effect=[self.prompt,'LAB AUTH OTHER:']
        with self.assertRaises(ValueError):self.run_cancel()
        self.dispatch.assert_not_called()
    def test_failed_dispatch_is_one_shot_without_shell_claim(self):
        self.dispatch.return_value.returncode=1
        with self.assertRaises(ValueError):self.run_cancel()
        self.assertTrue((self.sec/'abandoned-transport-cancel/intent.json').is_file())
        self.assertFalse((self.sec/'abandoned-transport-cancel/complete.json').exists())
        with self.assertRaises(FileExistsError):self.run_cancel()
        self.dispatch.assert_called_once()
    def test_second_fresh_observation_waits_out_cursor_without_input(self):
        self.observer.screen.side_effect=[self.prompt,self.prompt+' \ufffd',self.prompt+' \ufffd',self.prompt,'bash-5.2$']
        with patch.object(x.time,'sleep'):self.run_cancel()
        self.assertEqual(self.observer.screen.call_count,5);self.dispatch.assert_called_once()
        self.observer.enter.assert_not_called()

    def test_second_observation_unknown_prompt_never_dispatches(self):
        self.observer.screen.side_effect=[self.prompt,self.prompt.replace('ABC','A\ufffdC')]
        with self.assertRaises(ValueError):self.run_cancel()
        self.dispatch.assert_not_called()
        self.assertEqual(list((self.sec/'abandoned-transport-cancel').iterdir()),[])

    def test_permanent_cursor_is_bounded_and_no_glyph_is_repaired(self):
        self.observer.screen.side_effect=None;self.observer.screen.return_value=self.prompt+' \ufffd'
        now=[0.0]
        def pause(seconds):now[0]+=seconds
        with self.assertRaisesRegex(ValueError,'expired'):
            x.wait_clean_prompt(self.observer,self.prompt,2,clock=lambda:now[0],pause=pause)
        self.assertEqual(self.observer.screen.call_count,4);self.dispatch.assert_not_called()

    def test_prior_intent_or_any_evidence_prevents_undispatched_claim(self):
        prior=self.sec/'abandoned-transport-cancel';prior.mkdir()
        x.empty_prior_attempt(self.lab)
        with patch.object(type(prior),'lstat',return_value=SimpleNamespace(st_file_attributes=0x400)):
            with self.assertRaisesRegex(ValueError,'reparse'):x.empty_prior_attempt(self.lab)
        for name in ('intent.json','complete.json','unexpected'):
            path=prior/name;path.write_text('already dispatched or uncertain')
            with self.assertRaises(ValueError):x.empty_prior_attempt(self.lab)
            path.unlink()

    def test_original_capture_lock_prevents_cancellation(self):
        original=self.root/'original-run';original.mkdir();(original/'console-capture.lock').write_text('busy')
        with self.assertRaisesRegex(ValueError,'original run'):self.run_cancel()
        self.dispatch.assert_not_called()

    def test_go_tool_is_fixed_ctrl_c_without_text_or_arbitrary_key(self):
        s=(HERE/'private-cancel.go').read_text()
        self.assertIn('UsbHidCode: 0x06<<16 | 7',s);self.assertIn('LeftControl: &control',s)
        self.assertIn('DisallowUnknownFields',s);self.assertNotIn('input.Text',s);self.assertNotIn('input.Code',s)
        self.assertIn('observed.Runtime.PowerState != types.VirtualMachinePowerStatePoweredOn',s)

class BindingTests(unittest.TestCase):
    def test_original_binding_frozen_binary_and_activity_guards(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);oldroot=root/'old';oldroot.mkdir();oldrun=oldroot/'run';oldrun.mkdir()
            newrun=root/'newrun';newrun.mkdir();(oldrun/'secrets').mkdir()
            ids=load('candidate-identities');old=dict(ids.source_profile(ids.E91),run_dir=str(oldrun),controller_manifest=str(oldroot/'manifest'))
            oldscope=oldroot/'scope';oldscope.write_text(json.dumps(old))
            owned={'uuid':x.UUID};(oldrun/'owned.json').write_text(json.dumps(owned))
            oldfreeze={'revision':x.REVISION};(oldroot/'manifest').write_text(json.dumps(oldfreeze))
            text=x.NONCE+'\nLAB AUTH ABCDEF0123456789:'
            capture=oldroot/'capture';capture.write_text(text)
            out=oldroot/'out';out.write_bytes(b'failed')
            err=oldroot/'err';err.write_bytes(b'Authenticated console transport blocked')
            receipt=oldroot/'receipt';receipt.write_text(json.dumps({'exit_code':1,'stdout_sha256':x.sha(out.read_bytes()),'stderr_sha256':x.sha(err.read_bytes())}))
            locations={'scope':oldscope,'manifest':oldroot/'manifest','owned':oldrun/'owned.json','pending_capture':capture,
                       'lifecycle_out':out,'lifecycle_err':err,'lifecycle_receipt':receipt}
            binary=root/'cancel.exe';binary.write_bytes(b'synthetic executable')
            binding=root/'binding';binding.write_text(json.dumps({'original_root':str(oldroot),
                'files':{k:{'path':str(p),'sha256':x.sha(p.read_bytes())} for k,p in locations.items()},
                'cancel_binary':str(binary),'cancel_binary_sha256':x.sha(binary.read_bytes())}))
            manifest={'files':{'test/e2e/appliance/esxi/private-cancel.go':x.sha((HERE/'private-cancel.go').read_bytes())},
                'external_inputs':[{'path':str(p),'sha256':x.sha(p.read_bytes())} for p in (binary,binding)]}
            lab=SimpleNamespace(c=dict(old,run_dir=str(newrun),controller_manifest=str(root/'newmanifest')),run=newrun,state=owned)
            real_load=x.load
            fakefreeze=SimpleNamespace(verify=lambda path,*args:oldfreeze if path==oldroot/'manifest' else manifest)
            with patch.object(x,'load',side_effect=lambda name:fakefreeze if name=='controller-freeze' else real_load(name)), \
                 patch.object(x,'CAPTURE_SHA',x.sha(capture.read_bytes())):
                self.assertEqual(x.validate(lab,binding)[1],'LAB AUTH ABCDEF0123456789:')
                for name in ('visual-capture.lock','console-capture.lock','operation.lock','access-aware-qualify.lock'):
                    path=oldrun/name;path.write_text('busy')
                    with self.assertRaisesRegex(ValueError,'original run'):x.validate(lab,binding)
                    path.unlink()
                lab.c['image_id']='changed'
                with self.assertRaisesRegex(ValueError,'only separate'):x.validate(lab,binding)
                lab.c['image_id']=old['image_id']
                binary.write_bytes(b'replaced')
                with self.assertRaisesRegex(ValueError,'external input'):x.validate(lab,binding)

class UndispatchedBindingTests(unittest.TestCase):
    def test_exact_prior_stop_requires_frozen_receipt_images_revision_and_empty_attempt(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);prior=root/'prior';tools=prior/'.tools';tools.mkdir(parents=True)
            run=tools/'run';sec=run/'secrets';sec.mkdir(parents=True)
            ops=tools/'private-operations';ops.mkdir()
            prompt='LAB AUTH ABCDEF0123456789:'
            scope={'run_dir':str(run),'controller_manifest':str(tools/'controller-freeze.json')}
            frozen={'revision':x.PRIOR_CANCEL_REVISION}
            binding={'original_root':'initial-root','files':{'synthetic':'unchanged'}}
            owned={'uuid':x.UUID}
            paths={'scope':tools/'scope-91-source.json','manifest':tools/'controller-freeze.json',
                   'binding':tools/'cancel-binding.json','owned':run/'owned.json',
                   'receipt':ops/'cancel-abandoned.receipt.json','out':ops/'cancel-abandoned.out','err':ops/'cancel-abandoned.err'}
            for name,value in [('scope',scope),('manifest',frozen),('binding',binding),('owned',owned)]:paths[name].write_text(json.dumps(value))
            paths['out'].write_bytes(b'');paths['err'].write_text('BLOCKED: cancellation unverified; preserve private evidence; no retry.\n')
            paths['receipt'].write_text(json.dumps({'exit_code':90,'stdout_sha256':x.sha(paths['out'].read_bytes()),'stderr_sha256':x.sha(paths['err'].read_bytes())}))
            for phase,directory in [('cursor','109f89739e460f32'),('clean','ac3930fc1af46dda'),('refresh','fabb6c0b5ece74be')]:
                cap=sec/('capture-'+directory);cap.mkdir()
                for kind,suffix in [('text','txt'),('png','png')]:
                    path=cap/('bootstrap-001.'+suffix);paths[phase+'_'+kind]=path
                    path.write_bytes((prompt+('' if phase=='clean' else ' \ufffd')).encode() if kind=='text' else b'synthetic pixels')
            attempt=sec/'abandoned-transport-cancel';attempt.mkdir()
            proof=root/'proof.json';proof.write_text(json.dumps({'original_root':str(prior),'files':{k:{'path':str(p),'sha256':x.sha(p.read_bytes())} for k,p in paths.items()}}))
            newfreeze={'external_inputs':[{'path':str(proof),'sha256':x.sha(proof.read_bytes())}]}
            lab=SimpleNamespace(run=run,sec=sec,state_file=paths['owned'],state=owned,c=dict(scope,controller_manifest=str(root/'new-freeze')))
            fake=SimpleNamespace(verify=lambda path,*args:frozen if path==paths['manifest'] else newfreeze)
            hashes={k:x.sha(paths[k].read_bytes()) for k in x.PRIOR_CANCEL_HASHES}
            real_load=x.load
            with patch.object(x,'load',side_effect=lambda name:fake if name=='controller-freeze' else real_load(name)),patch.object(x,'PRIOR_CANCEL_HASHES',hashes):
                self.assertEqual(x.validate_undispatched(lab,proof,paths['binding'],prompt),x.sha(proof.read_bytes()))
                (attempt/'intent.json').write_text('uncertain')
                with self.assertRaisesRegex(ValueError,'undispatched'):x.validate_undispatched(lab,proof,paths['binding'],prompt)
                (attempt/'intent.json').unlink()
                lab.c['run_dir']='different'
                with self.assertRaisesRegex(ValueError,'same active run'):x.validate_undispatched(lab,proof,paths['binding'],prompt)
                lab.c['run_dir']=scope['run_dir']
                hashes['refresh_png']='0'*64
                with self.assertRaisesRegex(ValueError,'recorded cursor stop'):x.validate_undispatched(lab,proof,paths['binding'],prompt)

if __name__=='__main__':unittest.main()
