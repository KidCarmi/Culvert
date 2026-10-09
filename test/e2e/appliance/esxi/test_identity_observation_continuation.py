"""Offline proof guards and initial-only geometry handling; no live calls."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from PIL import Image

HERE = Path(__file__).parent
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
c = load('identity_campaign_test', 'p1-campaign.py')
b = load('identity_bootstrap_test', 'bootstrap-checks.py')


class IdentityContinuationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.sec = Path(self.tmp.name); self.folder = self.sec / 'p1-regressions'; self.folder.mkdir()
        self.owner = '11111111-1111-4111-8111-111111111111'
        self.write('identity-bootstrap.attempt.json', {'status':'blocked','uuid':self.owner,'campaign':'initial'})
        for name in ('identity-reset', 'identity-power-on'):
            self.write(name+'.attempt.json', {'status':'pass','uuid':self.owner,'campaign':'initial'})
        self.write('identity-before.json', {'phase':'identity-before-reset','identity':{'source':c.IDENTITY_SOURCE}})
        self.write('export-readiness.json', {'uuid':self.owner,'ova_sha256':c.IDENTITY_OVA,
                   'backup_export_verified':True,'escrow_export_verified':True})
        self.write('controller-exception-1.json', {'action':'identity-bootstrap','campaign':'initial',
                   'type':'ValueError','error':'console image contains partial glyph cells','undispatched_continuation':False})
        for name in ('old-console-password','old-console-password-original'):
            (self.folder/name).write_bytes(b'synthetic old value')
        self.frame = self.sec/'p1-identity-fresh-001.png'; Image.new('RGB',(640,480)).save(self.frame)
        for name, value in (('SOURCE',c.IDENTITY_SOURCE),('IDENTITY_FRAME',hashlib.sha256(self.frame.read_bytes()).hexdigest())):
            p=patch.object(c,name,value); p.start(); self.addCleanup(p.stop)

    def write(self,name,value): (self.folder/name).write_text(json.dumps(value))
    def bind(self): return c.identity_observation_binding(self.sec,'initial',self.owner)

    def test_preserves_originals_and_effective_stage_requires_bound_pass(self):
        old={p.name:p.read_bytes() for p in self.folder.iterdir()}
        binding=self.bind()
        self.assertEqual(old,{p.name:p.read_bytes() for p in self.folder.iterdir()})
        new=self.sec/'bootstrap-console-password';new.write_bytes(b'synthetic new value')
        for status in ('started','blocked','pass'):
            self.write('identity-bootstrap.continuation-attempt.json',{'status':status,'uuid':self.owner,'campaign':'initial',
                       'continuation':binding,'new_credential_sha256':hashlib.sha256(new.read_bytes()).hexdigest()})
            if status=='pass':self.assertEqual(c.effective_stage(self.sec,'initial','identity-bootstrap',self.owner)['status'],'pass')
            else:
                with self.assertRaises(ValueError):c.effective_stage(self.sec,'initial','identity-bootstrap',self.owner)
        (self.folder/'identity-reset.attempt.json').write_bytes(old['identity-reset.attempt.json']+b' ')
        with self.assertRaises(ValueError):c.effective_stage(self.sec,'initial','identity-bootstrap',self.owner)

    def test_any_new_credential_refuses_before_authentication(self):
        for value in (b'',b'new'):
            (self.sec/'bootstrap-console-password').write_bytes(value)
            with self.assertRaises(ValueError):self.bind()

    def test_old_password_owner_source_ova_and_exception_mutations_refuse(self):
        files={p.name:p.read_bytes() for p in self.folder.iterdir()}
        cases=[('old-console-password-original',b'changed'),
               ('identity-power-on.attempt.json',b'{"status":"blocked"}'),
               ('identity-reset.attempt.json',json.dumps({'status':'pass','uuid':'other','campaign':'initial'}).encode()),
               ('identity-before.json',b'{"phase":"identity-before-reset","identity":{"source":"other"}}'),
               ('export-readiness.json',b'{}'),
               ('controller-exception-1.json',b'{"action":"identity-bootstrap","type":"ValueError","error":"other"}')]
        for name,raw in cases:
            with self.subTest(name=name):
                (self.folder/name).write_bytes(raw)
                with self.assertRaises(ValueError):self.bind()
                (self.folder/name).write_bytes(files[name])

    def test_extra_frame_duplicate_exception_or_changed_frame_refuse(self):
        extra=self.sec/'p1-identity-fresh-002.png';extra.write_bytes(self.frame.read_bytes())
        with self.assertRaises(ValueError):self.bind()
        extra.unlink()
        duplicate=self.folder/'controller-exception-2.json';duplicate.write_bytes((self.folder/'controller-exception-1.json').read_bytes())
        with self.assertRaises(ValueError):self.bind()
        duplicate.unlink()
        Image.new('RGB',(720,400)).save(self.frame)
        with self.assertRaises(ValueError):self.bind()


class InitialGeometryTests(unittest.TestCase):
    def test_integral_grid_keeps_unknown_text_and_decoder_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab=SimpleNamespace(sec=Path(tmp),c={'console_cell_width':9},state={'path':'owned'},vm=Mock())
            def gov(*args,**kwargs):Image.new('RGB',(720,400)).save(Path(args[1].split('=',1)[1]))
            lab.gov=gov
            lab.run = lab.sec; lab.private_diagnostics = lab.sec
            lab.capture_snapshot = lambda path,deadline: b.module.capture.snapshot(lab,path,deadline)
            flow=b.Bootstrap(lab,Mock())
            decoder=SimpleNamespace(decode=Mock(return_value='unknown \ufffd'))
            spec=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module:None))
            with patch.dict(os.environ,{'CULVERT_ESXI_CONSOLE_FONT':'synthetic'}), \
                    patch.object(b.importlib.util,'spec_from_file_location',return_value=spec), \
                    patch.object(b.importlib.util,'module_from_spec',return_value=decoder):
                self.assertEqual(flow.screen(time.monotonic()+30),'unknown \ufffd')
                decoder.decode.side_effect=ValueError('bad font')
                with self.assertRaisesRegex(ValueError,'bad font'):flow.screen(time.monotonic()+30)
            flow.keyboard.send.assert_not_called()

    def test_partial_geometry_is_empty_only_before_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            sec=Path(tmp)
            lab=SimpleNamespace(sec=sec,c={'console_cell_width':9},state={'path':'owned'},vm=Mock())
            def gov(*args,**kwargs):Image.new('RGB',(640,480)).save(Path(args[1].split('=',1)[1]))
            lab.gov=gov
            lab.run = lab.sec; lab.private_diagnostics = lab.sec
            lab.capture_snapshot = lambda path,deadline: b.module.capture.snapshot(lab,path,deadline)
            flow=b.Bootstrap(lab,Mock())
            # Supply an actual pinned font if configured; geometry refusal occurs
            # before glyph decoding for the initial-only case.
            with patch.dict(os.environ,{'CULVERT_ESXI_CONSOLE_FONT':'untrusted-font'}):
                self.assertEqual(flow.screen(time.monotonic()+30),'')
                self.assertTrue((sec/'bootstrap-001.geometry.json').exists())
                flow.stage='pam-login'
                with self.assertRaises((ValueError,FileNotFoundError)):flow.screen(time.monotonic()+30)
                self.assertFalse((sec/'bootstrap-002.geometry.json').exists())
                class ExistingPasswordConsole(b.Bootstrap): pass
                inherited=ExistingPasswordConsole(lab,Mock(),capture_prefix='existing-auth')
                with self.assertRaises((ValueError,FileNotFoundError)):inherited.screen(time.monotonic()+30)
                self.assertFalse((sec/'existing-auth-001.geometry.json').exists())


if __name__=='__main__':unittest.main()
