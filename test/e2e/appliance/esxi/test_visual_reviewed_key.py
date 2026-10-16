"""Finite reviewed pixels, bounded observation and no ambiguous-key replay."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
m=load('visual-reviewed-key');v=load('visual-capture')
PNG=b'\x89PNG\r\n\x1a\n'+struct.pack('>I',13)+b'IHDR'+struct.pack('>II',640,400)


class ReviewedKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);root=Path(self.temp.name)
        sec=root/'secrets';sec.mkdir();scope=root/'scope.json';scope.write_text('{}');manifest=root/'freeze.json';manifest.write_text('{}')
        self.lab=SimpleNamespace(run=root,sec=sec,scope_path=scope,c={'source_sha':'source','ova_sha256':'ova','image_id':'image','controller_manifest':str(manifest)},state={'uuid':'owner'},vm=mock.Mock(return_value={'runtime':{'powerState':'poweredOn'}}))
        self.campaign=sec/'visual-delayed';self.campaign.mkdir();self.frame=self.campaign/'frame-0000.png';self.frame.write_bytes(PNG)
        self.meta=v.image_metadata(self.frame,v.MAX_IMAGE);now=time.time_ns()
        header={'event':'owned','identity':{'uuid':'owner'},'scope_sha256':m.sha(scope),'source':'source','ova_sha256':'ova','image_id':'image'}
        row={'event':'frame','filename':self.frame.name,'uuid':'owner','finished_realtime_ns':now,**self.meta}
        (self.campaign/'frames.jsonl').write_text(json.dumps(header)+'\n'+json.dumps(row)+'\n')
        self.proof={'source_sha':'source','ova_sha256':'ova','image_id':'image','uuid':'owner','key':'esc','scope_sha256':m.sha(scope),'manifest_sha256':m.sha(manifest),'reviewed_state':'culvert-splash-no-auth','reviewed_realtime_ns':now,'campaign':'delayed','frames':[{'filename':self.frame.name,**self.meta}],'prior_attempts':[],'_sha256':'reviewhash'}
        self.directory=sec/'visual-reviewed-key-try';self.directory.mkdir();self.now=0

    def fake_capture(self,values):
        def capture(path,deadline):
            path.write_bytes(next(values));self.now+=.1;return path
        self.lab.capture_snapshot=capture

    def run_attempt(self,key):
        accepted,claim=m.validate_review(self.lab,self.proof,v)
        m.observe_then_send(self.lab,key,v,accepted,self.directory,claim,self.proof,clock=lambda:self.now,pause=lambda n:setattr(self,'now',self.now+n))
        return claim

    def test_unknown_animation_then_exact_reviewed_frame_sends_once(self):
        self.fake_capture(iter([PNG+b'other',PNG,PNG+b'after']));key=SimpleNamespace(send=mock.Mock())
        self.run_attempt(key);key.send.assert_called_once_with('KEY_ESC')
        self.assertTrue((self.directory/'observation-00.json').exists())
        self.assertTrue((self.directory/'complete.json').exists())

    def test_unreviewed_auth_or_any_other_pixels_never_send(self):
        self.fake_capture(iter([PNG+b'unreviewed-password-pixels']*10));key=SimpleNamespace(send=mock.Mock())
        with self.assertRaises(ValueError):self.run_attempt(key)
        key.send.assert_not_called();self.assertFalse((self.directory/'intent.json').exists())

    def test_durable_intent_precedes_input_and_blocks_replay_after_send_failure(self):
        self.fake_capture(iter([PNG]));synced=[]
        def send(key):
            self.assertTrue((self.directory/'intent.json').exists());self.assertGreaterEqual(len(synced),3)
            self.assertTrue((self.lab.run/'console-capture.lock').is_file())
            raise OSError('ambiguous send')
        with mock.patch.object(m.os,'fsync',side_effect=lambda fd:synced.append(fd)):
            with self.assertRaises(OSError):self.run_attempt(SimpleNamespace(send=send))
        with self.assertRaisesRegex(ValueError,'prior Esc intent'):m.validate_review(self.lab,self.proof,v)

    def test_held_capture_lock_deadline_refuses_without_intent(self):
        (self.lab.run/'console-capture.lock').write_text('other observer')
        self.fake_capture(iter([PNG]));key=SimpleNamespace(send=mock.Mock())
        with self.assertRaises(TimeoutError):self.run_attempt(key)
        key.send.assert_not_called();self.assertFalse((self.directory/'intent.json').exists())

    def test_wrong_owner_stale_scope_or_modified_frame_refused(self):
        for field,value in (('uuid','other'),('scope_sha256','bad'),('manifest_sha256','bad'),('reviewed_realtime_ns',time.time_ns()-121*10**9),('reviewed_state','password')):
            with self.subTest(field=field),self.assertRaises(ValueError):m.validate_review(self.lab,dict(self.proof,**{field:value}),v)
        self.frame.write_bytes(PNG+b'changed')
        with self.assertRaises(ValueError):m.validate_review(self.lab,self.proof,v)

    def test_prior_refusal_must_remain_exact_without_intent(self):
        old=self.lab.sec/'visual-key-before';old.mkdir();file=old/'before.png';file.write_bytes(PNG+b'old')
        self.proof['prior_attempts']=[{'directory':old.name,'files':{'before.png':m.sha(file)}}]
        m.validate_review(self.lab,self.proof,v)
        (old/'intent.json').write_text('{}')
        with self.assertRaises(ValueError):m.validate_review(self.lab,self.proof,v)

    def test_late_ownership_or_scope_change_never_sends(self):
        def capture(path,deadline):
            path.write_bytes(PNG);self.lab.scope_path.write_text('{"changed":true}');return path
        self.lab.capture_snapshot=capture;key=SimpleNamespace(send=mock.Mock())
        with self.assertRaises(ValueError):self.run_attempt(key)
        key.send.assert_not_called()

if __name__=='__main__':unittest.main()
