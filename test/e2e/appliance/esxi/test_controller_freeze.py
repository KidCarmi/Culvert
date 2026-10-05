import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('freeze', Path(__file__).with_name('controller-freeze.py'))
freeze = importlib.util.module_from_spec(spec)
spec.loader.exec_module(freeze)


class FreezeTests(unittest.TestCase):
    def test_source_and_external_mutations_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = 'test/e2e/appliance/esxi/controller-freeze.py'
            source = root/name
            source.parent.mkdir(parents=True)
            source.write_bytes(b'original')
            external = root/'font.psf'
            external.write_bytes(b'font')
            manifest = root/'freeze.json'
            value = {'schema':1,'revision':'a'*40,
                     'files':{name:hashlib.sha256(b'original').hexdigest()},
                     'external_inputs':[{'path':str(external),'sha256':hashlib.sha256(b'font').hexdigest()}]}
            manifest.write_text(json.dumps(value))
            with patch.object(freeze, 'git', side_effect=lambda _, *args:'a'*40 if args[0]=='rev-parse' else ''):
                freeze.verify(manifest, root)
                source.write_bytes(b'modified')
                with self.assertRaisesRegex(ValueError, 'source bytes'):freeze.verify(manifest, root)
                source.write_bytes(b'original')
                external.write_bytes(b'wrong font')
                with self.assertRaisesRegex(ValueError, 'external'):freeze.verify(manifest, root)

    def test_revision_dirty_checkout_and_path_escape_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);manifest=root/'freeze.json'
            value={'schema':1,'revision':'a'*40,'files':{'test/e2e/appliance/esxi/controller-freeze.py':'0'*64}}
            manifest.write_text(json.dumps(value))
            with patch.object(freeze,'git',return_value='b'*40):
                with self.assertRaisesRegex(ValueError,'revision changed'):freeze.verify(manifest,root)
            with patch.object(freeze,'git',side_effect=['a'*40,' M changed']):
                with self.assertRaisesRegex(ValueError,'checkout changed'):freeze.verify(manifest,root)
            value['files']={'../outside':'0'*64,**value['files']};manifest.write_text(json.dumps(value))
            with patch.object(freeze,'git',side_effect=['a'*40,'']):
                with self.assertRaisesRegex(ValueError,'outside checkout'):freeze.verify(manifest,root)


if __name__=='__main__':unittest.main()
