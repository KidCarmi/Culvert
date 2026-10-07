import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('reviewed_esc', Path(__file__).with_name('reviewed-splash-esc.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ReviewedSplashTests(unittest.TestCase):
    def test_only_exact_full_text_matches(self):
        splash = '\n' * 10 + '       CULVERT\n       Starting services .\n' + '\n' * 12
        self.assertTrue(m.matches(splash, (splash,)))
        for value in ('Sign in', 'Password:', splash + 'x', splash.replace('CULVERT', '\ufffdULVERT'),
                      splash.replace('       CULVERT', '      CULVERT'), splash.replace('\n', '\n\n', 1)):
            self.assertFalse(m.matches(value, (splash,)))

    def test_reference_hash_size_unknown_and_layout_guards(self):
        text = '\n' * 24
        visual = SimpleNamespace(MAX_IMAGE=1024, image_metadata=Mock())
        pixel = SimpleNamespace(decode=Mock(return_value=text))
        expected = next(iter(m.REFERENCES.values()))
        meta = dict(width=720, height=400, sha256=expected)
        with patch.object(m, 'REFERENCES', {'ref.png': expected}):
            visual.image_metadata.return_value = meta
            self.assertEqual(m.references(Path('.'), visual, pixel, 'font'), (text,))
            for changed in ({**meta, 'sha256': '0' * 64}, {**meta, 'width': 640}):
                visual.image_metadata.return_value = changed
                with self.assertRaises(ValueError): m.references(Path('.'), visual, pixel, 'font')
            visual.image_metadata.return_value = meta
            for changed in ('\ufffd' + text, '\n' * 23):
                pixel.decode.return_value = changed
                with self.assertRaises(ValueError): m.references(Path('.'), visual, pixel, 'font')
        pixel.decode.assert_called_with(Path('ref.png'), 'font', cell_width=9)

    def run_observer(self, root, text='splash', send_error=False, ownership_error=False):
        scope = root / 'scope.json'; scope.write_text('{}')
        state = {'path': 'owned'}
        lab = SimpleNamespace(scope_path=scope, state_file=root / 'state', state=state,
                              gov=Mock(), vm=Mock(return_value={'runtime': {'powerState': 'poweredOn'}}))
        visual = SimpleNamespace(identity=lambda value: value, read_json=lambda path: state,
                                 no_identity_reset=Mock(), MAX_TOTAL=100000,
                                 image_metadata=Mock(return_value={'bytes': 50, 'width': 720, 'height': 400, 'sha256': 'a' * 64}))
        if ownership_error: lab.vm.side_effect = ValueError('owner differs')
        keyboard = SimpleNamespace(send=Mock(side_effect=ValueError('ambiguous') if send_error else None))
        now = [0]
        def pause(seconds): now[0] += seconds
        if text == 'expired':
            def expired_decode(*args, **kwargs): now[0] = 46; return 'splash'
            pixel = SimpleNamespace(decode=expired_decode)
        else: pixel = SimpleNamespace(decode=lambda *args, **kwargs: text)
        try:
            m.observe(lab, root, visual, pixel, 'font', keyboard, ('splash',), clock=lambda: now[0], pause=pause)
            error = None
        except ValueError as caught: error = caught
        return keyboard, error, lab

    def test_sends_once_after_durable_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keyboard, error, lab = self.run_observer(root)
            self.assertIsNone(error)
            keyboard.send.assert_called_once_with('KEY_ESC')
            self.assertTrue((root / 'intent.json').is_file())
            self.assertTrue((root / 'complete.json').is_file())
            self.assertEqual(lab.gov.call_count, 2)

    def test_ambiguous_input_never_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keyboard, error, lab = self.run_observer(root, send_error=True)
            self.assertIsNotNone(error)
            keyboard.send.assert_called_once_with('KEY_ESC')
            self.assertTrue((root / 'intent.json').exists())
            self.assertFalse((root / 'complete.json').exists())

    def test_wrong_screen_owner_and_expired_match_never_type(self):
        for options in ({'text': 'menu'}, {'text': '\ufffdsplash'}, {'text': 'expired'}, {'ownership_error': True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                keyboard, error, lab = self.run_observer(root, **options)
                self.assertIsNotNone(error)
                keyboard.send.assert_not_called()
                self.assertFalse((root / 'intent.json').exists())
                self.assertLessEqual(lab.gov.call_count, 45)


if __name__ == '__main__': unittest.main()
