"""Offline exact-glyph and observation-bound tests; no captured credentials."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from PIL import Image


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pixel = load('pixel_console_test', 'pixel-console.py')
bootstrap = load('bootstrap_pixel_test', 'bootstrap-checks.py')
PASSWORD = 'Qv7AbcDefGhjKmn9'  # Synthetic fixture, never a guest password.
TEXT = 'INITIAL CONSOLE ACCESS\nUser: culvert\nOne-time password:\n' + PASSWORD


class PixelConsoleTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.font = self.directory / 'synthetic.psf'
        self.png = self.directory / 'synthetic.png'
        self.glyphs = [bytes(16) if code == 32 else bytes(4) + bytes([code]) * 8 + bytes(4)
                       for code in range(256)]
        self.pin = patch.object(pixel, 'FONT_SHA256', '')
        self.pin.start()
        self.addCleanup(self.pin.stop)
        self.write_font()

    def write_font(self):
        data = b'\x36\x04\x00\x10' + b''.join(self.glyphs)
        self.font.write_bytes(data)
        pixel.FONT_SHA256 = hashlib.sha256(data).hexdigest()

    def render(self, text=TEXT):
        rows = text.splitlines()
        image = Image.new('RGB', (max(map(len, rows)) * 8, len(rows) * 16), 'black')
        for row, line in enumerate(rows):
            for column, character in enumerate(line):
                for y, bits in enumerate(self.glyphs[ord(character)]):
                    for x in range(8):
                        if bits & (1 << (7 - x)):
                            image.putpixel((column * 8 + x, row * 16 + y), (170, 170, 170))
        return image

    def decode(self, image):
        image.save(self.png)
        return pixel.decode(self.png, self.font)

    def test_exact_glyphs_preserve_case_and_accept_only_complete_credential(self):
        decoded = self.decode(self.render())
        self.assertEqual(decoded, TEXT)
        self.assertEqual(bootstrap.extract_initial(decoded), PASSWORD)

    def test_unknown_and_multicolor_credential_cells_are_not_repaired(self):
        for color in ((170, 170, 170), (255, 0, 0)):
            with self.subTest(color=color):
                image = self.render()
                # The top row of every synthetic glyph is empty. Altering one
                # credential cell creates either an unknown bitmap or a third color.
                image.putpixel((1, 3 * 16), color)
                decoded = self.decode(image)
                self.assertIn('\ufffd', decoded.splitlines()[3])
                self.assertIsNone(bootstrap.extract_initial(decoded))

    def test_duplicate_ascii_glyphs_remain_ambiguous(self):
        self.glyphs[ord('u')] = self.glyphs[ord('v')]
        self.write_font()
        decoded = self.decode(self.render())
        self.assertIn('\ufffd', decoded.splitlines()[3])
        self.assertIsNone(bootstrap.extract_initial(decoded))

    def second_font(self, ambiguous=False):
        data = bytearray(self.font.read_bytes())
        if ambiguous:
            a, b = 4 + ord('Q') * 16, 4 + ord('v') * 16
            data[a:a+16], data[b:b+16] = data[b:b+16], data[a:a+16]
        else:
            for code in range(33, 127):
                start = 4 + code * 16
                data[start:start+16] = bytes([1]) + data[start+1:start+16]
        other = self.directory / 'other.psf'
        other.write_bytes(data)
        pin = patch.object(pixel, 'GOHA_FONT_SHA256', hashlib.sha256(data).hexdigest())
        pin.start()
        self.addCleanup(pin.stop)
        return other, bytes(data)

    def test_one_global_font_is_selected_for_each_capture(self):
        other, data = self.second_font()
        paths = str(self.font) + os.pathsep + str(other)
        self.render().save(self.png)
        self.assertEqual(pixel.decode(self.png, paths), TEXT)
        self.glyphs = [data[4+c*16:4+(c+1)*16] for c in range(256)]
        self.render().save(self.png)
        self.assertEqual(pixel.decode(self.png, paths), TEXT)

    def test_mixed_font_capture_is_not_assembled_into_a_credential(self):
        other, data = self.second_font()
        image = self.render()
        self.glyphs = [data[4+c*16:4+(c+1)*16] for c in range(256)]
        alternate = self.render()
        image.paste(alternate.crop((0, 48, 8, 64)), (0, 48))
        image.save(self.png)
        decoded = pixel.decode(self.png, str(self.font) + os.pathsep + str(other))
        self.assertIsNone(bootstrap.extract_initial(decoded))
        self.assertIn('\ufffd', decoded)

    def test_conflicting_character_maps_remain_unknown(self):
        other, _ = self.second_font(ambiguous=True)
        self.render().save(self.png)
        decoded = pixel.decode(self.png, str(self.font) + os.pathsep + str(other))
        self.assertIn('\ufffd', decoded.splitlines()[3])
        self.assertIsNone(bootstrap.extract_initial(decoded))

    def test_font_list_is_bounded_and_unknown_second_pin_refuses(self):
        self.render().save(self.png)
        for paths in (str(self.font) + os.pathsep, os.pathsep.join([str(self.font)] * 3)):
            with self.assertRaises(ValueError):
                pixel.decode(self.png, paths)
        other = self.directory / 'untrusted.psf'
        other.write_bytes(self.font.read_bytes() + b'untrusted')
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            pixel.decode(self.png, str(self.font) + os.pathsep + str(other))

    def test_wrong_font_identity_is_refused(self):
        self.font.write_bytes(self.font.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'font identity mismatch'):
            self.decode(self.render())

    def test_unexpected_background_is_refused(self):
        image = self.render()
        image.putpixel((0, 0), (255, 255, 255))
        with self.assertRaisesRegex(ValueError, 'background'):
            self.decode(image)

    def test_oversized_and_partial_cell_images_are_refused(self):
        for size, message in [((4104, 16), 'bounds'), ((8, 4112), 'bounds'),
                              ((9, 16), 'partial'), ((8, 17), 'partial')]:
            with self.subTest(size=size):
                with self.assertRaisesRegex(ValueError, message):
                    self.decode(Image.new('RGB', size, 'black'))


class BootstrapObservationTests(unittest.TestCase):
    def test_observation_and_capture_name_bounds(self):
        for seconds in (0, 1201):
            with self.subTest(seconds=seconds):
                with self.assertRaises(bootstrap.Blocked):
                    bootstrap.Bootstrap(None, None, initial_timeout=seconds)
        for prefix in ('../escape', 'Uppercase', 'with space', ''):
            with self.subTest(prefix=prefix):
                with self.assertRaises(bootstrap.Blocked):
                    bootstrap.Bootstrap(None, None, capture_prefix=prefix)

    def test_capture_limit_refuses_before_any_vm_call(self):
        lab = SimpleNamespace(vm=Mock(side_effect=AssertionError('VM call forbidden')))
        flow = bootstrap.Bootstrap(lab, None, initial_timeout=1200)
        self.assertEqual(flow.capture_limit, 280)
        flow.sequence = flow.capture_limit
        with self.assertRaisesRegex(bootstrap.Blocked, 'capture count'):
            flow.screen(flow.deadline)
        lab.vm.assert_not_called()

    def test_unknown_capture_resets_identical_observation_requirement(self):
        keyboard = Mock()
        flow = bootstrap.Bootstrap(None, keyboard)
        unknown = TEXT.replace(PASSWORD, PASSWORD[:4] + '\ufffd' + PASSWORD[5:])
        flow.screen = Mock(side_effect=[TEXT, unknown, TEXT, TEXT])
        with patch.object(bootstrap.time, 'sleep'):
            self.assertEqual(flow.initial(), PASSWORD)
        self.assertEqual(flow.screen.call_count, 4)
        keyboard.send.assert_not_called()

    def test_pixel_observation_refuses_oversized_text_and_expired_deadline(self):
        for name in ('oversized', 'expired'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                private = Path(directory)

                def capture(*args, **kwargs):
                    # A fake screenshot producer, never a hypervisor invocation.
                    Path(args[1].removeprefix('-capture=')).write_bytes(b'synthetic')

                lab = SimpleNamespace(sec=private, state={'path': 'synthetic'},
                                      vm=Mock(), gov=Mock(side_effect=capture))
                flow = bootstrap.Bootstrap(lab, None)
                decoder = SimpleNamespace(decode=lambda *args: '\ufffd' * 21846)
                spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
                budgets = [15, 20, bootstrap.Blocked('bounded bootstrap observation expired')]
                with patch.dict(bootstrap.os.environ, {'CULVERT_ESXI_CONSOLE_FONT': 'synthetic'}), \
                        patch.object(bootstrap.importlib.util, 'spec_from_file_location', return_value=spec), \
                        patch.object(bootstrap.importlib.util, 'module_from_spec', return_value=decoder):
                    if name == 'expired':
                        flow.budget = Mock(side_effect=budgets)
                    with self.assertRaisesRegex(bootstrap.Blocked, 'expired|pixel text exceeded'):
                        flow.screen(flow.deadline)
                self.assertFalse((private / 'bootstrap-001.txt').exists())


class OptionalPinnedFontTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('CULVERT_ESXI_CONSOLE_FONT'), 'external Ubuntu font not provided')
    def test_real_pinned_font_renders_exact_ascii_without_credential_capture(self):
        font_path = Path(os.environ['CULVERT_ESXI_CONSOLE_FONT'].split(os.pathsep)[0])
        font = font_path.read_bytes()
        self.assertIn(hashlib.sha256(font).hexdigest(), {pixel.FONT_SHA256, pixel.GOHA_FONT_SHA256})
        text = 'Synthetic ABC xyz 0123456789'
        image = Image.new('RGB', (len(text) * 8, 16), 'black')
        for column, character in enumerate(text):
            for y, bits in enumerate(font[4 + ord(character) * 16:4 + (ord(character) + 1) * 16]):
                for x in range(8):
                    if bits & (1 << (7 - x)):
                        image.putpixel((column * 8 + x, y), (170, 170, 170))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.png'
            image.save(path)
            self.assertEqual(pixel.decode(path, font_path), text)


if __name__ == '__main__':
    unittest.main()
