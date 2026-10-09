import importlib.util
from pathlib import Path
import socket
import struct
import unittest
import tempfile
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('pressure_observe', Path(__file__).with_name('disk-pressure-observe.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def packet(payload=b'stream: Eicar-Test-Signature FOUND\0', source='172.18.0.3', target='172.18.0.2', port=3310):
    eth = b'\0' * 12 + b'\x08\x00'
    ip = bytearray(20)
    ip[0], ip[9] = 0x45, 6
    ip[2:4] = (40 + len(payload)).to_bytes(2, 'big')
    ip[12:16], ip[16:20] = socket.inet_aton(source), socket.inet_aton(target)
    tcp = bytearray(20)
    tcp[:8] = struct.pack('!HHI', port, 42000, 123)
    tcp[12], tcp[13] = 0x50, 0x18
    return eth + ip + tcp + payload


class ReplyTests(unittest.TestCase):
    def parse(self, value):
        return m.response_fragment(value, '172.18.0.3', '172.18.0.2')

    def test_only_exact_server_reply_is_retained(self):
        result = self.parse(packet())
        self.assertEqual(result['destination_port'], 42000)
        self.assertIn(b'FOUND', bytes.fromhex(result['response_fragment_hex']))
        for value in (packet(source='172.18.0.2', target='172.18.0.3'),
                      packet(target='172.18.0.1'), packet(port=80), packet(payload=b'')):
            self.assertIsNone(self.parse(value))

    def test_socket_uses_prebridge_all_protocol_tap_but_parser_stays_narrow(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = m.ReplyCapture('172.18.0.3', '172.18.0.2', Path(temporary)/'capture.jsonl')
            with patch.object(m.socket, 'AF_PACKET', 17, create=True), \
                    patch.object(m.socket, 'socket', return_value=Mock()) as socket_call, \
                    patch.object(m.os, 'O_NOFOLLOW', 0, create=True), \
                    patch.object(m.threading, 'Thread', return_value=Mock()):
                capture.start()
                socket_call.assert_called_once_with(17, m.socket.SOCK_RAW, m.socket.htons(0x0003))
                capture.close()
        for frame in (packet(source='172.18.0.4'), packet(port=9090), b'\0'*12+b'\x08\x06'+b'\0'*80):
            self.assertIsNone(self.parse(frame))

    def test_observations_do_not_widen_request_window(self):
        capture = m.ReplyCapture('172.18.0.3', '172.18.0.2', Path('unused'))
        capture.records = [{'monotonic_ns': value} for value in (9, 10, 15, 16)]
        self.assertEqual(capture.observations(10, 15), [{'monotonic_ns': 10}, {'monotonic_ns': 15}])

    def test_truncation_is_explicit_no_unbounded_payload(self):
        result = self.parse(packet(payload=b'x' * 1000))
        self.assertTrue(result['fragment_truncated'])
        self.assertEqual(len(result['response_fragment_hex']), 1024)
        self.assertEqual(result['payload_bytes'], 1000)

    def test_short_fragmented_and_malformed_frames_are_ignored(self):
        full = packet()
        for size in range(len(full)):
            self.assertIsNone(self.parse(full[:size]))
        fragmented = bytearray(full)
        fragmented[20:22] = b'\x20\x00'
        self.assertIsNone(self.parse(fragmented))
        malformed = bytearray(full)
        malformed[46] = 0xf0
        self.assertIsNone(self.parse(malformed))


if __name__ == '__main__':
    unittest.main()
