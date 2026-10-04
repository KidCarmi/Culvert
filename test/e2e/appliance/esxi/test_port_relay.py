"""Synthetic loopback tests only; never connect to ESXi or an appliance."""
import argparse
import asyncio
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import socket
import struct
import unittest

spec = importlib.util.spec_from_file_location('esxi_port_relay', Path(__file__).with_name('esxi-port-relay.py'))
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class ValidationTests(unittest.TestCase):
    def test_only_approved_ipv4_host_and_mappings(self):
        self.assertEqual(relay.validated_target('192.168.1.120'), '192.168.1.120')
        for value in ('127.0.0.1', '::1', '192.168.1.0', '192.168.1.255', '192.168.2.1', 'hostname'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                relay.validated_target(value)
        self.assertEqual(relay.validated_mapping('19090:9090'), (19090, 9090))
        for value in ('0:22', '2222:23', '22:22', 'abc:22', '2222:22:22'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                relay.validated_mapping(value)


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_stop_closes_live_connections_before_waiting_for_servers(self):
        connected = asyncio.Event()
        async def sink(reader, writer):
            connected.set()
            try:
                await reader.read()
            finally:
                await relay.close_writer(writer)
        upstream = await asyncio.start_server(sink, '127.0.0.1', 0)
        service = relay.Relay('127.0.0.1', [(0, upstream.sockets[0].getsockname()[1])])
        task = asyncio.create_task(service.run())
        writer = None
        try:
            for _ in range(100):
                if service.servers:
                    break
                await asyncio.sleep(.01)
            reader, writer = await asyncio.open_connection(*service.servers[0].sockets[0].getsockname())
            await asyncio.wait_for(connected.wait(), 1)
            service.stopped.set()
            self.assertEqual(await asyncio.wait_for(task, 3), 0)
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
            self.assertEqual(service.active, 0)
        finally:
            if writer is not None:
                await relay.close_writer(writer)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await service.close()
            upstream.close()
            await upstream.wait_closed()

    async def test_upstream_reset_fails_whole_process_contract(self):
        # asyncio's Windows transport.abort() performs shutdown first and can
        # send FIN. Close a raw linger-zero socket to exercise an actual RST.
        upstream = socket.socket()
        upstream.bind(('127.0.0.1', 0))
        upstream.listen()
        upstream.setblocking(False)
        async def reset():
            sock, _ = await asyncio.get_running_loop().sock_accept(upstream)
            await asyncio.sleep(.05)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack('hh' if os.name == 'nt' else 'ii', 1, 0))
            sock.close()

        reset_task = asyncio.create_task(reset())
        service = relay.Relay('127.0.0.1', [(0, upstream.getsockname()[1])])
        task = asyncio.create_task(service.run())
        writer = None
        try:
            for _ in range(100):
                if service.servers:
                    break
                await asyncio.sleep(.01)
            _, writer = await asyncio.open_connection(*service.servers[0].sockets[0].getsockname())
            self.assertEqual(await asyncio.wait_for(task, 3), 1)
            self.assertEqual(service.active, 0)
        finally:
            if writer is not None:
                await relay.close_writer(writer)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await service.close()
            upstream.close()
            reset_task.cancel()
            await asyncio.gather(reset_task, return_exceptions=True)

    async def test_bidirectional_half_close_and_loopback_bind(self):
        async def echo(reader, writer):
            data = await reader.read()
            writer.write(b'reply:' + data)
            await writer.drain()
            await relay.close_writer(writer)

        upstream = await asyncio.start_server(echo, '127.0.0.1', 0)
        port = upstream.sockets[0].getsockname()[1]
        service = relay.Relay('127.0.0.1', [(0, port)], connect_timeout=.5)
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                await service.start()
                address = service.servers[0].sockets[0].getsockname()
                self.assertEqual(address[0], '127.0.0.1')
                reader, writer = await asyncio.open_connection(*address)
                writer.write(b'SYNTHETIC_PRIVATE_PAYLOAD')
                await writer.drain()
                writer.write_eof()
                result = await asyncio.wait_for(reader.read(), 2)
                self.assertEqual(result, b'reply:SYNTHETIC_PRIVATE_PAYLOAD')
                await relay.close_writer(writer)
                self.assertFalse(service.failed.is_set())
        finally:
            await service.close()
            upstream.close()
            await upstream.wait_closed()
        self.assertEqual(output.getvalue(), '')

    async def test_upstream_connect_failure_exits_and_closes_listeners(self):
        unused = socket.socket()
        unused.bind(('127.0.0.1', 0))
        port = unused.getsockname()[1]
        unused.close()
        service = relay.Relay('127.0.0.1', [(0, port)], connect_timeout=.5)
        task = asyncio.create_task(service.run())
        try:
            for _ in range(100):
                if service.servers:
                    break
                await asyncio.sleep(.01)
            self.assertTrue(service.servers)
            reader, writer = await asyncio.open_connection(*service.servers[0].sockets[0].getsockname())
            self.assertEqual(await asyncio.wait_for(task, 2), 1)
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
            await relay.close_writer(writer)
            self.assertTrue(all(not server.is_serving() for server in service.servers))
            self.assertEqual(service.active, 0)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await service.close()

    async def test_connection_limit_refuses_extra_without_forwarding(self):
        accepted = 0
        async def sink(reader, writer):
            nonlocal accepted
            accepted += 1
            try:
                await reader.read()
            finally:
                await relay.close_writer(writer)
        upstream = await asyncio.start_server(sink, '127.0.0.1', 0)
        service = relay.Relay('127.0.0.1', [(0, upstream.sockets[0].getsockname()[1])], max_connections=1)
        writers = []
        try:
            await service.start()
            address = service.servers[0].sockets[0].getsockname()
            _, first = await asyncio.open_connection(*address)
            writers.append(first)
            for _ in range(100):
                if accepted:
                    break
                await asyncio.sleep(.01)
            reader, second = await asyncio.open_connection(*address)
            writers.append(second)
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
            self.assertEqual(accepted, 1)
            self.assertFalse(service.failed.is_set())
        finally:
            for writer in writers:
                await relay.close_writer(writer)
            await service.close()
            upstream.close()
            await upstream.wait_closed()


if __name__ == '__main__':
    unittest.main()
