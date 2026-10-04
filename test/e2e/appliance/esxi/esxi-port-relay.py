#!/usr/bin/env python3
"""Local qualification transport; no SSH forwarding or guest configuration.

Example: --target 192.168.1.120 --map 2222:22 --map 18080:8080 --map 19090:9090
Only 127.0.0.1 listeners and the approved guest IPv4 subnet are accepted. No
payloads, credentials, connection addresses or exception details are logged.
"""
import argparse
import asyncio
import ipaddress
import signal
import sys

APPROVED_NETWORK = ipaddress.IPv4Network('192.168.1.0/24')
ALLOWED_MAPPINGS = {(2222, 22), (18080, 8080), (19090, 9090)}


class ClientDisconnected(Exception):
    pass


def validated_target(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise argparse.ArgumentTypeError('an approved IPv4 guest address is required') from None
    if address not in APPROVED_NETWORK or address in (APPROVED_NETWORK.network_address, APPROVED_NETWORK.broadcast_address):
        raise argparse.ArgumentTypeError('guest address is outside the approved host range')
    return str(address)


def validated_mapping(value):
    try:
        parts = value.split(':')
        if len(parts) != 2:
            raise ValueError
        mapping = tuple(int(part) for part in parts)
    except ValueError:
        raise argparse.ArgumentTypeError('mapping must be local-port:guest-port') from None
    if mapping not in ALLOWED_MAPPINGS:
        raise argparse.ArgumentTypeError('mapping is not allowlisted')
    return mapping


async def close_writer(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (OSError, asyncio.TimeoutError):
        pass


class Relay:
    def __init__(self, target, mappings, connect_timeout=10, max_connections=64):
        self.target, self.mappings = target, mappings
        self.connect_timeout, self.max_connections = connect_timeout, max_connections
        self.failed = asyncio.Event()
        self.stopped = asyncio.Event()
        self.servers = []
        self.tasks = set()
        self.active = 0

    async def start(self):
        try:
            for local, remote in self.mappings:
                server = await asyncio.start_server(
                    lambda reader, writer, port=remote: self.accept(reader, writer, port),
                    host='127.0.0.1', port=local, limit=65536)
                self.servers.append(server)
        except Exception:
            await self.close()
            raise

    async def pump(self, reader, writer, upstream_source):
        while True:
            try:
                data = await reader.read(65536)
            except OSError:
                if upstream_source:
                    self.failed.set()
                else:
                    raise ClientDisconnected from None
                return
            if not data:
                try:
                    if writer.can_write_eof():
                        writer.write_eof()
                        await writer.drain()
                except OSError:
                    if not upstream_source:
                        self.failed.set()
                    else:
                        raise ClientDisconnected from None
                return
            try:
                writer.write(data)
                await writer.drain()
            except OSError:
                if not upstream_source:
                    self.failed.set()
                else:
                    raise ClientDisconnected from None
                return

    async def accept(self, reader, writer, port):
        if self.active >= self.max_connections or self.failed.is_set():
            await close_writer(writer)
            return
        task = asyncio.current_task()
        self.tasks.add(task)
        self.active += 1
        upstream = None
        pumps = []
        try:
            try:
                upstream_reader, upstream = await asyncio.wait_for(
                    asyncio.open_connection(self.target, port, limit=65536), self.connect_timeout)
            except (OSError, asyncio.TimeoutError):
                self.failed.set()
                return
            pumps = [asyncio.create_task(self.pump(reader, upstream, False)),
                     asyncio.create_task(self.pump(upstream_reader, writer, True))]
            await asyncio.gather(*pumps)
        except ClientDisconnected:
            pass
        except OSError:
            self.failed.set()
        finally:
            # Close both transports before any await: supervisor cancellation
            # may arrive while a connection is already finishing.
            writer.close()
            if upstream is not None:
                upstream.close()
            for pump in pumps:
                pump.cancel()
            try:
                if pumps:
                    await asyncio.gather(*pumps, return_exceptions=True)
                if upstream is not None:
                    await close_writer(upstream)
                await close_writer(writer)
            finally:
                self.active -= 1
                self.tasks.discard(task)

    async def close(self):
        for server in self.servers:
            server.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.wait_for(
            asyncio.gather(*(server.wait_closed() for server in self.servers)), 3)

    async def run(self):
        await self.start()
        waits = [asyncio.create_task(self.failed.wait()), asyncio.create_task(self.stopped.wait())]
        try:
            await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
            return 1 if self.failed.is_set() else 0
        finally:
            for wait in waits:
                wait.cancel()
            await asyncio.gather(*waits, return_exceptions=True)
            await self.close()


async def serve(target, mappings):
    relay = Relay(target, mappings)
    loop = asyncio.get_running_loop()
    # Windows does not implement add_signal_handler. The supervisor's process
    # termination still closes all sockets at the OS boundary there.
    for name in ('SIGTERM', 'SIGINT'):
        try:
            loop.add_signal_handler(getattr(signal, name), relay.stopped.set)
        except (NotImplementedError, RuntimeError):
            pass
    return await relay.run()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=validated_target)
    parser.add_argument('--map', action='append', required=True, type=validated_mapping, dest='mappings')
    args = parser.parse_args()
    if len(args.mappings) != len(set(args.mappings)):
        parser.error('duplicate listener mapping')
    try:
        result = asyncio.run(serve(args.target, args.mappings))
    except KeyboardInterrupt:
        return 1
    except Exception:
        result = 1
    if result:
        print('Local relay stopped; upstream transport is unavailable.', file=sys.stderr)
    return result


if __name__ == '__main__':
    raise SystemExit(main())
