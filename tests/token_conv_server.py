import io
import asyncio
import socket
import struct


async def handler(reader, writer):
    r = await reader.read(8)
    print(r)
    writer.write(b"\x81\x9d\x74\x13")
    await asyncio.sleep(1)
    writer.write(b"\x00\x00\x00\x01")
    await asyncio.sleep(1)
    while True:
        r = await reader.read(4)
        if len(r) == 0:
            break
        l, = struct.unpack(">I", r)
        print(l)
        in_ = await reader.read(l)
        print(in_)
        payload = b"hello world"
        writer.write(struct.pack(">I", len(payload)) + payload)


async def main():
    server1 = await asyncio.start_server(
        handler,
        family=socket.AF_INET,
        host="127.0.0.1",
        port=65321,
    )
    server2 = await asyncio.start_unix_server(
        handler,
        family=socket.AF_INET6,
        host="::",
        port=65321,
    )
    server3 = await asyncio.start_unix_server(
        handler,
        path="/tmp/test.sock",
    )
    await server1.start_serving()
    await server2.start_serving()
    await server3.start_serving()
    await server1.wait_closed()
    await server2.wait_closed()
    await server3.wait_closed()


asyncio.run(main())
