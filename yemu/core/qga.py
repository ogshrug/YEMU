"""
Minimal async client for the QEMU guest agent (QGA) and QMP over TCP.

Each operation opens its own connection, so a client can be used from any event
loop (GUI worker, CLI, tests) without the loop-binding problems of a shared socket.
"""

import asyncio
import base64
import json
import logging
import random

logger = logging.getLogger(__name__)

# guest-file-read/write carry base64 chunks well past asyncio's 64 KiB default line limit
STREAM_LIMIT = 4 * 1024 * 1024


class AgentError(RuntimeError):
    pass


class GuestAgent:
    def __init__(self, host, port, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    @property
    def reader(self) -> asyncio.StreamReader:
        if self._reader is None:
            raise AgentError("not connected")
        return self._reader

    @property
    def writer(self) -> asyncio.StreamWriter:
        if self._writer is None:
            raise AgentError("not connected")
        return self._writer

    async def __aenter__(self):
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, limit=STREAM_LIMIT), self.timeout
        )
        await self._sync()
        return self

    async def __aexit__(self, *exc):
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _send(self, payload):
        self.writer.write((json.dumps(payload) + "\n").encode())
        await self.writer.drain()

    async def _sync(self):
        # guest-sync-delimited prefixes its reply with 0xFF so stale output from a
        # previous client can be discarded
        token = random.randint(1, 2**31)
        await self._send({"execute": "guest-sync-delimited", "arguments": {"id": token}})
        while True:
            await asyncio.wait_for(self.reader.readuntil(b"\xff"), self.timeout)
            line = await asyncio.wait_for(self.reader.readline(), self.timeout)
            try:
                if json.loads(line).get("return") == token:
                    return
            except json.JSONDecodeError:
                continue

    async def execute(self, command, arguments=None, expect_reply=True):
        payload = {"execute": command}
        if arguments is not None:
            payload["arguments"] = arguments
        await self._send(payload)
        if not expect_reply:
            return None
        while True:
            line = await asyncio.wait_for(self.reader.readline(), self.timeout)
            if not line:
                raise AgentError(f"agent closed connection during {command}")
            line = line.lstrip(b"\xff").strip()
            if not line:
                continue
            resp = json.loads(line)
            if "error" in resp:
                raise AgentError(f"{command}: {resp['error'].get('desc', resp['error'])}")
            if "return" in resp:
                return resp["return"]

    async def ping(self):
        await self.execute("guest-ping")

    async def exec(self, path, args, poll_interval=1.0, timeout=60):
        """Run a program in the guest; returns (exitcode, stdout, stderr). exitcode is None on timeout."""
        pid = (await self.execute("guest-exec", {"path": path, "arg": list(args), "capture-output": True}))["pid"]
        waited = 0.0
        while waited < timeout:
            status = await self.execute("guest-exec-status", {"pid": pid})
            if status.get("exited"):
                out = base64.b64decode(status.get("out-data", "")).decode(errors="replace")
                err = base64.b64decode(status.get("err-data", "")).decode(errors="replace")
                return status.get("exitcode"), out, err
            await asyncio.sleep(poll_interval)
            waited += poll_interval
        return None, "", ""

    async def write_file(self, guest_path, local_path, chunk_size=48 * 1024):
        handle = await self.execute("guest-file-open", {"path": guest_path, "mode": "wb"})
        try:
            with open(local_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    await self.execute(
                        "guest-file-write", {"handle": handle, "buf-b64": base64.b64encode(chunk).decode()}
                    )
        finally:
            await self.execute("guest-file-close", {"handle": handle})

    async def read_file(self, guest_path, local_path, chunk_size=48 * 1024):
        handle = await self.execute("guest-file-open", {"path": guest_path, "mode": "rb"})
        try:
            with open(local_path, "wb") as f:
                while True:
                    data = await self.execute("guest-file-read", {"handle": handle, "count": chunk_size})
                    f.write(base64.b64decode(data.get("buf-b64", "")))
                    if data.get("eof") or not data.get("count"):
                        break
        finally:
            await self.execute("guest-file-close", {"handle": handle})

    async def shutdown(self):
        # guest-shutdown never replies on success
        await self.execute("guest-shutdown", {"mode": "powerdown"}, expect_reply=False)


class QMP:
    """QEMU machine protocol, used to query and stop a running VM."""

    def __init__(self, host, port, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout

    async def command(self, command, arguments=None):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, limit=STREAM_LIMIT), self.timeout
        )
        try:
            await asyncio.wait_for(reader.readline(), self.timeout)  # greeting
            for cmd in (
                {"execute": "qmp_capabilities"},
                {"execute": command, **({"arguments": arguments} if arguments else {})},
            ):
                writer.write((json.dumps(cmd) + "\n").encode())
                await writer.drain()
                while True:
                    line = await asyncio.wait_for(reader.readline(), self.timeout)
                    if not line:
                        return None  # e.g. 'quit' closes the socket
                    resp = json.loads(line)
                    if "event" in resp:
                        continue
                    if "error" in resp:
                        raise AgentError(f"QMP {cmd['execute']}: {resp['error'].get('desc')}")
                    result = resp.get("return")
                    break
            return result
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
