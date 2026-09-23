import asyncio
import base64
import json

import pytest
import pytest_asyncio

from yemu.core.provisioning import provision_vm
from yemu.core.qemu_backend import QemuBackend
from yemu.core.qga import AgentError, GuestAgent
from yemu.core.vm_backend import PROVISION_NETWORK, VMSpec
from yemu.core.vm_manager import MockVMManager


class FakeAgent:
    """Speaks enough of the QEMU guest agent protocol for the client under test."""

    def __init__(self):
        self.files = {}
        self.handles = {}
        self.commands = []

    async def handle(self, reader, writer):
        while line := await reader.readline():
            req = json.loads(line)
            cmd, args = req["execute"], req.get("arguments", {})
            self.commands.append(cmd)
            if cmd == "guest-sync-delimited":
                writer.write(b"\xff" + json.dumps({"return": args["id"]}).encode() + b"\n")
            elif cmd == "guest-ping":
                writer.write(b'{"return": {}}\n')
            elif cmd == "guest-exec":
                self.last_exec = args
                writer.write(b'{"return": {"pid": 42}}\n')
            elif cmd == "guest-exec-status":
                out = base64.b64encode(b"hello from guest").decode()
                writer.write(json.dumps({"return": {"exited": True, "exitcode": 0, "out-data": out}}).encode() + b"\n")
            elif cmd == "guest-file-open":
                handle = len(self.handles) + 1
                self.handles[handle] = [args["path"], args["mode"], 0]
                self.files.setdefault(args["path"], b"") if "r" in args["mode"] else self.files.__setitem__(
                    args["path"], b""
                )
                writer.write(json.dumps({"return": handle}).encode() + b"\n")
            elif cmd == "guest-file-write":
                path = self.handles[args["handle"]][0]
                self.files[path] += base64.b64decode(args["buf-b64"])
                writer.write(b'{"return": {"count": 1}}\n')
            elif cmd == "guest-file-read":
                h = self.handles[args["handle"]]
                data = self.files[h[0]][h[2] : h[2] + args["count"]]
                h[2] += len(data)
                eof = h[2] >= len(self.files[h[0]])
                writer.write(
                    json.dumps(
                        {"return": {"count": len(data), "buf-b64": base64.b64encode(data).decode(), "eof": eof}}
                    ).encode()
                    + b"\n"
                )
            elif cmd == "guest-file-close":
                writer.write(b'{"return": {}}\n')
            else:
                writer.write(json.dumps({"error": {"class": "CommandNotFound", "desc": cmd}}).encode() + b"\n")
            await writer.drain()
        writer.close()


@pytest_asyncio.fixture
async def agent_server():
    agent = FakeAgent()
    server = await asyncio.start_server(agent.handle, "127.0.0.1", 0, limit=4 * 1024 * 1024)
    agent.port = server.sockets[0].getsockname()[1]
    yield agent
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio
async def test_guest_agent_exec_and_file_round_trip(agent_server, tmp_path):
    src = tmp_path / "sample.bin"
    src.write_bytes(bytes(range(256)) * 500)  # >1 chunk
    async with GuestAgent("127.0.0.1", agent_server.port) as qga:
        await qga.ping()
        code, out, _ = await qga.exec("/bin/sh", ["-c", "echo hi"])
        assert (code, out) == (0, "hello from guest")
        await qga.write_file("/malware_sample", str(src))
    assert agent_server.files["/malware_sample"] == src.read_bytes()

    dst = tmp_path / "back.bin"
    async with GuestAgent("127.0.0.1", agent_server.port) as qga:
        await qga.read_file("/malware_sample", str(dst))
    assert dst.read_bytes() == src.read_bytes()


@pytest.mark.asyncio
async def test_guest_agent_surfaces_errors(agent_server):
    async with GuestAgent("127.0.0.1", agent_server.port) as qga:
        with pytest.raises(AgentError):
            await qga.execute("guest-not-a-command")


def _backend_with(accel):
    b = QemuBackend(config={"qemu": {"bin_dir": "", "accel": accel, "extra_args": ["-snapshot"]}})
    b.qemu_system = "qemu-system-x86_64"
    return b


@pytest.mark.parametrize(
    "mode,expect_netdev",
    [
        ("restricted", "user,id=n0,restrict=on"),
        ("user", "user,id=n0"),
    ],
)
def test_build_command_network_modes(mode, expect_netdev):
    b = _backend_with("tcg")
    vm = {
        "name": "t",
        "ram_mb": 1024,
        "cpus": 1,
        "disk_path": "d.qcow2",
        "cloud_init_path": "seed.iso",
        "network_mode": mode,
    }
    cmd = b.build_command(vm, {"qmp_port": 1, "qga_port": 2, "vnc_display": 100})
    assert cmd[cmd.index("-netdev") + 1] == expect_netdev
    assert "file=seed.iso,media=cdrom,readonly=on" in cmd
    assert "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0" in cmd
    assert cmd[-1] == "-snapshot"  # extra_args appended


def test_build_command_whpx_avoids_cpu_max():
    cmd = _backend_with("whpx").build_command(
        {"name": "t", "ram_mb": 512, "cpus": 1, "disk_path": "d.qcow2"},
        {"qmp_port": 1, "qga_port": 2, "vnc_display": 100},
    )
    assert cmd[cmd.index("-accel") + 1] == "whpx,kernel-irqchip=off"
    assert "-cpu" not in cmd


@pytest.mark.asyncio
async def test_define_and_switch_network_updates_isolation():
    b = _backend_with("tcg")
    await b.define_vm(
        VMSpec(name="iso-test", disk_path="d.qcow2", network=PROVISION_NETWORK, cloud_init_path="seed.iso")
    )
    assert await b.find_internet_facing_networks("iso-test") == ["QEMU user-mode NAT"]
    await b.switch_network("iso-test", PROVISION_NETWORK, "malware-analysis")
    assert await b.find_internet_facing_networks("iso-test") == []
    assert b._load("iso-test")["cloud_init_path"] is None
    assert b.list_vms() == ["iso-test"]
    await b.delete_vm("iso-test")
    assert b.list_vms() == []


class FakeProvisioner:
    CLOUD_IMAGES = {"ubuntu": "https://example.invalid/ubuntu.img"}
    guest_password = "pw123"
    download_dir = "."

    def download_file(self, url, filename=None, progress_callback=None):
        if progress_callback:
            progress_callback(5, 10)
        return "base.img"

    def create_cloud_init_iso(self, vm_name, user_data):
        return "seed.iso"

    def get_default_user_data(self):
        return "packages: [yara]"


class RecordingMock(MockVMManager):
    def __init__(self):
        super().__init__()
        self.calls = []

    async def run_command(self, vm_name, command, shell="/bin/sh"):
        return "YEMU_TOOLS_OK" if "YEMU_TOOLS_OK" in command else "done"

    async def switch_network(self, vm_name, from_network, to_network):
        self.calls.append(("switch", from_network, to_network))
        return True

    async def define_vm(self, spec):
        self.calls.append(("define", spec.network, spec.cloud_init_path))
        return True

    async def create_snapshot(self, vm_name, snapshot_name="clean-baseline", description=""):
        self.calls.append(("snapshot", snapshot_name))
        return True


@pytest.mark.asyncio
async def test_provisioning_flow_isolates_before_snapshot():
    backend = RecordingMock()
    messages = []
    password = await provision_vm(
        backend, "vm1", provisioner=FakeProvisioner(), progress=lambda m, f: messages.append((m, f))
    )
    assert password == "pw123"
    assert backend.calls == [
        ("define", PROVISION_NETWORK, "seed.iso"),
        ("switch", PROVISION_NETWORK, "malware-analysis"),
        ("snapshot", "clean-baseline"),
    ]
    assert messages[-1] == ("vm1 is ready.", 1.0)
