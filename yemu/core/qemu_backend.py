"""
Standalone QEMU backend: no libvirt, works on Windows (WHPX) and Linux (KVM),
falling back to TCG emulation.

Each VM is a directory under <vm storage>/qemu/<name>/ holding:
  vm.json   the VMSpec plus the network mode
  run.json  runtime state while the VM is up (pid, QMP/QGA/VNC ports)
  console.log  serial console, handy when a guest fails to boot

Networking uses QEMU user-mode (slirp): "user" is NAT (provisioning only),
"restricted" blocks all traffic leaving the guest (analysis), "none" has no NIC.
Snapshots are qcow2 internal disk snapshots taken with the VM powered off.
"""

import asyncio
import json
import os
import shutil
import signal
import socket
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any

from yemu import paths
from yemu.core.qemu_tools import choose_accel, find_binary
from yemu.core.qga import QMP, AgentError, GuestAgent
from yemu.core.vm_backend import PROVISION_NETWORK, VMBackend, VMSpec

HOST = "127.0.0.1"


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def _free_vnc_display():
    for display in range(100, 1000):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((HOST, 5900 + display))
                return display
            except OSError:
                continue
    raise RuntimeError("No free VNC display between :100 and :999")


def _network_mode(network_name):
    return "user" if network_name == PROVISION_NETWORK else "restricted"


class QemuBackend(VMBackend):
    name = "qemu"

    def __init__(self, ui_callback=None, config=None):
        super().__init__(ui_callback=ui_callback)
        qcfg = (config or {}).get("qemu", {})
        self.bin_dir = qcfg.get("bin_dir", "")
        self.accel_pref = qcfg.get("accel", "auto")
        self.extra_args = list(qcfg.get("extra_args", []))
        self.qemu_system = find_binary("qemu-system-x86_64", self.bin_dir)
        self.qemu_img = find_binary("qemu-img", self.bin_dir)
        self._accel = None

    # --- helpers ---
    def available(self):
        return bool(self.qemu_system and self.qemu_img)

    @property
    def accel(self):
        if self._accel is None:
            self._accel = choose_accel(self.qemu_system, self.accel_pref) if self.qemu_system else "tcg"
        return self._accel

    def _root(self):
        return paths.vm_storage_dir() / "qemu"

    def _vm_dir(self, vm_name):
        return self._root() / vm_name

    def _load(self, vm_name):
        cfg = self._vm_dir(vm_name) / "vm.json"
        if not cfg.is_file():
            return None
        return json.loads(cfg.read_text(encoding="utf-8"))

    def _save(self, vm_name, data):
        d = self._vm_dir(vm_name)
        d.mkdir(parents=True, exist_ok=True)
        (d / "vm.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _run_state(self, vm_name):
        f = self._vm_dir(vm_name) / "run.json"
        if not f.is_file():
            return None
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def _require(self, vm_name):
        vm = self._load(vm_name)
        if vm is None:
            msg = f"VM '{vm_name}' not found. Create it with 'yemu vm create {vm_name}' or Prepare New VM."
            self._notify_ui(msg, "CRITICAL")
            raise RuntimeError(msg)
        return vm

    async def _run_tool(self, *args, timeout=120):
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(f"{Path(args[0]).name} timed out") from None
        if proc.returncode != 0:
            raise RuntimeError(f"{Path(args[0]).name} {args[1]} failed: {err.decode(errors='replace').strip()}")
        return out.decode(errors="replace")

    async def is_running(self, vm_name):
        state = self._run_state(vm_name)
        if not state:
            return False
        try:
            await QMP(HOST, state["qmp_port"], timeout=2).command("query-status")
            return True
        except (OSError, asyncio.TimeoutError, AgentError, json.JSONDecodeError):
            (self._vm_dir(vm_name) / "run.json").unlink(missing_ok=True)
            return False

    def _agent(self, vm_name, timeout=10):
        state = self._run_state(vm_name)
        if not state:
            raise AgentError(f"VM '{vm_name}' is not running")
        return GuestAgent(HOST, state["qga_port"], timeout=timeout)

    def _kill(self, pid):
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True)
            else:
                os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
        except (OSError, ProcessLookupError):
            pass

    async def _wait_stopped(self, vm_name, timeout):
        for _ in range(int(timeout)):
            if not await self.is_running(vm_name):
                return True
            await asyncio.sleep(1)
        return False

    async def _graceful_stop(self, vm_name, timeout=120):
        if not await self.is_running(vm_name):
            return True
        try:
            async with self._agent(vm_name, timeout=5) as qga:
                await qga.shutdown()
        except (OSError, asyncio.TimeoutError, AgentError):
            try:
                await QMP(HOST, self._run_state(vm_name)["qmp_port"]).command("system_powerdown")
            except (OSError, asyncio.TimeoutError, AgentError, TypeError):
                pass
        if await self._wait_stopped(vm_name, timeout):
            return True
        self.logger.warning(f"{vm_name} did not power off in {timeout}s, forcing stop")
        return await self.stop_vm(vm_name)

    def build_command(self, vm, state):
        """QEMU argv for a VM definition and allocated ports (kept separate for testing)."""
        accel = self.accel
        accel_arg = "whpx,kernel-irqchip=off" if accel == "whpx" else accel
        cmd = [
            self.qemu_system,
            "-name",
            vm["name"],
            "-machine",
            "q35",
            "-accel",
            accel_arg,
        ]
        # WHPX crashes ("Unexpected VP exit code 4") with -cpu max; its default model works
        if accel in ("kvm", "hvf"):
            cmd += ["-cpu", "host"]
        elif accel == "tcg":
            cmd += ["-cpu", "max"]
        cmd += [
            "-m",
            str(vm["ram_mb"]),
            "-smp",
            str(vm["cpus"]),
            "-drive",
            f"file={vm['disk_path']},if=virtio,format=qcow2",
        ]
        for cd in (vm.get("iso_path"), vm.get("cloud_init_path")):
            if cd:
                cmd += ["-drive", f"file={cd},media=cdrom,readonly=on"]
        mode = vm.get("network_mode", "restricted")
        if mode != "none":
            restrict = ",restrict=on" if mode == "restricted" else ""
            cmd += ["-netdev", f"user,id=n0{restrict}", "-device", "virtio-net-pci,netdev=n0"]
        else:
            cmd += ["-nic", "none"]
        cmd += [
            "-chardev",
            f"socket,id=qga0,host={HOST},port={state['qga_port']},server=on,wait=off",
            "-device",
            "virtio-serial-pci",
            "-device",
            "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
            "-qmp",
            f"tcp:{HOST}:{state['qmp_port']},server=on,wait=off",
            "-vnc",
            f"{HOST}:{state['vnc_display']}",
            "-serial",
            f"file:{self._vm_dir(vm['name']) / 'console.log'}",
            "-monitor",
            "none",
        ]
        return cmd + self.extra_args

    # --- inventory ---
    def list_vms(self):
        root = self._root()
        if not root.is_dir():
            return []
        return sorted(d.name for d in root.iterdir() if (d / "vm.json").is_file())

    def list_snapshots(self, vm_name):
        vm = self._load(vm_name)
        if not vm or not self.qemu_img:
            return []
        try:
            out = subprocess.run(
                [self.qemu_img, "info", "-U", "--output=json", vm["disk_path"]],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return [s["name"] for s in json.loads(out.stdout).get("snapshots", [])]
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to list snapshots for {vm_name}: {e}")
            return []

    async def vm_state(self, vm_name):
        return "running" if await self.is_running(vm_name) else "stopped"

    async def verify_environment(self, vm_name):
        if not self.available():
            return False, "QEMU not found (install QEMU or set [qemu].bin_dir)"
        if self._load(vm_name) is None:
            return False, f"VM {vm_name} not found"
        return True, "OK"

    async def find_internet_facing_networks(self, vm_name):
        vm = self._load(vm_name)
        if vm and vm.get("network_mode") == "user":
            return ["QEMU user-mode NAT"]
        return []

    # --- lifecycle ---
    async def start_vm(self, vm_name):
        vm = self._require(vm_name)
        if await self.is_running(vm_name):
            return True
        vm_dir = self._vm_dir(vm_name)
        state = {"qmp_port": _free_port(), "qga_port": _free_port()}
        state["vnc_display"] = _free_vnc_display()
        cmd = self.build_command(vm, state)
        self.logger.info(f"Starting QEMU ({self.accel}): {' '.join(cmd)}")
        log = open(vm_dir / "qemu.log", "ab")
        kwargs: dict[str, Any] = {"stdout": log, "stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        else:
            kwargs["start_new_session"] = True
        try:
            proc = subprocess.Popen(cmd, **kwargs)
        except OSError as e:
            self._notify_ui(f"Failed to launch QEMU: {e}", "CRITICAL")
            return False
        finally:
            log.close()
        state["pid"] = proc.pid
        (vm_dir / "run.json").write_text(json.dumps(state), encoding="utf-8")

        for _ in range(30):
            if proc.poll() is not None:
                tail = (vm_dir / "qemu.log").read_text(encoding="utf-8", errors="replace")[-800:]
                self._notify_ui(f"QEMU exited during start: {tail.strip()}", "CRITICAL")
                (vm_dir / "run.json").unlink(missing_ok=True)
                return False
            if await self.is_running(vm_name):
                return True
            await asyncio.sleep(1)
        self._notify_ui("QEMU did not open its QMP socket in time.", "CRITICAL")
        return False

    async def stop_vm(self, vm_name):
        state = self._run_state(vm_name)
        if not state:
            return True
        try:
            await QMP(HOST, state["qmp_port"]).command("quit")
        except (OSError, asyncio.TimeoutError, AgentError):
            pass
        if not await self._wait_stopped(vm_name, 10):
            self._kill(state.get("pid"))
            await asyncio.sleep(1)
        (self._vm_dir(vm_name) / "run.json").unlink(missing_ok=True)
        return True

    async def revert_to_snapshot(self, vm_name, snapshot_name="clean-baseline"):
        vm = self._require(vm_name)
        await self.stop_vm(vm_name)
        try:
            await self._run_tool(self.qemu_img, "snapshot", "-a", snapshot_name, vm["disk_path"])
            return True
        except RuntimeError as e:
            raise RuntimeError(f"Failed to revert to snapshot: {e}") from e

    async def create_snapshot(self, vm_name, snapshot_name="clean-baseline", description="Clean state"):
        vm = self._require(vm_name)
        # Disk snapshots need a quiesced, powered-off guest
        await self._graceful_stop(vm_name)
        try:
            if snapshot_name in self.list_snapshots(vm_name):
                await self._run_tool(self.qemu_img, "snapshot", "-d", snapshot_name, vm["disk_path"])
            await self._run_tool(self.qemu_img, "snapshot", "-c", snapshot_name, vm["disk_path"])
            return True
        except RuntimeError as e:
            self.logger.error(f"Failed to create snapshot: {e}")
            return False

    async def wait_for_guest_agent(self, vm_name, timeout=300):
        self.logger.info(f"Waiting for guest agent on {vm_name} (timeout {timeout}s)...")
        for _ in range(max(1, timeout // 5)):
            if not await self.is_running(vm_name):
                self.logger.warning(f"VM {vm_name} is not running")
                return False
            try:
                async with self._agent(vm_name, timeout=5) as qga:
                    await qga.ping()
                return True
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, AgentError, json.JSONDecodeError):
                await asyncio.sleep(5)
        self.logger.warning(f"Guest agent timeout for VM {vm_name}.")
        return False

    async def open_gui(self, vm_name):
        state = self._run_state(vm_name)
        if not state:
            self._notify_ui(f"VM {vm_name} is not running.", "CRITICAL")
            return False
        address = f"{HOST}:{5900 + state['vnc_display']}"
        for viewer in ("remote-viewer", "vncviewer", "tvnviewer", "gvncviewer"):
            exe = shutil.which(viewer)
            if exe:
                target = f"vnc://{address}" if viewer == "remote-viewer" else address
                subprocess.Popen([exe, target])
                return True
        self._notify_ui(f"No VNC viewer found. Connect one to {address} to see the VM.", "WARN")
        return True

    # --- guest I/O ---
    async def run_command(self, vm_name, command, shell="/bin/sh"):
        self.logger.info(f"Running command in {vm_name}: {command}")
        try:
            async with self._agent(vm_name, timeout=30) as qga:
                code, out, err = await qga.exec(shell, ["/c" if "cmd" in shell else "-c", command])
            if code is None:
                self.logger.warning(f"Command '{command}' timed out in guest.")
                return "TIMEOUT"
            return out
        except (OSError, asyncio.TimeoutError, AgentError, json.JSONDecodeError) as e:
            self.logger.error(f"run_command failed: {e}")
            return ""

    async def inject_file_via_agent(self, vm_name, local_path, guest_path):
        try:
            async with self._agent(vm_name, timeout=30) as qga:
                await qga.write_file(guest_path, local_path)
            return True
        except (OSError, asyncio.TimeoutError, AgentError) as e:
            self.logger.error(f"inject_file_via_agent failed: {e}")
            return False

    async def inject_file(self, vm_name, local_path, guest_path):
        # No offline disk access without libguestfs; boot the guest and use the agent
        if not await self.is_running(vm_name):
            if not await self.start_vm(vm_name) or not await self.wait_for_guest_agent(vm_name):
                return False
        return await self.inject_file_via_agent(vm_name, local_path, guest_path)

    async def pull_file(self, vm_name, guest_path, local_path):
        try:
            async with self._agent(vm_name, timeout=30) as qga:
                await qga.read_file(guest_path, local_path)
            return True
        except (OSError, asyncio.TimeoutError, AgentError) as e:
            self.logger.error(f"Pull failed: {e}")
            return False

    # --- provisioning ---
    async def ensure_network(self, network_name="malware-analysis", nat=False):
        return True  # user-mode networking needs no host setup

    def vm_disk_path(self, vm_name):
        return str(self._vm_dir(vm_name) / "disk.qcow2")

    async def create_disk(self, disk_path, size_gb, backing_file=None):
        Path(disk_path).parent.mkdir(parents=True, exist_ok=True)
        cmd = [self.qemu_img, "create", "-f", "qcow2"]
        if backing_file:
            cmd += ["-b", str(Path(backing_file).resolve()), "-F", "qcow2"]
        cmd += [disk_path, f"{size_gb}G"]
        try:
            await self._run_tool(*cmd, timeout=60)
            return disk_path
        except RuntimeError as e:
            self.logger.error(f"Disk creation failed: {e}")
            return False

    async def define_vm(self, spec: VMSpec):
        if spec.os_type != "linux":
            self._notify_ui("The QEMU backend currently supports Linux guests only.", "CRITICAL")
            return False
        if await self.is_running(spec.name):
            await self.stop_vm(spec.name)
        data = asdict(spec)
        data["network_mode"] = _network_mode(spec.network)
        self._save(spec.name, data)
        return True

    async def switch_network(self, vm_name, from_network, to_network):
        vm = self._require(vm_name)
        await self._graceful_stop(vm_name)
        vm["network"] = to_network
        vm["network_mode"] = _network_mode(to_network)
        # The cloud-init seed is only needed on first boot
        vm["cloud_init_path"] = None
        self._save(vm_name, vm)
        return True

    async def delete_vm(self, vm_name):
        await self.stop_vm(vm_name)
        shutil.rmtree(self._vm_dir(vm_name), ignore_errors=True)
        return True
