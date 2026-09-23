"""
The contract every hypervisor backend implements. The orchestrator and UI only talk
to this interface, so adding a backend (e.g. Hyper-V on Windows) means adding one
subclass and registering it in create_backend().
"""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

PROVISION_NETWORK = "yemu-provision"


@dataclass
class VMSpec:
    """Backend-neutral VM definition; each backend renders it (libvirt XML, QEMU argv...)."""
    name: str
    disk_path: str
    ram_mb: int = 2048
    cpus: int = 2
    network: str = "malware-analysis"
    os_type: str = "linux"
    iso_path: Optional[str] = None
    cloud_init_path: Optional[str] = None
    virtio_win_path: Optional[str] = None
    windows_auto_path: Optional[str] = None


class VMBackend(ABC):
    name = "base"

    def __init__(self, ui_callback=None):
        self.logger = logging.getLogger(type(self).__module__)
        self.ui_callback = ui_callback

    def _notify_ui(self, msg, severity="INFO"):
        if self.ui_callback:
            self.ui_callback(msg, severity)

    # --- inventory ---
    @abstractmethod
    def list_vms(self): ...

    @abstractmethod
    def list_snapshots(self, vm_name): ...

    @abstractmethod
    async def verify_environment(self, vm_name):
        """Return (ok: bool, message: str)."""

    @abstractmethod
    async def find_internet_facing_networks(self, vm_name):
        """Return descriptions of interfaces that can reach the host LAN / internet."""

    # --- lifecycle ---
    @abstractmethod
    async def start_vm(self, vm_name): ...

    @abstractmethod
    async def stop_vm(self, vm_name): ...

    @abstractmethod
    async def revert_to_snapshot(self, vm_name, snapshot_name="clean-baseline"): ...

    @abstractmethod
    async def create_snapshot(self, vm_name, snapshot_name="clean-baseline", description="Clean state"): ...

    @abstractmethod
    async def wait_for_guest_agent(self, vm_name, timeout=300): ...

    @abstractmethod
    async def open_gui(self, vm_name): ...

    # --- guest I/O ---
    @abstractmethod
    async def run_command(self, vm_name, command, shell="/bin/sh"): ...

    @abstractmethod
    async def inject_file(self, vm_name, local_path, guest_path):
        """Copy a file into a (possibly stopped) guest."""

    async def inject_file_via_agent(self, vm_name, local_path, guest_path):
        """Copy a file into a running guest. Backends without a live channel fall back to inject_file."""
        return await self.inject_file(vm_name, local_path, guest_path)

    @abstractmethod
    async def pull_file(self, vm_name, guest_path, local_path): ...

    # --- provisioning ---
    @abstractmethod
    async def ensure_network(self, network_name="malware-analysis", nat=False): ...

    @abstractmethod
    async def create_disk(self, disk_path, size_gb, backing_file=None): ...

    @abstractmethod
    async def define_vm(self, spec):
        """Create or replace a VM from a VMSpec."""

    def vm_disk_path(self, vm_name):
        """Where provisioning should put this VM's disk."""
        from yemu import paths
        return str(paths.vm_storage_dir() / f"{vm_name}.qcow2")

    @abstractmethod
    async def switch_network(self, vm_name, from_network, to_network):
        """Re-attach a stopped VM's interfaces from one network to another."""


BACKENDS = ("auto", "libvirt", "qemu", "mock")


def create_backend(name="auto", ui_callback=None, config=None):
    """
    Build a backend by name. "auto" prefers libvirt (Linux), then standalone QEMU
    (Windows/Linux), then the mock backend, so the UI and CLI stay usable anywhere.
    """
    import os
    from yemu import config as yemu_config
    from yemu.core.vm_manager import VMManager, MockVMManager
    from yemu.core.qemu_backend import QemuBackend

    logger = logging.getLogger(__name__)
    config = config or yemu_config.load()
    if name == "mock":
        return MockVMManager(ui_callback=ui_callback)
    if name == "libvirt":
        return VMManager(ui_callback=ui_callback)
    if name == "qemu":
        return QemuBackend(ui_callback=ui_callback, config=config)
    if name != "auto":
        raise ValueError(f"Unknown VM backend '{name}'. Choose from: {', '.join(BACKENDS)}")

    reasons = []
    if os.name == "posix":
        backend = VMManager(ui_callback=ui_callback)
        try:
            backend._get_conn()
            return backend
        except Exception as e:
            reasons.append(f"libvirt: {e}")

    qemu = QemuBackend(ui_callback=ui_callback, config=config)
    if qemu.available():
        return qemu
    reasons.append("qemu: qemu-system-x86_64 / qemu-img not found")

    reason = "; ".join(reasons)
    logger.warning(f"No VM backend available ({reason}); using mock backend")
    if ui_callback:
        ui_callback(f"No VM backend available ({reason}). Running in Mock Mode.", "WARN")
    return MockVMManager(ui_callback=ui_callback)
