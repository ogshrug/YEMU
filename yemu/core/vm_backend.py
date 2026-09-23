"""
The contract every hypervisor backend implements. The orchestrator and UI only talk
to this interface, so adding a backend (e.g. Hyper-V on Windows) means adding one
subclass and registering it in create_backend().
"""
import logging
from abc import ABC, abstractmethod


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
    async def define_vm(self, xml, vm_name): ...

    @abstractmethod
    async def switch_network(self, vm_name, from_network, to_network):
        """Re-attach a stopped VM's interfaces from one network to another."""


BACKENDS = ("auto", "libvirt", "mock")


def create_backend(name="auto", ui_callback=None):
    """
    Build a backend by name. "auto" tries libvirt and falls back to the mock backend,
    so the UI and CLI stay usable on hosts without virtualization.
    """
    from yemu.core.vm_manager import VMManager, MockVMManager

    logger = logging.getLogger(__name__)
    if name == "mock":
        return MockVMManager(ui_callback=ui_callback)
    if name == "libvirt":
        return VMManager(ui_callback=ui_callback)
    if name != "auto":
        raise ValueError(f"Unknown VM backend '{name}'. Choose from: {', '.join(BACKENDS)}")

    backend = VMManager(ui_callback=ui_callback)
    try:
        backend._get_conn()
        return backend
    except Exception as e:
        logger.warning(f"libvirt unavailable ({e}); using mock backend")
        if ui_callback:
            ui_callback(f"libvirt unavailable ({e}). Running in Mock Mode.", "WARN")
        return MockVMManager(ui_callback=ui_callback)
