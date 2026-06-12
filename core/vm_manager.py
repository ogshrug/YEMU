import logging
import asyncio

class VMManager:
    """
    Handles VM lifecycle operations.
    Wraps libvirt, but includes a Mock mode for environments without KVM.
    """
    def __init__(self, use_mock=True):
        self.use_mock = use_mock
        self.logger = logging.getLogger(__name__)
        if not use_mock:
            try:
                import libvirt
                self.conn = libvirt.open('qemu:///system')
            except Exception as e:
                self.logger.error(f"Failed to connect to libvirt: {e}. Falling back to Mock mode.")
                self.use_mock = True

    async def start_vm(self, vm_name):
        self.logger.info(f"Starting VM: {vm_name} (Mock: {self.use_mock})")
        if self.use_mock:
            await asyncio.sleep(2)
            return True
        # Libvirt logic here
        return True

    async def stop_vm(self, vm_name):
        self.logger.info(f"Stopping VM: {vm_name}")
        if self.use_mock:
            await asyncio.sleep(1)
            return True
        return True

    async def revert_to_snapshot(self, vm_name, snapshot_name="clean-baseline"):
        self.logger.info(f"Reverting {vm_name} to snapshot {snapshot_name}")
        if self.use_mock:
            await asyncio.sleep(3)
            return True
        return True

    async def inject_file(self, vm_name, local_path, guest_path):
        self.logger.info(f"Injecting {local_path} to {vm_name}:{guest_path}")
        if self.use_mock:
            await asyncio.sleep(1)
            return True
        return True

    async def run_command(self, vm_name, command):
        self.logger.info(f"Running command in {vm_name}: {command}")
        if self.use_mock:
            await asyncio.sleep(1)
            return "Mock output"
        return ""
