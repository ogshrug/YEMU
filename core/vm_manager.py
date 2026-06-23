import logging
import asyncio
import libvirt
import os
import subprocess
import json
import base64
import tempfile
import shutil

class VMManager:
    """
    Handles VM lifecycle operations using libvirt and guestfs tools.
    """
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        try:
            self.conn = libvirt.open('qemu:///system')
            if self.conn is None:
                raise RuntimeError("Failed to open connection to qemu:///system")
        except Exception as e:
            self.logger.critical(f"Failed to connect to libvirt: {e}")
            raise

    def _get_domain(self, vm_name):
        try:
            return self.conn.lookupByName(vm_name)
        except libvirt.libvirtError:
            self.logger.error(f"Domain {vm_name} not found.")
            return None

    async def verify_environment(self, vm_name, snapshot_name="clean-baseline"):
        """Automated check for VM and snapshot existence."""
        dom = self._get_domain(vm_name)
        if not dom:
            return False, f"VM '{vm_name}' not found in libvirt."

        try:
            dom.snapshotLookupByName(snapshot_name)
        except libvirt.libvirtError:
            return False, f"Snapshot '{snapshot_name}' not found for VM '{vm_name}'."

        return True, "Environment verified."

    async def start_vm(self, vm_name):
        self.logger.info(f"Starting VM: {vm_name}")
        dom = self._get_domain(vm_name)
        if not dom: return False

        try:
            if not dom.isActive():
                dom.create()

            # Poll for guest agent readiness
            for _ in range(60): # 60 seconds timeout
                try:
                    # Send a simple ping command to guest agent
                    ping_args = {"execute": "guest-ping"}
                    cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(ping_args)]
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await proc.communicate()
                    if proc.returncode == 0:
                        self.logger.info(f"Guest agent ready for {vm_name}")
                        return True
                except:
                    pass
                await asyncio.sleep(2)

            self.logger.error(f"Guest agent timeout for VM {vm_name}")
            return False
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to start VM: {e}")
            return False

    async def stop_vm(self, vm_name):
        self.logger.info(f"Stopping VM: {vm_name}")
        dom = self._get_domain(vm_name)
        if not dom: return False

        try:
            if dom.isActive():
                dom.destroy()
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to stop VM: {e}")
            return False

    async def revert_to_snapshot(self, vm_name, snapshot_name="clean-baseline"):
        self.logger.info(f"Reverting {vm_name} to snapshot {snapshot_name}")
        dom = self._get_domain(vm_name)
        if not dom: return False

        try:
            if dom.isActive():
                dom.destroy()

            snap = dom.snapshotLookupByName(snapshot_name)
            dom.revertToSnapshot(snap)
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to revert to snapshot: {e}")
            return False

    async def inject_file(self, vm_name, local_path, guest_path):
        """Injects a file into the guest. VM MUST BE STOPPED for virt-copy-in."""
        self.logger.info(f"Injecting {local_path} to {vm_name}:{guest_path}")

        # virt-copy-in -d domain local_file /remote/dir
        # We handle renaming by creating a temporary file with the target name
        target_name = os.path.basename(guest_path)
        remote_dir = os.path.dirname(guest_path)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_local_file = os.path.join(tmpdir, target_name)
            shutil.copy2(local_path, tmp_local_file)

            cmd = ["virt-copy-in", "-d", vm_name, tmp_local_file, remote_dir]
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode != 0:
                    self.logger.error(f"virt-copy-in failed: {stderr.decode()}")
                    return False
                return True
            except Exception as e:
                self.logger.error(f"Injection failed: {e}")
                return False

    async def run_command(self, vm_name, command):
        """Runs a command in the guest via qemu-guest-agent."""
        self.logger.info(f"Running command in {vm_name}: {command}")

        try:
            exec_args = {
                "execute": "guest-exec",
                "arguments": {
                    "path": "/bin/sh",
                    "arg": ["-c", command],
                    "capture-output": True
                }
            }

            cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(exec_args)]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                self.logger.error(f"virsh qemu-agent-command failed: {stderr.decode()}")
                return ""

            resp = json.loads(stdout.decode())
            if 'return' not in resp or 'pid' not in resp['return']:
                self.logger.error(f"Unexpected response from guest agent: {resp}")
                return ""

            pid = resp['return']['pid']

            status_args = {
                "execute": "guest-exec-status",
                "arguments": {"pid": pid}
            }

            for _ in range(60):
                await asyncio.sleep(1)
                cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(status_args)]
                proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, _ = await proc.communicate()
                status_resp = json.loads(stdout.decode())

                if 'return' in status_resp and status_resp['return']['exited']:
                    out_b64 = status_resp['return'].get('out-data', '')
                    return base64.b64decode(out_b64).decode(errors='replace')

            self.logger.warning(f"Command '{command}' timed out in guest.")
            return "TIMEOUT"

        except Exception as e:
            self.logger.error(f"run_command failed: {e}")
            return ""
