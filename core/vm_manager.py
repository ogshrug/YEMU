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
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._conn = None

    def _get_conn(self):
        if self._conn is None:
            self._conn = libvirt.open('qemu:///system')
            if self._conn is None:
                raise RuntimeError("Failed to open connection to qemu:///system")
        return self._conn

    def _get_domain(self, vm_name):
        try:
            return self._get_conn().lookupByName(vm_name)
        except libvirt.libvirtError:
            return None

    def list_vms(self):
        try:
            conn = self._get_conn()
            domains = conn.listAllDomains(0)
            return [dom.name() for dom in domains]
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to list VMs: {e}")
            return []

    def list_snapshots(self, vm_name):
        dom = self._get_domain(vm_name)
        if not dom:
            return []
        try:
            snapshots = dom.listAllSnapshots(0)
            return [snap.getName() for snap in snapshots]
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to list snapshots for {vm_name}: {e}")
            return []

    def _remove_existing_domain(self, vm_name):
        dom = self._get_domain(vm_name)
        if dom is None:
            return
        self.logger.info(f"Removing existing domain: {vm_name}")
        try:
            if dom.isActive():
                dom.destroy()
        except libvirt.libvirtError:
            pass
        try:
            dom.undefine()
        except libvirt.libvirtError as e:
            self.logger.warning(f"Could not undefine domain: {e}")

    async def ensure_network(self, network_name="malware-analysis"):
        conn = self._get_conn()
        try:
            net = conn.networkLookupByName(network_name)
            if not net.isActive():
                net.create()
            return True
        except libvirt.libvirtError:
            self.logger.info(f"Network {network_name} not found. Creating...")
            xml = f"""
            <network>
              <name>{network_name}</name>
              <bridge name='virbr-malware' stp='on' delay='0'/>
              <ip address='192.168.100.1' netmask='255.255.255.0'>
              </ip>
            </network>
            """
            try:
                net = conn.networkDefineXML(xml)
                net.setAutostart(True)
                net.create()
                return True
            except libvirt.libvirtError as e:
                self.logger.error(f"Failed to create network: {e}")
                return False

    async def create_disk(self, disk_path, size_gb, backing_file=None):
        os.makedirs(os.path.dirname(disk_path), exist_ok=True)
        cmd = ["qemu-img", "create", "-f", "qcow2"]
        if backing_file:
            cmd += ["-b", backing_file, "-F", "qcow2", disk_path, f"{size_gb}G"]
        else:
            cmd += [disk_path, f"{size_gb}G"]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                self.logger.error(f"qemu-img failed: {stderr.decode()}")
                stderr_str = stderr.decode()
                if "Permission denied" in stderr_str or "Could not open" in stderr_str:
                    new_path = os.path.join("/var/tmp", os.path.basename(disk_path))
                    self.logger.warning(f"Retrying in /var/tmp as {new_path}...")
                    return await self.create_disk(new_path, size_gb, backing_file)
                return False
            os.chmod(disk_path, 0o644)
            return disk_path
        except Exception as e:
            self.logger.error(f"Disk creation failed: {e}")
            return False

    async def define_vm(self, xml, vm_name):
        conn = self._get_conn()
        self._remove_existing_domain(vm_name)
        try:
            conn.defineXML(xml)
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to define VM: {e}")
            return False

    async def create_snapshot(self, vm_name, snapshot_name="clean-baseline", description="Clean state"):
        dom = self._get_domain(vm_name)
        if not dom:
            return False
        xml = f"""
        <domainsnapshot>
          <name>{snapshot_name}</name>
          <description>{description}</description>
        </domainsnapshot>
        """
        try:
            dom.snapshotCreateXML(xml, 0)
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to create snapshot: {e}")
            return False

    async def start_vm(self, vm_name):
        self.logger.info(f"Starting VM: {vm_name}")
        dom = self._get_domain(vm_name)
        if not dom:
            return False
        try:
            if not dom.isActive():
                dom.create()
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to start VM: {e}")
            return False

    async def wait_for_guest_agent(self, vm_name, timeout=300):
        self.logger.info(f"Waiting for guest agent on {vm_name} (timeout {timeout}s)...")
        for _ in range(timeout // 5):
            try:
                ping_args = {"execute": "guest-ping"}
                cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(ping_args)]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
                if proc.returncode == 0:
                    self.logger.info(f"Guest agent ready for {vm_name}")
                    return True
            except Exception:
                pass
            await asyncio.sleep(5)
        self.logger.error(f"Guest agent timeout for VM {vm_name}")
        return False

    async def stop_vm(self, vm_name):
        self.logger.info(f"Stopping VM: {vm_name}")
        dom = self._get_domain(vm_name)
        if not dom:
            return False
        try:
            if dom.isActive():
                dom.destroy()
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to stop VM: {e}")
            return False

    async def inject_file(self, vm_name, local_path, guest_path):
        self.logger.info(f"Injecting {local_path} to {vm_name}:{guest_path}")
        target_name = os.path.basename(guest_path)
        remote_dir = os.path.dirname(guest_path)
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_local_file = os.path.join(tmpdir, target_name)
            shutil.copy2(local_path, tmp_local_file)
            cmd = ["virt-copy-in", "-d", vm_name, tmp_local_file, remote_dir]
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode != 0:
                    self.logger.error(f"virt-copy-in failed: {stderr.decode()}")
                    return False
                return True
            except Exception as e:
                self.logger.error(f"Injection failed: {e}")
                return False

    async def run_command(self, vm_name, command, shell="/bin/sh"):
        self.logger.info(f"Running command in {vm_name}: {command}")
        try:
            exec_args = {
                "execute": "guest-exec",
                "arguments": {
                    "path": shell,
                    "arg": ["/c" if "cmd" in shell else "-c", command],
                    "capture-output": True
                }
            }
            cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(exec_args)]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                self.logger.error(f"virsh qemu-agent-command failed: {stderr.decode()}")
                return ""
            resp = json.loads(stdout.decode())
            if 'return' not in resp or 'pid' not in resp['return']:
                self.logger.error(f"Unexpected response: {resp}")
                return ""
            pid = resp['return']['pid']
            status_args = {
                "execute": "guest-exec-status",
                "arguments": {"pid": pid}
            }
            for _ in range(60):
                await asyncio.sleep(1)
                cmd = ["virsh", "qemu-agent-command", vm_name, json.dumps(status_args)]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
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

    async def verify_environment(self, vm_name):
        try:
            conn = self._get_conn()
            if not conn.isAlive():
                return False, "Libvirt connection is not alive"
            dom = self._get_domain(vm_name)
            if not dom:
                return False, f"VM {vm_name} not found"
            return True, "OK"
        except Exception as e:
            return False, str(e)

    async def revert_to_snapshot(self, vm_name, snapshot_name="clean-baseline"):
        dom = self._get_domain(vm_name)
        if not dom:
            raise RuntimeError(f"VM {vm_name} not found")
        try:
            snap = dom.snapshotLookupByName(snapshot_name)
            dom.revertToSnapshot(snap)
            return True
        except libvirt.libvirtError as e:
            self.logger.error(f"Failed to revert to snapshot {snapshot_name}: {e}")
            raise RuntimeError(f"Failed to revert to snapshot: {e}")

    async def open_gui(self, vm_name):
        self.logger.info(f"Opening GUI for {vm_name}")
        try:
            subprocess.Popen(["virt-viewer", "-c", "qemu:///system", "--attach", vm_name])
            return True
        except Exception as e:
            self.logger.error(f"Failed to open GUI: {e}")
            return False

    async def pull_file(self, vm_name, guest_path, local_path):
        self.logger.info(f"Pulling {vm_name}:{guest_path} to {local_path}")
        cmd = ["virt-copy-out", "-d", vm_name, guest_path, os.path.dirname(local_path)]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                self.logger.error(f"virt-copy-out failed: {stderr.decode()}")
                return False

            # virt-copy-out copies to the directory, we might need to rename if local_path is different
            filename = os.path.basename(guest_path)
            downloaded_path = os.path.join(os.path.dirname(local_path), filename)
            if downloaded_path != local_path:
                os.rename(downloaded_path, local_path)
            return True
        except Exception as e:
            self.logger.error(f"Pull failed: {e}")
            return False
